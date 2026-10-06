//! Grant-scoped persistent host for plugin-owned agent sessions.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration as StdDuration;

use chrono::{DateTime, Utc};
use serde_json::Value;
use tokio::sync::{Mutex as AsyncMutex, OwnedMutexGuard};
use uuid::Uuid;
use voidb_core::{
    AgentSessionBinding, AgentSessionCallRequest, AgentSessionCallResult,
    AgentSessionCancelRequest, AgentSessionCloseAgentRequest, AgentSessionConcurrency,
    AgentSessionContinuity, AgentSessionListRequest, AgentSessionOpenContext,
    AgentSessionOpenRequest, AgentSessionRef, AgentSessionRenewRequest, AgentSessionStatusRequest,
    AgentSessionView, PluginAgentSession, PluginAgentSessionFactory, PluginSessionError,
    PluginSessionErrorCode, PluginSessionHealth, PluginSessionReason,
};

struct HostedSession {
    view: AgentSessionView,
    handle: Option<Arc<dyn PluginAgentSession>>,
    cancelled_calls: HashSet<String>,
    call_gate: Option<Arc<AsyncMutex<()>>>,
    in_flight_calls: usize,
}

pub(crate) struct PreparedAgentSessionCall {
    handle: Arc<dyn PluginAgentSession>,
    call_gate: Option<Arc<AsyncMutex<()>>>,
    accepted_at: DateTime<Utc>,
    accepted_instant: tokio::time::Instant,
    deadline: tokio::time::Instant,
    deadline_at: DateTime<Utc>,
    output_limit_bytes: usize,
}

impl PreparedAgentSessionCall {
    pub(crate) async fn acquire_serialized(&self) -> Option<OwnedMutexGuard<()>> {
        match &self.call_gate {
            Some(call_gate) => Some(Arc::clone(call_gate).lock_owned().await),
            None => None,
        }
    }

    pub(crate) fn deadline_at(&self) -> DateTime<Utc> {
        self.deadline_at
    }

    pub(crate) fn current_time(&self) -> DateTime<Utc> {
        chrono::Duration::from_std(self.accepted_instant.elapsed())
            .ok()
            .and_then(|elapsed| self.accepted_at.checked_add_signed(elapsed))
            .unwrap_or(self.accepted_at)
    }

    pub(crate) async fn execute(
        &self,
        request: AgentSessionCallRequest,
    ) -> Result<AgentSessionCallResult, PluginSessionError> {
        let remaining = self
            .deadline
            .saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(session_error(
                PluginSessionErrorCode::TimedOut,
                "Plugin session call timed out before execution began.",
                &request.session,
            ));
        }
        let call_id = request.call_id.clone();
        let result = match tokio::time::timeout(remaining, self.handle.call(request.clone())).await
        {
            Ok(result) => result?,
            Err(_) => {
                let _ = self.handle.cancel(&call_id).await;
                return Err(session_error(
                    PluginSessionErrorCode::TimedOut,
                    "Plugin session call timed out and cancellation was requested.",
                    &request.session,
                ));
            }
        };
        if result.call_id != call_id {
            return Err(session_error(
                PluginSessionErrorCode::CallIdMismatch,
                "Plugin session returned a different call ID than the caller supplied.",
                &request.session,
            ));
        }
        if matches!(
            result.redaction,
            voidb_core::RedactionStatus::Withheld | voidb_core::RedactionStatus::FailedClosed
        ) && !result.output.is_null()
        {
            return Err(session_error(
                PluginSessionErrorCode::RedactionFailed,
                "Withheld or failed-closed session output must not contain a payload.",
                &request.session,
            ));
        }
        if result.output_bytes > self.output_limit_bytes
            || result.output_bytes > voidb_core::MAX_AGENT_SESSION_OUTPUT_BYTES
        {
            return Err(session_error(
                PluginSessionErrorCode::OutputLimit,
                "Plugin session output exceeded the negotiated bound.",
                &request.session,
            ));
        }
        Ok(result)
    }
}

pub struct AgentSessionHost {
    grant_id: String,
    profile_id: String,
    plugin_id: String,
    allowed_capabilities: Vec<String>,
    grant_expires_at: DateTime<Utc>,
    host_generation: u64,
    factories: HashMap<String, Arc<dyn PluginAgentSessionFactory>>,
    sessions: HashMap<String, HostedSession>,
}

impl AgentSessionHost {
    pub fn new(
        grant_id: impl Into<String>,
        profile_id: impl Into<String>,
        plugin_id: impl Into<String>,
        allowed_capabilities: Vec<String>,
        grant_expires_at: DateTime<Utc>,
        host_generation: u64,
    ) -> Self {
        Self {
            grant_id: grant_id.into(),
            profile_id: profile_id.into(),
            plugin_id: plugin_id.into(),
            allowed_capabilities,
            grant_expires_at,
            host_generation,
            factories: HashMap::new(),
            sessions: HashMap::new(),
        }
    }

    pub fn register_factory(&mut self, factory: Arc<dyn PluginAgentSessionFactory>) {
        self.factories
            .insert(factory.plugin_id().to_owned(), factory);
    }

    pub fn renew_grant(&mut self, expires_at: DateTime<Utc>) {
        self.grant_expires_at = expires_at;
    }

    pub async fn open(
        &mut self,
        mut request: AgentSessionOpenRequest,
        now: DateTime<Utc>,
    ) -> Result<AgentSessionView, PluginSessionError> {
        self.expire(now).await;
        let factory = self
            .factories
            .get(&self.plugin_id)
            .cloned()
            .ok_or_else(|| {
                PluginSessionError::new(
                    PluginSessionErrorCode::Unsupported,
                    format!(
                        "Plugin '{}' does not provide persistent agent sessions.",
                        self.plugin_id
                    ),
                )
            })?;

        if request.capabilities.is_empty() {
            request.capabilities = self.allowed_capabilities.clone();
        }
        if request.capabilities.is_empty() {
            return Err(PluginSessionError::new(
                PluginSessionErrorCode::PolicyDenied,
                "A persistent session requires at least one capability.",
            ));
        }
        for capability in &request.capabilities {
            self.validate_capability(capability)?;
        }
        let lease_expires_at = request.lease_expires_at(now, self.grant_expires_at)?;
        let binding = AgentSessionBinding {
            grant_id: self.grant_id.clone(),
            profile_id: self.profile_id.clone(),
            plugin_id: self.plugin_id.clone(),
            purpose: request.purpose.clone(),
            allowed_capabilities: request.capabilities.clone(),
            host_generation: self.host_generation,
        };
        let handle = factory
            .open(AgentSessionOpenContext {
                binding: binding.clone(),
                request: request.clone(),
                lease_expires_at,
            })
            .await?;
        let concurrency = handle.concurrency();
        if request.concurrency == AgentSessionConcurrency::Multiplexed
            && concurrency != AgentSessionConcurrency::Multiplexed
        {
            let _ = handle.close("unsupported_multiplexing".into()).await;
            return Err(PluginSessionError::new(
                PluginSessionErrorCode::PolicyDenied,
                "Plugin session does not declare safe multiplexing.",
            ));
        }
        let health = handle.health().await?;
        let reference = AgentSessionRef::new(format!("agent-session:{}", Uuid::new_v4()), 1);
        let view = AgentSessionView {
            session: reference.clone(),
            binding,
            health,
            concurrency,
            continuity: AgentSessionContinuity::Original,
            created_at: now,
            last_used_at: now,
            lease_expires_at,
            metadata: Value::Null,
        };
        self.sessions.insert(
            reference.session_id.clone(),
            HostedSession {
                view: view.clone(),
                handle: Some(handle),
                cancelled_calls: HashSet::new(),
                call_gate: (concurrency == AgentSessionConcurrency::Serialized)
                    .then(|| Arc::new(AsyncMutex::new(()))),
                in_flight_calls: 0,
            },
        );
        Ok(view)
    }

    pub async fn call(
        &mut self,
        request: AgentSessionCallRequest,
        now: DateTime<Utc>,
    ) -> Result<AgentSessionCallResult, PluginSessionError> {
        let prepared = self.prepare_call(&request, now).await?;
        let _serialized = prepared.acquire_serialized().await;
        let result = if self
            .call_is_active(&request.session, prepared.current_time())
            .is_ok()
        {
            prepared.execute(request.clone()).await
        } else {
            Err(session_error(
                PluginSessionErrorCode::Cancelled,
                "Plugin session call was stopped before execution began.",
                &request.session,
            ))
        };
        self.finish_prepared_call(&request.session, prepared.current_time());
        result
    }

    pub(crate) async fn prepare_call(
        &mut self,
        request: &AgentSessionCallRequest,
        now: DateTime<Utc>,
    ) -> Result<PreparedAgentSessionCall, PluginSessionError> {
        self.expire(now).await;
        request.validate_call_id()?;
        request.validate_output_limit()?;
        self.validate_capability(&request.capability)?;
        let handle = {
            let entry = self.active_entry(&request.session, now)?;
            if !entry.view.binding.allows_capability(&request.capability) {
                return Err(session_error(
                    PluginSessionErrorCode::PolicyDenied,
                    "Capability is outside this session binding.",
                    &request.session,
                ));
            }
            entry.handle.clone().ok_or_else(|| {
                session_error(
                    PluginSessionErrorCode::OwnerUnavailable,
                    "Plugin session owner is unavailable.",
                    &request.session,
                )
            })?
        };
        if request.timeout_ms == Some(0) {
            return Err(session_error(
                PluginSessionErrorCode::PolicyDenied,
                "Session call timeout must be greater than zero.",
                &request.session,
            ));
        }
        let remaining = self
            .active_entry(&request.session, now)?
            .view
            .lease_expires_at
            .signed_duration_since(now)
            .to_std()
            .unwrap_or(StdDuration::ZERO);
        let requested_timeout = request
            .timeout_ms
            .map(StdDuration::from_millis)
            .unwrap_or(remaining);
        let deadline = requested_timeout.min(remaining);
        let deadline_at = chrono::Duration::from_std(deadline)
            .ok()
            .and_then(|duration| now.checked_add_signed(duration))
            .unwrap_or_else(|| {
                self.active_entry(&request.session, now)
                    .expect("checked")
                    .view
                    .lease_expires_at
            });
        let entry = self
            .sessions
            .get_mut(&request.session.session_id)
            .expect("entry checked");
        entry.in_flight_calls += 1;
        entry.view.last_used_at = now;
        entry.view.health = PluginSessionHealth::Busy;
        Ok(PreparedAgentSessionCall {
            handle,
            call_gate: entry.call_gate.clone(),
            accepted_at: now,
            accepted_instant: tokio::time::Instant::now(),
            deadline: tokio::time::Instant::now() + deadline,
            deadline_at,
            output_limit_bytes: request.output_limit_bytes,
        })
    }

    pub(crate) fn call_is_active(
        &self,
        reference: &AgentSessionRef,
        now: DateTime<Utc>,
    ) -> Result<(), PluginSessionError> {
        self.active_entry(reference, now).map(|_| ())
    }

    pub(crate) fn finish_prepared_call(&mut self, reference: &AgentSessionRef, now: DateTime<Utc>) {
        if let Some(entry) = self.sessions.get_mut(&reference.session_id) {
            entry.in_flight_calls = entry.in_flight_calls.saturating_sub(1);
            entry.view.last_used_at = now;
            if entry.in_flight_calls == 0
                && entry.handle.is_some()
                && !entry.view.health.is_terminal()
            {
                entry.view.health = PluginSessionHealth::Ready;
            }
        }
    }

    pub async fn status(
        &mut self,
        request: AgentSessionStatusRequest,
        now: DateTime<Utc>,
    ) -> Result<AgentSessionView, PluginSessionError> {
        self.expire(now).await;
        let handle = {
            let entry = self.entry(&request.session)?;
            entry.handle.clone()
        };
        if let Some(handle) = handle {
            let health = handle.health().await?;
            if let Some(entry) = self.sessions.get_mut(&request.session.session_id) {
                entry.view.health = health;
                entry.view.last_used_at = now;
            }
        }
        Ok(self.entry(&request.session)?.view.clone())
    }

    pub async fn list(
        &mut self,
        request: AgentSessionListRequest,
        now: DateTime<Utc>,
    ) -> Vec<AgentSessionView> {
        self.expire(now).await;
        let mut sessions = self
            .sessions
            .values()
            .filter(|entry| request.include_terminal || !entry.view.health.is_terminal())
            .filter(|entry| {
                request
                    .purpose
                    .as_ref()
                    .is_none_or(|purpose| entry.view.binding.purpose == *purpose)
            })
            .map(|entry| entry.view.clone())
            .collect::<Vec<_>>();
        sessions.sort_by_key(|left| left.created_at);
        sessions
    }

    pub async fn renew(
        &mut self,
        request: AgentSessionRenewRequest,
        now: DateTime<Utc>,
    ) -> Result<AgentSessionView, PluginSessionError> {
        self.expire(now).await;
        let open_request = AgentSessionOpenRequest {
            purpose: self.entry(&request.session)?.view.binding.purpose.clone(),
            capabilities: Vec::new(),
            lease_seconds: request.lease_seconds,
            concurrency: AgentSessionConcurrency::Serialized,
            destructive_acknowledged: false,
            input: Value::Null,
        };
        let lease_expires_at = open_request.lease_expires_at(now, self.grant_expires_at)?;
        let handle = self
            .active_entry(&request.session, now)?
            .handle
            .clone()
            .ok_or_else(|| {
                session_error(
                    PluginSessionErrorCode::OwnerUnavailable,
                    "Plugin session owner is unavailable.",
                    &request.session,
                )
            })?;
        handle.renew(lease_expires_at).await?;
        let entry = self
            .sessions
            .get_mut(&request.session.session_id)
            .expect("entry checked");
        entry.view.lease_expires_at = lease_expires_at;
        entry.view.last_used_at = now;
        Ok(entry.view.clone())
    }

    pub async fn cancel(
        &mut self,
        request: AgentSessionCancelRequest,
        now: DateTime<Utc>,
    ) -> Result<AgentSessionView, PluginSessionError> {
        self.expire(now).await;
        request.validate_call_id()?;
        let timeout = request.timeout()?;
        let call_id = request.call_id.clone();
        let session = request.session.clone();
        let handle = {
            let entry = self.active_entry(&session, now)?;
            if entry.cancelled_calls.contains(&call_id) {
                return Ok(entry.view.clone());
            }
            entry.handle.clone().ok_or_else(|| {
                session_error(
                    PluginSessionErrorCode::OwnerUnavailable,
                    "Plugin session owner is unavailable.",
                    &session,
                )
            })?
        };
        match tokio::time::timeout(timeout, handle.cancel(&call_id)).await {
            Ok(result) => result?,
            Err(_) => {
                let _ = self
                    .close(
                        AgentSessionCloseAgentRequest {
                            session: session.clone(),
                            reason: "cancel_timeout".into(),
                            timeout_ms: None,
                        },
                        now,
                    )
                    .await;
                return Err(session_error(
                    PluginSessionErrorCode::ControlTimeout,
                    "Plugin session cancellation exceeded its deadline; session close was requested.",
                    &session,
                ));
            }
        }
        let entry = self
            .sessions
            .get_mut(&session.session_id)
            .expect("entry checked");
        entry.cancelled_calls.insert(call_id);
        entry.view.last_used_at = now;
        Ok(entry.view.clone())
    }

    pub async fn close(
        &mut self,
        request: AgentSessionCloseAgentRequest,
        now: DateTime<Utc>,
    ) -> Result<AgentSessionView, PluginSessionError> {
        let timeout = request.timeout()?;
        let handle = {
            let entry = self.entry(&request.session)?;
            if entry.handle.is_none() || entry.view.health.is_terminal() {
                return Ok(entry.view.clone());
            }
            entry.handle.clone()
        };
        if let Some(entry) = self.sessions.get_mut(&request.session.session_id) {
            entry.view.health = PluginSessionHealth::Closing;
            entry.view.last_used_at = now;
        }
        let close_error = if let Some(handle) = handle {
            match tokio::time::timeout(timeout, handle.close(request.reason.clone())).await {
                Ok(Ok(())) => None,
                Ok(Err(error)) => Some(error),
                Err(_) => Some(session_error(
                    PluginSessionErrorCode::CloseTimeout,
                    "Plugin session close exceeded the bounded shutdown deadline.",
                    &request.session,
                )),
            }
        } else {
            None
        };
        let entry = self
            .sessions
            .get_mut(&request.session.session_id)
            .expect("entry checked");
        entry.handle = None;
        entry.view.health = if close_error.is_some() {
            PluginSessionHealth::Failed
        } else {
            PluginSessionHealth::Closed
        };
        entry.view.last_used_at = now;
        let view = entry.view.clone();
        if let Some(error) = close_error {
            Err(error)
        } else {
            Ok(view)
        }
    }

    pub async fn close_all(&mut self, reason: PluginSessionReason, now: DateTime<Utc>) {
        let sessions = self
            .sessions
            .values()
            .filter(|entry| entry.handle.is_some())
            .map(|entry| entry.view.session.clone())
            .collect::<Vec<_>>();
        for session in sessions {
            let _ = self
                .close(
                    AgentSessionCloseAgentRequest {
                        session,
                        reason: reason.clone(),
                        timeout_ms: None,
                    },
                    now,
                )
                .await;
        }
    }

    async fn expire(&mut self, now: DateTime<Utc>) {
        let expired = self
            .sessions
            .values()
            .filter(|entry| entry.handle.is_some() && entry.view.lease_expires_at <= now)
            .map(|entry| entry.view.session.clone())
            .collect::<Vec<_>>();
        for session in expired {
            let _ = self
                .close(
                    AgentSessionCloseAgentRequest {
                        session,
                        reason: "lease_expired".into(),
                        timeout_ms: None,
                    },
                    now,
                )
                .await;
        }
    }

    fn entry(&self, reference: &AgentSessionRef) -> Result<&HostedSession, PluginSessionError> {
        let entry = self.sessions.get(&reference.session_id).ok_or_else(|| {
            session_error(
                PluginSessionErrorCode::NotFound,
                "Agent session was not found.",
                reference,
            )
        })?;
        self.validate_entry(entry, reference)?;
        Ok(entry)
    }

    fn active_entry(
        &self,
        reference: &AgentSessionRef,
        now: DateTime<Utc>,
    ) -> Result<&HostedSession, PluginSessionError> {
        let entry = self.entry(reference)?;
        if entry.view.health.is_terminal() || entry.view.lease_expires_at <= now {
            return Err(session_error(
                PluginSessionErrorCode::Expired,
                "Agent session is closed or expired.",
                reference,
            ));
        }
        Ok(entry)
    }

    fn validate_entry(
        &self,
        entry: &HostedSession,
        reference: &AgentSessionRef,
    ) -> Result<(), PluginSessionError> {
        if entry.view.session.generation != reference.generation {
            return Err(session_error(
                PluginSessionErrorCode::Stale,
                "Agent session generation is stale.",
                reference,
            ));
        }
        entry.view.binding.validate(
            &self.grant_id,
            &self.profile_id,
            &self.plugin_id,
            self.host_generation,
        )
    }

    fn validate_capability(&self, capability: &str) -> Result<(), PluginSessionError> {
        let Some((plugin, _)) = capability.split_once('.') else {
            return Err(PluginSessionError::new(
                PluginSessionErrorCode::PolicyDenied,
                "Session capabilities must be qualified with a plugin ID.",
            ));
        };
        if plugin != self.plugin_id || !capability_allowed(&self.allowed_capabilities, capability) {
            return Err(PluginSessionError::new(
                PluginSessionErrorCode::PolicyDenied,
                "Capability is outside the active agent grant.",
            ));
        }
        Ok(())
    }
}

fn capability_allowed(allowed_capabilities: &[String], capability: &str) -> bool {
    let operation = capability
        .split_once('.')
        .map(|(_, operation)| operation)
        .unwrap_or(capability);
    allowed_capabilities
        .iter()
        .any(|allowed| allowed == "*" || allowed == capability || allowed == operation)
}

fn session_error(
    code: PluginSessionErrorCode,
    message: impl Into<String>,
    reference: &AgentSessionRef,
) -> PluginSessionError {
    PluginSessionError::new(code, message).with_session_id(reference.session_id.clone())
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;
    use chrono::Duration;
    use serde_json::json;

    use super::*;

    struct MockHandle {
        events: Arc<Mutex<Vec<String>>>,
        call_delay: StdDuration,
        cancel_delay: StdDuration,
        close_delay: StdDuration,
        drops: Arc<AtomicUsize>,
    }

    impl Drop for MockHandle {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[async_trait]
    impl PluginAgentSession for MockHandle {
        async fn call(
            &self,
            request: AgentSessionCallRequest,
        ) -> Result<AgentSessionCallResult, PluginSessionError> {
            let call_id = request.call_id.clone();
            if !self.call_delay.is_zero() {
                tokio::time::sleep(self.call_delay).await;
            }
            self.events
                .lock()
                .expect("events")
                .push(format!("call:{}", request.capability));
            AgentSessionCallResult::bounded(call_id, json!({ "ok": true }), 1024)
        }

        async fn health(&self) -> Result<PluginSessionHealth, PluginSessionError> {
            Ok(PluginSessionHealth::Ready)
        }

        async fn cancel(&self, call_id: &str) -> Result<(), PluginSessionError> {
            self.events
                .lock()
                .expect("events")
                .push(format!("cancel:{call_id}"));
            if !self.cancel_delay.is_zero() {
                tokio::time::sleep(self.cancel_delay).await;
            }
            Ok(())
        }

        async fn close(&self, reason: PluginSessionReason) -> Result<(), PluginSessionError> {
            self.events
                .lock()
                .expect("events")
                .push(format!("close:{reason}"));
            if !self.close_delay.is_zero() {
                tokio::time::sleep(self.close_delay).await;
            }
            Ok(())
        }
    }

    struct MockFactory {
        events: Arc<Mutex<Vec<String>>>,
        call_delay: StdDuration,
        cancel_delay: StdDuration,
        close_delay: StdDuration,
        drops: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl PluginAgentSessionFactory for MockFactory {
        fn plugin_id(&self) -> &str {
            "ssh"
        }

        async fn open(
            &self,
            _context: AgentSessionOpenContext,
        ) -> Result<Arc<dyn PluginAgentSession>, PluginSessionError> {
            self.events.lock().expect("events").push("open".into());
            Ok(Arc::new(MockHandle {
                events: Arc::clone(&self.events),
                call_delay: self.call_delay,
                cancel_delay: self.cancel_delay,
                close_delay: self.close_delay,
                drops: Arc::clone(&self.drops),
            }))
        }
    }

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-07-11T00:00:00Z")
            .expect("time")
            .with_timezone(&Utc)
    }

    fn host(events: Arc<Mutex<Vec<String>>>) -> AgentSessionHost {
        host_with_delay(events, StdDuration::ZERO)
    }

    fn host_with_delay(
        events: Arc<Mutex<Vec<String>>>,
        call_delay: StdDuration,
    ) -> AgentSessionHost {
        host_with_control_delays(
            events,
            Arc::new(AtomicUsize::new(0)),
            call_delay,
            StdDuration::ZERO,
            StdDuration::ZERO,
        )
    }

    fn host_with_control_delays(
        events: Arc<Mutex<Vec<String>>>,
        drops: Arc<AtomicUsize>,
        call_delay: StdDuration,
        cancel_delay: StdDuration,
        close_delay: StdDuration,
    ) -> AgentSessionHost {
        let mut host = AgentSessionHost::new(
            "grant-1",
            "profile-1",
            "ssh",
            vec!["ssh.exec".into()],
            now() + Duration::minutes(5),
            9,
        );
        host.register_factory(Arc::new(MockFactory {
            events,
            call_delay,
            cancel_delay,
            close_delay,
            drops,
        }));
        host
    }

    fn open_request() -> AgentSessionOpenRequest {
        AgentSessionOpenRequest {
            purpose: voidb_core::PluginSessionPurpose::InteractiveTerminal,
            capabilities: vec!["ssh.exec".into()],
            lease_seconds: 60,
            concurrency: AgentSessionConcurrency::Serialized,
            destructive_acknowledged: false,
            input: Value::Null,
        }
    }

    #[tokio::test]
    async fn host_keeps_one_handle_across_calls_and_closes_it() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut host = host(Arc::clone(&events));
        let view = host.open(open_request(), now()).await.expect("open");
        let result = host
            .call(
                AgentSessionCallRequest {
                    session: view.session.clone(),
                    call_id: "call-1".into(),
                    capability: "ssh.exec".into(),
                    input: json!({ "command": "pwd" }),
                    destructive_acknowledged: true,
                    timeout_ms: Some(1000),
                    output_limit_bytes: 1024,
                },
                now() + Duration::seconds(1),
            )
            .await
            .expect("call");
        assert_eq!(result.output, json!({ "ok": true }));
        host.close(
            AgentSessionCloseAgentRequest {
                session: view.session,
                reason: "user_closed".into(),
                timeout_ms: None,
            },
            now() + Duration::seconds(2),
        )
        .await
        .expect("close");
        assert_eq!(
            *events.lock().expect("events"),
            vec!["open", "call:ssh.exec", "close:user_closed"]
        );
    }

    #[tokio::test]
    async fn host_rejects_capability_escape_and_stale_generation() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut host = host(events);
        let error = host
            .open(
                AgentSessionOpenRequest {
                    capabilities: vec!["ssh.forward_open".into()],
                    ..open_request()
                },
                now(),
            )
            .await
            .expect_err("capability escape");
        assert_eq!(error.code, PluginSessionErrorCode::PolicyDenied);

        let view = host.open(open_request(), now()).await.expect("open");
        let error = host
            .status(
                AgentSessionStatusRequest {
                    session: AgentSessionRef::new(view.session.session_id, 99),
                },
                now(),
            )
            .await
            .expect_err("stale generation");
        assert_eq!(error.code, PluginSessionErrorCode::Stale);
    }

    #[tokio::test]
    async fn lease_expiry_closes_live_handle() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut host = host(Arc::clone(&events));
        let view = host.open(open_request(), now()).await.expect("open");
        let sessions = host
            .list(
                AgentSessionListRequest {
                    purpose: None,
                    include_terminal: false,
                },
                now() + Duration::seconds(61),
            )
            .await;
        assert!(sessions.is_empty());
        let status = host
            .status(
                AgentSessionStatusRequest {
                    session: view.session,
                },
                now() + Duration::seconds(61),
            )
            .await
            .expect("terminal status");
        assert_eq!(status.health, PluginSessionHealth::Closed);
        assert!(
            events
                .lock()
                .expect("events")
                .contains(&"close:lease_expired".into())
        );
    }

    #[tokio::test]
    async fn call_timeout_requests_cancellation_and_close_all_is_bounded() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let mut host = host_with_delay(Arc::clone(&events), StdDuration::from_millis(50));
        let view = host.open(open_request(), now()).await.expect("open");
        let error = host
            .call(
                AgentSessionCallRequest {
                    session: view.session,
                    call_id: "call-timeout".into(),
                    capability: "ssh.exec".into(),
                    input: json!({ "command": "sleep 1" }),
                    destructive_acknowledged: true,
                    timeout_ms: Some(1),
                    output_limit_bytes: 1024,
                },
                now(),
            )
            .await
            .expect_err("timeout");
        assert_eq!(error.code, PluginSessionErrorCode::TimedOut);
        host.close_all("uses_exhausted".into(), now()).await;
        assert_eq!(
            *events.lock().expect("events"),
            vec!["open", "cancel:call-timeout", "close:uses_exhausted"]
        );
    }

    #[tokio::test]
    async fn repeated_cancel_and_close_requests_are_idempotent() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let drops = Arc::new(AtomicUsize::new(0));
        let mut host = host_with_control_delays(
            Arc::clone(&events),
            Arc::clone(&drops),
            StdDuration::ZERO,
            StdDuration::ZERO,
            StdDuration::ZERO,
        );
        let view = host.open(open_request(), now()).await.expect("open");
        let cancel = AgentSessionCancelRequest {
            session: view.session.clone(),
            call_id: "call:caller-owned".into(),
            timeout_ms: None,
        };
        host.cancel(cancel.clone(), now()).await.expect("cancel");
        host.cancel(cancel, now()).await.expect("repeat cancel");

        let close = AgentSessionCloseAgentRequest {
            session: view.session,
            reason: "user_closed".into(),
            timeout_ms: None,
        };
        let closed = host.close(close.clone(), now()).await.expect("close");
        assert_eq!(closed.health, PluginSessionHealth::Closed);
        let repeated = host.close(close, now()).await.expect("repeat close");
        assert_eq!(repeated.health, PluginSessionHealth::Closed);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(
            *events.lock().expect("events"),
            vec!["open", "cancel:call:caller-owned", "close:user_closed"]
        );
    }

    #[tokio::test]
    async fn control_deadlines_escalate_and_drop_the_live_handle_once() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let drops = Arc::new(AtomicUsize::new(0));
        let mut host = host_with_control_delays(
            Arc::clone(&events),
            Arc::clone(&drops),
            StdDuration::ZERO,
            StdDuration::from_millis(50),
            StdDuration::from_millis(50),
        );
        let view = host.open(open_request(), now()).await.expect("open");
        let error = host
            .cancel(
                AgentSessionCancelRequest {
                    session: view.session.clone(),
                    call_id: "call:blocked".into(),
                    timeout_ms: Some(1),
                },
                now(),
            )
            .await
            .expect_err("cancel timeout");
        assert_eq!(error.code, PluginSessionErrorCode::ControlTimeout);

        let status = host
            .status(
                AgentSessionStatusRequest {
                    session: view.session.clone(),
                },
                now(),
            )
            .await
            .expect("terminal status");
        assert_eq!(status.health, PluginSessionHealth::Closed);
        let repeated = host
            .close(
                AgentSessionCloseAgentRequest {
                    session: view.session,
                    reason: "repeat".into(),
                    timeout_ms: Some(1),
                },
                now(),
            )
            .await
            .expect("idempotent terminal close");
        assert_eq!(repeated.health, PluginSessionHealth::Closed);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(
            *events.lock().expect("events"),
            vec!["open", "cancel:call:blocked", "close:cancel_timeout"]
        );
    }

    #[tokio::test]
    async fn close_timeout_marks_failed_and_still_releases_the_handle() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let drops = Arc::new(AtomicUsize::new(0));
        let mut host = host_with_control_delays(
            Arc::clone(&events),
            Arc::clone(&drops),
            StdDuration::ZERO,
            StdDuration::ZERO,
            StdDuration::from_millis(50),
        );
        let view = host.open(open_request(), now()).await.expect("open");
        let close = AgentSessionCloseAgentRequest {
            session: view.session,
            reason: "shutdown".into(),
            timeout_ms: Some(1),
        };
        let error = host
            .close(close.clone(), now())
            .await
            .expect_err("close timeout");
        assert_eq!(error.code, PluginSessionErrorCode::CloseTimeout);
        let repeated = host.close(close, now()).await.expect("repeat close");
        assert_eq!(repeated.health, PluginSessionHealth::Failed);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_eq!(
            *events.lock().expect("events"),
            vec!["open", "close:shutdown"]
        );
    }
}
