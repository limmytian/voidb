#![cfg_attr(not(unix), allow(unused_imports))]

use crate::agent_session_host::{AgentSessionHost, PreparedAgentSessionCall};
use crate::builtin::invoke::{resolved_authorization_capabilities, resolved_capability_risk};
use anyhow::{Context, anyhow, bail};
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Mutex as AsyncMutex, watch};
#[cfg(unix)]
use tokio::task::JoinSet;
use uuid::Uuid;
use voidb_core::{
    AGENT_BROKER_PROTOCOL_VERSION, AGENT_BROKER_SUPPORTED_PROTOCOL_VERSIONS,
    AgentSessionCallRequest, AgentSessionCallStatusRequest, AgentSessionCallView,
    AgentSessionCallWaitRequest, AgentSessionCancelRequest, AgentSessionCloseAgentRequest,
    AgentSessionControlDisposition, AgentSessionControlKind, AgentSessionListRequest,
    AgentSessionOpenRequest, AgentSessionRef, AppConfig, AuditOperation, CapabilityDefinition,
    CapabilityExecutionMode, MAX_AGENT_GRANT_TTL_MINUTES, MAX_AGENT_GRANT_USES,
    MAX_AGENT_SESSION_CONTROL_TIMEOUT_MS, PluginSessionError, PluginSessionErrorCode,
    VOIDB_MASTER_PASSWORD_ENV, authorize_normalized_operation,
    is_supported_agent_broker_protocol_version, normalize_agent_operation,
};

use super::audit::{AgentSessionAuditContext, append_agent_audit, append_agent_session_audit};
use super::commands::execution_mode_name;
use super::ledger::AgentGrantFile;
use super::session::{command_allowed, has_long_option, request_requires_current_broker_protocol};
use super::wire::{
    BrokerCallEntry, BrokerCallRegistry, BrokerRequest, BrokerResponse, BrokerWireRequest,
};
use super::{BROKER_CHILD_ENV, BROKER_PROBE_TIMEOUT, BROKER_READY_TIMEOUT, GRANT_VERSION};

struct BrokerMutableState {
    grant: AgentGrantFile,
    session_host: AgentSessionHost,
}

struct BrokerStartedCall {
    entry: Arc<BrokerCallEntry>,
    grant: AgentGrantFile,
}

struct BrokerRuntime {
    grant_path: PathBuf,
    state: AsyncMutex<BrokerMutableState>,
    calls: BrokerCallRegistry,
    password: AsyncMutex<String>,
    shutdown_tx: watch::Sender<Option<String>>,
}

impl BrokerRuntime {
    fn new(
        grant_path: PathBuf,
        grant: AgentGrantFile,
        session_host: AgentSessionHost,
        password: String,
    ) -> Self {
        let (shutdown_tx, _) = watch::channel(None);
        Self {
            grant_path,
            state: AsyncMutex::new(BrokerMutableState {
                grant,
                session_host,
            }),
            calls: BrokerCallRegistry::default(),
            password: AsyncMutex::new(password),
            shutdown_tx,
        }
    }

    fn subscribe_shutdown(&self) -> watch::Receiver<Option<String>> {
        self.shutdown_tx.subscribe()
    }

    fn request_shutdown(&self, reason: impl Into<String>) {
        let _ = self.shutdown_tx.send(Some(reason.into()));
    }

    async fn grant_snapshot(&self) -> AgentGrantFile {
        self.state.lock().await.grant.clone()
    }

    async fn dispatch(
        self: &Arc<Self>,
        request: BrokerRequest,
    ) -> (BrokerResponse, Option<String>) {
        match request {
            BrokerRequest::SessionCall { token, request } => {
                (self.session_call(token, request).await, None)
            }
            BrokerRequest::SessionCallStart { token, request } => {
                (self.session_call_start(token, request).await, None)
            }
            BrokerRequest::SessionCallStatus { token, request } => {
                (self.session_call_status(token, request).await, None)
            }
            BrokerRequest::SessionCallWait { token, request } => {
                (self.session_call_wait(token, request).await, None)
            }
            BrokerRequest::SessionCancel { token, request } => {
                (self.session_cancel(token, request).await, None)
            }
            BrokerRequest::SessionClose { token, request } => {
                (self.session_close(token, request).await, None)
            }
            request => self.dispatch_serialized(request).await,
        }
    }

    async fn dispatch_serialized(
        &self,
        request: BrokerRequest,
    ) -> (BrokerResponse, Option<String>) {
        let explicit_shutdown = matches!(&request, BrokerRequest::Shutdown { .. });
        let consumes_use = matches!(
            &request,
            BrokerRequest::Run { .. } | BrokerRequest::SessionOpen { .. }
        );
        let mut state = self.state.lock().await;
        if consumes_use && !grant_accepts_new_work(&state.grant) {
            return (
                broker_session_error(
                    &state.grant,
                    "session.expired",
                    "Agent grant has expired or has no remaining uses.",
                ),
                None,
            );
        }
        let BrokerMutableState {
            grant,
            session_host,
        } = &mut *state;
        let (response, terminate) =
            handle_broker_request(grant, session_host, &self.password.lock().await, request).await;
        let _ = write_grant(&self.grant_path, grant);
        let shutdown_reason = (explicit_shutdown && terminate).then(|| "user_revoked".into());
        (response, shutdown_reason)
    }

    async fn session_call_start(
        self: &Arc<Self>,
        token: String,
        request: AgentSessionCallRequest,
    ) -> BrokerResponse {
        match self.start_call(token, request).await {
            Ok(started) => session_result(&started.grant, Ok(started.entry.snapshot())),
            Err(response) => response,
        }
    }

    async fn session_call(
        self: &Arc<Self>,
        token: String,
        request: AgentSessionCallRequest,
    ) -> BrokerResponse {
        let started = match self.start_call(token, request).await {
            Ok(started) => started,
            Err(response) => return response,
        };
        let call = self.calls.wait_until_terminal(&started.entry).await;
        let grant = self.grant_snapshot().await;
        terminal_call_response(&grant, call)
    }

    async fn start_call(
        self: &Arc<Self>,
        token: String,
        request: AgentSessionCallRequest,
    ) -> Result<BrokerStartedCall, BrokerResponse> {
        let started_at = Utc::now();
        let session = request.session.clone();
        let capability = request.capability.clone();
        let call_id = request.call_id.clone();
        let (prepared, entry, grant) = {
            let mut state = self.state.lock().await;
            if token != state.grant.token {
                return Err(invalid_token_response(&state.grant).0);
            }
            if !grant_accepts_new_work(&state.grant) {
                return Err(broker_session_error(
                    &state.grant,
                    "session.expired",
                    "Agent grant has expired or has no remaining uses.",
                ));
            }
            if let Err(error) = request.validate_call_id() {
                let response =
                    broker_session_error(&state.grant, error.code.as_str(), error.to_string());
                append_agent_session_audit(
                    &state.grant,
                    AuditOperation::SessionCall,
                    &response,
                    AgentSessionAuditContext {
                        session: Some(&session),
                        capability: Some(&capability),
                        ..AgentSessionAuditContext::default()
                    },
                    started_at,
                );
                return Err(response);
            }
            if let Err(error) = session_call_allowed(&state.grant, &request) {
                let response =
                    broker_session_error(&state.grant, "session.policy_denied", error.to_string());
                append_agent_session_audit(
                    &state.grant,
                    AuditOperation::SessionCall,
                    &response,
                    AgentSessionAuditContext {
                        session: Some(&session),
                        call_id: Some(&call_id),
                        capability: Some(&capability),
                        ..AgentSessionAuditContext::default()
                    },
                    started_at,
                );
                return Err(response);
            }
            let prepared = match state.session_host.prepare_call(&request, started_at).await {
                Ok(prepared) => prepared,
                Err(error) => {
                    let response =
                        broker_session_error(&state.grant, error.code.as_str(), error.to_string());
                    append_agent_session_audit(
                        &state.grant,
                        AuditOperation::SessionCall,
                        &response,
                        AgentSessionAuditContext {
                            session: Some(&session),
                            call_id: Some(&call_id),
                            capability: Some(&capability),
                            ..AgentSessionAuditContext::default()
                        },
                        started_at,
                    );
                    return Err(response);
                }
            };
            let entry = match self
                .calls
                .register(&request, started_at, prepared.deadline_at())
            {
                Ok(entry) => entry,
                Err(error) => {
                    state
                        .session_host
                        .finish_prepared_call(&request.session, Utc::now());
                    let response =
                        broker_session_error(&state.grant, error.code.as_str(), error.to_string());
                    append_agent_session_audit(
                        &state.grant,
                        AuditOperation::SessionCall,
                        &response,
                        AgentSessionAuditContext {
                            session: Some(&session),
                            call_id: Some(&call_id),
                            capability: Some(&capability),
                            ..AgentSessionAuditContext::default()
                        },
                        started_at,
                    );
                    return Err(response);
                }
            };
            consume_agent_use(
                &mut state.grant,
                "session",
                "call",
                Some(&request.capability),
            );
            if let Err(error) = write_grant(&self.grant_path, &state.grant) {
                state
                    .session_host
                    .finish_prepared_call(&request.session, Utc::now());
                self.calls.finish(
                    &entry,
                    Err(PluginSessionError::new(
                        PluginSessionErrorCode::OwnerUnavailable,
                        format!("Persist agent grant use: {error}"),
                    )),
                    Utc::now(),
                );
                return Err(broker_session_error(
                    &state.grant,
                    "session.owner_unavailable",
                    "Agent broker could not persist the grant use reservation.",
                ));
            }
            (prepared, entry, state.grant.clone())
        };
        self.spawn_call(request, prepared, Arc::clone(&entry), started_at);
        Ok(BrokerStartedCall { entry, grant })
    }

    fn spawn_call(
        self: &Arc<Self>,
        request: AgentSessionCallRequest,
        prepared: PreparedAgentSessionCall,
        entry: Arc<BrokerCallEntry>,
        accepted_at: DateTime<Utc>,
    ) {
        let runtime = Arc::clone(self);
        let task_entry = Arc::clone(&entry);
        let task = tokio::spawn(async move {
            let serialized = tokio::select! {
                biased;
                _ = task_entry.wait_for_control() => None,
                serialized = prepared.acquire_serialized() => Some(serialized),
            };
            let result = if let Some(_serialized) = serialized {
                let may_run = {
                    let state = runtime.state.lock().await;
                    state
                        .session_host
                        .call_is_active(&request.session, prepared.current_time())
                        .is_ok()
                } && runtime
                    .calls
                    .mark_running(&task_entry, prepared.current_time());
                if may_run {
                    prepared.execute(request.clone()).await
                } else {
                    Err(PluginSessionError::new(
                        PluginSessionErrorCode::Cancelled,
                        "Session call was stopped before execution began.",
                    )
                    .with_session_id(request.session.session_id.clone()))
                }
            } else {
                Err(PluginSessionError::new(
                    PluginSessionErrorCode::Cancelled,
                    "Session call was stopped before execution began.",
                )
                .with_session_id(request.session.session_id.clone()))
            };
            {
                let mut state = runtime.state.lock().await;
                state
                    .session_host
                    .finish_prepared_call(&request.session, prepared.current_time());
            }
            let call = runtime.calls.finish(&task_entry, result, Utc::now());
            let grant = runtime.grant_snapshot().await;
            let response = terminal_call_response(&grant, call);
            append_agent_session_audit(
                &grant,
                AuditOperation::SessionCall,
                &response,
                AgentSessionAuditContext {
                    session: Some(&request.session),
                    call_id: Some(&request.call_id),
                    capability: Some(&request.capability),
                    ..AgentSessionAuditContext::default()
                },
                accepted_at,
            );
        });
        entry.set_abort_handle(task.abort_handle());
        drop(task);
    }

    fn abort_calls_and_release_host_reservations(
        &self,
        session_host: &mut AgentSessionHost,
        entries: &[Arc<BrokerCallEntry>],
        completed_at: DateTime<Utc>,
    ) {
        self.calls.abort_entries(entries, completed_at);
        for entry in entries {
            session_host.finish_prepared_call(&entry.snapshot().session, completed_at);
        }
    }

    async fn authorized_grant(&self, token: &str) -> Result<AgentGrantFile, BrokerResponse> {
        let state = self.state.lock().await;
        if token == state.grant.token {
            Ok(state.grant.clone())
        } else {
            Err(invalid_token_response(&state.grant).0)
        }
    }

    async fn session_call_status(
        &self,
        token: String,
        request: AgentSessionCallStatusRequest,
    ) -> BrokerResponse {
        let grant = match self.authorized_grant(&token).await {
            Ok(grant) => grant,
            Err(response) => return response,
        };
        let started_at = Utc::now();
        let response = session_result(&grant, self.calls.snapshot(&request));
        append_agent_session_audit(
            &grant,
            AuditOperation::SessionStatus,
            &response,
            AgentSessionAuditContext {
                session: Some(&request.session),
                call_id: Some(&request.call_id),
                ..AgentSessionAuditContext::default()
            },
            started_at,
        );
        response
    }

    async fn session_call_wait(
        &self,
        token: String,
        request: AgentSessionCallWaitRequest,
    ) -> BrokerResponse {
        let grant = match self.authorized_grant(&token).await {
            Ok(grant) => grant,
            Err(response) => return response,
        };
        let started_at = Utc::now();
        let response = session_result(&grant, self.calls.wait(&request).await);
        append_agent_session_audit(
            &grant,
            AuditOperation::SessionStatus,
            &response,
            AgentSessionAuditContext {
                session: Some(&request.session),
                call_id: Some(&request.call_id),
                ..AgentSessionAuditContext::default()
            },
            started_at,
        );
        response
    }

    async fn session_cancel(
        &self,
        token: String,
        request: AgentSessionCancelRequest,
    ) -> BrokerResponse {
        let started_at = Utc::now();
        let grant = match self.authorized_grant(&token).await {
            Ok(grant) => grant,
            Err(response) => return response,
        };
        let (disposition, call) = match self.calls.request_control(
            &request.session,
            &request.call_id,
            AgentSessionControlKind::Cancel,
            started_at,
        ) {
            Ok(control) => control,
            Err(error) => {
                let response = broker_session_error(&grant, error.code.as_str(), error.to_string());
                append_agent_session_audit(
                    &grant,
                    AuditOperation::SessionCancel,
                    &response,
                    AgentSessionAuditContext {
                        session: Some(&request.session),
                        call_id: Some(&request.call_id),
                        ..AgentSessionAuditContext::default()
                    },
                    started_at,
                );
                return response;
            }
        };
        if matches!(
            disposition,
            AgentSessionControlDisposition::AlreadyRequested
                | AgentSessionControlDisposition::AlreadyTerminal
        ) {
            return broker_data_response(
                &grant,
                json!({ "call": call, "control_disposition": disposition }),
            );
        }
        let mut state = self.state.lock().await;
        let BrokerMutableState {
            grant,
            session_host,
        } = &mut *state;
        let (mut response, _) = handle_broker_request(
            grant,
            session_host,
            &self.password.lock().await,
            BrokerRequest::SessionCancel {
                token,
                request: request.clone(),
            },
        )
        .await;
        let _ = write_grant(&self.grant_path, grant);
        let session_data = response.data.take();
        let mut close_escalated = false;
        if !response.ok {
            close_escalated = true;
            let controlled = self.calls.request_session_control(
                &request.session,
                AgentSessionControlKind::Close,
                Utc::now(),
            );
            let _ = session_host
                .close(
                    AgentSessionCloseAgentRequest {
                        session: request.session.clone(),
                        reason: "cancel_failed".into(),
                        timeout_ms: None,
                    },
                    Utc::now(),
                )
                .await;
            self.abort_calls_and_release_host_reservations(session_host, &controlled, Utc::now());
        }
        response.data = Some(json!({
            "session": session_data,
            "call": self.calls.entry(&request.session, &request.call_id).map(|entry| entry.snapshot()).ok(),
            "control_disposition": disposition,
            "close_escalated": close_escalated,
        }));
        response
    }

    async fn session_close(
        &self,
        token: String,
        request: AgentSessionCloseAgentRequest,
    ) -> BrokerResponse {
        if let Err(response) = self.authorized_grant(&token).await {
            return response;
        }
        let controlled = self.calls.request_session_control(
            &request.session,
            AgentSessionControlKind::Close,
            Utc::now(),
        );
        let mut state = self.state.lock().await;
        let BrokerMutableState {
            grant,
            session_host,
        } = &mut *state;
        let (mut response, _) = handle_broker_request(
            grant,
            session_host,
            &self.password.lock().await,
            BrokerRequest::SessionClose { token, request },
        )
        .await;
        let _ = write_grant(&self.grant_path, grant);
        self.abort_calls_and_release_host_reservations(session_host, &controlled, Utc::now());
        let session_data = response.data.take();
        response.data = Some(json!({
            "session": session_data,
            "calls": BrokerCallRegistry::snapshots(&controlled),
        }));
        response
    }

    async fn shutdown(&self, reason: &str) -> AgentGrantFile {
        let controlled = self
            .calls
            .request_all_control(AgentSessionControlKind::Shutdown, Utc::now());
        let mut state = self.state.lock().await;
        let close_all = state.session_host.close_all(reason.into(), Utc::now());
        let _ = tokio::time::timeout(
            Duration::from_millis(MAX_AGENT_SESSION_CONTROL_TIMEOUT_MS),
            close_all,
        )
        .await;
        self.abort_calls_and_release_host_reservations(
            &mut state.session_host,
            &controlled,
            Utc::now(),
        );
        self.password.lock().await.clear();
        state.grant.clone()
    }
}

fn grant_accepts_new_work(grant: &AgentGrantFile) -> bool {
    grant.expires_at > Utc::now() && !grant_uses_exhausted(grant)
}

fn terminal_call_response(grant: &AgentGrantFile, call: AgentSessionCallView) -> BrokerResponse {
    if let Some(result) = call.result {
        session_result(grant, Ok(result))
    } else if let Some(error) = call.error {
        broker_session_error(grant, error.code.as_str(), error.to_string())
    } else {
        broker_session_error(
            grant,
            "session.owner_unavailable",
            "Session call reached a terminal state without a result.",
        )
    }
}

#[cfg(unix)]
pub(super) async fn run_broker(grant_path: &Path) -> anyhow::Result<()> {
    let mut password = String::new();
    tokio::io::stdin().read_to_string(&mut password).await?;
    if password.is_empty() {
        bail!("broker did not receive a master password");
    }
    let result = broker_loop(grant_path, &password).await;
    password.clear();
    result
}

#[cfg(unix)]
pub(super) async fn broker_loop(grant_path: &Path, password: &str) -> anyhow::Result<()> {
    let grant = read_grant(grant_path)?;
    let host_generation = Utc::now().timestamp_micros().unsigned_abs().max(1);
    let mut session_host = AgentSessionHost::new(
        grant.id.clone(),
        grant.profile_id.clone(),
        grant.plugin_id.clone(),
        grant.capabilities.clone(),
        grant.expires_at,
        host_generation,
    );
    register_session_factories(&mut session_host, &grant, password)?;
    broker_loop_with_host(grant_path, grant, session_host, password).await
}

#[cfg(unix)]
pub(super) async fn broker_loop_with_host(
    grant_path: &Path,
    grant: AgentGrantFile,
    session_host: AgentSessionHost,
    password: &str,
) -> anyhow::Result<()> {
    let _ = fs::remove_file(&grant.socket_path);
    let listener = UnixListener::bind(&grant.socket_path)?;
    fs::set_permissions(&grant.socket_path, fs::Permissions::from_mode(0o600))?;

    let socket_path = grant.socket_path.clone();
    let runtime = Arc::new(BrokerRuntime::new(
        grant_path.to_path_buf(),
        grant,
        session_host,
        password.to_owned(),
    ));
    let mut shutdown_rx = runtime.subscribe_shutdown();
    let mut clients = JoinSet::new();
    let release_reason = loop {
        if let Some(reason) = shutdown_rx.borrow().clone() {
            break reason;
        }
        let current_grant = runtime.grant_snapshot().await;
        let remaining = (current_grant.expires_at - Utc::now())
            .to_std()
            .unwrap_or(Duration::ZERO);
        if remaining.is_zero() {
            break "expired".to_owned();
        }
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_err() {
                    break "broker_shutdown".to_owned();
                }
            }
            accepted = listener.accept() => {
                if let Ok((stream, _)) = accepted {
                    let runtime = Arc::clone(&runtime);
                    clients.spawn(async move {
                        let _ = handle_broker_connection(runtime, stream).await;
                    });
                }
            }
            _ = tokio::time::sleep(remaining) => {}
            _ = clients.join_next(), if !clients.is_empty() => {}
        }
    };
    clients.abort_all();
    while clients.join_next().await.is_some() {}
    let grant = runtime.shutdown(&release_reason).await;
    append_agent_audit(
        &grant,
        AuditOperation::CredentialGrantReleased,
        json!({ "reason": release_reason }),
    );
    let _ = fs::remove_file(&socket_path);
    let _ = fs::remove_file(grant_path);
    Ok(())
}

#[cfg(unix)]
async fn handle_broker_connection(
    runtime: Arc<BrokerRuntime>,
    mut stream: UnixStream,
) -> anyhow::Result<()> {
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await?;
    let Ok(wire_request) = serde_json::from_slice::<BrokerWireRequest>(&bytes) else {
        return Ok(());
    };
    let selected_protocol_version = wire_request.protocol_version;
    let requires_current_protocol = request_requires_current_broker_protocol(&wire_request.request);
    let (mut response, shutdown_reason) = if is_supported_agent_broker_protocol_version(
        selected_protocol_version,
    ) && (!requires_current_protocol
        || selected_protocol_version >= AGENT_BROKER_PROTOCOL_VERSION)
    {
        runtime.dispatch(wire_request.request).await
    } else if is_supported_agent_broker_protocol_version(selected_protocol_version) {
        let grant = runtime.grant_snapshot().await;
        let mut response = broker_session_error(
            &grant,
            "session.protocol_unsupported",
            "Asynchronous session-call lifecycle operations require agent-broker protocol version 2.",
        );
        response.data = Some(json!({
            "required_protocol_version": AGENT_BROKER_PROTOCOL_VERSION,
            "selected_protocol_version": selected_protocol_version,
        }));
        (response, None)
    } else {
        let grant = runtime.grant_snapshot().await;
        let mut response = broker_session_error(
            &grant,
            "session.protocol_unsupported",
            format!("Agent broker protocol version {selected_protocol_version} is unsupported."),
        );
        response.data = Some(json!({
            "supported_protocol_versions": AGENT_BROKER_SUPPORTED_PROTOCOL_VERSIONS,
        }));
        (response, None)
    };
    response.protocol_version =
        if is_supported_agent_broker_protocol_version(selected_protocol_version) {
            selected_protocol_version
        } else {
            AGENT_BROKER_PROTOCOL_VERSION
        };
    if stream
        .write_all(&serde_json::to_vec(&response)?)
        .await
        .is_ok()
    {
        // A client may close immediately after receiving the response. A
        // BrokenPipe during the best-effort shutdown belongs to this one
        // socket and must not terminate the long-lived broker.
        let _ = stream.shutdown().await;
    }
    if let Some(reason) = shutdown_reason {
        runtime.request_shutdown(reason);
    }
    Ok(())
}

#[cfg(not(unix))]
pub(super) async fn run_broker(_grant_path: &Path) -> anyhow::Result<()> {
    bail!("agent broker currently requires a Unix-domain socket platform")
}

#[cfg(not(unix))]
pub(super) async fn broker_loop_with_host(
    _grant_path: &Path,
    _grant: AgentGrantFile,
    _session_host: AgentSessionHost,
    _password: &str,
) -> anyhow::Result<()> {
    bail!("agent broker currently requires a Unix-domain socket platform")
}

pub(super) async fn handle_broker_request(
    grant: &mut AgentGrantFile,
    session_host: &mut AgentSessionHost,
    password: &str,
    request: BrokerRequest,
) -> (BrokerResponse, bool) {
    match request {
        BrokerRequest::Inspect { token } => {
            if token != grant.token {
                return invalid_token_response(grant);
            }
            let sessions = session_host
                .list(AgentSessionListRequest::default(), Utc::now())
                .await;
            (
                broker_data_response(
                    grant,
                    json!({
                        "active_session_count": sessions.len(),
                        "broker": "online",
                    }),
                ),
                false,
            )
        }
        BrokerRequest::RenewGrant {
            token,
            expires_at,
            remaining_uses,
        } => {
            if token != grant.token {
                return invalid_token_response(grant);
            }
            let now = Utc::now();
            let maximum_expiry =
                now + chrono::Duration::minutes(MAX_AGENT_GRANT_TTL_MINUTES as i64);
            if expires_at <= now
                || expires_at > maximum_expiry
                || remaining_uses.is_some_and(|uses| !(1..=MAX_AGENT_GRANT_USES).contains(&uses))
            {
                return (
                    broker_response(
                        grant,
                        Some("grant renewal limits are invalid".into()),
                        6,
                        String::new(),
                        String::new(),
                    ),
                    false,
                );
            }
            grant.expires_at = expires_at;
            grant.remaining_uses = remaining_uses;
            session_host.renew_grant(expires_at);
            append_agent_audit(
                grant,
                AuditOperation::CredentialGrantIssued,
                json!({
                    "lifecycle": "renewed",
                    "expires_at": expires_at,
                    "remaining_uses": remaining_uses,
                    "profile_id": grant.profile_id,
                    "plugin_id": grant.plugin_id,
                }),
            );
            (
                broker_data_response(grant, json!({ "renewed": true })),
                false,
            )
        }
        BrokerRequest::Shutdown { token } => {
            if token != grant.token {
                (
                    broker_response(
                        grant,
                        Some("invalid grant token".into()),
                        6,
                        String::new(),
                        String::new(),
                    ),
                    false,
                )
            } else {
                (
                    broker_response(grant, None, 0, String::new(), String::new()),
                    true,
                )
            }
        }
        BrokerRequest::Run { token, argv } => {
            if token != grant.token {
                return (
                    broker_response(
                        grant,
                        Some("invalid grant token".into()),
                        6,
                        String::new(),
                        String::new(),
                    ),
                    false,
                );
            }
            if let Err(error) = command_allowed(grant, &argv) {
                return (
                    broker_response(
                        grant,
                        Some(error.to_string()),
                        6,
                        String::new(),
                        String::new(),
                    ),
                    false,
                );
            }
            if !grant.allow_destructive
                && !has_long_option(&argv, "--dry-run")
                && let Some(capability) = invoked_capability(&argv)
                && let Err(error) = ensure_read_only_capability(capability)
            {
                return (
                    broker_response(
                        grant,
                        Some(error.to_string()),
                        6,
                        String::new(),
                        String::new(),
                    ),
                    false,
                );
            }
            decrement_grant_use(grant);
            append_agent_audit(
                grant,
                AuditOperation::CredentialGrantUsed,
                json!({
                    "remaining_uses": grant.remaining_uses,
                    "command_group": argv.first(),
                    "command": argv.get(1),
                }),
            );
            let remaining = (grant.expires_at - Utc::now())
                .to_std()
                .unwrap_or(Duration::ZERO);
            match run_scoped_child(&argv, password, remaining).await {
                Ok(output) => {
                    let exit_code = output.status.code().unwrap_or(1);
                    (
                        broker_response(
                            grant,
                            None,
                            exit_code,
                            String::from_utf8_lossy(&output.stdout).into_owned(),
                            String::from_utf8_lossy(&output.stderr).into_owned(),
                        ),
                        grant_uses_exhausted(grant),
                    )
                }
                Err(error) => (
                    broker_response(
                        grant,
                        Some(format!("start scoped VoidB command: {error}")),
                        5,
                        String::new(),
                        String::new(),
                    ),
                    grant_uses_exhausted(grant),
                ),
            }
        }
        BrokerRequest::SessionOpen { token, request } => {
            if token != grant.token {
                return invalid_token_response(grant);
            }
            let started_at = Utc::now();
            let purpose = request.purpose.clone();
            if let Err(error) = session_open_allowed(grant, &request) {
                let response =
                    broker_session_error(grant, "session.policy_denied", error.to_string());
                append_agent_session_audit(
                    grant,
                    AuditOperation::SessionOpen,
                    &response,
                    AgentSessionAuditContext {
                        purpose: Some(&purpose),
                        ..AgentSessionAuditContext::default()
                    },
                    started_at,
                );
                return (response, false);
            }
            consume_agent_use(grant, "session", "open", None);
            let response = session_result(grant, session_host.open(request, Utc::now()).await);
            let session = response_session_ref(&response);
            append_agent_session_audit(
                grant,
                AuditOperation::SessionOpen,
                &response,
                AgentSessionAuditContext {
                    session: session.as_ref(),
                    purpose: Some(&purpose),
                    ..AgentSessionAuditContext::default()
                },
                started_at,
            );
            (response, grant_uses_exhausted(grant))
        }
        BrokerRequest::SessionCall { token, request } => {
            if token != grant.token {
                return invalid_token_response(grant);
            }
            let started_at = Utc::now();
            let session = request.session.clone();
            let capability = request.capability.clone();
            let call_id = request.call_id.clone();
            if let Err(error) = request.validate_call_id() {
                let response = broker_session_error(grant, error.code.as_str(), error.to_string());
                append_agent_session_audit(
                    grant,
                    AuditOperation::SessionCall,
                    &response,
                    AgentSessionAuditContext {
                        session: Some(&session),
                        capability: Some(&capability),
                        ..AgentSessionAuditContext::default()
                    },
                    started_at,
                );
                return (response, false);
            }
            if let Err(error) = session_call_allowed(grant, &request) {
                let response =
                    broker_session_error(grant, "session.policy_denied", error.to_string());
                append_agent_session_audit(
                    grant,
                    AuditOperation::SessionCall,
                    &response,
                    AgentSessionAuditContext {
                        session: Some(&session),
                        call_id: Some(&call_id),
                        capability: Some(&capability),
                        ..AgentSessionAuditContext::default()
                    },
                    started_at,
                );
                return (response, false);
            }
            consume_agent_use(grant, "session", "call", Some(&request.capability));
            let response = session_result(grant, session_host.call(request, Utc::now()).await);
            append_agent_session_audit(
                grant,
                AuditOperation::SessionCall,
                &response,
                AgentSessionAuditContext {
                    session: Some(&session),
                    call_id: Some(&call_id),
                    capability: Some(&capability),
                    ..AgentSessionAuditContext::default()
                },
                started_at,
            );
            (response, grant_uses_exhausted(grant))
        }
        BrokerRequest::SessionCallStart { .. }
        | BrokerRequest::SessionCallStatus { .. }
        | BrokerRequest::SessionCallWait { .. } => (
            broker_session_error(
                grant,
                "session.protocol_unsupported",
                "Asynchronous session-call operations require the concurrent broker dispatcher.",
            ),
            false,
        ),
        BrokerRequest::SessionStatus { token, request } => {
            if token != grant.token {
                return invalid_token_response(grant);
            }
            let started_at = Utc::now();
            let session = request.session.clone();
            let response = session_result(grant, session_host.status(request, Utc::now()).await);
            append_agent_session_audit(
                grant,
                AuditOperation::SessionStatus,
                &response,
                AgentSessionAuditContext {
                    session: Some(&session),
                    ..AgentSessionAuditContext::default()
                },
                started_at,
            );
            (response, false)
        }
        BrokerRequest::SessionList { token, request } => {
            if token != grant.token {
                return invalid_token_response(grant);
            }
            let started_at = Utc::now();
            let purpose = request.purpose.clone();
            let sessions = session_host.list(request, Utc::now()).await;
            let response = broker_data_response(
                grant,
                json!({ "count": sessions.len(), "sessions": sessions }),
            );
            append_agent_session_audit(
                grant,
                AuditOperation::SessionList,
                &response,
                AgentSessionAuditContext {
                    purpose: purpose.as_ref(),
                    ..AgentSessionAuditContext::default()
                },
                started_at,
            );
            (response, false)
        }
        BrokerRequest::SessionRenew { token, request } => {
            if token != grant.token {
                return invalid_token_response(grant);
            }
            let started_at = Utc::now();
            let session = request.session.clone();
            let response = session_result(grant, session_host.renew(request, Utc::now()).await);
            append_agent_session_audit(
                grant,
                AuditOperation::SessionRenew,
                &response,
                AgentSessionAuditContext {
                    session: Some(&session),
                    ..AgentSessionAuditContext::default()
                },
                started_at,
            );
            (response, false)
        }
        BrokerRequest::SessionCancel { token, request } => {
            if token != grant.token {
                return invalid_token_response(grant);
            }
            let started_at = Utc::now();
            let session = request.session.clone();
            let call_id = request.call_id.clone();
            if let Err(error) = request.validate_call_id() {
                let response = broker_session_error(grant, error.code.as_str(), error.to_string());
                append_agent_session_audit(
                    grant,
                    AuditOperation::SessionCancel,
                    &response,
                    AgentSessionAuditContext {
                        session: Some(&session),
                        ..AgentSessionAuditContext::default()
                    },
                    started_at,
                );
                return (response, false);
            }
            let response = session_result(grant, session_host.cancel(request, Utc::now()).await);
            append_agent_session_audit(
                grant,
                AuditOperation::SessionCancel,
                &response,
                AgentSessionAuditContext {
                    session: Some(&session),
                    call_id: Some(&call_id),
                    ..AgentSessionAuditContext::default()
                },
                started_at,
            );
            (response, false)
        }
        BrokerRequest::SessionClose { token, request } => {
            if token != grant.token {
                return invalid_token_response(grant);
            }
            let started_at = Utc::now();
            let session = request.session.clone();
            let response = session_result(grant, session_host.close(request, Utc::now()).await);
            append_agent_session_audit(
                grant,
                AuditOperation::SessionClose,
                &response,
                AgentSessionAuditContext {
                    session: Some(&session),
                    ..AgentSessionAuditContext::default()
                },
                started_at,
            );
            (response, false)
        }
    }
}

#[cfg(not(test))]
fn register_session_factories(
    _host: &mut AgentSessionHost,
    _grant: &AgentGrantFile,
    _password: &str,
) -> anyhow::Result<()> {
    Ok(())
}

#[cfg(test)]
fn register_session_factories(
    _host: &mut AgentSessionHost,
    _grant: &AgentGrantFile,
    _password: &str,
) -> anyhow::Result<()> {
    Ok(())
}

async fn run_scoped_child(
    argv: &[String],
    password: &str,
    deadline: Duration,
) -> std::io::Result<std::process::Output> {
    let mut command = tokio::process::Command::new(
        std::env::current_exe().unwrap_or_else(|_| PathBuf::from("voidb-cli")),
    );
    command
        .args(argv)
        .env_remove(VOIDB_MASTER_PASSWORD_ENV)
        .env(BROKER_CHILD_ENV, "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let mut child = command.spawn()?;
    let stdin = child.stdin.take().ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::BrokenPipe, "open broker child input")
    })?;
    write_password_and_close(stdin, password.as_bytes()).await?;
    tokio::time::timeout(deadline, child.wait_with_output())
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "agent grant expired while the command was running",
            )
        })?
}

pub(super) async fn write_password_and_close<W>(
    mut writer: W,
    password: &[u8],
) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer.write_all(password).await?;
    writer.shutdown().await?;
    drop(writer);
    Ok(())
}

pub(super) fn invoked_capability(argv: &[String]) -> Option<&str> {
    (argv.first().map(String::as_str) == Some("invoke")
        && argv.get(1).map(String::as_str) == Some("run"))
    .then(|| argv.get(2).map(String::as_str))
    .flatten()
}

pub(super) fn ensure_read_only_capability(capability: &str) -> anyhow::Result<()> {
    let risk = resolved_capability_risk(capability)
        .map_err(|error| anyhow!("capability risk could not be verified: {error}"))?;
    if risk == voidb_core::CapabilityRiskLevel::ReadOnly {
        Ok(())
    } else {
        bail!("agent grant is read-only; capability risk is '{risk:?}'")
    }
}

pub(super) fn session_call_allowed(
    grant: &AgentGrantFile,
    request: &AgentSessionCallRequest,
) -> anyhow::Result<()> {
    let Some((plugin, operation)) = request.capability.split_once('.') else {
        bail!("session capability must be qualified");
    };
    if plugin != grant.plugin_id {
        bail!("capability plugin is outside the agent grant scope");
    }
    if !grant
        .capabilities
        .iter()
        .any(|allowed| allowed == "*" || allowed == &request.capability || allowed == operation)
    {
        bail!("capability is outside the agent grant scope");
    }
    ensure_grant_execution_mode(
        grant,
        &request.capability,
        CapabilityExecutionMode::SessionOnly,
    )?;
    let risk = resolved_capability_risk(&request.capability)
        .map_err(|error| anyhow!("capability risk could not be verified: {error}"))?;
    if risk != voidb_core::CapabilityRiskLevel::ReadOnly {
        if !grant.allow_destructive {
            bail!("agent grant is read-only; capability risk is '{risk:?}'");
        }
        if !request.destructive_acknowledged {
            bail!("session call requires --yes for capability risk '{risk:?}'");
        }
    } else if request.destructive_acknowledged && !grant.allow_destructive {
        bail!("agent grant does not permit destructive acknowledgements");
    }
    if grant.authorization_scopes.is_empty() {
        ensure_capability_wide_authorization_allowed(grant, &request.capability)?;
    } else {
        ensure_jit_operation_allowed(grant, &request.capability, request.input.clone())?;
    }
    Ok(())
}

pub(super) fn session_open_allowed(
    grant: &AgentGrantFile,
    request: &AgentSessionOpenRequest,
) -> anyhow::Result<()> {
    if !grant.execution_mode.supports_session() {
        bail!(
            "agent grant execution mode '{}' does not permit persistent sessions",
            execution_mode_name(grant.execution_mode)
        );
    }
    if request.capabilities.is_empty() {
        bail!("session open requires one or more explicit --capability values");
    }
    let mut session_family = None;
    for capability in &request.capabilities {
        let operation = capability
            .split_once('.')
            .map(|(_, operation)| operation)
            .ok_or_else(|| anyhow!("session capability must be qualified"))?;
        if !grant
            .capabilities
            .iter()
            .any(|allowed| allowed == "*" || allowed == capability || allowed == operation)
        {
            bail!("capability is outside the agent grant scope");
        }
        let definition =
            ensure_grant_execution_mode(grant, capability, CapabilityExecutionMode::SessionOnly)?;
        let handoff = definition.session_handoff.as_ref().ok_or_else(|| {
            anyhow!("capability '{capability}' has no persistent-session handoff declaration")
        })?;
        if handoff.purpose != request.purpose {
            bail!(
                "capability '{capability}' requires session purpose '{}'",
                crate::builtin::invoke::session_purpose_cli_name(&handoff.purpose)
            );
        }
        if !handoff
            .capabilities
            .iter()
            .any(|declared| declared == capability)
        {
            bail!("capability '{capability}' is outside its declared session handoff binding");
        }
        if let Some(expected) = &session_family {
            if expected != handoff {
                bail!("session capabilities must belong to one declared session handoff family");
            }
        } else {
            session_family = Some(handoff.clone());
        }
    }
    if let Some(handoff) = &session_family {
        if handoff.live_session.is_some() {
            let requested = request.capabilities.iter().collect::<BTreeSet<_>>();
            let declared = handoff.capabilities.iter().collect::<BTreeSet<_>>();
            if requested != declared {
                bail!("live sessions require the complete declared capability family at open");
            }
        }
        live_session_start_allowed(grant, request, handoff)?;
    }
    Ok(())
}

pub(super) fn live_session_start_allowed(
    grant: &AgentGrantFile,
    request: &AgentSessionOpenRequest,
    handoff: &voidb_core::CapabilitySessionHandoff,
) -> anyhow::Result<()> {
    if let Some(contract) = &handoff.live_session {
        contract
            .validate(&handoff.capabilities)
            .map_err(|error| anyhow!(error))?;
        contract
            .validate_start(&request.input)
            .map_err(|error| anyhow!(error))?;
        if contract.start_risk != voidb_core::CapabilityRiskLevel::ReadOnly {
            if !grant.allow_destructive {
                bail!(
                    "agent grant is read-only; live-session start risk is '{:?}'",
                    contract.start_risk
                );
            }
            if !request.destructive_acknowledged {
                bail!(
                    "live-session start requires --yes for risk '{:?}'",
                    contract.start_risk
                );
            }
        } else if request.destructive_acknowledged && !grant.allow_destructive {
            bail!("agent grant does not permit destructive acknowledgements");
        }
    }
    Ok(())
}

pub(super) fn ensure_grant_execution_mode(
    grant: &AgentGrantFile,
    capability: &str,
    requested_mode: CapabilityExecutionMode,
) -> anyhow::Result<CapabilityDefinition> {
    let grant_allows = match requested_mode {
        CapabilityExecutionMode::Stateless => grant.execution_mode.supports_stateless(),
        CapabilityExecutionMode::SessionOnly => grant.execution_mode.supports_session(),
        CapabilityExecutionMode::Both => grant.execution_mode == CapabilityExecutionMode::Both,
    };
    if !grant_allows {
        bail!(
            "agent grant execution mode '{}' does not permit {} execution",
            execution_mode_name(grant.execution_mode),
            execution_mode_name(requested_mode)
        );
    }
    let definitions = resolved_authorization_capabilities(Some(&grant.plugin_id))
        .map_err(|error| anyhow!("load capability execution metadata: {error}"))?;
    let definition = definitions
        .into_iter()
        .find(|definition| definition.qualified_id() == capability)
        .ok_or_else(|| anyhow!("capability has no current execution-mode declaration"))?;
    let capability_allows = match requested_mode {
        CapabilityExecutionMode::Stateless => definition.supports_stateless_execution(),
        CapabilityExecutionMode::SessionOnly => definition.supports_session_execution(),
        CapabilityExecutionMode::Both => {
            definition.supports_stateless_execution() && definition.supports_session_execution()
        }
    };
    if !capability_allows {
        bail!(
            "capability '{capability}' does not support {} execution; declared mode is '{}'",
            execution_mode_name(requested_mode),
            execution_mode_name(definition.execution_mode)
        );
    }
    Ok(definition)
}

pub(super) fn ensure_capability_wide_authorization_allowed(
    grant: &AgentGrantFile,
    capability: &str,
) -> anyhow::Result<()> {
    let definitions = resolved_authorization_capabilities(Some(&grant.plugin_id))
        .map_err(|error| anyhow!("load capability authorization metadata: {error}"))?;
    let definition = definitions
        .iter()
        .find(|definition| definition.qualified_id() == capability)
        .ok_or_else(|| anyhow!("capability has no current authorization declaration"))?;
    if !definition.authorization.capability_wide_allowed {
        bail!(
            "permission.local_path_scope_required: capability requires a structured or exact JIT authorization scope; a proactive capability grant is insufficient"
        );
    }
    Ok(())
}

pub(super) fn ensure_jit_operation_allowed(
    grant: &AgentGrantFile,
    capability: &str,
    input: Value,
) -> anyhow::Result<()> {
    let operation = normalize_agent_operation(capability, input)
        .map_err(|error| anyhow!("normalize JIT operation: {error}"))?;
    let definitions = resolved_authorization_capabilities(Some(&grant.plugin_id))
        .map_err(|error| anyhow!("load JIT capability metadata: {error}"))?;
    let definition = definitions
        .iter()
        .find(|definition| definition.qualified_id() == capability)
        .ok_or_else(|| anyhow!("capability has no current JIT authorization declaration"))?;
    if grant.authorization_scopes.iter().any(|scope| {
        authorize_normalized_operation(&definition.authorization, scope, &operation).is_ok()
    }) {
        Ok(())
    } else {
        bail!("normalized operation is outside the current JIT grant revision")
    }
}

pub(super) fn consume_agent_use(
    grant: &mut AgentGrantFile,
    command_group: &str,
    command: &str,
    capability: Option<&str>,
) {
    decrement_grant_use(grant);
    append_agent_audit(
        grant,
        AuditOperation::CredentialGrantUsed,
        json!({
            "remaining_uses": grant.remaining_uses,
            "command_group": command_group,
            "command": command,
            "capability": capability,
        }),
    );
}

fn decrement_grant_use(grant: &mut AgentGrantFile) {
    if let Some(remaining) = grant.remaining_uses.as_mut() {
        *remaining = remaining.saturating_sub(1);
    }
}

pub(super) fn grant_uses_exhausted(grant: &AgentGrantFile) -> bool {
    grant.remaining_uses == Some(0)
}

fn invalid_token_response(grant: &AgentGrantFile) -> (BrokerResponse, bool) {
    (
        broker_response(
            grant,
            Some("invalid grant token".into()),
            6,
            String::new(),
            String::new(),
        ),
        false,
    )
}

fn session_result<T: Serialize>(
    grant: &AgentGrantFile,
    result: Result<T, PluginSessionError>,
) -> BrokerResponse {
    match result {
        Ok(data) => match serde_json::to_value(data) {
            Ok(data) => broker_data_response(grant, data),
            Err(error) => broker_session_error(
                grant,
                "session.redaction_failed",
                format!("serialize session response: {error}"),
            ),
        },
        Err(error) => broker_session_error(grant, error.code.as_str(), error.to_string()),
    }
}

fn response_session_ref(response: &BrokerResponse) -> Option<AgentSessionRef> {
    response
        .data
        .as_ref()
        .and_then(|data| data.get("session"))
        .and_then(|session| serde_json::from_value(session.clone()).ok())
}

pub(super) fn broker_data_response(grant: &AgentGrantFile, data: Value) -> BrokerResponse {
    BrokerResponse {
        protocol_version: AGENT_BROKER_PROTOCOL_VERSION,
        ok: true,
        exit_code: 0,
        stdout: String::new(),
        stderr: String::new(),
        error: None,
        error_code: None,
        data: Some(data),
        remaining_uses: grant.remaining_uses,
        expires_at: grant.expires_at,
    }
}

pub(super) fn broker_session_error(
    grant: &AgentGrantFile,
    code: impl Into<String>,
    message: impl Into<String>,
) -> BrokerResponse {
    BrokerResponse {
        protocol_version: AGENT_BROKER_PROTOCOL_VERSION,
        ok: false,
        exit_code: 6,
        stdout: String::new(),
        stderr: String::new(),
        error: Some(message.into()),
        error_code: Some(code.into()),
        data: None,
        remaining_uses: grant.remaining_uses,
        expires_at: grant.expires_at,
    }
}

fn broker_response(
    grant: &AgentGrantFile,
    error: Option<String>,
    exit_code: i32,
    stdout: String,
    stderr: String,
) -> BrokerResponse {
    BrokerResponse {
        protocol_version: AGENT_BROKER_PROTOCOL_VERSION,
        ok: error.is_none() && exit_code == 0,
        exit_code,
        stdout,
        stderr,
        error,
        error_code: None,
        data: None,
        remaining_uses: grant.remaining_uses,
        expires_at: grant.expires_at,
    }
}

#[cfg(unix)]
pub(super) async fn send_request(
    grant: &AgentGrantFile,
    request: BrokerRequest,
) -> anyhow::Result<BrokerResponse> {
    let mut stream = UnixStream::connect(&grant.socket_path)
        .await
        .context("connect to agent broker")?;
    stream
        .write_all(&serde_json::to_vec(&BrokerWireRequest {
            protocol_version: AGENT_BROKER_PROTOCOL_VERSION,
            request,
        })?)
        .await?;
    stream.shutdown().await?;
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await?;
    let response = serde_json::from_slice::<BrokerResponse>(&bytes)?;
    if !is_supported_agent_broker_protocol_version(response.protocol_version) {
        bail!(
            "agent broker selected unsupported protocol version {}",
            response.protocol_version
        );
    }
    Ok(response)
}

#[cfg(not(unix))]
pub(super) async fn send_request(
    _grant: &AgentGrantFile,
    _request: BrokerRequest,
) -> anyhow::Result<BrokerResponse> {
    bail!("agent broker currently requires a Unix-domain socket platform")
}

pub(super) async fn shutdown_grant(
    grant: &AgentGrantFile,
    recovery_reason: &str,
) -> anyhow::Result<()> {
    let broker_responded = if grant.socket_path.exists() {
        matches!(
            tokio::time::timeout(
                BROKER_PROBE_TIMEOUT,
                send_request(
                    grant,
                    BrokerRequest::Shutdown {
                        token: grant.token.clone(),
                    },
                ),
            )
            .await,
            Ok(Ok(response)) if response.ok
        )
    } else {
        false
    };
    if broker_responded {
        let started = tokio::time::Instant::now();
        while started.elapsed() < BROKER_PROBE_TIMEOUT
            && (grant.socket_path.exists() || grant_path_for_id(&grant.id)?.exists())
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    } else {
        append_agent_audit(
            grant,
            AuditOperation::CredentialGrantReleased,
            json!({
                "reason": recovery_reason,
                "broker_health": if grant.socket_path.exists() { "stale_socket" } else { "offline" },
            }),
        );
    }
    remove_grant_artifacts(grant)
}

pub(super) async fn wait_for_socket(socket_path: &Path) -> anyhow::Result<()> {
    let started = tokio::time::Instant::now();
    #[cfg(unix)]
    let mut last_error = None;
    while started.elapsed() < BROKER_READY_TIMEOUT {
        #[cfg(unix)]
        match UnixStream::connect(socket_path).await {
            Ok(stream) => {
                drop(stream);
                return Ok(());
            }
            Err(error) => last_error = Some(error),
        }
        #[cfg(not(unix))]
        if socket_path.exists() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    #[cfg(unix)]
    if let Some(error) = last_error {
        bail!("agent broker did not become ready: {error}");
    }
    bail!("agent broker did not become ready")
}

pub(super) fn grant_directory() -> anyhow::Result<PathBuf> {
    let path = AppConfig::config_dir()?.join("agent-grants");
    fs::create_dir_all(&path)?;
    #[cfg(unix)]
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    Ok(path)
}

pub(super) fn grant_path_for_id(id: &str) -> anyhow::Result<PathBuf> {
    Ok(grant_directory()?.join(format!("{}.json", id.trim_start_matches("agent-grant:"))))
}

pub(super) fn load_grants(prune: bool) -> anyhow::Result<Vec<AgentGrantFile>> {
    let directory = grant_directory()?;
    let mut grants = Vec::new();
    for entry in fs::read_dir(directory)? {
        let path = entry?.path();
        if path.extension().and_then(|value| value.to_str()) != Some("json") {
            continue;
        }
        let grant = match read_grant(&path) {
            Ok(grant) => grant,
            Err(_) => continue,
        };
        if grant.version != GRANT_VERSION {
            continue;
        }
        // A live broker with exhausted data-operation uses must remain
        // addressable long enough for status, wait, cancel, and close requests
        // against calls that were already accepted.
        let terminal = grant.expires_at <= Utc::now()
            || (grant_uses_exhausted(&grant) && !grant.socket_path.exists());
        if terminal && prune {
            let _ = remove_grant_artifacts(&grant);
            let _ = fs::remove_file(path);
            continue;
        }
        grants.push(grant);
    }
    grants.sort_by_key(|grant| grant.expires_at);
    Ok(grants)
}

pub(super) fn read_grant(path: &Path) -> anyhow::Result<AgentGrantFile> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}

pub(super) fn write_grant(path: &Path, grant: &AgentGrantFile) -> anyhow::Result<()> {
    let content = serde_json::to_vec_pretty(grant)?;
    let temporary = path.with_extension(format!("tmp-{}", Uuid::new_v4()));
    let result = (|| -> anyhow::Result<()> {
        let mut options = OpenOptions::new();
        options.create_new(true).write(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&temporary)?;
        file.write_all(&content)?;
        file.sync_all()?;
        #[cfg(unix)]
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))?;
        drop(file);
        fs::rename(&temporary, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

pub(super) fn remove_grant_artifacts(grant: &AgentGrantFile) -> anyhow::Result<()> {
    let _ = fs::remove_file(&grant.socket_path);
    let _ = fs::remove_file(grant_path_for_id(&grant.id)?);
    Ok(())
}

pub(super) fn ensure_unix() -> anyhow::Result<()> {
    if cfg!(unix) {
        Ok(())
    } else {
        bail!("agent broker currently requires a Unix-domain socket platform")
    }
}
