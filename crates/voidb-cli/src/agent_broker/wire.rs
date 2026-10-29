#![cfg_attr(not(unix), allow(unused_imports))]

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex as StdMutex};
use tokio::sync::Notify;
use tokio::task::AbortHandle;
use voidb_core::{
    AGENT_BROKER_LEGACY_PROTOCOL_VERSION, AgentSessionCallLifecycle, AgentSessionCallRequest,
    AgentSessionCallResult, AgentSessionCallState, AgentSessionCallStatusRequest,
    AgentSessionCallView, AgentSessionCallWaitRequest, AgentSessionCallWaitResult,
    AgentSessionCancelRequest, AgentSessionCloseAgentRequest, AgentSessionControlDisposition,
    AgentSessionControlKind, AgentSessionListRequest, AgentSessionOpenRequest, AgentSessionRef,
    AgentSessionRenewRequest, AgentSessionStatusRequest, PluginSessionError,
    PluginSessionErrorCode, validate_agent_session_call_id,
};

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub(super) enum BrokerRequest {
    Inspect {
        token: String,
    },
    RenewGrant {
        token: String,
        expires_at: DateTime<Utc>,
        remaining_uses: Option<u32>,
    },
    Run {
        token: String,
        argv: Vec<String>,
    },
    SessionOpen {
        token: String,
        request: AgentSessionOpenRequest,
    },
    SessionCall {
        token: String,
        request: AgentSessionCallRequest,
    },
    SessionCallStart {
        token: String,
        request: AgentSessionCallRequest,
    },
    SessionCallStatus {
        token: String,
        request: AgentSessionCallStatusRequest,
    },
    SessionCallWait {
        token: String,
        request: AgentSessionCallWaitRequest,
    },
    SessionStatus {
        token: String,
        request: AgentSessionStatusRequest,
    },
    SessionList {
        token: String,
        request: AgentSessionListRequest,
    },
    SessionRenew {
        token: String,
        request: AgentSessionRenewRequest,
    },
    SessionCancel {
        token: String,
        request: AgentSessionCancelRequest,
    },
    SessionClose {
        token: String,
        request: AgentSessionCloseAgentRequest,
    },
    Shutdown {
        token: String,
    },
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct BrokerWireRequest {
    #[serde(default = "legacy_broker_protocol_version")]
    pub(super) protocol_version: u32,

    #[serde(flatten)]
    pub(super) request: BrokerRequest,
}

fn legacy_broker_protocol_version() -> u32 {
    AGENT_BROKER_LEGACY_PROTOCOL_VERSION
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct BrokerResponse {
    #[serde(default = "legacy_broker_protocol_version")]
    pub(super) protocol_version: u32,
    pub(super) ok: bool,
    pub(super) exit_code: i32,
    pub(super) stdout: String,
    pub(super) stderr: String,
    pub(super) error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) error_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) data: Option<Value>,
    #[serde(default)]
    pub(super) remaining_uses: Option<u32>,
    pub(super) expires_at: DateTime<Utc>,
}

pub(super) struct BrokerCallEntry {
    pub(super) view: StdMutex<AgentSessionCallView>,
    pub(super) changed: Notify,
    pub(super) abort_handle: StdMutex<Option<AbortHandle>>,
}

impl BrokerCallEntry {
    pub(super) fn new(view: AgentSessionCallView) -> Self {
        Self {
            view: StdMutex::new(view),
            changed: Notify::new(),
            abort_handle: StdMutex::new(None),
        }
    }

    pub(super) fn snapshot(&self) -> AgentSessionCallView {
        self.view
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .clone()
    }

    pub(super) fn set_abort_handle(&self, abort_handle: AbortHandle) {
        let view = self.view.lock().unwrap_or_else(|error| error.into_inner());
        if view.lifecycle.state.is_terminal() {
            return;
        }
        *self
            .abort_handle
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some(abort_handle);
    }

    fn clear_abort_handle(&self) {
        self.abort_handle
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take();
    }

    fn abort(&self) {
        if let Some(abort_handle) = self
            .abort_handle
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
        {
            abort_handle.abort();
        }
    }

    pub(super) async fn wait_for_control(&self) {
        loop {
            let mut changed = Box::pin(self.changed.notified());
            changed.as_mut().enable();
            let lifecycle = &self.snapshot().lifecycle;
            if lifecycle.control.is_some() || lifecycle.state.is_terminal() {
                return;
            }
            changed.await;
        }
    }
}

#[derive(Default)]
pub(super) struct BrokerCallRegistry {
    pub(super) calls: StdMutex<BTreeMap<(String, u64, String), Arc<BrokerCallEntry>>>,
}

impl BrokerCallRegistry {
    pub(super) fn register(
        &self,
        request: &AgentSessionCallRequest,
        accepted_at: DateTime<Utc>,
        deadline_at: DateTime<Utc>,
    ) -> Result<Arc<BrokerCallEntry>, PluginSessionError> {
        request.validate_call_id()?;
        let mut calls = self.calls.lock().unwrap_or_else(|error| error.into_inner());
        let key = (
            request.session.session_id.clone(),
            request.session.generation,
            request.call_id.clone(),
        );
        if calls.contains_key(&key) {
            return Err(PluginSessionError::new(
                PluginSessionErrorCode::CallIdConflict,
                "Session call ID is already registered for this session generation.",
            )
            .with_session_id(request.session.session_id.clone()));
        }
        let entry = Arc::new(BrokerCallEntry::new(AgentSessionCallView {
            session: request.session.clone(),
            capability: request.capability.clone(),
            lifecycle: AgentSessionCallLifecycle::accepted(
                request.call_id.clone(),
                accepted_at,
                Some(deadline_at),
            )?,
            result: None,
            error: None,
        }));
        calls.insert(key, Arc::clone(&entry));
        Ok(entry)
    }

    pub(super) fn entry(
        &self,
        session: &AgentSessionRef,
        call_id: &str,
    ) -> Result<Arc<BrokerCallEntry>, PluginSessionError> {
        validate_agent_session_call_id(call_id)?;
        let entry = self
            .calls
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .get(&(
                session.session_id.clone(),
                session.generation,
                call_id.to_owned(),
            ))
            .cloned()
            .ok_or_else(|| {
                PluginSessionError::new(
                    PluginSessionErrorCode::CallNotFound,
                    "Session call was not found.",
                )
                .with_session_id(session.session_id.clone())
            })?;
        if entry.snapshot().session != *session {
            return Err(PluginSessionError::new(
                PluginSessionErrorCode::CallNotFound,
                "Session call was not found for this session generation.",
            )
            .with_session_id(session.session_id.clone()));
        }
        Ok(entry)
    }

    pub(super) fn snapshot(
        &self,
        request: &AgentSessionCallStatusRequest,
    ) -> Result<AgentSessionCallView, PluginSessionError> {
        request.validate_call_id()?;
        Ok(self.entry(&request.session, &request.call_id)?.snapshot())
    }

    pub(super) async fn wait(
        &self,
        request: &AgentSessionCallWaitRequest,
    ) -> Result<AgentSessionCallWaitResult, PluginSessionError> {
        request.validate_call_id()?;
        let timeout = request.timeout()?;
        let entry = self.entry(&request.session, &request.call_id)?;
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let mut changed = Box::pin(entry.changed.notified());
            changed.as_mut().enable();
            let call = entry.snapshot();
            if call.lifecycle.state.is_terminal() {
                return Ok(AgentSessionCallWaitResult {
                    call,
                    wait_timed_out: false,
                });
            }
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() || tokio::time::timeout(remaining, changed).await.is_err() {
                return Ok(AgentSessionCallWaitResult {
                    call: entry.snapshot(),
                    wait_timed_out: true,
                });
            }
        }
    }

    pub(super) async fn wait_until_terminal(
        &self,
        entry: &BrokerCallEntry,
    ) -> AgentSessionCallView {
        loop {
            let mut changed = Box::pin(entry.changed.notified());
            changed.as_mut().enable();
            let call = entry.snapshot();
            if call.lifecycle.state.is_terminal() {
                return call;
            }
            changed.await;
        }
    }

    pub(super) fn mark_running(&self, entry: &BrokerCallEntry, started_at: DateTime<Utc>) -> bool {
        let mut view = entry.view.lock().unwrap_or_else(|error| error.into_inner());
        let started = view.lifecycle.mark_running(started_at);
        drop(view);
        if started {
            entry.changed.notify_waiters();
        }
        started
    }

    pub(super) fn request_control(
        &self,
        session: &AgentSessionRef,
        call_id: &str,
        control: AgentSessionControlKind,
        requested_at: DateTime<Utc>,
    ) -> Result<(AgentSessionControlDisposition, AgentSessionCallView), PluginSessionError> {
        let entry = self.entry(session, call_id)?;
        let mut view = entry.view.lock().unwrap_or_else(|error| error.into_inner());
        let disposition = view.lifecycle.request_control(control, requested_at);
        let snapshot = view.clone();
        drop(view);
        entry.changed.notify_waiters();
        Ok((disposition, snapshot))
    }

    pub(super) fn request_session_control(
        &self,
        session: &AgentSessionRef,
        control: AgentSessionControlKind,
        requested_at: DateTime<Utc>,
    ) -> Vec<Arc<BrokerCallEntry>> {
        let entries = self
            .calls
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .values()
            .filter(|entry| {
                let view = entry.snapshot();
                view.session == *session && !view.lifecycle.state.is_terminal()
            })
            .cloned()
            .collect::<Vec<_>>();
        for entry in &entries {
            let mut view = entry.view.lock().unwrap_or_else(|error| error.into_inner());
            view.lifecycle.request_control(control, requested_at);
            drop(view);
            entry.changed.notify_waiters();
        }
        entries
    }

    pub(super) fn request_all_control(
        &self,
        control: AgentSessionControlKind,
        requested_at: DateTime<Utc>,
    ) -> Vec<Arc<BrokerCallEntry>> {
        let entries = self
            .calls
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .values()
            .filter(|entry| !entry.snapshot().lifecycle.state.is_terminal())
            .cloned()
            .collect::<Vec<_>>();
        for entry in &entries {
            let mut view = entry.view.lock().unwrap_or_else(|error| error.into_inner());
            view.lifecycle.request_control(control, requested_at);
            drop(view);
            entry.changed.notify_waiters();
        }
        entries
    }

    pub(super) fn finish(
        &self,
        entry: &BrokerCallEntry,
        result: Result<AgentSessionCallResult, PluginSessionError>,
        completed_at: DateTime<Utc>,
    ) -> AgentSessionCallView {
        let mut view = entry.view.lock().unwrap_or_else(|error| error.into_inner());
        let terminal_state = match &result {
            Ok(_) => AgentSessionCallState::Succeeded,
            Err(error) => match error.code {
                PluginSessionErrorCode::TimedOut => AgentSessionCallState::TimedOut,
                PluginSessionErrorCode::Cancelled => AgentSessionCallState::Cancelled,
                PluginSessionErrorCode::Aborted => AgentSessionCallState::Aborted,
                _ => AgentSessionCallState::Failed,
            },
        };
        let changed = view
            .lifecycle
            .finish(terminal_state, completed_at)
            .unwrap_or(false);
        if changed {
            match view.lifecycle.state {
                AgentSessionCallState::Succeeded => {
                    view.result = result.ok();
                    view.error = None;
                }
                AgentSessionCallState::Cancelled => {
                    view.result = None;
                    view.error = Some(
                        PluginSessionError::new(
                            PluginSessionErrorCode::Cancelled,
                            "Session call was cancelled.",
                        )
                        .with_session_id(view.session.session_id.clone()),
                    );
                }
                AgentSessionCallState::Aborted => {
                    view.result = None;
                    view.error = Some(
                        PluginSessionError::new(
                            PluginSessionErrorCode::Aborted,
                            "Session call was aborted because its session closed.",
                        )
                        .with_session_id(view.session.session_id.clone()),
                    );
                }
                _ => {
                    view.result = None;
                    view.error = result.err();
                }
            }
        }
        let snapshot = view.clone();
        drop(view);
        entry.clear_abort_handle();
        entry.changed.notify_waiters();
        snapshot
    }

    pub(super) fn abort_entries(
        &self,
        entries: &[Arc<BrokerCallEntry>],
        completed_at: DateTime<Utc>,
    ) {
        for entry in entries {
            entry.abort();
            self.finish(
                entry,
                Err(PluginSessionError::new(
                    PluginSessionErrorCode::Aborted,
                    "Session call was aborted by a higher-priority control request.",
                )),
                completed_at,
            );
        }
    }

    pub(super) fn snapshots(entries: &[Arc<BrokerCallEntry>]) -> Vec<AgentSessionCallView> {
        entries.iter().map(|entry| entry.snapshot()).collect()
    }
}
