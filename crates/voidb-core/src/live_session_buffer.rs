//! Reusable bounded storage and cooperative call cancellation for live sessions.
//!
//! The owning plugin still owns every target client and producer task. This
//! module only provides the protocol-shaped, in-process queue used by those
//! plugin sessions.

use std::collections::{HashMap, HashSet, VecDeque};
use std::future::Future;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::{Mutex, Notify, watch};

use crate::capability::RedactionStatus;
use crate::live_session::{
    AgentLiveSessionBufferOverflow, AgentLiveSessionBufferPolicy, AgentLiveSessionCheckpoint,
    AgentLiveSessionContract, AgentLiveSessionCursor, AgentLiveSessionEventBatch,
    AgentLiveSessionEventEnvelope, AgentLiveSessionEventKind, AgentLiveSessionReadRequest,
};
use crate::session::{PluginSessionError, PluginSessionErrorCode};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentLiveSessionPushDisposition {
    Retained { sequence: u64 },
    Dropped { sequence: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentLiveSessionBufferSnapshot {
    pub next_sequence: u64,
    pub retained_events: usize,
    pub retained_bytes: usize,
    pub source_closed: bool,
    pub dropped_events: u64,
    pub dropped_bytes: u64,
    pub coalesced_events: u64,
    pub reconnect_attempts: u32,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<AgentLiveSessionCheckpoint>,
}

#[derive(Debug)]
struct BufferedEvent {
    envelope: AgentLiveSessionEventEnvelope,
    retained_bytes: usize,
}

#[derive(Debug)]
struct EventBufferState {
    events: VecDeque<BufferedEvent>,
    retained_bytes: usize,
    next_sequence: u64,
    source_closed: bool,
    dropped_events: u64,
    dropped_bytes: u64,
    coalesced_events: u64,
    reconnect_attempts: u32,
    checkpoint: Option<AgentLiveSessionCheckpoint>,
}

impl Default for EventBufferState {
    fn default() -> Self {
        Self {
            events: VecDeque::new(),
            retained_bytes: 0,
            next_sequence: 1,
            source_closed: false,
            dropped_events: 0,
            dropped_bytes: 0,
            coalesced_events: 0,
            reconnect_attempts: 0,
            checkpoint: None,
        }
    }
}

#[derive(Debug)]
struct EventBufferShared {
    contract: AgentLiveSessionContract,
    policy: AgentLiveSessionBufferPolicy,
    state: Mutex<EventBufferState>,
    changed: Notify,
}

/// A cloneable, multi-producer event ring with explicit overflow accounting.
#[derive(Debug, Clone)]
pub struct AgentLiveSessionEventBuffer {
    shared: Arc<EventBufferShared>,
}

impl AgentLiveSessionEventBuffer {
    pub fn new(
        contract: AgentLiveSessionContract,
        policy: AgentLiveSessionBufferPolicy,
    ) -> Result<Self, PluginSessionError> {
        policy.validate()?;
        if !contract.buffer.allows(&policy) {
            return Err(session_error(
                PluginSessionErrorCode::PolicyDenied,
                "Live-session buffer policy exceeds its discovery contract.",
            ));
        }
        Ok(Self {
            shared: Arc::new(EventBufferShared {
                contract,
                policy,
                state: Mutex::new(EventBufferState::default()),
                changed: Notify::new(),
            }),
        })
    }

    pub fn contract(&self) -> &AgentLiveSessionContract {
        &self.shared.contract
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn push(
        &self,
        observed_at: DateTime<Utc>,
        kind: AgentLiveSessionEventKind,
        data: Value,
        cursor: Option<AgentLiveSessionCursor>,
        redaction: RedactionStatus,
        terminal: bool,
    ) -> Result<AgentLiveSessionPushDisposition, PluginSessionError> {
        let mut state = self.shared.state.lock().await;
        if state.source_closed {
            return Err(session_error(
                PluginSessionErrorCode::Aborted,
                "The live-session event source is already closed.",
            ));
        }

        let sequence = state.next_sequence;
        let event = AgentLiveSessionEventEnvelope::bounded(
            sequence,
            observed_at,
            kind,
            data,
            cursor,
            redaction,
            terminal,
        )?;
        self.shared.contract.validate_event(&event)?;
        let retained_bytes = serde_json::to_vec(&event)
            .map_err(|_| {
                session_error(
                    PluginSessionErrorCode::RedactionFailed,
                    "Live-session event could not be serialized for buffer accounting.",
                )
            })?
            .len();
        state.next_sequence = state.next_sequence.saturating_add(1);

        let mut disposition = AgentLiveSessionPushDisposition::Retained { sequence };
        if retained_bytes > self.shared.policy.max_bytes {
            state.dropped_events = state.dropped_events.saturating_add(1);
            state.dropped_bytes = state.dropped_bytes.saturating_add(retained_bytes as u64);
            disposition = AgentLiveSessionPushDisposition::Dropped { sequence };
        } else {
            if self.shared.policy.overflow == AgentLiveSessionBufferOverflow::Coalesce
                && !terminal
                && let Some(index) = state
                    .events
                    .iter()
                    .rposition(|retained| retained.envelope.kind == event.kind)
                && let Some(replaced) = state.events.remove(index)
            {
                state.retained_bytes = state.retained_bytes.saturating_sub(replaced.retained_bytes);
                state.coalesced_events = state.coalesced_events.saturating_add(1);
            }

            let exceeds = |state: &EventBufferState| {
                state.events.len().saturating_add(1) > self.shared.policy.max_events
                    || state.retained_bytes.saturating_add(retained_bytes)
                        > self.shared.policy.max_bytes
            };
            match self.shared.policy.overflow {
                AgentLiveSessionBufferOverflow::DropNewest if exceeds(&state) && !terminal => {
                    state.dropped_events = state.dropped_events.saturating_add(1);
                    state.dropped_bytes = state.dropped_bytes.saturating_add(retained_bytes as u64);
                    disposition = AgentLiveSessionPushDisposition::Dropped { sequence };
                }
                overflow => {
                    while exceeds(&state) {
                        let Some(removed) = state.events.pop_front() else {
                            break;
                        };
                        state.retained_bytes =
                            state.retained_bytes.saturating_sub(removed.retained_bytes);
                        match overflow {
                            AgentLiveSessionBufferOverflow::Coalesce => {
                                state.coalesced_events = state.coalesced_events.saturating_add(1);
                            }
                            AgentLiveSessionBufferOverflow::DropOldest
                            | AgentLiveSessionBufferOverflow::DropNewest => {
                                state.dropped_events = state.dropped_events.saturating_add(1);
                                state.dropped_bytes = state
                                    .dropped_bytes
                                    .saturating_add(removed.retained_bytes as u64);
                            }
                        }
                    }
                    state.retained_bytes = state.retained_bytes.saturating_add(retained_bytes);
                    if let Some(cursor) = event.cursor.clone() {
                        state.checkpoint = Some(AgentLiveSessionCheckpoint { sequence, cursor });
                    }
                    state.events.push_back(BufferedEvent {
                        envelope: event,
                        retained_bytes,
                    });
                }
            }
        }

        if terminal {
            state.source_closed = true;
        }
        drop(state);
        self.notify_change();
        Ok(disposition)
    }

    pub async fn record_reconnect(&self) -> Result<u32, PluginSessionError> {
        let mut state = self.shared.state.lock().await;
        let next = state.reconnect_attempts.saturating_add(1);
        if next > self.shared.contract.reconnect.max_attempts {
            return Err(session_error(
                PluginSessionErrorCode::PolicyDenied,
                "Live-session reconnect attempts exceed the declared contract.",
            ));
        }
        state.reconnect_attempts = next;
        drop(state);
        self.notify_change();
        Ok(next)
    }

    pub async fn close_source(&self) {
        let mut state = self.shared.state.lock().await;
        state.source_closed = true;
        drop(state);
        self.notify_change();
    }

    pub async fn snapshot(&self) -> AgentLiveSessionBufferSnapshot {
        let state = self.shared.state.lock().await;
        AgentLiveSessionBufferSnapshot {
            next_sequence: state.next_sequence,
            retained_events: state.events.len(),
            retained_bytes: state.retained_bytes,
            source_closed: state.source_closed,
            dropped_events: state.dropped_events,
            dropped_bytes: state.dropped_bytes,
            coalesced_events: state.coalesced_events,
            reconnect_attempts: state.reconnect_attempts,
            checkpoint: state.checkpoint.clone(),
        }
    }

    /// Wait until data, loss accounting, reconnect state, or source closure is
    /// observable after the requested sequence, then return a bounded batch.
    pub async fn read(
        &self,
        request: &AgentLiveSessionReadRequest,
    ) -> Result<AgentLiveSessionEventBatch, PluginSessionError> {
        let wait_timeout_ms = self.shared.contract.effective_read_wait_ms(request)?;
        let deadline = tokio::time::Instant::now() + Duration::from_millis(wait_timeout_ms);
        loop {
            let notified = self.shared.changed.notified();
            if let Some(batch) = self.try_read(request).await? {
                return Ok(batch);
            }
            if wait_timeout_ms == 0 || tokio::time::timeout_at(deadline, notified).await.is_err() {
                let state = self.shared.state.lock().await;
                return self.build_batch(&state, request, true);
            }
        }
    }

    /// Return immediately, including an empty batch when the source has not
    /// changed. Useful for status probes and deterministic tests.
    pub async fn read_available(
        &self,
        request: &AgentLiveSessionReadRequest,
    ) -> Result<AgentLiveSessionEventBatch, PluginSessionError> {
        self.shared.contract.validate_read(request)?;
        let state = self.shared.state.lock().await;
        self.build_batch(&state, request, false)
    }

    async fn try_read(
        &self,
        request: &AgentLiveSessionReadRequest,
    ) -> Result<Option<AgentLiveSessionEventBatch>, PluginSessionError> {
        let state = self.shared.state.lock().await;
        let after = request.after_sequence.unwrap_or(0);
        let has_event = state
            .events
            .iter()
            .any(|event| event.envelope.sequence > after);
        let observed_gap = state.next_sequence > after.saturating_add(1);
        if !has_event && !observed_gap && !state.source_closed {
            return Ok(None);
        }
        self.build_batch(&state, request, false).map(Some)
    }

    fn build_batch(
        &self,
        state: &EventBufferState,
        request: &AgentLiveSessionReadRequest,
        wait_expired: bool,
    ) -> Result<AgentLiveSessionEventBatch, PluginSessionError> {
        let after = request.after_sequence.unwrap_or(0);
        let candidates = state
            .events
            .iter()
            .filter(|event| event.envelope.sequence > after)
            .collect::<Vec<_>>();
        let mut events = Vec::new();
        for candidate in candidates.iter().take(request.max_events) {
            let mut trial = events.clone();
            trial.push(candidate.envelope.clone());
            let trial_batch = self.batch_from_events(state, after, trial, false, false);
            let encoded = serde_json::to_vec(&trial_batch)
                .map_err(|_| {
                    session_error(
                        PluginSessionErrorCode::RedactionFailed,
                        "Live-session event batch could not be serialized.",
                    )
                })?
                .len();
            if encoded > request.max_bytes {
                if events.is_empty() {
                    return Err(session_error(
                        PluginSessionErrorCode::OutputLimit,
                        "The next live-session event does not fit the requested output bound.",
                    ));
                }
                break;
            }
            events.push(candidate.envelope.clone());
        }

        let last = events.last().map(|event| event.sequence).unwrap_or(after);
        let more_available = candidates
            .iter()
            .any(|event| event.envelope.sequence > last);
        let batch = self.batch_from_events(state, after, events, more_available, wait_expired);
        batch.validate(request, &self.shared.contract)?;
        Ok(batch)
    }

    fn batch_from_events(
        &self,
        state: &EventBufferState,
        after: u64,
        events: Vec<AgentLiveSessionEventEnvelope>,
        more_available: bool,
        wait_expired: bool,
    ) -> AgentLiveSessionEventBatch {
        let last_sequence = events.last().map(|event| event.sequence).unwrap_or(after);
        let next_sequence = if more_available {
            last_sequence.saturating_add(1)
        } else {
            state
                .next_sequence
                .max(last_sequence.saturating_add(1))
                .max(after.saturating_add(1))
        };
        let checkpoint = events
            .iter()
            .rev()
            .find_map(|event| {
                event
                    .cursor
                    .clone()
                    .map(|cursor| AgentLiveSessionCheckpoint {
                        sequence: event.sequence,
                        cursor,
                    })
            })
            .or_else(|| {
                (!more_available)
                    .then(|| state.checkpoint.clone())
                    .flatten()
            });
        let resume_cursor = checkpoint
            .as_ref()
            .map(|checkpoint| checkpoint.cursor.clone());
        let oldest_available_sequence = state.events.front().map(|event| event.envelope.sequence);
        let mut previous = after;
        let mut truncated = false;
        for event in &events {
            truncated |= event.sequence > previous.saturating_add(1);
            previous = event.sequence;
        }
        truncated |= next_sequence > previous.saturating_add(1);
        let source_closed = state.source_closed && !more_available;
        let timed_out = wait_expired && events.is_empty() && !source_closed && !truncated;
        AgentLiveSessionEventBatch {
            protocol_version: crate::live_session::AGENT_LIVE_SESSION_PROTOCOL_VERSION,
            events,
            next_sequence,
            resume_cursor,
            checkpoint,
            oldest_available_sequence,
            truncated: Some(truncated),
            timed_out,
            source_closed,
            dropped_events: state.dropped_events,
            dropped_bytes: state.dropped_bytes,
            coalesced_events: state.coalesced_events,
            reconnect_attempts: state.reconnect_attempts,
        }
    }

    fn notify_change(&self) {
        self.shared.changed.notify_waiters();
        self.shared.changed.notify_one();
    }
}

#[derive(Debug, Default)]
struct CancellationState {
    active: HashMap<String, watch::Sender<bool>>,
    cancelled_before_start: HashSet<String>,
    closed: bool,
}

/// Coordinates explicit broker cancellation with a plugin's active call
/// futures without terminating the underlying live source.
#[derive(Debug, Clone, Default)]
pub struct AgentLiveSessionCallCancellation {
    state: Arc<StdMutex<CancellationState>>,
}

impl AgentLiveSessionCallCancellation {
    pub async fn run<F, T>(&self, call_id: &str, future: F) -> Result<T, PluginSessionError>
    where
        F: Future<Output = Result<T, PluginSessionError>>,
    {
        let (mut receiver, _registration) = self.register(call_id)?;
        tokio::select! {
            result = future => result,
            () = wait_for_cancellation(&mut receiver) => {
                Err(session_error(
                    PluginSessionErrorCode::Cancelled,
                    "The live-session call was cancelled.",
                ))
            }
        }
    }

    pub async fn cancel(&self, call_id: &str) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if let Some(sender) = state.active.get(call_id) {
            let _ = sender.send(true);
        } else {
            state.cancelled_before_start.insert(call_id.to_string());
        }
    }

    pub async fn close(&self) {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        state.closed = true;
        for sender in state.active.values() {
            let _ = sender.send(true);
        }
        state.cancelled_before_start.clear();
    }

    fn register(
        &self,
        call_id: &str,
    ) -> Result<(watch::Receiver<bool>, ActiveCallRegistration), PluginSessionError> {
        let mut state = self.state.lock().unwrap_or_else(|error| error.into_inner());
        if state.closed || state.cancelled_before_start.remove(call_id) {
            return Err(session_error(
                PluginSessionErrorCode::Cancelled,
                "The live-session call was cancelled before it started.",
            ));
        }
        if state.active.contains_key(call_id) {
            return Err(session_error(
                PluginSessionErrorCode::CallIdMismatch,
                "The live-session call ID is already active.",
            ));
        }
        let (sender, receiver) = watch::channel(false);
        state.active.insert(call_id.to_string(), sender);
        Ok((
            receiver,
            ActiveCallRegistration {
                state: Arc::clone(&self.state),
                call_id: call_id.to_string(),
            },
        ))
    }
}

struct ActiveCallRegistration {
    state: Arc<StdMutex<CancellationState>>,
    call_id: String,
}

impl Drop for ActiveCallRegistration {
    fn drop(&mut self) {
        self.state
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .active
            .remove(&self.call_id);
    }
}

async fn wait_for_cancellation(receiver: &mut watch::Receiver<bool>) {
    if *receiver.borrow() {
        return;
    }
    loop {
        if receiver.changed().await.is_err() || *receiver.borrow() {
            return;
        }
    }
}

fn session_error(code: PluginSessionErrorCode, message: impl Into<String>) -> PluginSessionError {
    PluginSessionError::new(code, message)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::capability::CapabilityRiskLevel;
    use crate::live_session::{
        AGENT_LIVE_SESSION_PROTOCOL_VERSION, AgentLiveSessionAuditIdentity,
        AgentLiveSessionControlPolicy, AgentLiveSessionKind, AgentLiveSessionOperations,
        AgentLiveSessionReconnectPolicy, AgentLiveSessionResourceDescriptor,
    };

    fn contract(overflow: AgentLiveSessionBufferOverflow) -> AgentLiveSessionContract {
        AgentLiveSessionContract {
            protocol_version: AGENT_LIVE_SESSION_PROTOCOL_VERSION,
            kind: AgentLiveSessionKind::Events,
            resource: AgentLiveSessionResourceDescriptor {
                resource_type: "fixture".into(),
                identity_schema: json!({
                    "type": "object",
                    "required": ["id"],
                    "properties": { "id": { "type": "string" } },
                    "additionalProperties": false
                }),
                identity_fields: vec!["/id".into()],
                audit_identity: AgentLiveSessionAuditIdentity::Omitted,
            },
            start_parameters_schema: json!({ "type": "object" }),
            event_schema: json!({
                "type": "object",
                "required": ["value"],
                "properties": { "value": { "type": "integer" } },
                "additionalProperties": false
            }),
            operations: AgentLiveSessionOperations {
                events: "fixture.events".into(),
                input: None,
                resize: None,
                signal: None,
            },
            buffer: AgentLiveSessionBufferPolicy {
                max_events: 2,
                max_bytes: 8 * 1024,
                overflow,
            },
            reconnect: AgentLiveSessionReconnectPolicy::default(),
            delivery: Default::default(),
            control: AgentLiveSessionControlPolicy::default(),
            start_risk: CapabilityRiskLevel::ReadOnly,
        }
    }

    async fn push(buffer: &AgentLiveSessionEventBuffer, value: i64) {
        buffer
            .push(
                Utc::now(),
                AgentLiveSessionEventKind::Data,
                json!({ "value": value }),
                None,
                RedactionStatus::Applied,
                false,
            )
            .await
            .expect("push event");
    }

    #[tokio::test]
    async fn drop_oldest_reports_loss_and_advances_sequence() {
        let contract = contract(AgentLiveSessionBufferOverflow::DropOldest);
        let buffer = AgentLiveSessionEventBuffer::new(contract.clone(), contract.buffer.clone())
            .expect("buffer");
        push(&buffer, 1).await;
        push(&buffer, 2).await;
        push(&buffer, 3).await;

        let batch = buffer
            .read_available(&AgentLiveSessionReadRequest::default())
            .await
            .expect("batch");
        assert_eq!(
            batch
                .events
                .iter()
                .map(|event| event.sequence)
                .collect::<Vec<_>>(),
            vec![2, 3]
        );
        assert_eq!(batch.next_sequence, 4);
        assert_eq!(batch.dropped_events, 1);
        assert!(batch.dropped_bytes > 0);
        assert_eq!(batch.truncated, Some(true));
        assert_eq!(batch.oldest_available_sequence, Some(2));
    }

    #[tokio::test]
    async fn coalesce_retains_only_the_latest_event_kind() {
        let contract = contract(AgentLiveSessionBufferOverflow::Coalesce);
        let buffer = AgentLiveSessionEventBuffer::new(contract.clone(), contract.buffer.clone())
            .expect("buffer");
        push(&buffer, 1).await;
        push(&buffer, 2).await;

        let batch = buffer
            .read_available(&AgentLiveSessionReadRequest::default())
            .await
            .expect("batch");
        assert_eq!(batch.events.len(), 1);
        assert_eq!(batch.events[0].data["value"], 2);
        assert_eq!(batch.coalesced_events, 1);
        assert_eq!(batch.next_sequence, 3);
        assert_eq!(batch.truncated, Some(true));
    }

    #[tokio::test]
    async fn waiting_read_wakes_on_terminal_source_close() {
        let contract = contract(AgentLiveSessionBufferOverflow::DropOldest);
        let buffer = AgentLiveSessionEventBuffer::new(contract.clone(), contract.buffer.clone())
            .expect("buffer");
        let reader = buffer.clone();
        let task = tokio::spawn(async move {
            reader
                .read(&AgentLiveSessionReadRequest::default())
                .await
                .expect("closed batch")
        });
        tokio::task::yield_now().await;
        buffer.close_source().await;
        let batch = task.await.expect("reader task");
        assert!(batch.events.is_empty());
        assert!(batch.source_closed);
    }

    #[tokio::test]
    async fn bounded_read_timeout_returns_a_retryable_empty_batch() {
        let contract = contract(AgentLiveSessionBufferOverflow::DropOldest);
        let buffer = AgentLiveSessionEventBuffer::new(contract.clone(), contract.buffer.clone())
            .expect("buffer");
        let request = AgentLiveSessionReadRequest {
            wait_timeout_ms: 1,
            ..AgentLiveSessionReadRequest::default()
        };

        let timed_out = buffer.read(&request).await.expect("timed-out batch");
        assert!(timed_out.timed_out);
        assert!(timed_out.events.is_empty());
        assert!(!timed_out.source_closed);
        assert_eq!(timed_out.truncated, Some(false));

        push(&buffer, 1).await;
        let available = buffer.read(&request).await.expect("available batch");
        assert!(!available.timed_out);
        assert_eq!(available.events.len(), 1);
    }

    #[tokio::test]
    async fn retained_cursor_is_exposed_as_a_scoped_checkpoint() {
        let mut contract = contract(AgentLiveSessionBufferOverflow::DropOldest);
        contract.reconnect = crate::live_session::AgentLiveSessionReconnectPolicy {
            mode: crate::live_session::AgentLiveSessionReconnectMode::Transient,
            max_attempts: 3,
            initial_backoff_ms: 10,
            max_backoff_ms: 100,
            resume: crate::live_session::AgentLiveSessionResumeMode::BestEffortCursor,
            cursor_kind: Some(crate::live_session::AgentLiveSessionCursorKind::EventId),
        };
        contract.delivery.cursor_scope =
            crate::live_session::AgentLiveSessionCursorScopePolicy::Required;
        let buffer = AgentLiveSessionEventBuffer::new(contract.clone(), contract.buffer.clone())
            .expect("buffer");
        for value in 1..=3 {
            buffer
                .push(
                    Utc::now(),
                    AgentLiveSessionEventKind::Data,
                    json!({ "value": value }),
                    Some(AgentLiveSessionCursor {
                        kind: crate::live_session::AgentLiveSessionCursorKind::EventId,
                        value: format!("{value}-0"),
                        scope: Some(
                            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                                .into(),
                        ),
                    }),
                    RedactionStatus::Applied,
                    false,
                )
                .await
                .expect("cursor event");
        }

        let batch = buffer
            .read_available(&AgentLiveSessionReadRequest::default())
            .await
            .expect("checkpoint batch");
        assert_eq!(batch.truncated, Some(true));
        assert_eq!(batch.oldest_available_sequence, Some(2));
        assert_eq!(batch.checkpoint.as_ref().unwrap().sequence, 3);
        assert_eq!(
            batch.checkpoint.as_ref().unwrap().cursor.scope.as_deref(),
            Some("sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
        );
        assert_eq!(
            batch.resume_cursor.as_ref(),
            batch
                .checkpoint
                .as_ref()
                .map(|checkpoint| &checkpoint.cursor)
        );
        assert_eq!(
            buffer.snapshot().await.checkpoint,
            batch.checkpoint,
            "snapshot and pull expose the same safe resume point"
        );
    }

    #[tokio::test]
    async fn explicit_call_cancellation_is_cooperative_and_bounded() {
        let cancellation = AgentLiveSessionCallCancellation::default();
        let running = cancellation.clone();
        let task = tokio::spawn(async move {
            running
                .run("call-1", async {
                    std::future::pending::<Result<(), PluginSessionError>>().await
                })
                .await
        });
        tokio::task::yield_now().await;
        cancellation.cancel("call-1").await;
        let error = task.await.expect("call task").expect_err("cancelled call");
        assert_eq!(error.code, PluginSessionErrorCode::Cancelled);
    }

    #[tokio::test]
    async fn timed_out_call_releases_its_cancellation_registration() {
        let cancellation = AgentLiveSessionCallCancellation::default();
        let timed_out = tokio::time::timeout(
            std::time::Duration::from_millis(1),
            cancellation.run("call-timeout", async {
                std::future::pending::<Result<(), PluginSessionError>>().await
            }),
        )
        .await;
        assert!(timed_out.is_err());

        cancellation
            .run("call-timeout", async { Ok(()) })
            .await
            .expect("dropped timeout future releases its call ID");
    }
}
