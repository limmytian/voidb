//! Shared contract for bounded, agent-owned live plugin sessions.
//!
//! The contract is deliberately transport-neutral. Plugins keep target clients,
//! stream handles, cursors, terminals, and listeners inside their service layer;
//! Core exposes only discovery metadata and bounded request/event envelopes.

use std::collections::{BTreeMap, HashSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::capability::{CapabilityId, CapabilityRiskLevel, RedactionStatus};
use crate::session::{MAX_AGENT_SESSION_OUTPUT_BYTES, PluginSessionError, PluginSessionErrorCode};

pub const AGENT_LIVE_SESSION_PROTOCOL_VERSION: u32 = 1;
pub const DEFAULT_AGENT_LIVE_SESSION_BUFFER_EVENTS: usize = 2_000;
pub const DEFAULT_AGENT_LIVE_SESSION_BUFFER_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_AGENT_LIVE_SESSION_BUFFER_EVENTS: usize = 10_000;
pub const MAX_AGENT_LIVE_SESSION_BUFFER_BYTES: usize = 8 * 1024 * 1024;
pub const DEFAULT_AGENT_LIVE_SESSION_BATCH_EVENTS: usize = 100;
pub const DEFAULT_AGENT_LIVE_SESSION_BATCH_BYTES: usize = 64 * 1024;
pub const MAX_AGENT_LIVE_SESSION_BATCH_EVENTS: usize = 1_000;
pub const MAX_AGENT_LIVE_SESSION_EVENT_BYTES: usize = 256 * 1024;
pub const MAX_AGENT_LIVE_SESSION_START_BYTES: usize = 64 * 1024;
pub const MAX_AGENT_LIVE_SESSION_CURSOR_BYTES: usize = 1_024;
pub const MAX_AGENT_LIVE_SESSION_CURSOR_SCOPE_BYTES: usize = 71;
pub const MAX_AGENT_LIVE_SESSION_RECONNECT_ATTEMPTS: u32 = 32;
pub const MAX_AGENT_LIVE_SESSION_RECONNECT_BACKOFF_MS: u64 = 60_000;
pub const DEFAULT_AGENT_LIVE_SESSION_READ_WAIT_MS: u64 = 30_000;
pub const MAX_AGENT_LIVE_SESSION_READ_WAIT_MS: u64 = 30_000;
pub const MIN_AGENT_LIVE_SESSION_HEARTBEAT_INTERVAL_MS: u64 = 250;
pub const MAX_AGENT_LIVE_SESSION_HEARTBEAT_INTERVAL_MS: u64 = 60_000;
pub const MAX_AGENT_LIVE_SESSION_IDLE_TIMEOUT_MS: u64 = 300_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum AgentLiveSessionKind {
    Log,
    Metrics,
    Events,
    Watch,
    Exec,
    Attach,
    PortForward,
    ProgressiveOutput,
    Wait,
    Queue,
    Subscription,
    Cursor,
    Transfer,
    PluginDefined(String),
}

impl AgentLiveSessionKind {
    fn validate(&self) -> Result<(), PluginSessionError> {
        if let Self::PluginDefined(value) = self {
            validate_public_label(value, "plugin-defined live-session kind")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentLiveSessionAuditIdentity {
    #[default]
    Omitted,
    Fingerprint,
}

/// Describes where a live-session start request carries target identity.
///
/// `identity_fields` are JSON pointers relative to `start.resource`. Their
/// values are used only by the owning plugin and must never be copied verbatim
/// into the shared audit summary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentLiveSessionResourceDescriptor {
    pub resource_type: String,
    pub identity_schema: Value,

    #[serde(default)]
    pub identity_fields: Vec<String>,

    #[serde(default)]
    pub audit_identity: AgentLiveSessionAuditIdentity,
}

impl AgentLiveSessionResourceDescriptor {
    pub fn validate(&self) -> Result<(), PluginSessionError> {
        validate_public_label(&self.resource_type, "live-session resource type")?;
        validate_schema(&self.identity_schema, "live-session resource identity")?;
        if self.identity_fields.is_empty() {
            return Err(policy_error(
                "A live-session resource descriptor needs at least one identity field.",
            ));
        }
        validate_unique_json_pointers(&self.identity_fields, "resource identity")
    }

    fn validate_identity(&self, identity: &Value) -> Result<(), PluginSessionError> {
        validate_json(
            &self.identity_schema,
            identity,
            "live-session resource identity",
        )?;
        for pointer in &self.identity_fields {
            let Some(value) = identity.pointer(pointer) else {
                return Err(policy_error(format!(
                    "Live-session resource identity is missing declared field '{pointer}'."
                )));
            };
            if value.is_null() || value.is_array() || value.is_object() {
                return Err(policy_error(format!(
                    "Live-session resource identity field '{pointer}' must be a scalar value."
                )));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentLiveSessionBufferOverflow {
    #[default]
    DropOldest,
    DropNewest,
    Coalesce,
}

/// Retained plugin-side queue bounds. Producers may never use an unbounded
/// channel as the authoritative live-session buffer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentLiveSessionBufferPolicy {
    pub max_events: usize,
    pub max_bytes: usize,

    #[serde(default)]
    pub overflow: AgentLiveSessionBufferOverflow,
}

impl Default for AgentLiveSessionBufferPolicy {
    fn default() -> Self {
        Self {
            max_events: DEFAULT_AGENT_LIVE_SESSION_BUFFER_EVENTS,
            max_bytes: DEFAULT_AGENT_LIVE_SESSION_BUFFER_BYTES,
            overflow: AgentLiveSessionBufferOverflow::DropOldest,
        }
    }
}

impl AgentLiveSessionBufferPolicy {
    pub fn validate(&self) -> Result<(), PluginSessionError> {
        if self.max_events == 0 || self.max_events > MAX_AGENT_LIVE_SESSION_BUFFER_EVENTS {
            return Err(policy_error(format!(
                "Live-session buffers must retain 1 to {MAX_AGENT_LIVE_SESSION_BUFFER_EVENTS} events."
            )));
        }
        if self.max_bytes == 0 || self.max_bytes > MAX_AGENT_LIVE_SESSION_BUFFER_BYTES {
            return Err(policy_error(format!(
                "Live-session buffers must retain 1 to {MAX_AGENT_LIVE_SESSION_BUFFER_BYTES} bytes."
            )));
        }
        Ok(())
    }

    pub fn allows(&self, requested: &Self) -> bool {
        requested.max_events <= self.max_events
            && requested.max_bytes <= self.max_bytes
            && requested.overflow == self.overflow
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentLiveSessionCursorKind {
    ByteOffset,
    EventId,
    ResourceVersion,
    Timestamp,
    Opaque,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentLiveSessionCursor {
    pub kind: AgentLiveSessionCursorKind,
    pub value: String,

    /// Opaque resource-scope fingerprint. It binds a resumable cursor to the
    /// plugin-owned source identity without exposing that identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

impl AgentLiveSessionCursor {
    pub fn validate(&self) -> Result<(), PluginSessionError> {
        if self.value.is_empty()
            || self.value.len() > MAX_AGENT_LIVE_SESSION_CURSOR_BYTES
            || self.value.chars().any(char::is_control)
        {
            return Err(policy_error(format!(
                "Live-session cursors must be 1 to {MAX_AGENT_LIVE_SESSION_CURSOR_BYTES} bytes and contain no control characters."
            )));
        }
        if let Some(scope) = &self.scope {
            validate_sha256_fingerprint(scope, "live-session cursor scope")?;
        }
        Ok(())
    }
}

/// Build the stable, opaque scope bound to one plugin-owned live resource.
///
/// The namespace distinguishes capability families while canonical JSON key
/// ordering makes semantically identical resource objects produce the same
/// fingerprint. Plugins must still compare a supplied resume cursor scope with
/// the expected value before opening a target-side cursor or stream.
pub fn agent_live_session_cursor_scope(
    namespace: &str,
    resource: &Value,
) -> Result<String, PluginSessionError> {
    validate_public_label(namespace, "live-session cursor namespace")?;
    let canonical = canonical_json(resource);
    let mut hasher = Sha256::new();
    hasher.update(namespace.as_bytes());
    hasher.update([0]);
    hasher.update(canonical.as_bytes());
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

fn canonical_json(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let sorted = map
                .iter()
                .map(|(key, value)| (key, canonical_json(value)))
                .collect::<BTreeMap<_, _>>();
            let body = sorted
                .into_iter()
                .map(|(key, value)| {
                    format!(
                        "{}:{value}",
                        serde_json::to_string(key).expect("JSON object keys always serialize")
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{body}}}")
        }
        Value::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(canonical_json)
                .collect::<Vec<_>>()
                .join(",")
        ),
        _ => serde_json::to_string(value).expect("JSON values always serialize"),
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentLiveSessionCursorScopePolicy {
    #[default]
    Optional,
    Required,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentLiveSessionBackpressureMode {
    /// A target producer may run ahead only into the declared bounded buffer.
    /// Overflow remains observable through loss and truncation fields.
    #[default]
    BoundedBuffer,

    /// The owning plugin advances the target source only while serving a
    /// bounded read. Such batches may never report buffered loss.
    SourcePaced,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AgentLiveSessionHeartbeatPolicy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval_ms: Option<u64>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_timeout_ms: Option<u64>,
}

impl AgentLiveSessionHeartbeatPolicy {
    fn validate(&self) -> Result<(), PluginSessionError> {
        match (self.interval_ms, self.idle_timeout_ms) {
            (None, None) => Ok(()),
            (Some(interval), Some(idle_timeout))
                if (MIN_AGENT_LIVE_SESSION_HEARTBEAT_INTERVAL_MS
                    ..=MAX_AGENT_LIVE_SESSION_HEARTBEAT_INTERVAL_MS)
                    .contains(&interval)
                    && idle_timeout > interval
                    && idle_timeout <= MAX_AGENT_LIVE_SESSION_IDLE_TIMEOUT_MS =>
            {
                Ok(())
            }
            _ => Err(policy_error(format!(
                "Live-session heartbeats need an interval from {MIN_AGENT_LIVE_SESSION_HEARTBEAT_INTERVAL_MS} to {MAX_AGENT_LIVE_SESSION_HEARTBEAT_INTERVAL_MS} milliseconds and a larger idle timeout capped at {MAX_AGENT_LIVE_SESSION_IDLE_TIMEOUT_MS} milliseconds."
            ))),
        }
    }

    fn enabled(&self) -> bool {
        self.interval_ms.is_some()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentLiveSessionDeliveryPolicy {
    #[serde(default)]
    pub backpressure: AgentLiveSessionBackpressureMode,

    #[serde(default)]
    pub cursor_scope: AgentLiveSessionCursorScopePolicy,

    #[serde(default)]
    pub heartbeat: AgentLiveSessionHeartbeatPolicy,

    #[serde(default = "default_read_wait_ms")]
    pub max_read_wait_ms: u64,
}

impl Default for AgentLiveSessionDeliveryPolicy {
    fn default() -> Self {
        Self {
            backpressure: AgentLiveSessionBackpressureMode::BoundedBuffer,
            cursor_scope: AgentLiveSessionCursorScopePolicy::Optional,
            heartbeat: AgentLiveSessionHeartbeatPolicy::default(),
            max_read_wait_ms: DEFAULT_AGENT_LIVE_SESSION_READ_WAIT_MS,
        }
    }
}

impl AgentLiveSessionDeliveryPolicy {
    fn validate(
        &self,
        reconnect: &AgentLiveSessionReconnectPolicy,
    ) -> Result<(), PluginSessionError> {
        if self.max_read_wait_ms == 0 || self.max_read_wait_ms > MAX_AGENT_LIVE_SESSION_READ_WAIT_MS
        {
            return Err(policy_error(format!(
                "Live-session read waits must be capped from 1 to {MAX_AGENT_LIVE_SESSION_READ_WAIT_MS} milliseconds."
            )));
        }
        self.heartbeat.validate()?;
        if self.cursor_scope == AgentLiveSessionCursorScopePolicy::Required
            && reconnect.cursor_kind.is_none()
        {
            return Err(policy_error(
                "Required cursor scoping needs a cursor-resumable live-session contract.",
            ));
        }
        Ok(())
    }

    fn validate_cursor_scope(
        &self,
        cursor: &AgentLiveSessionCursor,
    ) -> Result<(), PluginSessionError> {
        if self.cursor_scope == AgentLiveSessionCursorScopePolicy::Required
            && cursor.scope.is_none()
        {
            return Err(policy_error(
                "This live-session contract requires a resource-scoped resume cursor.",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentLiveSessionReconnectMode {
    #[default]
    Never,
    Transient,
    Always,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentLiveSessionResumeMode {
    #[default]
    Unsupported,
    Restart,
    BestEffortCursor,
    ExactCursor,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentLiveSessionReconnectPolicy {
    #[serde(default)]
    pub mode: AgentLiveSessionReconnectMode,

    #[serde(default)]
    pub max_attempts: u32,

    #[serde(default)]
    pub initial_backoff_ms: u64,

    #[serde(default)]
    pub max_backoff_ms: u64,

    #[serde(default)]
    pub resume: AgentLiveSessionResumeMode,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor_kind: Option<AgentLiveSessionCursorKind>,
}

impl Default for AgentLiveSessionReconnectPolicy {
    fn default() -> Self {
        Self {
            mode: AgentLiveSessionReconnectMode::Never,
            max_attempts: 0,
            initial_backoff_ms: 0,
            max_backoff_ms: 0,
            resume: AgentLiveSessionResumeMode::Unsupported,
            cursor_kind: None,
        }
    }
}

impl AgentLiveSessionReconnectPolicy {
    pub fn validate(&self) -> Result<(), PluginSessionError> {
        match self.mode {
            AgentLiveSessionReconnectMode::Never => {
                if self.max_attempts != 0
                    || self.initial_backoff_ms != 0
                    || self.max_backoff_ms != 0
                {
                    return Err(policy_error(
                        "A non-reconnecting live session cannot declare retry attempts or backoff.",
                    ));
                }
            }
            AgentLiveSessionReconnectMode::Transient | AgentLiveSessionReconnectMode::Always => {
                if self.max_attempts == 0
                    || self.max_attempts > MAX_AGENT_LIVE_SESSION_RECONNECT_ATTEMPTS
                    || self.initial_backoff_ms == 0
                    || self.initial_backoff_ms > self.max_backoff_ms
                    || self.max_backoff_ms > MAX_AGENT_LIVE_SESSION_RECONNECT_BACKOFF_MS
                {
                    return Err(policy_error(format!(
                        "Live-session reconnects need 1 to {MAX_AGENT_LIVE_SESSION_RECONNECT_ATTEMPTS} attempts and an ordered backoff capped at {MAX_AGENT_LIVE_SESSION_RECONNECT_BACKOFF_MS} milliseconds."
                    )));
                }
            }
        }

        let cursor_mode = matches!(
            self.resume,
            AgentLiveSessionResumeMode::BestEffortCursor | AgentLiveSessionResumeMode::ExactCursor
        );
        if cursor_mode != self.cursor_kind.is_some() {
            return Err(policy_error(
                "Cursor resume modes must declare exactly one cursor kind; other resume modes must not.",
            ));
        }
        Ok(())
    }

    fn validate_cursor(
        &self,
        cursor: Option<&AgentLiveSessionCursor>,
    ) -> Result<(), PluginSessionError> {
        let Some(cursor) = cursor else {
            return Ok(());
        };
        if !matches!(
            self.resume,
            AgentLiveSessionResumeMode::BestEffortCursor | AgentLiveSessionResumeMode::ExactCursor
        ) {
            return Err(policy_error(
                "This live-session contract does not accept a resume cursor.",
            ));
        }
        cursor.validate()?;
        if self.cursor_kind != Some(cursor.kind) {
            return Err(policy_error(
                "The resume cursor kind does not match the live-session contract.",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentLiveSessionCancelBehavior {
    #[default]
    CallOnly,
    CallAndSource,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentLiveSessionCloseEffect {
    #[default]
    StopObservation,
    DetachRemote,
    TerminateRemote,
}

/// Generic broker control mapping. Cancel always targets the caller-owned call
/// ID; close always targets the session generation and must remain idempotent.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentLiveSessionControlPolicy {
    #[serde(default)]
    pub cancel: AgentLiveSessionCancelBehavior,

    #[serde(default)]
    pub close: AgentLiveSessionCloseEffect,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentLiveSessionOperations {
    pub events: CapabilityId,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<CapabilityId>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resize: Option<CapabilityId>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signal: Option<CapabilityId>,
}

impl AgentLiveSessionOperations {
    pub fn capabilities(&self) -> impl Iterator<Item = &CapabilityId> {
        std::iter::once(&self.events)
            .chain(self.input.iter())
            .chain(self.resize.iter())
            .chain(self.signal.iter())
    }

    fn validate(&self, handoff_capabilities: &[CapabilityId]) -> Result<(), PluginSessionError> {
        let mut seen = HashSet::new();
        for capability in self.capabilities() {
            if capability.split_once('.').is_none() || !seen.insert(capability.as_str()) {
                return Err(policy_error(
                    "Live-session operation capabilities must be unique, fully qualified IDs.",
                ));
            }
            if !handoff_capabilities.contains(capability) {
                return Err(policy_error(format!(
                    "Live-session operation capability '{capability}' is outside the session handoff."
                )));
            }
        }
        Ok(())
    }
}

/// Static discovery contract attached to `CapabilitySessionHandoff`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentLiveSessionContract {
    #[serde(default = "agent_live_session_protocol_version")]
    pub protocol_version: u32,
    pub kind: AgentLiveSessionKind,
    pub resource: AgentLiveSessionResourceDescriptor,
    pub start_parameters_schema: Value,
    pub event_schema: Value,
    pub operations: AgentLiveSessionOperations,

    #[serde(default)]
    pub buffer: AgentLiveSessionBufferPolicy,

    #[serde(default)]
    pub reconnect: AgentLiveSessionReconnectPolicy,

    #[serde(default)]
    pub delivery: AgentLiveSessionDeliveryPolicy,

    #[serde(default)]
    pub control: AgentLiveSessionControlPolicy,

    #[serde(default)]
    pub start_risk: CapabilityRiskLevel,
}

impl AgentLiveSessionContract {
    pub fn validate(
        &self,
        handoff_capabilities: &[CapabilityId],
    ) -> Result<(), PluginSessionError> {
        if self.protocol_version != AGENT_LIVE_SESSION_PROTOCOL_VERSION {
            return Err(policy_error(format!(
                "Unsupported live-session protocol version '{}'.",
                self.protocol_version
            )));
        }
        self.kind.validate()?;
        self.resource.validate()?;
        validate_schema(
            &self.start_parameters_schema,
            "live-session start parameters",
        )?;
        validate_schema(&self.event_schema, "live-session event payload")?;
        self.operations.validate(handoff_capabilities)?;
        self.buffer.validate()?;
        self.reconnect.validate()?;
        self.delivery.validate(&self.reconnect)?;
        if self.control.close == AgentLiveSessionCloseEffect::TerminateRemote
            && self.start_risk == CapabilityRiskLevel::ReadOnly
        {
            return Err(policy_error(
                "A live session whose close terminates remote work cannot have a read-only start risk.",
            ));
        }
        Ok(())
    }

    pub fn validate_start(&self, input: &Value) -> Result<(), PluginSessionError> {
        let encoded = serde_json::to_vec(input).map_err(|_| {
            policy_error("Live-session start input could not be serialized for size validation.")
        })?;
        if encoded.len() > MAX_AGENT_LIVE_SESSION_START_BYTES {
            return Err(output_limit_error(format!(
                "Live-session start input exceeds {MAX_AGENT_LIVE_SESSION_START_BYTES} bytes."
            )));
        }
        let start: AgentLiveSessionStartRequest = serde_json::from_value(input.clone())
            .map_err(|_| policy_error("Live-session start input has an invalid envelope."))?;
        self.resource.validate_identity(&start.resource)?;
        validate_json(
            &self.start_parameters_schema,
            &start.parameters,
            "live-session start parameters",
        )?;
        if let Some(buffer) = &start.buffer {
            buffer.validate()?;
            if !self.buffer.allows(buffer) {
                return Err(policy_error(
                    "Requested live-session buffer bounds or overflow behavior exceed the declared contract.",
                ));
            }
        }
        self.validate_cursor(start.resume_from.as_ref())
    }

    pub fn validate_event(
        &self,
        event: &AgentLiveSessionEventEnvelope,
    ) -> Result<(), PluginSessionError> {
        event.validate()?;
        if event.kind == AgentLiveSessionEventKind::Heartbeat {
            if !self.delivery.heartbeat.enabled() {
                return Err(policy_error(
                    "This live-session contract does not declare heartbeats.",
                ));
            }
        } else if !matches!(
            event.redaction,
            RedactionStatus::Withheld | RedactionStatus::FailedClosed
        ) {
            validate_json(
                &self.event_schema,
                &event.data,
                "live-session event payload",
            )?;
        }
        if let Some(cursor) = &event.cursor {
            self.validate_cursor(Some(cursor))?;
        }
        Ok(())
    }

    pub fn validate_read(
        &self,
        request: &AgentLiveSessionReadRequest,
    ) -> Result<(), PluginSessionError> {
        request.validate()
    }

    pub fn effective_read_wait_ms(
        &self,
        request: &AgentLiveSessionReadRequest,
    ) -> Result<u64, PluginSessionError> {
        self.validate_read(request)?;
        Ok(request.wait_timeout_ms.min(self.delivery.max_read_wait_ms))
    }

    fn validate_cursor(
        &self,
        cursor: Option<&AgentLiveSessionCursor>,
    ) -> Result<(), PluginSessionError> {
        self.reconnect.validate_cursor(cursor)?;
        if let Some(cursor) = cursor {
            self.delivery.validate_cursor_scope(cursor)?;
        }
        Ok(())
    }

    pub fn start_requires_acknowledgement(&self) -> bool {
        self.start_risk != CapabilityRiskLevel::ReadOnly
    }
}

fn agent_live_session_protocol_version() -> u32 {
    AGENT_LIVE_SESSION_PROTOCOL_VERSION
}

fn empty_object() -> Value {
    json!({})
}

/// Stable input envelope passed through `AgentSessionOpenRequest.input`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentLiveSessionStartRequest {
    pub resource: Value,

    #[serde(default = "empty_object")]
    pub parameters: Value,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resume_from: Option<AgentLiveSessionCursor>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub buffer: Option<AgentLiveSessionBufferPolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentLiveSessionReadRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after_sequence: Option<u64>,

    #[serde(default = "default_batch_events")]
    pub max_events: usize,

    #[serde(default = "default_batch_bytes")]
    pub max_bytes: usize,

    /// Maximum time this pull may wait for an observable change. Zero is a
    /// non-blocking poll; the contract caps every positive value.
    #[serde(default = "default_read_wait_ms")]
    pub wait_timeout_ms: u64,
}

impl Default for AgentLiveSessionReadRequest {
    fn default() -> Self {
        Self {
            after_sequence: None,
            max_events: DEFAULT_AGENT_LIVE_SESSION_BATCH_EVENTS,
            max_bytes: DEFAULT_AGENT_LIVE_SESSION_BATCH_BYTES,
            wait_timeout_ms: DEFAULT_AGENT_LIVE_SESSION_READ_WAIT_MS,
        }
    }
}

impl AgentLiveSessionReadRequest {
    pub fn validate(&self) -> Result<(), PluginSessionError> {
        if self.max_events == 0 || self.max_events > MAX_AGENT_LIVE_SESSION_BATCH_EVENTS {
            return Err(policy_error(format!(
                "Live-session reads must request 1 to {MAX_AGENT_LIVE_SESSION_BATCH_EVENTS} events."
            )));
        }
        if self.max_bytes == 0 || self.max_bytes > MAX_AGENT_SESSION_OUTPUT_BYTES {
            return Err(policy_error(format!(
                "Live-session reads must request 1 to {MAX_AGENT_SESSION_OUTPUT_BYTES} bytes."
            )));
        }
        if self.wait_timeout_ms > MAX_AGENT_LIVE_SESSION_READ_WAIT_MS {
            return Err(policy_error(format!(
                "Live-session reads may wait at most {MAX_AGENT_LIVE_SESSION_READ_WAIT_MS} milliseconds."
            )));
        }
        Ok(())
    }
}

fn default_batch_events() -> usize {
    DEFAULT_AGENT_LIVE_SESSION_BATCH_EVENTS
}

fn default_batch_bytes() -> usize {
    DEFAULT_AGENT_LIVE_SESSION_BATCH_BYTES
}

fn default_read_wait_ms() -> u64 {
    DEFAULT_AGENT_LIVE_SESSION_READ_WAIT_MS
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentLiveSessionEventKind {
    Data,
    Progress,
    State,
    Heartbeat,
    Warning,
    Error,
    End,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentLiveSessionEventEnvelope {
    #[serde(default = "agent_live_session_protocol_version")]
    pub protocol_version: u32,
    pub sequence: u64,
    pub observed_at: DateTime<Utc>,
    pub kind: AgentLiveSessionEventKind,

    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub data: Value,

    pub data_bytes: usize,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<AgentLiveSessionCursor>,

    #[serde(default)]
    pub redaction: RedactionStatus,

    #[serde(default)]
    pub terminal: bool,
}

impl AgentLiveSessionEventEnvelope {
    pub fn bounded(
        sequence: u64,
        observed_at: DateTime<Utc>,
        kind: AgentLiveSessionEventKind,
        data: Value,
        cursor: Option<AgentLiveSessionCursor>,
        redaction: RedactionStatus,
        terminal: bool,
    ) -> Result<Self, PluginSessionError> {
        let data = if matches!(
            redaction,
            RedactionStatus::Withheld | RedactionStatus::FailedClosed
        ) {
            Value::Null
        } else {
            data
        };
        let data_bytes = serialized_event_data_bytes(&data)?;
        let event = Self {
            protocol_version: AGENT_LIVE_SESSION_PROTOCOL_VERSION,
            sequence,
            observed_at,
            kind,
            data,
            data_bytes,
            cursor,
            redaction,
            terminal,
        };
        event.validate()?;
        Ok(event)
    }

    pub fn validate(&self) -> Result<(), PluginSessionError> {
        if self.protocol_version != AGENT_LIVE_SESSION_PROTOCOL_VERSION || self.sequence == 0 {
            return Err(policy_error(
                "Live-session events need the supported protocol version and a positive sequence.",
            ));
        }
        if self.data_bytes > MAX_AGENT_LIVE_SESSION_EVENT_BYTES {
            return Err(output_limit_error(format!(
                "Live-session event data exceeds {MAX_AGENT_LIVE_SESSION_EVENT_BYTES} bytes."
            )));
        }
        let actual_bytes = serialized_event_data_bytes(&self.data)?;
        if actual_bytes != self.data_bytes {
            return Err(policy_error(
                "Live-session event byte accounting does not match its payload.",
            ));
        }
        if matches!(
            self.redaction,
            RedactionStatus::Withheld | RedactionStatus::FailedClosed
        ) && !self.data.is_null()
        {
            return Err(PluginSessionError::new(
                PluginSessionErrorCode::RedactionFailed,
                "Withheld or failed-closed live-session events cannot carry data.",
            ));
        }
        if self.kind == AgentLiveSessionEventKind::Heartbeat
            && (!self.data.is_null() || self.data_bytes != 0 || self.terminal)
        {
            return Err(policy_error(
                "Live-session heartbeat events must be content-free and non-terminal.",
            ));
        }
        if let Some(cursor) = &self.cursor {
            cursor.validate()?;
        }
        Ok(())
    }
}

/// A safe resume point paired with the session-local sequence that produced
/// it. The cursor remains opaque and the sequence never claims cross-session
/// identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentLiveSessionCheckpoint {
    pub sequence: u64,
    pub cursor: AgentLiveSessionCursor,
}

impl AgentLiveSessionCheckpoint {
    pub fn validate(&self, contract: &AgentLiveSessionContract) -> Result<(), PluginSessionError> {
        if self.sequence == 0 {
            return Err(policy_error(
                "Live-session checkpoints need a positive sequence.",
            ));
        }
        contract.validate_cursor(Some(&self.cursor))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentLiveSessionEventBatch {
    #[serde(default = "agent_live_session_protocol_version")]
    pub protocol_version: u32,

    #[serde(default)]
    pub events: Vec<AgentLiveSessionEventEnvelope>,

    pub next_sequence: u64,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resume_cursor: Option<AgentLiveSessionCursor>,

    /// Latest plugin-declared safe resume point. `resume_cursor` remains the
    /// protocol-v1 compatibility projection of this checkpoint's cursor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<AgentLiveSessionCheckpoint>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oldest_available_sequence: Option<u64>,

    /// At least one sequence in the requested window was dropped or
    /// coalesced. Consumers must not infer continuity from `next_sequence`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub truncated: Option<bool>,

    /// The bounded pull wait expired without an event, loss transition, or
    /// source closure. Retrying from the same sequence is safe.
    #[serde(default)]
    pub timed_out: bool,

    #[serde(default)]
    pub source_closed: bool,

    #[serde(default)]
    pub dropped_events: u64,

    #[serde(default)]
    pub dropped_bytes: u64,

    #[serde(default)]
    pub coalesced_events: u64,

    #[serde(default)]
    pub reconnect_attempts: u32,
}

/// One plugin-produced candidate for a source-paced live-session batch.
/// Sequence numbers are intentionally assigned by
/// [`AgentLiveSessionSourcePacedState`] only after the event fits the caller's
/// negotiated output bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentLiveSessionEventInput {
    pub observed_at: DateTime<Utc>,
    pub kind: AgentLiveSessionEventKind,
    pub data: Value,
    pub cursor: Option<AgentLiveSessionCursor>,
    pub redaction: RedactionStatus,
    pub terminal: bool,
}

/// Session-local sequence/checkpoint state for target cursors that advance
/// only while serving a bounded broker read.
#[derive(Debug, Clone)]
pub struct AgentLiveSessionSourcePacedState {
    next_sequence: u64,
    checkpoint: Option<AgentLiveSessionCheckpoint>,
    reconnect_attempts: u32,
    source_closed: bool,
}

impl Default for AgentLiveSessionSourcePacedState {
    fn default() -> Self {
        Self {
            next_sequence: 1,
            checkpoint: None,
            reconnect_attempts: 0,
            source_closed: false,
        }
    }
}

impl AgentLiveSessionSourcePacedState {
    pub fn record_reconnect(
        &mut self,
        contract: &AgentLiveSessionContract,
    ) -> Result<u32, PluginSessionError> {
        let next = self.reconnect_attempts.saturating_add(1);
        if next > contract.reconnect.max_attempts {
            return Err(policy_error(
                "Live-session reconnect attempts exceed the declared contract.",
            ));
        }
        self.reconnect_attempts = next;
        Ok(next)
    }

    pub fn close_source(&mut self) {
        self.source_closed = true;
    }

    pub fn latest_cursor(&self) -> Option<&AgentLiveSessionCursor> {
        self.checkpoint
            .as_ref()
            .map(|checkpoint| &checkpoint.cursor)
    }

    /// Fit as many candidate events as possible without advancing a sequence
    /// for an event that is retained for a later pull. The returned count is
    /// the prefix the plugin may remove from its pending target results.
    pub fn build_batch(
        &mut self,
        request: &AgentLiveSessionReadRequest,
        contract: &AgentLiveSessionContract,
        candidates: &[AgentLiveSessionEventInput],
        wait_expired: bool,
        source_closed: bool,
    ) -> Result<(AgentLiveSessionEventBatch, usize), PluginSessionError> {
        contract.validate_read(request)?;
        if contract.delivery.backpressure != AgentLiveSessionBackpressureMode::SourcePaced {
            return Err(policy_error(
                "The source-paced batch state requires a source-paced live-session contract.",
            ));
        }
        let expected_after = self.next_sequence.saturating_sub(1);
        let requested_after = request.after_sequence.unwrap_or(0);
        if requested_after != expected_after {
            return Err(policy_error(
                "Source-paced reads must continue from the previously returned sequence.",
            ));
        }

        let mut events = Vec::new();
        let mut checkpoint = self.checkpoint.clone();
        let max_candidates = candidates.len().min(request.max_events);
        for candidate in candidates.iter().take(max_candidates) {
            let sequence = self.next_sequence.saturating_add(events.len() as u64);
            let event = AgentLiveSessionEventEnvelope::bounded(
                sequence,
                candidate.observed_at,
                candidate.kind,
                candidate.data.clone(),
                candidate.cursor.clone(),
                candidate.redaction,
                candidate.terminal,
            )?;
            contract.validate_event(&event)?;
            let mut trial_events = events.clone();
            trial_events.push(event.clone());
            let trial_checkpoint = event
                .cursor
                .clone()
                .map(|cursor| AgentLiveSessionCheckpoint { sequence, cursor })
                .or_else(|| checkpoint.clone());
            let trial = source_paced_batch(
                trial_events,
                sequence.saturating_add(1),
                trial_checkpoint,
                false,
                self.reconnect_attempts,
            );
            let encoded_bytes = serde_json::to_vec(&trial)
                .map_err(|_| policy_error("Live-session event batch could not be serialized."))?
                .len();
            if encoded_bytes > request.max_bytes || encoded_bytes > MAX_AGENT_SESSION_OUTPUT_BYTES {
                if events.is_empty() {
                    return Err(output_limit_error(
                        "The next live-session event does not fit the requested output bound.",
                    ));
                }
                break;
            }
            if let Some(cursor) = event.cursor.clone() {
                checkpoint = Some(AgentLiveSessionCheckpoint { sequence, cursor });
            }
            events.push(event);
        }

        let consumed = events.len();
        self.next_sequence = self.next_sequence.saturating_add(consumed as u64);
        self.checkpoint = checkpoint;
        self.source_closed |= source_closed && consumed == candidates.len();
        let timed_out = wait_expired && events.is_empty() && !self.source_closed;
        let batch = source_paced_batch(
            events,
            self.next_sequence,
            self.checkpoint.clone(),
            timed_out,
            self.reconnect_attempts,
        );
        let mut batch = AgentLiveSessionEventBatch {
            source_closed: self.source_closed,
            ..batch
        };
        if batch.source_closed {
            batch.timed_out = false;
        }
        batch.validate(request, contract)?;
        Ok((batch, consumed))
    }
}

fn source_paced_batch(
    events: Vec<AgentLiveSessionEventEnvelope>,
    next_sequence: u64,
    checkpoint: Option<AgentLiveSessionCheckpoint>,
    timed_out: bool,
    reconnect_attempts: u32,
) -> AgentLiveSessionEventBatch {
    AgentLiveSessionEventBatch {
        protocol_version: AGENT_LIVE_SESSION_PROTOCOL_VERSION,
        events,
        next_sequence,
        resume_cursor: checkpoint
            .as_ref()
            .map(|checkpoint| checkpoint.cursor.clone()),
        checkpoint,
        oldest_available_sequence: None,
        truncated: Some(false),
        timed_out,
        source_closed: false,
        dropped_events: 0,
        dropped_bytes: 0,
        coalesced_events: 0,
        reconnect_attempts,
    }
}

impl AgentLiveSessionEventBatch {
    pub fn validate(
        &self,
        request: &AgentLiveSessionReadRequest,
        contract: &AgentLiveSessionContract,
    ) -> Result<(), PluginSessionError> {
        contract.validate_read(request)?;
        if self.protocol_version != AGENT_LIVE_SESSION_PROTOCOL_VERSION
            || self.events.len() > request.max_events
            || self.reconnect_attempts > MAX_AGENT_LIVE_SESSION_RECONNECT_ATTEMPTS
        {
            return Err(policy_error(
                "Live-session event batch exceeds its protocol, event, or reconnect bounds.",
            ));
        }
        let encoded_bytes = serde_json::to_vec(self)
            .map_err(|_| policy_error("Live-session event batch could not be serialized."))?
            .len();
        if encoded_bytes > request.max_bytes || encoded_bytes > MAX_AGENT_SESSION_OUTPUT_BYTES {
            return Err(output_limit_error(
                "Live-session event batch exceeds the negotiated output bound.",
            ));
        }

        let mut previous = request.after_sequence.unwrap_or(0);
        let mut observed_gap = false;
        for event in &self.events {
            contract.validate_event(event)?;
            if event.sequence <= previous {
                return Err(policy_error(
                    "Live-session event sequences must be strictly increasing after the requested offset.",
                ));
            }
            observed_gap |= event.sequence > previous.saturating_add(1);
            previous = event.sequence;
        }
        if self.next_sequence <= previous {
            return Err(policy_error(
                "Live-session next_sequence must advance beyond every delivered event.",
            ));
        }
        observed_gap |= self.next_sequence > previous.saturating_add(1);
        if self
            .truncated
            .is_some_and(|truncated| truncated != observed_gap)
        {
            return Err(policy_error(
                "Live-session truncation must exactly describe sequence gaps in this batch.",
            ));
        }
        if self.timed_out && (!self.events.is_empty() || self.source_closed || observed_gap) {
            return Err(policy_error(
                "A timed-out live-session batch cannot contain data, loss, or source closure.",
            ));
        }
        if let Some(oldest) = self.oldest_available_sequence
            && (oldest == 0
                || oldest >= self.next_sequence
                || self
                    .events
                    .first()
                    .is_some_and(|event| oldest > event.sequence))
        {
            return Err(policy_error(
                "The oldest available live-session sequence is inconsistent with the batch.",
            ));
        }
        if let Some(checkpoint) = &self.checkpoint {
            checkpoint.validate(contract)?;
            if checkpoint.sequence >= self.next_sequence {
                return Err(policy_error(
                    "A live-session checkpoint cannot advance beyond the batch sequence.",
                ));
            }
            if self.resume_cursor.as_ref() != Some(&checkpoint.cursor) {
                return Err(policy_error(
                    "The compatibility resume cursor must match the live-session checkpoint.",
                ));
            }
        }
        contract.validate_cursor(self.resume_cursor.as_ref())?;
        if contract.delivery.backpressure == AgentLiveSessionBackpressureMode::SourcePaced
            && (observed_gap
                || self.dropped_events != 0
                || self.dropped_bytes != 0
                || self.coalesced_events != 0)
        {
            return Err(policy_error(
                "Source-paced live sessions cannot report buffered loss or coalescing.",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentLiveSessionAuditState {
    Starting,
    Active,
    Reconnecting,
    Completed,
    Cancelled,
    Closed,
    Failed,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentLiveSessionResumeOutcome {
    #[default]
    NotRequested,
    Accepted,
    Restarted,
    Rejected,
    Unsupported,
}

/// Content-free audit projection. Raw resource identity, cursors, event data,
/// commands, stdin, logs, and target error bodies have no field in this type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentLiveSessionAuditSummary {
    #[serde(default = "agent_live_session_protocol_version")]
    pub protocol_version: u32,
    pub kind: AgentLiveSessionKind,
    pub resource_type: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_fingerprint: Option<String>,

    pub start_risk: CapabilityRiskLevel,
    pub state: AgentLiveSessionAuditState,
    pub started_at: DateTime<Utc>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<DateTime<Utc>>,

    #[serde(default)]
    pub delivered_events: u64,

    #[serde(default)]
    pub delivered_bytes: u64,

    #[serde(default)]
    pub dropped_events: u64,

    #[serde(default)]
    pub dropped_bytes: u64,

    #[serde(default)]
    pub coalesced_events: u64,

    #[serde(default)]
    pub reconnect_attempts: u32,

    #[serde(default)]
    pub resume: AgentLiveSessionResumeOutcome,

    #[serde(default)]
    pub redaction: RedactionStatus,
}

impl AgentLiveSessionAuditSummary {
    pub fn validate(&self) -> Result<(), PluginSessionError> {
        if self.protocol_version != AGENT_LIVE_SESSION_PROTOCOL_VERSION
            || self.reconnect_attempts > MAX_AGENT_LIVE_SESSION_RECONNECT_ATTEMPTS
            || self
                .finished_at
                .is_some_and(|finished| finished < self.started_at)
        {
            return Err(policy_error(
                "Live-session audit timing, protocol, or reconnect fields are invalid.",
            ));
        }
        self.kind.validate()?;
        validate_public_label(&self.resource_type, "live-session audit resource type")?;
        if let Some(fingerprint) = &self.resource_fingerprint {
            validate_opaque_fingerprint(fingerprint, 160, "live-session resource fingerprint")?;
        }
        Ok(())
    }
}

fn validate_schema(schema: &Value, label: &str) -> Result<(), PluginSessionError> {
    jsonschema::validator_for(schema)
        .map(|_| ())
        .map_err(|_| policy_error(format!("The {label} schema is invalid.")))
}

fn serialized_event_data_bytes(data: &Value) -> Result<usize, PluginSessionError> {
    if data.is_null() {
        return Ok(0);
    }
    serde_json::to_vec(data)
        .map(|encoded| encoded.len())
        .map_err(|_| policy_error("Live-session event data could not be serialized."))
}

fn validate_json(schema: &Value, value: &Value, label: &str) -> Result<(), PluginSessionError> {
    jsonschema::validate(schema, value)
        .map(|_| ())
        .map_err(|_| policy_error(format!("The {label} does not match its declared schema.")))
}

fn validate_unique_json_pointers(
    pointers: &[String],
    label: &str,
) -> Result<(), PluginSessionError> {
    let mut seen = HashSet::new();
    for pointer in pointers {
        if !pointer.starts_with('/') || pointer.contains("//") || !seen.insert(pointer.as_str()) {
            return Err(policy_error(format!(
                "Declared {label} fields must be unique non-empty JSON pointers."
            )));
        }
    }
    Ok(())
}

fn validate_public_label(value: &str, label: &str) -> Result<(), PluginSessionError> {
    if value.trim().is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        return Err(policy_error(format!(
            "The {label} must be a non-empty public label of at most 128 bytes."
        )));
    }
    Ok(())
}

fn validate_opaque_fingerprint(
    value: &str,
    max_bytes: usize,
    label: &str,
) -> Result<(), PluginSessionError> {
    if value.is_empty()
        || value.len() > max_bytes
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'-' | b'_' | b'.'))
    {
        return Err(policy_error(format!(
            "The {label} must be a bounded opaque public identifier."
        )));
    }
    Ok(())
}

fn validate_sha256_fingerprint(value: &str, label: &str) -> Result<(), PluginSessionError> {
    let digest = value.strip_prefix("sha256:").unwrap_or_default();
    if value.len() != MAX_AGENT_LIVE_SESSION_CURSOR_SCOPE_BYTES
        || digest.len() != 64
        || !digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(policy_error(format!(
            "The {label} must be a complete sha256 fingerprint."
        )));
    }
    Ok(())
}

fn policy_error(message: impl Into<String>) -> PluginSessionError {
    PluginSessionError::new(PluginSessionErrorCode::PolicyDenied, message)
}

fn output_limit_error(message: impl Into<String>) -> PluginSessionError {
    PluginSessionError::new(PluginSessionErrorCode::OutputLimit, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contract() -> AgentLiveSessionContract {
        AgentLiveSessionContract {
            protocol_version: AGENT_LIVE_SESSION_PROTOCOL_VERSION,
            kind: AgentLiveSessionKind::Log,
            resource: AgentLiveSessionResourceDescriptor {
                resource_type: "container".into(),
                identity_schema: json!({
                    "type": "object",
                    "required": ["container_id"],
                    "properties": {
                        "container_id": { "type": "string", "minLength": 1 }
                    },
                    "additionalProperties": false
                }),
                identity_fields: vec!["/container_id".into()],
                audit_identity: AgentLiveSessionAuditIdentity::Fingerprint,
            },
            start_parameters_schema: json!({
                "type": "object",
                "properties": { "tail": { "type": "integer", "minimum": 0 } },
                "additionalProperties": false
            }),
            event_schema: json!({
                "type": "object",
                "required": ["stream", "text"],
                "properties": {
                    "stream": { "enum": ["stdout", "stderr"] },
                    "text": { "type": "string" }
                },
                "additionalProperties": false
            }),
            operations: AgentLiveSessionOperations {
                events: "docker.logs_follow".into(),
                input: None,
                resize: None,
                signal: None,
            },
            buffer: AgentLiveSessionBufferPolicy::default(),
            reconnect: AgentLiveSessionReconnectPolicy {
                mode: AgentLiveSessionReconnectMode::Transient,
                max_attempts: 5,
                initial_backoff_ms: 100,
                max_backoff_ms: 5_000,
                resume: AgentLiveSessionResumeMode::BestEffortCursor,
                cursor_kind: Some(AgentLiveSessionCursorKind::Timestamp),
            },
            delivery: AgentLiveSessionDeliveryPolicy::default(),
            control: AgentLiveSessionControlPolicy {
                cancel: AgentLiveSessionCancelBehavior::CallOnly,
                close: AgentLiveSessionCloseEffect::StopObservation,
            },
            start_risk: CapabilityRiskLevel::ReadOnly,
        }
    }

    fn start_input() -> Value {
        serde_json::to_value(AgentLiveSessionStartRequest {
            resource: json!({ "container_id": "fixture-container" }),
            parameters: json!({ "tail": 200 }),
            resume_from: Some(AgentLiveSessionCursor {
                kind: AgentLiveSessionCursorKind::Timestamp,
                value: "2026-07-24T00:00:00Z".into(),
                scope: None,
            }),
            buffer: Some(AgentLiveSessionBufferPolicy {
                max_events: 500,
                max_bytes: 512 * 1024,
                overflow: AgentLiveSessionBufferOverflow::DropOldest,
            }),
        })
        .expect("serialize start")
    }

    #[test]
    fn contract_composes_handoff_operations_with_bounded_start_input() {
        let contract = contract();
        contract
            .validate(&["docker.logs_follow".into()])
            .expect("valid contract");
        contract
            .validate_start(&start_input())
            .expect("valid start input");

        let mut invalid = start_input();
        invalid["parameters"]["tail"] = json!("all");
        assert_eq!(
            contract
                .validate_start(&invalid)
                .expect_err("schema mismatch")
                .code,
            PluginSessionErrorCode::PolicyDenied
        );

        let mut oversized = start_input();
        oversized["buffer"]["max_bytes"] = json!(MAX_AGENT_LIVE_SESSION_BUFFER_BYTES + 1);
        assert_eq!(
            contract
                .validate_start(&oversized)
                .expect_err("oversized buffer")
                .code,
            PluginSessionErrorCode::PolicyDenied
        );
    }

    #[test]
    fn discovery_handoff_serializes_the_live_contract_without_changing_legacy_defaults() {
        let handoff = crate::capability::CapabilitySessionHandoff::new(
            crate::session::PluginSessionPurpose::LogStream,
            ["docker.logs_follow"],
        )
        .with_live_session(contract());
        let encoded = serde_json::to_value(&handoff).expect("serialize handoff");
        assert_eq!(encoded["live_session"]["protocol_version"], 1);
        assert_eq!(encoded["live_session"]["kind"]["kind"], "log");
        assert_eq!(
            encoded["live_session"]["operations"]["events"],
            "docker.logs_follow"
        );

        let legacy: crate::capability::CapabilitySessionHandoff = serde_json::from_value(json!({
            "purpose": { "kind": "log_stream" },
            "capabilities": ["docker.logs_follow"]
        }))
        .expect("legacy handoff");
        assert_eq!(legacy.live_session, None);
    }

    #[test]
    fn contract_rejects_unbound_operations_and_unsafe_close_classification() {
        let mut unbound = contract();
        unbound.operations.input = Some("docker.exec_input".into());
        assert_eq!(
            unbound
                .validate(&["docker.logs_follow".into()])
                .expect_err("unbound operation")
                .code,
            PluginSessionErrorCode::PolicyDenied
        );

        let mut unsafe_close = contract();
        unsafe_close.control.close = AgentLiveSessionCloseEffect::TerminateRemote;
        assert_eq!(
            unsafe_close
                .validate(&["docker.logs_follow".into()])
                .expect_err("unsafe close")
                .code,
            PluginSessionErrorCode::PolicyDenied
        );
        unsafe_close.start_risk = CapabilityRiskLevel::ExternalSideEffect;
        unsafe_close
            .validate(&["docker.logs_follow".into()])
            .expect("acknowledged risk classification");
        assert!(unsafe_close.start_requires_acknowledgement());
    }

    #[test]
    fn event_batches_are_schema_checked_ordered_and_bounded() {
        let contract = contract();
        let first = AgentLiveSessionEventEnvelope::bounded(
            1,
            Utc::now(),
            AgentLiveSessionEventKind::Data,
            json!({ "stream": "stdout", "text": "ready" }),
            Some(AgentLiveSessionCursor {
                kind: AgentLiveSessionCursorKind::Timestamp,
                value: "2026-07-24T00:00:01Z".into(),
                scope: None,
            }),
            RedactionStatus::Applied,
            false,
        )
        .expect("event");
        let request = AgentLiveSessionReadRequest::default();
        let batch = AgentLiveSessionEventBatch {
            protocol_version: AGENT_LIVE_SESSION_PROTOCOL_VERSION,
            events: vec![first.clone()],
            next_sequence: 2,
            resume_cursor: first.cursor.clone(),
            checkpoint: first
                .cursor
                .clone()
                .map(|cursor| AgentLiveSessionCheckpoint {
                    sequence: first.sequence,
                    cursor,
                }),
            oldest_available_sequence: Some(1),
            truncated: Some(false),
            timed_out: false,
            source_closed: false,
            dropped_events: 3,
            dropped_bytes: 12,
            coalesced_events: 0,
            reconnect_attempts: 1,
        };
        batch
            .validate(&request, &contract)
            .expect("valid event batch");

        let mut unordered = batch;
        unordered.next_sequence = 1;
        assert_eq!(
            unordered
                .validate(&request, &contract)
                .expect_err("sequence did not advance")
                .code,
            PluginSessionErrorCode::PolicyDenied
        );
    }

    #[test]
    fn scoped_cursor_heartbeat_checkpoint_and_source_pacing_are_enforced() {
        let mut contract = contract();
        contract.kind = AgentLiveSessionKind::Cursor;
        contract.delivery = AgentLiveSessionDeliveryPolicy {
            backpressure: AgentLiveSessionBackpressureMode::SourcePaced,
            cursor_scope: AgentLiveSessionCursorScopePolicy::Required,
            heartbeat: AgentLiveSessionHeartbeatPolicy {
                interval_ms: Some(1_000),
                idle_timeout_ms: Some(5_000),
            },
            max_read_wait_ms: 5_000,
        };
        contract
            .validate(&["docker.logs_follow".into()])
            .expect("source-paced contract");

        let scoped_cursor = AgentLiveSessionCursor {
            kind: AgentLiveSessionCursorKind::Timestamp,
            value: "opaque-resume-token".into(),
            scope: Some(
                "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
            ),
        };
        let heartbeat = AgentLiveSessionEventEnvelope::bounded(
            1,
            Utc::now(),
            AgentLiveSessionEventKind::Heartbeat,
            Value::Null,
            Some(scoped_cursor.clone()),
            RedactionStatus::NotRequired,
            false,
        )
        .expect("heartbeat envelope");
        contract
            .validate_event(&heartbeat)
            .expect("declared heartbeat");

        let mut raw_scope = scoped_cursor.clone();
        raw_scope.scope = Some("redis:raw-key-name".into());
        assert!(raw_scope.validate().is_err());

        let mut contentful = heartbeat.clone();
        contentful.data = json!({ "driver_state": "must-not-leak" });
        contentful.data_bytes = serde_json::to_vec(&contentful.data).unwrap().len();
        assert!(contract.validate_event(&contentful).is_err());

        let request = AgentLiveSessionReadRequest {
            wait_timeout_ms: 5_000,
            ..AgentLiveSessionReadRequest::default()
        };
        let mut batch = AgentLiveSessionEventBatch {
            protocol_version: AGENT_LIVE_SESSION_PROTOCOL_VERSION,
            events: vec![heartbeat],
            next_sequence: 2,
            resume_cursor: Some(scoped_cursor.clone()),
            checkpoint: Some(AgentLiveSessionCheckpoint {
                sequence: 1,
                cursor: scoped_cursor,
            }),
            oldest_available_sequence: Some(1),
            truncated: Some(false),
            timed_out: false,
            source_closed: false,
            dropped_events: 0,
            dropped_bytes: 0,
            coalesced_events: 0,
            reconnect_attempts: 0,
        };
        batch
            .validate(&request, &contract)
            .expect("lossless source-paced batch");
        let mut missing_compatibility_cursor = batch.clone();
        missing_compatibility_cursor.resume_cursor = None;
        assert!(
            missing_compatibility_cursor
                .validate(&request, &contract)
                .is_err()
        );
        batch.dropped_events = 1;
        assert!(batch.validate(&request, &contract).is_err());

        let mut unscoped = start_input();
        unscoped["resume_from"]["scope"] = Value::Null;
        assert!(contract.validate_start(&unscoped).is_err());
    }

    #[test]
    fn data_search_protocols_map_to_shared_scoped_cursor_envelopes() {
        let cases = [
            (
                "redis.stream_read",
                "redis_stream",
                AgentLiveSessionKind::Cursor,
                AgentLiveSessionCursorKind::EventId,
                AgentLiveSessionResumeMode::BestEffortCursor,
            ),
            (
                "mongodb.change_stream_read",
                "mongodb_change_stream",
                AgentLiveSessionKind::Cursor,
                AgentLiveSessionCursorKind::Opaque,
                AgentLiveSessionResumeMode::ExactCursor,
            ),
            (
                "elasticsearch.search_stream_read",
                "elasticsearch_index_search",
                AgentLiveSessionKind::Cursor,
                AgentLiveSessionCursorKind::Opaque,
                AgentLiveSessionResumeMode::BestEffortCursor,
            ),
        ];

        for (capability, resource_type, kind, cursor_kind, resume) in cases {
            let mut mapped = contract();
            mapped.kind = kind;
            mapped.resource.resource_type = resource_type.into();
            mapped.operations.events = capability.into();
            mapped.reconnect = AgentLiveSessionReconnectPolicy {
                mode: AgentLiveSessionReconnectMode::Transient,
                max_attempts: 8,
                initial_backoff_ms: 250,
                max_backoff_ms: 10_000,
                resume,
                cursor_kind: Some(cursor_kind),
            };
            mapped.delivery = AgentLiveSessionDeliveryPolicy {
                backpressure: AgentLiveSessionBackpressureMode::SourcePaced,
                cursor_scope: AgentLiveSessionCursorScopePolicy::Required,
                heartbeat: AgentLiveSessionHeartbeatPolicy {
                    interval_ms: Some(5_000),
                    idle_timeout_ms: Some(20_000),
                },
                max_read_wait_ms: 20_000,
            };
            mapped
                .validate(&[capability.into()])
                .expect("data/search mapping");
            assert_eq!(
                mapped
                    .effective_read_wait_ms(&AgentLiveSessionReadRequest::default())
                    .unwrap(),
                20_000
            );

            let mut start = start_input();
            start["resume_from"] = serde_json::to_value(AgentLiveSessionCursor {
                kind: cursor_kind,
                value: "opaque-native-token".into(),
                scope: Some(
                    "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
                        .into(),
                ),
            })
            .unwrap();
            mapped.validate_start(&start).expect("scoped resume token");

            let encoded = serde_json::to_string(&mapped).unwrap();
            for forbidden in [
                "client_handle",
                "connection_handle",
                "cursor_object",
                "pit_id",
            ] {
                assert!(!encoded.contains(forbidden), "{capability}: {forbidden}");
            }
        }
    }

    #[test]
    fn cursor_scope_is_canonical_and_binds_namespace_and_query() {
        let first = agent_live_session_cursor_scope(
            "mongodb.change_stream_read",
            &json!({
                "resource": { "collection": "events", "database": "app" },
                "pipeline": [{ "$match": { "tenant": 7 } }]
            }),
        )
        .unwrap();
        let reordered = agent_live_session_cursor_scope(
            "mongodb.change_stream_read",
            &json!({
                "pipeline": [{ "$match": { "tenant": 7 } }],
                "resource": { "database": "app", "collection": "events" }
            }),
        )
        .unwrap();
        let other_query = agent_live_session_cursor_scope(
            "mongodb.change_stream_read",
            &json!({
                "resource": { "database": "app", "collection": "events" },
                "pipeline": [{ "$match": { "tenant": 8 } }]
            }),
        )
        .unwrap();
        let other_family = agent_live_session_cursor_scope(
            "elasticsearch.search_stream_read",
            &json!({
                "resource": { "database": "app", "collection": "events" },
                "pipeline": [{ "$match": { "tenant": 7 } }]
            }),
        )
        .unwrap();

        assert_eq!(first, reordered);
        assert_ne!(first, other_query);
        assert_ne!(first, other_family);
        assert_eq!(first.len(), MAX_AGENT_LIVE_SESSION_CURSOR_SCOPE_BYTES);
        assert!(first.starts_with("sha256:"));
    }

    #[test]
    fn source_paced_builder_advances_only_the_fitted_prefix() {
        let mut contract = contract();
        contract.delivery.backpressure = AgentLiveSessionBackpressureMode::SourcePaced;
        let candidates = (0..3)
            .map(|index| AgentLiveSessionEventInput {
                observed_at: Utc::now(),
                kind: AgentLiveSessionEventKind::Data,
                data: json!({ "stream": "stdout", "text": format!("event-{index}") }),
                cursor: None,
                redaction: RedactionStatus::NotRequired,
                terminal: false,
            })
            .collect::<Vec<_>>();
        let mut state = AgentLiveSessionSourcePacedState::default();
        let first_read = AgentLiveSessionReadRequest {
            after_sequence: None,
            max_events: 2,
            max_bytes: 4096,
            wait_timeout_ms: 0,
        };
        let (first, consumed) = state
            .build_batch(&first_read, &contract, &candidates, false, false)
            .unwrap();
        assert_eq!(consumed, 2);
        assert_eq!(first.events.len(), 2);
        assert_eq!(first.next_sequence, 3);
        assert_eq!(first.truncated, Some(false));

        let wrong_offset = AgentLiveSessionReadRequest {
            after_sequence: Some(1),
            ..first_read.clone()
        };
        assert!(
            state
                .build_batch(&wrong_offset, &contract, &candidates[2..], false, true)
                .is_err()
        );
        let second_read = AgentLiveSessionReadRequest {
            after_sequence: Some(2),
            ..first_read
        };
        let (second, consumed) = state
            .build_batch(&second_read, &contract, &candidates[2..], false, true)
            .unwrap();
        assert_eq!(consumed, 1);
        assert_eq!(second.events[0].sequence, 3);
        assert!(second.source_closed);
    }

    #[test]
    fn protocol_v1_defaults_decode_pre_delivery_envelopes() {
        let mut encoded_contract = serde_json::to_value(contract()).unwrap();
        encoded_contract.as_object_mut().unwrap().remove("delivery");
        let decoded_contract: AgentLiveSessionContract =
            serde_json::from_value(encoded_contract).unwrap();
        assert_eq!(
            decoded_contract.delivery,
            AgentLiveSessionDeliveryPolicy::default()
        );

        let cursor: AgentLiveSessionCursor = serde_json::from_value(json!({
            "kind": "opaque",
            "value": "legacy-token"
        }))
        .unwrap();
        assert_eq!(cursor.scope, None);

        let read: AgentLiveSessionReadRequest = serde_json::from_value(json!({
            "after_sequence": 4,
            "max_events": 10,
            "max_bytes": 4096
        }))
        .unwrap();
        assert_eq!(
            read.wait_timeout_ms,
            DEFAULT_AGENT_LIVE_SESSION_READ_WAIT_MS
        );

        let batch: AgentLiveSessionEventBatch = serde_json::from_value(json!({
            "protocol_version": 1,
            "events": [],
            "next_sequence": 1,
            "source_closed": false,
            "dropped_events": 0,
            "dropped_bytes": 0,
            "coalesced_events": 0,
            "reconnect_attempts": 0
        }))
        .unwrap();
        assert_eq!(batch.checkpoint, None);
        assert_eq!(batch.truncated, None);
        assert!(!batch.timed_out);

        let legacy_event = AgentLiveSessionEventEnvelope::bounded(
            2,
            Utc::now(),
            AgentLiveSessionEventKind::Data,
            json!({ "stream": "stdout", "text": "retained after loss" }),
            None,
            RedactionStatus::Applied,
            false,
        )
        .unwrap();
        let mut legacy_loss = serde_json::to_value(AgentLiveSessionEventBatch {
            protocol_version: AGENT_LIVE_SESSION_PROTOCOL_VERSION,
            events: vec![legacy_event],
            next_sequence: 3,
            resume_cursor: None,
            checkpoint: None,
            oldest_available_sequence: Some(2),
            truncated: Some(true),
            timed_out: false,
            source_closed: false,
            dropped_events: 1,
            dropped_bytes: 10,
            coalesced_events: 0,
            reconnect_attempts: 0,
        })
        .unwrap();
        legacy_loss.as_object_mut().unwrap().remove("truncated");
        legacy_loss
            .as_object_mut()
            .unwrap()
            .remove("oldest_available_sequence");
        let legacy_loss: AgentLiveSessionEventBatch = serde_json::from_value(legacy_loss).unwrap();
        assert_eq!(legacy_loss.truncated, None);
        legacy_loss
            .validate(&AgentLiveSessionReadRequest::default(), &contract())
            .expect("pre-extension loss batch remains valid");
    }

    #[test]
    fn withheld_events_fail_closed_without_payload_data() {
        let protected = "credential-looking-output";
        let event = AgentLiveSessionEventEnvelope::bounded(
            1,
            Utc::now(),
            AgentLiveSessionEventKind::Warning,
            json!({ "text": protected }),
            None,
            RedactionStatus::FailedClosed,
            false,
        )
        .expect("failed-closed event");
        assert_eq!(event.data, Value::Null);
        assert_eq!(event.data_bytes, 0);
        assert!(!serde_json::to_string(&event).unwrap().contains(protected));
    }

    #[test]
    fn audit_summary_has_no_raw_resource_cursor_or_event_fields() {
        let summary = AgentLiveSessionAuditSummary {
            protocol_version: AGENT_LIVE_SESSION_PROTOCOL_VERSION,
            kind: AgentLiveSessionKind::Log,
            resource_type: "container".into(),
            resource_fingerprint: Some("sha256:0123456789abcdef".into()),
            start_risk: CapabilityRiskLevel::ReadOnly,
            state: AgentLiveSessionAuditState::Closed,
            started_at: Utc::now(),
            finished_at: None,
            delivered_events: 10,
            delivered_bytes: 200,
            dropped_events: 2,
            dropped_bytes: 40,
            coalesced_events: 0,
            reconnect_attempts: 1,
            resume: AgentLiveSessionResumeOutcome::Accepted,
            redaction: RedactionStatus::Applied,
        };
        summary.validate().expect("audit summary");
        let encoded = serde_json::to_string(&summary).expect("serialize summary");
        for forbidden in ["container_id", "cursor", "event_data", "stdin", "command"] {
            assert!(!encoded.contains(forbidden));
        }
    }
}
