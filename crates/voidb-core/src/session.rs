//! Shared plugin session descriptors and lifecycle registry.
//!
//! The registry coordinates session metadata, leases, reuse, and shutdown
//! requests. Live protocol handles remain inside the owning plugin service.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;

use crate::capability::{ConnectionProfileRef, PluginId, RedactionStatus};

pub type PluginSessionId = String;
pub type PluginSessionOwnerId = String;
pub type PluginSessionReason = String;

pub const MAX_PLUGIN_SESSION_METADATA_BYTES: usize = 4096;
pub const DEFAULT_AGENT_SESSION_OUTPUT_BYTES: usize = 64 * 1024;
pub const MAX_AGENT_SESSION_OUTPUT_BYTES: usize = 1024 * 1024;
pub const AGENT_BROKER_LEGACY_PROTOCOL_VERSION: u32 = 1;
pub const AGENT_BROKER_PROTOCOL_VERSION: u32 = 2;
pub const AGENT_BROKER_SUPPORTED_PROTOCOL_VERSIONS: &[u32] = &[
    AGENT_BROKER_LEGACY_PROTOCOL_VERSION,
    AGENT_BROKER_PROTOCOL_VERSION,
];
pub const MAX_AGENT_SESSION_CALL_ID_BYTES: usize = 128;
pub const DEFAULT_AGENT_SESSION_CANCEL_TIMEOUT_MS: u64 = 1_000;
pub const DEFAULT_AGENT_SESSION_CLOSE_TIMEOUT_MS: u64 = 5_000;
pub const MAX_AGENT_SESSION_CONTROL_TIMEOUT_MS: u64 = 30_000;
pub const DEFAULT_AGENT_SESSION_WAIT_TIMEOUT_MS: u64 = 30_000;
pub const MAX_AGENT_SESSION_WAIT_TIMEOUT_MS: u64 = 30_000;

static NEXT_PLUGIN_SESSION_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum PluginSessionPurpose {
    InteractiveTerminal,
    FileTransfer,
    PortForward,
    DatabaseQuery,
    DatabaseTransaction,
    CacheCommand,
    LogStream,
    WatchStream,
    InfrastructureClient,
    SyncClient,
    CapabilityInvocation,
    PluginDefined(String),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginSessionScope {
    LocalOnly,
    #[default]
    LocalProcess,
    RemoteTarget,
    HostedService,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginSessionHealth {
    #[default]
    Starting,
    Ready,
    Busy,
    Degraded,
    Stale,
    Closing,
    Closed,
    Failed,
}

impl PluginSessionHealth {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            PluginSessionHealth::Stale
                | PluginSessionHealth::Closing
                | PluginSessionHealth::Closed
                | PluginSessionHealth::Failed
        )
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PluginSessionDescriptor {
    pub session_id: PluginSessionId,
    pub plugin_id: PluginId,
    pub owner_id: PluginSessionOwnerId,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_ref: Option<ConnectionProfileRef>,

    pub purpose: PluginSessionPurpose,
    pub scope: PluginSessionScope,
    pub health: PluginSessionHealth,

    #[serde(default)]
    pub authenticated: bool,

    #[serde(default)]
    pub destructive_capable: bool,

    #[serde(default)]
    pub stream_capable: bool,

    pub created_at: DateTime<Utc>,
    pub last_used_at: DateTime<Utc>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_expires_at: Option<DateTime<Utc>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub closed_at: Option<DateTime<Utc>>,

    #[serde(default = "default_generation")]
    pub generation: u64,

    #[serde(default)]
    pub redaction: RedactionStatus,

    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub metadata: Value,

    #[serde(default)]
    pub active_leases: usize,
}

impl PluginSessionDescriptor {
    pub fn new(
        plugin_id: impl Into<PluginId>,
        owner_id: impl Into<PluginSessionOwnerId>,
        purpose: PluginSessionPurpose,
        scope: PluginSessionScope,
    ) -> Self {
        Self::new_at(plugin_id, owner_id, purpose, scope, Utc::now())
    }

    pub fn new_at(
        plugin_id: impl Into<PluginId>,
        owner_id: impl Into<PluginSessionOwnerId>,
        purpose: PluginSessionPurpose,
        scope: PluginSessionScope,
        now: DateTime<Utc>,
    ) -> Self {
        Self {
            session_id: next_plugin_session_id(now),
            plugin_id: plugin_id.into(),
            owner_id: owner_id.into(),
            profile_ref: None,
            purpose,
            scope,
            health: PluginSessionHealth::Starting,
            authenticated: false,
            destructive_capable: false,
            stream_capable: false,
            created_at: now,
            last_used_at: now,
            lease_expires_at: None,
            closed_at: None,
            generation: default_generation(),
            redaction: RedactionStatus::NotRequired,
            metadata: Value::Null,
            active_leases: 0,
        }
    }

    pub fn reuse_key(
        &self,
        compatibility_fingerprint: Option<impl Into<String>>,
    ) -> PluginSessionReuseKey {
        PluginSessionReuseKey {
            plugin_id: self.plugin_id.clone(),
            profile_ref: self.profile_ref.clone(),
            purpose: self.purpose.clone(),
            scope: self.scope,
            compatibility_fingerprint: compatibility_fingerprint.map(Into::into),
        }
    }

    pub fn is_reusable_at(&self, now: DateTime<Utc>) -> bool {
        if self.health.is_terminal() {
            return false;
        }
        if let Some(expires_at) = self.lease_expires_at
            && expires_at <= now
        {
            return false;
        }
        matches!(
            self.health,
            PluginSessionHealth::Ready | PluginSessionHealth::Busy | PluginSessionHealth::Degraded
        )
    }

    fn is_expired_at(&self, now: DateTime<Utc>) -> bool {
        if self.health.is_terminal() {
            return false;
        }
        self.lease_expires_at
            .map(|expires_at| expires_at <= now)
            .unwrap_or(false)
    }
}

fn default_generation() -> u64 {
    1
}

fn next_plugin_session_id(now: DateTime<Utc>) -> PluginSessionId {
    let sequence = NEXT_PLUGIN_SESSION_ID.fetch_add(1, Ordering::Relaxed);
    format!("plugin-session-{}-{}", now.timestamp_micros(), sequence)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PluginSessionReuseKey {
    pub plugin_id: PluginId,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_ref: Option<ConnectionProfileRef>,

    pub purpose: PluginSessionPurpose,
    pub scope: PluginSessionScope,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compatibility_fingerprint: Option<String>,
}

impl PluginSessionReuseKey {
    pub fn new(
        plugin_id: impl Into<PluginId>,
        purpose: PluginSessionPurpose,
        scope: PluginSessionScope,
    ) -> Self {
        Self {
            plugin_id: plugin_id.into(),
            profile_ref: None,
            purpose,
            scope,
            compatibility_fingerprint: None,
        }
    }

    pub fn with_profile_ref(mut self, profile_ref: ConnectionProfileRef) -> Self {
        self.profile_ref = Some(profile_ref);
        self
    }

    pub fn with_compatibility_fingerprint(mut self, fingerprint: impl Into<String>) -> Self {
        self.compatibility_fingerprint = Some(fingerprint.into());
        self
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginSessionReusePolicy {
    #[default]
    Allow,
    Require,
    Never,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PluginSessionLease {
    pub session_id: PluginSessionId,
    pub plugin_id: PluginId,
    pub owner_id: PluginSessionOwnerId,
    pub generation: u64,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_expires_at: Option<DateTime<Utc>>,
}

/// Opaque agent-facing reference to one live plugin-owned session generation.
///
/// The host must verify the grant binding separately. A generation change means
/// that transport reconnect or owner replacement lost semantic session state.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AgentSessionRef {
    pub session_id: PluginSessionId,
    pub generation: u64,
}

impl AgentSessionRef {
    pub fn new(session_id: impl Into<PluginSessionId>, generation: u64) -> Self {
        Self {
            session_id: session_id.into(),
            generation,
        }
    }
}

/// Immutable security scope attached by the host when a session opens.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentSessionBinding {
    pub grant_id: String,
    pub profile_id: String,
    pub plugin_id: PluginId,
    pub purpose: PluginSessionPurpose,

    #[serde(default)]
    pub allowed_capabilities: Vec<String>,

    pub host_generation: u64,
}

impl AgentSessionBinding {
    pub fn allows_capability(&self, capability: &str) -> bool {
        let unqualified = capability
            .split_once('.')
            .map(|(_, operation)| operation)
            .unwrap_or(capability);
        self.allowed_capabilities
            .iter()
            .any(|allowed| allowed == "*" || allowed == capability || allowed == unqualified)
    }

    pub fn validate(
        &self,
        grant_id: &str,
        profile_id: &str,
        plugin_id: &str,
        host_generation: u64,
    ) -> Result<(), PluginSessionError> {
        if self.grant_id != grant_id
            || self.profile_id != profile_id
            || self.plugin_id != plugin_id
            || self.host_generation != host_generation
        {
            return Err(PluginSessionError::new(
                PluginSessionErrorCode::BindingMismatch,
                "Session is outside the active grant, profile, plugin, or host generation.",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentSessionConcurrency {
    #[default]
    Serialized,
    Multiplexed,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentSessionContinuity {
    #[default]
    Original,
    ReconnectedStateLost,
}

pub fn is_supported_agent_broker_protocol_version(version: u32) -> bool {
    AGENT_BROKER_SUPPORTED_PROTOCOL_VERSIONS.contains(&version)
}

pub fn validate_agent_session_call_id(call_id: &str) -> Result<(), PluginSessionError> {
    let valid = !call_id.is_empty()
        && call_id.len() <= MAX_AGENT_SESSION_CALL_ID_BYTES
        && call_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'));
    if valid {
        Ok(())
    } else {
        Err(PluginSessionError::new(
            PluginSessionErrorCode::CallIdInvalid,
            format!(
                "Session call IDs must be 1 to {MAX_AGENT_SESSION_CALL_ID_BYTES} bytes and use only A-Z, a-z, 0-9, '-', '_', '.', or ':'."
            ),
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentSessionCallState {
    Accepted,
    Running,
    CancelRequested,
    Succeeded,
    Failed,
    Cancelled,
    TimedOut,
    Aborted,
}

impl AgentSessionCallState {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::Cancelled | Self::TimedOut | Self::Aborted
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentSessionControlKind {
    Cancel,
    Close,
    Shutdown,
}

impl AgentSessionControlKind {
    fn priority(self) -> u8 {
        match self {
            Self::Cancel => 1,
            Self::Close => 2,
            Self::Shutdown => 3,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentSessionControlDisposition {
    Accepted,
    Escalated,
    AlreadyRequested,
    AlreadyTerminal,
}

/// Secret-free lifecycle projection for one caller-owned session call ID.
///
/// Control requests are monotonic: close outranks cancel and shutdown outranks
/// close. Once a control request is accepted, a racing successful plugin result
/// cannot make the call look successful to the caller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentSessionCallLifecycle {
    pub call_id: String,
    pub state: AgentSessionCallState,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control: Option<AgentSessionControlKind>,

    pub accepted_at: DateTime<Utc>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<DateTime<Utc>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_requested_at: Option<DateTime<Utc>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<DateTime<Utc>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline_at: Option<DateTime<Utc>>,
}

impl AgentSessionCallLifecycle {
    pub fn accepted(
        call_id: impl Into<String>,
        accepted_at: DateTime<Utc>,
        deadline_at: Option<DateTime<Utc>>,
    ) -> Result<Self, PluginSessionError> {
        let call_id = call_id.into();
        validate_agent_session_call_id(&call_id)?;
        Ok(Self {
            call_id,
            state: AgentSessionCallState::Accepted,
            control: None,
            accepted_at,
            started_at: None,
            control_requested_at: None,
            completed_at: None,
            deadline_at,
        })
    }

    pub fn mark_running(&mut self, started_at: DateTime<Utc>) -> bool {
        if self.state != AgentSessionCallState::Accepted {
            return false;
        }
        self.state = AgentSessionCallState::Running;
        self.started_at = Some(started_at);
        true
    }

    pub fn request_control(
        &mut self,
        control: AgentSessionControlKind,
        requested_at: DateTime<Utc>,
    ) -> AgentSessionControlDisposition {
        if self.state.is_terminal() {
            return AgentSessionControlDisposition::AlreadyTerminal;
        }
        let disposition = match self.control {
            None => AgentSessionControlDisposition::Accepted,
            Some(current) if control.priority() > current.priority() => {
                AgentSessionControlDisposition::Escalated
            }
            Some(_) => AgentSessionControlDisposition::AlreadyRequested,
        };
        if matches!(
            disposition,
            AgentSessionControlDisposition::Accepted | AgentSessionControlDisposition::Escalated
        ) {
            self.control = Some(control);
            self.control_requested_at = Some(requested_at);
            self.state = AgentSessionCallState::CancelRequested;
        }
        disposition
    }

    pub fn finish(
        &mut self,
        terminal_state: AgentSessionCallState,
        completed_at: DateTime<Utc>,
    ) -> Result<bool, PluginSessionError> {
        if !terminal_state.is_terminal() {
            return Err(PluginSessionError::new(
                PluginSessionErrorCode::PolicyDenied,
                "A session call may finish only in a terminal state.",
            ));
        }
        if self.state.is_terminal() {
            return Ok(false);
        }
        self.state = match self.control {
            Some(AgentSessionControlKind::Cancel) => AgentSessionCallState::Cancelled,
            Some(AgentSessionControlKind::Close | AgentSessionControlKind::Shutdown) => {
                AgentSessionCallState::Aborted
            }
            None => terminal_state,
        };
        self.completed_at = Some(completed_at);
        Ok(true)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentSessionOpenRequest {
    pub purpose: PluginSessionPurpose,

    #[serde(default)]
    pub capabilities: Vec<String>,

    pub lease_seconds: u64,

    #[serde(default)]
    pub concurrency: AgentSessionConcurrency,

    /// Per-open acknowledgement for a live-session contract whose start has
    /// target or external side effects. The grant remains a separate scope.
    #[serde(default)]
    pub destructive_acknowledged: bool,

    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub input: Value,
}

impl AgentSessionOpenRequest {
    pub fn lease_expires_at(
        &self,
        now: DateTime<Utc>,
        grant_expires_at: DateTime<Utc>,
    ) -> Result<DateTime<Utc>, PluginSessionError> {
        if self.lease_seconds == 0 {
            return Err(PluginSessionError::new(
                PluginSessionErrorCode::PolicyDenied,
                "Session lease must be greater than zero.",
            ));
        }
        let requested = i64::try_from(self.lease_seconds)
            .ok()
            .and_then(|seconds| now.checked_add_signed(Duration::seconds(seconds)))
            .unwrap_or(grant_expires_at);
        let expires_at = requested.min(grant_expires_at);
        if expires_at <= now {
            return Err(PluginSessionError::new(
                PluginSessionErrorCode::Expired,
                "Agent grant has expired.",
            ));
        }
        Ok(expires_at)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentSessionCallRequest {
    pub session: AgentSessionRef,
    pub call_id: String,
    pub capability: String,

    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub input: Value,

    #[serde(default)]
    pub destructive_acknowledged: bool,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,

    #[serde(default = "default_agent_session_output_bytes")]
    pub output_limit_bytes: usize,
}

impl AgentSessionCallRequest {
    pub fn validate_call_id(&self) -> Result<(), PluginSessionError> {
        validate_agent_session_call_id(&self.call_id)
    }

    pub fn validate_output_limit(&self) -> Result<(), PluginSessionError> {
        if self.output_limit_bytes == 0 || self.output_limit_bytes > MAX_AGENT_SESSION_OUTPUT_BYTES
        {
            return Err(PluginSessionError::new(
                PluginSessionErrorCode::PolicyDenied,
                format!(
                    "Session output limit must be between 1 and {MAX_AGENT_SESSION_OUTPUT_BYTES} bytes."
                ),
            ));
        }
        Ok(())
    }
}

fn default_agent_session_output_bytes() -> usize {
    DEFAULT_AGENT_SESSION_OUTPUT_BYTES
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentSessionCallResult {
    pub call_id: String,

    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub output: Value,

    pub output_bytes: usize,

    pub redaction: RedactionStatus,

    #[serde(default)]
    pub truncated: bool,
}

impl AgentSessionCallResult {
    pub fn bounded(
        call_id: impl Into<String>,
        output: Value,
        limit: usize,
    ) -> Result<Self, PluginSessionError> {
        let call_id = call_id.into();
        if limit == 0 || limit > MAX_AGENT_SESSION_OUTPUT_BYTES {
            return Err(PluginSessionError::new(
                PluginSessionErrorCode::PolicyDenied,
                "Invalid agent session output limit.",
            ));
        }
        let output_bytes = serde_json::to_vec(&output)
            .map_err(|error| {
                PluginSessionError::new(
                    PluginSessionErrorCode::RedactionFailed,
                    format!("Serialize bounded session output: {error}"),
                )
            })?
            .len();
        if output_bytes > limit {
            return Err(PluginSessionError::new(
                PluginSessionErrorCode::OutputLimit,
                "Plugin session output exceeded the negotiated bound.",
            ));
        }
        Ok(Self {
            call_id,
            output,
            output_bytes,
            redaction: RedactionStatus::Applied,
            truncated: false,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentSessionCallStatusRequest {
    pub session: AgentSessionRef,
    pub call_id: String,
}

impl AgentSessionCallStatusRequest {
    pub fn validate_call_id(&self) -> Result<(), PluginSessionError> {
        validate_agent_session_call_id(&self.call_id)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentSessionCallWaitRequest {
    pub session: AgentSessionRef,
    pub call_id: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

impl AgentSessionCallWaitRequest {
    pub fn validate_call_id(&self) -> Result<(), PluginSessionError> {
        validate_agent_session_call_id(&self.call_id)
    }

    pub fn timeout(&self) -> Result<std::time::Duration, PluginSessionError> {
        let timeout_ms = self
            .timeout_ms
            .unwrap_or(DEFAULT_AGENT_SESSION_WAIT_TIMEOUT_MS);
        if timeout_ms == 0 || timeout_ms > MAX_AGENT_SESSION_WAIT_TIMEOUT_MS {
            return Err(PluginSessionError::new(
                PluginSessionErrorCode::PolicyDenied,
                format!(
                    "Session call wait timeout must be between 1 and {MAX_AGENT_SESSION_WAIT_TIMEOUT_MS} milliseconds."
                ),
            ));
        }
        Ok(std::time::Duration::from_millis(timeout_ms))
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentSessionCallView {
    pub session: AgentSessionRef,
    pub capability: String,
    pub lifecycle: AgentSessionCallLifecycle,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<AgentSessionCallResult>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<PluginSessionError>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentSessionCallWaitResult {
    pub call: AgentSessionCallView,
    pub wait_timed_out: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentSessionView {
    pub session: AgentSessionRef,
    pub binding: AgentSessionBinding,
    pub health: PluginSessionHealth,
    pub concurrency: AgentSessionConcurrency,
    pub continuity: AgentSessionContinuity,
    pub created_at: DateTime<Utc>,
    pub last_used_at: DateTime<Utc>,
    pub lease_expires_at: DateTime<Utc>,

    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub metadata: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentSessionStatusRequest {
    pub session: AgentSessionRef,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentSessionListRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<PluginSessionPurpose>,

    #[serde(default)]
    pub include_terminal: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentSessionRenewRequest {
    pub session: AgentSessionRef,
    pub lease_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentSessionCancelRequest {
    pub session: AgentSessionRef,
    pub call_id: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

impl AgentSessionCancelRequest {
    pub fn validate_call_id(&self) -> Result<(), PluginSessionError> {
        validate_agent_session_call_id(&self.call_id)
    }

    pub fn timeout(&self) -> Result<std::time::Duration, PluginSessionError> {
        agent_session_control_timeout(
            self.timeout_ms,
            DEFAULT_AGENT_SESSION_CANCEL_TIMEOUT_MS,
            "cancel",
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentSessionCloseAgentRequest {
    pub session: AgentSessionRef,
    pub reason: PluginSessionReason,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

impl AgentSessionCloseAgentRequest {
    pub fn timeout(&self) -> Result<std::time::Duration, PluginSessionError> {
        agent_session_control_timeout(
            self.timeout_ms,
            DEFAULT_AGENT_SESSION_CLOSE_TIMEOUT_MS,
            "close",
        )
    }
}

fn agent_session_control_timeout(
    requested: Option<u64>,
    default_ms: u64,
    operation: &str,
) -> Result<std::time::Duration, PluginSessionError> {
    let timeout_ms = requested.unwrap_or(default_ms);
    if timeout_ms == 0 || timeout_ms > MAX_AGENT_SESSION_CONTROL_TIMEOUT_MS {
        return Err(PluginSessionError::new(
            PluginSessionErrorCode::PolicyDenied,
            format!(
                "Session {operation} timeout must be between 1 and {MAX_AGENT_SESSION_CONTROL_TIMEOUT_MS} milliseconds."
            ),
        ));
    }
    Ok(std::time::Duration::from_millis(timeout_ms))
}

#[derive(Debug, Clone)]
pub struct AgentSessionOpenContext {
    pub binding: AgentSessionBinding,
    pub request: AgentSessionOpenRequest,
    pub lease_expires_at: DateTime<Utc>,
}

/// Plugin-owned live session handle. Hosts serialize calls unless the handle
/// explicitly declares safe multiplexing.
#[async_trait]
pub trait PluginAgentSession: Send + Sync {
    fn concurrency(&self) -> AgentSessionConcurrency {
        AgentSessionConcurrency::Serialized
    }

    async fn call(
        &self,
        request: AgentSessionCallRequest,
    ) -> Result<AgentSessionCallResult, PluginSessionError>;

    async fn health(&self) -> Result<PluginSessionHealth, PluginSessionError>;

    async fn renew(&self, _lease_expires_at: DateTime<Utc>) -> Result<(), PluginSessionError> {
        Ok(())
    }

    async fn cancel(&self, _call_id: &str) -> Result<(), PluginSessionError> {
        Err(PluginSessionError::new(
            PluginSessionErrorCode::Unsupported,
            "This plugin session does not support call cancellation.",
        ))
    }

    async fn close(&self, reason: PluginSessionReason) -> Result<(), PluginSessionError>;
}

#[async_trait]
pub trait PluginAgentSessionFactory: Send + Sync {
    fn plugin_id(&self) -> &str;

    async fn open(
        &self,
        context: AgentSessionOpenContext,
    ) -> Result<Arc<dyn PluginAgentSession>, PluginSessionError>;
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PluginSessionCloseRequest {
    pub session_id: PluginSessionId,
    pub plugin_id: PluginId,
    pub owner_id: PluginSessionOwnerId,
    pub generation: u64,
    pub reason: PluginSessionReason,
}

pub trait PluginSessionCloser: Send + Sync {
    fn request_close(&self, request: PluginSessionCloseRequest) -> Result<(), PluginSessionError>;
}

impl<F> PluginSessionCloser for F
where
    F: Fn(PluginSessionCloseRequest) -> Result<(), PluginSessionError> + Send + Sync,
{
    fn request_close(&self, request: PluginSessionCloseRequest) -> Result<(), PluginSessionError> {
        self(request)
    }
}

#[derive(Clone)]
pub struct PluginSessionRegistration {
    pub descriptor: PluginSessionDescriptor,
    pub reuse_key: Option<PluginSessionReuseKey>,
    close_callback: Option<Arc<dyn PluginSessionCloser>>,
}

impl PluginSessionRegistration {
    pub fn new(
        plugin_id: impl Into<PluginId>,
        owner_id: impl Into<PluginSessionOwnerId>,
        purpose: PluginSessionPurpose,
        scope: PluginSessionScope,
    ) -> Self {
        Self::new_at(plugin_id, owner_id, purpose, scope, Utc::now())
    }

    pub fn new_at(
        plugin_id: impl Into<PluginId>,
        owner_id: impl Into<PluginSessionOwnerId>,
        purpose: PluginSessionPurpose,
        scope: PluginSessionScope,
        now: DateTime<Utc>,
    ) -> Self {
        let descriptor = PluginSessionDescriptor::new_at(plugin_id, owner_id, purpose, scope, now);
        let reuse_key = Some(descriptor.reuse_key(None::<String>));
        Self {
            descriptor,
            reuse_key,
            close_callback: None,
        }
    }

    pub fn from_descriptor(descriptor: PluginSessionDescriptor) -> Self {
        let reuse_key = Some(descriptor.reuse_key(None::<String>));
        Self {
            descriptor,
            reuse_key,
            close_callback: None,
        }
    }

    pub fn with_session_id(mut self, session_id: impl Into<PluginSessionId>) -> Self {
        self.descriptor.session_id = session_id.into();
        self
    }

    pub fn with_profile_ref(mut self, profile_ref: ConnectionProfileRef) -> Self {
        self.descriptor.profile_ref = Some(profile_ref.clone());
        if let Some(reuse_key) = &mut self.reuse_key {
            reuse_key.profile_ref = Some(profile_ref);
        }
        self
    }

    pub fn with_reuse_fingerprint(mut self, fingerprint: impl Into<String>) -> Self {
        if let Some(reuse_key) = &mut self.reuse_key {
            reuse_key.compatibility_fingerprint = Some(fingerprint.into());
        }
        self
    }

    pub fn with_reuse_key(mut self, reuse_key: Option<PluginSessionReuseKey>) -> Self {
        self.reuse_key = reuse_key;
        self
    }

    pub fn with_health(mut self, health: PluginSessionHealth) -> Self {
        self.descriptor.health = health;
        self
    }

    pub fn with_lease_expires_at(mut self, expires_at: DateTime<Utc>) -> Self {
        self.descriptor.lease_expires_at = Some(expires_at);
        self
    }

    pub fn with_authenticated(mut self, authenticated: bool) -> Self {
        self.descriptor.authenticated = authenticated;
        self
    }

    pub fn with_destructive_capable(mut self, destructive_capable: bool) -> Self {
        self.descriptor.destructive_capable = destructive_capable;
        self
    }

    pub fn with_stream_capable(mut self, stream_capable: bool) -> Self {
        self.descriptor.stream_capable = stream_capable;
        self
    }

    pub fn with_metadata(mut self, metadata: Value, redaction: RedactionStatus) -> Self {
        self.descriptor.metadata = metadata;
        self.descriptor.redaction = redaction;
        self
    }

    pub fn with_close_callback<F>(mut self, callback: F) -> Self
    where
        F: PluginSessionCloser + 'static,
    {
        self.close_callback = Some(Arc::new(callback));
        self
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PluginSessionListFilter {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugin_id: Option<PluginId>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_id: Option<PluginSessionOwnerId>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_ref: Option<ConnectionProfileRef>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<PluginSessionPurpose>,

    #[serde(default)]
    pub include_terminal: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PluginSessionAuditEvent {
    pub operation: String,
    pub session_id: PluginSessionId,
    pub plugin_id: PluginId,
    pub owner_id: PluginSessionOwnerId,
    pub purpose: PluginSessionPurpose,
    pub scope: PluginSessionScope,
    pub health: PluginSessionHealth,
    pub timestamp: DateTime<Utc>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<PluginSessionReason>,

    #[serde(default)]
    pub redaction: RedactionStatus,

    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub metadata: Value,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PluginSessionCloseReport {
    pub closed: Vec<PluginSessionDescriptor>,
    pub failed: Vec<PluginSessionCloseFailure>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PluginSessionCloseFailure {
    pub session_id: PluginSessionId,
    pub error: PluginSessionError,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PluginSessionErrorCode {
    #[serde(rename = "session.not_found")]
    NotFound,
    #[serde(rename = "session.stale")]
    Stale,
    #[serde(rename = "session.owner_unavailable")]
    OwnerUnavailable,
    #[serde(rename = "session.incompatible_reuse")]
    IncompatibleReuse,
    #[serde(rename = "session.health_failed")]
    HealthFailed,
    #[serde(rename = "session.close_timeout")]
    CloseTimeout,
    #[serde(rename = "session.policy_denied")]
    PolicyDenied,
    #[serde(rename = "session.redaction_failed")]
    RedactionFailed,
    #[serde(rename = "session.binding_mismatch")]
    BindingMismatch,
    #[serde(rename = "session.expired")]
    Expired,
    #[serde(rename = "session.cancelled")]
    Cancelled,
    #[serde(rename = "session.unsupported")]
    Unsupported,
    #[serde(rename = "session.output_limit")]
    OutputLimit,
    #[serde(rename = "session.timeout")]
    TimedOut,
    #[serde(rename = "session.call_id_invalid")]
    CallIdInvalid,
    #[serde(rename = "session.call_id_mismatch")]
    CallIdMismatch,
    #[serde(rename = "session.control_timeout")]
    ControlTimeout,
    #[serde(rename = "session.call_not_found")]
    CallNotFound,
    #[serde(rename = "session.call_id_conflict")]
    CallIdConflict,
    #[serde(rename = "session.aborted")]
    Aborted,
}

impl PluginSessionErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotFound => "session.not_found",
            Self::Stale => "session.stale",
            Self::OwnerUnavailable => "session.owner_unavailable",
            Self::IncompatibleReuse => "session.incompatible_reuse",
            Self::HealthFailed => "session.health_failed",
            Self::CloseTimeout => "session.close_timeout",
            Self::PolicyDenied => "session.policy_denied",
            Self::RedactionFailed => "session.redaction_failed",
            Self::BindingMismatch => "session.binding_mismatch",
            Self::Expired => "session.expired",
            Self::Cancelled => "session.cancelled",
            Self::Unsupported => "session.unsupported",
            Self::OutputLimit => "session.output_limit",
            Self::TimedOut => "session.timeout",
            Self::CallIdInvalid => "session.call_id_invalid",
            Self::CallIdMismatch => "session.call_id_mismatch",
            Self::ControlTimeout => "session.control_timeout",
            Self::CallNotFound => "session.call_not_found",
            Self::CallIdConflict => "session.call_id_conflict",
            Self::Aborted => "session.aborted",
        }
    }
}

impl fmt::Display for PluginSessionErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Error)]
#[error("{code}: {message}")]
pub struct PluginSessionError {
    pub code: PluginSessionErrorCode,
    pub message: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<PluginSessionId>,
}

impl PluginSessionError {
    pub fn new(code: PluginSessionErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            session_id: None,
        }
    }

    pub fn with_session_id(mut self, session_id: impl Into<PluginSessionId>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }
}

#[derive(Default)]
pub struct PluginSessionRegistry {
    state: RwLock<PluginSessionRegistryState>,
}

#[derive(Default)]
struct PluginSessionRegistryState {
    sessions: HashMap<PluginSessionId, PluginSessionEntry>,
    audit_events: Vec<PluginSessionAuditEvent>,
}

struct PluginSessionEntry {
    descriptor: PluginSessionDescriptor,
    reuse_key: Option<PluginSessionReuseKey>,
    close_callback: Option<Arc<dyn PluginSessionCloser>>,
}

impl PluginSessionRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(
        &self,
        registration: PluginSessionRegistration,
    ) -> Result<PluginSessionDescriptor, PluginSessionError> {
        self.register_at(registration, Utc::now())
    }

    pub fn register_at(
        &self,
        registration: PluginSessionRegistration,
        now: DateTime<Utc>,
    ) -> Result<PluginSessionDescriptor, PluginSessionError> {
        let mut descriptor = registration.descriptor;
        sanitize_descriptor(&mut descriptor)?;
        validate_descriptor(&descriptor)?;
        if descriptor.generation == 0 {
            descriptor.generation = default_generation();
        }
        descriptor.last_used_at = now;

        let mut state = self.write_state();
        if state.sessions.contains_key(&descriptor.session_id) {
            return Err(PluginSessionError::new(
                PluginSessionErrorCode::PolicyDenied,
                "Session ID is already registered.",
            )
            .with_session_id(descriptor.session_id));
        }

        let descriptor_for_event = descriptor.clone();
        let descriptor_for_return = descriptor.clone();
        state.sessions.insert(
            descriptor.session_id.clone(),
            PluginSessionEntry {
                descriptor,
                reuse_key: registration.reuse_key,
                close_callback: registration.close_callback,
            },
        );
        record_event(
            &mut state,
            "session.register",
            &descriptor_for_event,
            Some("registered"),
            now,
        );
        Ok(descriptor_for_return)
    }

    pub fn acquire(
        &self,
        reuse_key: &PluginSessionReuseKey,
        policy: PluginSessionReusePolicy,
        lease_for: Option<Duration>,
    ) -> Result<Option<PluginSessionLease>, PluginSessionError> {
        self.acquire_at(reuse_key, policy, lease_for, Utc::now())
    }

    pub fn acquire_at(
        &self,
        reuse_key: &PluginSessionReuseKey,
        policy: PluginSessionReusePolicy,
        lease_for: Option<Duration>,
        now: DateTime<Utc>,
    ) -> Result<Option<PluginSessionLease>, PluginSessionError> {
        if policy == PluginSessionReusePolicy::Never {
            return Ok(None);
        }

        let mut state = self.write_state();
        let Some(session_id) = state.sessions.iter().find_map(|(session_id, entry)| {
            (entry.reuse_key.as_ref() == Some(reuse_key) && entry.descriptor.is_reusable_at(now))
                .then(|| session_id.clone())
        }) else {
            if policy == PluginSessionReusePolicy::Require {
                return Err(PluginSessionError::new(
                    PluginSessionErrorCode::IncompatibleReuse,
                    "No compatible reusable session is available.",
                ));
            }
            return Ok(None);
        };

        let descriptor = {
            let entry = state.sessions.get_mut(&session_id).expect("session exists");
            entry.descriptor.last_used_at = now;
            if let Some(lease_for) = lease_for {
                entry.descriptor.lease_expires_at = Some(now + lease_for);
            }
            entry.descriptor.active_leases += 1;
            entry.descriptor.clone()
        };
        record_event(
            &mut state,
            "session.reuse",
            &descriptor,
            Some("compatible_reuse"),
            now,
        );

        Ok(Some(PluginSessionLease {
            session_id: descriptor.session_id,
            plugin_id: descriptor.plugin_id,
            owner_id: descriptor.owner_id,
            generation: descriptor.generation,
            lease_expires_at: descriptor.lease_expires_at,
        }))
    }

    pub fn renew(
        &self,
        session_id: &str,
        expected_generation: u64,
        lease_for: Duration,
    ) -> Result<PluginSessionDescriptor, PluginSessionError> {
        self.renew_at(session_id, expected_generation, lease_for, Utc::now())
    }

    pub fn renew_at(
        &self,
        session_id: &str,
        expected_generation: u64,
        lease_for: Duration,
        now: DateTime<Utc>,
    ) -> Result<PluginSessionDescriptor, PluginSessionError> {
        let mut state = self.write_state();
        let descriptor = {
            let entry = entry_mut(&mut state, session_id)?;
            assert_generation(&entry.descriptor, expected_generation)?;
            if entry.descriptor.health.is_terminal() {
                return Err(PluginSessionError::new(
                    PluginSessionErrorCode::Stale,
                    "Session is not active.",
                )
                .with_session_id(session_id));
            }
            entry.descriptor.last_used_at = now;
            entry.descriptor.lease_expires_at = Some(now + lease_for);
            entry.descriptor.clone()
        };
        record_event(
            &mut state,
            "session.renew",
            &descriptor,
            Some("lease_renewed"),
            now,
        );
        Ok(descriptor)
    }

    pub fn release(
        &self,
        session_id: &str,
        expected_generation: u64,
    ) -> Result<PluginSessionDescriptor, PluginSessionError> {
        self.release_at(session_id, expected_generation, Utc::now())
    }

    pub fn release_at(
        &self,
        session_id: &str,
        expected_generation: u64,
        now: DateTime<Utc>,
    ) -> Result<PluginSessionDescriptor, PluginSessionError> {
        let mut state = self.write_state();
        let descriptor = {
            let entry = entry_mut(&mut state, session_id)?;
            assert_generation(&entry.descriptor, expected_generation)?;
            entry.descriptor.last_used_at = now;
            entry.descriptor.active_leases = entry.descriptor.active_leases.saturating_sub(1);
            entry.descriptor.clone()
        };
        record_event(
            &mut state,
            "session.release",
            &descriptor,
            Some("lease_released"),
            now,
        );
        Ok(descriptor)
    }

    pub fn update_health(
        &self,
        session_id: &str,
        expected_generation: u64,
        health: PluginSessionHealth,
        reason: impl Into<String>,
    ) -> Result<PluginSessionDescriptor, PluginSessionError> {
        self.update_health_at(session_id, expected_generation, health, reason, Utc::now())
    }

    pub fn update_health_at(
        &self,
        session_id: &str,
        expected_generation: u64,
        health: PluginSessionHealth,
        reason: impl Into<String>,
        now: DateTime<Utc>,
    ) -> Result<PluginSessionDescriptor, PluginSessionError> {
        let reason = reason.into();
        let mut state = self.write_state();
        let descriptor = {
            let entry = entry_mut(&mut state, session_id)?;
            assert_generation(&entry.descriptor, expected_generation)?;
            entry.descriptor.health = health;
            entry.descriptor.last_used_at = now;
            entry.descriptor.generation += 1;
            if health == PluginSessionHealth::Closed {
                entry.descriptor.closed_at = Some(now);
                entry.descriptor.active_leases = 0;
            }
            entry.descriptor.clone()
        };
        record_event(
            &mut state,
            "session.health",
            &descriptor,
            Some(&reason),
            now,
        );
        Ok(descriptor)
    }

    pub fn invalidate(
        &self,
        session_id: &str,
        reason: impl Into<String>,
    ) -> Result<PluginSessionDescriptor, PluginSessionError> {
        self.invalidate_at(session_id, reason, Utc::now())
    }

    pub fn invalidate_at(
        &self,
        session_id: &str,
        reason: impl Into<String>,
        now: DateTime<Utc>,
    ) -> Result<PluginSessionDescriptor, PluginSessionError> {
        let reason = reason.into();
        let mut state = self.write_state();
        let descriptor = {
            let entry = entry_mut(&mut state, session_id)?;
            entry.descriptor.health = PluginSessionHealth::Stale;
            entry.descriptor.last_used_at = now;
            entry.descriptor.active_leases = 0;
            entry.descriptor.generation += 1;
            entry.descriptor.clone()
        };
        record_event(
            &mut state,
            "session.invalidate",
            &descriptor,
            Some(&reason),
            now,
        );
        Ok(descriptor)
    }

    pub fn close(
        &self,
        session_id: &str,
        reason: impl Into<String>,
    ) -> Result<PluginSessionDescriptor, PluginSessionError> {
        self.close_at(session_id, reason, Utc::now())
    }

    pub fn close_at(
        &self,
        session_id: &str,
        reason: impl Into<String>,
        now: DateTime<Utc>,
    ) -> Result<PluginSessionDescriptor, PluginSessionError> {
        self.close_with_operation_at(session_id, reason, "session.close", now)
    }

    pub fn close_owner(
        &self,
        owner_id: &str,
        reason: impl Into<String>,
    ) -> PluginSessionCloseReport {
        self.close_owner_at(owner_id, reason, Utc::now())
    }

    pub fn close_owner_at(
        &self,
        owner_id: &str,
        reason: impl Into<String>,
        now: DateTime<Utc>,
    ) -> PluginSessionCloseReport {
        let reason = reason.into();
        let session_ids = {
            let state = self.read_state();
            state
                .sessions
                .values()
                .filter(|entry| {
                    entry.descriptor.owner_id == owner_id && !entry.descriptor.health.is_terminal()
                })
                .map(|entry| entry.descriptor.session_id.clone())
                .collect::<Vec<_>>()
        };
        self.close_many_at(session_ids, reason, "session.close", now)
    }

    pub fn shutdown(&self, reason: impl Into<String>) -> PluginSessionCloseReport {
        self.shutdown_at(reason, Utc::now())
    }

    pub fn shutdown_at(
        &self,
        reason: impl Into<String>,
        now: DateTime<Utc>,
    ) -> PluginSessionCloseReport {
        let reason = reason.into();
        let session_ids = {
            let state = self.read_state();
            state
                .sessions
                .values()
                .filter(|entry| !entry.descriptor.health.is_terminal())
                .map(|entry| entry.descriptor.session_id.clone())
                .collect::<Vec<_>>()
        };
        self.close_many_at(session_ids, reason, "session.shutdown", now)
    }

    pub fn expire(&self, reason: impl Into<String>) -> Vec<PluginSessionDescriptor> {
        self.expire_at(Utc::now(), reason)
    }

    pub fn expire_at(
        &self,
        now: DateTime<Utc>,
        reason: impl Into<String>,
    ) -> Vec<PluginSessionDescriptor> {
        let reason = reason.into();
        let mut state = self.write_state();
        let session_ids = state
            .sessions
            .iter()
            .filter(|(_, entry)| entry.descriptor.is_expired_at(now))
            .map(|(session_id, _)| session_id.clone())
            .collect::<Vec<_>>();

        let mut expired = Vec::new();
        for session_id in session_ids {
            let descriptor = {
                let entry = state.sessions.get_mut(&session_id).expect("session exists");
                entry.descriptor.health = PluginSessionHealth::Stale;
                entry.descriptor.last_used_at = now;
                entry.descriptor.active_leases = 0;
                entry.descriptor.generation += 1;
                entry.descriptor.clone()
            };
            record_event(
                &mut state,
                "session.health",
                &descriptor,
                Some(&reason),
                now,
            );
            expired.push(descriptor);
        }

        expired
    }

    pub fn get(&self, session_id: &str) -> Option<PluginSessionDescriptor> {
        self.read_state()
            .sessions
            .get(session_id)
            .map(|entry| entry.descriptor.clone())
    }

    pub fn list(&self, filter: PluginSessionListFilter) -> Vec<PluginSessionDescriptor> {
        let mut sessions = self
            .read_state()
            .sessions
            .values()
            .filter(|entry| session_matches_filter(&entry.descriptor, &filter))
            .map(|entry| entry.descriptor.clone())
            .collect::<Vec<_>>();
        sessions.sort_by(|left, right| {
            left.created_at
                .cmp(&right.created_at)
                .then_with(|| left.session_id.cmp(&right.session_id))
        });
        sessions
    }

    pub fn audit_events(&self) -> Vec<PluginSessionAuditEvent> {
        self.read_state().audit_events.clone()
    }

    fn close_many_at(
        &self,
        session_ids: Vec<PluginSessionId>,
        reason: PluginSessionReason,
        operation: &'static str,
        now: DateTime<Utc>,
    ) -> PluginSessionCloseReport {
        let mut report = PluginSessionCloseReport::default();
        for session_id in session_ids {
            match self.close_with_operation_at(&session_id, reason.clone(), operation, now) {
                Ok(descriptor) => report.closed.push(descriptor),
                Err(error) => report
                    .failed
                    .push(PluginSessionCloseFailure { session_id, error }),
            }
        }
        report
    }

    fn close_with_operation_at(
        &self,
        session_id: &str,
        reason: impl Into<String>,
        operation: &'static str,
        now: DateTime<Utc>,
    ) -> Result<PluginSessionDescriptor, PluginSessionError> {
        let reason = reason.into();
        let (request, callback) = {
            let mut state = self.write_state();
            let entry = entry_mut(&mut state, session_id)?;
            if entry.descriptor.health == PluginSessionHealth::Closed {
                return Ok(entry.descriptor.clone());
            }
            entry.descriptor.health = PluginSessionHealth::Closing;
            entry.descriptor.last_used_at = now;
            entry.descriptor.active_leases = 0;
            entry.descriptor.generation += 1;
            let descriptor = entry.descriptor.clone();
            let callback = entry.close_callback.clone();
            record_event(
                &mut state,
                operation,
                &descriptor,
                Some(reason.as_str()),
                now,
            );
            (
                PluginSessionCloseRequest {
                    session_id: descriptor.session_id,
                    plugin_id: descriptor.plugin_id,
                    owner_id: descriptor.owner_id,
                    generation: descriptor.generation,
                    reason: reason.clone(),
                },
                callback,
            )
        };

        if let Some(callback) = callback
            && let Err(error) = callback.request_close(request.clone())
        {
            let descriptor = self.mark_close_failed(session_id, operation, &reason, now)?;
            return Err(error.with_session_id(descriptor.session_id));
        }

        let mut state = self.write_state();
        let descriptor = {
            let entry = entry_mut(&mut state, session_id)?;
            entry.descriptor.health = PluginSessionHealth::Closed;
            entry.descriptor.closed_at = Some(now);
            entry.descriptor.last_used_at = now;
            entry.descriptor.active_leases = 0;
            entry.descriptor.generation += 1;
            entry.descriptor.clone()
        };
        record_event(
            &mut state,
            operation,
            &descriptor,
            Some(reason.as_str()),
            now,
        );
        Ok(descriptor)
    }

    fn mark_close_failed(
        &self,
        session_id: &str,
        operation: &'static str,
        reason: &str,
        now: DateTime<Utc>,
    ) -> Result<PluginSessionDescriptor, PluginSessionError> {
        let mut state = self.write_state();
        let descriptor = {
            let entry = entry_mut(&mut state, session_id)?;
            entry.descriptor.health = PluginSessionHealth::Failed;
            entry.descriptor.last_used_at = now;
            entry.descriptor.active_leases = 0;
            entry.descriptor.generation += 1;
            entry.descriptor.clone()
        };
        record_event(&mut state, operation, &descriptor, Some(reason), now);
        Ok(descriptor)
    }

    fn read_state(&self) -> std::sync::RwLockReadGuard<'_, PluginSessionRegistryState> {
        self.state
            .read()
            .expect("plugin session registry read lock poisoned")
    }

    fn write_state(&self) -> std::sync::RwLockWriteGuard<'_, PluginSessionRegistryState> {
        self.state
            .write()
            .expect("plugin session registry write lock poisoned")
    }
}

fn sanitize_descriptor(descriptor: &mut PluginSessionDescriptor) -> Result<(), PluginSessionError> {
    if descriptor.redaction == RedactionStatus::FailedClosed {
        descriptor.metadata = Value::Null;
        return Ok(());
    }

    let metadata_bytes = serde_json::to_vec(&descriptor.metadata).map_err(|_| {
        PluginSessionError::new(
            PluginSessionErrorCode::RedactionFailed,
            "Session metadata could not be serialized for size validation.",
        )
    })?;
    if metadata_bytes.len() > MAX_PLUGIN_SESSION_METADATA_BYTES {
        return Err(PluginSessionError::new(
            PluginSessionErrorCode::RedactionFailed,
            "Session metadata exceeds the maximum safe descriptor size.",
        )
        .with_session_id(descriptor.session_id.clone()));
    }

    Ok(())
}

fn validate_descriptor(descriptor: &PluginSessionDescriptor) -> Result<(), PluginSessionError> {
    if descriptor.session_id.trim().is_empty() {
        return Err(PluginSessionError::new(
            PluginSessionErrorCode::PolicyDenied,
            "Session ID cannot be empty.",
        ));
    }
    if descriptor.plugin_id.trim().is_empty() {
        return Err(PluginSessionError::new(
            PluginSessionErrorCode::PolicyDenied,
            "Plugin ID cannot be empty.",
        )
        .with_session_id(descriptor.session_id.clone()));
    }
    if descriptor.owner_id.trim().is_empty() {
        return Err(PluginSessionError::new(
            PluginSessionErrorCode::PolicyDenied,
            "Owner ID cannot be empty.",
        )
        .with_session_id(descriptor.session_id.clone()));
    }
    Ok(())
}

fn entry_mut<'a>(
    state: &'a mut PluginSessionRegistryState,
    session_id: &str,
) -> Result<&'a mut PluginSessionEntry, PluginSessionError> {
    state.sessions.get_mut(session_id).ok_or_else(|| {
        PluginSessionError::new(PluginSessionErrorCode::NotFound, "Session was not found.")
            .with_session_id(session_id)
    })
}

fn assert_generation(
    descriptor: &PluginSessionDescriptor,
    expected_generation: u64,
) -> Result<(), PluginSessionError> {
    if descriptor.generation == expected_generation {
        return Ok(());
    }
    Err(PluginSessionError::new(
        PluginSessionErrorCode::Stale,
        "Session generation is stale.",
    )
    .with_session_id(descriptor.session_id.clone()))
}

fn session_matches_filter(
    descriptor: &PluginSessionDescriptor,
    filter: &PluginSessionListFilter,
) -> bool {
    if !filter.include_terminal && descriptor.health.is_terminal() {
        return false;
    }
    if let Some(plugin_id) = &filter.plugin_id
        && descriptor.plugin_id != *plugin_id
    {
        return false;
    }
    if let Some(owner_id) = &filter.owner_id
        && descriptor.owner_id != *owner_id
    {
        return false;
    }
    if let Some(profile_ref) = &filter.profile_ref
        && descriptor.profile_ref.as_ref() != Some(profile_ref)
    {
        return false;
    }
    if let Some(purpose) = &filter.purpose
        && descriptor.purpose != *purpose
    {
        return false;
    }
    true
}

fn record_event(
    state: &mut PluginSessionRegistryState,
    operation: &'static str,
    descriptor: &PluginSessionDescriptor,
    reason: Option<&str>,
    timestamp: DateTime<Utc>,
) {
    state.audit_events.push(PluginSessionAuditEvent {
        operation: operation.into(),
        session_id: descriptor.session_id.clone(),
        plugin_id: descriptor.plugin_id.clone(),
        owner_id: descriptor.owner_id.clone(),
        purpose: descriptor.purpose.clone(),
        scope: descriptor.scope,
        health: descriptor.health,
        timestamp,
        reason: reason.map(str::to_string),
        redaction: descriptor.redaction,
        metadata: json!({
            "generation": descriptor.generation,
            "authenticated": descriptor.authenticated,
            "destructive_capable": descriptor.destructive_capable,
            "stream_capable": descriptor.stream_capable,
            "active_leases": descriptor.active_leases,
        }),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ConnectionProfileRef;
    use std::sync::Mutex;

    fn fixed_time() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-07-05T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc)
    }

    fn ready_registration(id: &str, now: DateTime<Utc>) -> PluginSessionRegistration {
        PluginSessionRegistration::new_at(
            "ssh",
            "tab-1",
            PluginSessionPurpose::InteractiveTerminal,
            PluginSessionScope::RemoteTarget,
            now,
        )
        .with_session_id(id)
        .with_health(PluginSessionHealth::Ready)
        .with_authenticated(true)
    }

    #[test]
    fn registers_and_lists_redacted_descriptors() {
        let now = fixed_time();
        let registry = PluginSessionRegistry::new();

        let registered = registry
            .register_at(
                ready_registration("session-1", now).with_metadata(
                    json!({ "host": "prod.example.com", "label": "primary" }),
                    RedactionStatus::FailedClosed,
                ),
                now,
            )
            .expect("register");

        assert_eq!(registered.redaction, RedactionStatus::FailedClosed);
        assert_eq!(registered.metadata, Value::Null);

        let listed = registry.list(PluginSessionListFilter {
            include_terminal: true,
            ..PluginSessionListFilter::default()
        });
        assert_eq!(listed.len(), 1);

        let encoded = serde_json::to_string(&listed[0]).expect("serialize descriptor");
        assert!(!encoded.contains("prod.example.com"));
        assert!(!encoded.contains("primary"));
    }

    #[test]
    fn reuses_compatible_session_and_rejects_incompatible_required_reuse() {
        let now = fixed_time();
        let registry = PluginSessionRegistry::new();
        let key = PluginSessionReuseKey::new(
            "postgres",
            PluginSessionPurpose::DatabaseQuery,
            PluginSessionScope::RemoteTarget,
        )
        .with_profile_ref(ConnectionProfileRef::name("prod"))
        .with_compatibility_fingerprint("schema:public");

        registry
            .register_at(
                PluginSessionRegistration::new_at(
                    "postgres",
                    "service-1",
                    PluginSessionPurpose::DatabaseQuery,
                    PluginSessionScope::RemoteTarget,
                    now,
                )
                .with_session_id("query-1")
                .with_profile_ref(ConnectionProfileRef::name("prod"))
                .with_reuse_fingerprint("schema:public")
                .with_health(PluginSessionHealth::Ready),
                now,
            )
            .expect("register");

        let lease = registry
            .acquire_at(
                &key,
                PluginSessionReusePolicy::Allow,
                Some(Duration::minutes(5)),
                now + Duration::seconds(1),
            )
            .expect("acquire")
            .expect("reused session");

        assert_eq!(lease.session_id, "query-1");
        assert_eq!(lease.generation, 1);
        assert_eq!(
            registry.get("query-1").expect("descriptor").active_leases,
            1
        );

        let incompatible = PluginSessionReuseKey::new(
            "postgres",
            PluginSessionPurpose::DatabaseTransaction,
            PluginSessionScope::RemoteTarget,
        )
        .with_profile_ref(ConnectionProfileRef::name("prod"));
        let error = registry
            .acquire_at(
                &incompatible,
                PluginSessionReusePolicy::Require,
                None,
                now + Duration::seconds(2),
            )
            .expect_err("incompatible reuse should fail");

        assert_eq!(error.code, PluginSessionErrorCode::IncompatibleReuse);
    }

    #[test]
    fn rejects_stale_generation_after_invalidation() {
        let now = fixed_time();
        let registry = PluginSessionRegistry::new();
        registry
            .register_at(ready_registration("session-1", now), now)
            .expect("register");

        let key = PluginSessionReuseKey::new(
            "ssh",
            PluginSessionPurpose::InteractiveTerminal,
            PluginSessionScope::RemoteTarget,
        );
        let lease = registry
            .acquire_at(
                &key,
                PluginSessionReusePolicy::Require,
                Some(Duration::minutes(5)),
                now,
            )
            .expect("acquire")
            .expect("lease");

        registry
            .invalidate_at(
                "session-1",
                "target_disconnected",
                now + Duration::seconds(1),
            )
            .expect("invalidate");

        let renew_error = registry
            .renew_at(
                "session-1",
                lease.generation,
                Duration::minutes(5),
                now + Duration::seconds(2),
            )
            .expect_err("stale renew should fail");
        assert_eq!(renew_error.code, PluginSessionErrorCode::Stale);

        let release_error = registry
            .release_at("session-1", lease.generation, now + Duration::seconds(3))
            .expect_err("stale release should fail");
        assert_eq!(release_error.code, PluginSessionErrorCode::Stale);
    }

    #[test]
    fn expires_sessions_and_blocks_future_reuse() {
        let now = fixed_time();
        let registry = PluginSessionRegistry::new();
        registry
            .register_at(
                ready_registration("session-1", now)
                    .with_lease_expires_at(now + Duration::seconds(5)),
                now,
            )
            .expect("register");

        let expired = registry.expire_at(now + Duration::seconds(6), "ttl_expired");
        assert_eq!(expired.len(), 1);
        assert_eq!(expired[0].health, PluginSessionHealth::Stale);

        let key = PluginSessionReuseKey::new(
            "ssh",
            PluginSessionPurpose::InteractiveTerminal,
            PluginSessionScope::RemoteTarget,
        );
        let error = registry
            .acquire_at(
                &key,
                PluginSessionReusePolicy::Require,
                None,
                now + Duration::seconds(7),
            )
            .expect_err("expired session should not be reusable");
        assert_eq!(error.code, PluginSessionErrorCode::IncompatibleReuse);
    }

    #[test]
    fn explicit_and_owner_close_invoke_callbacks() {
        let now = fixed_time();
        let registry = PluginSessionRegistry::new();
        let closed = Arc::new(Mutex::new(Vec::new()));

        for id in ["session-1", "session-2"] {
            let closed = Arc::clone(&closed);
            registry
                .register_at(
                    ready_registration(id, now).with_close_callback(
                        move |request: PluginSessionCloseRequest| {
                            closed.lock().expect("closed lock").push(request.session_id);
                            Ok(())
                        },
                    ),
                    now,
                )
                .expect("register");
        }

        let descriptor = registry
            .close_at("session-1", "user_closed", now + Duration::seconds(1))
            .expect("close");
        assert_eq!(descriptor.health, PluginSessionHealth::Closed);
        assert_eq!(descriptor.closed_at, Some(now + Duration::seconds(1)));

        let report = registry.close_owner_at("tab-1", "tab_closed", now + Duration::seconds(2));
        assert_eq!(report.closed.len(), 1);
        assert!(report.failed.is_empty());

        let mut closed_ids = closed.lock().expect("closed lock").clone();
        closed_ids.sort();
        assert_eq!(closed_ids, vec!["session-1", "session-2"]);
    }

    #[test]
    fn shutdown_closes_sessions_and_keeps_audit_secret_free() {
        let now = fixed_time();
        let registry = PluginSessionRegistry::new();
        registry
            .register_at(
                ready_registration("session-1", now).with_metadata(
                    json!({ "host": "secret-host.internal" }),
                    RedactionStatus::FailedClosed,
                ),
                now,
            )
            .expect("register");

        let report = registry.shutdown_at("app_shutdown", now + Duration::seconds(10));
        assert_eq!(report.closed.len(), 1);
        assert!(report.failed.is_empty());
        assert_eq!(report.closed[0].health, PluginSessionHealth::Closed);

        let events = registry.audit_events();
        assert!(
            events
                .iter()
                .any(|event| event.operation == "session.register")
        );
        assert!(
            events
                .iter()
                .any(|event| event.operation == "session.shutdown")
        );
        assert!(
            events
                .iter()
                .any(|event| event.health == PluginSessionHealth::Closed)
        );

        let encoded = serde_json::to_string(&events).expect("serialize audit");
        assert!(!encoded.contains("secret-host.internal"));
        assert!(encoded.contains("session.shutdown"));
    }

    #[test]
    fn agent_binding_enforces_grant_profile_plugin_generation_and_capabilities() {
        let binding = AgentSessionBinding {
            grant_id: "grant-1".into(),
            profile_id: "profile-1".into(),
            plugin_id: "ssh".into(),
            purpose: PluginSessionPurpose::InteractiveTerminal,
            allowed_capabilities: vec!["ssh.exec".into(), "sftp_list".into()],
            host_generation: 7,
        };

        assert!(binding.allows_capability("ssh.exec"));
        assert!(binding.allows_capability("ssh.sftp_list"));
        assert!(!binding.allows_capability("ssh.forward_open"));
        binding
            .validate("grant-1", "profile-1", "ssh", 7)
            .expect("matching binding");

        let error = binding
            .validate("grant-2", "profile-1", "ssh", 7)
            .expect_err("cross-grant binding must fail");
        assert_eq!(error.code, PluginSessionErrorCode::BindingMismatch);
    }

    #[test]
    fn agent_lease_is_positive_and_capped_by_grant_expiry() {
        let now = fixed_time();
        let grant_expires_at = now + Duration::minutes(5);
        let request = AgentSessionOpenRequest {
            purpose: PluginSessionPurpose::DatabaseTransaction,
            capabilities: vec!["postgres.query".into()],
            lease_seconds: 3600,
            concurrency: AgentSessionConcurrency::Serialized,
            destructive_acknowledged: false,
            input: Value::Null,
        };
        assert_eq!(
            request
                .lease_expires_at(now, grant_expires_at)
                .expect("lease"),
            grant_expires_at
        );

        let zero_lease = AgentSessionOpenRequest {
            lease_seconds: 0,
            ..request
        };
        assert_eq!(
            zero_lease
                .lease_expires_at(now, grant_expires_at)
                .expect_err("zero lease")
                .code,
            PluginSessionErrorCode::PolicyDenied
        );

        let legacy: AgentSessionOpenRequest = serde_json::from_value(json!({
            "purpose": { "kind": "database_query" },
            "capabilities": ["postgres.query"],
            "lease_seconds": 60,
            "input": {}
        }))
        .expect("legacy open request");
        assert!(!legacy.destructive_acknowledged);
    }

    #[test]
    fn agent_call_output_is_bounded_without_emitting_partial_json() {
        let result = AgentSessionCallResult::bounded(
            "call-1",
            json!({ "stdout": "ok", "exit_code": 0 }),
            1024,
        )
        .expect("bounded result");
        assert!(!result.truncated);
        assert!(result.output_bytes > 0);

        let error =
            AgentSessionCallResult::bounded("call-2", json!({ "stdout": "x".repeat(32) }), 8)
                .expect_err("oversized output");
        assert_eq!(error.code, PluginSessionErrorCode::OutputLimit);
    }

    #[test]
    fn agent_broker_protocol_versions_keep_legacy_negotiation_explicit() {
        assert!(is_supported_agent_broker_protocol_version(
            AGENT_BROKER_LEGACY_PROTOCOL_VERSION
        ));
        assert!(is_supported_agent_broker_protocol_version(
            AGENT_BROKER_PROTOCOL_VERSION
        ));
        assert!(!is_supported_agent_broker_protocol_version(0));
        assert!(!is_supported_agent_broker_protocol_version(
            AGENT_BROKER_PROTOCOL_VERSION + 1
        ));
    }

    #[test]
    fn caller_owned_call_ids_are_public_bounded_identifiers() {
        for call_id in ["call:agent-01", "task_2.call-3", "A"] {
            validate_agent_session_call_id(call_id).expect("valid call ID");
        }
        for call_id in ["", "call id", "call/slash", &"x".repeat(129)] {
            let error = validate_agent_session_call_id(call_id).expect_err("invalid call ID");
            assert_eq!(error.code, PluginSessionErrorCode::CallIdInvalid);
        }
    }

    #[test]
    fn call_lifecycle_prioritizes_close_and_keeps_terminal_state_immutable() {
        let now = fixed_time();
        let mut lifecycle = AgentSessionCallLifecycle::accepted(
            "call:known-before-start",
            now,
            Some(now + Duration::seconds(30)),
        )
        .expect("accepted lifecycle");
        assert!(lifecycle.mark_running(now + Duration::milliseconds(1)));
        assert_eq!(
            lifecycle.request_control(
                AgentSessionControlKind::Cancel,
                now + Duration::milliseconds(2)
            ),
            AgentSessionControlDisposition::Accepted
        );
        assert_eq!(
            lifecycle.request_control(
                AgentSessionControlKind::Cancel,
                now + Duration::milliseconds(3)
            ),
            AgentSessionControlDisposition::AlreadyRequested
        );
        assert_eq!(
            lifecycle.request_control(
                AgentSessionControlKind::Close,
                now + Duration::milliseconds(4)
            ),
            AgentSessionControlDisposition::Escalated
        );
        lifecycle
            .finish(
                AgentSessionCallState::Succeeded,
                now + Duration::milliseconds(5),
            )
            .expect("terminal transition");
        assert_eq!(lifecycle.state, AgentSessionCallState::Aborted);
        assert_eq!(
            lifecycle.request_control(
                AgentSessionControlKind::Shutdown,
                now + Duration::milliseconds(6)
            ),
            AgentSessionControlDisposition::AlreadyTerminal
        );
        assert!(
            !lifecycle
                .finish(
                    AgentSessionCallState::Failed,
                    now + Duration::milliseconds(7)
                )
                .expect("idempotent terminal transition")
        );
        assert_eq!(lifecycle.state, AgentSessionCallState::Aborted);
    }

    #[test]
    fn legacy_control_requests_receive_bounded_default_deadlines() {
        let cancel: AgentSessionCancelRequest = serde_json::from_value(json!({
            "session": { "session_id": "agent-session:test", "generation": 1 },
            "call_id": "call:test"
        }))
        .expect("legacy cancel request");
        assert_eq!(
            cancel.timeout().expect("cancel timeout"),
            std::time::Duration::from_millis(DEFAULT_AGENT_SESSION_CANCEL_TIMEOUT_MS)
        );

        let close: AgentSessionCloseAgentRequest = serde_json::from_value(json!({
            "session": { "session_id": "agent-session:test", "generation": 1 },
            "reason": "user_closed"
        }))
        .expect("legacy close request");
        assert_eq!(
            close.timeout().expect("close timeout"),
            std::time::Duration::from_millis(DEFAULT_AGENT_SESSION_CLOSE_TIMEOUT_MS)
        );
    }

    #[test]
    fn asynchronous_call_lookup_and_wait_contracts_are_bounded() {
        let session = AgentSessionRef::new("agent-session:test", 3);
        let status = AgentSessionCallStatusRequest {
            session: session.clone(),
            call_id: "call:async".into(),
        };
        status.validate_call_id().expect("status call ID");

        let wait: AgentSessionCallWaitRequest = serde_json::from_value(json!({
            "session": session,
            "call_id": "call:async"
        }))
        .expect("legacy-compatible wait request");
        assert_eq!(
            wait.timeout().expect("default wait timeout"),
            std::time::Duration::from_millis(DEFAULT_AGENT_SESSION_WAIT_TIMEOUT_MS)
        );
        let invalid = AgentSessionCallWaitRequest {
            timeout_ms: Some(MAX_AGENT_SESSION_WAIT_TIMEOUT_MS + 1),
            ..wait
        };
        assert_eq!(
            invalid.timeout().expect_err("oversized wait timeout").code,
            PluginSessionErrorCode::PolicyDenied
        );
    }
}
