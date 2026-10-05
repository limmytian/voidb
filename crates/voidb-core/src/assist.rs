//! Shared external-agent context and operation contracts.
//!
//! A plugin may publish bounded, redacted context and accept structured agent
//! operation requests while keeping live handles and input ownership inside the
//! owning plugin service. Legacy `Assist*` names remain source and decoding
//! compatibility spellings; they do not imply an embedded question/answer UI.

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration as StdDuration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use crate::agent_authorization::AgentPrincipal;
use crate::capability::{ActorRef, CapabilityId, ConnectionProfileRef, PluginId, RedactionStatus};
use crate::session::{
    AgentSessionConcurrency, AgentSessionOpenRequest, AgentSessionRef, PluginSessionDescriptor,
    PluginSessionHealth, PluginSessionId, PluginSessionOwnerId, PluginSessionPurpose,
};

pub type AssistRequestId = String;
pub type AssistResponseId = String;
pub type AssistPermissionGrantId = String;

pub type AgentContextShareId = AssistRequestId;
pub type AgentOperationRequestId = AssistResponseId;

pub const DEFAULT_ASSIST_REQUEST_TTL_SECONDS: i64 = 600;
pub const MAX_ASSIST_REQUEST_TTL_SECONDS: i64 = 3600;
pub const MAX_AGENT_CONTEXT_LABEL_CHARS: usize = 2000;
pub const MAX_ASSIST_QUESTION_CHARS: usize = MAX_AGENT_CONTEXT_LABEL_CHARS;

pub const DEFAULT_ASSIST_VISIBLE_SCREEN_ROWS: u16 = 80;
pub const DEFAULT_ASSIST_VISIBLE_SCREEN_COLS: u16 = 160;
pub const MAX_ASSIST_VISIBLE_SCREEN_CELLS: u32 = 24_000;

pub const DEFAULT_ASSIST_TRANSCRIPT_TAIL_BYTES: usize = 16 * 1024;
pub const MAX_ASSIST_TRANSCRIPT_TAIL_BYTES: usize = 64 * 1024;
pub const DEFAULT_ASSIST_METADATA_BYTES: usize = 4 * 1024;
pub const MAX_ASSIST_METADATA_BYTES: usize = 8 * 1024;

pub const DEFAULT_ASSIST_CONTROL_TTL_SECONDS: u64 = 60;
pub const MAX_ASSIST_CONTROL_TTL_SECONDS: u64 = 300;
pub const DEFAULT_ASSIST_OUTPUT_LIMIT_BYTES: usize = 64 * 1024;
pub const MAX_ASSIST_OUTPUT_LIMIT_BYTES: usize = 256 * 1024;
pub const ASSIST_BROKER_STORE_VERSION: u32 = 1;
pub const ASSIST_OWNER_LEASE_VERSION: u32 = 1;
const ASSIST_RECORD_LOCK_TIMEOUT: StdDuration = StdDuration::from_millis(500);
const ASSIST_STALE_RECORD_LOCK_AGE: StdDuration = StdDuration::from_secs(30);

struct AssistRecordLock {
    path: PathBuf,
}

pub fn assist_owner_lease_filename(request_id: &str) -> String {
    format!(".{}.owner-lease", safe_assist_request_filename(request_id))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssistOwnerLeaseDescriptor {
    pub version: u32,
}

pub struct AssistOwnerLease {
    path: PathBuf,
    file: File,
}

impl std::fmt::Debug for AssistOwnerLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AssistOwnerLease")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl Drop for AssistOwnerLease {
    fn drop(&mut self) {
        let _ = self.file.unlock();
        // Keep the private sidecar in place. An unlocked lease on a non-terminal
        // record is the crash signal observed by external processes.
    }
}

impl Drop for AssistRecordLock {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.path);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssistPermission {
    SuggestOnly,
    AgentSideInspect,
    ProposeCommands,
    TakeControl,
}

impl AssistPermission {
    pub fn risk_rank(self) -> u8 {
        match self {
            Self::SuggestOnly => 0,
            Self::AgentSideInspect => 1,
            Self::ProposeCommands => 2,
            Self::TakeControl => 3,
        }
    }

    pub fn requires_explicit_approval(self) -> bool {
        !matches!(self, Self::SuggestOnly)
    }

    pub fn uses_current_pty(self) -> bool {
        matches!(self, Self::TakeControl)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssistRequestStatus {
    Draft,
    Pending,

    #[serde(rename = "operation_pending", alias = "responded")]
    Responded,
    Cancelled,
    Expired,
    Closed,
}

impl AssistRequestStatus {
    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Cancelled | Self::Expired | Self::Closed)
    }

    pub fn can_transition_to(self, next: Self) -> bool {
        use AssistRequestStatus as Status;
        match (self, next) {
            (Status::Draft, Status::Pending | Status::Cancelled | Status::Expired) => true,
            (Status::Pending, Status::Responded | Status::Cancelled | Status::Expired) => true,
            (Status::Responded, Status::Closed | Status::Cancelled | Status::Expired) => true,
            _ if self == next => true,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssistPermissionStatus {
    Requested,
    Approved,
    Denied,
    Revoked,
    Expired,
    Cancelled,
}

impl AssistPermissionStatus {
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Denied | Self::Revoked | Self::Expired | Self::Cancelled
        )
    }

    pub fn can_transition_to(self, next: Self) -> bool {
        use AssistPermissionStatus as Status;
        match (self, next) {
            (
                Status::Requested,
                Status::Approved | Status::Denied | Status::Cancelled | Status::Expired,
            ) => true,
            (Status::Approved, Status::Revoked | Status::Expired) => true,
            _ if self == next => true,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssistWithholdingReason {
    SecretMaterial,
    SensitiveMetadata,
    Policy,
    LimitExceeded,
    UnsupportedMode,
    RedactionFailed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssistWithheldField {
    pub field: String,
    pub reason: AssistWithholdingReason,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssistSessionContinuity {
    Current,
    ReconnectedStateLost,
    Stale,
    OwnerUnavailable,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssistSessionBinding {
    pub plugin_id: PluginId,
    pub session_id: PluginSessionId,
    pub generation: u64,
    pub owner_id: PluginSessionOwnerId,
    pub purpose: PluginSessionPurpose,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_ref: Option<ConnectionProfileRef>,
}

impl AssistSessionBinding {
    pub fn from_descriptor(descriptor: &PluginSessionDescriptor) -> Self {
        Self {
            plugin_id: descriptor.plugin_id.clone(),
            session_id: descriptor.session_id.clone(),
            generation: descriptor.generation,
            owner_id: descriptor.owner_id.clone(),
            purpose: descriptor.purpose.clone(),
            profile_ref: descriptor.profile_ref.clone(),
        }
    }

    pub fn agent_session_ref(&self) -> AgentSessionRef {
        AgentSessionRef::new(self.session_id.clone(), self.generation)
    }

    pub fn continuity_against(
        &self,
        descriptor: &PluginSessionDescriptor,
    ) -> AssistSessionContinuity {
        if self.session_id != descriptor.session_id
            || self.plugin_id != descriptor.plugin_id
            || self.owner_id != descriptor.owner_id
        {
            return AssistSessionContinuity::OwnerUnavailable;
        }
        if descriptor.health.is_terminal() {
            return AssistSessionContinuity::Stale;
        }
        if self.generation != descriptor.generation {
            return AssistSessionContinuity::ReconnectedStateLost;
        }
        AssistSessionContinuity::Current
    }

    pub fn validate_current(
        &self,
        descriptor: &PluginSessionDescriptor,
    ) -> Result<(), AssistContractError> {
        match self.continuity_against(descriptor) {
            AssistSessionContinuity::Current => Ok(()),
            AssistSessionContinuity::ReconnectedStateLost | AssistSessionContinuity::Stale => {
                Err(AssistContractError::StaleSession)
            }
            AssistSessionContinuity::OwnerUnavailable => Err(AssistContractError::BindingMismatch),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssistContextPolicy {
    pub visible_screen_rows: u16,
    pub visible_screen_cols: u16,
    pub transcript_tail_bytes: usize,
    pub metadata_bytes: usize,
    pub output_limit_bytes: usize,
}

impl Default for AssistContextPolicy {
    fn default() -> Self {
        Self {
            visible_screen_rows: DEFAULT_ASSIST_VISIBLE_SCREEN_ROWS,
            visible_screen_cols: DEFAULT_ASSIST_VISIBLE_SCREEN_COLS,
            transcript_tail_bytes: DEFAULT_ASSIST_TRANSCRIPT_TAIL_BYTES,
            metadata_bytes: DEFAULT_ASSIST_METADATA_BYTES,
            output_limit_bytes: DEFAULT_ASSIST_OUTPUT_LIMIT_BYTES,
        }
    }
}

impl AssistContextPolicy {
    pub fn validate(&self) -> Result<(), AssistContractError> {
        let screen_cells =
            u32::from(self.visible_screen_rows) * u32::from(self.visible_screen_cols);
        if self.visible_screen_rows == 0
            || self.visible_screen_cols == 0
            || screen_cells > MAX_ASSIST_VISIBLE_SCREEN_CELLS
        {
            return Err(AssistContractError::InvalidPolicy(format!(
                "visible screen bounds must be 1 to {MAX_ASSIST_VISIBLE_SCREEN_CELLS} cells"
            )));
        }
        if self.transcript_tail_bytes == 0
            || self.transcript_tail_bytes > MAX_ASSIST_TRANSCRIPT_TAIL_BYTES
        {
            return Err(AssistContractError::InvalidPolicy(format!(
                "transcript tail must be 1 to {MAX_ASSIST_TRANSCRIPT_TAIL_BYTES} bytes"
            )));
        }
        if self.metadata_bytes > MAX_ASSIST_METADATA_BYTES {
            return Err(AssistContractError::InvalidPolicy(format!(
                "metadata must not exceed {MAX_ASSIST_METADATA_BYTES} bytes"
            )));
        }
        if self.output_limit_bytes == 0 || self.output_limit_bytes > MAX_ASSIST_OUTPUT_LIMIT_BYTES {
            return Err(AssistContractError::InvalidPolicy(format!(
                "output limit must be 1 to {MAX_ASSIST_OUTPUT_LIMIT_BYTES} bytes"
            )));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssistTerminalDimensions {
    pub rows: u16,
    pub cols: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssistBoundedText {
    pub text: String,
    pub byte_count: usize,
    pub limit_bytes: usize,
    pub truncated: bool,
    pub redaction: RedactionStatus,
}

impl AssistBoundedText {
    pub fn capture(
        text: &str,
        limit_bytes: usize,
        redaction: RedactionStatus,
    ) -> Result<Self, AssistContractError> {
        if limit_bytes == 0 {
            return Err(AssistContractError::InvalidPolicy(
                "bounded text limit must be greater than zero".into(),
            ));
        }
        let original_len = text.len();
        if original_len <= limit_bytes {
            return Ok(Self {
                text: text.to_string(),
                byte_count: original_len,
                limit_bytes,
                truncated: false,
                redaction,
            });
        }

        let mut end = 0;
        for (idx, ch) in text.char_indices() {
            let next = idx + ch.len_utf8();
            if next > limit_bytes {
                break;
            }
            end = next;
        }

        let captured = text[..end].to_string();
        Ok(Self {
            byte_count: captured.len(),
            text: captured,
            limit_bytes,
            truncated: true,
            redaction,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssistContextSnapshot {
    pub binding: AssistSessionBinding,
    pub captured_at: DateTime<Utc>,
    pub mode: String,
    pub health: PluginSessionHealth,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal: Option<AssistTerminalDimensions>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visible_screen: Option<AssistBoundedText>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transcript_tail: Option<AssistBoundedText>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_line: Option<AssistBoundedText>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub withheld_fields: Vec<AssistWithheldField>,

    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub metadata: Value,

    #[serde(default)]
    pub redaction: RedactionStatus,
}

impl AssistContextSnapshot {
    pub fn preview(&self) -> AssistContextPreview {
        AssistContextPreview {
            captured_at: self.captured_at,
            mode: self.mode.clone(),
            health: self.health,
            terminal: self.terminal,
            visible_screen_bytes: self.visible_screen.as_ref().map(|text| text.byte_count),
            transcript_tail_bytes: self.transcript_tail.as_ref().map(|text| text.byte_count),
            status_line_bytes: self.status_line.as_ref().map(|text| text.byte_count),
            visible_screen_truncated: self
                .visible_screen
                .as_ref()
                .is_some_and(|text| text.truncated),
            transcript_tail_truncated: self
                .transcript_tail
                .as_ref()
                .is_some_and(|text| text.truncated),
            withheld_fields: self.withheld_fields.clone(),
            redaction: self.redaction,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssistContextPreview {
    pub captured_at: DateTime<Utc>,
    pub mode: String,
    pub health: PluginSessionHealth,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal: Option<AssistTerminalDimensions>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visible_screen_bytes: Option<usize>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transcript_tail_bytes: Option<usize>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_line_bytes: Option<usize>,

    #[serde(default)]
    pub visible_screen_truncated: bool,

    #[serde(default)]
    pub transcript_tail_truncated: bool,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub withheld_fields: Vec<AssistWithheldField>,

    #[serde(default)]
    pub redaction: RedactionStatus,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssistRequest {
    pub id: AssistRequestId,

    #[serde(alias = "question")]
    pub label: String,

    pub binding: AssistSessionBinding,
    pub requester: ActorRef,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_agent: Option<AgentPrincipal>,

    #[serde(default)]
    pub context_policy: AssistContextPolicy,

    #[serde(default)]
    pub requested_permissions: Vec<AssistPermission>,

    pub status: AssistRequestStatus,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<AssistContextPreview>,

    #[serde(default)]
    pub redaction: RedactionStatus,
}

impl AssistRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new_context_share(
        id: AssistRequestId,
        label: String,
        binding: AssistSessionBinding,
        requester: ActorRef,
        external_agent: Option<AgentPrincipal>,
        context_policy: AssistContextPolicy,
        created_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, AssistContractError> {
        validate_request_id("agent context share", &id)?;
        validate_context_label(&label)?;
        validate_ttl(created_at, expires_at, MAX_ASSIST_REQUEST_TTL_SECONDS)?;
        if let Some(agent) = &external_agent {
            agent
                .validate()
                .map_err(|error| AssistContractError::InvalidRequest(error.to_string()))?;
        }
        context_policy.validate()?;
        Ok(Self {
            id,
            label,
            binding,
            requester,
            external_agent,
            context_policy,
            requested_permissions: vec![AssistPermission::SuggestOnly],
            status: AssistRequestStatus::Draft,
            created_at,
            expires_at,
            preview: None,
            redaction: RedactionStatus::Applied,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: AssistRequestId,
        label: String,
        binding: AssistSessionBinding,
        requester: ActorRef,
        external_agent: Option<AgentPrincipal>,
        context_policy: AssistContextPolicy,
        created_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, AssistContractError> {
        Self::new_context_share(
            id,
            label,
            binding,
            requester,
            external_agent,
            context_policy,
            created_at,
            expires_at,
        )
    }

    pub fn transition_to(
        &mut self,
        status: AssistRequestStatus,
    ) -> Result<(), AssistContractError> {
        if !self.status.can_transition_to(status) {
            return Err(AssistContractError::InvalidTransition {
                from: format!("{:?}", self.status),
                to: format!("{status:?}"),
            });
        }
        self.status = status;
        Ok(())
    }

    pub fn expire_at(&mut self, now: DateTime<Utc>) -> bool {
        if !self.status.is_terminal() && self.expires_at <= now {
            self.status = AssistRequestStatus::Expired;
            true
        } else {
            false
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssistPermissionGrant {
    pub id: AssistPermissionGrantId,
    pub request_id: AssistRequestId,
    pub permission: AssistPermission,
    pub status: AssistPermissionStatus,
    pub requested_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub generation: u64,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_at: Option<DateTime<Utc>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl AssistPermissionGrant {
    pub fn new(
        id: AssistPermissionGrantId,
        request_id: AssistRequestId,
        permission: AssistPermission,
        requested_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        generation: u64,
    ) -> Result<Self, AssistContractError> {
        validate_request_id("assist permission grant", &id)?;
        validate_request_id("context share", &request_id)?;
        validate_ttl(
            requested_at,
            expires_at,
            MAX_ASSIST_CONTROL_TTL_SECONDS as i64,
        )?;
        if generation == 0 {
            return Err(AssistContractError::InvalidRequest(
                "permission grant generation must be greater than zero".into(),
            ));
        }
        Ok(Self {
            id,
            request_id,
            permission,
            status: AssistPermissionStatus::Requested,
            requested_at,
            expires_at,
            generation,
            decided_at: None,
            revoked_at: None,
            reason: None,
        })
    }

    pub fn transition_at(
        &mut self,
        status: AssistPermissionStatus,
        now: DateTime<Utc>,
        reason: Option<String>,
    ) -> Result<(), AssistContractError> {
        if !self.status.can_transition_to(status) {
            return Err(AssistContractError::InvalidTransition {
                from: format!("{:?}", self.status),
                to: format!("{status:?}"),
            });
        }
        self.status = status;
        self.reason = reason;
        match status {
            AssistPermissionStatus::Approved | AssistPermissionStatus::Denied => {
                self.decided_at = Some(now);
            }
            AssistPermissionStatus::Revoked => {
                self.revoked_at = Some(now);
            }
            AssistPermissionStatus::Expired | AssistPermissionStatus::Cancelled => {
                self.decided_at.get_or_insert(now);
            }
            AssistPermissionStatus::Requested => {}
        }
        Ok(())
    }

    pub fn expire_at(&mut self, now: DateTime<Utc>) -> bool {
        if !self.status.is_terminal() && self.expires_at <= now {
            let _ = self.transition_at(
                AssistPermissionStatus::Expired,
                now,
                Some("ttl_expired".into()),
            );
            true
        } else {
            false
        }
    }

    pub fn validate_generation(&self, generation: u64) -> Result<(), AssistContractError> {
        if self.generation == generation {
            Ok(())
        } else {
            Err(AssistContractError::StaleSession)
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssistActionRisk {
    Low,
    Review,
    Destructive,
    SecretSensitive,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AssistActionTarget {
    HumanOnly,
    AgentSideSession { session: AgentSessionRef },
    CurrentPty { binding: AssistSessionBinding },
    Capability { capability_id: CapabilityId },
}

impl AssistActionTarget {
    pub fn uses_current_pty(&self) -> bool {
        matches!(self, Self::CurrentPty { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AssistAction {
    Guidance {
        title: String,
        body: String,
    },
    RequestPermission {
        permission: AssistPermission,
        reason: String,
        ttl_seconds: u64,
    },
    ProposedCommand {
        command: String,
        rationale: String,
        risk: AssistActionRisk,
        target: AssistActionTarget,
    },
    CapabilityCall {
        capability_id: CapabilityId,
        input_summary: Value,
        rationale: String,
        risk: AssistActionRisk,
        target: AssistActionTarget,
    },
}

impl AssistAction {
    pub fn uses_current_pty(&self) -> bool {
        match self {
            Self::RequestPermission { permission, .. } => permission.uses_current_pty(),
            Self::ProposedCommand { target, .. } | Self::CapabilityCall { target, .. } => {
                target.uses_current_pty()
            }
            Self::Guidance { .. } => false,
        }
    }

    pub fn requested_permission(&self) -> Option<AssistPermission> {
        match self {
            Self::RequestPermission { permission, .. } => Some(*permission),
            Self::ProposedCommand { target, .. } if target.uses_current_pty() => {
                Some(AssistPermission::TakeControl)
            }
            Self::ProposedCommand { .. } => Some(AssistPermission::ProposeCommands),
            Self::CapabilityCall { target, .. } if target.uses_current_pty() => {
                Some(AssistPermission::TakeControl)
            }
            Self::CapabilityCall { .. } => Some(AssistPermission::AgentSideInspect),
            Self::Guidance { .. } => None,
        }
    }

    fn validate(&self) -> Result<(), AssistContractError> {
        fn bounded(label: &str, value: &str, max_bytes: usize) -> Result<(), AssistContractError> {
            if value.trim().is_empty()
                || value.len() > max_bytes
                || value.chars().any(char::is_control)
            {
                return Err(AssistContractError::InvalidRequest(format!(
                    "{label} must contain 1 to {max_bytes} non-control bytes"
                )));
            }
            Ok(())
        }

        fn contains_sensitive_summary(value: &Value) -> bool {
            match value {
                Value::Object(fields) => fields.iter().any(|(key, value)| {
                    let normalized = key
                        .chars()
                        .filter(|character| character.is_ascii_alphanumeric())
                        .flat_map(char::to_lowercase)
                        .collect::<String>();
                    matches!(
                        normalized.as_str(),
                        "password"
                            | "passwd"
                            | "token"
                            | "accesstoken"
                            | "refreshtoken"
                            | "secret"
                            | "apikey"
                            | "privatekey"
                            | "credential"
                            | "credentials"
                            | "authorization"
                            | "cookie"
                    ) || contains_sensitive_summary(value)
                }),
                Value::Array(values) => values.iter().any(contains_sensitive_summary),
                Value::String(value) => {
                    value.contains("-----BEGIN PRIVATE KEY-----")
                        || value
                            .split_once("://")
                            .and_then(|(_, rest)| rest.split_once('@'))
                            .is_some_and(|(userinfo, _)| userinfo.contains(':'))
                }
                _ => false,
            }
        }

        match self {
            Self::Guidance { title, body } => {
                bounded("operation guidance title", title, 1000)?;
                bounded("operation guidance body", body, 8000)?;
            }
            Self::RequestPermission {
                reason,
                ttl_seconds,
                ..
            } => {
                bounded("operation permission reason", reason, 4000)?;
                if *ttl_seconds == 0 || *ttl_seconds > MAX_ASSIST_CONTROL_TTL_SECONDS {
                    return Err(AssistContractError::InvalidRequest(format!(
                        "operation permission TTL must be between 1 and {MAX_ASSIST_CONTROL_TTL_SECONDS} seconds"
                    )));
                }
            }
            Self::ProposedCommand {
                command, rationale, ..
            } => {
                bounded("proposed command", command, 8000)?;
                bounded("operation rationale", rationale, 4000)?;
            }
            Self::CapabilityCall {
                capability_id,
                input_summary,
                rationale,
                ..
            } => {
                bounded("operation capability ID", capability_id, 255)?;
                bounded("operation rationale", rationale, 4000)?;
                let input_bytes = serde_json::to_vec(input_summary).map_err(|_| {
                    AssistContractError::InvalidRequest(
                        "operation input summary is not serializable".into(),
                    )
                })?;
                if input_bytes.len() > MAX_ASSIST_METADATA_BYTES {
                    return Err(AssistContractError::InvalidRequest(format!(
                        "operation input summary exceeds {MAX_ASSIST_METADATA_BYTES} bytes"
                    )));
                }
                if contains_sensitive_summary(input_summary) {
                    return Err(AssistContractError::InvalidRequest(
                        "operation input summary contains credential-like material".into(),
                    ));
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssistResponse {
    pub id: AssistResponseId,
    pub request_id: AssistRequestId,
    pub agent: AgentPrincipal,
    pub created_at: DateTime<Utc>,
    pub summary: String,

    #[serde(
        default,
        rename = "note",
        alias = "diagnosis",
        skip_serializing_if = "Option::is_none"
    )]
    pub diagnosis: Option<String>,

    #[serde(default, rename = "operations", alias = "actions")]
    pub actions: Vec<AssistAction>,

    #[serde(default)]
    pub requested_permissions: Vec<AssistPermission>,

    #[serde(default)]
    pub redaction: RedactionStatus,
}

impl AssistResponse {
    pub fn validate(&self) -> Result<(), AssistContractError> {
        validate_request_id("agent operation request", &self.id)?;
        validate_request_id("agent context share", &self.request_id)?;
        self.agent
            .validate()
            .map_err(|error| AssistContractError::InvalidRequest(error.to_string()))?;
        if self.summary.trim().is_empty() || self.summary.len() > 4000 {
            return Err(AssistContractError::InvalidRequest(
                "operation summary must contain 1 to 4000 bytes".into(),
            ));
        }
        if self.summary.chars().any(char::is_control) {
            return Err(AssistContractError::InvalidRequest(
                "operation summary must not contain control characters".into(),
            ));
        }
        if self
            .diagnosis
            .as_ref()
            .is_some_and(|note| note.len() > 4000 || note.chars().any(char::is_control))
        {
            return Err(AssistContractError::InvalidRequest(
                "operation note must contain at most 4000 non-control bytes".into(),
            ));
        }
        if self.actions.len() > 128 {
            return Err(AssistContractError::InvalidRequest(
                "operation request contains too many operations".into(),
            ));
        }
        for action in &self.actions {
            action.validate()?;
        }
        if matches!(self.redaction, RedactionStatus::FailedClosed) {
            return Err(AssistContractError::InvalidRequest(
                "operation request redaction failed closed".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssistPluginState {
    pub mode: String,
    pub health: PluginSessionHealth,
    pub status: String,
    pub updated_at: DateTime<Utc>,

    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub metadata: Value,

    #[serde(default)]
    pub redaction: RedactionStatus,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssistSubmitInput {
    pub request: AssistRequest,
    pub context: AssistContextSnapshot,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugin_state: Option<AssistPluginState>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssistActionConfirmation {
    pub request_id: AssistRequestId,

    #[serde(rename = "operation_request_id", alias = "response_id")]
    pub response_id: AssistResponseId,

    #[serde(rename = "operation_index", alias = "action_index")]
    pub action_index: usize,
    pub target: String,
    pub uses_current_pty: bool,
    pub generation: u64,
    pub confirmed_at: DateTime<Utc>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_summary: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_id: Option<CapabilityId>,

    pub status: String,
    pub note: String,

    #[serde(default)]
    pub redaction: RedactionStatus,
}

impl AssistActionConfirmation {
    pub(crate) fn validate_shape(&self) -> Result<(), AssistContractError> {
        validate_request_id("agent context share", &self.request_id)?;
        validate_request_id("agent operation request", &self.response_id)?;
        if self.status.trim().is_empty() {
            return Err(AssistContractError::InvalidRequest(
                "operation confirmation status is required".into(),
            ));
        }
        if self.status.len() > 128
            || self.status.chars().any(char::is_control)
            || self.target.trim().is_empty()
            || self.target.len() > 1000
            || self.target.chars().any(char::is_control)
            || self.note.len() > 1000
            || self.note.chars().any(char::is_control)
            || self.command_summary.as_ref().is_some_and(|summary| {
                summary.len() > 4000 || summary.chars().any(char::is_control)
            })
            || self
                .capability_id
                .as_ref()
                .is_some_and(|capability| capability.trim().is_empty() || capability.len() > 255)
            || matches!(self.redaction, RedactionStatus::FailedClosed)
        {
            return Err(AssistContractError::InvalidRequest(
                "operation confirmation contains invalid or unbounded text".into(),
            ));
        }
        if self
            .expires_at
            .is_some_and(|expires_at| expires_at < self.confirmed_at)
        {
            return Err(AssistContractError::InvalidRequest(
                "operation confirmation expiry precedes its decision time".into(),
            ));
        }
        Ok(())
    }

    pub fn validate_against(
        &self,
        request: &AssistRequest,
        responses: &[AssistResponse],
        policy: &AssistBrokerPolicy,
    ) -> Result<(), AssistContractError> {
        self.validate_shape()?;
        if self.request_id != request.id {
            return Err(AssistContractError::InvalidRequest(
                "operation confirmation share ID does not match the target share".into(),
            ));
        }
        if request.status.is_terminal() {
            return Err(AssistContractError::InvalidRequest(
                "agent context share is already terminal".into(),
            ));
        }
        if self.generation != request.binding.generation {
            return Err(AssistContractError::StaleSession);
        }
        if !policy.allow_current_pty && self.uses_current_pty {
            return Err(AssistContractError::InvalidRequest(
                "non-PTY context stores cannot confirm current PTY operations".into(),
            ));
        }

        let response = responses
            .iter()
            .find(|response| response.id == self.response_id)
            .ok_or_else(|| {
                AssistContractError::InvalidRequest(
                    "operation confirmation request ID was not found".into(),
                )
            })?;
        let action = response.actions.get(self.action_index).ok_or_else(|| {
            AssistContractError::InvalidRequest("operation confirmation index was not found".into())
        })?;
        if !policy.allow_current_pty && action.uses_current_pty() {
            return Err(AssistContractError::InvalidRequest(
                "non-PTY context-share stores cannot confirm current PTY operations".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssistAgentInspectionConfig {
    pub purpose: PluginSessionPurpose,

    #[serde(default)]
    pub capabilities: Vec<CapabilityId>,

    pub lease_seconds: u64,

    #[serde(default)]
    pub concurrency: AgentSessionConcurrency,

    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub call_template: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssistAgentInspectionTemplate {
    pub permission: AssistPermission,
    pub uses_current_pty: bool,
    pub purpose: PluginSessionPurpose,
    pub capabilities: Vec<CapabilityId>,
    pub open_request: AgentSessionOpenRequest,
    pub call_template: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssistBrokerPolicy {
    #[serde(default)]
    pub allow_current_pty: bool,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_side_inspection: Option<AssistAgentInspectionConfig>,
}

impl AssistBrokerPolicy {
    pub fn non_pty() -> Self {
        Self {
            allow_current_pty: false,
            agent_side_inspection: None,
        }
    }

    pub fn current_pty_capable() -> Self {
        Self {
            allow_current_pty: true,
            agent_side_inspection: None,
        }
    }

    pub fn with_agent_side_inspection(mut self, config: AssistAgentInspectionConfig) -> Self {
        self.agent_side_inspection = Some(config);
        self
    }

    pub fn validate_operation_request(
        &self,
        response: &AssistResponse,
    ) -> Result<(), AssistContractError> {
        response.validate()?;
        if self.allow_current_pty {
            return Ok(());
        }
        if response.actions.len() != 1 {
            return Err(AssistContractError::InvalidRequest(
                "non-PTY operation requests must contain exactly one operation".into(),
            ));
        }
        if response
            .requested_permissions
            .iter()
            .any(|permission| permission.uses_current_pty())
            || response.actions.iter().any(AssistAction::uses_current_pty)
        {
            return Err(AssistContractError::InvalidRequest(
                "non-PTY context stores cannot request current PTY control".into(),
            ));
        }
        Ok(())
    }

    pub fn validate_response(&self, response: &AssistResponse) -> Result<(), AssistContractError> {
        self.validate_operation_request(response)
    }
}

impl Default for AssistBrokerPolicy {
    fn default() -> Self {
        Self::non_pty()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssistBrokerRecord {
    pub version: u32,
    pub request: AssistRequest,
    pub context: AssistContextSnapshot,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_lease: Option<AssistOwnerLeaseDescriptor>,

    #[serde(
        default,
        alias = "terminal_state",
        skip_serializing_if = "Option::is_none"
    )]
    pub plugin_state: Option<AssistPluginState>,

    #[serde(default, rename = "operation_requests", alias = "responses")]
    pub responses: Vec<AssistResponse>,

    #[serde(
        default,
        rename = "operation_confirmations",
        alias = "action_confirmations"
    )]
    pub action_confirmations: Vec<AssistActionConfirmation>,
}

impl AssistBrokerRecord {
    pub fn latest_operation_request(&self) -> Option<&AssistResponse> {
        self.responses.last()
    }

    pub fn latest_response(&self) -> Option<&AssistResponse> {
        self.latest_operation_request()
    }

    pub fn operation_confirmation(
        &self,
        operation_request_id: &str,
        operation_index: usize,
    ) -> Option<&AssistActionConfirmation> {
        self.action_confirmations.iter().find(|confirmation| {
            confirmation.response_id == operation_request_id
                && confirmation.action_index == operation_index
        })
    }

    pub fn operation_request_complete(&self, response: &AssistResponse) -> bool {
        !response.actions.is_empty()
            && response
                .actions
                .iter()
                .enumerate()
                .all(|(index, _)| self.operation_confirmation(&response.id, index).is_some())
    }

    pub fn latest_pending_operation_request(&self) -> Option<&AssistResponse> {
        self.responses
            .iter()
            .rev()
            .find(|response| !self.operation_request_complete(response))
    }

    fn expire_if_due(&mut self, now: DateTime<Utc>) {
        if self.request.expire_at(now) {
            self.updated_at = now;
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssistBrokerListItem {
    pub id: AssistRequestId,

    #[serde(alias = "question")]
    pub label: String,

    pub status: AssistRequestStatus,
    pub mode: String,
    pub health: PluginSessionHealth,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(alias = "response_count")]
    pub operation_request_count: usize,

    pub redaction: RedactionStatus,
}

impl From<&AssistBrokerRecord> for AssistBrokerListItem {
    fn from(record: &AssistBrokerRecord) -> Self {
        Self {
            id: record.request.id.clone(),
            label: record.request.label.clone(),
            status: record.request.status,
            mode: record.context.mode.clone(),
            health: record.context.health,
            created_at: record.created_at,
            updated_at: record.updated_at,
            operation_request_count: record.responses.len(),
            redaction: record.request.redaction,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssistBrokerDetail {
    pub record: AssistBrokerRecord,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_side_inspection: Option<AssistAgentInspectionTemplate>,
}

#[derive(Debug, Clone)]
pub struct AssistBrokerStore {
    root: PathBuf,
    policy: AssistBrokerPolicy,
}

impl AssistBrokerStore {
    pub fn new(root: PathBuf, policy: AssistBrokerPolicy) -> Result<Self> {
        if fs::symlink_metadata(&root).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
            bail!("context-share store root must not be a symbolic link");
        }
        fs::create_dir_all(&root)
            .with_context(|| format!("create context-share store {}", root.display()))?;
        #[cfg(unix)]
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("protect context-share store {}", root.display()))?;
        Ok(Self { root, policy })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn policy(&self) -> &AssistBrokerPolicy {
        &self.policy
    }

    pub fn share(
        &self,
        request: AssistRequest,
        context: AssistContextSnapshot,
        plugin_state: Option<AssistPluginState>,
    ) -> Result<AssistBrokerRecord> {
        self.share_inner(request, context, plugin_state, None)
    }

    pub fn share_with_owner_lease(
        &self,
        request: AssistRequest,
        context: AssistContextSnapshot,
        plugin_state: Option<AssistPluginState>,
    ) -> Result<(AssistBrokerRecord, AssistOwnerLease)> {
        let lease = self.acquire_owner_lease(&request.id)?;
        let record = match self.share_inner(
            request,
            context,
            plugin_state,
            Some(AssistOwnerLeaseDescriptor {
                version: ASSIST_OWNER_LEASE_VERSION,
            }),
        ) {
            Ok(record) => record,
            Err(error) => {
                let unused_path = lease.path.clone();
                drop(lease);
                let _ = fs::remove_file(unused_path);
                return Err(error);
            }
        };
        Ok((record, lease))
    }

    fn share_inner(
        &self,
        request: AssistRequest,
        context: AssistContextSnapshot,
        plugin_state: Option<AssistPluginState>,
        owner_lease: Option<AssistOwnerLeaseDescriptor>,
    ) -> Result<AssistBrokerRecord> {
        if request.binding != context.binding {
            bail!("context share binding does not match context snapshot binding");
        }
        request
            .context_policy
            .validate()
            .map_err(|error| anyhow!(error.to_string()))?;
        let _lock = self.lock_record(&request.id)?;
        if self.record_path(&request.id).exists() {
            bail!("agent context share already exists");
        }
        let now = Utc::now();
        let mut record = AssistBrokerRecord {
            version: ASSIST_BROKER_STORE_VERSION,
            request,
            context,
            created_at: now,
            updated_at: now,
            owner_lease,
            plugin_state,
            responses: Vec::new(),
            action_confirmations: Vec::new(),
        };
        record.expire_if_due(now);
        self.write_record(&record)?;
        Ok(record)
    }

    pub fn submit(
        &self,
        request: AssistRequest,
        context: AssistContextSnapshot,
        plugin_state: Option<AssistPluginState>,
    ) -> Result<AssistBrokerRecord> {
        self.share(request, context, plugin_state)
    }

    pub fn submit_input(&self, input: AssistSubmitInput) -> Result<AssistBrokerRecord> {
        self.share(input.request, input.context, input.plugin_state)
    }

    pub fn list(&self, status: Option<AssistRequestStatus>) -> Result<Vec<AssistBrokerListItem>> {
        let mut records = self.read_all_records()?;
        if let Some(status) = status {
            records.retain(|record| record.request.status == status);
        }
        records.sort_by_key(|record| std::cmp::Reverse(record.updated_at));
        Ok(records.iter().map(AssistBrokerListItem::from).collect())
    }

    pub fn detail(&self, request_id: &str) -> Result<AssistBrokerDetail> {
        let record = self.read_record(request_id)?;
        let agent_side_inspection = self.agent_side_inspection_template(&record);
        Ok(AssistBrokerDetail {
            record,
            agent_side_inspection,
        })
    }

    pub fn read_record(&self, request_id: &str) -> Result<AssistBrokerRecord> {
        let path = self.record_path(request_id);
        let text = fs::read_to_string(&path)
            .with_context(|| format!("context share {request_id} was not found"))?;
        let mut record: AssistBrokerRecord = serde_json::from_str(&text)
            .with_context(|| format!("context share {request_id} is corrupt"))?;
        if record.version != ASSIST_BROKER_STORE_VERSION {
            bail!("context share {request_id} uses unsupported store version");
        }
        record.expire_if_due(Utc::now());
        Ok(record)
    }

    pub fn post_operation_request(
        &self,
        request_id: &str,
        response: AssistResponse,
    ) -> Result<AssistBrokerRecord> {
        let _lock = self.lock_record(request_id)?;
        let mut record = self.read_record(request_id)?;
        if response.request_id != record.request.id {
            bail!("operation request share ID does not match the target share");
        }
        if record.request.status.is_terminal() {
            bail!("agent context share is already terminal");
        }
        self.policy
            .validate_operation_request(&response)
            .map_err(|error| anyhow!(error.to_string()))?;
        if let Some(existing) = record.responses.iter().find(|item| item.id == response.id) {
            if existing == &response {
                return Ok(record);
            }
            bail!("operation request ID replay changed the original payload");
        }
        if record.latest_pending_operation_request().is_some() {
            bail!("another operation request is still pending review");
        }
        if record
            .request
            .external_agent
            .as_ref()
            .is_some_and(|principal| principal != &response.agent)
        {
            bail!("agent context share is bound to a different external principal");
        }
        record.request.external_agent = Some(response.agent.clone());
        record
            .request
            .transition_to(AssistRequestStatus::Responded)
            .map_err(|error| anyhow!(error.to_string()))?;
        record.updated_at = Utc::now();
        record.responses.push(response);
        self.write_record(&record)?;
        Ok(record)
    }

    pub fn post_response(
        &self,
        request_id: &str,
        response: AssistResponse,
    ) -> Result<AssistBrokerRecord> {
        self.post_operation_request(request_id, response)
    }

    pub fn cancel(&self, request_id: &str) -> Result<AssistBrokerRecord> {
        let _lock = self.lock_record(request_id)?;
        let mut record = self.read_record(request_id)?;
        record
            .request
            .transition_to(AssistRequestStatus::Cancelled)
            .map_err(|error| anyhow!(error.to_string()))?;
        record.updated_at = Utc::now();
        self.write_record(&record)?;
        Ok(record)
    }

    pub fn close(&self, request_id: &str) -> Result<AssistBrokerRecord> {
        let _lock = self.lock_record(request_id)?;
        let mut record = self.read_record(request_id)?;
        record
            .request
            .transition_to(AssistRequestStatus::Closed)
            .map_err(|error| anyhow!(error.to_string()))?;
        record.updated_at = Utc::now();
        self.write_record(&record)?;
        Ok(record)
    }

    pub fn update_plugin_state(
        &self,
        request_id: &str,
        plugin_state: AssistPluginState,
    ) -> Result<AssistBrokerRecord> {
        let _lock = self.lock_record(request_id)?;
        let mut record = self.read_record(request_id)?;
        record.plugin_state = Some(plugin_state);
        record.updated_at = Utc::now();
        self.write_record(&record)?;
        Ok(record)
    }

    pub fn confirm_operation(
        &self,
        request_id: &str,
        confirmation: AgentOperationConfirmation,
    ) -> Result<AssistBrokerRecord> {
        let _lock = self.lock_record(request_id)?;
        let mut record = self.read_record(request_id)?;
        confirmation
            .validate_against(&record.request, &record.responses, &self.policy)
            .map_err(|error| anyhow!(error.to_string()))?;
        if record
            .operation_confirmation(&confirmation.response_id, confirmation.action_index)
            .is_some()
        {
            bail!("operation decision replay is not allowed");
        }
        record.action_confirmations.push(confirmation);
        record.updated_at = Utc::now();
        self.write_record(&record)?;
        Ok(record)
    }

    pub fn confirm_action(
        &self,
        request_id: &str,
        confirmation: AssistActionConfirmation,
    ) -> Result<AssistBrokerRecord> {
        self.confirm_operation(request_id, confirmation)
    }

    pub fn wait_for_operation_request(
        &self,
        request_id: &str,
        timeout: StdDuration,
        interval: StdDuration,
    ) -> Result<AssistBrokerDetail> {
        let started = Instant::now();
        loop {
            let detail = self.detail(request_id)?;
            if detail.record.latest_operation_request().is_some()
                || detail.record.request.status.is_terminal()
            {
                return Ok(detail);
            }
            if started.elapsed() >= timeout {
                bail!("context-share operation wait timed out");
            }
            thread::sleep(interval.min(StdDuration::from_secs(1)));
        }
    }

    pub fn wait_for_response(
        &self,
        request_id: &str,
        timeout: StdDuration,
        interval: StdDuration,
    ) -> Result<AssistBrokerDetail> {
        self.wait_for_operation_request(request_id, timeout, interval)
    }

    fn read_all_records(&self) -> Result<Vec<AssistBrokerRecord>> {
        let mut records = Vec::new();
        for entry in fs::read_dir(&self.root)
            .with_context(|| format!("read context-share store {}", self.root.display()))?
        {
            let entry = entry?;
            if entry.path().extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let text = fs::read_to_string(entry.path())?;
            let mut record: AssistBrokerRecord = serde_json::from_str(&text)?;
            if record.version == ASSIST_BROKER_STORE_VERSION {
                record.expire_if_due(Utc::now());
                records.push(record);
            }
        }
        Ok(records)
    }

    fn write_record(&self, record: &AssistBrokerRecord) -> Result<()> {
        let path = self.record_path(&record.request.id);
        let tmp = self.root.join(format!(
            ".{}.{}.tmp",
            safe_assist_request_filename(&record.request.id),
            Uuid::new_v4()
        ));
        let bytes = serde_json::to_vec_pretty(record)?;
        let result = (|| -> Result<()> {
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            options.mode(0o600);
            let mut file = options.open(&tmp)?;
            file.write_all(&bytes)?;
            drop(file);
            fs::rename(&tmp, &path)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        result?;
        Ok(())
    }

    fn lock_record(&self, request_id: &str) -> Result<AssistRecordLock> {
        let path = self.root.join(format!(
            ".{}.lock",
            safe_assist_request_filename(request_id)
        ));
        let started = Instant::now();
        loop {
            match fs::create_dir(&path) {
                Ok(()) => {
                    #[cfg(unix)]
                    if let Err(error) =
                        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                    {
                        let _ = fs::remove_dir(&path);
                        return Err(error).context("protect agent context record lock");
                    }
                    return Ok(AssistRecordLock { path });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let stale = fs::metadata(&path)
                        .and_then(|metadata| metadata.modified())
                        .ok()
                        .and_then(|modified| modified.elapsed().ok())
                        .is_some_and(|age| age >= ASSIST_STALE_RECORD_LOCK_AGE);
                    if stale && fs::remove_dir(&path).is_ok() {
                        continue;
                    }
                    if started.elapsed() >= ASSIST_RECORD_LOCK_TIMEOUT {
                        bail!("timed out waiting for agent context record lock");
                    }
                    thread::sleep(StdDuration::from_millis(5));
                }
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("lock agent context record {request_id}"));
                }
            }
        }
    }

    fn acquire_owner_lease(&self, request_id: &str) -> Result<AssistOwnerLease> {
        validate_request_id("agent context share", request_id)
            .map_err(|error| anyhow!(error.to_string()))?;
        let path = self.root.join(assist_owner_lease_filename(request_id));
        let mut options = fs::OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options
            .open(&path)
            .with_context(|| format!("open agent context owner lease {request_id}"))?;
        let initialized = (|| -> Result<()> {
            #[cfg(unix)]
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .with_context(|| format!("protect agent context owner lease {request_id}"))?;
            file.try_lock().with_context(|| {
                format!("agent context owner lease {request_id} is already active")
            })?;
            file.set_len(0)?;
            file.write_all(b"voidb-owner-lease-v1\n")?;
            file.sync_data()?;
            Ok(())
        })();
        if let Err(error) = initialized {
            drop(file);
            let _ = fs::remove_file(&path);
            return Err(error);
        }
        Ok(AssistOwnerLease { path, file })
    }

    fn record_path(&self, request_id: &str) -> PathBuf {
        self.root
            .join(format!("{}.json", safe_assist_request_filename(request_id)))
    }

    fn agent_side_inspection_template(
        &self,
        record: &AssistBrokerRecord,
    ) -> Option<AssistAgentInspectionTemplate> {
        let config = self.policy.agent_side_inspection.as_ref()?;
        let capabilities = config.capabilities.clone();
        Some(AssistAgentInspectionTemplate {
            permission: AssistPermission::AgentSideInspect,
            uses_current_pty: false,
            purpose: config.purpose.clone(),
            capabilities: capabilities.clone(),
            open_request: AgentSessionOpenRequest {
                purpose: config.purpose.clone(),
                capabilities,
                lease_seconds: config.lease_seconds,
                concurrency: config.concurrency,
                destructive_acknowledged: false,
                input: serde_json::json!({
                    "assist_request_id": record.request.id.clone(),
                    "source_session": {
                        "session_id": record.request.binding.session_id.clone(),
                        "generation": record.request.binding.generation,
                        "plugin_id": record.request.binding.plugin_id.clone(),
                        "owner_id": record.request.binding.owner_id.clone()
                    },
                    "uses_current_pty": false
                }),
            },
            call_template: config.call_template.clone(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FrontendAssistRequest {
    pub id: AssistRequestId,

    #[serde(alias = "question")]
    pub label: String,

    pub status: AssistRequestStatus,
    pub plugin_id: PluginId,
    pub session_id: PluginSessionId,
    pub generation: u64,
    pub owner_id: PluginSessionOwnerId,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_ref: Option<ConnectionProfileRef>,

    pub requester: ActorRef,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_agent_fingerprint: Option<String>,

    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preview: Option<AssistContextPreview>,

    #[serde(default)]
    pub requested_permissions: Vec<AssistPermission>,

    #[serde(default)]
    pub redaction: RedactionStatus,
}

impl TryFrom<&AssistRequest> for FrontendAssistRequest {
    type Error = AssistContractError;

    fn try_from(request: &AssistRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            id: request.id.clone(),
            label: request.label.clone(),
            status: request.status,
            plugin_id: request.binding.plugin_id.clone(),
            session_id: request.binding.session_id.clone(),
            generation: request.binding.generation,
            owner_id: request.binding.owner_id.clone(),
            profile_ref: request.binding.profile_ref.clone(),
            requester: request.requester.clone(),
            external_agent_fingerprint: request
                .external_agent
                .as_ref()
                .map(AgentPrincipal::fingerprint)
                .transpose()
                .map_err(|error| AssistContractError::InvalidRequest(error.to_string()))?,
            created_at: request.created_at,
            expires_at: request.expires_at,
            preview: request.preview.clone(),
            requested_permissions: request.requested_permissions.clone(),
            redaction: request.redaction,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FrontendAssistPermissionGrant {
    pub id: AssistPermissionGrantId,
    pub request_id: AssistRequestId,
    pub permission: AssistPermission,
    pub status: AssistPermissionStatus,
    pub requested_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub generation: u64,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl From<&AssistPermissionGrant> for FrontendAssistPermissionGrant {
    fn from(grant: &AssistPermissionGrant) -> Self {
        Self {
            id: grant.id.clone(),
            request_id: grant.request_id.clone(),
            permission: grant.permission,
            status: grant.status,
            requested_at: grant.requested_at,
            expires_at: grant.expires_at,
            generation: grant.generation,
            reason: grant.reason.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssistAuditAction {
    Create,
    Preview,
    Send,
    Respond,
    Inspect,
    Propose,
    ApproveControl,
    Revoke,
    Cancel,
    Expire,
    Close,
}

impl AssistAuditAction {
    pub fn operation_name(self) -> &'static str {
        match self {
            Self::Create => "assist.create",
            Self::Preview => "assist.preview",
            Self::Send => "assist.send",
            Self::Respond => "assist.respond",
            Self::Inspect => "assist.inspect",
            Self::Propose => "assist.propose",
            Self::ApproveControl => "assist.approve_control",
            Self::Revoke => "assist.revoke",
            Self::Cancel => "assist.cancel",
            Self::Expire => "assist.expire",
            Self::Close => "assist.close",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssistAuditProjection {
    pub action: AssistAuditAction,
    pub request_id: AssistRequestId,
    pub plugin_id: PluginId,
    pub session_id: PluginSessionId,
    pub generation: u64,
    pub owner_id: PluginSessionOwnerId,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_ref: Option<ConnectionProfileRef>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub permission: Option<AssistPermission>,

    pub occurred_at: DateTime<Utc>,
    pub redaction: RedactionStatus,
}

impl AssistAuditProjection {
    pub fn from_request(
        action: AssistAuditAction,
        request: &AssistRequest,
        occurred_at: DateTime<Utc>,
    ) -> Self {
        Self {
            action,
            request_id: request.id.clone(),
            plugin_id: request.binding.plugin_id.clone(),
            session_id: request.binding.session_id.clone(),
            generation: request.binding.generation,
            owner_id: request.binding.owner_id.clone(),
            profile_ref: request.binding.profile_ref.clone(),
            permission: None,
            occurred_at,
            redaction: request.redaction,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AssistContractError {
    #[error("invalid external-agent interaction: {0}")]
    InvalidRequest(String),
    #[error("invalid context-share policy: {0}")]
    InvalidPolicy(String),
    #[error("agent context share binding mismatch")]
    BindingMismatch,
    #[error("agent context share is stale")]
    StaleSession,
    #[error("agent context share has expired")]
    Expired,
    #[error("invalid context-share transition from {from} to {to}")]
    InvalidTransition { from: String, to: String },
}

// Canonical external-first vocabulary. The `Assist*` definitions above remain
// available so store version 1 and downstream source users can migrate without
// weakening validation or duplicating the contract.
pub type AgentContextShare = AssistRequest;
pub type AgentContextShareStatus = AssistRequestStatus;
pub type AgentContextSharePolicy = AssistBrokerPolicy;
pub type AgentContextShareRecord = AssistBrokerRecord;
pub type AgentContextShareListItem = AssistBrokerListItem;
pub type AgentContextShareDetail = AssistBrokerDetail;
pub type AgentContextShareStore = AssistBrokerStore;
pub type AgentContextShareSubmitInput = AssistSubmitInput;
pub type AgentContextSharePreview = AssistContextPreview;
pub type AgentOperation = AssistAction;
pub type AgentOperationRisk = AssistActionRisk;
pub type AgentOperationTarget = AssistActionTarget;
pub type AgentOperationRequest = AssistResponse;
pub type AgentOperationConfirmation = AssistActionConfirmation;

fn validate_request_id(kind: &str, id: &str) -> Result<(), AssistContractError> {
    if id.trim().is_empty() || id.len() > 255 {
        Err(AssistContractError::InvalidRequest(format!(
            "{kind} ID must contain 1 to 255 bytes"
        )))
    } else {
        Ok(())
    }
}

fn validate_context_label(label: &str) -> Result<(), AssistContractError> {
    if label.trim().is_empty() || label.chars().count() > MAX_AGENT_CONTEXT_LABEL_CHARS {
        Err(AssistContractError::InvalidRequest(format!(
            "context-share label must contain 1 to {MAX_AGENT_CONTEXT_LABEL_CHARS} characters"
        )))
    } else {
        Ok(())
    }
}

fn validate_ttl(
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    max_seconds: i64,
) -> Result<(), AssistContractError> {
    let ttl = expires_at - created_at;
    if ttl <= Duration::zero() || ttl > Duration::seconds(max_seconds) {
        Err(AssistContractError::InvalidRequest(format!(
            "TTL must be greater than zero and no more than {max_seconds} seconds"
        )))
    } else {
        Ok(())
    }
}

pub(crate) fn safe_assist_request_filename(request_id: &str) -> String {
    let safe = request_id
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    if safe.is_empty() {
        "assist-request".to_string()
    } else {
        safe
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use serde_json::json;

    use crate::capability::{ActorRef, ActorType};
    use crate::session::{
        PluginSessionHealth, PluginSessionPurpose, PluginSessionRegistration, PluginSessionScope,
    };

    use super::*;

    fn fixed_time() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 12, 10, 0, 0).unwrap()
    }

    fn descriptor(now: DateTime<Utc>) -> PluginSessionDescriptor {
        PluginSessionRegistration::new_at(
            "ssh",
            "tab-1",
            PluginSessionPurpose::InteractiveTerminal,
            PluginSessionScope::RemoteTarget,
            now,
        )
        .with_session_id("session-1")
        .with_health(PluginSessionHealth::Ready)
        .with_authenticated(true)
        .descriptor
    }

    fn principal() -> AgentPrincipal {
        AgentPrincipal {
            client_id: "agent-desktop".into(),
            task_id: "tw-task".into(),
            instance_id: Some("instance-1".into()),
        }
    }

    fn request(now: DateTime<Utc>) -> AssistRequest {
        AssistRequest::new_context_share(
            "assist:req-1".into(),
            "Deployment prompt state".into(),
            AssistSessionBinding::from_descriptor(&descriptor(now)),
            ActorRef {
                id: "human:local".into(),
                actor_type: ActorType::Human,
            },
            Some(principal()),
            AssistContextPolicy::default(),
            now,
            now + Duration::seconds(DEFAULT_ASSIST_REQUEST_TTL_SECONDS),
        )
        .expect("request")
    }

    fn assist_store() -> AssistBrokerStore {
        AssistBrokerStore::new(
            std::env::temp_dir().join(format!("voidb-assist-core-test-{}", Uuid::new_v4())),
            AssistBrokerPolicy::non_pty().with_agent_side_inspection(AssistAgentInspectionConfig {
                purpose: PluginSessionPurpose::InteractiveTerminal,
                capabilities: vec!["ssh.exec".into()],
                lease_seconds: 300,
                concurrency: AgentSessionConcurrency::Serialized,
                call_template: json!({
                    "capability": "ssh.exec",
                    "input": { "command": "<diagnostic command>" }
                }),
            }),
        )
        .expect("store")
    }

    fn pending_request_and_snapshot() -> (AssistRequest, AssistContextSnapshot) {
        let now = Utc::now();
        let mut request = AssistRequest::new_context_share(
            "assist:req-1".into(),
            "Deployment prompt state".into(),
            AssistSessionBinding::from_descriptor(&descriptor(now)),
            ActorRef {
                id: "human:local".into(),
                actor_type: ActorType::Human,
            },
            Some(principal()),
            AssistContextPolicy::default(),
            now,
            now + Duration::seconds(DEFAULT_ASSIST_REQUEST_TTL_SECONDS),
        )
        .expect("request");
        request
            .transition_to(AssistRequestStatus::Pending)
            .expect("pending");
        let snapshot = AssistContextSnapshot {
            binding: request.binding.clone(),
            captured_at: now,
            mode: "non-pty-fixture".into(),
            health: PluginSessionHealth::Ready,
            terminal: None,
            visible_screen: None,
            transcript_tail: None,
            status_line: Some(
                AssistBoundedText::capture("safe status", 1024, RedactionStatus::NotRequired)
                    .expect("status"),
            ),
            withheld_fields: vec![],
            metadata: json!({"kind": "core-test"}),
            redaction: RedactionStatus::NotRequired,
        };
        (request, snapshot)
    }

    fn non_pty_response(request_id: &str) -> AssistResponse {
        AssistResponse {
            id: "assist:response-1".into(),
            request_id: request_id.into(),
            agent: principal(),
            created_at: fixed_time(),
            summary: "review the safe plan".into(),
            diagnosis: Some("fixture diagnosis".into()),
            actions: vec![AssistAction::CapabilityCall {
                capability_id: "ssh.exec".into(),
                input_summary: json!({"command": "ps"}),
                rationale: "inspect with an agent-owned session".into(),
                risk: AssistActionRisk::Review,
                target: AssistActionTarget::Capability {
                    capability_id: "ssh.exec".into(),
                },
            }],
            requested_permissions: vec![AssistPermission::AgentSideInspect],
            redaction: RedactionStatus::NotRequired,
        }
    }

    fn confirmation(
        request: &AssistRequest,
        response: &AssistResponse,
    ) -> AssistActionConfirmation {
        AssistActionConfirmation {
            request_id: request.id.clone(),
            response_id: response.id.clone(),
            action_index: 0,
            target: "capability:ssh.exec".into(),
            uses_current_pty: false,
            generation: request.binding.generation,
            confirmed_at: fixed_time(),
            expires_at: None,
            command_summary: Some("ps".into()),
            capability_id: Some("ssh.exec".into()),
            status: "confirmed_capability_plan".into(),
            note: "current PTY unchanged".into(),
            redaction: RedactionStatus::NotRequired,
        }
    }

    #[test]
    fn session_binding_rejects_generation_mismatch_without_exposing_handles() {
        let now = fixed_time();
        let descriptor = descriptor(now);
        let binding = AssistSessionBinding::from_descriptor(&descriptor);
        binding.validate_current(&descriptor).expect("current");

        let mut reconnected = descriptor;
        reconnected.generation += 1;
        assert_eq!(
            binding.continuity_against(&reconnected),
            AssistSessionContinuity::ReconnectedStateLost
        );
        assert_eq!(
            binding.validate_current(&reconnected),
            Err(AssistContractError::StaleSession)
        );
    }

    #[test]
    fn bounded_text_truncates_on_utf8_boundary() {
        let captured =
            AssistBoundedText::capture("ok 测试 done", 6, RedactionStatus::Applied).unwrap();
        assert_eq!(captured.text, "ok 测");
        assert!(captured.truncated);
        assert_eq!(captured.byte_count, 6);
    }

    #[test]
    fn context_preview_omits_raw_screen_and_transcript() {
        let now = fixed_time();
        let snapshot = AssistContextSnapshot {
            binding: AssistSessionBinding::from_descriptor(&descriptor(now)),
            captured_at: now,
            mode: "terminal".into(),
            health: PluginSessionHealth::Ready,
            terminal: Some(AssistTerminalDimensions { rows: 24, cols: 80 }),
            visible_screen: Some(
                AssistBoundedText::capture(
                    "password=secret\nstatus=blocked",
                    1024,
                    RedactionStatus::Applied,
                )
                .unwrap(),
            ),
            transcript_tail: Some(
                AssistBoundedText::capture("secret transcript", 1024, RedactionStatus::Withheld)
                    .unwrap(),
            ),
            status_line: None,
            withheld_fields: vec![AssistWithheldField {
                field: "transcript_tail".into(),
                reason: AssistWithholdingReason::SecretMaterial,
            }],
            metadata: json!({"redaction_passes": 2}),
            redaction: RedactionStatus::Applied,
        };

        let preview = snapshot.preview();
        let encoded = serde_json::to_string(&preview).unwrap();
        assert_eq!(preview.visible_screen_bytes, Some(30));
        assert!(encoded.contains("transcript_tail"));
        assert!(!encoded.contains("password=secret"));
        assert!(!encoded.contains("secret transcript"));
    }

    #[test]
    fn request_and_permission_transitions_are_stable() {
        let now = fixed_time();
        let mut request = request(now);
        request
            .transition_to(AssistRequestStatus::Pending)
            .expect("send");
        request
            .transition_to(AssistRequestStatus::Responded)
            .expect("operation request");
        assert!(request.transition_to(AssistRequestStatus::Pending).is_err());

        let mut grant = AssistPermissionGrant::new(
            "assist:grant-1".into(),
            request.id.clone(),
            AssistPermission::TakeControl,
            now,
            now + Duration::seconds(DEFAULT_ASSIST_CONTROL_TTL_SECONDS as i64),
            request.binding.generation,
        )
        .expect("grant");
        grant
            .transition_at(
                AssistPermissionStatus::Approved,
                now + Duration::seconds(1),
                Some("human_approved".into()),
            )
            .expect("approve");
        grant
            .transition_at(
                AssistPermissionStatus::Revoked,
                now + Duration::seconds(2),
                Some("human_revoked".into()),
            )
            .expect("revoke");
        assert!(
            grant
                .transition_at(AssistPermissionStatus::Approved, now, None)
                .is_err()
        );
    }

    #[test]
    fn legacy_question_and_response_fields_decode_to_canonical_output() {
        let now = fixed_time();
        let mut legacy_share = serde_json::to_value(request(now)).unwrap();
        let label = legacy_share
            .as_object_mut()
            .unwrap()
            .remove("label")
            .unwrap();
        legacy_share
            .as_object_mut()
            .unwrap()
            .insert("question".into(), label);
        legacy_share["status"] = json!("responded");

        let decoded_share: AgentContextShare = serde_json::from_value(legacy_share).unwrap();
        assert_eq!(decoded_share.label, "Deployment prompt state");
        assert_eq!(decoded_share.status, AssistRequestStatus::Responded);
        let canonical_share = serde_json::to_value(decoded_share).unwrap();
        assert_eq!(canonical_share["label"], "Deployment prompt state");
        assert_eq!(canonical_share["status"], "operation_pending");
        assert!(canonical_share.get("question").is_none());

        let legacy_operation = json!({
            "id": "assist:response-legacy",
            "request_id": "assist:req-1",
            "agent": {
                "client_id": "agent-desktop",
                "task_id": "tw-task",
                "instance_id": "instance-1"
            },
            "created_at": now,
            "summary": "Review one bounded operation",
            "diagnosis": "legacy note",
            "actions": [],
            "requested_permissions": [],
            "redaction": "not_required"
        });
        let decoded_operation: AgentOperationRequest =
            serde_json::from_value(legacy_operation).unwrap();
        decoded_operation.validate().unwrap();
        let canonical_operation = serde_json::to_value(&decoded_operation).unwrap();
        assert_eq!(canonical_operation["note"], "legacy note");
        assert_eq!(canonical_operation["operations"], json!([]));
        assert!(canonical_operation.get("diagnosis").is_none());
        assert!(canonical_operation.get("actions").is_none());

        let (share, context) = pending_request_and_snapshot();
        let mut legacy_record = serde_json::to_value(AssistBrokerRecord {
            version: ASSIST_BROKER_STORE_VERSION,
            request: share,
            context,
            created_at: now,
            updated_at: now,
            owner_lease: None,
            plugin_state: None,
            responses: vec![decoded_operation],
            action_confirmations: Vec::new(),
        })
        .unwrap();
        let operation_requests = legacy_record
            .as_object_mut()
            .unwrap()
            .remove("operation_requests")
            .unwrap();
        let operation_confirmations = legacy_record
            .as_object_mut()
            .unwrap()
            .remove("operation_confirmations")
            .unwrap();
        legacy_record
            .as_object_mut()
            .unwrap()
            .insert("responses".into(), operation_requests);
        legacy_record
            .as_object_mut()
            .unwrap()
            .insert("action_confirmations".into(), operation_confirmations);
        let decoded_record: AgentContextShareRecord =
            serde_json::from_value(legacy_record).unwrap();
        assert_eq!(decoded_record.responses.len(), 1);
    }

    #[test]
    fn frontend_request_uses_agent_fingerprint_and_preview_only() {
        let now = fixed_time();
        let mut request = request(now);
        request.preview = Some(AssistContextPreview {
            captured_at: now,
            mode: "terminal".into(),
            health: PluginSessionHealth::Ready,
            terminal: Some(AssistTerminalDimensions { rows: 24, cols: 80 }),
            visible_screen_bytes: Some(100),
            transcript_tail_bytes: Some(512),
            status_line_bytes: None,
            visible_screen_truncated: false,
            transcript_tail_truncated: true,
            withheld_fields: vec![],
            redaction: RedactionStatus::Applied,
        });

        let frontend = FrontendAssistRequest::try_from(&request).expect("frontend");
        let encoded = serde_json::to_value(frontend).unwrap();
        assert!(
            encoded["external_agent_fingerprint"]
                .as_str()
                .unwrap()
                .starts_with("agent-principal:")
        );
        assert_eq!(encoded.get("external_agent"), None);
        assert_eq!(encoded.get("visible_screen"), None);
        assert_eq!(encoded.get("transcript_tail"), None);
    }

    #[test]
    fn non_pty_store_records_safe_operation_and_confirmation() {
        let store = assist_store();
        let (request, snapshot) = pending_request_and_snapshot();
        let request_id = request.id.clone();
        let submitted = store
            .share(
                request.clone(),
                snapshot,
                Some(AssistPluginState {
                    mode: "fixture".into(),
                    health: PluginSessionHealth::Ready,
                    status: "safe status".into(),
                    updated_at: Utc::now(),
                    metadata: json!({"selected": "container"}),
                    redaction: RedactionStatus::NotRequired,
                }),
            )
            .expect("submit");
        assert_eq!(submitted.request.status, AssistRequestStatus::Pending);
        assert_eq!(store.list(None).expect("list").len(), 1);

        let response = non_pty_response(&request_id);
        let with_operation = store
            .post_operation_request(&request_id, response.clone())
            .expect("operation request");
        assert_eq!(
            with_operation.request.status,
            AssistRequestStatus::Responded
        );

        let detail = store.detail(&request_id).expect("detail");
        assert!(detail.agent_side_inspection.is_some());
        assert_eq!(
            detail
                .agent_side_inspection
                .as_ref()
                .unwrap()
                .open_request
                .input["uses_current_pty"],
            false
        );

        let confirmed = store
            .confirm_operation(&request_id, confirmation(&request, &response))
            .expect("confirm");
        assert_eq!(confirmed.action_confirmations.len(), 1);
        assert!(!confirmed.action_confirmations[0].uses_current_pty);
        let replay = store
            .confirm_operation(&request_id, confirmation(&request, &response))
            .expect_err("indexed operation decision is one-shot");
        assert!(replay.to_string().contains("replay"));
    }

    #[test]
    fn non_pty_store_rejects_current_pty_operation_and_stale_confirmation() {
        let store = assist_store();
        let (request, snapshot) = pending_request_and_snapshot();
        let request_id = request.id.clone();
        store
            .share(request.clone(), snapshot, None)
            .expect("publish context share");

        let mut current_pty_response = non_pty_response(&request_id);
        current_pty_response.actions = vec![AssistAction::RequestPermission {
            permission: AssistPermission::TakeControl,
            reason: "write to the existing terminal".into(),
            ttl_seconds: 30,
        }];
        let error = store
            .post_operation_request(&request_id, current_pty_response)
            .expect_err("current PTY blocked");
        assert!(error.to_string().contains("current PTY"));

        let mut multi_action_response = non_pty_response(&request_id);
        multi_action_response.id = "assist:response-multi".into();
        multi_action_response
            .actions
            .push(multi_action_response.actions[0].clone());
        let error = store
            .post_operation_request(&request_id, multi_action_response)
            .expect_err("partial multi-action review blocked");
        assert!(error.to_string().contains("exactly one operation"));

        let response = non_pty_response(&request_id);
        store
            .post_operation_request(&request_id, response.clone())
            .expect("safe operation request");
        let mut stale = confirmation(&request, &response);
        stale.generation += 1;
        let error = store
            .confirm_action(&request_id, stale)
            .expect_err("stale generation blocked");
        assert!(error.to_string().contains("stale"));
    }
}
