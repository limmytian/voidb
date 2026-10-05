//! Shared, driver-free contract for bounded storage transfer lifecycles.
//!
//! Plugins keep clients, multipart upload IDs, lock tokens, open files, and
//! staging handles inside their service layer. This module contains only the
//! serializable policy and event shapes that Agent sessions, CLI streams, and
//! plugin-owned TUIs may share.

use std::collections::HashSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use thiserror::Error;

use crate::capability::RedactionStatus;

pub const AGENT_TRANSFER_PROTOCOL_VERSION: u32 = 1;
pub const MAX_AGENT_TRANSFER_ID_BYTES: usize = 128;
pub const MAX_AGENT_TRANSFER_TARGET_KIND_BYTES: usize = 64;
pub const MAX_AGENT_TRANSFER_RESUME_TOKEN_BYTES: usize = 16 * 1024;
pub const MAX_AGENT_TRANSFER_CHECKSUM_BYTES: usize = 512;
pub const MAX_AGENT_TRANSFER_STABLE_CODE_BYTES: usize = 128;
pub const MAX_AGENT_TRANSFER_CHUNKS: u32 = 10_000;
pub const MAX_AGENT_TRANSFER_PARALLEL_CHUNKS: u16 = 64;
pub const MAX_AGENT_TRANSFER_RETRIES: u32 = 16;
pub const MAX_AGENT_TRANSFER_BACKOFF_MS: u64 = 5 * 60 * 1_000;
pub const MAX_AGENT_TRANSFER_CLEANUP_TIMEOUT_MS: u64 = 5 * 60 * 1_000;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AgentTransferContractError {
    #[error("unsupported transfer protocol version {0}")]
    UnsupportedProtocol(u32),

    #[error("invalid transfer contract field '{field}': {reason}")]
    InvalidField {
        field: &'static str,
        reason: &'static str,
    },

    #[error("transfer phase cannot move from {from:?} to {to:?}")]
    InvalidTransition {
        from: AgentTransferPhase,
        to: AgentTransferPhase,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentTransferOperation {
    Upload,
    Download,
    Copy,
    Move,
}

impl AgentTransferOperation {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Upload => "upload",
            Self::Download => "download",
            Self::Copy => "copy",
            Self::Move => "move",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentTransferChunkMode {
    Single,
    ByteRange,
    Multipart,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentTransferChecksumAlgorithm {
    Sha256,
    Md5,
    Etag,
    WebdavDigest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentTransferChecksumScope {
    WholeTransfer,
    Object,
    Chunk,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentTransferConflictPolicy {
    Fail,
    Skip,
    Replace,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentTransferPrecondition {
    SourceMatch,
    DestinationAbsent,
    DestinationMatch,
    LockToken,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentTransferResumeMode {
    #[default]
    Unsupported,
    BestEffort,
    Exact,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentTransferLocalAccess {
    ReadFile,
    CreateFile,
    ReplaceFile,
    ResumeTransfer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentTransferCleanupAction {
    RemoveLocalStaging,
    AbortRemotePartial,
    RetainBoundCheckpoint,
    ReleaseRemoteLock,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentTransferChunkPolicy {
    pub modes: Vec<AgentTransferChunkMode>,
    pub max_chunks: u32,
    pub max_parallel_chunks: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentTransferRetryPolicy {
    pub max_retries: u32,
    pub initial_backoff_ms: u64,
    pub max_backoff_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentTransferResumePolicy {
    pub mode: AgentTransferResumeMode,
    pub max_token_bytes: usize,
    pub token_ttl_seconds: u64,
    pub require_scope_fingerprint: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentTransferLocalPathPolicy {
    pub access: Vec<AgentTransferLocalAccess>,

    /// Absolute local paths are always withheld from Agent output and audit.
    pub disclose_absolute_paths: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentTransferCleanupPolicy {
    pub on_cancel: Vec<AgentTransferCleanupAction>,
    pub on_failure: Vec<AgentTransferCleanupAction>,
    pub timeout_ms: u64,
}

/// Static policy shared by all transfer surfaces for one storage backend.
///
/// A contract is descriptive and does not make a capability available. A
/// plugin advertises support only after wiring the corresponding capability
/// and live service implementation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentTransferContract {
    #[serde(default = "agent_transfer_protocol_version")]
    pub protocol_version: u32,
    pub target_kind: String,
    pub operations: Vec<AgentTransferOperation>,
    pub chunking: AgentTransferChunkPolicy,
    pub checksums: Vec<AgentTransferChecksumAlgorithm>,
    pub conflicts: Vec<AgentTransferConflictPolicy>,
    pub preconditions: Vec<AgentTransferPrecondition>,
    pub retry: AgentTransferRetryPolicy,
    pub resume: AgentTransferResumePolicy,
    pub local_path: AgentTransferLocalPathPolicy,
    pub cleanup: AgentTransferCleanupPolicy,
}

impl AgentTransferContract {
    pub fn validate(&self) -> Result<(), AgentTransferContractError> {
        if self.protocol_version != AGENT_TRANSFER_PROTOCOL_VERSION {
            return Err(AgentTransferContractError::UnsupportedProtocol(
                self.protocol_version,
            ));
        }
        validate_label(
            &self.target_kind,
            MAX_AGENT_TRANSFER_TARGET_KIND_BYTES,
            "target_kind",
        )?;
        validate_non_empty_unique(&self.operations, "operations")?;
        validate_non_empty_unique(&self.chunking.modes, "chunking.modes")?;
        validate_non_empty_unique(&self.checksums, "checksums")?;
        validate_non_empty_unique(&self.conflicts, "conflicts")?;
        validate_non_empty_unique(&self.preconditions, "preconditions")?;
        validate_non_empty_unique(&self.local_path.access, "local_path.access")?;
        validate_non_empty_unique(&self.cleanup.on_cancel, "cleanup.on_cancel")?;
        validate_non_empty_unique(&self.cleanup.on_failure, "cleanup.on_failure")?;

        if !self
            .chunking
            .modes
            .contains(&AgentTransferChunkMode::Single)
        {
            return Err(invalid(
                "chunking.modes",
                "single must remain available as the compatibility mode",
            ));
        }
        if self.chunking.max_chunks == 0 || self.chunking.max_chunks > MAX_AGENT_TRANSFER_CHUNKS {
            return Err(invalid(
                "chunking.max_chunks",
                "must be within the shared chunk bound",
            ));
        }
        if self.chunking.max_parallel_chunks == 0
            || self.chunking.max_parallel_chunks > MAX_AGENT_TRANSFER_PARALLEL_CHUNKS
        {
            return Err(invalid(
                "chunking.max_parallel_chunks",
                "must be within the shared parallelism bound",
            ));
        }
        if self.retry.max_retries > MAX_AGENT_TRANSFER_RETRIES {
            return Err(invalid(
                "retry.max_retries",
                "exceeds the shared retry bound",
            ));
        }
        if self.retry.max_retries > 0
            && (self.retry.initial_backoff_ms == 0
                || self.retry.initial_backoff_ms > self.retry.max_backoff_ms
                || self.retry.max_backoff_ms > MAX_AGENT_TRANSFER_BACKOFF_MS)
        {
            return Err(invalid(
                "retry",
                "retry backoff must be positive, ordered, and bounded",
            ));
        }
        self.validate_resume_policy()?;
        if self.cleanup.timeout_ms == 0
            || self.cleanup.timeout_ms > MAX_AGENT_TRANSFER_CLEANUP_TIMEOUT_MS
        {
            return Err(invalid(
                "cleanup.timeout_ms",
                "must be within the shared cleanup bound",
            ));
        }
        if self.local_path.disclose_absolute_paths {
            return Err(invalid(
                "local_path.disclose_absolute_paths",
                "absolute local paths must remain withheld",
            ));
        }

        let access = &self.local_path.access;
        if self.operations.contains(&AgentTransferOperation::Upload)
            && !access.contains(&AgentTransferLocalAccess::ReadFile)
        {
            return Err(invalid(
                "local_path.access",
                "upload requires read_file authority",
            ));
        }
        if self.operations.contains(&AgentTransferOperation::Download)
            && !access.contains(&AgentTransferLocalAccess::CreateFile)
        {
            return Err(invalid(
                "local_path.access",
                "download requires create_file authority",
            ));
        }
        if self
            .conflicts
            .contains(&AgentTransferConflictPolicy::Replace)
            && self.operations.contains(&AgentTransferOperation::Download)
            && !access.contains(&AgentTransferLocalAccess::ReplaceFile)
        {
            return Err(invalid(
                "local_path.access",
                "download replacement requires replace_file authority",
            ));
        }
        if self.resume.mode != AgentTransferResumeMode::Unsupported
            && !access.contains(&AgentTransferLocalAccess::ResumeTransfer)
        {
            return Err(invalid(
                "local_path.access",
                "resumable transfers require resume_transfer authority",
            ));
        }
        if self
            .chunking
            .modes
            .contains(&AgentTransferChunkMode::Multipart)
            && !contains_cleanup(
                &self.cleanup.on_failure,
                AgentTransferCleanupAction::AbortRemotePartial,
                AgentTransferCleanupAction::RetainBoundCheckpoint,
            )
        {
            return Err(invalid(
                "cleanup.on_failure",
                "multipart failure must abort remote state or retain a bound checkpoint",
            ));
        }
        if self
            .preconditions
            .contains(&AgentTransferPrecondition::LockToken)
            && !self
                .cleanup
                .on_cancel
                .contains(&AgentTransferCleanupAction::ReleaseRemoteLock)
        {
            return Err(invalid(
                "cleanup.on_cancel",
                "lock-token transfers must release the remote lock on cancellation",
            ));
        }
        Ok(())
    }

    fn validate_resume_policy(&self) -> Result<(), AgentTransferContractError> {
        match self.resume.mode {
            AgentTransferResumeMode::Unsupported => {
                if self.resume.max_token_bytes != 0
                    || self.resume.token_ttl_seconds != 0
                    || self.resume.require_scope_fingerprint
                {
                    return Err(invalid(
                        "resume",
                        "unsupported resume mode cannot declare token authority",
                    ));
                }
            }
            AgentTransferResumeMode::BestEffort | AgentTransferResumeMode::Exact => {
                if self.resume.max_token_bytes == 0
                    || self.resume.max_token_bytes > MAX_AGENT_TRANSFER_RESUME_TOKEN_BYTES
                    || self.resume.token_ttl_seconds == 0
                    || !self.resume.require_scope_fingerprint
                {
                    return Err(invalid(
                        "resume",
                        "resume tokens must be bounded, expiring, and scope-bound",
                    ));
                }
                if !self
                    .preconditions
                    .contains(&AgentTransferPrecondition::SourceMatch)
                {
                    return Err(invalid(
                        "preconditions",
                        "resumable transfers require a source identity precondition",
                    ));
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentTransferPhase {
    Planned,
    AwaitingAuthorization,
    Queued,
    Preparing,
    Transferring,
    Paused,
    Conflict,
    RetryWaiting,
    Verifying,
    Committing,
    Cancelling,
    CleaningUp,
    Completed,
    Cancelled,
    Failed,
}

impl AgentTransferPhase {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::AwaitingAuthorization => "awaiting_authorization",
            Self::Queued => "queued",
            Self::Preparing => "preparing",
            Self::Transferring => "transferring",
            Self::Paused => "paused",
            Self::Conflict => "conflict",
            Self::RetryWaiting => "retry_waiting",
            Self::Verifying => "verifying",
            Self::Committing => "committing",
            Self::Cancelling => "cancelling",
            Self::CleaningUp => "cleaning_up",
            Self::Completed => "completed",
            Self::Cancelled => "cancelled",
            Self::Failed => "failed",
        }
    }

    pub fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Cancelled | Self::Failed)
    }

    pub fn allows(self, next: Self) -> bool {
        if self == next {
            return true;
        }
        match self {
            Self::Planned => matches!(
                next,
                Self::AwaitingAuthorization | Self::Queued | Self::Cancelled | Self::Failed
            ),
            Self::AwaitingAuthorization => {
                matches!(next, Self::Queued | Self::Cancelled | Self::Failed)
            }
            Self::Queued => matches!(
                next,
                Self::Preparing | Self::Cancelling | Self::Cancelled | Self::Failed
            ),
            Self::Preparing => matches!(
                next,
                Self::Transferring
                    | Self::Conflict
                    | Self::RetryWaiting
                    | Self::Cancelling
                    | Self::Failed
            ),
            Self::Transferring => matches!(
                next,
                Self::Paused
                    | Self::Conflict
                    | Self::RetryWaiting
                    | Self::Verifying
                    | Self::Committing
                    | Self::Cancelling
                    | Self::CleaningUp
                    | Self::Completed
                    | Self::Failed
            ),
            Self::Paused => matches!(
                next,
                Self::Transferring | Self::RetryWaiting | Self::Cancelling | Self::Failed
            ),
            Self::Conflict => matches!(
                next,
                Self::Preparing
                    | Self::Transferring
                    | Self::Committing
                    | Self::CleaningUp
                    | Self::Completed
                    | Self::Cancelling
                    | Self::Failed
            ),
            Self::RetryWaiting => matches!(
                next,
                Self::Preparing | Self::Transferring | Self::Cancelling | Self::Failed
            ),
            Self::Verifying => matches!(
                next,
                Self::Committing
                    | Self::RetryWaiting
                    | Self::Cancelling
                    | Self::CleaningUp
                    | Self::Failed
            ),
            Self::Committing => matches!(
                next,
                Self::CleaningUp | Self::Completed | Self::Cancelling | Self::Failed
            ),
            Self::Cancelling => matches!(next, Self::CleaningUp | Self::Cancelled | Self::Failed),
            Self::CleaningUp => {
                matches!(next, Self::Completed | Self::Cancelled | Self::Failed)
            }
            Self::Completed | Self::Cancelled | Self::Failed => false,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentTransferProgress {
    pub bytes_completed: u64,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_total: Option<u64>,

    pub objects_completed: u64,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub objects_total: Option<u64>,

    pub chunks_completed: u32,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chunks_total: Option<u32>,
}

impl AgentTransferProgress {
    fn validate(&self, contract: &AgentTransferContract) -> Result<(), AgentTransferContractError> {
        validate_counter(self.bytes_completed, self.bytes_total, "progress.bytes")?;
        validate_counter(
            self.objects_completed,
            self.objects_total,
            "progress.objects",
        )?;
        validate_counter(
            u64::from(self.chunks_completed),
            self.chunks_total.map(u64::from),
            "progress.chunks",
        )?;
        if self.chunks_completed > contract.chunking.max_chunks
            || self
                .chunks_total
                .is_some_and(|total| total > contract.chunking.max_chunks)
        {
            return Err(invalid(
                "progress.chunks",
                "exceeds the backend chunk bound",
            ));
        }
        Ok(())
    }

    fn is_monotonic_from(&self, previous: &Self) -> bool {
        self.bytes_completed >= previous.bytes_completed
            && self.objects_completed >= previous.objects_completed
            && self.chunks_completed >= previous.chunks_completed
            && totals_stable(previous.bytes_total, self.bytes_total)
            && totals_stable(previous.objects_total, self.objects_total)
            && totals_stable(previous.chunks_total, self.chunks_total)
    }

    fn is_complete(&self) -> bool {
        self.bytes_total
            .is_none_or(|total| self.bytes_completed == total)
            && self
                .objects_total
                .is_none_or(|total| self.objects_completed == total)
            && self
                .chunks_total
                .is_none_or(|total| self.chunks_completed == total)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentTransferChunkState {
    pub index: u32,
    pub offset: u64,
    pub length: u64,
    pub completed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentTransferResumeCheckpoint {
    pub token: String,
    pub scope: String,
    pub completed_bytes: u64,
    pub completed_chunks: u32,
    pub expires_at: DateTime<Utc>,
}

impl AgentTransferResumeCheckpoint {
    fn validate(
        &self,
        contract: &AgentTransferContract,
        observed_at: DateTime<Utc>,
        progress: &AgentTransferProgress,
    ) -> Result<(), AgentTransferContractError> {
        if contract.resume.mode == AgentTransferResumeMode::Unsupported {
            return Err(invalid(
                "checkpoint",
                "backend does not support resume tokens",
            ));
        }
        if self.token.is_empty()
            || self.token.len() > contract.resume.max_token_bytes
            || self.token.chars().any(char::is_control)
        {
            return Err(invalid(
                "checkpoint.token",
                "must be non-empty, bounded, and contain no control characters",
            ));
        }
        validate_sha256_fingerprint(&self.scope, "checkpoint.scope")?;
        if self.expires_at <= observed_at {
            return Err(invalid("checkpoint.expires_at", "must be in the future"));
        }
        if self.completed_bytes > progress.bytes_completed
            || self.completed_chunks > progress.chunks_completed
        {
            return Err(invalid(
                "checkpoint",
                "cannot claim progress beyond the current event",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentTransferChecksum {
    pub algorithm: AgentTransferChecksumAlgorithm,
    pub scope: AgentTransferChecksumScope,
    pub value: String,
    pub verified: bool,
}

impl AgentTransferChecksum {
    fn validate(&self, contract: &AgentTransferContract) -> Result<(), AgentTransferContractError> {
        if !contract.checksums.contains(&self.algorithm) {
            return Err(invalid(
                "checksum.algorithm",
                "algorithm is outside the backend contract",
            ));
        }
        if self.value.is_empty()
            || self.value.len() > MAX_AGENT_TRANSFER_CHECKSUM_BYTES
            || self.value.chars().any(char::is_control)
        {
            return Err(invalid(
                "checksum.value",
                "must be non-empty, bounded, and contain no control characters",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentTransferRetry {
    pub attempt: u32,
    pub backoff_ms: u64,
    pub reason_code: String,
}

impl AgentTransferRetry {
    fn validate(&self, contract: &AgentTransferContract) -> Result<(), AgentTransferContractError> {
        if self.attempt == 0 || self.attempt > contract.retry.max_retries {
            return Err(invalid(
                "retry.attempt",
                "must be within the backend retry policy",
            ));
        }
        if self.backoff_ms < contract.retry.initial_backoff_ms
            || self.backoff_ms > contract.retry.max_backoff_ms
        {
            return Err(invalid(
                "retry.backoff_ms",
                "must be within the backend retry policy",
            ));
        }
        validate_stable_code(&self.reason_code, "retry.reason_code")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentTransferConflictResolution {
    Pending,
    Failed,
    Skipped,
    Replaced,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentTransferConflict {
    pub code: String,
    pub policy: AgentTransferConflictPolicy,
    pub resolution: AgentTransferConflictResolution,
}

impl AgentTransferConflict {
    fn validate(&self, contract: &AgentTransferContract) -> Result<(), AgentTransferContractError> {
        validate_stable_code(&self.code, "conflict.code")?;
        if !contract.conflicts.contains(&self.policy) {
            return Err(invalid(
                "conflict.policy",
                "policy is outside the backend contract",
            ));
        }
        let valid_resolution = match self.policy {
            AgentTransferConflictPolicy::Fail => matches!(
                self.resolution,
                AgentTransferConflictResolution::Pending | AgentTransferConflictResolution::Failed
            ),
            AgentTransferConflictPolicy::Skip => matches!(
                self.resolution,
                AgentTransferConflictResolution::Pending | AgentTransferConflictResolution::Skipped
            ),
            AgentTransferConflictPolicy::Replace => matches!(
                self.resolution,
                AgentTransferConflictResolution::Pending
                    | AgentTransferConflictResolution::Replaced
            ),
        };
        if !valid_resolution {
            return Err(invalid(
                "conflict.resolution",
                "resolution does not match the selected conflict policy",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentTransferCleanupState {
    NotApplicable,
    Pending,
    Removed,
    Aborted,
    Released,
    RetainedForResume,
    FailedClosed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentTransferCleanupReport {
    pub local_staging: AgentTransferCleanupState,
    pub remote_partial: AgentTransferCleanupState,
    pub remote_lock: AgentTransferCleanupState,
}

impl AgentTransferCleanupReport {
    fn is_settled(&self) -> bool {
        !matches!(self.local_staging, AgentTransferCleanupState::Pending)
            && !matches!(self.remote_partial, AgentTransferCleanupState::Pending)
            && !matches!(self.remote_lock, AgentTransferCleanupState::Pending)
    }
}

/// One portable transfer lifecycle event.
///
/// Source and destination names are intentionally absent. Plugins may emit
/// opaque resource fingerprints in their outer live-session envelope, but this
/// payload stays safe for CLI JSON, Agent output, TUI service events, and audit
/// summaries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentTransferEvent {
    #[serde(default = "agent_transfer_protocol_version")]
    pub protocol_version: u32,
    pub transfer_id: String,
    pub sequence: u64,
    pub observed_at: DateTime<Utc>,
    pub operation: AgentTransferOperation,
    pub phase: AgentTransferPhase,
    pub progress: AgentTransferProgress,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_chunk: Option<AgentTransferChunkState>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<AgentTransferResumeCheckpoint>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checksum: Option<AgentTransferChecksum>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry: Option<AgentTransferRetry>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conflict: Option<AgentTransferConflict>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cleanup: Option<AgentTransferCleanupReport>,

    #[serde(default)]
    pub terminal: bool,

    #[serde(default)]
    pub redaction: RedactionStatus,
}

impl AgentTransferEvent {
    /// Build a redacted snapshot for one-object CLI or TUI presentation.
    ///
    /// Backend sessions may enrich this with chunk, retry, conflict, checksum,
    /// resume, and cleanup metadata before validating it against their
    /// contract.
    pub fn single_object_snapshot(
        transfer_id: impl Into<String>,
        operation: AgentTransferOperation,
        phase: AgentTransferPhase,
        sequence: u64,
        bytes_completed: u64,
        bytes_total: Option<u64>,
    ) -> Self {
        let terminal = phase.is_terminal();
        let completed = phase == AgentTransferPhase::Completed;
        Self {
            protocol_version: AGENT_TRANSFER_PROTOCOL_VERSION,
            transfer_id: transfer_id.into(),
            sequence: sequence.max(1),
            observed_at: Utc::now(),
            operation,
            phase,
            progress: AgentTransferProgress {
                bytes_completed,
                bytes_total,
                objects_completed: u64::from(completed),
                objects_total: Some(1),
                chunks_completed: u32::from(completed),
                chunks_total: Some(1),
            },
            current_chunk: None,
            checkpoint: None,
            checksum: None,
            retry: None,
            conflict: None,
            cleanup: terminal.then_some(AgentTransferCleanupReport {
                local_staging: AgentTransferCleanupState::NotApplicable,
                remote_partial: AgentTransferCleanupState::NotApplicable,
                remote_lock: AgentTransferCleanupState::NotApplicable,
            }),
            terminal,
            redaction: RedactionStatus::Applied,
        }
    }

    /// Stable human summary used by storage CLI and standalone TUI surfaces.
    pub fn human_summary(&self) -> String {
        let total = self
            .progress
            .bytes_total
            .map(|total| total.to_string())
            .unwrap_or_else(|| "?".to_string());
        format!(
            "{} {}: {}/{} bytes",
            self.operation.as_str(),
            self.phase.as_str(),
            self.progress.bytes_completed,
            total
        )
    }

    pub fn validate(
        &self,
        contract: &AgentTransferContract,
    ) -> Result<(), AgentTransferContractError> {
        contract.validate()?;
        if self.protocol_version != AGENT_TRANSFER_PROTOCOL_VERSION {
            return Err(AgentTransferContractError::UnsupportedProtocol(
                self.protocol_version,
            ));
        }
        validate_label(
            &self.transfer_id,
            MAX_AGENT_TRANSFER_ID_BYTES,
            "transfer_id",
        )?;
        if self.sequence == 0 {
            return Err(invalid("sequence", "must be positive"));
        }
        if !contract.operations.contains(&self.operation) {
            return Err(invalid(
                "operation",
                "operation is outside the backend contract",
            ));
        }
        self.progress.validate(contract)?;
        if let Some(chunk) = &self.current_chunk
            && (chunk.index == 0
                || chunk.index > contract.chunking.max_chunks
                || chunk.length == 0
                || chunk.offset.checked_add(chunk.length).is_none())
        {
            return Err(invalid(
                "current_chunk",
                "chunk index, range, or length is invalid",
            ));
        }
        if let Some(checkpoint) = &self.checkpoint {
            checkpoint.validate(contract, self.observed_at, &self.progress)?;
        }
        if let Some(checksum) = &self.checksum {
            checksum.validate(contract)?;
        }
        match (&self.phase, &self.retry) {
            (AgentTransferPhase::RetryWaiting, Some(retry)) => retry.validate(contract)?,
            (AgentTransferPhase::RetryWaiting, None) => {
                return Err(invalid(
                    "retry",
                    "retry_waiting phase requires retry metadata",
                ));
            }
            (_, Some(_)) => {
                return Err(invalid(
                    "retry",
                    "retry metadata is valid only while retry_waiting",
                ));
            }
            (_, None) => {}
        }
        match (&self.phase, &self.conflict) {
            (AgentTransferPhase::Conflict, Some(conflict)) => conflict.validate(contract)?,
            (AgentTransferPhase::Conflict, None) => {
                return Err(invalid(
                    "conflict",
                    "conflict phase requires conflict metadata",
                ));
            }
            (_, Some(conflict)) if self.phase == AgentTransferPhase::Failed => {
                conflict.validate(contract)?;
            }
            (_, Some(_)) => {
                return Err(invalid(
                    "conflict",
                    "conflict metadata is valid only during conflict or terminal failure",
                ));
            }
            (_, None) => {}
        }
        if self.terminal != self.phase.is_terminal() {
            return Err(invalid(
                "terminal",
                "must exactly match the lifecycle phase",
            ));
        }
        if self.phase == AgentTransferPhase::Completed && !self.progress.is_complete() {
            return Err(invalid(
                "progress",
                "completed transfers must satisfy every known total",
            ));
        }
        if self.phase.is_terminal()
            && self
                .cleanup
                .as_ref()
                .is_some_and(|report| !report.is_settled())
        {
            return Err(invalid(
                "cleanup",
                "terminal cleanup reports cannot remain pending",
            ));
        }
        if self.phase == AgentTransferPhase::Completed && self.checkpoint.is_some() {
            return Err(invalid(
                "checkpoint",
                "completed transfers cannot retain resume state",
            ));
        }
        Ok(())
    }

    pub fn validate_transition(
        &self,
        previous: &Self,
        contract: &AgentTransferContract,
    ) -> Result<(), AgentTransferContractError> {
        previous.validate(contract)?;
        self.validate(contract)?;
        if self.transfer_id != previous.transfer_id || self.operation != previous.operation {
            return Err(invalid(
                "transfer_id",
                "a lifecycle cannot change transfer identity or operation",
            ));
        }
        if self.sequence <= previous.sequence {
            return Err(invalid("sequence", "must increase monotonically"));
        }
        if self.observed_at < previous.observed_at {
            return Err(invalid("observed_at", "cannot move backwards"));
        }
        if !previous.phase.allows(self.phase) {
            return Err(AgentTransferContractError::InvalidTransition {
                from: previous.phase,
                to: self.phase,
            });
        }
        if !self.progress.is_monotonic_from(&previous.progress) {
            return Err(invalid(
                "progress",
                "verified progress and known totals cannot regress",
            ));
        }
        Ok(())
    }
}

/// JSON Schema for `AgentTransferEvent` payloads embedded in a live-session
/// event descriptor. Runtime validation remains authoritative for transitions,
/// resume binding, progress monotonicity, and backend-specific bounds.
pub fn agent_transfer_event_schema() -> Value {
    json!({
        "type": "object",
        "required": [
            "protocol_version", "transfer_id", "sequence", "observed_at",
            "operation", "phase", "progress", "terminal", "redaction"
        ],
        "properties": {
            "protocol_version": { "const": AGENT_TRANSFER_PROTOCOL_VERSION },
            "transfer_id": { "type": "string", "minLength": 1, "maxLength": MAX_AGENT_TRANSFER_ID_BYTES },
            "sequence": { "type": "integer", "minimum": 1 },
            "observed_at": { "type": "string", "format": "date-time" },
            "operation": { "type": "string", "enum": ["upload", "download", "copy", "move"] },
            "phase": {
                "type": "string",
                "enum": [
                    "planned", "awaiting_authorization", "queued", "preparing",
                    "transferring", "paused", "conflict", "retry_waiting",
                    "verifying", "committing", "cancelling", "cleaning_up",
                    "completed", "cancelled", "failed"
                ]
            },
            "progress": {
                "type": "object",
                "required": ["bytes_completed", "objects_completed", "chunks_completed"],
                "properties": {
                    "bytes_completed": { "type": "integer", "minimum": 0 },
                    "bytes_total": { "type": "integer", "minimum": 0 },
                    "objects_completed": { "type": "integer", "minimum": 0 },
                    "objects_total": { "type": "integer", "minimum": 0 },
                    "chunks_completed": { "type": "integer", "minimum": 0 },
                    "chunks_total": { "type": "integer", "minimum": 0 }
                },
                "additionalProperties": false
            },
            "current_chunk": {
                "type": "object",
                "required": ["index", "offset", "length", "completed"],
                "properties": {
                    "index": { "type": "integer", "minimum": 1 },
                    "offset": { "type": "integer", "minimum": 0 },
                    "length": { "type": "integer", "minimum": 1 },
                    "completed": { "type": "boolean" }
                },
                "additionalProperties": false
            },
            "checkpoint": {
                "type": "object",
                "required": ["token", "scope", "completed_bytes", "completed_chunks", "expires_at"],
                "properties": {
                    "token": { "type": "string", "minLength": 1, "maxLength": MAX_AGENT_TRANSFER_RESUME_TOKEN_BYTES },
                    "scope": { "type": "string", "pattern": "^sha256:[0-9a-f]{64}$" },
                    "completed_bytes": { "type": "integer", "minimum": 0 },
                    "completed_chunks": { "type": "integer", "minimum": 0 },
                    "expires_at": { "type": "string", "format": "date-time" }
                },
                "additionalProperties": false
            },
            "checksum": {
                "type": "object",
                "required": ["algorithm", "scope", "value", "verified"],
                "properties": {
                    "algorithm": { "type": "string", "enum": ["sha256", "md5", "etag", "webdav_digest"] },
                    "scope": { "type": "string", "enum": ["whole_transfer", "object", "chunk"] },
                    "value": { "type": "string", "minLength": 1, "maxLength": MAX_AGENT_TRANSFER_CHECKSUM_BYTES },
                    "verified": { "type": "boolean" }
                },
                "additionalProperties": false
            },
            "retry": {
                "type": "object",
                "required": ["attempt", "backoff_ms", "reason_code"],
                "properties": {
                    "attempt": { "type": "integer", "minimum": 1, "maximum": MAX_AGENT_TRANSFER_RETRIES },
                    "backoff_ms": { "type": "integer", "minimum": 0, "maximum": MAX_AGENT_TRANSFER_BACKOFF_MS },
                    "reason_code": { "type": "string", "minLength": 1, "maxLength": MAX_AGENT_TRANSFER_STABLE_CODE_BYTES }
                },
                "additionalProperties": false
            },
            "conflict": {
                "type": "object",
                "required": ["code", "policy", "resolution"],
                "properties": {
                    "code": { "type": "string", "minLength": 1, "maxLength": MAX_AGENT_TRANSFER_STABLE_CODE_BYTES },
                    "policy": { "type": "string", "enum": ["fail", "skip", "replace"] },
                    "resolution": { "type": "string", "enum": ["pending", "failed", "skipped", "replaced"] }
                },
                "additionalProperties": false
            },
            "cleanup": {
                "type": "object",
                "required": ["local_staging", "remote_partial", "remote_lock"],
                "properties": {
                    "local_staging": { "$ref": "#/$defs/cleanup_state" },
                    "remote_partial": { "$ref": "#/$defs/cleanup_state" },
                    "remote_lock": { "$ref": "#/$defs/cleanup_state" }
                },
                "additionalProperties": false
            },
            "terminal": { "type": "boolean" },
            "redaction": { "type": "string", "enum": ["not_required", "applied", "withheld", "failed_closed"] }
        },
        "$defs": {
            "cleanup_state": {
                "type": "string",
                "enum": [
                    "not_applicable", "pending", "removed", "aborted", "released",
                    "retained_for_resume", "failed_closed"
                ]
            }
        },
        "additionalProperties": false
    })
}

fn agent_transfer_protocol_version() -> u32 {
    AGENT_TRANSFER_PROTOCOL_VERSION
}

fn invalid(field: &'static str, reason: &'static str) -> AgentTransferContractError {
    AgentTransferContractError::InvalidField { field, reason }
}

fn validate_label(
    value: &str,
    max_bytes: usize,
    field: &'static str,
) -> Result<(), AgentTransferContractError> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.chars().any(char::is_control)
        || value.chars().any(char::is_whitespace)
    {
        return Err(invalid(
            field,
            "must be non-empty, bounded, and contain no control or whitespace characters",
        ));
    }
    Ok(())
}

fn validate_stable_code(
    value: &str,
    field: &'static str,
) -> Result<(), AgentTransferContractError> {
    validate_label(value, MAX_AGENT_TRANSFER_STABLE_CODE_BYTES, field)?;
    if value.chars().any(|character| {
        !(character.is_ascii_lowercase() || character.is_ascii_digit() || "._-".contains(character))
    }) {
        return Err(invalid(
            field,
            "must contain only lowercase ASCII letters, digits, dot, underscore, or dash",
        ));
    }
    Ok(())
}

fn validate_sha256_fingerprint(
    value: &str,
    field: &'static str,
) -> Result<(), AgentTransferContractError> {
    let digest = value
        .strip_prefix("sha256:")
        .ok_or_else(|| invalid(field, "must be an opaque sha256 fingerprint"))?;
    if digest.len() != 64
        || !digest
            .chars()
            .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase())
    {
        return Err(invalid(field, "must be an opaque sha256 fingerprint"));
    }
    Ok(())
}

fn validate_non_empty_unique<T>(
    values: &[T],
    field: &'static str,
) -> Result<(), AgentTransferContractError>
where
    T: Copy + Eq + std::hash::Hash,
{
    if values.is_empty() || values.iter().copied().collect::<HashSet<_>>().len() != values.len() {
        return Err(invalid(
            field,
            "must be non-empty and contain no duplicates",
        ));
    }
    Ok(())
}

fn validate_counter(
    completed: u64,
    total: Option<u64>,
    field: &'static str,
) -> Result<(), AgentTransferContractError> {
    if total.is_some_and(|total| completed > total) {
        return Err(invalid(field, "completed count cannot exceed its total"));
    }
    Ok(())
}

fn totals_stable<T: Copy + PartialEq>(previous: Option<T>, current: Option<T>) -> bool {
    previous.is_none_or(|previous| current == Some(previous))
}

fn contains_cleanup(
    actions: &[AgentTransferCleanupAction],
    left: AgentTransferCleanupAction,
    right: AgentTransferCleanupAction,
) -> bool {
    actions.contains(&left) || actions.contains(&right)
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use jsonschema::validator_for;

    use super::*;

    fn contract() -> AgentTransferContract {
        AgentTransferContract {
            protocol_version: AGENT_TRANSFER_PROTOCOL_VERSION,
            target_kind: "fixture_object".into(),
            operations: vec![
                AgentTransferOperation::Upload,
                AgentTransferOperation::Download,
                AgentTransferOperation::Copy,
                AgentTransferOperation::Move,
            ],
            chunking: AgentTransferChunkPolicy {
                modes: vec![
                    AgentTransferChunkMode::Single,
                    AgentTransferChunkMode::ByteRange,
                    AgentTransferChunkMode::Multipart,
                ],
                max_chunks: MAX_AGENT_TRANSFER_CHUNKS,
                max_parallel_chunks: 8,
            },
            checksums: vec![
                AgentTransferChecksumAlgorithm::Sha256,
                AgentTransferChecksumAlgorithm::Etag,
            ],
            conflicts: vec![
                AgentTransferConflictPolicy::Fail,
                AgentTransferConflictPolicy::Skip,
                AgentTransferConflictPolicy::Replace,
            ],
            preconditions: vec![
                AgentTransferPrecondition::SourceMatch,
                AgentTransferPrecondition::DestinationAbsent,
                AgentTransferPrecondition::DestinationMatch,
            ],
            retry: AgentTransferRetryPolicy {
                max_retries: 4,
                initial_backoff_ms: 100,
                max_backoff_ms: 2_000,
            },
            resume: AgentTransferResumePolicy {
                mode: AgentTransferResumeMode::Exact,
                max_token_bytes: 4_096,
                token_ttl_seconds: 3_600,
                require_scope_fingerprint: true,
            },
            local_path: AgentTransferLocalPathPolicy {
                access: vec![
                    AgentTransferLocalAccess::ReadFile,
                    AgentTransferLocalAccess::CreateFile,
                    AgentTransferLocalAccess::ReplaceFile,
                    AgentTransferLocalAccess::ResumeTransfer,
                ],
                disclose_absolute_paths: false,
            },
            cleanup: AgentTransferCleanupPolicy {
                on_cancel: vec![
                    AgentTransferCleanupAction::RemoveLocalStaging,
                    AgentTransferCleanupAction::AbortRemotePartial,
                ],
                on_failure: vec![
                    AgentTransferCleanupAction::RemoveLocalStaging,
                    AgentTransferCleanupAction::RetainBoundCheckpoint,
                ],
                timeout_ms: 30_000,
            },
        }
    }

    fn event(phase: AgentTransferPhase, sequence: u64) -> AgentTransferEvent {
        AgentTransferEvent {
            protocol_version: AGENT_TRANSFER_PROTOCOL_VERSION,
            transfer_id: "transfer:fixture:1".into(),
            sequence,
            observed_at: Utc::now(),
            operation: AgentTransferOperation::Download,
            phase,
            progress: AgentTransferProgress {
                bytes_completed: 5,
                bytes_total: Some(10),
                objects_completed: 0,
                objects_total: Some(1),
                chunks_completed: 1,
                chunks_total: Some(2),
            },
            current_chunk: Some(AgentTransferChunkState {
                index: 1,
                offset: 0,
                length: 5,
                completed: true,
            }),
            checkpoint: None,
            checksum: None,
            retry: None,
            conflict: None,
            cleanup: None,
            terminal: phase.is_terminal(),
            redaction: RedactionStatus::NotRequired,
        }
    }

    #[test]
    fn validates_shared_policy_and_rejects_authority_drift() {
        let contract = contract();
        contract.validate().expect("valid contract");

        let mut unsafe_contract = contract.clone();
        unsafe_contract.local_path.disclose_absolute_paths = true;
        assert_eq!(
            unsafe_contract.validate(),
            Err(invalid(
                "local_path.disclose_absolute_paths",
                "absolute local paths must remain withheld"
            ))
        );

        let mut unbound_resume = contract;
        unbound_resume
            .local_path
            .access
            .retain(|access| *access != AgentTransferLocalAccess::ResumeTransfer);
        assert_eq!(
            unbound_resume.validate(),
            Err(invalid(
                "local_path.access",
                "resumable transfers require resume_transfer authority"
            ))
        );
    }

    #[test]
    fn validates_checkpoint_retry_conflict_and_cleanup_metadata() {
        let contract = contract();
        let mut checkpoint = event(AgentTransferPhase::Transferring, 2);
        checkpoint.checkpoint = Some(AgentTransferResumeCheckpoint {
            token: "opaque-checkpoint".into(),
            scope: format!("sha256:{}", "a".repeat(64)),
            completed_bytes: 5,
            completed_chunks: 1,
            expires_at: checkpoint.observed_at + Duration::minutes(5),
        });
        checkpoint.validate(&contract).expect("checkpoint event");

        let mut retry = event(AgentTransferPhase::RetryWaiting, 3);
        retry.observed_at = checkpoint.observed_at + Duration::seconds(1);
        retry.retry = Some(AgentTransferRetry {
            attempt: 1,
            backoff_ms: 100,
            reason_code: "unavailable.target".into(),
        });
        retry
            .validate_transition(&checkpoint, &contract)
            .expect("retry transition");

        let mut conflict = event(AgentTransferPhase::Conflict, 4);
        conflict.observed_at = retry.observed_at + Duration::seconds(1);
        conflict.conflict = Some(AgentTransferConflict {
            code: "conflict.destination_exists".into(),
            policy: AgentTransferConflictPolicy::Replace,
            resolution: AgentTransferConflictResolution::Pending,
        });
        assert_eq!(
            conflict.validate_transition(&retry, &contract),
            Err(AgentTransferContractError::InvalidTransition {
                from: AgentTransferPhase::RetryWaiting,
                to: AgentTransferPhase::Conflict,
            })
        );

        let mut cancelled = event(AgentTransferPhase::Cancelled, 5);
        cancelled.cleanup = Some(AgentTransferCleanupReport {
            local_staging: AgentTransferCleanupState::Pending,
            remote_partial: AgentTransferCleanupState::Aborted,
            remote_lock: AgentTransferCleanupState::NotApplicable,
        });
        assert_eq!(
            cancelled.validate(&contract),
            Err(invalid(
                "cleanup",
                "terminal cleanup reports cannot remain pending"
            ))
        );
    }

    #[test]
    fn transition_rejects_progress_regression_and_terminal_escape() {
        let contract = contract();
        let first = event(AgentTransferPhase::Transferring, 1);
        let mut regressed = event(AgentTransferPhase::Verifying, 2);
        regressed.progress.bytes_completed = 4;
        assert_eq!(
            regressed.validate_transition(&first, &contract),
            Err(invalid(
                "progress",
                "verified progress and known totals cannot regress"
            ))
        );

        let mut completed = event(AgentTransferPhase::Completed, 3);
        completed.progress.bytes_completed = 10;
        completed.progress.objects_completed = 1;
        completed.progress.chunks_completed = 2;
        completed.cleanup = Some(AgentTransferCleanupReport {
            local_staging: AgentTransferCleanupState::Removed,
            remote_partial: AgentTransferCleanupState::NotApplicable,
            remote_lock: AgentTransferCleanupState::NotApplicable,
        });
        completed.validate(&contract).expect("completed event");

        let mut escaped = event(AgentTransferPhase::Preparing, 4);
        escaped.progress = completed.progress.clone();
        assert_eq!(
            escaped.validate_transition(&completed, &contract),
            Err(AgentTransferContractError::InvalidTransition {
                from: AgentTransferPhase::Completed,
                to: AgentTransferPhase::Preparing,
            })
        );
    }

    #[test]
    fn serialized_event_matches_machine_schema() {
        let contract = contract();
        let event = event(AgentTransferPhase::Transferring, 1);
        event.validate(&contract).expect("valid event");
        let schema = agent_transfer_event_schema();
        let validator = validator_for(&schema).expect("transfer event schema");
        let value = serde_json::to_value(event).expect("serialize event");
        assert!(validator.is_valid(&value), "event: {value}");
    }

    #[test]
    fn single_object_snapshot_has_consistent_machine_and_human_views() {
        let transferring = AgentTransferEvent::single_object_snapshot(
            "cli-transfer",
            AgentTransferOperation::Download,
            AgentTransferPhase::Transferring,
            1,
            5,
            Some(10),
        );
        transferring
            .validate(&contract())
            .expect("valid transfer snapshot");
        assert_eq!(
            transferring.human_summary(),
            "download transferring: 5/10 bytes"
        );
        assert_eq!(transferring.progress.objects_completed, 0);

        let completed = AgentTransferEvent::single_object_snapshot(
            "cli-transfer",
            AgentTransferOperation::Download,
            AgentTransferPhase::Completed,
            2,
            10,
            Some(10),
        );
        completed
            .validate_transition(&transferring, &contract())
            .expect("valid completion snapshot");
        assert!(completed.terminal);
        assert_eq!(completed.progress.objects_completed, 1);

        let cancelling = AgentTransferEvent::single_object_snapshot(
            "cancelled-transfer",
            AgentTransferOperation::Upload,
            AgentTransferPhase::Transferring,
            1,
            0,
            Some(10),
        );
        let cancelling_next = AgentTransferEvent::single_object_snapshot(
            "cancelled-transfer",
            AgentTransferOperation::Upload,
            AgentTransferPhase::Cancelling,
            2,
            0,
            Some(10),
        );
        cancelling_next
            .validate_transition(&cancelling, &contract())
            .expect("valid cancelling snapshot");
        let cancelled = AgentTransferEvent::single_object_snapshot(
            "cancelled-transfer",
            AgentTransferOperation::Upload,
            AgentTransferPhase::Cancelled,
            3,
            0,
            Some(10),
        );
        cancelled
            .validate_transition(&cancelling_next, &contract())
            .expect("valid cancelled snapshot");
    }
}
