//! Versioned, non-PTY external context discovery contract.
//!
//! Context owners keep live handles and UI state in their own processes. This
//! module reads only bounded store records, projects principal-safe output, and
//! defines the stable command/error vocabulary used by external automation.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration as StdDuration, Instant};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use crate::agent_authorization::AgentPrincipal;
use crate::assist::{
    ASSIST_BROKER_STORE_VERSION, ASSIST_OWNER_LEASE_VERSION, AssistAction,
    AssistActionConfirmation, AssistActionTarget, AssistBoundedText, AssistBrokerPolicy,
    AssistBrokerRecord, AssistContextSnapshot, AssistPermission, AssistPluginState,
    AssistRequestStatus, AssistResponse, FrontendAssistRequest, MAX_AGENT_CONTEXT_LABEL_CHARS,
    MAX_ASSIST_OUTPUT_LIMIT_BYTES, MAX_ASSIST_REQUEST_TTL_SECONDS, MAX_ASSIST_VISIBLE_SCREEN_CELLS,
    assist_owner_lease_filename, safe_assist_request_filename,
};
use crate::capability::{PluginId, RedactionStatus};
use crate::session::PluginSessionHealth;

pub const AGENT_CONTEXT_PROTOCOL_VERSION: u32 = 1;
pub const MAX_AGENT_CONTEXT_RECORD_BYTES: u64 = 512 * 1024;
pub const MAX_AGENT_CONTEXT_STORE_RECORDS: usize = 4096;
pub const MAX_AGENT_CONTEXT_OPERATION_INPUT_BYTES: usize = 64 * 1024;
pub const MAX_AGENT_CONTEXT_WAIT_MS: u64 = 300_000;
pub const DEFAULT_AGENT_CONTEXT_WAIT_POLL_MS: u64 = 100;
const AGENT_CONTEXT_RECORD_LOCK_TIMEOUT: StdDuration = StdDuration::from_millis(500);
const AGENT_CONTEXT_STALE_RECORD_LOCK_AGE: StdDuration = StdDuration::from_secs(30);

pub const AGENT_CONTEXT_CLIENT_ID_ENV: &str = "VOIDB_AGENT_CLIENT_ID";
pub const AGENT_CONTEXT_TASK_ID_ENV: &str = "VOIDB_AGENT_TASK_ID";
pub const AGENT_CONTEXT_INSTANCE_ID_ENV: &str = "VOIDB_AGENT_INSTANCE_ID";

/// Stable command names for discovery and the complete review workflow,
/// without legacy ask/answer terminology.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentContextCommand {
    List,
    Show,
    Operation,
    Deny,
    Status,
    Wait,
}

impl AgentContextCommand {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::List => "list",
            Self::Show => "show",
            Self::Operation => "operation",
            Self::Deny => "deny",
            Self::Status => "status",
            Self::Wait => "wait",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AgentContextRef {
    pub plugin_id: PluginId,
    pub context_id: String,
    pub generation: u64,
}

impl AgentContextRef {
    pub fn new(
        plugin_id: impl Into<PluginId>,
        context_id: impl Into<String>,
        generation: u64,
    ) -> Result<Self, AgentContextProtocolError> {
        let reference = Self {
            plugin_id: plugin_id.into(),
            context_id: context_id.into(),
            generation,
        };
        reference.validate()?;
        Ok(reference)
    }

    pub fn validate(&self) -> Result<(), AgentContextProtocolError> {
        if !valid_identifier(&self.plugin_id, 128) {
            return Err(AgentContextProtocolError::invalid_request(
                "plugin_id must contain 1 to 128 safe identifier bytes",
            ));
        }
        if !valid_identifier(&self.context_id, 255) {
            return Err(AgentContextProtocolError::invalid_request(
                "context_id must contain 1 to 255 safe identifier bytes",
            ));
        }
        if self.generation == 0 {
            return Err(AgentContextProtocolError::invalid_request(
                "generation must be greater than zero",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentContextAvailability {
    Active,
    Expired,
    Stale,
    Terminal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentContextErrorCode {
    InvalidRequest,
    NotFound,
    PrincipalMismatch,
    Expired,
    Stale,
    Incompatible,
    Conflict,
    Replay,
    Timeout,
    OwnerUnavailable,
    StoreUnavailable,
    Internal,
}

impl AgentContextErrorCode {
    /// Stable process exit status for machine clients.
    pub const fn exit_code(self) -> u8 {
        match self {
            Self::InvalidRequest => 2,
            Self::NotFound => 3,
            Self::PrincipalMismatch => 4,
            Self::Expired => 5,
            Self::Stale => 6,
            Self::Incompatible => 7,
            Self::Conflict => 8,
            Self::Replay => 9,
            Self::Timeout => 10,
            Self::OwnerUnavailable => 11,
            Self::StoreUnavailable => 12,
            Self::Internal => 70,
        }
    }

    pub const fn retryable(self) -> bool {
        matches!(
            self,
            Self::Timeout | Self::OwnerUnavailable | Self::StoreUnavailable
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentContextProtocolError {
    pub code: AgentContextErrorCode,
    pub message: String,
    pub exit_code: u8,
    pub retryable: bool,
}

impl AgentContextProtocolError {
    pub fn new(code: AgentContextErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            exit_code: code.exit_code(),
            retryable: code.retryable(),
        }
    }

    pub fn invalid_request(message: impl Into<String>) -> Self {
        Self::new(AgentContextErrorCode::InvalidRequest, message)
    }
}

impl std::fmt::Display for AgentContextProtocolError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for AgentContextProtocolError {}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentContextEnvelope<T> {
    pub ok: bool,
    pub protocol_version: u32,
    pub command: AgentContextCommand,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<AgentContextProtocolError>,
}

impl<T> AgentContextEnvelope<T> {
    pub fn success(command: AgentContextCommand, data: T) -> Self {
        Self {
            ok: true,
            protocol_version: AGENT_CONTEXT_PROTOCOL_VERSION,
            command,
            data: Some(data),
            error: None,
        }
    }

    pub fn failure(command: AgentContextCommand, error: AgentContextProtocolError) -> Self {
        Self {
            ok: false,
            protocol_version: AGENT_CONTEXT_PROTOCOL_VERSION,
            command,
            data: None,
            error: Some(error),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentContextSummary {
    pub context: AgentContextRef,

    /// Labels are withheld once a context is expired or stale.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,

    pub status: AssistRequestStatus,
    pub availability: AgentContextAvailability,
    pub mode: String,
    pub health: PluginSessionHealth,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub operation_request_count: usize,
    pub operation_decision_count: usize,
    pub principal_bound: bool,
    pub redaction: RedactionStatus,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentContextOperationSummary {
    pub operation_request_id: String,
    pub created_at: DateTime<Utc>,
    pub summary: String,
    pub operation_count: usize,
    pub decision_count: usize,
    pub agent_fingerprint: String,
    pub redaction: RedactionStatus,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub operations: Vec<AgentContextOperationStatus>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentContextOperationStatus {
    pub operation_index: usize,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision: Option<AgentContextOperationDecision>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentContextDetail {
    pub summary: AgentContextSummary,
    pub request: FrontendAssistRequest,
    pub context: AssistContextSnapshot,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugin_state: Option<AssistPluginState>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub operation_requests: Vec<AgentContextOperationSummary>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentContextDiscoveryIssueCode {
    PrincipalMismatch,
    IncompatibleVersion,
    InvalidRecord,
    CorruptRecord,
    DuplicateRecord,
    UnsafeStore,
    UnsafeRecord,
    StoreUnavailable,
    RecordLimitExceeded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentContextDiscoveryDiagnostic {
    pub plugin_id: PluginId,
    pub code: AgentContextDiscoveryIssueCode,
    pub count: usize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentContextListData {
    pub contexts: Vec<AgentContextSummary>,

    /// Aggregated counts deliberately omit record IDs and filesystem paths.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<AgentContextDiscoveryDiagnostic>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentContextShowData {
    pub context: AgentContextDetail,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentContextOperationInput {
    pub operation_request_id: String,
    pub summary: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,

    pub operations: Vec<AssistAction>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentContextOperationData {
    pub context: AgentContextRef,
    pub operation_request_id: String,
    pub operation_count: usize,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub created: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentContextStatusData {
    pub context: AgentContextSummary,
    pub operation_requests: Vec<AgentContextOperationSummary>,
    pub complete: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentContextWaitData {
    pub status: AgentContextStatusData,
    pub changed: bool,
    pub waited_ms: u64,
}

/// Every action is reviewed by `(operation_request_id, operation_index)`.
/// This prevents a UI from approving an entire multi-action request after
/// inspecting only its first action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentContextOperationDecision {
    Allowed,
    Denied,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentContextDecisionData {
    pub context: AgentContextRef,
    pub operation_request_id: String,
    pub operation_index: usize,
    pub decision: AgentContextOperationDecision,
    pub decided_at: DateTime<Utc>,
    pub created: bool,
}

struct AgentContextRecordLock {
    path: PathBuf,
}

impl Drop for AgentContextRecordLock {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.path);
    }
}

#[derive(Debug, Clone)]
pub struct AgentContextStoreSource {
    pub plugin_id: PluginId,
    pub root: PathBuf,
}

impl AgentContextStoreSource {
    pub fn new(plugin_id: impl Into<PluginId>, root: impl Into<PathBuf>) -> Self {
        Self {
            plugin_id: plugin_id.into(),
            root: root.into(),
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct AgentContextStoreCatalog {
    sources: Vec<AgentContextStoreSource>,
}

impl AgentContextStoreCatalog {
    pub fn new(sources: Vec<AgentContextStoreSource>) -> Self {
        Self { sources }
    }

    pub fn sources(&self) -> &[AgentContextStoreSource] {
        &self.sources
    }

    pub fn list(
        &self,
        principal: &AgentPrincipal,
        plugin_filter: Option<&str>,
    ) -> Result<AgentContextListData, AgentContextProtocolError> {
        self.list_at(principal, plugin_filter, Utc::now())
    }

    pub fn list_at(
        &self,
        principal: &AgentPrincipal,
        plugin_filter: Option<&str>,
        now: DateTime<Utc>,
    ) -> Result<AgentContextListData, AgentContextProtocolError> {
        validate_principal(principal)?;
        let sources = self.selected_sources(plugin_filter)?;
        let mut summaries = Vec::new();
        let mut issue_counts = BTreeMap::<(String, AgentContextDiscoveryIssueCode), usize>::new();

        for source in sources {
            let scan = scan_source(source, now);
            for issue in scan.issues {
                *issue_counts
                    .entry((source.plugin_id.clone(), issue.code))
                    .or_default() += 1;
            }

            let mut id_counts = BTreeMap::<String, usize>::new();
            for record in &scan.records {
                *id_counts.entry(record.request.id.clone()).or_default() += 1;
            }
            for record in scan.records {
                if id_counts.get(&record.request.id).copied().unwrap_or(0) > 1 {
                    *issue_counts
                        .entry((
                            source.plugin_id.clone(),
                            AgentContextDiscoveryIssueCode::DuplicateRecord,
                        ))
                        .or_default() += 1;
                    continue;
                }
                if !principal_matches(&record, principal) {
                    *issue_counts
                        .entry((
                            source.plugin_id.clone(),
                            AgentContextDiscoveryIssueCode::PrincipalMismatch,
                        ))
                        .or_default() += 1;
                    continue;
                }
                summaries.push(summary_from_record(&record, now));
            }
        }

        summaries.sort_by(|left, right| {
            right
                .updated_at
                .cmp(&left.updated_at)
                .then_with(|| left.context.plugin_id.cmp(&right.context.plugin_id))
                .then_with(|| left.context.context_id.cmp(&right.context.context_id))
        });
        let diagnostics = issue_counts
            .into_iter()
            .map(
                |((plugin_id, code), count)| AgentContextDiscoveryDiagnostic {
                    plugin_id,
                    code,
                    count,
                },
            )
            .collect();
        Ok(AgentContextListData {
            contexts: summaries,
            diagnostics,
        })
    }

    pub fn show(
        &self,
        principal: &AgentPrincipal,
        reference: &AgentContextRef,
    ) -> Result<AgentContextShowData, AgentContextProtocolError> {
        self.show_at(principal, reference, Utc::now())
    }

    pub fn show_at(
        &self,
        principal: &AgentPrincipal,
        reference: &AgentContextRef,
        now: DateTime<Utc>,
    ) -> Result<AgentContextShowData, AgentContextProtocolError> {
        validate_principal(principal)?;
        reference.validate()?;
        let source = self.source_for_reference(reference)?;
        let record = load_exact_record(source, principal, reference, now)?;

        Ok(AgentContextShowData {
            context: detail_from_record(&record, now)?,
        })
    }

    pub fn operation(
        &self,
        principal: &AgentPrincipal,
        reference: &AgentContextRef,
        input: AgentContextOperationInput,
    ) -> Result<AgentContextOperationData, AgentContextProtocolError> {
        self.operation_at(principal, reference, input, Utc::now())
    }

    pub fn operation_at(
        &self,
        principal: &AgentPrincipal,
        reference: &AgentContextRef,
        input: AgentContextOperationInput,
        now: DateTime<Utc>,
    ) -> Result<AgentContextOperationData, AgentContextProtocolError> {
        validate_principal(principal)?;
        reference.validate()?;
        let source = self.source_for_reference(reference)?;
        require_writable_non_pty_source(source)?;
        let response = operation_response(reference, principal, &input, now)?;
        let _lock = lock_context_record(source, &reference.context_id)?;
        let mut record = load_exact_record(source, principal, reference, now)?;

        if let Some(existing) = record
            .responses
            .iter()
            .find(|existing| existing.id == response.id)
        {
            if operation_payload_matches(existing, &response) {
                return Ok(operation_data(
                    reference,
                    existing,
                    record.request.expires_at,
                    false,
                ));
            }
            return Err(AgentContextProtocolError::new(
                AgentContextErrorCode::Replay,
                "operation request ID was already used with a different payload",
            ));
        }
        if record.request.status.is_terminal() {
            return Err(AgentContextProtocolError::new(
                AgentContextErrorCode::Conflict,
                "terminal context cannot accept a new operation request",
            ));
        }
        if record.latest_pending_operation_request().is_some() {
            return Err(AgentContextProtocolError::new(
                AgentContextErrorCode::Conflict,
                "another operation request is still pending review",
            ));
        }
        record.request.external_agent = Some(principal.clone());
        record
            .request
            .transition_to(AssistRequestStatus::Responded)
            .map_err(|_| {
                AgentContextProtocolError::new(
                    AgentContextErrorCode::Conflict,
                    "context cannot transition to operation review",
                )
            })?;
        record.responses.push(response.clone());
        record.updated_at = now;
        write_protocol_record(source, &record)?;
        Ok(operation_data(
            reference,
            &response,
            record.request.expires_at,
            true,
        ))
    }

    pub fn deny(
        &self,
        principal: &AgentPrincipal,
        reference: &AgentContextRef,
        operation_request_id: &str,
        operation_index: usize,
        reason: &str,
    ) -> Result<AgentContextDecisionData, AgentContextProtocolError> {
        self.deny_at(
            principal,
            reference,
            operation_request_id,
            operation_index,
            reason,
            Utc::now(),
        )
    }

    pub fn deny_at(
        &self,
        principal: &AgentPrincipal,
        reference: &AgentContextRef,
        operation_request_id: &str,
        operation_index: usize,
        reason: &str,
        now: DateTime<Utc>,
    ) -> Result<AgentContextDecisionData, AgentContextProtocolError> {
        validate_principal(principal)?;
        reference.validate()?;
        if !valid_identifier(operation_request_id, 255) {
            return Err(AgentContextProtocolError::invalid_request(
                "operation_request_id must contain 1 to 255 safe identifier bytes",
            ));
        }
        if !valid_text_component(reason, 1000) {
            return Err(AgentContextProtocolError::invalid_request(
                "denial reason must contain 1 to 1000 non-control bytes",
            ));
        }
        let source = self.source_for_reference(reference)?;
        require_writable_non_pty_source(source)?;
        let _lock = lock_context_record(source, &reference.context_id)?;
        let mut record = load_exact_record(source, principal, reference, now)?;
        let operation = record
            .responses
            .iter()
            .find(|operation| operation.id == operation_request_id)
            .ok_or_else(|| {
                AgentContextProtocolError::new(
                    AgentContextErrorCode::NotFound,
                    "operation request was not found",
                )
            })?;
        if &operation.agent != principal {
            return Err(AgentContextProtocolError::new(
                AgentContextErrorCode::PrincipalMismatch,
                "operation request is bound to a different external principal",
            ));
        }
        let action = operation.actions.get(operation_index).ok_or_else(|| {
            AgentContextProtocolError::invalid_request("operation_index does not exist")
        })?;
        if let Some(existing) = record.operation_confirmation(operation_request_id, operation_index)
        {
            let same_denial = confirmation_decision(existing)
                == AgentContextOperationDecision::Denied
                && existing.status == "denied_by_agent"
                && existing.note == reason;
            if same_denial {
                return Ok(decision_data(reference, existing, false));
            }
            return Err(AgentContextProtocolError::new(
                AgentContextErrorCode::Replay,
                "operation index already has a decision",
            ));
        }
        if record.request.status.is_terminal() {
            return Err(AgentContextProtocolError::new(
                AgentContextErrorCode::Conflict,
                "terminal context cannot accept an operation decision",
            ));
        }
        let confirmation = AssistActionConfirmation {
            request_id: reference.context_id.clone(),
            response_id: operation_request_id.to_string(),
            action_index: operation_index,
            target: operation_target_label(action),
            uses_current_pty: false,
            generation: reference.generation,
            confirmed_at: now,
            expires_at: Some(record.request.expires_at),
            command_summary: operation_command_summary(action),
            capability_id: operation_capability_id(action),
            status: "denied_by_agent".to_string(),
            note: reason.to_string(),
            redaction: RedactionStatus::NotRequired,
        };
        confirmation
            .validate_against(
                &record.request,
                &record.responses,
                &AssistBrokerPolicy::non_pty(),
            )
            .map_err(|_| {
                AgentContextProtocolError::invalid_request(
                    "operation denial violates the context policy",
                )
            })?;
        record.action_confirmations.push(confirmation.clone());
        record.updated_at = now;
        write_protocol_record(source, &record)?;
        Ok(decision_data(reference, &confirmation, true))
    }

    pub fn status(
        &self,
        principal: &AgentPrincipal,
        reference: &AgentContextRef,
    ) -> Result<AgentContextStatusData, AgentContextProtocolError> {
        self.status_at(principal, reference, Utc::now())
    }

    pub fn status_at(
        &self,
        principal: &AgentPrincipal,
        reference: &AgentContextRef,
        now: DateTime<Utc>,
    ) -> Result<AgentContextStatusData, AgentContextProtocolError> {
        validate_principal(principal)?;
        reference.validate()?;
        let source = self.source_for_reference(reference)?;
        let record = load_exact_record(source, principal, reference, now)?;
        status_from_record(&record, now)
    }

    pub fn wait(
        &self,
        principal: &AgentPrincipal,
        reference: &AgentContextRef,
        timeout: StdDuration,
        interval: StdDuration,
    ) -> Result<AgentContextWaitData, AgentContextProtocolError> {
        if timeout.is_zero() || timeout > StdDuration::from_millis(MAX_AGENT_CONTEXT_WAIT_MS) {
            return Err(AgentContextProtocolError::invalid_request(format!(
                "wait timeout must be between 1 and {MAX_AGENT_CONTEXT_WAIT_MS} milliseconds"
            )));
        }
        if interval.is_zero() || interval > StdDuration::from_secs(1) {
            return Err(AgentContextProtocolError::invalid_request(
                "wait poll interval must be between 1 and 1000 milliseconds",
            ));
        }
        let started = Instant::now();
        let initial = self.status(principal, reference)?;
        if initial.complete {
            return Ok(AgentContextWaitData {
                status: initial,
                changed: false,
                waited_ms: 0,
            });
        }
        loop {
            let elapsed = started.elapsed();
            if elapsed >= timeout {
                return Err(AgentContextProtocolError::new(
                    AgentContextErrorCode::Timeout,
                    "context wait timed out before operation review completed",
                ));
            }
            thread::sleep(interval.min(timeout.saturating_sub(elapsed)));
            let status = self.status(principal, reference)?;
            if status.complete {
                return Ok(AgentContextWaitData {
                    status,
                    changed: true,
                    waited_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
                });
            }
        }
    }

    fn source_for_reference(
        &self,
        reference: &AgentContextRef,
    ) -> Result<&AgentContextStoreSource, AgentContextProtocolError> {
        self.sources
            .iter()
            .find(|source| source.plugin_id == reference.plugin_id)
            .ok_or_else(|| {
                AgentContextProtocolError::invalid_request(
                    "plugin_id is not an enabled context-store source",
                )
            })
    }

    fn selected_sources(
        &self,
        plugin_filter: Option<&str>,
    ) -> Result<Vec<&AgentContextStoreSource>, AgentContextProtocolError> {
        if let Some(plugin_id) = plugin_filter {
            if !valid_identifier(plugin_id, 128) {
                return Err(AgentContextProtocolError::invalid_request(
                    "plugin filter is not a safe plugin identifier",
                ));
            }
            let selected = self
                .sources
                .iter()
                .filter(|source| source.plugin_id == plugin_id)
                .collect::<Vec<_>>();
            if selected.is_empty() {
                return Err(AgentContextProtocolError::invalid_request(
                    "plugin filter is not an enabled context-store source",
                ));
            }
            return Ok(selected);
        }
        Ok(self.sources.iter().collect())
    }
}

fn load_exact_record(
    source: &AgentContextStoreSource,
    principal: &AgentPrincipal,
    reference: &AgentContextRef,
    now: DateTime<Utc>,
) -> Result<AssistBrokerRecord, AgentContextProtocolError> {
    let expected_path = source.root.join(format!(
        "{}.json",
        safe_assist_request_filename(&reference.context_id)
    ));
    if fs::symlink_metadata(&expected_path).is_ok()
        && !safe_record_metadata(
            &expected_path,
            fs::symlink_metadata(&source.root).ok().as_ref(),
        )
    {
        return Err(AgentContextProtocolError::new(
            AgentContextErrorCode::StoreUnavailable,
            "context record failed local store safety checks",
        ));
    }

    let scan = scan_source(source, now);
    if let Some(code) = scan.source_error {
        return Err(source_error(code));
    }
    let matching_failures = scan
        .issues
        .iter()
        .filter(|failure| failure.context_id.as_deref() == Some(&reference.context_id))
        .collect::<Vec<_>>();
    if matching_failures
        .iter()
        .any(|failure| failure.code == AgentContextDiscoveryIssueCode::IncompatibleVersion)
    {
        return Err(AgentContextProtocolError::new(
            AgentContextErrorCode::Incompatible,
            "context record uses an unsupported store version",
        ));
    }
    if !matching_failures.is_empty() {
        return Err(AgentContextProtocolError::new(
            AgentContextErrorCode::Incompatible,
            "context record is corrupt or violates the external context contract",
        ));
    }

    let record_limit_exceeded = scan
        .issues
        .iter()
        .any(|issue| issue.code == AgentContextDiscoveryIssueCode::RecordLimitExceeded);
    let matching = scan
        .records
        .into_iter()
        .filter(|record| record.request.id == reference.context_id)
        .collect::<Vec<_>>();
    let record = match matching.as_slice() {
        [] if record_limit_exceeded => {
            return Err(AgentContextProtocolError::new(
                AgentContextErrorCode::StoreUnavailable,
                "context store record limit was exceeded",
            ));
        }
        [] => {
            return Err(AgentContextProtocolError::new(
                AgentContextErrorCode::NotFound,
                "context was not found",
            ));
        }
        [record] => record.clone(),
        _ => {
            return Err(AgentContextProtocolError::new(
                AgentContextErrorCode::Conflict,
                "multiple records use the requested context ID",
            ));
        }
    };

    // Principal checks intentionally precede generation checks so an exact ID
    // cannot be used as a generation oracle by a different external task.
    if !principal_matches(&record, principal) {
        return Err(AgentContextProtocolError::new(
            AgentContextErrorCode::PrincipalMismatch,
            "context is bound to a different external principal",
        ));
    }
    if record.request.binding.generation != reference.generation {
        return Err(AgentContextProtocolError::new(
            AgentContextErrorCode::Stale,
            "context generation is stale",
        ));
    }
    match availability(&record, now) {
        AgentContextAvailability::Expired => {
            return Err(AgentContextProtocolError::new(
                AgentContextErrorCode::Expired,
                "context has expired",
            ));
        }
        AgentContextAvailability::Stale => {
            return Err(AgentContextProtocolError::new(
                AgentContextErrorCode::Stale,
                "context owner or session is stale",
            ));
        }
        AgentContextAvailability::Active | AgentContextAvailability::Terminal => {}
    }
    Ok(record)
}

fn require_writable_non_pty_source(
    source: &AgentContextStoreSource,
) -> Result<(), AgentContextProtocolError> {
    if matches!(
        source.plugin_id.as_str(),
        "docker" | "kubernetes" | "jenkins"
    ) {
        Ok(())
    } else {
        Err(AgentContextProtocolError::new(
            AgentContextErrorCode::Incompatible,
            "generic operation writes are supported only for non-PTY infrastructure contexts",
        ))
    }
}

fn operation_response(
    reference: &AgentContextRef,
    principal: &AgentPrincipal,
    input: &AgentContextOperationInput,
    now: DateTime<Utc>,
) -> Result<AssistResponse, AgentContextProtocolError> {
    let encoded = serde_json::to_vec(input).map_err(|_| {
        AgentContextProtocolError::invalid_request("operation input is not serializable")
    })?;
    if encoded.len() > MAX_AGENT_CONTEXT_OPERATION_INPUT_BYTES {
        return Err(AgentContextProtocolError::invalid_request(format!(
            "operation input exceeds {MAX_AGENT_CONTEXT_OPERATION_INPUT_BYTES} bytes"
        )));
    }
    if input.operations.len() != 1 {
        return Err(AgentContextProtocolError::invalid_request(
            "non-PTY operation requests must contain exactly one operation",
        ));
    }
    let mut requested_permissions = Vec::new();
    for permission in input
        .operations
        .iter()
        .filter_map(AssistAction::requested_permission)
    {
        if !requested_permissions.contains(&permission) {
            requested_permissions.push(permission);
        }
    }
    if requested_permissions.is_empty() {
        requested_permissions.push(AssistPermission::SuggestOnly);
    }
    let response = AssistResponse {
        id: input.operation_request_id.clone(),
        request_id: reference.context_id.clone(),
        agent: principal.clone(),
        created_at: now,
        summary: input.summary.clone(),
        diagnosis: input.note.clone(),
        actions: input.operations.clone(),
        requested_permissions,
        redaction: RedactionStatus::NotRequired,
    };
    AssistBrokerPolicy::non_pty()
        .validate_operation_request(&response)
        .map_err(|error| AgentContextProtocolError::invalid_request(error.to_string()))?;
    Ok(response)
}

fn operation_payload_matches(existing: &AssistResponse, requested: &AssistResponse) -> bool {
    existing.id == requested.id
        && existing.request_id == requested.request_id
        && existing.agent == requested.agent
        && existing.summary == requested.summary
        && existing.diagnosis == requested.diagnosis
        && existing.actions == requested.actions
        && existing.requested_permissions == requested.requested_permissions
        && existing.redaction == requested.redaction
}

fn operation_data(
    reference: &AgentContextRef,
    operation: &AssistResponse,
    expires_at: DateTime<Utc>,
    created: bool,
) -> AgentContextOperationData {
    AgentContextOperationData {
        context: reference.clone(),
        operation_request_id: operation.id.clone(),
        operation_count: operation.actions.len(),
        created_at: operation.created_at,
        expires_at,
        created,
    }
}

fn decision_data(
    reference: &AgentContextRef,
    confirmation: &AssistActionConfirmation,
    created: bool,
) -> AgentContextDecisionData {
    AgentContextDecisionData {
        context: reference.clone(),
        operation_request_id: confirmation.response_id.clone(),
        operation_index: confirmation.action_index,
        decision: confirmation_decision(confirmation),
        decided_at: confirmation.confirmed_at,
        created,
    }
}

fn confirmation_decision(confirmation: &AssistActionConfirmation) -> AgentContextOperationDecision {
    if confirmation.status.starts_with("denied") {
        AgentContextOperationDecision::Denied
    } else {
        AgentContextOperationDecision::Allowed
    }
}

fn status_from_record(
    record: &AssistBrokerRecord,
    now: DateTime<Utc>,
) -> Result<AgentContextStatusData, AgentContextProtocolError> {
    let complete = record.request.status.is_terminal()
        || (!record.responses.is_empty()
            && record
                .responses
                .iter()
                .all(|operation| record.operation_request_complete(operation)));
    Ok(AgentContextStatusData {
        context: summary_from_record(record, now),
        operation_requests: operation_summaries(record)?,
        complete,
    })
}

fn operation_summaries(
    record: &AssistBrokerRecord,
) -> Result<Vec<AgentContextOperationSummary>, AgentContextProtocolError> {
    let mut operation_requests = Vec::with_capacity(record.responses.len());
    for operation in &record.responses {
        let agent_fingerprint = operation.agent.fingerprint().map_err(|_| {
            AgentContextProtocolError::new(
                AgentContextErrorCode::Incompatible,
                "operation principal projection is invalid",
            )
        })?;
        let operations = operation
            .actions
            .iter()
            .enumerate()
            .map(|(operation_index, _)| {
                let confirmation = record.operation_confirmation(&operation.id, operation_index);
                AgentContextOperationStatus {
                    operation_index,
                    decision: confirmation.map(confirmation_decision),
                    decided_at: confirmation.map(|decision| decision.confirmed_at),
                }
            })
            .collect();
        operation_requests.push(AgentContextOperationSummary {
            operation_request_id: operation.id.clone(),
            created_at: operation.created_at,
            summary: operation.summary.clone(),
            operation_count: operation.actions.len(),
            decision_count: record
                .action_confirmations
                .iter()
                .filter(|decision| decision.response_id == operation.id)
                .count(),
            agent_fingerprint,
            redaction: operation.redaction,
            operations,
        });
    }
    Ok(operation_requests)
}

fn lock_context_record(
    source: &AgentContextStoreSource,
    context_id: &str,
) -> Result<AgentContextRecordLock, AgentContextProtocolError> {
    let path = source.root.join(format!(
        ".{}.lock",
        safe_assist_request_filename(context_id)
    ));
    let started = Instant::now();
    loop {
        match fs::create_dir(&path) {
            Ok(()) => {
                #[cfg(unix)]
                if fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).is_err() {
                    let _ = fs::remove_dir(&path);
                    return Err(AgentContextProtocolError::new(
                        AgentContextErrorCode::StoreUnavailable,
                        "cannot protect the context record lock",
                    ));
                }
                return Ok(AgentContextRecordLock { path });
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let stale = fs::metadata(&path)
                    .and_then(|metadata| metadata.modified())
                    .ok()
                    .and_then(|modified| modified.elapsed().ok())
                    .is_some_and(|age| age >= AGENT_CONTEXT_STALE_RECORD_LOCK_AGE);
                if stale && fs::remove_dir(&path).is_ok() {
                    continue;
                }
                if started.elapsed() >= AGENT_CONTEXT_RECORD_LOCK_TIMEOUT {
                    return Err(AgentContextProtocolError::new(
                        AgentContextErrorCode::Conflict,
                        "context record is being updated by another process",
                    ));
                }
                thread::sleep(StdDuration::from_millis(5));
            }
            Err(_) => {
                return Err(AgentContextProtocolError::new(
                    AgentContextErrorCode::StoreUnavailable,
                    "cannot lock the context record",
                ));
            }
        }
    }
}

fn write_protocol_record(
    source: &AgentContextStoreSource,
    record: &AssistBrokerRecord,
) -> Result<(), AgentContextProtocolError> {
    validate_record(record, source).map_err(|_| {
        AgentContextProtocolError::new(
            AgentContextErrorCode::Incompatible,
            "updated context record violates the external context contract",
        )
    })?;
    let bytes = serde_json::to_vec_pretty(record).map_err(|_| {
        AgentContextProtocolError::new(
            AgentContextErrorCode::Internal,
            "cannot serialize the updated context record",
        )
    })?;
    if bytes.len() as u64 > MAX_AGENT_CONTEXT_RECORD_BYTES {
        return Err(AgentContextProtocolError::invalid_request(
            "operation would exceed the bounded context record size",
        ));
    }
    let path = source.root.join(format!(
        "{}.json",
        safe_assist_request_filename(&record.request.id)
    ));
    let temporary = source.root.join(format!(
        ".{}.{}.tmp",
        safe_assist_request_filename(&record.request.id),
        Uuid::new_v4()
    ));
    let result = (|| -> std::io::Result<()> {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_data()?;
        drop(file);
        fs::rename(&temporary, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(|_| {
        AgentContextProtocolError::new(
            AgentContextErrorCode::StoreUnavailable,
            "cannot persist the updated context record",
        )
    })
}

fn operation_target_label(action: &AssistAction) -> String {
    match action {
        AssistAction::Guidance { .. } => "human_review".to_string(),
        AssistAction::RequestPermission { permission, .. } => {
            format!("permission:{}", permission_label(*permission))
        }
        AssistAction::ProposedCommand { target, .. } => action_target_label(target),
        AssistAction::CapabilityCall { capability_id, .. } => {
            format!("capability:{capability_id}")
        }
    }
}

fn action_target_label(target: &AssistActionTarget) -> String {
    match target {
        AssistActionTarget::HumanOnly => "human_review".to_string(),
        AssistActionTarget::AgentSideSession { .. } => "agent_side_session".to_string(),
        AssistActionTarget::CurrentPty { .. } => "current_pty".to_string(),
        AssistActionTarget::Capability { capability_id } => {
            format!("capability:{capability_id}")
        }
    }
}

fn permission_label(permission: AssistPermission) -> &'static str {
    match permission {
        AssistPermission::SuggestOnly => "suggest_only",
        AssistPermission::AgentSideInspect => "agent_side_inspect",
        AssistPermission::ProposeCommands => "propose_commands",
        AssistPermission::TakeControl => "take_control",
    }
}

fn operation_command_summary(action: &AssistAction) -> Option<String> {
    matches!(action, AssistAction::ProposedCommand { .. })
        .then(|| "bounded proposed command".to_string())
}

fn operation_capability_id(action: &AssistAction) -> Option<String> {
    match action {
        AssistAction::CapabilityCall { capability_id, .. } => Some(capability_id.clone()),
        _ => None,
    }
}

#[derive(Debug)]
struct ScanIssue {
    code: AgentContextDiscoveryIssueCode,
    context_id: Option<String>,
}

#[derive(Debug, Default)]
struct SourceScan {
    records: Vec<AssistBrokerRecord>,
    issues: Vec<ScanIssue>,
    source_error: Option<AgentContextDiscoveryIssueCode>,
}

fn scan_source(source: &AgentContextStoreSource, now: DateTime<Utc>) -> SourceScan {
    let metadata = match fs::symlink_metadata(&source.root) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return SourceScan::default(),
        Err(_) => {
            return SourceScan {
                source_error: Some(AgentContextDiscoveryIssueCode::StoreUnavailable),
                issues: vec![ScanIssue {
                    code: AgentContextDiscoveryIssueCode::StoreUnavailable,
                    context_id: None,
                }],
                ..SourceScan::default()
            };
        }
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || !private_permissions(&metadata, true)
    {
        return SourceScan {
            source_error: Some(AgentContextDiscoveryIssueCode::UnsafeStore),
            issues: vec![ScanIssue {
                code: AgentContextDiscoveryIssueCode::UnsafeStore,
                context_id: None,
            }],
            ..SourceScan::default()
        };
    }

    let entries = match fs::read_dir(&source.root) {
        Ok(entries) => entries,
        Err(_) => {
            return SourceScan {
                source_error: Some(AgentContextDiscoveryIssueCode::StoreUnavailable),
                issues: vec![ScanIssue {
                    code: AgentContextDiscoveryIssueCode::StoreUnavailable,
                    context_id: None,
                }],
                ..SourceScan::default()
            };
        }
    };
    let mut scan = SourceScan::default();
    let mut paths = Vec::new();
    for entry in entries {
        match entry {
            Ok(entry)
                if entry
                    .path()
                    .extension()
                    .and_then(|extension| extension.to_str())
                    == Some("json") =>
            {
                paths.push(entry.path());
            }
            Ok(_) => {}
            Err(_) => scan.issues.push(ScanIssue {
                code: AgentContextDiscoveryIssueCode::StoreUnavailable,
                context_id: None,
            }),
        }
    }
    paths.sort();

    if paths.len() > MAX_AGENT_CONTEXT_STORE_RECORDS {
        scan.issues.push(ScanIssue {
            code: AgentContextDiscoveryIssueCode::RecordLimitExceeded,
            context_id: None,
        });
        paths.truncate(MAX_AGENT_CONTEXT_STORE_RECORDS);
    }
    for path in paths {
        match read_record(&path, source, &metadata, now) {
            Ok(record) => scan.records.push(record),
            Err(issue) => scan.issues.push(issue),
        }
    }
    scan
}

fn read_record(
    path: &Path,
    source: &AgentContextStoreSource,
    root_metadata: &fs::Metadata,
    now: DateTime<Utc>,
) -> Result<AssistBrokerRecord, ScanIssue> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ScanIssue {
        code: AgentContextDiscoveryIssueCode::StoreUnavailable,
        context_id: None,
    })?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() > MAX_AGENT_CONTEXT_RECORD_BYTES
        || !private_permissions(&metadata, false)
        || !same_owner(&metadata, root_metadata)
    {
        return Err(ScanIssue {
            code: AgentContextDiscoveryIssueCode::UnsafeRecord,
            context_id: None,
        });
    }

    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)
        .and_then(|file| {
            file.take(MAX_AGENT_CONTEXT_RECORD_BYTES + 1)
                .read_to_end(&mut bytes)
        })
        .map_err(|_| ScanIssue {
            code: AgentContextDiscoveryIssueCode::StoreUnavailable,
            context_id: None,
        })?;
    if bytes.len() as u64 > MAX_AGENT_CONTEXT_RECORD_BYTES {
        return Err(ScanIssue {
            code: AgentContextDiscoveryIssueCode::UnsafeRecord,
            context_id: None,
        });
    }
    let value: serde_json::Value = serde_json::from_slice(&bytes).map_err(|_| ScanIssue {
        code: AgentContextDiscoveryIssueCode::CorruptRecord,
        context_id: None,
    })?;
    let context_id = value
        .pointer("/request/id")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    if value.get("version").and_then(serde_json::Value::as_u64)
        != Some(u64::from(ASSIST_BROKER_STORE_VERSION))
    {
        return Err(ScanIssue {
            code: AgentContextDiscoveryIssueCode::IncompatibleVersion,
            context_id,
        });
    }
    let mut record: AssistBrokerRecord = serde_json::from_value(value).map_err(|_| ScanIssue {
        code: AgentContextDiscoveryIssueCode::CorruptRecord,
        context_id: context_id.clone(),
    })?;
    validate_record(&record, source).map_err(|_| ScanIssue {
        code: AgentContextDiscoveryIssueCode::InvalidRecord,
        context_id,
    })?;
    record.request.expire_at(now);
    if !record.request.status.is_terminal()
        && record.owner_lease.is_some()
        && !owner_lease_is_active(source, &record.request.id, root_metadata)?
    {
        record.context.health = PluginSessionHealth::Closed;
    }
    Ok(record)
}

fn owner_lease_is_active(
    source: &AgentContextStoreSource,
    context_id: &str,
    root_metadata: &fs::Metadata,
) -> Result<bool, ScanIssue> {
    let path = source.root.join(assist_owner_lease_filename(context_id));
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(_) => {
            return Err(ScanIssue {
                code: AgentContextDiscoveryIssueCode::StoreUnavailable,
                context_id: Some(context_id.to_string()),
            });
        }
    };
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || !private_permissions(&metadata, false)
        || !same_owner(&metadata, root_metadata)
    {
        return Err(ScanIssue {
            code: AgentContextDiscoveryIssueCode::UnsafeRecord,
            context_id: Some(context_id.to_string()),
        });
    }
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(|_| ScanIssue {
            code: AgentContextDiscoveryIssueCode::StoreUnavailable,
            context_id: Some(context_id.to_string()),
        })?;
    match file.try_lock() {
        Ok(()) => {
            let _ = file.unlock();
            Ok(false)
        }
        Err(std::fs::TryLockError::WouldBlock) => Ok(true),
        Err(std::fs::TryLockError::Error(_)) => Err(ScanIssue {
            code: AgentContextDiscoveryIssueCode::StoreUnavailable,
            context_id: Some(context_id.to_string()),
        }),
    }
}

fn validate_record(
    record: &AssistBrokerRecord,
    source: &AgentContextStoreSource,
) -> Result<(), ()> {
    if record.version != ASSIST_BROKER_STORE_VERSION
        || !valid_identifier(&record.request.id, 255)
        || record.request.label.trim().is_empty()
        || record.request.label.chars().count() > MAX_AGENT_CONTEXT_LABEL_CHARS
        || record.request.binding.plugin_id != source.plugin_id
        || record.context.binding != record.request.binding
        || record.request.binding.generation == 0
        || !valid_text_component(&record.request.binding.session_id, 255)
        || !valid_text_component(&record.request.binding.owner_id, 255)
        || !valid_text_component(&record.request.requester.id, 255)
        || record.updated_at < record.created_at
        || record.request.expires_at <= record.request.created_at
        || (record.request.expires_at - record.request.created_at).num_seconds()
            > MAX_ASSIST_REQUEST_TTL_SECONDS
        || record.request.context_policy.validate().is_err()
        || record.context.mode.trim().is_empty()
        || record.context.mode.len() > 255
        || matches!(record.request.redaction, RedactionStatus::FailedClosed)
        || matches!(record.context.redaction, RedactionStatus::FailedClosed)
        || record
            .owner_lease
            .is_some_and(|lease| lease.version != ASSIST_OWNER_LEASE_VERSION)
    {
        return Err(());
    }
    if let Some(principal) = &record.request.external_agent {
        principal.validate().map_err(|_| ())?;
    }
    if let Some(terminal) = record.context.terminal {
        let cells = u32::from(terminal.rows) * u32::from(terminal.cols);
        if terminal.rows == 0 || terminal.cols == 0 || cells > MAX_ASSIST_VISIBLE_SCREEN_CELLS {
            return Err(());
        }
    }
    for text in [
        record.context.visible_screen.as_ref(),
        record.context.transcript_tail.as_ref(),
        record.context.status_line.as_ref(),
    ]
    .into_iter()
    .flatten()
    {
        validate_bounded_text(text)?;
    }
    if record.context.withheld_fields.len() > 128
        || record
            .context
            .withheld_fields
            .iter()
            .any(|field| field.field.trim().is_empty() || field.field.len() > 255)
        || serialized_value_len(&record.context.metadata)?
            > record.request.context_policy.metadata_bytes
    {
        return Err(());
    }
    if let Some(state) = &record.plugin_state
        && (state.mode.trim().is_empty()
            || state.mode.len() > 255
            || state.status.trim().is_empty()
            || state.status.len() > 4000
            || matches!(state.redaction, RedactionStatus::FailedClosed)
            || serialized_value_len(&state.metadata)?
                > record.request.context_policy.metadata_bytes)
    {
        return Err(());
    }

    if record.responses.len() > 256 || record.action_confirmations.len() > 256 {
        return Err(());
    }
    let mut operation_ids = BTreeSet::new();
    for operation in &record.responses {
        operation.validate().map_err(|_| ())?;
        if operation.request_id != record.request.id || !operation_ids.insert(&operation.id) {
            return Err(());
        }
        if record.request.external_agent.as_ref() != Some(&operation.agent) {
            return Err(());
        }
    }
    let mut decisions = BTreeSet::new();
    for decision in &record.action_confirmations {
        if decision.request_id != record.request.id
            || decision.generation != record.request.binding.generation
            || !decisions.insert((decision.response_id.clone(), decision.action_index))
            || decision.validate_shape().is_err()
            || (source.plugin_id != "ssh" && decision.uses_current_pty)
            || (source.plugin_id != "ssh"
                && !matches!(
                    decision.status.as_str(),
                    "staged_for_plan_review" | "denied_by_user" | "denied_by_agent"
                ))
        {
            return Err(());
        }
        let Some(operation) = record
            .responses
            .iter()
            .find(|operation| operation.id == decision.response_id)
        else {
            return Err(());
        };
        if operation.actions.get(decision.action_index).is_none() {
            return Err(());
        }
        if source.plugin_id != "ssh" && operation.actions[decision.action_index].uses_current_pty()
        {
            return Err(());
        }
    }
    Ok(())
}

fn validate_bounded_text(text: &AssistBoundedText) -> Result<(), ()> {
    if text.limit_bytes == 0
        || text.limit_bytes > MAX_ASSIST_OUTPUT_LIMIT_BYTES
        || text.byte_count != text.text.len()
        || text.byte_count > text.limit_bytes
    {
        Err(())
    } else {
        Ok(())
    }
}

fn serialized_value_len(value: &serde_json::Value) -> Result<usize, ()> {
    if value.is_null() {
        Ok(0)
    } else {
        serde_json::to_vec(value)
            .map(|bytes| bytes.len())
            .map_err(|_| ())
    }
}

fn summary_from_record(record: &AssistBrokerRecord, now: DateTime<Utc>) -> AgentContextSummary {
    let availability = availability(record, now);
    AgentContextSummary {
        context: AgentContextRef {
            plugin_id: record.request.binding.plugin_id.clone(),
            context_id: record.request.id.clone(),
            generation: record.request.binding.generation,
        },
        label: (availability == AgentContextAvailability::Active)
            .then(|| record.request.label.clone()),
        status: record.request.status,
        availability,
        mode: record.context.mode.clone(),
        health: effective_health(record),
        created_at: record.created_at,
        updated_at: record.updated_at,
        expires_at: record.request.expires_at,
        operation_request_count: record.responses.len(),
        operation_decision_count: record.action_confirmations.len(),
        principal_bound: record.request.external_agent.is_some(),
        redaction: record.request.redaction,
    }
}

fn detail_from_record(
    record: &AssistBrokerRecord,
    now: DateTime<Utc>,
) -> Result<AgentContextDetail, AgentContextProtocolError> {
    let mut request = FrontendAssistRequest::try_from(&record.request).map_err(|_| {
        AgentContextProtocolError::new(
            AgentContextErrorCode::Incompatible,
            "context principal projection is invalid",
        )
    })?;
    // The snapshot is the authoritative bounded source. Never trust a stale or
    // hand-edited preview embedded in a store record.
    request.preview = Some(record.context.preview());
    Ok(AgentContextDetail {
        summary: summary_from_record(record, now),
        request,
        context: record.context.clone(),
        plugin_state: record.plugin_state.clone(),
        operation_requests: operation_summaries(record)?,
    })
}

fn availability(record: &AssistBrokerRecord, now: DateTime<Utc>) -> AgentContextAvailability {
    if record.request.status == AssistRequestStatus::Expired || record.request.expires_at <= now {
        AgentContextAvailability::Expired
    } else if effective_health(record).is_terminal() {
        AgentContextAvailability::Stale
    } else if record.request.status.is_terminal() {
        AgentContextAvailability::Terminal
    } else {
        AgentContextAvailability::Active
    }
}

fn effective_health(record: &AssistBrokerRecord) -> PluginSessionHealth {
    if record.context.health.is_terminal() {
        record.context.health
    } else {
        record
            .plugin_state
            .as_ref()
            .map(|state| state.health)
            .unwrap_or(record.context.health)
    }
}

fn principal_matches(record: &AssistBrokerRecord, principal: &AgentPrincipal) -> bool {
    record
        .request
        .external_agent
        .as_ref()
        .is_none_or(|bound| bound == principal)
}

fn validate_principal(principal: &AgentPrincipal) -> Result<(), AgentContextProtocolError> {
    principal.validate().map_err(|_| {
        AgentContextProtocolError::invalid_request(
            "external principal requires valid client_id, task_id, and optional instance_id",
        )
    })
}

fn source_error(code: AgentContextDiscoveryIssueCode) -> AgentContextProtocolError {
    let message = match code {
        AgentContextDiscoveryIssueCode::UnsafeStore => {
            "context store failed ownership, permission, or symlink safety checks"
        }
        _ => "context store is unavailable",
    };
    AgentContextProtocolError::new(AgentContextErrorCode::StoreUnavailable, message)
}

fn safe_record_metadata(path: &Path, root_metadata: Option<&fs::Metadata>) -> bool {
    fs::symlink_metadata(path).is_ok_and(|metadata| {
        !metadata.file_type().is_symlink()
            && metadata.is_file()
            && metadata.len() <= MAX_AGENT_CONTEXT_RECORD_BYTES
            && private_permissions(&metadata, false)
            && root_metadata.is_some_and(|root| same_owner(&metadata, root))
    })
}

#[cfg(unix)]
fn same_owner(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;

    left.uid() == right.uid()
}

#[cfg(not(unix))]
fn same_owner(_left: &fs::Metadata, _right: &fs::Metadata) -> bool {
    true
}

#[cfg(unix)]
fn private_permissions(metadata: &fs::Metadata, directory: bool) -> bool {
    use std::os::unix::fs::PermissionsExt;

    let mode = metadata.permissions().mode() & 0o777;
    mode & 0o077 == 0 && (!directory || mode & 0o700 == 0o700)
}

#[cfg(not(unix))]
fn private_permissions(_metadata: &fs::Metadata, _directory: bool) -> bool {
    true
}

fn valid_identifier(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

fn valid_text_component(value: &str, max_bytes: usize) -> bool {
    !value.trim().is_empty() && value.len() <= max_bytes && !value.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use serde_json::json;
    use uuid::Uuid;

    use crate::assist::{
        AssistBrokerPolicy, AssistBrokerStore, AssistContextPolicy, AssistRequest,
        AssistSessionBinding,
    };
    use crate::capability::{ActorRef, ActorType};
    use crate::session::PluginSessionPurpose;

    use super::*;

    fn principal(task_id: &str) -> AgentPrincipal {
        AgentPrincipal {
            client_id: "agent-cli".into(),
            task_id: task_id.into(),
            instance_id: Some("instance-1".into()),
        }
    }

    fn record_parts(
        plugin_id: &str,
        context_id: &str,
        bound: Option<AgentPrincipal>,
        now: DateTime<Utc>,
    ) -> (AssistRequest, AssistContextSnapshot) {
        let binding = AssistSessionBinding {
            plugin_id: plugin_id.into(),
            session_id: format!("{plugin_id}-session"),
            generation: 3,
            owner_id: format!("{plugin_id} TUI owner"),
            purpose: PluginSessionPurpose::InfrastructureClient,
            profile_ref: None,
        };
        let mut request = AssistRequest::new_context_share(
            context_id.into(),
            format!("{plugin_id} safe context"),
            binding.clone(),
            ActorRef {
                id: format!("{plugin_id}-tui"),
                actor_type: ActorType::Human,
            },
            bound,
            AssistContextPolicy::default(),
            now,
            now + Duration::minutes(10),
        )
        .unwrap();
        request.transition_to(AssistRequestStatus::Pending).unwrap();
        let context = AssistContextSnapshot {
            binding,
            captured_at: now,
            mode: "resources".into(),
            health: PluginSessionHealth::Ready,
            terminal: None,
            visible_screen: None,
            transcript_tail: None,
            status_line: Some(
                AssistBoundedText::capture("safe status", 1024, RedactionStatus::Applied).unwrap(),
            ),
            withheld_fields: Vec::new(),
            metadata: json!({"selection": "safe-label"}),
            redaction: RedactionStatus::Applied,
        };
        (request, context)
    }

    fn store_root(plugin_id: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "voidb-external-context-{plugin_id}-{}",
            Uuid::new_v4()
        ))
    }

    fn write_record(
        root: &Path,
        plugin_id: &str,
        context_id: &str,
        bound: Option<AgentPrincipal>,
        now: DateTime<Utc>,
    ) {
        let store = AssistBrokerStore::new(root.to_path_buf(), AssistBrokerPolicy::non_pty())
            .expect("store");
        let (request, context) = record_parts(plugin_id, context_id, bound, now);
        store.share(request, context, None).expect("share");
    }

    fn capability_operation(action: &str) -> AssistAction {
        AssistAction::CapabilityCall {
            capability_id: "docker.container_action".into(),
            input_summary: json!({
                "action": action,
                "target_id": "container-1",
                "target_label": "api"
            }),
            rationale: "Use the existing Docker review plan.".into(),
            risk: crate::assist::AssistActionRisk::Destructive,
            target: AssistActionTarget::Capability {
                capability_id: "docker.container_action".into(),
            },
        }
    }

    fn operation_input(id: &str, action: &str) -> AgentContextOperationInput {
        AgentContextOperationInput {
            operation_request_id: id.into(),
            summary: format!("Review Docker {action}."),
            note: Some("Bounded fixture operation.".into()),
            operations: vec![capability_operation(action)],
        }
    }

    #[test]
    fn contract_has_stable_commands_and_exit_codes() {
        assert_eq!(AgentContextCommand::Operation.as_str(), "operation");
        assert_eq!(AgentContextErrorCode::InvalidRequest.exit_code(), 2);
        assert_eq!(AgentContextErrorCode::PrincipalMismatch.exit_code(), 4);
        assert_eq!(AgentContextErrorCode::Internal.exit_code(), 70);
        let reference = AgentContextRef::new("docker", "context:docker:1:1", 2).unwrap();
        assert_eq!(reference.generation, 2);
        assert!(AgentContextRef::new("docker", "bad/id", 2).is_err());
        assert!(AgentContextRef::new("docker", "context:docker:1:1", 0).is_err());
    }

    #[test]
    fn catalog_lists_bound_and_unbound_records_without_leaking_other_principals() {
        let now = Utc::now();
        let root = store_root("docker");
        write_record(
            &root,
            "docker",
            "context:docker:1:1",
            Some(principal("task-a")),
            now,
        );
        write_record(
            &root,
            "docker",
            "context:docker:1:2",
            Some(principal("task-b")),
            now,
        );
        write_record(&root, "docker", "context:docker:1:3", None, now);
        let catalog =
            AgentContextStoreCatalog::new(vec![AgentContextStoreSource::new("docker", &root)]);

        let result = catalog
            .list_at(&principal("task-a"), None, now + Duration::seconds(1))
            .unwrap();
        assert_eq!(result.contexts.len(), 2);
        assert!(
            result
                .contexts
                .iter()
                .all(|item| item.context.context_id != "context:docker:1:2")
        );
        assert_eq!(
            result
                .diagnostics
                .iter()
                .find(|item| item.code == AgentContextDiscoveryIssueCode::PrincipalMismatch)
                .map(|item| item.count),
            Some(1)
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn show_enforces_generation_principal_expiry_and_stale_health() {
        let now = Utc::now();
        let root = store_root("jenkins");
        write_record(
            &root,
            "jenkins",
            "context:jenkins:1:1",
            Some(principal("task-a")),
            now,
        );
        let catalog =
            AgentContextStoreCatalog::new(vec![AgentContextStoreSource::new("jenkins", &root)]);
        let reference = AgentContextRef::new("jenkins", "context:jenkins:1:1", 3).unwrap();
        let detail = catalog
            .show_at(&principal("task-a"), &reference, now + Duration::seconds(1))
            .unwrap();
        assert_eq!(
            detail.context.summary.availability,
            AgentContextAvailability::Active
        );
        assert!(detail.context.request.external_agent_fingerprint.is_some());

        let wrong_generation = AgentContextRef {
            generation: 4,
            ..reference.clone()
        };
        assert_eq!(
            catalog
                .show_at(&principal("task-a"), &wrong_generation, now)
                .unwrap_err()
                .code,
            AgentContextErrorCode::Stale
        );
        assert_eq!(
            catalog
                .show_at(&principal("task-b"), &reference, now)
                .unwrap_err()
                .code,
            AgentContextErrorCode::PrincipalMismatch
        );
        assert_eq!(
            catalog
                .show_at(&principal("task-b"), &wrong_generation, now)
                .unwrap_err()
                .code,
            AgentContextErrorCode::PrincipalMismatch
        );
        assert_eq!(
            catalog
                .show_at(
                    &principal("task-a"),
                    &reference,
                    now + Duration::minutes(11)
                )
                .unwrap_err()
                .code,
            AgentContextErrorCode::Expired
        );

        let path = root.join(format!(
            "{}.json",
            safe_assist_request_filename("context:jenkins:1:1")
        ));
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["context"]["health"] = json!("stale");
        value["plugin_state"] = json!({
            "mode": "resources",
            "health": "ready",
            "status": "owner last reported ready",
            "updated_at": now,
            "metadata": null,
            "redaction": "applied"
        });
        fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert_eq!(
            catalog
                .show_at(&principal("task-a"), &reference, now + Duration::seconds(1))
                .unwrap_err()
                .code,
            AgentContextErrorCode::Stale
        );
        let stale_list = catalog
            .list_at(&principal("task-a"), None, now + Duration::seconds(1))
            .unwrap();
        assert_eq!(
            stale_list.contexts[0].availability,
            AgentContextAvailability::Stale
        );
        assert!(stale_list.contexts[0].label.is_none());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn owner_lease_marks_a_crashed_tui_stale_without_waiting_for_ttl() {
        let now = Utc::now();
        let root = store_root("docker");
        let store = AssistBrokerStore::new(root.clone(), AssistBrokerPolicy::non_pty()).unwrap();
        let (request, context) = record_parts(
            "docker",
            "context:docker:leased:1",
            Some(principal("task-a")),
            now,
        );
        let (_, owner_lease) = store
            .share_with_owner_lease(request, context, None)
            .unwrap();
        let catalog =
            AgentContextStoreCatalog::new(vec![AgentContextStoreSource::new("docker", &root)]);
        let reference = AgentContextRef::new("docker", "context:docker:leased:1", 3).unwrap();

        let active = catalog
            .list_at(&principal("task-a"), None, now + Duration::seconds(1))
            .unwrap();
        assert_eq!(
            active.contexts[0].availability,
            AgentContextAvailability::Active
        );

        drop(owner_lease);
        let stale = catalog
            .list_at(&principal("task-a"), None, now + Duration::seconds(2))
            .unwrap();
        assert_eq!(
            stale.contexts[0].availability,
            AgentContextAvailability::Stale
        );
        let error = catalog
            .show_at(&principal("task-a"), &reference, now + Duration::seconds(2))
            .unwrap_err();
        assert_eq!(error.code, AgentContextErrorCode::Stale);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn corrupt_and_incompatible_records_do_not_abort_listing() {
        let now = Utc::now();
        let root = store_root("kubernetes");
        write_record(&root, "kubernetes", "context:kubernetes:1:1", None, now);
        let corrupt = root.join("corrupt.json");
        fs::write(&corrupt, b"not-json").unwrap();
        let incompatible = root.join("incompatible.json");
        fs::write(
            &incompatible,
            br#"{"version":99,"request":{"id":"context:kubernetes:old:1"}}"#,
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&corrupt, fs::Permissions::from_mode(0o600)).unwrap();
            fs::set_permissions(&incompatible, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let catalog =
            AgentContextStoreCatalog::new(vec![AgentContextStoreSource::new("kubernetes", &root)]);

        let result = catalog.list_at(&principal("task-a"), None, now).unwrap();
        assert_eq!(result.contexts.len(), 1);
        assert!(
            result
                .diagnostics
                .iter()
                .any(|item| item.code == AgentContextDiscoveryIssueCode::CorruptRecord)
        );
        assert!(
            result
                .diagnostics
                .iter()
                .any(|item| item.code == AgentContextDiscoveryIssueCode::IncompatibleVersion)
        );
        let reference = AgentContextRef::new("kubernetes", "context:kubernetes:old:1", 1).unwrap();
        assert_eq!(
            catalog
                .show_at(&principal("task-a"), &reference, now)
                .unwrap_err()
                .code,
            AgentContextErrorCode::Incompatible
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn ssh_store_v1_terminal_state_projects_through_generic_show() {
        let now = Utc::now();
        let root = store_root("ssh");
        write_record(&root, "ssh", "context:ssh:1:1", None, now);
        let path = root.join(format!(
            "{}.json",
            safe_assist_request_filename("context:ssh:1:1")
        ));
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["terminal_state"] = json!({
            "mode": "terminal",
            "health": "ready",
            "status": "shared",
            "updated_at": now,
            "redaction": "applied"
        });
        fs::write(&path, serde_json::to_vec_pretty(&value).unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let catalog =
            AgentContextStoreCatalog::new(vec![AgentContextStoreSource::new("ssh", &root)]);
        let reference = AgentContextRef::new("ssh", "context:ssh:1:1", 3).unwrap();
        let shown = catalog
            .show_at(&principal("task-a"), &reference, now + Duration::seconds(1))
            .unwrap();
        let state = shown
            .context
            .plugin_state
            .expect("SSH terminal state alias");
        assert_eq!(state.mode, "terminal");
        assert_eq!(state.status, "shared");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn operation_binds_principal_and_retries_idempotently_but_rejects_substitution() {
        let now = Utc::now();
        let root = store_root("docker-operation");
        let context_id = "context:docker:operation:1";
        write_record(&root, "docker", context_id, None, now);
        let catalog =
            AgentContextStoreCatalog::new(vec![AgentContextStoreSource::new("docker", &root)]);
        let reference = AgentContextRef::new("docker", context_id, 3).unwrap();
        let input = operation_input("operation:docker:1", "stop");

        let created = catalog
            .operation_at(
                &principal("task-a"),
                &reference,
                input.clone(),
                now + Duration::seconds(1),
            )
            .unwrap();
        assert!(created.created);
        let retried = catalog
            .operation_at(
                &principal("task-a"),
                &reference,
                input,
                now + Duration::seconds(2),
            )
            .unwrap();
        assert!(!retried.created);
        assert_eq!(retried.created_at, created.created_at);

        let replay = catalog
            .operation_at(
                &principal("task-a"),
                &reference,
                operation_input("operation:docker:1", "restart"),
                now + Duration::seconds(3),
            )
            .unwrap_err();
        assert_eq!(replay.code, AgentContextErrorCode::Replay);
        assert_eq!(
            catalog
                .status_at(&principal("task-b"), &reference, now + Duration::seconds(3))
                .unwrap_err()
                .code,
            AgentContextErrorCode::PrincipalMismatch
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn non_pty_operation_rejects_partial_or_reordered_multi_action_requests() {
        let now = Utc::now();
        let root = store_root("docker-multi-operation");
        let context_id = "context:docker:operation:multi";
        write_record(&root, "docker", context_id, None, now);
        let catalog =
            AgentContextStoreCatalog::new(vec![AgentContextStoreSource::new("docker", &root)]);
        let reference = AgentContextRef::new("docker", context_id, 3).unwrap();
        let mut input = operation_input("operation:docker:multi", "stop");
        input.operations.push(capability_operation("restart"));
        input.operations.reverse();

        let error = catalog
            .operation_at(
                &principal("task-a"),
                &reference,
                input,
                now + Duration::seconds(1),
            )
            .unwrap_err();
        assert_eq!(error.code, AgentContextErrorCode::InvalidRequest);
        let mut secret = operation_input("operation:docker:secret", "stop");
        let AssistAction::CapabilityCall { input_summary, .. } = &mut secret.operations[0] else {
            unreachable!("fixture uses a capability call")
        };
        *input_summary = json!({
            "action": "stop",
            "target_id": "container-1",
            "token": "must-not-enter-the-context-store"
        });
        assert_eq!(
            catalog
                .operation_at(
                    &principal("task-a"),
                    &reference,
                    secret,
                    now + Duration::seconds(1),
                )
                .unwrap_err()
                .code,
            AgentContextErrorCode::InvalidRequest
        );
        let shown = catalog
            .show_at(&principal("task-a"), &reference, now + Duration::seconds(1))
            .unwrap();
        assert_eq!(shown.context.summary.operation_request_count, 0);
        assert!(!shown.context.summary.principal_bound);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn indexed_denial_is_idempotent_and_status_is_complete() {
        let now = Utc::now();
        let root = store_root("docker-denial");
        let context_id = "context:docker:denial:1";
        write_record(&root, "docker", context_id, None, now);
        let catalog =
            AgentContextStoreCatalog::new(vec![AgentContextStoreSource::new("docker", &root)]);
        let reference = AgentContextRef::new("docker", context_id, 3).unwrap();
        catalog
            .operation_at(
                &principal("task-a"),
                &reference,
                operation_input("operation:docker:deny", "stop"),
                now + Duration::seconds(1),
            )
            .unwrap();
        let pending = catalog
            .status_at(&principal("task-a"), &reference, now + Duration::seconds(2))
            .unwrap();
        assert!(!pending.complete);
        assert_eq!(pending.operation_requests[0].operations[0].decision, None);

        let denied = catalog
            .deny_at(
                &principal("task-a"),
                &reference,
                "operation:docker:deny",
                0,
                "No maintenance window.",
                now + Duration::seconds(3),
            )
            .unwrap();
        assert!(denied.created);
        assert_eq!(denied.decision, AgentContextOperationDecision::Denied);
        let retried = catalog
            .deny_at(
                &principal("task-a"),
                &reference,
                "operation:docker:deny",
                0,
                "No maintenance window.",
                now + Duration::seconds(4),
            )
            .unwrap();
        assert!(!retried.created);
        assert_eq!(
            catalog
                .deny_at(
                    &principal("task-a"),
                    &reference,
                    "operation:docker:deny",
                    0,
                    "Changed replay reason.",
                    now + Duration::seconds(5),
                )
                .unwrap_err()
                .code,
            AgentContextErrorCode::Replay
        );
        let complete = catalog
            .status_at(&principal("task-a"), &reference, now + Duration::seconds(5))
            .unwrap();
        assert!(complete.complete);
        assert_eq!(
            complete.operation_requests[0].operations[0].decision,
            Some(AgentContextOperationDecision::Denied)
        );
        let waited = catalog
            .wait(
                &principal("task-a"),
                &reference,
                StdDuration::from_millis(50),
                StdDuration::from_millis(5),
            )
            .unwrap();
        assert!(!waited.changed);
        assert_eq!(waited.waited_ms, 0);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn local_allowed_decision_projects_by_exact_operation_index() {
        let now = Utc::now();
        let root = store_root("kubernetes-allow");
        let context_id = "context:kubernetes:allow:1";
        write_record(&root, "kubernetes", context_id, None, now);
        let catalog =
            AgentContextStoreCatalog::new(vec![AgentContextStoreSource::new("kubernetes", &root)]);
        let reference = AgentContextRef::new("kubernetes", context_id, 3).unwrap();
        let mut input = operation_input("operation:kubernetes:allow", "stop");
        input.operations = vec![AssistAction::CapabilityCall {
            capability_id: "kubernetes.delete".into(),
            input_summary: json!({
                "action": "delete",
                "resource_type": "pod",
                "namespace": "default",
                "target_name": "api-0"
            }),
            rationale: "Use the existing Kubernetes delete review plan.".into(),
            risk: crate::assist::AssistActionRisk::Destructive,
            target: AssistActionTarget::Capability {
                capability_id: "kubernetes.delete".into(),
            },
        }];
        catalog
            .operation_at(
                &principal("task-a"),
                &reference,
                input,
                now + Duration::seconds(1),
            )
            .unwrap();
        let store = AssistBrokerStore::new(root.clone(), AssistBrokerPolicy::non_pty()).unwrap();
        let expires_at = store.detail(context_id).unwrap().record.request.expires_at;
        store
            .confirm_operation(
                context_id,
                AssistActionConfirmation {
                    request_id: context_id.into(),
                    response_id: "operation:kubernetes:allow".into(),
                    action_index: 0,
                    target: "capability:kubernetes.delete".into(),
                    uses_current_pty: false,
                    generation: 3,
                    confirmed_at: now + Duration::seconds(2),
                    expires_at: Some(expires_at),
                    command_summary: None,
                    capability_id: Some("kubernetes.delete".into()),
                    status: "staged_for_plan_review".into(),
                    note: "Operator staged the bounded local plan.".into(),
                    redaction: RedactionStatus::Applied,
                },
            )
            .unwrap();

        let status = catalog
            .status_at(&principal("task-a"), &reference, now + Duration::seconds(3))
            .unwrap();
        assert!(status.complete);
        assert_eq!(
            status.operation_requests[0].operations[0].decision,
            Some(AgentContextOperationDecision::Allowed)
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn wait_observes_cross_process_decision_without_blocking_the_owner() {
        let now = Utc::now();
        let root = store_root("docker-wait");
        let context_id = "context:docker:wait:1";
        write_record(&root, "docker", context_id, None, now);
        let catalog =
            AgentContextStoreCatalog::new(vec![AgentContextStoreSource::new("docker", &root)]);
        let reference = AgentContextRef::new("docker", context_id, 3).unwrap();
        catalog
            .operation(
                &principal("task-a"),
                &reference,
                operation_input("operation:docker:wait", "stop"),
            )
            .unwrap();
        let deciding_catalog = catalog.clone();
        let deciding_reference = reference.clone();
        let decision = thread::spawn(move || {
            thread::sleep(StdDuration::from_millis(25));
            deciding_catalog
                .deny(
                    &principal("task-a"),
                    &deciding_reference,
                    "operation:docker:wait",
                    0,
                    "Automated task was cancelled.",
                )
                .unwrap();
        });
        let waited = catalog
            .wait(
                &principal("task-a"),
                &reference,
                StdDuration::from_secs(1),
                StdDuration::from_millis(5),
            )
            .unwrap();
        decision.join().unwrap();
        assert!(waited.changed);
        assert!(waited.status.complete);
        assert!(waited.waited_ms >= 5);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn wait_returns_stable_timeout_without_mutating_pending_review() {
        let now = Utc::now();
        let root = store_root("docker-timeout");
        let context_id = "context:docker:wait:timeout";
        write_record(&root, "docker", context_id, None, now);
        let catalog =
            AgentContextStoreCatalog::new(vec![AgentContextStoreSource::new("docker", &root)]);
        let reference = AgentContextRef::new("docker", context_id, 3).unwrap();
        catalog
            .operation(
                &principal("task-a"),
                &reference,
                operation_input("operation:docker:timeout", "stop"),
            )
            .unwrap();

        let error = catalog
            .wait(
                &principal("task-a"),
                &reference,
                StdDuration::from_millis(15),
                StdDuration::from_millis(5),
            )
            .unwrap_err();
        assert_eq!(error.code, AgentContextErrorCode::Timeout);
        assert!(error.retryable);
        assert!(
            !catalog
                .status(&principal("task-a"), &reference)
                .unwrap()
                .complete
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn operation_and_decision_reject_stale_generation() {
        let now = Utc::now();
        let root = store_root("jenkins-stale-operation");
        let context_id = "context:jenkins:operation:stale";
        write_record(&root, "jenkins", context_id, None, now);
        let catalog =
            AgentContextStoreCatalog::new(vec![AgentContextStoreSource::new("jenkins", &root)]);
        let stale = AgentContextRef::new("jenkins", context_id, 4).unwrap();
        assert_eq!(
            catalog
                .operation_at(
                    &principal("task-a"),
                    &stale,
                    operation_input("operation:jenkins:stale", "stop"),
                    now + Duration::seconds(1),
                )
                .unwrap_err()
                .code,
            AgentContextErrorCode::Stale
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn shared_store_protects_directory_and_record_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let now = Utc::now();
        let root = store_root("docker-permissions");
        write_record(&root, "docker", "context:docker:1:1", None, now);
        let path = root.join(format!(
            "{}.json",
            safe_assist_request_filename("context:docker:1:1")
        ));
        assert_eq!(
            fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn catalog_rejects_world_readable_and_symlinked_stores() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let now = Utc::now();
        let root = store_root("docker");
        write_record(&root, "docker", "context:docker:1:1", None, now);
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        let catalog =
            AgentContextStoreCatalog::new(vec![AgentContextStoreSource::new("docker", &root)]);
        let result = catalog.list_at(&principal("task-a"), None, now).unwrap();
        assert!(result.contexts.is_empty());
        assert_eq!(
            result.diagnostics[0].code,
            AgentContextDiscoveryIssueCode::UnsafeStore
        );

        let link = store_root("docker-link");
        symlink(&root, &link).unwrap();
        let linked =
            AgentContextStoreCatalog::new(vec![AgentContextStoreSource::new("docker", &link)]);
        assert_eq!(
            linked
                .list_at(&principal("task-a"), None, now)
                .unwrap()
                .diagnostics[0]
                .code,
            AgentContextDiscoveryIssueCode::UnsafeStore
        );
        fs::remove_file(link).unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}
