//! Local audit event storage.
//!
//! The first audit backend is intentionally small: newline-delimited JSON on
//! the local machine, with redacted metadata supplied by callers. The storage
//! layer never accepts plaintext credential material intentionally; it stores
//! structured summaries, stable references, and structured errors.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::capability::{
    ActorRef, ActorType, CapabilityError, CapabilityErrorCategory, ConnectionProfileRef,
    CredentialRef, PolicyDecisionOutcome, RedactionStatus,
};
use crate::{InvocationStatus, VoidbError};

pub type AuditEventId = String;

pub const DEFAULT_AUDIT_MAX_FILE_BYTES: u64 = 5 * 1024 * 1024;
pub const DEFAULT_AUDIT_MAX_ROTATED_FILES: usize = 5;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: AuditEventId,
    pub timestamp: DateTime<Utc>,
    pub actor: ActorRef,
    pub operation: AuditOperation,
    pub status: AuditEventStatus,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invocation_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<ConnectionProfileRef>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugin_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_id: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,

    #[serde(default)]
    pub credential_refs: Vec<CredentialRef>,

    #[serde(default)]
    pub metadata: Value,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<CapabilityError>,

    #[serde(default)]
    pub redaction: RedactionStatus,
}

impl AuditEvent {
    pub fn new(operation: AuditOperation, status: AuditEventStatus) -> Self {
        Self {
            id: next_audit_event_id(),
            timestamp: Utc::now(),
            actor: local_cli_actor(),
            operation,
            status,
            invocation_id: None,
            grant_id: None,
            profile: None,
            plugin_id: None,
            capability_id: None,
            duration_ms: None,
            credential_refs: Vec::new(),
            metadata: Value::Null,
            error: None,
            redaction: RedactionStatus::NotRequired,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOperation {
    ProfileList,
    ProfileShow,
    ProfileTest,
    ProfileMigrate,
    CapabilityInvoke,
    CredentialGrantIssued,
    CredentialGrantUsed,
    CredentialGrantReleased,
    SessionOpen,
    SessionCall,
    SessionStatus,
    SessionList,
    SessionRenew,
    SessionCancel,
    SessionClose,
    CredentialSyncPush,
    CredentialSyncPull,
    CredentialSyncUnavailable,
    CredentialSyncReenroll,
    CredentialSyncMappingMigrated,
    SyncObjectConflict,
    SyncObjectForcePush,
    SyncObjectKeepRemote,
    SyncObjectMerge,
    SyncObjectTombstone,
    CredentialSyncReenrollHandoff,
    TeamShareInviteCreated,
    TeamShareInviteAccepted,
    TeamShareImportPlanned,
    TeamShareImportBlocked,
    TeamShareAccessRevoked,
    TeamShareCredentialReenrollmentRequired,
    AssistCreate,
    AssistPreview,
    AssistSend,
    AssistRespond,
    AssistInspect,
    AssistPropose,
    AssistApproveControl,
    AssistRevoke,
    AssistCancel,
    AssistExpire,
    AssistClose,
}

impl std::str::FromStr for AuditOperation {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "profile_list" => Ok(Self::ProfileList),
            "profile_show" | "profile_inspect" => Ok(Self::ProfileShow),
            "profile_test" => Ok(Self::ProfileTest),
            "profile_migrate" => Ok(Self::ProfileMigrate),
            "capability_invoke" | "invoke" => Ok(Self::CapabilityInvoke),
            "credential_grant_issued" => Ok(Self::CredentialGrantIssued),
            "credential_grant_used" => Ok(Self::CredentialGrantUsed),
            "credential_grant_released" => Ok(Self::CredentialGrantReleased),
            "session_open" | "session.open" => Ok(Self::SessionOpen),
            "session_call" | "session.call" => Ok(Self::SessionCall),
            "session_status" | "session.status" => Ok(Self::SessionStatus),
            "session_list" | "session.list" => Ok(Self::SessionList),
            "session_renew" | "session.renew" => Ok(Self::SessionRenew),
            "session_cancel" | "session.cancel" => Ok(Self::SessionCancel),
            "session_close" | "session.close" => Ok(Self::SessionClose),
            "credential_sync_push" => Ok(Self::CredentialSyncPush),
            "credential_sync_pull" => Ok(Self::CredentialSyncPull),
            "credential_sync_unavailable" => Ok(Self::CredentialSyncUnavailable),
            "credential_sync_reenroll" => Ok(Self::CredentialSyncReenroll),
            "credential_sync_mapping_migrated" => Ok(Self::CredentialSyncMappingMigrated),
            "sync_object_conflict" | "sync.object_conflict" => Ok(Self::SyncObjectConflict),
            "sync_object_force_push" | "sync.object_force_push" => Ok(Self::SyncObjectForcePush),
            "sync_object_keep_remote" | "sync.object_keep_remote" => Ok(Self::SyncObjectKeepRemote),
            "sync_object_merge" | "sync.object_merge" => Ok(Self::SyncObjectMerge),
            "sync_object_tombstone" | "sync.object_tombstone" => Ok(Self::SyncObjectTombstone),
            "credential_sync_reenroll_handoff" | "credential.sync_reenroll_handoff" => {
                Ok(Self::CredentialSyncReenrollHandoff)
            }
            "team_share_invite_created" | "team_share.invite_created" => {
                Ok(Self::TeamShareInviteCreated)
            }
            "team_share_invite_accepted" | "team_share.invite_accepted" => {
                Ok(Self::TeamShareInviteAccepted)
            }
            "team_share_import_planned" | "team_share.import_planned" => {
                Ok(Self::TeamShareImportPlanned)
            }
            "team_share_import_blocked" | "team_share.import_blocked" => {
                Ok(Self::TeamShareImportBlocked)
            }
            "team_share_access_revoked" | "team_share.access_revoked" => {
                Ok(Self::TeamShareAccessRevoked)
            }
            "team_share_credential_reenrollment_required"
            | "team_share.credential_reenrollment_required" => {
                Ok(Self::TeamShareCredentialReenrollmentRequired)
            }
            "assist_create" | "assist.create" => Ok(Self::AssistCreate),
            "assist_preview" | "assist.preview" => Ok(Self::AssistPreview),
            "assist_send" | "assist.send" => Ok(Self::AssistSend),
            "assist_respond" | "assist.respond" => Ok(Self::AssistRespond),
            "assist_inspect" | "assist.inspect" => Ok(Self::AssistInspect),
            "assist_propose" | "assist.propose" => Ok(Self::AssistPropose),
            "assist_approve_control" | "assist.approve_control" => {
                Ok(Self::AssistApproveControl)
            }
            "assist_revoke" | "assist.revoke" => Ok(Self::AssistRevoke),
            "assist_cancel" | "assist.cancel" => Ok(Self::AssistCancel),
            "assist_expire" | "assist.expire" => Ok(Self::AssistExpire),
            "assist_close" | "assist.close" => Ok(Self::AssistClose),
            other => Err(format!("Unsupported audit operation: {}", other)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventStatus {
    Succeeded,
    Failed,
    Blocked,
    TimedOut,
    Cancelled,
}

impl From<InvocationStatus> for AuditEventStatus {
    fn from(status: InvocationStatus) -> Self {
        match status {
            InvocationStatus::Accepted
            | InvocationStatus::Running
            | InvocationStatus::Succeeded => Self::Succeeded,
            InvocationStatus::Failed => Self::Failed,
            InvocationStatus::Cancelled => Self::Cancelled,
            InvocationStatus::TimedOut => Self::TimedOut,
        }
    }
}

impl std::str::FromStr for AuditEventStatus {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "succeeded" => Ok(Self::Succeeded),
            "failed" => Ok(Self::Failed),
            "blocked" => Ok(Self::Blocked),
            "timed_out" => Ok(Self::TimedOut),
            "cancelled" => Ok(Self::Cancelled),
            other => Err(format!("Unsupported audit status: {}", other)),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditQuery {
    pub operation: Option<AuditOperation>,
    pub status: Option<AuditEventStatus>,
    pub actor_id: Option<String>,
    pub actor_type: Option<ActorType>,
    pub invocation_id: Option<String>,
    pub grant_id: Option<String>,
    pub credential_ref_id: Option<String>,
    pub profile: Option<String>,
    pub plugin_id: Option<String>,
    pub capability_id: Option<String>,
    pub policy_outcome: Option<PolicyDecisionOutcome>,
    pub policy_reason_code: Option<String>,
    pub error_category: Option<CapabilityErrorCategory>,
    pub error_code: Option<String>,
    pub redaction: Option<RedactionStatus>,
    pub since: Option<DateTime<Utc>>,
    pub until: Option<DateTime<Utc>>,
    pub limit: Option<usize>,
    pub page_token: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditRetentionPolicy {
    pub max_file_bytes: u64,
    pub max_rotated_files: usize,
}

impl Default for AuditRetentionPolicy {
    fn default() -> Self {
        Self {
            max_file_bytes: DEFAULT_AUDIT_MAX_FILE_BYTES,
            max_rotated_files: DEFAULT_AUDIT_MAX_ROTATED_FILES,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AuditQueryResult {
    pub events: Vec<AuditEvent>,
    pub page: AuditQueryPage,
    pub source_files: Vec<AuditSourceFile>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditQueryPage {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_page_token: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditSourceFile {
    pub path: PathBuf,
    pub bytes: u64,
}

pub trait AuditEventStore {
    fn append(&self, event: &AuditEvent) -> Result<(), VoidbError>;
    fn query(&self, query: &AuditQuery) -> Result<Vec<AuditEvent>, VoidbError>;
}

#[derive(Debug, Clone)]
pub struct LocalAuditStore {
    path: PathBuf,
    retention: AuditRetentionPolicy,
}

impl LocalAuditStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            retention: AuditRetentionPolicy::default(),
        }
    }

    pub fn with_retention(path: impl Into<PathBuf>, retention: AuditRetentionPolicy) -> Self {
        Self {
            path: path.into(),
            retention,
        }
    }

    pub fn default_path() -> Result<PathBuf, VoidbError> {
        if let Some(path) = std::env::var_os("VOIDB_AUDIT_PATH") {
            return Ok(PathBuf::from(path));
        }
        let data_dir = dirs::data_dir()
            .ok_or_else(|| VoidbError::Config("Cannot determine data directory".to_string()))?;
        Ok(data_dir.join("voidb").join("audit").join("events.jsonl"))
    }

    pub fn default_store() -> Result<Self, VoidbError> {
        Ok(Self::new(Self::default_path()?))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn retention(&self) -> &AuditRetentionPolicy {
        &self.retention
    }

    pub fn query_page(&self, query: &AuditQuery) -> Result<AuditQueryResult, VoidbError> {
        let source_files = self.audit_source_files()?;
        let mut events = Vec::new();
        for source in &source_files {
            let content = fs::read_to_string(&source.path)?;
            for (line_index, line) in content.lines().enumerate() {
                if line.trim().is_empty() {
                    continue;
                }
                let event = serde_json::from_str::<AuditEvent>(line).map_err(|error| {
                    VoidbError::Other(format!(
                        "Cannot parse audit event in {} at line {}: {}",
                        source.path.display(),
                        line_index + 1,
                        error
                    ))
                })?;
                if audit_event_matches_query(&event, query) {
                    events.push(event);
                }
            }
        }

        events.sort_by(|left, right| {
            right
                .timestamp
                .cmp(&left.timestamp)
                .then_with(|| right.id.cmp(&left.id))
        });

        let offset = parse_audit_page_token(query.page_token.as_deref())?;
        let limit = query.limit.unwrap_or(events.len());
        let total = events.len();
        let selected = events
            .into_iter()
            .skip(offset)
            .take(limit)
            .collect::<Vec<_>>();
        let next_offset = offset.saturating_add(selected.len());
        let next_page_token = if limit > 0 && next_offset < total {
            Some(format!("offset:{next_offset}"))
        } else {
            None
        };

        Ok(AuditQueryResult {
            events: selected,
            page: AuditQueryPage { next_page_token },
            source_files,
        })
    }

    fn audit_source_files(&self) -> Result<Vec<AuditSourceFile>, VoidbError> {
        let mut files = Vec::new();
        push_audit_source_file(&mut files, self.path.clone())?;
        for index in 1..=self.retention.max_rotated_files {
            push_audit_source_file(&mut files, rotated_audit_path(&self.path, index))?;
        }
        Ok(files)
    }

    fn rotate_if_needed(&self, incoming_len: u64) -> std::io::Result<()> {
        if self.retention.max_file_bytes == 0 || self.retention.max_rotated_files == 0 {
            return Ok(());
        }
        let current_len = match fs::metadata(&self.path) {
            Ok(metadata) => metadata.len(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        if current_len == 0
            || current_len.saturating_add(incoming_len).saturating_add(1)
                <= self.retention.max_file_bytes
        {
            return Ok(());
        }

        let oldest = rotated_audit_path(&self.path, self.retention.max_rotated_files);
        if oldest.exists() {
            fs::remove_file(oldest)?;
        }
        for index in (1..self.retention.max_rotated_files).rev() {
            let from = rotated_audit_path(&self.path, index);
            if from.exists() {
                fs::rename(from, rotated_audit_path(&self.path, index + 1))?;
            }
        }
        fs::rename(&self.path, rotated_audit_path(&self.path, 1))?;
        Ok(())
    }
}

impl AuditEventStore for LocalAuditStore {
    fn append(&self, event: &AuditEvent) -> Result<(), VoidbError> {
        let serialized = serde_json::to_string(event)
            .map_err(|error| VoidbError::Other(format!("Cannot serialize audit event: {error}")))?;
        self.rotate_if_needed(serialized.len() as u64)
            .map_err(|error| VoidbError::Io(std::io::Error::new(error.kind(), error)))?;
        append_private_line(&self.path, &serialized)
            .map_err(|error| VoidbError::Io(std::io::Error::new(error.kind(), error)))?;
        Ok(())
    }

    fn query(&self, query: &AuditQuery) -> Result<Vec<AuditEvent>, VoidbError> {
        self.query_page(query).map(|result| result.events)
    }
}

fn push_audit_source_file(
    files: &mut Vec<AuditSourceFile>,
    path: PathBuf,
) -> Result<(), VoidbError> {
    match fs::metadata(&path) {
        Ok(metadata) if metadata.is_file() => files.push(AuditSourceFile {
            path,
            bytes: metadata.len(),
        }),
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(VoidbError::Io(error)),
    }
    Ok(())
}

fn rotated_audit_path(path: &Path, index: usize) -> PathBuf {
    let mut rotated = path.as_os_str().to_os_string();
    rotated.push(format!(".{index}"));
    PathBuf::from(rotated)
}

fn parse_audit_page_token(token: Option<&str>) -> Result<usize, VoidbError> {
    let Some(token) = token.filter(|token| !token.is_empty()) else {
        return Ok(0);
    };
    let offset = token.strip_prefix("offset:").ok_or_else(|| {
        VoidbError::Other("Invalid audit page token; expected offset:<number>".into())
    })?;
    offset.parse::<usize>().map_err(|error| {
        VoidbError::Other(format!(
            "Invalid audit page token offset '{}': {}",
            offset, error
        ))
    })
}

pub fn local_cli_actor() -> ActorRef {
    ActorRef {
        id: "local-cli".into(),
        actor_type: ActorType::Human,
    }
}

pub fn audit_json_summary(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut fields = map.keys().cloned().collect::<Vec<_>>();
            fields.sort();
            json!({
                "kind": "object",
                "fields": fields,
                "field_count": fields.len(),
            })
        }
        Value::Array(items) => json!({
            "kind": "array",
            "length": items.len(),
        }),
        Value::String(_) => json!({ "kind": "string" }),
        Value::Number(_) => json!({ "kind": "number" }),
        Value::Bool(_) => json!({ "kind": "boolean" }),
        Value::Null => json!({ "kind": "null" }),
    }
}

fn audit_event_matches_query(event: &AuditEvent, query: &AuditQuery) -> bool {
    if query
        .operation
        .is_some_and(|operation| event.operation != operation)
    {
        return false;
    }
    if query.status.is_some_and(|status| event.status != status) {
        return false;
    }
    if let Some(actor_id) = &query.actor_id
        && event.actor.id.as_str() != actor_id
    {
        return false;
    }
    if let Some(actor_type) = query.actor_type
        && event.actor.actor_type != actor_type
    {
        return false;
    }
    if let Some(invocation_id) = &query.invocation_id
        && event.invocation_id.as_deref() != Some(invocation_id)
    {
        return false;
    }
    if let Some(grant_id) = &query.grant_id
        && !audit_event_matches_grant(event, grant_id)
    {
        return false;
    }
    if let Some(credential_ref_id) = &query.credential_ref_id
        && !event
            .credential_refs
            .iter()
            .any(|credential_ref| credential_ref.id.as_str() == credential_ref_id)
    {
        return false;
    }
    if let Some(profile) = &query.profile
        && !audit_event_matches_profile(event, profile)
    {
        return false;
    }
    if let Some(plugin_id) = &query.plugin_id
        && event.plugin_id.as_ref() != Some(plugin_id)
    {
        return false;
    }
    if let Some(capability_id) = &query.capability_id
        && event.capability_id.as_ref() != Some(capability_id)
    {
        return false;
    }
    if let Some(policy_outcome) = query.policy_outcome
        && !audit_event_matches_policy_outcome(event, policy_outcome)
    {
        return false;
    }
    if let Some(policy_reason_code) = &query.policy_reason_code
        && !audit_event_matches_policy_reason_code(event, policy_reason_code)
    {
        return false;
    }
    if let Some(error_category) = query.error_category
        && event.error.as_ref().map(|error| error.category) != Some(error_category)
    {
        return false;
    }
    if let Some(error_code) = &query.error_code
        && event.error.as_ref().map(|error| error.code.as_str()) != Some(error_code.as_str())
    {
        return false;
    }
    if let Some(redaction) = query.redaction
        && event.redaction != redaction
    {
        return false;
    }
    if query.since.is_some_and(|since| event.timestamp < since) {
        return false;
    }
    if query.until.is_some_and(|until| event.timestamp > until) {
        return false;
    }
    true
}

fn audit_event_matches_grant(event: &AuditEvent, grant_id: &str) -> bool {
    event.grant_id.as_deref() == Some(grant_id)
        || event
            .metadata
            .get("grant_id")
            .and_then(Value::as_str)
            .is_some_and(|metadata_grant_id| metadata_grant_id == grant_id)
}

fn audit_event_matches_profile(event: &AuditEvent, profile: &str) -> bool {
    match &event.profile {
        Some(ConnectionProfileRef::Id(id)) => id == profile || format!("id:{id}") == profile,
        Some(ConnectionProfileRef::Name(name)) => {
            let requested = profile
                .strip_prefix("name:")
                .or_else(|| profile.strip_prefix("alias:"))
                .unwrap_or(profile);
            crate::profile_names_equal(name, requested)
        }
        None => false,
    }
}

fn audit_event_matches_policy_outcome(
    event: &AuditEvent,
    outcome: PolicyDecisionOutcome,
) -> bool {
    event
        .metadata
        .get("policy_decision")
        .and_then(|decision| decision.get("outcome"))
        .and_then(Value::as_str)
        .is_some_and(|value| value == policy_outcome_name(outcome))
}

fn audit_event_matches_policy_reason_code(event: &AuditEvent, reason_code: &str) -> bool {
    event
        .metadata
        .get("policy_decision")
        .and_then(|decision| decision.get("reason"))
        .and_then(|reason| reason.get("code"))
        .and_then(Value::as_str)
        .is_some_and(|value| value == reason_code)
}

fn policy_outcome_name(outcome: PolicyDecisionOutcome) -> &'static str {
    match outcome {
        PolicyDecisionOutcome::Allow => "allow",
        PolicyDecisionOutcome::Deny => "deny",
        PolicyDecisionOutcome::RequiresApproval => "requires_approval",
        PolicyDecisionOutcome::RequiresAcknowledgement => "requires_acknowledgement",
        PolicyDecisionOutcome::DryRunOnly => "dry_run_only",
    }
}

fn next_audit_event_id() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    format!("audit-{}-{nanos}", std::process::id())
}

#[cfg(unix)]
fn append_private_line(path: &Path, line: &str) -> std::io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)?;
    writeln!(file, "{line}")?;
    file.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn append_private_line(path: &Path, line: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    writeln!(file, "{line}")?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::{
        ActorType, CapabilityErrorCategory, CredentialClass, PolicyDecisionOutcome,
        RedactionStatus,
    };
    use chrono::TimeZone;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn summary_records_shape_without_values() {
        let summary = audit_json_summary(&json!({
            "password": "super-secret",
            "sql": "select * from users",
        }));
        let encoded = summary.to_string();

        assert_eq!(summary["kind"], "object");
        assert!(encoded.contains("password"));
        assert!(encoded.contains("sql"));
        assert!(!encoded.contains("super-secret"));
        assert!(!encoded.contains("select *"));
    }

    #[test]
    fn team_share_operations_parse_stable_aliases() {
        assert_eq!(
            "team_share_invite_created"
                .parse::<AuditOperation>()
                .expect("parse invite"),
            AuditOperation::TeamShareInviteCreated
        );
        assert_eq!(
            "team_share.import_blocked"
                .parse::<AuditOperation>()
                .expect("parse import blocked"),
            AuditOperation::TeamShareImportBlocked
        );
        assert_eq!(
            "team_share.credential_reenrollment_required"
                .parse::<AuditOperation>()
                .expect("parse reenrollment"),
            AuditOperation::TeamShareCredentialReenrollmentRequired
        );
    }

    #[test]
    fn session_operations_parse_stable_aliases() {
        assert_eq!(
            "session_open"
                .parse::<AuditOperation>()
                .expect("parse session open"),
            AuditOperation::SessionOpen
        );
        assert_eq!(
            "session.call"
                .parse::<AuditOperation>()
                .expect("parse session call"),
            AuditOperation::SessionCall
        );
        assert_eq!(
            "session_close"
                .parse::<AuditOperation>()
                .expect("parse session close"),
            AuditOperation::SessionClose
        );
    }

    #[test]
    fn assist_operations_parse_stable_aliases() {
        assert_eq!(
            "assist.create"
                .parse::<AuditOperation>()
                .expect("parse assist create"),
            AuditOperation::AssistCreate
        );
        assert_eq!(
            "assist_approve_control"
                .parse::<AuditOperation>()
                .expect("parse assist approve control"),
            AuditOperation::AssistApproveControl
        );
        assert_eq!(
            "assist.close"
                .parse::<AuditOperation>()
                .expect("parse assist close"),
            AuditOperation::AssistClose
        );
    }

    #[test]
    fn local_store_appends_and_queries_recent_events() {
        let temp = TempFile::new("events.jsonl");
        let store = LocalAuditStore::new(temp.path());
        let mut first = AuditEvent::new(AuditOperation::ProfileList, AuditEventStatus::Succeeded);
        first.profile = Some(ConnectionProfileRef::Name("prod".into()));
        first.plugin_id = Some("mysql".into());
        let mut second =
            AuditEvent::new(AuditOperation::CapabilityInvoke, AuditEventStatus::Failed);
        second.actor = ActorRef {
            id: "agent:test".into(),
            actor_type: ActorType::Agent,
        };
        second.plugin_id = Some("redis".into());
        second.capability_id = Some("set".into());
        second.metadata = json!({
            "policy_decision": {
                "outcome": "requires_acknowledgement",
                "reason": {
                    "code": "policy.destructive_denied_by_default"
                }
            }
        });
        second.error = Some(CapabilityError {
            category: CapabilityErrorCategory::TargetSystem,
            code: "redis.connect_failed".into(),
            message: "Target failed.".into(),
            details: Value::Null,
            target: None,
            retryable: false,
            redaction: RedactionStatus::Applied,
        });

        store.append(&first).expect("append first");
        store.append(&second).expect("append second");

        let redis_events = store
            .query(&AuditQuery {
                plugin_id: Some("redis".into()),
                ..AuditQuery::default()
            })
            .expect("query redis");
        assert_eq!(redis_events.len(), 1);
        assert_eq!(redis_events[0].capability_id.as_deref(), Some("set"));

        let policy_events = store
            .query(&AuditQuery {
                actor_id: Some("agent:test".into()),
                actor_type: Some(ActorType::Agent),
                policy_outcome: Some(PolicyDecisionOutcome::RequiresAcknowledgement),
                policy_reason_code: Some("policy.destructive_denied_by_default".into()),
                ..AuditQuery::default()
            })
            .expect("query policy events");
        assert_eq!(policy_events.len(), 1);
        assert_eq!(policy_events[0].actor.actor_type, ActorType::Agent);

        let limited = store
            .query(&AuditQuery {
                limit: Some(1),
                ..AuditQuery::default()
            })
            .expect("query limited");
        assert_eq!(limited.len(), 1);
    }

    #[test]
    fn local_store_rotates_and_queries_without_sensitive_values() {
        let temp = TempFile::new("rotating/events.jsonl");
        let store = LocalAuditStore::with_retention(
            temp.path(),
            AuditRetentionPolicy {
                max_file_bytes: 360,
                max_rotated_files: 2,
            },
        );

        for index in 0..3 {
            let mut event = AuditEvent::new(
                AuditOperation::CredentialGrantUsed,
                AuditEventStatus::Succeeded,
            );
            event.id = format!("audit-{index}");
            event.timestamp = Utc.timestamp_opt(1_700_000_000 + index, 0).unwrap();
            event.invocation_id = Some(format!("invoke-{index}"));
            event.grant_id = Some(format!("grant-{index}"));
            event.profile = Some(ConnectionProfileRef::Name("prod".into()));
            event.plugin_id = Some("redis".into());
            event.capability_id = Some("set".into());
            event.credential_refs = vec![CredentialRef {
                id: format!("credential-ref-{index}"),
                class: CredentialClass::Password,
                label: Some("password".into()),
            }];
            event.metadata = json!({
                "input_summary": audit_json_summary(&json!({
                    "sql": "select * from users where password = 'super-secret'",
                    "token": "secret-token",
                })),
                "credential_ref_count": 1,
            });
            if index == 1 {
                event.status = AuditEventStatus::Failed;
                event.error = Some(CapabilityError {
                    category: CapabilityErrorCategory::TargetSystem,
                    code: "redis.command_failed".into(),
                    message: "Target failed.".into(),
                    details: Value::Null,
                    target: None,
                    retryable: false,
                    redaction: RedactionStatus::Applied,
                });
                event.redaction = RedactionStatus::Applied;
            }

            store.append(&event).expect("append event");
        }

        assert!(temp.path().exists());
        assert!(rotated_audit_path(temp.path(), 1).exists());
        assert!(rotated_audit_path(temp.path(), 2).exists());

        let first_page = store
            .query_page(&AuditQuery {
                limit: Some(2),
                ..AuditQuery::default()
            })
            .expect("first page");
        assert_eq!(first_page.events.len(), 2);
        assert_eq!(first_page.page.next_page_token.as_deref(), Some("offset:2"));
        assert_eq!(first_page.source_files.len(), 3);

        let second_page = store
            .query_page(&AuditQuery {
                limit: Some(2),
                page_token: first_page.page.next_page_token,
                ..AuditQuery::default()
            })
            .expect("second page");
        assert_eq!(second_page.events.len(), 1);
        assert_eq!(second_page.page.next_page_token, None);

        let filtered = store
            .query_page(&AuditQuery {
                invocation_id: Some("invoke-1".into()),
                grant_id: Some("grant-1".into()),
                credential_ref_id: Some("credential-ref-1".into()),
                error_category: Some(CapabilityErrorCategory::TargetSystem),
                error_code: Some("redis.command_failed".into()),
                redaction: Some(RedactionStatus::Applied),
                ..AuditQuery::default()
            })
            .expect("filtered query");
        assert_eq!(filtered.events.len(), 1);
        assert_eq!(filtered.events[0].grant_id.as_deref(), Some("grant-1"));

        let mut persisted = String::new();
        for source in &filtered.source_files {
            persisted.push_str(&fs::read_to_string(&source.path).expect("read source"));
        }
        let queried = serde_json::to_string(&filtered).expect("serialize query");
        for encoded in [persisted.as_str(), queried.as_str()] {
            assert!(!encoded.contains("super-secret"));
            assert!(!encoded.contains("secret-token"));
            assert!(!encoded.contains("select * from users"));
        }
    }

    #[test]
    fn local_store_rejects_invalid_page_token() {
        let temp = TempFile::new("events.jsonl");
        let store = LocalAuditStore::new(temp.path());
        let error = store
            .query_page(&AuditQuery {
                page_token: Some("bad-token".into()),
                ..AuditQuery::default()
            })
            .expect_err("invalid page token");

        assert!(error.to_string().contains("Invalid audit page token"));
    }

    #[cfg(unix)]
    #[test]
    fn local_store_creates_private_file() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempFile::new("private/events.jsonl");
        let store = LocalAuditStore::new(temp.path());
        store
            .append(&AuditEvent::new(
                AuditOperation::ProfileList,
                AuditEventStatus::Succeeded,
            ))
            .expect("append");

        let mode = fs::metadata(temp.path())
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    struct TempFile {
        root: PathBuf,
        path: PathBuf,
    }

    impl TempFile {
        fn new(name: &str) -> Self {
            let nonce = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock")
                .as_nanos();
            let sequence = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
            let root = std::env::temp_dir().join(format!(
                "voidb-audit-test-{}-{nonce}-{sequence}",
                std::process::id()
            ));
            let path = root.join(name);
            Self { root, path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempFile {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}
