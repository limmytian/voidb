//! Local file-backed context-share store for the SSH TUI.
//!
//! The store persists only bounded, redacted context and structured operation
//! requests. It never owns SSH live handles; external agents use the existing
//! authorization broker and session commands for agent-owned connections.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;
use voidb_core::{
    AgentSessionConcurrency, AgentSessionOpenRequest, AppConfig, AssistAction,
    AssistActionConfirmation, AssistContextSnapshot, AssistPermission, AssistRequest,
    AssistRequestStatus, AssistResponse, PluginSessionHealth, PluginSessionPurpose,
    RedactionStatus,
};

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

pub const SSH_AGENT_SESSION_STORE_DIR_ENV: &str = "VOIDB_SSH_AGENT_SESSION_DIR";
#[doc(hidden)]
pub const SSH_ASSIST_STORE_DIR_ENV: &str = "VOIDB_SSH_ASSIST_DIR";
const STORE_VERSION: u32 = 1;
const RECORD_LOCK_TIMEOUT: Duration = Duration::from_millis(500);
const STALE_RECORD_LOCK_AGE: Duration = Duration::from_secs(30);

struct RecordLock {
    path: PathBuf,
}

impl Drop for RecordLock {
    fn drop(&mut self) {
        let _ = fs::remove_dir(&self.path);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshAssistTerminalState {
    pub mode: String,
    pub health: PluginSessionHealth,
    pub status: String,
    pub updated_at: DateTime<Utc>,

    #[serde(default)]
    pub redaction: RedactionStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshAssistRecord {
    pub version: u32,
    pub request: AssistRequest,
    pub context: AssistContextSnapshot,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_state: Option<SshAssistTerminalState>,

    #[serde(default, rename = "operation_requests", alias = "responses")]
    pub responses: Vec<AssistResponse>,

    #[serde(
        default,
        rename = "operation_confirmations",
        alias = "action_confirmations"
    )]
    pub action_confirmations: Vec<SshAssistActionConfirmation>,
}

impl SshAssistRecord {
    pub fn latest_operation_request(&self) -> Option<&AssistResponse> {
        self.responses.last()
    }

    pub fn latest_response(&self) -> Option<&AssistResponse> {
        self.latest_operation_request()
    }

    fn expire_if_due(&mut self, now: DateTime<Utc>) {
        if self.request.expire_at(now) {
            self.updated_at = now;
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshAssistSubmitInput {
    pub request: AssistRequest,
    pub context: AssistContextSnapshot,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_state: Option<SshAssistTerminalState>,
}

pub type SshAssistActionConfirmation = AssistActionConfirmation;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshAssistListItem {
    pub id: String,

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

impl From<&SshAssistRecord> for SshAssistListItem {
    fn from(record: &SshAssistRecord) -> Self {
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshAssistAgentInspectionTemplate {
    pub permission: AssistPermission,
    pub uses_current_pty: bool,
    pub purpose: PluginSessionPurpose,
    pub capabilities: Vec<String>,
    pub open_request: AgentSessionOpenRequest,
    pub call_template: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshAssistDetail {
    pub record: SshAssistRecord,
    pub agent_side_inspection: SshAssistAgentInspectionTemplate,
}

#[derive(Debug, Clone)]
pub struct SshAssistStore {
    root: PathBuf,
}

impl SshAssistStore {
    pub fn default_store() -> Result<Self> {
        Self::new(ssh_agent_context_store_root()?)
    }

    pub fn default_store_root() -> Result<PathBuf> {
        ssh_agent_context_store_root()
    }

    pub fn new(root: PathBuf) -> Result<Self> {
        fs::create_dir_all(&root)
            .with_context(|| format!("create SSH session-share store {}", root.display()))?;
        #[cfg(unix)]
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("protect SSH session-share store {}", root.display()))?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn share(
        &self,
        request: AssistRequest,
        context: AssistContextSnapshot,
        terminal_state: Option<SshAssistTerminalState>,
    ) -> Result<SshAssistRecord> {
        if request.binding != context.binding {
            bail!("session-share binding does not match context snapshot binding");
        }
        request
            .context_policy
            .validate()
            .map_err(|error| anyhow!(error.to_string()))?;
        let _lock = self.lock_record(&request.id)?;
        if self.record_path(&request.id).exists() {
            bail!("session share already exists");
        }
        let now = Utc::now();
        let mut record = SshAssistRecord {
            version: STORE_VERSION,
            request,
            context,
            created_at: now,
            updated_at: now,
            terminal_state,
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
        terminal_state: Option<SshAssistTerminalState>,
    ) -> Result<SshAssistRecord> {
        self.share(request, context, terminal_state)
    }

    pub fn list(&self, status: Option<AssistRequestStatus>) -> Result<Vec<SshAssistListItem>> {
        let mut records = self.read_all_records()?;
        if let Some(status) = status {
            records.retain(|record| record.request.status == status);
        }
        records.sort_by_key(|record| std::cmp::Reverse(record.updated_at));
        Ok(records.iter().map(SshAssistListItem::from).collect())
    }

    pub fn detail(&self, request_id: &str) -> Result<SshAssistDetail> {
        let record = self.read_record(request_id)?;
        Ok(SshAssistDetail {
            agent_side_inspection: agent_side_inspection_template(&record),
            record,
        })
    }

    pub fn read_record(&self, request_id: &str) -> Result<SshAssistRecord> {
        let path = self.record_path(request_id);
        let text = fs::read_to_string(&path)
            .with_context(|| format!("session share {request_id} was not found"))?;
        let mut record: SshAssistRecord = serde_json::from_str(&text)
            .with_context(|| format!("session share {request_id} is corrupt"))?;
        if record.version != STORE_VERSION {
            bail!("session share {request_id} uses unsupported store version");
        }
        record.expire_if_due(Utc::now());
        Ok(record)
    }

    pub fn post_operation_request(
        &self,
        request_id: &str,
        response: AssistResponse,
    ) -> Result<SshAssistRecord> {
        let _lock = self.lock_record(request_id)?;
        let mut record = self.read_record(request_id)?;
        if response.request_id != record.request.id {
            bail!("operation request share ID does not match the target session share");
        }
        if record.request.status.is_terminal() {
            bail!("session share is already terminal");
        }
        response
            .validate()
            .map_err(|error| anyhow!(error.to_string()))?;
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
    ) -> Result<SshAssistRecord> {
        self.post_operation_request(request_id, response)
    }

    pub fn cancel(&self, request_id: &str) -> Result<SshAssistRecord> {
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

    pub fn close(&self, request_id: &str) -> Result<SshAssistRecord> {
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

    pub fn update_terminal_state(
        &self,
        request_id: &str,
        terminal_state: SshAssistTerminalState,
    ) -> Result<SshAssistRecord> {
        let _lock = self.lock_record(request_id)?;
        let mut record = self.read_record(request_id)?;
        record.terminal_state = Some(terminal_state);
        record.updated_at = Utc::now();
        self.write_record(&record)?;
        Ok(record)
    }

    /// Refresh the bounded, redacted view of a live TUI session.
    ///
    /// The SSH service and PTY remain owned by the TUI process. External agents
    /// only observe this snapshot and submit separately reviewed input actions.
    pub fn update_context(
        &self,
        request_id: &str,
        context: AssistContextSnapshot,
        terminal_state: SshAssistTerminalState,
    ) -> Result<SshAssistRecord> {
        let _lock = self.lock_record(request_id)?;
        let mut record = self.read_record(request_id)?;
        if record.request.status.is_terminal() {
            bail!("session share is already terminal");
        }
        if context.binding != record.request.binding {
            bail!("context binding does not match the shared session");
        }
        record.context = context;
        record.terminal_state = Some(terminal_state);
        record.updated_at = Utc::now();
        self.write_record(&record)?;
        Ok(record)
    }

    pub fn confirm_action(
        &self,
        request_id: &str,
        confirmation: SshAssistActionConfirmation,
    ) -> Result<SshAssistRecord> {
        let _lock = self.lock_record(request_id)?;
        let mut record = self.read_record(request_id)?;
        if confirmation.request_id != record.request.id {
            bail!("operation confirmation share ID does not match the target session share");
        }
        if !record
            .responses
            .iter()
            .any(|response| response.id == confirmation.response_id)
        {
            bail!("operation confirmation request ID was not found");
        }
        if record.request.status.is_terminal() {
            bail!("session share is already terminal");
        }
        if record.action_confirmations.iter().any(|existing| {
            existing.response_id == confirmation.response_id
                && existing.action_index == confirmation.action_index
        }) {
            bail!("operation action has already been confirmed");
        }
        record.action_confirmations.push(confirmation);
        record.updated_at = Utc::now();
        self.write_record(&record)?;
        Ok(record)
    }

    pub fn wait_for_operation_request(
        &self,
        request_id: &str,
        timeout: Duration,
        interval: Duration,
    ) -> Result<SshAssistDetail> {
        let started = Instant::now();
        loop {
            let detail = self.detail(request_id)?;
            if detail.record.latest_operation_request().is_some()
                || detail.record.request.status.is_terminal()
            {
                return Ok(detail);
            }
            if started.elapsed() >= timeout {
                bail!("session operation wait timed out");
            }
            thread::sleep(interval.min(Duration::from_secs(1)));
        }
    }

    pub fn wait_for_response(
        &self,
        request_id: &str,
        timeout: Duration,
        interval: Duration,
    ) -> Result<SshAssistDetail> {
        self.wait_for_operation_request(request_id, timeout, interval)
    }

    fn read_all_records(&self) -> Result<Vec<SshAssistRecord>> {
        let mut records = Vec::new();
        for entry in fs::read_dir(&self.root)
            .with_context(|| format!("read SSH session-share store {}", self.root.display()))?
        {
            let entry = entry?;
            if entry.path().extension().and_then(|ext| ext.to_str()) != Some("json") {
                continue;
            }
            let text = fs::read_to_string(entry.path())?;
            let mut record: SshAssistRecord = serde_json::from_str(&text)?;
            if record.version == STORE_VERSION {
                record.expire_if_due(Utc::now());
                records.push(record);
            }
        }
        Ok(records)
    }

    fn write_record(&self, record: &SshAssistRecord) -> Result<()> {
        let path = self.record_path(&record.request.id);
        let tmp = self.root.join(format!(
            ".{}.{}.tmp",
            safe_request_filename(&record.request.id),
            Uuid::new_v4()
        ));
        let bytes = serde_json::to_vec_pretty(record)?;
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&tmp)?;
        file.write_all(&bytes)?;
        drop(file);
        fs::rename(&tmp, &path)?;
        Ok(())
    }

    fn lock_record(&self, request_id: &str) -> Result<RecordLock> {
        let path = self
            .root
            .join(format!(".{}.lock", safe_request_filename(request_id)));
        let started = Instant::now();
        loop {
            match fs::create_dir(&path) {
                Ok(()) => return Ok(RecordLock { path }),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let stale = fs::metadata(&path)
                        .and_then(|metadata| metadata.modified())
                        .ok()
                        .and_then(|modified| modified.elapsed().ok())
                        .is_some_and(|age| age >= STALE_RECORD_LOCK_AGE);
                    if stale {
                        let _ = fs::remove_dir(&path);
                        continue;
                    }
                    if started.elapsed() >= RECORD_LOCK_TIMEOUT {
                        bail!("timed out waiting for shared SSH session record lock");
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("lock shared SSH session record {request_id}"));
                }
            }
        }
    }

    fn record_path(&self, request_id: &str) -> PathBuf {
        self.root
            .join(format!("{}.json", safe_request_filename(request_id)))
    }
}

pub fn ssh_agent_context_store_root() -> Result<PathBuf> {
    if let Some(path) = std::env::var_os(SSH_AGENT_SESSION_STORE_DIR_ENV) {
        Ok(PathBuf::from(path))
    } else if let Some(path) = std::env::var_os(SSH_ASSIST_STORE_DIR_ENV) {
        Ok(PathBuf::from(path))
    } else {
        Ok(AppConfig::config_dir()
            .map_err(|error| anyhow!(error.to_string()))?
            .join("ssh-assist"))
    }
}

pub fn agent_side_inspection_template(
    record: &SshAssistRecord,
) -> SshAssistAgentInspectionTemplate {
    let capabilities = vec!["ssh.exec".to_string()];
    SshAssistAgentInspectionTemplate {
        permission: AssistPermission::AgentSideInspect,
        uses_current_pty: false,
        purpose: PluginSessionPurpose::InteractiveTerminal,
        capabilities: capabilities.clone(),
        open_request: AgentSessionOpenRequest {
            purpose: PluginSessionPurpose::InteractiveTerminal,
            capabilities,
            lease_seconds: 300,
            concurrency: AgentSessionConcurrency::Serialized,
            destructive_acknowledged: false,
            input: json!({
                "context_share_id": record.request.id,
                "source_session": {
                    "session_id": record.request.binding.session_id,
                    "generation": record.request.binding.generation,
                    "plugin_id": record.request.binding.plugin_id,
                    "owner_id": record.request.binding.owner_id
                },
                "uses_current_pty": false
            }),
        },
        call_template: json!({
            "capability": "ssh.exec",
            "input": {
                "command": "<diagnostic command>",
                "max_stdout_bytes": 32768,
                "max_stderr_bytes": 32768
            },
            "destructive_acknowledged": false,
            "output_limit_bytes": 65536
        }),
    }
}

pub fn operation_requests_agent_side_inspection(response: &AssistResponse) -> bool {
    response
        .requested_permissions
        .contains(&AssistPermission::AgentSideInspect)
        || response.actions.iter().any(|action| {
            matches!(
                action,
                AssistAction::RequestPermission {
                    permission: AssistPermission::AgentSideInspect,
                    ..
                }
            )
        })
}

fn safe_request_filename(request_id: &str) -> String {
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
    use chrono::Duration as ChronoDuration;
    use voidb_core::{
        ActorRef, ActorType, AssistBoundedText, AssistContextPolicy, AssistSessionBinding,
        AssistTerminalDimensions, PluginSessionRegistration, PluginSessionScope,
    };

    use super::*;

    fn store() -> SshAssistStore {
        SshAssistStore::new(
            std::env::temp_dir().join(format!("voidb-ssh-assist-test-{}", Uuid::new_v4())),
        )
        .unwrap()
    }

    fn request_and_context() -> (AssistRequest, AssistContextSnapshot) {
        let now = Utc::now();
        let descriptor = PluginSessionRegistration::new(
            "ssh",
            "owner-1",
            PluginSessionPurpose::InteractiveTerminal,
            PluginSessionScope::RemoteTarget,
        )
        .with_health(PluginSessionHealth::Ready)
        .with_authenticated(true)
        .descriptor;
        let binding = AssistSessionBinding::from_descriptor(&descriptor);
        let policy = AssistContextPolicy::default();
        let mut request = AssistRequest::new_context_share(
            "assist:test:1".to_string(),
            "Shared SSH terminal state".to_string(),
            binding.clone(),
            ActorRef {
                id: "human:test".to_string(),
                actor_type: ActorType::Human,
            },
            None,
            policy,
            now,
            now + ChronoDuration::minutes(5),
        )
        .unwrap();
        request.transition_to(AssistRequestStatus::Pending).unwrap();
        let context = AssistContextSnapshot {
            binding,
            captured_at: now,
            mode: "terminal".to_string(),
            health: PluginSessionHealth::Ready,
            terminal: Some(AssistTerminalDimensions { rows: 24, cols: 80 }),
            visible_screen: Some(
                AssistBoundedText::capture("safe screen", 4096, RedactionStatus::NotRequired)
                    .unwrap(),
            ),
            transcript_tail: None,
            status_line: None,
            withheld_fields: Vec::new(),
            metadata: json!({ "kind": "test" }),
            redaction: RedactionStatus::NotRequired,
        };
        (request, context)
    }

    fn operation_request(request_id: &str) -> AssistResponse {
        AssistResponse {
            id: "assist:response:1".to_string(),
            request_id: request_id.to_string(),
            agent: voidb_core::AgentPrincipal {
                client_id: "agent".to_string(),
                task_id: "task-1".to_string(),
                instance_id: None,
            },
            created_at: Utc::now(),
            summary: "inspect separately".to_string(),
            diagnosis: Some("need more data".to_string()),
            actions: vec![AssistAction::RequestPermission {
                permission: AssistPermission::AgentSideInspect,
                reason: "collect process state in a separate session".to_string(),
                ttl_seconds: 300,
            }],
            requested_permissions: vec![AssistPermission::AgentSideInspect],
            redaction: RedactionStatus::NotRequired,
        }
    }

    fn confirmation(request_id: &str) -> SshAssistActionConfirmation {
        SshAssistActionConfirmation {
            request_id: request_id.to_string(),
            response_id: "assist:response:1".to_string(),
            action_index: 0,
            target: "agent_side_session:session-1:1".to_string(),
            uses_current_pty: false,
            generation: 1,
            confirmed_at: Utc::now(),
            expires_at: None,
            command_summary: Some("ps aux".to_string()),
            capability_id: Some("ssh.exec".to_string()),
            status: "confirmed_agent_side_command".to_string(),
            note: "current PTY unchanged".to_string(),
            redaction: RedactionStatus::NotRequired,
        }
    }

    #[test]
    fn store_shares_lists_and_posts_safe_operations() {
        let store = store();
        let (request, context) = request_and_context();
        let request_id = request.id.clone();

        let submitted = store.share(request, context, None).unwrap();
        assert_eq!(submitted.request.status, AssistRequestStatus::Pending);
        let list = store.list(None).unwrap();
        assert_eq!(list.len(), 1);
        let list_json = serde_json::to_value(&list).unwrap();
        assert_eq!(list_json[0]["label"], "Shared SSH terminal state");
        assert_eq!(list_json[0]["operation_request_count"], 0);
        assert!(list_json[0].get("question").is_none());
        assert!(list_json[0].get("response_count").is_none());

        let updated = store
            .post_operation_request(&request_id, operation_request(&request_id))
            .unwrap();
        assert_eq!(updated.request.status, AssistRequestStatus::Responded);
        assert_eq!(updated.responses.len(), 1);
        let updated_json = serde_json::to_value(&updated).unwrap();
        assert!(updated_json.get("operation_requests").is_some());
        assert!(updated_json.get("responses").is_none());
        assert!(
            updated_json["operation_requests"][0]
                .get("operations")
                .is_some()
        );
        assert!(
            updated_json["operation_requests"][0]
                .get("actions")
                .is_none()
        );

        let detail = store.detail(&request_id).unwrap();
        assert!(!detail.agent_side_inspection.uses_current_pty);
        assert_eq!(
            detail.agent_side_inspection.open_request.capabilities,
            vec!["ssh.exec".to_string()]
        );
        assert!(operation_requests_agent_side_inspection(
            detail.record.latest_operation_request().unwrap()
        ));

        let confirmed = store
            .confirm_action(&request_id, confirmation(&request_id))
            .unwrap();
        assert_eq!(confirmed.action_confirmations.len(), 1);
        assert!(!confirmed.action_confirmations[0].uses_current_pty);

        let error = store
            .confirm_action(&request_id, confirmation(&request_id))
            .unwrap_err();
        assert!(error.to_string().contains("already been confirmed"));
        assert_eq!(
            store
                .detail(&request_id)
                .unwrap()
                .record
                .action_confirmations
                .len(),
            1
        );

        store.close(&request_id).unwrap();
        let error = store
            .confirm_action(&request_id, confirmation(&request_id))
            .unwrap_err();
        assert!(error.to_string().contains("terminal"));
    }

    #[test]
    fn cancel_prevents_late_operation_request() {
        let store = store();
        let (request, context) = request_and_context();
        let request_id = request.id.clone();
        store.share(request, context, None).unwrap();

        let cancelled = store.cancel(&request_id).unwrap();
        assert_eq!(cancelled.request.status, AssistRequestStatus::Cancelled);
        let error = store
            .post_operation_request(&request_id, operation_request(&request_id))
            .unwrap_err();
        assert!(error.to_string().contains("terminal"));
    }

    #[test]
    fn wait_returns_when_operation_arrives() {
        let store = store();
        let (request, context) = request_and_context();
        let request_id = request.id.clone();
        store.share(request, context, None).unwrap();
        store
            .post_operation_request(&request_id, operation_request(&request_id))
            .unwrap();

        let detail = store
            .wait_for_operation_request(
                &request_id,
                Duration::from_millis(10),
                Duration::from_millis(1),
            )
            .unwrap();

        assert!(detail.record.latest_operation_request().is_some());
    }

    #[test]
    fn live_session_context_can_refresh_without_losing_operations() {
        let store = store();
        let (request, context) = request_and_context();
        let request_id = request.id.clone();
        store.share(request, context.clone(), None).unwrap();
        store
            .post_operation_request(&request_id, operation_request(&request_id))
            .unwrap();

        let mut refreshed = context;
        refreshed.captured_at = Utc::now();
        refreshed.visible_screen = Some(
            AssistBoundedText::capture("new safe screen", 4096, RedactionStatus::NotRequired)
                .unwrap(),
        );
        let updated = store
            .update_context(
                &request_id,
                refreshed,
                SshAssistTerminalState {
                    mode: "terminal".to_string(),
                    health: PluginSessionHealth::Ready,
                    status: "ready".to_string(),
                    updated_at: Utc::now(),
                    redaction: RedactionStatus::NotRequired,
                },
            )
            .unwrap();

        assert_eq!(updated.responses.len(), 1);
        assert_eq!(
            updated.context.visible_screen.unwrap().text,
            "new safe screen"
        );
    }
}
