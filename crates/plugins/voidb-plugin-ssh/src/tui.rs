use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Gauge, Paragraph, Wrap};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::{mpsc, oneshot};
use voidb_core::{
    ActorRef, ActorType, AgentPrincipal, AssistAction, AssistActionTarget, AssistAuditAction,
    AssistAuditProjection, AssistBoundedText, AssistContextPolicy, AssistContextSnapshot,
    AssistContractError, AssistPermission, AssistRequest, AssistRequestStatus, AssistResponse,
    AssistSessionBinding, AssistTerminalDimensions, AssistWithheldField, AssistWithholdingReason,
    ConnectionProfileRef, DEFAULT_ASSIST_CONTROL_TTL_SECONDS, DEFAULT_ASSIST_OUTPUT_LIMIT_BYTES,
    MAX_ASSIST_REQUEST_TTL_SECONDS, PluginSessionDescriptor, PluginSessionHealth,
    PluginSessionListFilter, PluginSessionPurpose, PluginSessionRegistration,
    PluginSessionRegistry, PluginSessionScope, RedactionStatus, TabInfo, TabManager, TuiLaunchPlan,
    redact_text_with_json, retained_tui_quality_gate,
};

use crate::assist_broker::{
    SshAssistActionConfirmation, SshAssistStore, SshAssistTerminalState,
    operation_requests_agent_side_inspection,
};
use crate::config::{SshAuthMethod, SshConfig};
use crate::service::{
    ForwardServiceCommand, ForwardStatus, ForwardType, MetricsServiceCommand, RemoteEntry,
    SftpCommand, SftpEvent, SftpHandle, SftpServiceCommand, SshCommand, SshEvent, SshService,
    SystemMetrics,
};

const MAX_TERMINAL_LINES: usize = 500;
const DEFAULT_TERMINAL_COLS: u16 = 80;
const DEFAULT_TERMINAL_ROWS: u16 = 24;
const ASSIST_STATUS_LIMIT_BYTES: usize = 512;
const ASSIST_CONTROL_COMMAND_LIMIT_BYTES: usize = 4096;

static NEXT_SSH_TUI_OWNER_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TerminalGridSize {
    cols: u16,
    rows: u16,
}

impl TerminalGridSize {
    fn new(cols: u16, rows: u16) -> Self {
        Self {
            cols: cols.max(1),
            rows: rows.max(1),
        }
    }
}

const DEFAULT_TERMINAL_GRID_SIZE: TerminalGridSize = TerminalGridSize {
    cols: DEFAULT_TERMINAL_COLS,
    rows: DEFAULT_TERMINAL_ROWS,
};

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SshTuiSource {
    Profile,
    Connection,
    Fixture,
}

#[derive(Debug, Clone)]
pub struct SshTuiLaunch {
    pub profile_label: String,
    pub config: Option<SshConfig>,
    pub source: SshTuiSource,
    pub fixture_path: Option<String>,
    pub purpose: String,
    pub readonly: bool,
    pub restore: bool,
    pub launch_plan: Option<TuiLaunchPlan>,
}

#[derive(Debug, Deserialize)]
struct SshTuiFixture {
    profile_label: Option<String>,
    target_label: String,
    auth_method: String,
    terminal_lines: Vec<String>,
    status: Option<String>,
    host_key: Option<FixtureHostKey>,
    sftp_path: Option<String>,
    #[serde(default)]
    sftp_entries: Vec<FixtureSftpEntry>,
    #[serde(default)]
    forward_rules: Vec<FixtureForwardRule>,
    metrics: Option<FixtureMetrics>,
}

#[derive(Debug, Clone, Deserialize)]
struct FixtureHostKey {
    host: String,
    port: u16,
    fingerprint: String,
    #[serde(default)]
    key_changed: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct FixtureSftpEntry {
    name: String,
    #[serde(default)]
    is_dir: bool,
    #[serde(default)]
    size: u64,
    permissions: Option<u32>,
    mtime: Option<u32>,
}

#[derive(Debug, Clone, Deserialize)]
struct FixtureForwardRule {
    id: u32,
    kind: String,
    summary: String,
    status: String,
    #[serde(default)]
    bytes_sent: u64,
    #[serde(default)]
    bytes_received: u64,
    #[serde(default)]
    active_connections: u64,
    #[serde(default)]
    total_connections: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct FixtureMetrics {
    hostname: String,
    os_label: String,
    cpu_usage: f64,
    memory_used: u64,
    memory_total: u64,
    load_average: [f64; 3],
    uptime_secs: u64,
}

#[derive(Debug, Clone)]
struct SshTuiData {
    profile_label: String,
    target_label: String,
    auth_method: String,
    terminal_lines: Vec<String>,
    status: String,
    host_key: Option<FixtureHostKey>,
    sftp_path: String,
    sftp_entries: Vec<SftpEntryView>,
    forward_rules: Vec<ForwardRuleView>,
    metrics: Option<MetricsView>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Terminal,
    Sftp,
    Forwarding,
    Monitor,
    HostKeyPrompt,
    AgentOperationReview,
    Help,
    Disconnected,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum PtyInputOwnerState {
    HumanActive,
    AgentObserve {
        request_id: String,
        response_id: String,
        generation: u64,
    },
    AgentControl {
        request_id: String,
        response_id: String,
        agent_label: String,
        generation: u64,
        action_index: usize,
        expires_at: DateTime<Utc>,
    },
    Revoking {
        request_id: String,
        generation: u64,
        reason: String,
    },
    Closed {
        reason: String,
    },
}

impl PtyInputOwnerState {
    fn label(&self, now: DateTime<Utc>) -> String {
        match self {
            Self::HumanActive => "human".to_string(),
            Self::AgentObserve { .. } => "agent-observe".to_string(),
            Self::AgentControl {
                agent_label,
                expires_at,
                ..
            } => {
                let remaining = (*expires_at - now).num_seconds().max(0);
                format!("agent-control:{agent_label}:{remaining}s")
            }
            Self::Revoking { .. } => "revoking".to_string(),
            Self::Closed { reason } => format!("closed:{}", safe_inline(reason, 32)),
        }
    }

    fn allows_human_input(&self, now: DateTime<Utc>) -> bool {
        match self {
            Self::HumanActive | Self::AgentObserve { .. } => true,
            Self::AgentControl { expires_at, .. } => now >= *expires_at,
            Self::Revoking { .. } | Self::Closed { .. } => false,
        }
    }

    fn request_id(&self) -> Option<&str> {
        match self {
            Self::AgentObserve { request_id, .. }
            | Self::AgentControl { request_id, .. }
            | Self::Revoking { request_id, .. } => Some(request_id),
            Self::HumanActive | Self::Closed { .. } => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PtyInputWriter {
    Human,
    Agent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AssistControlAuditOutcome {
    Requested,
    Approved,
    Blocked,
    Delegated,
    Executed,
    Revoked,
    Expired,
    Dropped,
    Closed,
}

#[derive(Debug, Clone, PartialEq)]
struct AssistControlAuditEntry {
    projection: AssistAuditProjection,
    outcome: AssistControlAuditOutcome,
    detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SftpEntryView {
    name: String,
    is_dir: bool,
    size: u64,
    permissions: Option<u32>,
    mtime: Option<u32>,
}

impl From<RemoteEntry> for SftpEntryView {
    fn from(entry: RemoteEntry) -> Self {
        Self {
            name: entry.name,
            is_dir: entry.is_dir,
            size: entry.size,
            permissions: entry.permissions,
            mtime: entry.mtime,
        }
    }
}

impl From<FixtureSftpEntry> for SftpEntryView {
    fn from(entry: FixtureSftpEntry) -> Self {
        Self {
            name: entry.name,
            is_dir: entry.is_dir,
            size: entry.size,
            permissions: entry.permissions,
            mtime: entry.mtime,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ForwardRuleView {
    id: u32,
    kind: String,
    summary: String,
    status: String,
    bytes_sent: u64,
    bytes_received: u64,
    active_connections: u64,
    total_connections: u64,
}

impl From<FixtureForwardRule> for ForwardRuleView {
    fn from(rule: FixtureForwardRule) -> Self {
        Self {
            id: rule.id,
            kind: rule.kind,
            summary: rule.summary,
            status: rule.status,
            bytes_sent: rule.bytes_sent,
            bytes_received: rule.bytes_received,
            active_connections: rule.active_connections,
            total_connections: rule.total_connections,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ForwardPlanView {
    forward_type: ForwardType,
    confirmed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TransferKind {
    Download,
    Upload,
    DeleteFile,
    DeleteDir,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TransferPlanView {
    kind: TransferKind,
    remote: String,
    local: Option<String>,
    confirmed: bool,
    progress: Option<TransferProgressView>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TransferProgressView {
    label: String,
    transferred: u64,
    total: u64,
}

#[derive(Debug, Clone)]
struct MetricsView {
    hostname: String,
    os_label: String,
    cpu_usage: f64,
    memory_used: u64,
    memory_total: u64,
    load_average: [f64; 3],
    uptime_secs: u64,
}

impl From<FixtureMetrics> for MetricsView {
    fn from(metrics: FixtureMetrics) -> Self {
        Self {
            hostname: metrics.hostname,
            os_label: metrics.os_label,
            cpu_usage: metrics.cpu_usage,
            memory_used: metrics.memory_used,
            memory_total: metrics.memory_total,
            load_average: metrics.load_average,
            uptime_secs: metrics.uptime_secs,
        }
    }
}

struct HostKeyPrompt {
    host: String,
    port: u16,
    fingerprint: String,
    key_changed: bool,
    reply: Option<oneshot::Sender<bool>>,
}

pub fn write_ssh_tui_preflight(launch: &SshTuiLaunch) -> Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(&preflight_value(launch))?
    );
    Ok(())
}

pub fn build_ssh_tui_evidence(launch: &SshTuiLaunch) -> Result<Value> {
    let data = if let Some(path) = &launch.fixture_path {
        load_fixture(path)?
    } else {
        let config = launch
            .config
            .as_ref()
            .context("ssh tui evidence requires a profile, connection, or fixture")?;
        config_data(launch.profile_label.clone(), config)
    };

    let host_key = data.host_key.as_ref().map(|prompt| {
        json!({
            "host": prompt.host,
            "port": prompt.port,
            "fingerprint": prompt.fingerprint,
            "key_changed": prompt.key_changed
        })
    });
    let sftp_entries = data
        .sftp_entries
        .iter()
        .map(|entry| {
            json!({
                "name": entry.name,
                "is_dir": entry.is_dir,
                "size": entry.size,
                "permissions": entry.permissions,
                "mtime": entry.mtime
            })
        })
        .collect::<Vec<_>>();
    let forward_rules = data
        .forward_rules
        .iter()
        .map(|rule| {
            json!({
                "id": rule.id,
                "kind": rule.kind,
                "summary": rule.summary,
                "status": rule.status,
                "bytes_sent": rule.bytes_sent,
                "bytes_received": rule.bytes_received,
                "active_connections": rule.active_connections,
                "total_connections": rule.total_connections
            })
        })
        .collect::<Vec<_>>();
    let metrics = data.metrics.as_ref().map(|metrics| {
        json!({
            "hostname": metrics.hostname,
            "os_label": metrics.os_label,
            "cpu_usage": metrics.cpu_usage,
            "memory_used": metrics.memory_used,
            "memory_total": metrics.memory_total,
            "load_average": metrics.load_average,
            "uptime_secs": metrics.uptime_secs
        })
    });

    let mut evidence = json!({
        "schema_version": 1,
        "kind": "ssh_tui_fixture_evidence",
        "quality_gate": retained_tui_quality_gate(
            "ssh",
            &["fixture-ssh", "VoidB SSH fixture terminal"],
            &["host_key_prompt", "disconnect_reconnect"],
            80,
            24,
            10_000
        ),
        "preflight": preflight_value(launch),
        "transcript": {
            "profile_label": data.profile_label,
            "target_label": data.target_label,
            "auth_method": data.auth_method,
            "terminal_lines": data.terminal_lines,
            "host_key_prompt": host_key,
            "sftp": {
                "path": data.sftp_path,
                "entries": sftp_entries
            },
            "forwarding": {
                "rules": forward_rules
            },
            "metrics": metrics
        },
        "recovery_contract": {
            "disconnected_state_forwards_raw_input": false,
            "error_state_forwards_raw_input": false,
            "keys": [
                {"key": "r", "action": "request reconnect"},
                {"key": "q", "action": "quit"},
                {"key": "?", "action": "show help"},
                {"key": "Ctrl+] then v", "action": "revoke external agent current PTY control"}
            ],
            "terminal_restore_on_exit": launch.restore
        },
        "external_agent_interaction": {
            "session_share": {
                "shortcut": "Ctrl+] then a",
                "bounded_context": ["visible_screen", "transcript_tail"],
                "redaction_before_publish": true,
                "conversation_surface": false,
                "refresh_interval_ms": 250
            },
            "external_agent_access": {
                "store_env": crate::assist_broker::SSH_AGENT_SESSION_STORE_DIR_ENV,
                "cli_commands": ["list", "show", "input", "wait", "cancel", "close", "state"],
                "legacy_aliases_hidden": true,
                "agent_side_inspection_default": true,
                "current_pty_handles_shared": false
            },
            "operation_review": {
                "select_operations": "j/k",
                "approve_once": "y",
                "allow_same_agent_for_share": "A",
                "deny": ["n", "x"],
                "revoke": "Ctrl+] then v"
            },
            "current_pty_control": {
                "owner_states": ["human_active", "agent_observe", "agent_control", "revoking", "closed"],
                "ttl_seconds": DEFAULT_ASSIST_CONTROL_TTL_SECONDS,
                "single_writer": true,
                "revoke_escape": "Ctrl+] then v",
                "dropped_input_accounting": true,
                "output_limit_bytes": DEFAULT_ASSIST_OUTPUT_LIMIT_BYTES
            },
            "blocked_takeover_contexts": [
                "stale_generation",
                "host_key_prompt",
                "disconnected_or_error",
                "password_like_prompt",
                "pending_local_input",
                "retained_output_over_limit",
                "readonly_tui"
            ],
            "human_reviewed_takeover_warnings": [
                "alternate_screen_or_application_mode"
            ],
            "audit_operations": [
                "assist.inspect",
                "assist.propose",
                "assist.approve_control",
                "assist.revoke",
                "assist.expire",
                "assist.close"
            ],
            "residual_live_smoke": [
                "manual real-terminal key routing",
                "disposable SSH fixture end-to-end external agent loop"
            ]
        },
        "coverage": [
            "startup",
            "raw_input_escape",
            "resize",
            "sftp_browser",
            "forwarding",
            "shared_session_context",
            "external_agent_session_share",
            "agent_operation_review",
            "agent_side_confirmation",
            "current_pty_operation_approval",
            "current_pty_control_revoke",
            "current_pty_control_guards",
            "stale_generation_block",
            "session_share_cancel",
            "agent_audit_shape",
            "host_key_prompt",
            "disconnect_reconnect",
            "quit_restore",
            "secret_leak_scan"
        ],
        "secret_leak_scan": null
    });

    let rendered = serde_json::to_string(&evidence)?;
    let markers = secret_leak_markers(&rendered);
    evidence["secret_leak_scan"] = json!({
        "passed": markers.is_empty(),
        "marker_count": markers.len(),
        "markers": markers
    });
    Ok(evidence)
}

pub async fn run_ssh_tui(launch: SshTuiLaunch) -> Result<()> {
    let mut terminal = ratatui::init();
    if let Err(error) = enable_bracketed_paste() {
        ratatui::restore();
        return Err(error);
    }
    let initial_size = terminal
        .size()
        .map(|size| terminal_grid_size_for_area(Rect::new(0, 0, size.width, size.height)))
        .unwrap_or(DEFAULT_TERMINAL_GRID_SIZE);
    let mut app = match SshTuiApp::new_with_terminal_size(launch, initial_size) {
        Ok(app) => app,
        Err(error) => {
            let _ = disable_bracketed_paste();
            ratatui::restore();
            return Err(error);
        }
    };
    let result = run_loop(&mut terminal, &mut app);
    app.shutdown();
    let paste_cleanup = disable_bracketed_paste();
    ratatui::restore();
    result.and(paste_cleanup)
}

fn enable_bracketed_paste() -> Result<()> {
    crossterm::execute!(std::io::stdout(), event::EnableBracketedPaste)
        .context("enable bracketed paste for SSH TUI")
}

fn disable_bracketed_paste() -> Result<()> {
    crossterm::execute!(std::io::stdout(), event::DisableBracketedPaste)
        .context("disable bracketed paste for SSH TUI")
}

fn preflight_value(launch: &SshTuiLaunch) -> Value {
    let fixture_data = launch
        .fixture_path
        .as_ref()
        .and_then(|path| load_fixture(path).ok());
    let target = launch
        .config
        .as_ref()
        .map(target_label)
        .or_else(|| {
            fixture_data
                .as_ref()
                .map(|fixture| fixture.target_label.clone())
        })
        .unwrap_or_else(|| "fixture".to_string());
    let profile_label = fixture_data
        .as_ref()
        .map(|fixture| fixture.profile_label.clone())
        .unwrap_or_else(|| launch.profile_label.clone());
    let auth_method = launch
        .config
        .as_ref()
        .map(auth_method_label)
        .or_else(|| {
            fixture_data
                .as_ref()
                .map(|fixture| fixture.auth_method.clone())
        })
        .unwrap_or_else(|| "fixture".to_string());
    let launch_plan = launch.launch_plan.as_ref().map(|plan| {
        json!({
            "schema_version": plan.schema_version,
            "plugin_id": plan.plugin_id,
            "command": plan.command,
            "args": plan.args,
            "profile": plan.profile,
            "purpose": plan.purpose,
            "readonly": plan.readonly,
            "restore": plan.restore,
            "raw_input": plan.raw_input,
            "credential_ref_count": plan.credential_grant.credential_refs.len(),
            "credential_grant_id": plan.credential_grant.id,
            "redaction": plan.redaction
        })
    });

    json!({
        "ok": true,
        "command": "ssh tui",
        "plugin_id": "ssh",
        "profile_label": profile_label,
        "source": launch.source,
        "target": target,
        "purpose": launch.purpose,
        "readonly": launch.readonly,
        "restore": launch.restore,
        "raw_input": true,
        "fixture": launch.fixture_path.is_some(),
        "auth": {
            "method": auth_method,
            "secret_material": "redacted"
        },
        "privacy": {
            "diagnostics_include_passwords": false,
            "diagnostics_include_private_keys": false,
            "diagnostics_include_passphrases": false,
            "terminal_transcript_redaction_required": true
        },
        "service_boundary": "SshService::Channel",
        "modes": [
            "terminal",
            "escape_layer",
            "host_key_prompt",
            "sftp_browser",
            "transfer_planning",
            "forwarding_monitor",
            "session_monitor",
            "external_agent_session_share",
            "agent_operation_review",
            "auth_failure",
            "disconnected"
        ],
        "launch_plan": launch_plan
    })
}

fn run_loop(terminal: &mut ratatui::DefaultTerminal, app: &mut SshTuiApp) -> Result<()> {
    terminal.draw(|frame| app.draw(frame))?;
    loop {
        let mut dirty = app.drain_service();
        if app.should_quit {
            return Ok(());
        }

        if event::poll(Duration::from_millis(50))? {
            match event::read()? {
                Event::Key(key) => {
                    app.handle_key(key);
                    dirty = true;
                }
                Event::Paste(text) => {
                    app.handle_paste(&text);
                    dirty = true;
                }
                Event::Resize(cols, rows) => {
                    app.handle_resize(cols, rows);
                    dirty = true;
                }
                _ => {}
            }
        }
        if dirty {
            terminal.draw(|frame| app.draw(frame))?;
        }
    }
}

fn load_fixture(path: &str) -> Result<SshTuiData> {
    let text = fs::read_to_string(path).with_context(|| format!("read fixture {path}"))?;
    let fixture: SshTuiFixture =
        serde_json::from_str(&text).with_context(|| format!("parse fixture {path}"))?;

    Ok(SshTuiData {
        profile_label: fixture
            .profile_label
            .unwrap_or_else(|| "fixture".to_string()),
        target_label: fixture.target_label,
        auth_method: fixture.auth_method,
        terminal_lines: fixture.terminal_lines,
        status: fixture
            .status
            .unwrap_or_else(|| "fixture terminal core ready".to_string()),
        host_key: fixture.host_key,
        sftp_path: fixture.sftp_path.unwrap_or_else(|| "/".to_string()),
        sftp_entries: fixture
            .sftp_entries
            .into_iter()
            .map(SftpEntryView::from)
            .collect(),
        forward_rules: fixture
            .forward_rules
            .into_iter()
            .map(ForwardRuleView::from)
            .collect(),
        metrics: fixture.metrics.map(MetricsView::from),
    })
}

fn config_data(profile_label: String, config: &SshConfig) -> SshTuiData {
    SshTuiData {
        profile_label,
        target_label: target_label(config),
        auth_method: auth_method_label(config),
        terminal_lines: vec![
            "Connecting through SshService channel mode...".to_string(),
            "Use Ctrl+] for the local escape layer.".to_string(),
        ],
        status: "connecting".to_string(),
        host_key: None,
        sftp_path: ".".to_string(),
        sftp_entries: Vec::new(),
        forward_rules: Vec::new(),
        metrics: None,
    }
}

fn next_ssh_tui_owner_id() -> String {
    let sequence = NEXT_SSH_TUI_OWNER_ID.fetch_add(1, Ordering::Relaxed);
    format!("ssh-tui-{}-{sequence}", std::process::id())
}

fn fallback_assist_descriptor(
    owner_id: &str,
    profile_ref: Option<ConnectionProfileRef>,
    health: PluginSessionHealth,
    authenticated: bool,
    terminal_size: TerminalGridSize,
) -> PluginSessionDescriptor {
    let mut registration = PluginSessionRegistration::new(
        "ssh",
        owner_id.to_string(),
        PluginSessionPurpose::InteractiveTerminal,
        PluginSessionScope::RemoteTarget,
    )
    .with_health(health)
    .with_authenticated(authenticated)
    .with_destructive_capable(true)
    .with_stream_capable(true)
    .with_metadata(
        json!({
            "kind": "pty",
            "cols": terminal_size.cols,
            "rows": terminal_size.rows,
        }),
        RedactionStatus::NotRequired,
    );
    if let Some(profile_ref) = profile_ref {
        registration = registration.with_profile_ref(profile_ref);
    }
    registration.descriptor
}

fn target_label(config: &SshConfig) -> String {
    format!("{}@{}:{}", config.username, config.host, config.port)
}

fn auth_method_label(config: &SshConfig) -> String {
    match &config.auth {
        SshAuthMethod::Password { .. } => "password".to_string(),
        SshAuthMethod::PublicKey { .. } => "public_key".to_string(),
        SshAuthMethod::Agent => "agent".to_string(),
    }
}

struct SshTuiApp {
    profile_label: String,
    target_label: String,
    auth_method: String,
    purpose: String,
    readonly: bool,
    restore: bool,
    source: SshTuiSource,
    service: Option<SshService>,
    sessions: Arc<PluginSessionRegistry>,
    owner_id: String,
    profile_ref: Option<ConnectionProfileRef>,
    sftp_handle: Option<SftpHandle>,
    sftp_path: String,
    sftp_entries: Vec<SftpEntryView>,
    sftp_selected: usize,
    transfer_plan: Option<TransferPlanView>,
    forward_rules: Vec<ForwardRuleView>,
    forward_selected: usize,
    forward_plan: Option<ForwardPlanView>,
    metrics: Option<MetricsView>,
    metrics_started: bool,
    terminal_parser: vt100::Parser,
    terminal_size: TerminalGridSize,
    terminal_lines: Vec<String>,
    status: String,
    mode: Mode,
    return_mode: Mode,
    host_key_prompt: Option<HostKeyPrompt>,
    assist_fallback_session: PluginSessionDescriptor,
    assist_request: Option<AssistRequest>,
    assist_response: Option<AssistResponse>,
    assist_response_seen_id: Option<String>,
    assist_action_selected: usize,
    assist_store: SshAssistStore,
    assist_last_context_refresh_at: Option<DateTime<Utc>>,
    agent_auto_control: Option<AgentPrincipal>,
    pty_input_owner: PtyInputOwnerState,
    pending_local_input_bytes: usize,
    dropped_pty_input_bytes: usize,
    #[cfg(test)]
    forwarded_pty_writes: Vec<Vec<u8>>,
    assist_control_audit: Vec<AssistControlAuditEntry>,
    escape_armed: bool,
    should_quit: bool,
    render_quit: Arc<AtomicBool>,
}

impl SshTuiApp {
    #[cfg(test)]
    fn new(launch: SshTuiLaunch) -> Result<Self> {
        Self::new_with_terminal_size(launch, DEFAULT_TERMINAL_GRID_SIZE)
    }

    fn new_with_terminal_size(
        launch: SshTuiLaunch,
        terminal_size: TerminalGridSize,
    ) -> Result<Self> {
        let data = if let Some(path) = &launch.fixture_path {
            load_fixture(path)?
        } else {
            let config = launch
                .config
                .as_ref()
                .context("ssh tui requires a profile, connection, or fixture")?;
            config_data(launch.profile_label.clone(), config)
        };

        let render_quit = Arc::new(AtomicBool::new(false));
        let sessions = Arc::new(PluginSessionRegistry::new());
        let owner_id = next_ssh_tui_owner_id();
        let profile_ref = launch
            .launch_plan
            .as_ref()
            .map(|plan| ConnectionProfileRef::Id(plan.profile.id.clone()));
        let service = if launch.fixture_path.is_none() {
            let config = launch
                .config
                .clone()
                .context("ssh tui requires SSH config outside fixture mode")?;
            let tabs = Arc::new(StandaloneSshTabManager::new(render_quit.clone()));
            let runtime = tokio::runtime::Handle::current();
            let service = SshService::new_with_sessions(
                config.clone(),
                tabs,
                runtime,
                Arc::clone(&sessions),
                owner_id.clone(),
                profile_ref.clone(),
            );
            service.send(SshCommand::Resize {
                cols: terminal_size.cols,
                rows: terminal_size.rows,
            });
            service.send(SshCommand::Connect { config });
            Some(service)
        } else {
            None
        };

        let mut terminal_parser =
            vt100::Parser::new(terminal_size.rows, terminal_size.cols, MAX_TERMINAL_LINES);
        seed_terminal_parser(&mut terminal_parser, &data.terminal_lines);
        let assist_fallback_session = fallback_assist_descriptor(
            &owner_id,
            profile_ref.clone(),
            if service.is_some() {
                PluginSessionHealth::Starting
            } else {
                PluginSessionHealth::Ready
            },
            service.is_none(),
            terminal_size,
        );
        #[cfg(not(test))]
        let assist_store = SshAssistStore::default_store()?;
        #[cfg(test)]
        let assist_store = SshAssistStore::new(
            std::env::temp_dir().join(format!("voidb-ssh-tui-app-test-{}", uuid::Uuid::new_v4())),
        )?;

        let mut app = Self {
            profile_label: data.profile_label,
            target_label: data.target_label,
            auth_method: data.auth_method,
            purpose: launch.purpose,
            readonly: launch.readonly,
            restore: launch.restore,
            source: launch.source,
            service,
            sessions,
            owner_id,
            profile_ref,
            sftp_handle: None,
            sftp_path: data.sftp_path,
            sftp_entries: data.sftp_entries,
            sftp_selected: 0,
            transfer_plan: None,
            forward_rules: data.forward_rules,
            forward_selected: 0,
            forward_plan: None,
            metrics: data.metrics,
            metrics_started: false,
            terminal_parser,
            terminal_size,
            terminal_lines: data
                .terminal_lines
                .into_iter()
                .map(|line| sanitize_terminal_text(&line))
                .filter(|line| !line.is_empty())
                .collect(),
            status: data.status,
            mode: Mode::Terminal,
            return_mode: Mode::Terminal,
            host_key_prompt: None,
            assist_fallback_session,
            assist_request: None,
            assist_response: None,
            assist_response_seen_id: None,
            assist_action_selected: 0,
            assist_store,
            assist_last_context_refresh_at: None,
            agent_auto_control: None,
            pty_input_owner: PtyInputOwnerState::HumanActive,
            pending_local_input_bytes: 0,
            dropped_pty_input_bytes: 0,
            #[cfg(test)]
            forwarded_pty_writes: Vec::new(),
            assist_control_audit: Vec::new(),
            escape_armed: false,
            should_quit: false,
            render_quit,
        };

        if let Some(prompt) = data.host_key {
            app.set_fixture_host_key_prompt(prompt);
        }

        Ok(app)
    }

    fn shutdown(&mut self) {
        if let Some(request) = self.assist_request.as_ref()
            && !request.status.is_terminal()
        {
            let _ = if request.status == AssistRequestStatus::Responded {
                self.assist_store.close(&request.id)
            } else {
                self.assist_store.cancel(&request.id)
            };
        }
        self.agent_auto_control = None;
        if let Some(service) = &self.service {
            service.send(SshCommand::Metrics(MetricsServiceCommand::Stop));
            service.send(SshCommand::Sftp(SftpServiceCommand::Close));
            service.send(SshCommand::Disconnect);
        }
    }

    fn drain_service(&mut self) -> bool {
        let mut changed = false;
        if self.render_quit.load(Ordering::SeqCst) {
            changed |= !self.should_quit;
            self.should_quit = true;
        }
        changed |= self.expire_pty_owner_if_needed();
        changed |= self.sync_agent_operation_request();

        let Some(mut service) = self.service.take() else {
            return changed | self.drain_sftp();
        };

        while let Some(event) = service.poll_event() {
            changed = true;
            self.handle_service_event(event);
        }
        while let Some(output) = service.poll_pty_output() {
            changed = true;
            self.push_terminal_output(&output);
        }

        self.service = Some(service);
        changed | self.drain_sftp()
    }

    fn drain_sftp(&mut self) -> bool {
        let mut changed = false;
        let Some(mut handle) = self.sftp_handle.take() else {
            return false;
        };

        while let Some(event) = handle.poll_event() {
            changed = true;
            self.handle_sftp_event(event);
        }

        self.sftp_handle = Some(handle);
        changed
    }

    fn handle_service_event(&mut self, event: SshEvent) {
        match event {
            SshEvent::Connected => {
                self.mode = Mode::Terminal;
                self.escape_armed = false;
                self.pty_input_owner = PtyInputOwnerState::HumanActive;
                self.pending_local_input_bytes = 0;
                self.status = "connected".to_string();
                self.push_line("[local] SSH PTY connected");
            }
            SshEvent::Disconnected => {
                self.clear_session_subsystems();
                self.close_pty_owner("session disconnected");
                self.mode = Mode::Disconnected;
                self.status =
                    "disconnected; press Ctrl+] then r to reconnect or q to quit".to_string();
                self.push_line("[local] SSH session disconnected");
            }
            SshEvent::Reconnecting {
                attempt,
                max_attempts,
                retry_in_secs,
            } => {
                self.close_pty_owner("session reconnecting");
                self.mode = Mode::Disconnected;
                self.status =
                    format!("reconnecting attempt {attempt}/{max_attempts} in {retry_in_secs:.1}s");
            }
            SshEvent::ReconnectFailed => {
                self.clear_session_subsystems();
                self.close_pty_owner("reconnect failed");
                self.mode = Mode::Error;
                self.status = "reconnect failed; press Ctrl+] then q to quit".to_string();
                self.push_line("[local] reconnect failed");
            }
            SshEvent::Error(message) => {
                self.clear_session_subsystems();
                self.close_pty_owner("session error");
                self.mode = Mode::Error;
                self.status = safe_error_summary(&message);
                self.push_line(&format!("[local] {}", self.status));
            }
            SshEvent::HostKeyVerify {
                host,
                port,
                fingerprint,
                key_changed,
                reply,
            } => {
                self.close_pty_owner("host key decision pending");
                self.mode = Mode::HostKeyPrompt;
                self.status = "host key decision required".to_string();
                self.host_key_prompt = Some(HostKeyPrompt {
                    host,
                    port,
                    fingerprint,
                    key_changed,
                    reply: Some(reply),
                });
            }
            SshEvent::SftpReady(handle) => {
                self.sftp_handle = Some(handle);
                self.mode = Mode::Sftp;
                self.status = format!("sftp ready; listing {}", self.sftp_path);
                self.request_sftp_list();
            }
            SshEvent::SftpClosed => {
                self.sftp_handle = None;
                self.status = "sftp closed".to_string();
            }
            SshEvent::SftpError(message) => {
                self.status = safe_error_summary(&message);
            }
            SshEvent::ForwardStatusChanged { id, status } => {
                let label = forward_status_label(&status).to_string();
                self.update_forward_status(id, &label);
                self.status = format!("forwarding rule {id} status: {label}");
            }
            SshEvent::MetricsUpdate(metrics) => {
                self.metrics = Some(MetricsView::from_system(metrics));
                self.status = "metrics updated".to_string();
            }
            SshEvent::MetricsError(message) => {
                self.status = safe_error_summary(&message);
            }
        }
    }

    fn handle_key(&mut self, key: KeyEvent) {
        self.expire_pty_owner_if_needed();
        if is_escape_layer_key(key) {
            self.escape_armed = true;
            self.status =
                "escape: q quit, r reconnect, s sftp, f forwarding, m monitor, a agent-share, v revoke, ? help"
                    .to_string();
            return;
        }

        if self.escape_armed {
            self.handle_escape_key(key);
            return;
        }

        if self.mode == Mode::HostKeyPrompt {
            self.handle_host_key_key(key);
            return;
        }

        match self.mode {
            Mode::AgentOperationReview => {
                self.handle_assist_response_key(key);
                return;
            }
            Mode::Help => {
                self.mode = self.return_mode;
                self.status = format!("returned to {}", mode_label(self.mode));
                return;
            }
            _ => {}
        }

        match self.mode {
            Mode::Sftp => {
                self.handle_sftp_key(key);
                return;
            }
            Mode::Forwarding => {
                self.handle_forwarding_key(key);
                return;
            }
            Mode::Monitor => {
                self.handle_monitor_key(key);
                return;
            }
            Mode::Disconnected | Mode::Error => {
                self.handle_recovery_key(key);
                return;
            }
            _ => {}
        }

        if let Some(bytes) = key_to_pty_bytes(key) {
            self.write_human_pty_input(bytes);
        }
    }

    fn handle_paste(&mut self, text: &str) {
        self.expire_pty_owner_if_needed();
        if text.is_empty() || self.escape_armed || self.mode != Mode::Terminal {
            return;
        }

        self.write_human_pty_input(text.as_bytes().to_vec());
    }

    fn handle_escape_key(&mut self, key: KeyEvent) {
        self.escape_armed = false;
        match key.code {
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Char('r') => self.request_reconnect(),
            KeyCode::Char('s') => self.open_sftp(),
            KeyCode::Char('f') => self.open_forwarding(),
            KeyCode::Char('m') => self.open_monitor(),
            KeyCode::Char('a') => self.share_current_session_with_agent(),
            KeyCode::Char('v') => self.revoke_pty_control("human escape revoke"),
            KeyCode::Char('t') => {
                self.mode = Mode::Terminal;
                self.status = "returned to terminal".to_string();
            }
            KeyCode::Char('?') => self.show_help(),
            KeyCode::Esc => {
                self.status = "escape cancelled".to_string();
            }
            _ => {
                self.status = "unknown escape command".to_string();
            }
        }
    }

    fn handle_recovery_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Char('r') => self.request_reconnect(),
            KeyCode::Char('?') => self.show_help(),
            KeyCode::Esc => {
                self.status = "recovery: r reconnect, q quit, ? help".to_string();
            }
            _ => {
                self.status = "recovery: r reconnect, q quit, ? help".to_string();
            }
        }
    }

    fn show_help(&mut self) {
        self.return_mode = self.mode;
        self.mode = Mode::Help;
        self.status = "help".to_string();
    }

    /// Publish or refresh the current live SSH session for an external agent.
    ///
    /// Conversation stays in the external agent. Pressing `a` is the local
    /// operator's explicit consent to expose one bounded, redacted session view;
    /// later input requests still require local approval unless the operator
    /// grants this agent automatic control for the current TUI lifetime.
    fn share_current_session_with_agent(&mut self) {
        if let Some(request) = self.assist_request.as_ref()
            && !request.status.is_terminal()
        {
            let request_id = request.id.clone();
            self.refresh_shared_session_context(true);
            if self.assist_response.is_some() {
                if self.mode != Mode::AgentOperationReview {
                    self.return_mode = self.mode;
                }
                self.mode = Mode::AgentOperationReview;
                self.status = format!("agent operation request: {request_id}");
            } else {
                self.status = format!("SSH session shared with external agents: {request_id}");
            }
            return;
        }

        let return_mode = self.mode;
        let policy = AssistContextPolicy::default();
        let snapshot = match self.build_assist_snapshot(&policy) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                self.status = format!("session share failed: {error}");
                return;
            }
        };
        let now = Utc::now();
        let request_id = Self::next_assist_request_id();
        let mut request = match AssistRequest::new_context_share(
            request_id.clone(),
            "Shared live SSH session".to_string(),
            snapshot.binding.clone(),
            ActorRef {
                id: "human:ssh-tui".to_string(),
                actor_type: ActorType::Human,
            },
            None,
            policy,
            now,
            now + ChronoDuration::seconds(MAX_ASSIST_REQUEST_TTL_SECONDS),
        ) {
            Ok(request) => request,
            Err(error) => {
                self.status = format!("session share failed: {error}");
                return;
            }
        };
        request.preview = Some(snapshot.preview());
        request.requested_permissions = vec![AssistPermission::SuggestOnly];
        if let Err(error) = request.transition_to(AssistRequestStatus::Pending) {
            self.status = format!("session share failed: {error}");
            return;
        }
        if let Err(error) = self.assist_store.share(
            request.clone(),
            snapshot.clone(),
            Some(self.current_assist_terminal_state()),
        ) {
            self.status = format!("session share failed: {error}");
            return;
        }

        self.return_mode = return_mode;
        self.assist_request = Some(request);
        self.agent_auto_control = None;
        self.assist_response = None;
        self.assist_response_seen_id = None;
        self.assist_action_selected = 0;
        self.assist_last_context_refresh_at = Some(now);
        self.record_assist_audit(
            AssistAuditAction::Send,
            Some(AssistPermission::SuggestOnly),
            AssistControlAuditOutcome::Approved,
            "operator shared the current bounded SSH session view",
        );
        self.status = format!("SSH session shared with external agents: {request_id}");
    }

    fn handle_assist_response_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Down | KeyCode::Char('j') => self.move_assist_action_selection(1),
            KeyCode::Up | KeyCode::Char('k') => self.move_assist_action_selection(-1),
            KeyCode::Char('x') | KeyCode::Char('n') => self.deny_selected_assist_action(),
            KeyCode::Char('A') => self.allow_selected_agent_for_session(),
            KeyCode::Char('y') => self.confirm_selected_assist_action(),
            KeyCode::Esc | KeyCode::Char('q') | KeyCode::Enter => {
                self.mode = self.return_mode;
                self.status = "agent operation request retained".to_string();
            }
            KeyCode::Char('c') => {
                if let Some(request_id) = self
                    .assist_request
                    .as_ref()
                    .map(|request| request.id.clone())
                {
                    match self.assist_store.close(&request_id) {
                        Ok(record) => {
                            if let Some(request) = &mut self.assist_request {
                                request.status = record.request.status;
                            }
                            self.mode = self.return_mode;
                            self.record_assist_audit(
                                AssistAuditAction::Close,
                                None,
                                AssistControlAuditOutcome::Closed,
                                "session share closed from TUI",
                            );
                            self.status = "shared agent session closed".to_string();
                        }
                        Err(error) => {
                            self.status = format!("session share close failed: {error}");
                        }
                    }
                }
            }
            _ => {
                self.status =
                    "agent operation: j/k select, y approve once, A allow for session, n deny, c close"
                        .to_string();
            }
        }
    }

    fn move_assist_action_selection(&mut self, delta: isize) {
        let count = self
            .assist_response
            .as_ref()
            .map_or(0, |response| response.actions.len());
        if count == 0 {
            self.status = "agent operation request has no executable operations".to_string();
            return;
        }
        let current = self.assist_action_selected.min(count.saturating_sub(1)) as isize;
        self.assist_action_selected =
            (current + delta).clamp(0, count.saturating_sub(1) as isize) as usize;
        self.status = format!(
            "agent operation {} selected",
            self.assist_action_selected + 1
        );
    }

    fn selected_assist_action(&self) -> Option<(usize, AssistAction)> {
        let response = self.assist_response.as_ref()?;
        if response.actions.is_empty() {
            return None;
        }
        let index = self
            .assist_action_selected
            .min(response.actions.len().saturating_sub(1));
        response
            .actions
            .get(index)
            .cloned()
            .map(|action| (index, action))
    }

    fn confirm_selected_assist_action(&mut self) {
        let Some((index, action)) = self.selected_assist_action() else {
            self.status = "agent operation request has no executable operations".to_string();
            return;
        };
        if !assist_action_requires_confirmation(&action) {
            self.status = "guidance actions do not execute anything".to_string();
            return;
        }
        self.execute_confirmed_assist_action(index, action);
    }

    fn deny_selected_assist_action(&mut self) {
        let Some((index, action)) = self.selected_assist_action() else {
            self.status = "agent operation request has no operation to deny".to_string();
            return;
        };
        if let Err(error) = self.persist_assist_action_confirmation(
            index,
            &action,
            "denied_by_operator",
            "operation denied by local operator",
            None,
        ) {
            self.status = format!("operation denial failed: {error}");
            return;
        }
        self.record_assist_audit(
            AssistAuditAction::ApproveControl,
            assist_action_permission(&action),
            AssistControlAuditOutcome::Blocked,
            "operation denied by local operator",
        );
        self.mode = self.return_mode;
        self.status = "external agent operation denied".to_string();
    }

    fn allow_selected_agent_for_session(&mut self) {
        let Some((index, action)) = self.selected_assist_action() else {
            self.status = "agent operation request has no operation to approve".to_string();
            return;
        };
        let (command, binding) = match &action {
            AssistAction::ProposedCommand {
                command,
                target: AssistActionTarget::CurrentPty { binding },
                ..
            } => (command, binding),
            _ => {
                self.status =
                    "automatic session approval only applies to current PTY commands".to_string();
                return;
            }
        };
        if let Err(error) = self.validate_current_pty_takeover(command, binding) {
            self.record_assist_audit(
                AssistAuditAction::ApproveControl,
                Some(AssistPermission::TakeControl),
                AssistControlAuditOutcome::Blocked,
                &error,
            );
            self.status = format!("automatic session control blocked: {error}");
            return;
        }
        let Some(agent) = self
            .assist_response
            .as_ref()
            .map(|response| response.agent.clone())
        else {
            self.status = "agent identity is unavailable".to_string();
            return;
        };
        self.agent_auto_control = Some(agent.clone());
        self.record_assist_audit(
            AssistAuditAction::ApproveControl,
            Some(AssistPermission::TakeControl),
            AssistControlAuditOutcome::Approved,
            format!(
                "operator allowed current-session commands from {} until share expiry or revoke",
                agent.client_id
            ),
        );
        self.execute_confirmed_assist_action(index, action);
    }

    fn execute_confirmed_assist_action(&mut self, index: usize, action: AssistAction) {
        match action {
            AssistAction::Guidance { .. } => {
                self.status = "guidance action retained; no execution performed".to_string();
            }
            AssistAction::RequestPermission {
                permission,
                reason,
                ttl_seconds,
            } => self.confirm_assist_permission(index, permission, ttl_seconds, &reason),
            AssistAction::ProposedCommand {
                command,
                rationale,
                risk,
                target,
            } => match target {
                AssistActionTarget::CurrentPty { binding } => {
                    self.execute_current_pty_command(index, command, rationale, risk, binding);
                }
                AssistActionTarget::AgentSideSession { .. } => {
                    self.confirm_delegated_assist_action(
                        index,
                        &AssistAction::ProposedCommand {
                            command,
                            rationale,
                            risk,
                            target,
                        },
                        "confirmed_agent_side_command",
                        "agent-side session command confirmed; current PTY unchanged",
                    );
                }
                AssistActionTarget::Capability { .. } => {
                    self.confirm_delegated_assist_action(
                        index,
                        &AssistAction::ProposedCommand {
                            command,
                            rationale,
                            risk,
                            target,
                        },
                        "confirmed_capability_command",
                        "capability-targeted command confirmed; current PTY unchanged",
                    );
                }
                AssistActionTarget::HumanOnly => {
                    self.status = "human-only action noted; no automated execution".to_string();
                }
            },
            AssistAction::CapabilityCall {
                capability_id,
                input_summary,
                rationale,
                risk,
                target,
            } => {
                let action = AssistAction::CapabilityCall {
                    capability_id,
                    input_summary,
                    rationale,
                    risk,
                    target,
                };
                self.confirm_delegated_assist_action(
                    index,
                    &action,
                    "confirmed_capability_call",
                    "capability call confirmed for external agent execution; current PTY unchanged",
                );
            }
        }
    }

    fn confirm_assist_permission(
        &mut self,
        index: usize,
        permission: AssistPermission,
        ttl_seconds: u64,
        reason: &str,
    ) {
        let expires_at = Utc::now()
            + ChronoDuration::seconds(
                ttl_seconds.clamp(1, DEFAULT_ASSIST_CONTROL_TTL_SECONDS) as i64
            );
        let action = AssistAction::RequestPermission {
            permission,
            reason: reason.to_string(),
            ttl_seconds,
        };
        if let Err(error) = self.persist_assist_action_confirmation(
            index,
            &action,
            "approved_permission",
            reason,
            Some(expires_at),
        ) {
            self.status = format!("agent permission confirmation failed: {error}");
            return;
        }
        self.mode = self.return_mode;

        match permission {
            AssistPermission::TakeControl => {
                if let Err(error) = self.grant_agent_control(index, Some(expires_at), reason) {
                    self.status = error;
                    return;
                }
                self.status =
                    "agent has current PTY input control; Ctrl+] then v revokes".to_string();
            }
            AssistPermission::AgentSideInspect => {
                self.set_agent_observe_if_requested();
                self.record_assist_audit(
                    AssistAuditAction::Inspect,
                    Some(permission),
                    AssistControlAuditOutcome::Approved,
                    "agent-side inspection permission confirmed",
                );
                self.status =
                    "agent-side inspection confirmed; current PTY remains human-owned".to_string();
            }
            AssistPermission::ProposeCommands => {
                self.record_assist_audit(
                    AssistAuditAction::Propose,
                    Some(permission),
                    AssistControlAuditOutcome::Approved,
                    "proposed command permission confirmed",
                );
                self.status =
                    "agent may propose commands; execution still requires local y approval"
                        .to_string();
            }
            AssistPermission::SuggestOnly => {
                self.status = "suggest-only permission requires no approval".to_string();
            }
        }
    }

    fn confirm_delegated_assist_action(
        &mut self,
        index: usize,
        action: &AssistAction,
        status: &str,
        note: &str,
    ) {
        if let Err(error) =
            self.persist_assist_action_confirmation(index, action, status, note, None)
        {
            self.status = format!("agent operation confirmation failed: {error}");
            return;
        }
        self.mode = self.return_mode;
        self.record_assist_audit(
            AssistAuditAction::Propose,
            assist_action_permission(action),
            AssistControlAuditOutcome::Delegated,
            note,
        );
        self.status = note.to_string();
    }

    fn execute_current_pty_command(
        &mut self,
        index: usize,
        command: String,
        rationale: String,
        risk: voidb_core::AssistActionRisk,
        binding: AssistSessionBinding,
    ) {
        let terminal_state_warning = self.current_pty_terminal_state_warning();
        if let Err(error) = self.validate_current_pty_takeover(&command, &binding) {
            self.record_assist_audit(
                AssistAuditAction::ApproveControl,
                Some(AssistPermission::TakeControl),
                AssistControlAuditOutcome::Blocked,
                &error,
            );
            self.status = format!("current PTY control blocked: {error}");
            return;
        }

        let expires_at =
            Utc::now() + ChronoDuration::seconds(DEFAULT_ASSIST_CONTROL_TTL_SECONDS as i64);
        let action = AssistAction::ProposedCommand {
            command: command.clone(),
            rationale,
            risk,
            target: AssistActionTarget::CurrentPty { binding },
        };
        let confirmation_note = terminal_state_warning
            .as_ref()
            .map(|warning| {
                format!(
                    "operator approved PTY input after reviewing terminal-state warning: {warning}"
                )
            })
            .unwrap_or_else(|| "current PTY command confirmed by human".to_string());
        if let Err(error) = self.persist_assist_action_confirmation(
            index,
            &action,
            "executed_current_pty",
            &confirmation_note,
            Some(expires_at),
        ) {
            self.status = format!("agent operation confirmation failed: {error}");
            return;
        }
        self.mode = self.return_mode;
        if let Err(error) = self.grant_agent_control(index, Some(expires_at), &confirmation_note) {
            self.status = error;
            return;
        }

        let mut bytes = command.trim_end_matches(['\r', '\n']).as_bytes().to_vec();
        bytes.push(b'\r');
        if self.write_agent_pty_input(bytes) {
            self.record_assist_audit(
                AssistAuditAction::Propose,
                Some(AssistPermission::TakeControl),
                AssistControlAuditOutcome::Executed,
                &confirmation_note,
            );
            self.status = if terminal_state_warning.is_some() {
                "confirmed input sent after operator accepted terminal-state warning; agent owns PTY input until TTL or revoke"
                    .to_string()
            } else {
                "confirmed command sent; agent owns PTY input until TTL or revoke".to_string()
            };
        }
    }

    fn persist_assist_action_confirmation(
        &mut self,
        index: usize,
        action: &AssistAction,
        status: &str,
        note: &str,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<()> {
        let request_id = self
            .assist_request
            .as_ref()
            .map(|request| request.id.clone())
            .context("no active session share")?;
        let response_id = self
            .assist_response
            .as_ref()
            .map(|response| response.id.clone())
            .context("no active agent operation request")?;
        let descriptor = self.current_assist_descriptor();
        let (command_summary, command_redaction) = match assist_action_command_summary(action) {
            Some(summary) => {
                let (summary, redaction) = self.redact_assist_text(&summary);
                (Some(safe_inline(&summary, 160)), redaction)
            }
            None => (None, RedactionStatus::NotRequired),
        };
        let confirmation = SshAssistActionConfirmation {
            request_id: request_id.clone(),
            response_id,
            action_index: index,
            target: assist_action_target_label(action),
            uses_current_pty: assist_action_uses_current_pty(action),
            generation: descriptor.generation,
            confirmed_at: Utc::now(),
            expires_at,
            command_summary,
            capability_id: assist_action_capability_id(action),
            status: status.to_string(),
            note: safe_inline(note, 240),
            redaction: command_redaction,
        };
        self.assist_store
            .confirm_action(&request_id, confirmation)
            .map(|_| ())
    }

    fn current_pty_terminal_state_warning(&self) -> Option<String> {
        let screen = self.terminal_parser.screen();
        let mut modes = Vec::new();
        if screen.alternate_screen() {
            modes.push("alternate-screen");
        }
        if screen.application_keypad() {
            modes.push("application-keypad");
        }
        if screen.application_cursor() {
            modes.push("application-cursor");
        }
        (!modes.is_empty()).then(|| format!("PTY reports {} mode", modes.join(", ")))
    }

    fn validate_current_pty_takeover(
        &self,
        command: &str,
        binding: &AssistSessionBinding,
    ) -> Result<(), String> {
        if self.readonly {
            return Err("readonly SSH TUI blocks current PTY control".to_string());
        }
        if command.trim().is_empty() {
            return Err("proposed command is empty".to_string());
        }
        if command.len() > ASSIST_CONTROL_COMMAND_LIMIT_BYTES {
            return Err(format!(
                "proposed command exceeds {ASSIST_CONTROL_COMMAND_LIMIT_BYTES} bytes"
            ));
        }
        if command.contains('\n') || command.contains('\r') {
            return Err("multi-line commands must run in an agent-side session".to_string());
        }
        if self.host_key_prompt.is_some()
            || matches!(self.mode, Mode::HostKeyPrompt)
            || matches!(self.return_mode, Mode::HostKeyPrompt)
        {
            return Err("host-key prompts block current PTY takeover".to_string());
        }
        if matches!(self.mode, Mode::Disconnected | Mode::Error)
            || matches!(self.return_mode, Mode::Disconnected | Mode::Error)
        {
            return Err("disconnected or failed sessions block current PTY takeover".to_string());
        }
        binding
            .validate_current(&self.current_assist_descriptor())
            .map_err(|error| format!("shared session binding is not current: {error}"))?;
        if self.pending_local_input_bytes > 0 {
            return Err(format!(
                "{} bytes of local input are still pending",
                self.pending_local_input_bytes
            ));
        }
        if self.retained_terminal_output_bytes() > DEFAULT_ASSIST_OUTPUT_LIMIT_BYTES {
            return Err(format!(
                "retained terminal output exceeds {DEFAULT_ASSIST_OUTPUT_LIMIT_BYTES} bytes"
            ));
        }
        if self.has_password_like_prompt() {
            return Err("password-like prompt blocks current PTY takeover".to_string());
        }

        let now = Utc::now();
        let active_request_id = self
            .assist_request
            .as_ref()
            .map(|request| request.id.as_str());
        match &self.pty_input_owner {
            PtyInputOwnerState::HumanActive => {}
            PtyInputOwnerState::AgentObserve { request_id, .. } => {
                if Some(request_id.as_str()) != active_request_id {
                    return Err("another context share is observing this PTY".to_string());
                }
            }
            PtyInputOwnerState::AgentControl {
                request_id,
                expires_at,
                ..
            } => {
                if now < *expires_at && Some(request_id.as_str()) != active_request_id {
                    return Err("another agent already owns current PTY input".to_string());
                }
            }
            PtyInputOwnerState::Revoking { .. } => {
                return Err("current PTY control is being revoked".to_string());
            }
            PtyInputOwnerState::Closed { reason } => {
                return Err(format!("current PTY input is closed: {reason}"));
            }
        }
        Ok(())
    }

    fn grant_agent_control(
        &mut self,
        action_index: usize,
        expires_at: Option<DateTime<Utc>>,
        reason: &str,
    ) -> Result<(), String> {
        let request_id = self
            .assist_request
            .as_ref()
            .map(|request| request.id.clone())
            .ok_or_else(|| "no active session share".to_string())?;
        let response = self
            .assist_response
            .as_ref()
            .ok_or_else(|| "no active agent operation request".to_string())?;
        let response_id = response.id.clone();
        let agent_label = response.agent.client_id.clone();
        let generation = self.current_assist_descriptor().generation;
        let expires_at = expires_at.unwrap_or_else(|| {
            Utc::now() + ChronoDuration::seconds(DEFAULT_ASSIST_CONTROL_TTL_SECONDS as i64)
        });
        self.pty_input_owner = PtyInputOwnerState::AgentControl {
            request_id,
            response_id,
            agent_label,
            generation,
            action_index,
            expires_at,
        };
        self.record_assist_audit(
            AssistAuditAction::ApproveControl,
            Some(AssistPermission::TakeControl),
            AssistControlAuditOutcome::Approved,
            reason,
        );
        Ok(())
    }

    fn set_agent_observe_if_requested(&mut self) {
        let Some(response) = self.assist_response.as_ref() else {
            return;
        };
        if !operation_requests_agent_side_inspection(response) {
            return;
        }
        if !matches!(self.pty_input_owner, PtyInputOwnerState::HumanActive) {
            return;
        }
        let Some(request) = self.assist_request.as_ref() else {
            return;
        };
        self.pty_input_owner = PtyInputOwnerState::AgentObserve {
            request_id: request.id.clone(),
            response_id: response.id.clone(),
            generation: self.current_assist_descriptor().generation,
        };
        self.record_assist_audit(
            AssistAuditAction::Inspect,
            Some(AssistPermission::AgentSideInspect),
            AssistControlAuditOutcome::Requested,
            "agent-side inspection requested; current PTY unchanged",
        );
    }

    fn write_human_pty_input(&mut self, bytes: Vec<u8>) {
        let now = Utc::now();
        if !self.pty_input_owner.allows_human_input(now) {
            self.dropped_pty_input_bytes += bytes.len();
            self.record_assist_audit(
                AssistAuditAction::Revoke,
                Some(AssistPermission::TakeControl),
                AssistControlAuditOutcome::Dropped,
                "human PTY input dropped while agent owns input",
            );
            self.status =
                "agent owns PTY input; press Ctrl+] then v to revoke before typing".to_string();
            return;
        }
        self.pending_local_input_bytes = self.pending_local_input_bytes.saturating_add(bytes.len());
        self.write_current_pty_bytes(bytes, PtyInputWriter::Human);
    }

    fn write_agent_pty_input(&mut self, bytes: Vec<u8>) -> bool {
        self.expire_pty_owner_if_needed();
        let now = Utc::now();
        let can_write = matches!(
            &self.pty_input_owner,
            PtyInputOwnerState::AgentControl { expires_at, .. } if now < *expires_at
        );
        if !can_write {
            self.dropped_pty_input_bytes += bytes.len();
            self.record_assist_audit(
                AssistAuditAction::ApproveControl,
                Some(AssistPermission::TakeControl),
                AssistControlAuditOutcome::Dropped,
                "agent PTY input dropped because control is not active",
            );
            self.status = "agent PTY input dropped; control is not active".to_string();
            return false;
        }
        self.write_current_pty_bytes(bytes, PtyInputWriter::Agent);
        true
    }

    fn write_current_pty_bytes(&mut self, bytes: Vec<u8>, _writer: PtyInputWriter) {
        #[cfg(test)]
        self.forwarded_pty_writes.push(bytes.clone());
        if let Some(service) = &self.service {
            service.send_pty_input(bytes);
        } else {
            self.push_terminal_output(&bytes);
        }
    }

    fn expire_pty_owner_if_needed(&mut self) -> bool {
        let now = Utc::now();
        let expired = match &self.pty_input_owner {
            PtyInputOwnerState::AgentControl {
                request_id,
                generation,
                expires_at,
                ..
            } if now >= *expires_at => Some((request_id.clone(), *generation)),
            _ => None,
        };
        let Some((request_id, generation)) = expired else {
            return false;
        };
        self.pty_input_owner = PtyInputOwnerState::HumanActive;
        self.pending_local_input_bytes = 0;
        self.record_assist_audit(
            AssistAuditAction::Expire,
            Some(AssistPermission::TakeControl),
            AssistControlAuditOutcome::Expired,
            format!("agent PTY control expired for {request_id} generation {generation}"),
        );
        self.status = "agent PTY control expired; human input restored".to_string();
        true
    }

    fn revoke_pty_control(&mut self, reason: &str) {
        self.expire_pty_owner_if_needed();
        let auto_control_revoked = self.agent_auto_control.take().is_some();
        let Some(request_id) = self
            .pty_input_owner
            .request_id()
            .map(std::borrow::ToOwned::to_owned)
        else {
            self.status = if auto_control_revoked {
                "automatic agent session control revoked".to_string()
            } else {
                "no agent PTY ownership to revoke".to_string()
            };
            return;
        };
        let generation = self.current_assist_descriptor().generation;
        self.pty_input_owner = PtyInputOwnerState::Revoking {
            request_id,
            generation,
            reason: reason.to_string(),
        };
        self.pending_local_input_bytes = 0;
        self.record_assist_audit(
            AssistAuditAction::Revoke,
            Some(AssistPermission::TakeControl),
            AssistControlAuditOutcome::Revoked,
            reason,
        );
        self.pty_input_owner = PtyInputOwnerState::HumanActive;
        self.status = "agent PTY ownership revoked; human input restored".to_string();
    }

    fn close_pty_owner(&mut self, reason: &str) {
        if !matches!(self.pty_input_owner, PtyInputOwnerState::HumanActive) {
            self.record_assist_audit(
                AssistAuditAction::Close,
                Some(AssistPermission::TakeControl),
                AssistControlAuditOutcome::Closed,
                reason,
            );
        }
        self.pty_input_owner = PtyInputOwnerState::Closed {
            reason: reason.to_string(),
        };
        self.pending_local_input_bytes = 0;
    }

    fn record_assist_audit(
        &mut self,
        action: AssistAuditAction,
        permission: Option<AssistPermission>,
        outcome: AssistControlAuditOutcome,
        detail: impl AsRef<str>,
    ) {
        let Some(request) = self.assist_request.as_ref() else {
            return;
        };
        let mut projection = AssistAuditProjection::from_request(action, request, Utc::now());
        projection.permission = permission;
        let detail = safe_inline(detail.as_ref(), 180);
        tracing::info!(
            target: "voidb_ssh_assist",
            operation = projection.action.operation_name(),
            request_id = %projection.request_id,
            outcome = ?outcome,
            detail = %detail
        );
        self.assist_control_audit.push(AssistControlAuditEntry {
            projection,
            outcome,
            detail,
        });
    }

    fn retained_terminal_output_bytes(&self) -> usize {
        self.terminal_lines
            .iter()
            .map(|line| line.len().saturating_add(1))
            .sum()
    }

    fn has_password_like_prompt(&self) -> bool {
        contains_password_like_prompt(&self.status)
            || contains_password_like_prompt(
                &self
                    .terminal_screen_text_lines(self.terminal_size.cols)
                    .join("\n"),
            )
    }

    fn next_assist_request_id() -> String {
        format!("assist:session:{}", uuid::Uuid::new_v4())
    }

    fn sync_agent_operation_request(&mut self) -> bool {
        let Some(request) = self.assist_request.clone() else {
            return false;
        };
        if request.status.is_terminal() {
            return false;
        }
        self.refresh_shared_session_context(false);
        let Ok(record) = self.assist_store.read_record(&request.id) else {
            return false;
        };
        if let Some(active) = self.assist_request.as_mut() {
            active.status = record.request.status;
            active.external_agent = record.request.external_agent.clone();
        }
        if record.request.status.is_terminal() {
            self.agent_auto_control = None;
            self.status = format!("shared agent session status: {:?}", record.request.status);
            return true;
        }
        let Some(response) = record.latest_operation_request().cloned() else {
            return false;
        };
        if self.assist_response_seen_id.as_deref() == Some(response.id.as_str()) {
            return false;
        }
        if let Some(active) = self.assist_request.as_mut() {
            active.status = AssistRequestStatus::Responded;
            active.external_agent = Some(response.agent.clone());
        }
        self.assist_response_seen_id = Some(response.id.clone());
        let auto_action = if self.agent_auto_control.as_ref() == Some(&response.agent)
            && response.actions.len() == 1
        {
            response.actions.first().cloned().filter(|action| {
                matches!(
                    action,
                    AssistAction::ProposedCommand {
                        target: AssistActionTarget::CurrentPty { .. },
                        ..
                    }
                )
            })
        } else {
            None
        };
        self.assist_response = Some(response);
        self.assist_action_selected = 0;
        self.set_agent_observe_if_requested();
        if let Some(action) = auto_action {
            self.execute_confirmed_assist_action(0, action);
            if self.mode == Mode::AgentOperationReview {
                self.mode = self.return_mode;
            }
        } else {
            if self.mode != Mode::AgentOperationReview {
                self.return_mode = self.mode;
            }
            self.mode = Mode::AgentOperationReview;
            self.status = "external agent requests an operation on this session".to_string();
        }
        true
    }

    fn refresh_shared_session_context(&mut self, force: bool) {
        let Some(request) = self.assist_request.as_ref() else {
            return;
        };
        if request.status.is_terminal() {
            return;
        }
        let now = Utc::now();
        if !force
            && self
                .assist_last_context_refresh_at
                .is_some_and(|last| (now - last) < ChronoDuration::milliseconds(250))
        {
            return;
        }
        let request_id = request.id.clone();
        let snapshot = match self.build_assist_snapshot(&AssistContextPolicy::default()) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                tracing::debug!(
                    target: "voidb_ssh_assist",
                    request_id = %request_id,
                    error = %error,
                    "failed to refresh shared SSH session context"
                );
                return;
            }
        };
        let terminal_state = self.current_assist_terminal_state();
        match self
            .assist_store
            .update_context(&request_id, snapshot.clone(), terminal_state)
        {
            Ok(record) => {
                if let Some(active) = self.assist_request.as_mut() {
                    active.status = record.request.status;
                    active.preview = Some(snapshot.preview());
                }
                self.assist_last_context_refresh_at = Some(now);
            }
            Err(error) => {
                tracing::debug!(
                    target: "voidb_ssh_assist",
                    request_id = %request_id,
                    error = %error,
                    "failed to persist shared SSH session context"
                );
            }
        }
    }

    fn current_assist_terminal_state(&self) -> SshAssistTerminalState {
        let (status, redaction) = self.redact_assist_text(&self.status);
        SshAssistTerminalState {
            mode: mode_label(self.mode).to_string(),
            health: self.assist_health(),
            status,
            updated_at: Utc::now(),
            redaction,
        }
    }

    fn request_reconnect(&mut self) {
        if let Some(service) = &self.service {
            service.send(SshCommand::Reconnect);
            self.status = "reconnect requested".to_string();
        } else {
            self.status = "fixture reconnect requested".to_string();
            self.push_line("[local] fixture reconnect requested");
        }
    }

    fn clear_session_subsystems(&mut self) {
        self.sftp_handle = None;
        self.transfer_plan = None;
        self.forward_plan = None;
        self.metrics_started = false;
    }

    fn handle_host_key_key(&mut self, key: KeyEvent) {
        let Some(prompt) = &mut self.host_key_prompt else {
            return;
        };

        match key.code {
            KeyCode::Char('a') => {
                if let Some(reply) = prompt.reply.take() {
                    let _ = reply.send(true);
                }
                self.mode = Mode::Terminal;
                self.status = "host key accepted for this SSH session".to_string();
                self.push_line("[local] host key accepted");
                self.host_key_prompt = None;
            }
            KeyCode::Char('r') | KeyCode::Esc => {
                if let Some(reply) = prompt.reply.take() {
                    let _ = reply.send(false);
                }
                self.mode = Mode::Disconnected;
                self.status = "host key rejected; session closed before authentication".to_string();
                self.push_line("[local] host key rejected");
                self.host_key_prompt = None;
            }
            _ => {
                self.status = "host key prompt requires a=accept or r=reject".to_string();
            }
        }
    }

    fn handle_resize(&mut self, cols: u16, rows: u16) {
        let size = terminal_grid_size_for_area(Rect::new(0, 0, cols, rows));
        self.set_terminal_size(size);
        self.status = format!("resized PTY to {}x{}", size.cols, size.rows);
    }

    fn open_sftp(&mut self) {
        self.mode = Mode::Sftp;
        if self.service.is_none() {
            self.status = format!("fixture sftp browser at {}", self.sftp_path);
            return;
        }

        if self.sftp_handle.is_some() {
            self.request_sftp_list();
        } else if let Some(service) = &self.service {
            service.send(SshCommand::Sftp(SftpServiceCommand::Open));
            self.status = "opening sftp subsystem".to_string();
        }
    }

    fn request_sftp_list(&mut self) {
        if let Some(handle) = &self.sftp_handle {
            handle.send(SftpCommand::ListDir(self.sftp_path.clone()));
            self.status = format!("listing {}", self.sftp_path);
        } else if self.service.is_none() {
            self.status = format!(
                "fixture directory {} has {} entries",
                self.sftp_path,
                self.sftp_entries.len()
            );
        } else {
            self.status = "sftp subsystem is not ready".to_string();
        }
    }

    fn handle_sftp_event(&mut self, event: SftpEvent) {
        match event {
            SftpEvent::DirListed { path, entries } => {
                self.sftp_path = path;
                self.sftp_entries = entries.into_iter().map(SftpEntryView::from).collect();
                self.sftp_entries.sort_by(sftp_entry_sort);
                self.sftp_selected = self
                    .sftp_selected
                    .min(self.sftp_entries.len().saturating_sub(1));
                self.status = format!(
                    "listed {} entries in {}",
                    self.sftp_entries.len(),
                    self.sftp_path
                );
            }
            SftpEvent::Error(message) => {
                self.status = safe_error_summary(&message);
                if let Some(plan) = &mut self.transfer_plan {
                    plan.progress = None;
                }
            }
            SftpEvent::DownloadProgress {
                remote,
                transferred,
                total,
            } => {
                self.set_transfer_progress(remote, transferred, total);
                self.status = format!("download {}", format_progress(transferred, total));
            }
            SftpEvent::DownloadComplete { remote: _, local } => {
                self.status = format!("download complete: {local}");
                self.transfer_plan = None;
            }
            SftpEvent::UploadProgress {
                local,
                transferred,
                total,
            } => {
                self.set_transfer_progress(local, transferred, total);
                self.status = format!("upload {}", format_progress(transferred, total));
            }
            SftpEvent::UploadComplete { local, remote: _ } => {
                self.status = format!("upload complete: {local}");
                self.transfer_plan = None;
                self.request_sftp_list();
            }
            SftpEvent::OperationComplete(message) => {
                self.status = message;
                self.transfer_plan = None;
                self.request_sftp_list();
            }
            SftpEvent::TransferCancelled => {
                self.status = "transfer cancelled".to_string();
                self.transfer_plan = None;
            }
        }
    }

    fn handle_sftp_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => self.move_sftp_selection(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_sftp_selection(1),
            KeyCode::Home | KeyCode::Char('g') => self.sftp_selected = 0,
            KeyCode::End | KeyCode::Char('G') => {
                self.sftp_selected = self.sftp_entries.len().saturating_sub(1);
            }
            KeyCode::Enter => self.open_selected_sftp_entry(),
            KeyCode::Backspace => {
                self.sftp_path = remote_parent_path(&self.sftp_path);
                self.sftp_selected = 0;
                self.request_sftp_list();
            }
            KeyCode::Char('r') | KeyCode::F(5) => self.request_sftp_list(),
            KeyCode::Char('d') => self.plan_download(),
            KeyCode::Char('u') => self.plan_upload(),
            KeyCode::Char('x') | KeyCode::Delete => self.plan_delete(),
            KeyCode::Char('y') => self.confirm_sftp_plan(),
            KeyCode::Char('c') => self.cancel_sftp_plan(),
            KeyCode::Char('f') => self.open_forwarding(),
            KeyCode::Char('m') => self.open_monitor(),
            KeyCode::Char('t') => {
                self.mode = Mode::Terminal;
                self.status = "returned to terminal".to_string();
            }
            KeyCode::Char('?') => self.show_help(),
            KeyCode::Esc => {
                if self.transfer_plan.is_some() {
                    self.cancel_sftp_plan();
                } else {
                    self.mode = Mode::Terminal;
                    self.status = "returned to terminal".to_string();
                }
            }
            _ => {
                self.status =
                    "sftp: j/k navigate, Enter open, d download, u upload, x delete".to_string();
            }
        }
    }

    fn move_sftp_selection(&mut self, delta: isize) {
        if self.sftp_entries.is_empty() {
            self.sftp_selected = 0;
            return;
        }
        let last = self.sftp_entries.len() as isize - 1;
        let next = (self.sftp_selected as isize + delta).clamp(0, last);
        self.sftp_selected = next as usize;
    }

    fn open_selected_sftp_entry(&mut self) {
        let Some(entry) = self.selected_sftp_entry().cloned() else {
            self.status = "sftp directory is empty".to_string();
            return;
        };

        if entry.is_dir {
            self.sftp_path = remote_child_path(&self.sftp_path, &entry.name);
            self.sftp_selected = 0;
            self.request_sftp_list();
        } else {
            self.status = format!("selected {}; press d to plan download", entry.name);
        }
    }

    fn selected_sftp_entry(&self) -> Option<&SftpEntryView> {
        self.sftp_entries.get(self.sftp_selected)
    }

    fn plan_download(&mut self) {
        let Some(entry) = self.selected_sftp_entry().cloned() else {
            self.status = "no remote file selected".to_string();
            return;
        };
        if entry.is_dir {
            self.status = "download planning requires a file selection".to_string();
            return;
        }

        let remote = remote_child_path(&self.sftp_path, &entry.name);
        let local = planned_download_path(&entry.name).display().to_string();
        self.transfer_plan = Some(TransferPlanView {
            kind: TransferKind::Download,
            remote: remote.clone(),
            local: Some(local.clone()),
            confirmed: false,
            progress: None,
        });
        self.status = format!("download plan staged: {remote} -> {local}; press y to execute");
    }

    fn plan_upload(&mut self) {
        self.transfer_plan = Some(TransferPlanView {
            kind: TransferKind::Upload,
            remote: self.sftp_path.clone(),
            local: Some("<choose-local-file>".to_string()),
            confirmed: false,
            progress: None,
        });
        self.status =
            "upload plan staged; local path picker is required before execution".to_string();
    }

    fn plan_delete(&mut self) {
        let Some(entry) = self.selected_sftp_entry().cloned() else {
            self.status = "no remote entry selected".to_string();
            return;
        };
        let kind = if entry.is_dir {
            TransferKind::DeleteDir
        } else {
            TransferKind::DeleteFile
        };
        let remote = remote_child_path(&self.sftp_path, &entry.name);
        self.transfer_plan = Some(TransferPlanView {
            kind,
            remote: remote.clone(),
            local: None,
            confirmed: false,
            progress: None,
        });
        self.status = format!("delete plan staged for {remote}; press y twice to execute");
    }

    fn confirm_sftp_plan(&mut self) {
        let Some(mut plan) = self.transfer_plan.take() else {
            self.status = "no transfer plan to confirm".to_string();
            return;
        };

        if self.readonly {
            plan.confirmed = true;
            self.status = "readonly launch keeps transfer plan non-executing".to_string();
            self.transfer_plan = Some(plan);
            return;
        }

        if plan.is_destructive() && !plan.confirmed {
            plan.confirmed = true;
            self.status = "destructive plan armed; press y again to execute".to_string();
            self.transfer_plan = Some(plan);
            return;
        }

        match plan.kind {
            TransferKind::Download => {
                let Some(local) = plan.local.clone() else {
                    self.status = "download plan has no local target".to_string();
                    self.transfer_plan = Some(plan);
                    return;
                };
                if let Err(message) = ensure_local_parent(&local) {
                    self.status = message;
                    self.transfer_plan = Some(plan);
                    return;
                }
                if let Some(handle) = &self.sftp_handle {
                    handle.send(SftpCommand::DownloadFile {
                        remote: plan.remote.clone(),
                        local: local.clone(),
                    });
                    plan.confirmed = true;
                    plan.progress = Some(TransferProgressView {
                        label: plan.remote.clone(),
                        transferred: 0,
                        total: 0,
                    });
                    self.status = format!("download started: {}", plan.remote);
                    self.transfer_plan = Some(plan);
                } else {
                    plan.confirmed = true;
                    plan.progress = Some(TransferProgressView {
                        label: plan.remote.clone(),
                        transferred: 1,
                        total: 1,
                    });
                    self.status = format!("fixture download complete: {local}");
                    self.transfer_plan = Some(plan);
                }
            }
            TransferKind::Upload => {
                let local = plan.local.clone().unwrap_or_default();
                if local == "<choose-local-file>" {
                    plan.confirmed = true;
                    self.status = "upload execution requires an explicit local path; plan retained"
                        .to_string();
                    self.transfer_plan = Some(plan);
                    return;
                }
                if let Some(handle) = &self.sftp_handle {
                    handle.send(SftpCommand::UploadFile {
                        local,
                        remote_dir: plan.remote.clone(),
                    });
                    plan.confirmed = true;
                    self.status = format!("upload started into {}", plan.remote);
                    self.transfer_plan = Some(plan);
                } else {
                    plan.confirmed = true;
                    self.status = "fixture upload plan confirmed".to_string();
                    self.transfer_plan = Some(plan);
                }
            }
            TransferKind::DeleteFile => {
                if let Some(handle) = &self.sftp_handle {
                    handle.send(SftpCommand::DeleteFile(plan.remote.clone()));
                } else {
                    self.remove_fixture_entry(&plan.remote);
                }
                self.status = format!("delete file requested: {}", plan.remote);
                self.transfer_plan = None;
            }
            TransferKind::DeleteDir => {
                if let Some(handle) = &self.sftp_handle {
                    handle.send(SftpCommand::DeleteDir(plan.remote.clone()));
                } else {
                    self.remove_fixture_entry(&plan.remote);
                }
                self.status = format!("delete directory requested: {}", plan.remote);
                self.transfer_plan = None;
            }
        }
    }

    fn cancel_sftp_plan(&mut self) {
        if let Some(handle) = &self.sftp_handle {
            handle.cancel_transfer();
            handle.send(SftpCommand::CancelTransfer);
        }
        self.transfer_plan = None;
        self.status = "transfer plan cancelled".to_string();
    }

    fn set_transfer_progress(&mut self, label: String, transferred: u64, total: u64) {
        if let Some(plan) = &mut self.transfer_plan {
            plan.progress = Some(TransferProgressView {
                label,
                transferred,
                total,
            });
        }
    }

    fn remove_fixture_entry(&mut self, remote: &str) {
        let name = remote
            .rsplit('/')
            .find(|part| !part.is_empty())
            .unwrap_or(remote);
        self.sftp_entries.retain(|entry| entry.name != name);
        self.sftp_selected = self
            .sftp_selected
            .min(self.sftp_entries.len().saturating_sub(1));
    }

    fn open_forwarding(&mut self) {
        self.mode = Mode::Forwarding;
        self.status =
            "forwarding: l local, r remote, d dynamic, y start plan, x stop selected".to_string();
    }

    fn handle_forwarding_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Up | KeyCode::Char('k') => self.move_forward_selection(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_forward_selection(1),
            KeyCode::Char('l') => self.plan_forward(ForwardType::Local {
                bind_addr: "127.0.0.1".to_string(),
                bind_port: 18080,
                remote_host: "localhost".to_string(),
                remote_port: 80,
            }),
            KeyCode::Char('r') => self.plan_forward(ForwardType::Remote {
                remote_addr: "127.0.0.1".to_string(),
                remote_port: 18080,
                local_host: "127.0.0.1".to_string(),
                local_port: 8080,
            }),
            KeyCode::Char('d') => self.plan_forward(ForwardType::Dynamic {
                bind_addr: "127.0.0.1".to_string(),
                bind_port: 18081,
            }),
            KeyCode::Char('y') => self.confirm_forward_plan(),
            KeyCode::Char('x') | KeyCode::Delete => self.stop_selected_forward(),
            KeyCode::Char('s') => self.open_sftp(),
            KeyCode::Char('m') => self.open_monitor(),
            KeyCode::Char('t') | KeyCode::Esc => {
                self.mode = Mode::Terminal;
                self.status = "returned to terminal".to_string();
            }
            KeyCode::Char('?') => self.show_help(),
            _ => {
                self.status =
                    "forwarding: j/k navigate, l/r/d plan, y start, x stop selected".to_string();
            }
        }
    }

    fn move_forward_selection(&mut self, delta: isize) {
        if self.forward_rules.is_empty() {
            self.forward_selected = 0;
            return;
        }
        let last = self.forward_rules.len() as isize - 1;
        let next = (self.forward_selected as isize + delta).clamp(0, last);
        self.forward_selected = next as usize;
    }

    fn plan_forward(&mut self, forward_type: ForwardType) {
        let summary = forward_type.summary();
        self.forward_plan = Some(ForwardPlanView {
            forward_type,
            confirmed: false,
        });
        self.status = format!("forward plan staged: {summary}; press y to start");
    }

    fn confirm_forward_plan(&mut self) {
        let Some(mut plan) = self.forward_plan.take() else {
            self.status = "no forwarding plan to confirm".to_string();
            return;
        };

        if self.readonly {
            plan.confirmed = true;
            self.status = "readonly launch keeps forwarding plan non-executing".to_string();
            self.forward_plan = Some(plan);
            return;
        }

        if let Some(service) = &self.service {
            service.send(SshCommand::Forward(ForwardServiceCommand::Add(
                plan.forward_type.clone(),
            )));
            plan.confirmed = true;
            self.status = format!("forward start requested: {}", plan.forward_type.summary());
            self.forward_plan = Some(plan);
        } else {
            let id = self.next_fixture_forward_id();
            self.forward_rules.push(ForwardRuleView {
                id,
                kind: plan.forward_type.type_label().to_string(),
                summary: plan.forward_type.summary(),
                status: "active".to_string(),
                bytes_sent: 0,
                bytes_received: 0,
                active_connections: 0,
                total_connections: 0,
            });
            self.forward_selected = self.forward_rules.len().saturating_sub(1);
            self.status = format!("fixture forward rule {id} active");
        }
    }

    fn stop_selected_forward(&mut self) {
        let Some(rule) = self.forward_rules.get_mut(self.forward_selected) else {
            self.status = "no forwarding rule selected".to_string();
            return;
        };
        if let Some(service) = &self.service {
            service.send(SshCommand::Forward(ForwardServiceCommand::Remove(rule.id)));
            self.status = format!("forward stop requested: rule {}", rule.id);
        } else {
            rule.status = "stopped".to_string();
            self.status = format!("fixture forward rule {} stopped", rule.id);
        }
    }

    fn update_forward_status(&mut self, id: u32, status: &str) {
        if let Some(rule) = self.forward_rules.iter_mut().find(|rule| rule.id == id) {
            rule.status = status.to_string();
            return;
        }

        self.forward_rules.push(ForwardRuleView {
            id,
            kind: "Forward".to_string(),
            summary: format!("rule {id}"),
            status: status.to_string(),
            bytes_sent: 0,
            bytes_received: 0,
            active_connections: 0,
            total_connections: 0,
        });
        self.forward_selected = self.forward_rules.len().saturating_sub(1);
    }

    fn next_fixture_forward_id(&self) -> u32 {
        self.forward_rules
            .iter()
            .map(|rule| rule.id)
            .max()
            .unwrap_or(0)
            + 1
    }

    fn open_monitor(&mut self) {
        self.mode = Mode::Monitor;
        if let Some(service) = &self.service {
            if !self.metrics_started {
                service.send(SshCommand::Metrics(MetricsServiceCommand::Start));
                self.metrics_started = true;
            }
            service.send(SshCommand::Metrics(MetricsServiceCommand::Refresh));
            self.status = "metrics refresh requested".to_string();
        } else {
            self.status = "fixture session monitor".to_string();
        }
    }

    fn handle_monitor_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('r') | KeyCode::F(5) => self.open_monitor(),
            KeyCode::Char('s') => self.open_sftp(),
            KeyCode::Char('f') => self.open_forwarding(),
            KeyCode::Char('t') | KeyCode::Esc => {
                self.mode = Mode::Terminal;
                self.status = "returned to terminal".to_string();
            }
            KeyCode::Char('?') => self.show_help(),
            _ => {
                self.status = "monitor: r refresh, s sftp, f forwarding, t terminal".to_string();
            }
        }
    }

    fn draw(&mut self, frame: &mut Frame) {
        let area = frame.area();
        self.sync_terminal_size_for_area(area);
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(8),
                Constraint::Length(3),
                Constraint::Length(1),
            ])
            .split(area);

        self.draw_header(frame, chunks[0]);
        match self.mode {
            Mode::Sftp => self.draw_sftp(frame, chunks[1]),
            Mode::Forwarding => self.draw_forwarding(frame, chunks[1]),
            Mode::Monitor => self.draw_monitor(frame, chunks[1]),
            _ => self.draw_terminal(frame, chunks[1]),
        }
        self.draw_status(frame, chunks[2]);
        self.draw_help_line(frame, chunks[3]);

        if self.mode == Mode::HostKeyPrompt {
            self.draw_host_key_prompt(frame, centered_rect(74, 38, area));
        } else if self.mode == Mode::AgentOperationReview {
            self.draw_assist_response(frame, centered_rect(82, 62, area));
        } else if self.mode == Mode::Help {
            self.draw_help(frame, centered_rect(72, 46, area));
        }
    }

    fn draw_header(&self, frame: &mut Frame, area: Rect) {
        let source = match self.source {
            SshTuiSource::Profile => "profile",
            SshTuiSource::Connection => "connection",
            SshTuiSource::Fixture => "fixture",
        };
        let title = format!("SSH TUI - {}", self.target_label);
        let line = Line::from(vec![
            Span::styled(title, Style::default().add_modifier(Modifier::BOLD)),
            Span::raw(" | "),
            Span::raw(format!("profile {}", self.profile_label)),
            Span::raw(" | "),
            Span::raw(format!("source {source}")),
            Span::raw(" | "),
            Span::raw(format!("auth {}", self.auth_method)),
        ]);
        frame.render_widget(
            Paragraph::new(line)
                .block(Block::default().borders(Borders::ALL))
                .alignment(Alignment::Left),
            area,
        );
    }

    fn draw_terminal(&self, frame: &mut Frame, area: Rect) {
        let width = area.width.saturating_sub(2).max(1);
        let lines = self.terminal_screen_lines(width);
        frame.render_widget(
            Paragraph::new(lines).block(Block::default().borders(Borders::ALL).title("Terminal")),
            area,
        );
    }

    fn draw_sftp(&self, frame: &mut Frame, area: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(62), Constraint::Percentage(38)])
            .split(area);

        let visible_height = chunks[0].height.saturating_sub(2) as usize;
        let start = window_start(self.sftp_selected, visible_height, self.sftp_entries.len());
        let lines = if self.sftp_entries.is_empty() {
            vec![Line::from("No entries loaded. Press r to refresh.")]
        } else {
            self.sftp_entries[start..]
                .iter()
                .take(visible_height)
                .enumerate()
                .map(|(offset, entry)| {
                    let index = start + offset;
                    let prefix = if index == self.sftp_selected {
                        "> "
                    } else {
                        "  "
                    };
                    let style = if index == self.sftp_selected {
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default()
                    };
                    Line::from(Span::styled(
                        format!("{prefix}{}", sftp_entry_label(entry)),
                        style,
                    ))
                })
                .collect()
        };

        frame.render_widget(
            Paragraph::new(lines)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(format!("SFTP {}", self.sftp_path)),
                )
                .wrap(Wrap { trim: false }),
            chunks[0],
        );

        self.draw_transfer_plan(frame, chunks[1]);
    }

    fn draw_transfer_plan(&self, frame: &mut Frame, area: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Min(6), Constraint::Length(3)])
            .split(area);

        let lines = if let Some(plan) = &self.transfer_plan {
            let mut lines = vec![
                Line::from(format!("Kind: {}", plan.kind.label())),
                Line::from(format!("Remote: {}", plan.remote)),
                Line::from(format!(
                    "Local: {}",
                    plan.local.as_deref().unwrap_or("not required")
                )),
                Line::from(format!("Confirmed: {}", plan.confirmed)),
            ];
            if plan.is_destructive() {
                lines.push(Line::from("Safety: destructive actions require y twice"));
            }
            lines
        } else {
            vec![
                Line::from("No transfer plan."),
                Line::from("d plans a download for the selected file."),
                Line::from("u stages an upload plan."),
                Line::from("x stages a delete plan."),
                Line::from("c cancels the current plan."),
            ]
        };

        frame.render_widget(
            Paragraph::new(lines)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title("Transfer Plan"),
                )
                .wrap(Wrap { trim: false }),
            chunks[0],
        );

        let progress = self
            .transfer_plan
            .as_ref()
            .and_then(|plan| plan.progress.as_ref());
        let (ratio, label) = if let Some(progress) = progress {
            (progress.ratio(), progress.label())
        } else {
            (0.0, "idle".to_string())
        };
        frame.render_widget(
            Gauge::default()
                .block(Block::default().borders(Borders::ALL).title("Progress"))
                .gauge_style(Style::default().fg(Color::Green))
                .ratio(ratio)
                .label(label),
            chunks[1],
        );
    }

    fn draw_forwarding(&self, frame: &mut Frame, area: Rect) {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(62), Constraint::Percentage(38)])
            .split(area);

        let visible_height = chunks[0].height.saturating_sub(2) as usize;
        let start = window_start(
            self.forward_selected,
            visible_height,
            self.forward_rules.len(),
        );
        let lines = if self.forward_rules.is_empty() {
            vec![Line::from(
                "No forwarding rules. Press l, r, or d to stage one.",
            )]
        } else {
            self.forward_rules[start..]
                .iter()
                .take(visible_height)
                .enumerate()
                .map(|(offset, rule)| {
                    let index = start + offset;
                    let prefix = if index == self.forward_selected {
                        "> "
                    } else {
                        "  "
                    };
                    let style = if index == self.forward_selected {
                        Style::default()
                            .fg(Color::Cyan)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default()
                    };
                    Line::from(Span::styled(
                        format!("{prefix}{}", forward_rule_label(rule)),
                        style,
                    ))
                })
                .collect()
        };

        frame.render_widget(
            Paragraph::new(lines)
                .block(Block::default().borders(Borders::ALL).title("Forwarding"))
                .wrap(Wrap { trim: false }),
            chunks[0],
        );

        let lines = if let Some(plan) = &self.forward_plan {
            vec![
                Line::from(format!("Kind: {}", plan.forward_type.type_label())),
                Line::from(format!("Spec: {}", plan.forward_type.summary())),
                Line::from(format!("Confirmed: {}", plan.confirmed)),
                Line::from("Press y to start through SshService channel mode."),
            ]
        } else {
            vec![
                Line::from("No forwarding plan."),
                Line::from("l stages -L local forwarding."),
                Line::from("r stages -R remote forwarding."),
                Line::from("d stages -D dynamic SOCKS5."),
                Line::from("x stops the selected active rule."),
            ]
        };
        frame.render_widget(
            Paragraph::new(lines)
                .block(Block::default().borders(Borders::ALL).title("Forward Plan"))
                .wrap(Wrap { trim: false }),
            chunks[1],
        );
    }

    fn draw_monitor(&self, frame: &mut Frame, area: Rect) {
        let sftp_state = if self.sftp_handle.is_some() {
            "open"
        } else if self.service.is_none() {
            "fixture"
        } else {
            "closed"
        };
        let metrics_lines = if let Some(metrics) = &self.metrics {
            vec![
                Line::from(format!("Host: {}", metrics.hostname)),
                Line::from(format!("OS: {}", metrics.os_label)),
                Line::from(format!("CPU: {:.1}%", metrics.cpu_usage)),
                Line::from(format!(
                    "Memory: {} / {}",
                    format_size(metrics.memory_used),
                    format_size(metrics.memory_total)
                )),
                Line::from(format!(
                    "Load: {:.2} {:.2} {:.2}",
                    metrics.load_average[0], metrics.load_average[1], metrics.load_average[2]
                )),
                Line::from(format!("Uptime: {}", format_duration(metrics.uptime_secs))),
            ]
        } else {
            vec![
                Line::from("No metrics snapshot yet."),
                Line::from("Press r to request a refresh."),
            ]
        };

        let mut lines = vec![
            Line::from(format!("Target: {}", self.target_label)),
            Line::from(format!(
                "Terminal lines retained: {}",
                self.terminal_lines.len()
            )),
            Line::from(format!("SFTP: {sftp_state} at {}", self.sftp_path)),
            Line::from(format!("Forwarding rules: {}", self.forward_rules.len())),
            Line::from(format!(
                "Metrics collector started: {}",
                self.metrics_started
            )),
            Line::from(""),
        ];
        lines.extend(metrics_lines);

        frame.render_widget(
            Paragraph::new(lines)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title("Session Monitor"),
                )
                .wrap(Wrap { trim: false }),
            area,
        );
    }

    fn draw_status(&self, frame: &mut Frame, area: Rect) {
        let mode = match self.mode {
            Mode::Terminal => "terminal",
            Mode::Sftp => "sftp",
            Mode::Forwarding => "forwarding",
            Mode::Monitor => "monitor",
            Mode::HostKeyPrompt => "host-key",
            Mode::AgentOperationReview => "agent-operation-review",
            Mode::Help => "help",
            Mode::Disconnected => "disconnected",
            Mode::Error => "error",
        };
        let line = Line::from(vec![
            Span::styled(
                format!("{mode} "),
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(&self.status),
            Span::raw(format!(
                " | owner {} | pending {} | dropped {} | purpose {} | readonly {} | restore {}",
                self.pty_input_owner.label(Utc::now()),
                self.pending_local_input_bytes,
                self.dropped_pty_input_bytes,
                self.purpose,
                self.readonly,
                self.restore
            )),
        ]);
        frame.render_widget(
            Paragraph::new(line).block(Block::default().borders(Borders::ALL).title("Status")),
            area,
        );
    }

    fn draw_help_line(&self, frame: &mut Frame, area: Rect) {
        let text = if self.escape_armed {
            "escape armed: q quit | r reconnect | s sftp | f forwarding | m monitor | a share/refresh agent session | v revoke | t terminal | ? help"
        } else if self.mode == Mode::Sftp {
            "sftp: j/k move | Enter open | Backspace parent | d/u/x plan | y confirm | t terminal"
        } else if self.mode == Mode::Forwarding {
            "forwarding: j/k move | l/r/d plan | y start | x stop | s sftp | m monitor | t terminal"
        } else if self.mode == Mode::Monitor {
            "monitor: r refresh | s sftp | f forwarding | t terminal"
        } else if self.mode == Mode::AgentOperationReview {
            "agent operation: j/k select | y approve once | A allow this agent for session | n deny | Enter/q return | c close"
        } else {
            "raw input active | Ctrl+] opens local escape layer"
        };
        frame.render_widget(Paragraph::new(text), area);
    }

    fn draw_host_key_prompt(&self, frame: &mut Frame, area: Rect) {
        let Some(prompt) = &self.host_key_prompt else {
            return;
        };
        frame.render_widget(Clear, area);
        let severity = if prompt.key_changed {
            "changed host key"
        } else {
            "unknown host key"
        };
        let lines = vec![
            Line::from(Span::styled(
                "SSH host key decision",
                Style::default().add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(format!("Target: {}:{}", prompt.host, prompt.port)),
            Line::from(format!("Status: {severity}")),
            Line::from(format!("Fingerprint: {}", prompt.fingerprint)),
            Line::from(""),
            Line::from("Press a to accept for this SSH session, r or Esc to reject."),
            Line::from("No password, private key, or passphrase is shown here."),
        ];
        frame.render_widget(
            Paragraph::new(lines)
                .block(Block::default().borders(Borders::ALL).title("Host Key"))
                .wrap(Wrap { trim: false }),
            area,
        );
    }

    fn draw_assist_response(&self, frame: &mut Frame, area: Rect) {
        frame.render_widget(Clear, area);
        let Some(response) = &self.assist_response else {
            return;
        };
        let mut lines = vec![
            Line::from(Span::styled(
                "External agent session operation",
                Style::default().add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(format!("Request: {}", response.request_id)),
            Line::from(format!("Agent: {}", response.agent.client_id)),
            Line::from(format!("Summary: {}", response.summary)),
        ];
        if let Some(diagnosis) = &response.diagnosis {
            lines.push(Line::from(format!("Note: {diagnosis}")));
        }
        if response.requested_permissions.is_empty() {
            lines.push(Line::from("Requested permissions: none"));
        } else {
            lines.push(Line::from(format!(
                "Requested permissions: {}",
                response
                    .requested_permissions
                    .iter()
                    .map(|permission| format!("{permission:?}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            )));
        }
        if operation_requests_agent_side_inspection(response) {
            lines.push(Line::from(
                "Agent-side inspect uses a separate authorized session; current PTY is unchanged.",
            ));
        }
        if response.actions.is_empty() {
            lines.push(Line::from("Actions: guidance only"));
        } else {
            lines.push(Line::from("Actions:"));
            lines.extend(response.actions.iter().enumerate().map(|(index, action)| {
                let selected = index == self.assist_action_selected;
                let marker = if selected { "> " } else { "  " };
                let style = if selected {
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default()
                };
                Line::from(Span::styled(
                    format!("{marker}{}: {}", index + 1, assist_action_label(action)),
                    style,
                ))
            }));
        }
        if response
            .actions
            .get(
                self.assist_action_selected
                    .min(response.actions.len().saturating_sub(1)),
            )
            .is_some_and(|action| {
                matches!(
                    action,
                    AssistAction::ProposedCommand {
                        target: AssistActionTarget::CurrentPty { .. },
                        ..
                    }
                )
            })
            && let Some(warning) = self.current_pty_terminal_state_warning()
        {
            lines.extend([
                Line::from(""),
                Line::from(Span::styled(
                    format!("Warning: {warning}."),
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD),
                )),
                Line::from("Approve only if the visible terminal is ready for the proposed input."),
            ]);
        }
        lines.extend([
            Line::from(""),
            Line::from("j/k selects. y approves once. A allows this agent for the session."),
            Line::from("n denies the selected operation and reports the decision to the agent."),
            Line::from("Enter or q returns. c closes the session share."),
        ]);
        frame.render_widget(
            Paragraph::new(lines)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title("Agent Operation Request"),
                )
                .wrap(Wrap { trim: false }),
            area,
        );
    }

    fn draw_help(&self, frame: &mut Frame, area: Rect) {
        frame.render_widget(Clear, area);
        let lines = vec![
            Line::from(Span::styled(
                "SSH TUI help",
                Style::default().add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from("Raw terminal input is sent to the SSH PTY."),
            Line::from("Ctrl+] opens the local escape layer."),
            Line::from(
                "Escape commands: q quit, r reconnect, s sftp, f forwarding, m monitor, a share/refresh agent session, v revoke, t terminal.",
            ),
            Line::from("Host-key decisions use explicit a/r keys and display fingerprints only."),
            Line::from("SFTP browser: j/k move, Enter open, d/u/x stage plans, y confirms."),
            Line::from("Forwarding pane: l/r/d stage local/remote/dynamic rules, x stops a rule."),
            Line::from("Session monitor: r requests a metrics refresh."),
            Line::from(""),
            Line::from("Press any key to return."),
        ];
        frame.render_widget(
            Paragraph::new(lines)
                .block(Block::default().borders(Borders::ALL).title("Help"))
                .wrap(Wrap { trim: false }),
            area,
        );
    }

    fn set_fixture_host_key_prompt(&mut self, prompt: FixtureHostKey) {
        self.mode = Mode::HostKeyPrompt;
        self.status = "fixture host key decision required".to_string();
        self.host_key_prompt = Some(HostKeyPrompt {
            host: prompt.host,
            port: prompt.port,
            fingerprint: prompt.fingerprint,
            key_changed: prompt.key_changed,
            reply: None,
        });
    }

    fn push_terminal_output(&mut self, bytes: &[u8]) {
        self.pending_local_input_bytes = 0;
        self.terminal_parser.process(bytes);
        let text = String::from_utf8_lossy(bytes);
        for line in text.split('\n') {
            let clean = sanitize_terminal_text(line.trim_end_matches('\r'));
            if !clean.is_empty() {
                self.push_transcript_line(&clean);
            }
        }
    }

    fn push_line(&mut self, line: &str) {
        let clean = sanitize_terminal_text(line);
        if clean.is_empty() {
            return;
        }
        self.terminal_parser.process(clean.as_bytes());
        self.terminal_parser.process(b"\r\n");
        self.push_transcript_line(&clean);
    }

    fn push_transcript_line(&mut self, line: &str) {
        self.terminal_lines.push(line.to_string());
        let overflow = self.terminal_lines.len().saturating_sub(MAX_TERMINAL_LINES);
        if overflow > 0 {
            self.terminal_lines.drain(0..overflow);
        }
    }

    fn sync_terminal_size_for_area(&mut self, area: Rect) {
        self.set_terminal_size(terminal_grid_size_for_area(area));
    }

    fn set_terminal_size(&mut self, size: TerminalGridSize) {
        if self.terminal_size == size {
            return;
        }
        self.terminal_size = size;
        self.assist_fallback_session.metadata = json!({
            "kind": "pty",
            "cols": size.cols,
            "rows": size.rows,
        });
        self.terminal_parser.set_size(size.rows, size.cols);
        if let Some(service) = &self.service {
            service.send(SshCommand::Resize {
                cols: size.cols,
                rows: size.rows,
            });
        }
    }

    fn build_assist_snapshot(
        &self,
        policy: &AssistContextPolicy,
    ) -> Result<AssistContextSnapshot, AssistContractError> {
        policy.validate()?;
        let descriptor = self.current_assist_descriptor();
        let binding = AssistSessionBinding::from_descriptor(&descriptor);
        let mut withheld_fields = Vec::new();
        let screen_limit = usize::from(policy.visible_screen_rows)
            * usize::from(policy.visible_screen_cols)
            + usize::from(policy.visible_screen_rows);
        let (visible_text, redaction) = self.redact_assist_text(&self.visible_screen_text(policy));
        let visible_screen = Some(AssistBoundedText::capture(
            &visible_text,
            screen_limit.max(1),
            redaction,
        )?);
        let transcript_text = self.terminal_lines.join("\n");
        let (transcript_text, redaction) = self.redact_assist_text(&transcript_text);
        let transcript_tail = Some(bounded_tail_text(
            &transcript_text,
            policy.transcript_tail_bytes,
            redaction,
        ));
        let (status_text, status_redaction) = self.redact_assist_text(&self.status);
        let status_line = Some(AssistBoundedText::capture(
            &status_text,
            ASSIST_STATUS_LIMIT_BYTES,
            status_redaction,
        )?);
        let mut redaction = redaction_for_snapshot(&visible_screen, &transcript_tail, &status_line);
        let mut metadata = self.assist_mode_metadata();
        if serde_json::to_vec(&metadata)
            .map(|bytes| bytes.len() > policy.metadata_bytes)
            .unwrap_or(true)
        {
            redaction = combine_redaction_status(redaction, RedactionStatus::Withheld);
            withheld_fields.push(AssistWithheldField {
                field: "metadata".to_string(),
                reason: AssistWithholdingReason::LimitExceeded,
            });
            metadata = json!({
                "mode": mode_label(self.mode),
                "scope": "visible_screen_and_transcript",
                "metadata_truncated": true,
            });
        }

        Ok(AssistContextSnapshot {
            binding,
            captured_at: Utc::now(),
            mode: mode_label(self.mode).to_string(),
            health: descriptor.health,
            terminal: Some(AssistTerminalDimensions {
                rows: self.terminal_size.rows,
                cols: self.terminal_size.cols,
            }),
            visible_screen,
            transcript_tail,
            status_line,
            withheld_fields,
            metadata,
            redaction,
        })
    }

    fn current_assist_descriptor(&self) -> PluginSessionDescriptor {
        let mut descriptors = self.sessions.list(PluginSessionListFilter {
            plugin_id: Some("ssh".to_string()),
            owner_id: Some(self.owner_id.clone()),
            profile_ref: self.profile_ref.clone(),
            purpose: Some(PluginSessionPurpose::InteractiveTerminal),
            include_terminal: true,
        });
        descriptors.sort_by_key(|descriptor| std::cmp::Reverse(descriptor.last_used_at));
        descriptors.into_iter().next().unwrap_or_else(|| {
            let mut descriptor = self.assist_fallback_session.clone();
            descriptor.health = self.assist_health();
            descriptor.last_used_at = Utc::now();
            descriptor
        })
    }

    fn assist_health(&self) -> PluginSessionHealth {
        match self.mode {
            Mode::Disconnected => PluginSessionHealth::Stale,
            Mode::Error => PluginSessionHealth::Failed,
            Mode::HostKeyPrompt => PluginSessionHealth::Degraded,
            _ if self.service.is_some() && self.assist_fallback_session.authenticated => {
                PluginSessionHealth::Ready
            }
            _ if self.service.is_some() => PluginSessionHealth::Starting,
            _ => PluginSessionHealth::Ready,
        }
    }

    fn visible_screen_text(&self, policy: &AssistContextPolicy) -> String {
        self.terminal_screen_text_lines(policy.visible_screen_cols)
            .into_iter()
            .take(usize::from(policy.visible_screen_rows))
            .collect::<Vec<_>>()
            .join("\n")
    }

    fn redact_assist_text(&self, text: &str) -> (String, RedactionStatus) {
        let sensitive_context = json!({
            "host": self.target_label,
            "endpoint": self.target_label,
            "user": self.profile_label,
        });
        let (redacted, structured_status) = redact_text_with_json(text, &sensitive_context);
        let (redacted, assignment_status) = redact_secret_assignments(&redacted);
        (
            redacted,
            combine_redaction_status(structured_status, assignment_status),
        )
    }

    fn assist_mode_metadata(&self) -> Value {
        let common = json!({
            "provider": "ssh_tui",
            "mode": mode_label(self.mode),
            "scope": "visible_screen_and_transcript",
            "source": self.source,
            "readonly": self.readonly,
            "restore": self.restore,
            "profile_label_present": !self.profile_label.is_empty(),
            "target_label_redacted": true,
            "terminal": {
                "rows": self.terminal_size.rows,
                "cols": self.terminal_size.cols,
                "retained_transcript_lines": self.terminal_lines.len(),
                "input_owner": self.pty_input_owner.label(Utc::now()),
                "pending_local_input_bytes": self.pending_local_input_bytes,
                "dropped_pty_input_bytes": self.dropped_pty_input_bytes
            }
        });

        let mode = match self.mode {
            Mode::Terminal | Mode::AgentOperationReview | Mode::Help => json!({
                "kind": "terminal",
                "raw_input": true,
                "escape_armed": self.escape_armed,
            }),
            Mode::Sftp => json!({
                "kind": "sftp",
                "path": self.sftp_path,
                "entry_count": self.sftp_entries.len(),
                "selected_index": self.sftp_selected.min(self.sftp_entries.len().saturating_sub(1)),
                "selected_kind": self.selected_sftp_entry().map(|entry| if entry.is_dir { "dir" } else { "file" }),
                "transfer_plan": self.transfer_plan.as_ref().map(|plan| json!({
                    "kind": plan.kind.label(),
                    "remote_present": !plan.remote.is_empty(),
                    "local_path_redacted": plan.local.is_some(),
                    "confirmed": plan.confirmed,
                    "destructive": plan.is_destructive(),
                    "progress": plan.progress.as_ref().map(|progress| json!({
                        "transferred": progress.transferred,
                        "total": progress.total,
                    }))
                }))
            }),
            Mode::Forwarding => json!({
                "kind": "forwarding",
                "rule_count": self.forward_rules.len(),
                "selected_index": self.forward_selected.min(self.forward_rules.len().saturating_sub(1)),
                "selected_status": self.forward_rules.get(self.forward_selected).map(|rule| rule.status.as_str()),
                "rules": self.forward_rules.iter().map(|rule| json!({
                    "kind": rule.kind,
                    "status": rule.status,
                    "bytes_sent": rule.bytes_sent,
                    "bytes_received": rule.bytes_received,
                    "active_connections": rule.active_connections,
                    "total_connections": rule.total_connections,
                    "endpoint_summary_redacted": true
                })).collect::<Vec<_>>(),
                "pending_plan": self.forward_plan.as_ref().map(|plan| json!({
                    "kind": plan.forward_type.type_label(),
                    "confirmed": plan.confirmed,
                    "endpoint_summary_redacted": true
                }))
            }),
            Mode::Monitor => json!({
                "kind": "monitor",
                "sftp_open": self.sftp_handle.is_some(),
                "forwarding_rule_count": self.forward_rules.len(),
                "metrics_started": self.metrics_started,
                "metrics": self.metrics.as_ref().map(|metrics| json!({
                    "hostname_redacted": true,
                    "os_label": metrics.os_label,
                    "cpu_usage": metrics.cpu_usage,
                    "memory_used": metrics.memory_used,
                    "memory_total": metrics.memory_total,
                    "load_average": metrics.load_average,
                    "uptime_secs": metrics.uptime_secs
                }))
            }),
            Mode::HostKeyPrompt => json!({
                "kind": "host_key_prompt",
                "prompt": self.host_key_prompt.as_ref().map(|prompt| json!({
                    "host_redacted": true,
                    "port": prompt.port,
                    "fingerprint": prompt.fingerprint,
                    "key_changed": prompt.key_changed
                }))
            }),
            Mode::Disconnected => json!({
                "kind": "disconnected",
                "reconnect_available": self.service.is_some(),
                "sftp_open": self.sftp_handle.is_some(),
                "forwarding_rule_count": self.forward_rules.len()
            }),
            Mode::Error => json!({
                "kind": "error",
                "status_present": !self.status.is_empty(),
                "status_line_redacted": true
            }),
        };

        json!({
            "common": common,
            "mode": mode,
        })
    }

    fn terminal_screen_lines(&self, width: u16) -> Vec<Line<'static>> {
        let screen = self.terminal_parser.screen();
        let (_, screen_cols) = screen.size();
        let width = width.max(1).min(screen_cols.max(1));
        let (screen_rows, _) = screen.size();
        (0..screen_rows)
            .map(|row| terminal_screen_line(screen, row, width))
            .collect()
    }

    fn terminal_screen_text_lines(&self, width: u16) -> Vec<String> {
        self.terminal_screen_lines(width)
            .into_iter()
            .map(|line| {
                line.spans
                    .into_iter()
                    .map(|span| span.content.into_owned())
                    .collect::<String>()
                    .trim_end()
                    .to_string()
            })
            .collect()
    }
}

impl TransferKind {
    fn label(&self) -> &'static str {
        match self {
            Self::Download => "download",
            Self::Upload => "upload",
            Self::DeleteFile => "delete file",
            Self::DeleteDir => "delete directory",
        }
    }
}

impl TransferPlanView {
    fn is_destructive(&self) -> bool {
        matches!(
            self.kind,
            TransferKind::DeleteFile | TransferKind::DeleteDir
        )
    }
}

impl TransferProgressView {
    fn ratio(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            (self.transferred as f64 / self.total as f64).clamp(0.0, 1.0)
        }
    }

    fn label(&self) -> String {
        format!(
            "{} {}",
            self.label,
            format_progress(self.transferred, self.total)
        )
    }
}

impl MetricsView {
    fn from_system(metrics: SystemMetrics) -> Self {
        Self {
            hostname: metrics.hostname,
            os_label: format!("{:?}", metrics.os_type),
            cpu_usage: metrics.cpu_usage,
            memory_used: metrics.memory.used,
            memory_total: metrics.memory.total,
            load_average: metrics.load_average,
            uptime_secs: metrics.uptime_secs,
        }
    }
}

fn sftp_entry_sort(left: &SftpEntryView, right: &SftpEntryView) -> std::cmp::Ordering {
    right
        .is_dir
        .cmp(&left.is_dir)
        .then_with(|| left.name.to_lowercase().cmp(&right.name.to_lowercase()))
        .then_with(|| left.name.cmp(&right.name))
}

fn sftp_entry_label(entry: &SftpEntryView) -> String {
    let kind = if entry.is_dir { "dir " } else { "file" };
    let permissions = entry
        .permissions
        .map(|mode| format!("{mode:o}"))
        .unwrap_or_else(|| "----".to_string());
    let mtime = entry
        .mtime
        .map(|value| value.to_string())
        .unwrap_or_else(|| "-".to_string());
    format!(
        "{kind} {:>10} {:>5} {:>10} {}",
        format_size(entry.size),
        permissions,
        mtime,
        entry.name
    )
}

fn forward_rule_label(rule: &ForwardRuleView) -> String {
    format!(
        "#{:<3} {:<8} {:<9} {:<26} sent {} recv {} active {} total {}",
        rule.id,
        rule.kind,
        rule.status,
        rule.summary,
        format_size(rule.bytes_sent),
        format_size(rule.bytes_received),
        rule.active_connections,
        rule.total_connections
    )
}

fn assist_action_label(action: &AssistAction) -> String {
    match action {
        AssistAction::Guidance { title, body } => {
            format!("guidance: {title} - {}", safe_inline(body, 120))
        }
        AssistAction::RequestPermission {
            permission,
            reason,
            ttl_seconds,
        } => format!(
            "request {:?} for {}s - {}",
            permission,
            ttl_seconds,
            safe_inline(reason, 120)
        ),
        AssistAction::ProposedCommand {
            command,
            rationale,
            risk,
            ..
        } => format!(
            "proposed command ({:?}): {} - {}",
            risk,
            safe_inline(command, 80),
            safe_inline(rationale, 100)
        ),
        AssistAction::CapabilityCall {
            capability_id,
            rationale,
            risk,
            ..
        } => format!(
            "capability call {} ({:?}) - {}",
            capability_id,
            risk,
            safe_inline(rationale, 120)
        ),
    }
}

fn assist_action_requires_confirmation(action: &AssistAction) -> bool {
    !matches!(action, AssistAction::Guidance { .. })
}

fn assist_action_permission(action: &AssistAction) -> Option<AssistPermission> {
    match action {
        AssistAction::RequestPermission { permission, .. } => Some(*permission),
        AssistAction::ProposedCommand { target, .. } if assist_target_uses_current_pty(target) => {
            Some(AssistPermission::TakeControl)
        }
        AssistAction::ProposedCommand { .. } => Some(AssistPermission::ProposeCommands),
        AssistAction::CapabilityCall { target, .. } if assist_target_uses_current_pty(target) => {
            Some(AssistPermission::TakeControl)
        }
        AssistAction::CapabilityCall { .. } => Some(AssistPermission::AgentSideInspect),
        AssistAction::Guidance { .. } => None,
    }
}

fn assist_action_uses_current_pty(action: &AssistAction) -> bool {
    match action {
        AssistAction::ProposedCommand { target, .. }
        | AssistAction::CapabilityCall { target, .. } => assist_target_uses_current_pty(target),
        AssistAction::RequestPermission { permission, .. } => permission.uses_current_pty(),
        AssistAction::Guidance { .. } => false,
    }
}

fn assist_target_uses_current_pty(target: &AssistActionTarget) -> bool {
    matches!(target, AssistActionTarget::CurrentPty { .. })
}

fn assist_action_target_label(action: &AssistAction) -> String {
    match action {
        AssistAction::Guidance { .. } => "human_only".to_string(),
        AssistAction::RequestPermission { permission, .. } => {
            format!("permission:{permission:?}")
        }
        AssistAction::ProposedCommand { target, .. }
        | AssistAction::CapabilityCall { target, .. } => assist_target_label(target),
    }
}

fn assist_target_label(target: &AssistActionTarget) -> String {
    match target {
        AssistActionTarget::HumanOnly => "human_only".to_string(),
        AssistActionTarget::AgentSideSession { session } => {
            format!(
                "agent_side_session:{}:{}",
                session.session_id, session.generation
            )
        }
        AssistActionTarget::CurrentPty { binding } => {
            format!("current_pty:{}:{}", binding.session_id, binding.generation)
        }
        AssistActionTarget::Capability { capability_id } => {
            format!("capability:{capability_id}")
        }
    }
}

fn assist_action_command_summary(action: &AssistAction) -> Option<String> {
    match action {
        AssistAction::ProposedCommand { command, .. } => Some(safe_inline(command, 160)),
        _ => None,
    }
}

fn assist_action_capability_id(action: &AssistAction) -> Option<String> {
    match action {
        AssistAction::CapabilityCall { capability_id, .. } => Some(capability_id.clone()),
        AssistAction::ProposedCommand {
            target: AssistActionTarget::Capability { capability_id },
            ..
        } => Some(capability_id.clone()),
        _ => None,
    }
}

fn contains_password_like_prompt(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    [
        "password:",
        "passphrase",
        "otp",
        "one-time code",
        "verification code",
        "token:",
        "secret:",
        "sudo password",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

fn safe_inline(text: &str, limit: usize) -> String {
    let mut value = text.replace('\n', " ");
    if value.len() > limit {
        value.truncate(limit.saturating_sub(3));
        value.push_str("...");
    }
    value
}

fn remote_child_path(parent: &str, name: &str) -> String {
    let parent = parent.trim_end_matches('/');
    if parent.is_empty() {
        format!("/{name}")
    } else if parent == "." {
        name.to_string()
    } else {
        format!("{parent}/{name}")
    }
}

fn remote_parent_path(path: &str) -> String {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() || trimmed == "/" || trimmed == "." {
        return trimmed.to_string();
    }
    match trimmed.rsplit_once('/') {
        Some(("", _)) => "/".to_string(),
        Some((parent, _)) => parent.to_string(),
        None => ".".to_string(),
    }
}

fn planned_download_path(name: &str) -> PathBuf {
    std::env::temp_dir()
        .join("voidb-sftp-downloads")
        .join(safe_local_filename(name))
}

fn safe_local_filename(name: &str) -> String {
    let safe = name
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
        "download".to_string()
    } else {
        safe
    }
}

fn ensure_local_parent(path: &str) -> std::result::Result<(), String> {
    let path = PathBuf::from(path);
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    fs::create_dir_all(parent)
        .map_err(|err| format!("failed to create local target directory: {err}"))
}

fn forward_status_label(status: &ForwardStatus) -> &str {
    match status {
        ForwardStatus::Starting => "starting",
        ForwardStatus::Active => "active",
        ForwardStatus::Error(_) => "error",
        ForwardStatus::Stopped => "stopped",
    }
}

fn mode_label(mode: Mode) -> &'static str {
    match mode {
        Mode::Terminal => "terminal",
        Mode::Sftp => "sftp",
        Mode::Forwarding => "forwarding",
        Mode::Monitor => "monitor",
        Mode::HostKeyPrompt => "host-key",
        Mode::AgentOperationReview => "agent-operation-review",
        Mode::Help => "help",
        Mode::Disconnected => "disconnected",
        Mode::Error => "error",
    }
}

fn secret_leak_markers(text: &str) -> Vec<String> {
    [
        "super-secret-password",
        "BEGIN OPENSSH PRIVATE KEY",
        "BEGIN RSA PRIVATE KEY",
        "raw_plugin_config",
        "fixture-private-key",
        "passphrase_value",
    ]
    .into_iter()
    .filter(|marker| text.contains(marker))
    .map(str::to_string)
    .collect()
}

fn format_progress(transferred: u64, total: u64) -> String {
    if total == 0 {
        format!("{} transferred", format_size(transferred))
    } else {
        let percent = (transferred as f64 / total as f64 * 100.0).min(100.0);
        format!(
            "{} / {} ({percent:.0}%)",
            format_size(transferred),
            format_size(total)
        )
    }
}

fn format_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} {}", UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

fn format_duration(seconds: u64) -> String {
    let days = seconds / 86_400;
    let hours = (seconds % 86_400) / 3_600;
    let minutes = (seconds % 3_600) / 60;
    if days > 0 {
        format!("{days}d {hours}h {minutes}m")
    } else if hours > 0 {
        format!("{hours}h {minutes}m")
    } else {
        format!("{minutes}m")
    }
}

fn window_start(selected: usize, visible: usize, len: usize) -> usize {
    if visible == 0 || len <= visible {
        0
    } else if selected >= visible {
        (selected + 1).saturating_sub(visible)
    } else {
        0
    }
}

fn terminal_grid_size_for_area(area: Rect) -> TerminalGridSize {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(8),
            Constraint::Length(3),
            Constraint::Length(1),
        ])
        .split(area);
    let terminal_area = chunks.get(1).copied().unwrap_or(area);
    TerminalGridSize::new(
        terminal_area.width.saturating_sub(2),
        terminal_area.height.saturating_sub(2),
    )
}

fn seed_terminal_parser(parser: &mut vt100::Parser, lines: &[String]) {
    for line in lines {
        parser.process(line.as_bytes());
        parser.process(b"\r\n");
    }
}

fn terminal_screen_line(screen: &vt100::Screen, row: u16, width: u16) -> Line<'static> {
    let mut spans = Vec::new();
    let mut current_style: Option<Style> = None;
    let mut current_text = String::new();

    for col in 0..width {
        let Some(cell) = screen.cell(row, col) else {
            continue;
        };
        if cell.is_wide_continuation() {
            continue;
        }

        let style = terminal_cell_style(cell);
        let text = terminal_cell_text(cell);

        if current_style == Some(style) {
            current_text.push_str(&text);
            continue;
        }

        push_terminal_span(&mut spans, &mut current_style, &mut current_text);
        current_style = Some(style);
        current_text.push_str(&text);
    }
    push_terminal_span(&mut spans, &mut current_style, &mut current_text);

    Line::from(spans)
}

fn push_terminal_span(
    spans: &mut Vec<Span<'static>>,
    style: &mut Option<Style>,
    text: &mut String,
) {
    let Some(span_style) = style.take() else {
        return;
    };
    if text.is_empty() {
        return;
    }

    spans.push(Span::styled(std::mem::take(text), span_style));
}

fn terminal_cell_text(cell: &vt100::Cell) -> String {
    if cell.has_contents() {
        sanitize_terminal_text(&cell.contents())
    } else {
        " ".to_string()
    }
}

fn terminal_cell_style(cell: &vt100::Cell) -> Style {
    let mut style = Style::default();
    if let Some(color) = vt100_color_to_ratatui(cell.fgcolor()) {
        style = style.fg(color);
    }
    if let Some(color) = vt100_color_to_ratatui(cell.bgcolor()) {
        style = style.bg(color);
    }
    if cell.bold() {
        style = style.add_modifier(Modifier::BOLD);
    }
    if cell.italic() {
        style = style.add_modifier(Modifier::ITALIC);
    }
    if cell.underline() {
        style = style.add_modifier(Modifier::UNDERLINED);
    }
    if cell.inverse() {
        style = style.add_modifier(Modifier::REVERSED);
    }
    style
}

fn vt100_color_to_ratatui(color: vt100::Color) -> Option<Color> {
    match color {
        vt100::Color::Default => None,
        vt100::Color::Idx(index) => Some(Color::Indexed(index)),
        vt100::Color::Rgb(red, green, blue) => Some(Color::Rgb(red, green, blue)),
    }
}

fn redaction_for_snapshot(
    visible_screen: &Option<AssistBoundedText>,
    transcript_tail: &Option<AssistBoundedText>,
    status_line: &Option<AssistBoundedText>,
) -> RedactionStatus {
    [visible_screen, transcript_tail, status_line]
        .into_iter()
        .filter_map(|text| text.as_ref().map(|text| text.redaction))
        .fold(RedactionStatus::NotRequired, combine_redaction_status)
}

fn combine_redaction_status(left: RedactionStatus, right: RedactionStatus) -> RedactionStatus {
    use RedactionStatus as Status;
    match (left, right) {
        (Status::FailedClosed, _) | (_, Status::FailedClosed) => Status::FailedClosed,
        (Status::Withheld, _) | (_, Status::Withheld) => Status::Withheld,
        (Status::Applied, _) | (_, Status::Applied) => Status::Applied,
        (Status::NotRequired, Status::NotRequired) => Status::NotRequired,
    }
}

fn redact_secret_assignments(text: &str) -> (String, RedactionStatus) {
    let mut changed = false;
    let mut output = String::with_capacity(text.len());
    for (index, line) in text.split('\n').enumerate() {
        if index > 0 {
            output.push('\n');
        }
        if let Some(redacted) = redact_secret_assignment_line(line) {
            changed = true;
            output.push_str(&redacted);
        } else {
            output.push_str(line);
        }
    }

    let status = if changed {
        RedactionStatus::Applied
    } else {
        RedactionStatus::NotRequired
    };
    (output, status)
}

fn redact_secret_assignment_line(line: &str) -> Option<String> {
    const MARKERS: [&str; 11] = [
        "authorization",
        "passphrase",
        "password",
        "private_key",
        "api_key",
        "apikey",
        "passwd",
        "secret",
        "cookie",
        "token",
        "bearer",
    ];

    let lower = line.to_ascii_lowercase();
    for marker in MARKERS {
        let Some(marker_start) = lower.find(marker) else {
            continue;
        };
        let marker_end = marker_start + marker.len();
        let trailing = &line[marker_end..];
        let Some(delimiter_offset) = trailing.find(['=', ':']) else {
            continue;
        };
        let delimiter_index = marker_end + delimiter_offset;
        let delimiter_end = delimiter_index
            + line[delimiter_index..]
                .chars()
                .next()
                .map(char::len_utf8)
                .unwrap_or(1);
        if line[delimiter_end..].trim().is_empty() {
            continue;
        }
        return Some(format!("{} <redacted:credential>", &line[..delimiter_end]));
    }

    None
}

fn bounded_tail_text(
    text: &str,
    limit_bytes: usize,
    redaction: RedactionStatus,
) -> AssistBoundedText {
    if limit_bytes == 0 {
        return AssistBoundedText {
            text: String::new(),
            byte_count: 0,
            limit_bytes,
            truncated: !text.is_empty(),
            redaction,
        };
    }
    if text.len() <= limit_bytes {
        return AssistBoundedText {
            text: text.to_string(),
            byte_count: text.len(),
            limit_bytes,
            truncated: false,
            redaction,
        };
    }

    let mut start = text.len().saturating_sub(limit_bytes);
    while start < text.len() && !text.is_char_boundary(start) {
        start += 1;
    }
    let captured = text[start..].to_string();
    AssistBoundedText {
        byte_count: captured.len(),
        text: captured,
        limit_bytes,
        truncated: true,
        redaction,
    }
}

fn sanitize_terminal_text(input: &str) -> String {
    #[derive(Clone, Copy)]
    enum EscapeState {
        Ground,
        Escape,
        Csi,
        Osc,
        OscEscape,
    }

    let mut output = String::with_capacity(input.len());
    let mut state = EscapeState::Ground;

    for ch in input.chars() {
        match state {
            EscapeState::Ground => match ch {
                '\x1b' => state = EscapeState::Escape,
                '\t' => output.push(ch),
                _ if ch.is_control() => {}
                _ => output.push(ch),
            },
            EscapeState::Escape => match ch {
                '[' => state = EscapeState::Csi,
                ']' => state = EscapeState::Osc,
                _ => state = EscapeState::Ground,
            },
            EscapeState::Csi => {
                if ('\u{40}'..='\u{7e}').contains(&ch) {
                    state = EscapeState::Ground;
                }
            }
            EscapeState::Osc => match ch {
                '\x07' => state = EscapeState::Ground,
                '\x1b' => state = EscapeState::OscEscape,
                _ => {}
            },
            EscapeState::OscEscape => {
                state = if ch == '\\' {
                    EscapeState::Ground
                } else {
                    EscapeState::Osc
                };
            }
        }
    }

    output
}

fn is_escape_layer_key(key: KeyEvent) -> bool {
    // Legacy terminals encode Ctrl+] as byte 0x1D, which crossterm reports as
    // Ctrl+5. Enhanced keyboard protocols preserve the right-bracket key.
    key.modifiers.contains(KeyModifiers::CONTROL)
        && matches!(key.code, KeyCode::Char(']') | KeyCode::Char('5'))
}

fn safe_error_summary(message: &str) -> String {
    let mut summary = message.replace('\n', " ");
    if summary.len() > 180 {
        summary.truncate(177);
        summary.push_str("...");
    }
    summary
}

fn key_to_pty_bytes(key: KeyEvent) -> Option<Vec<u8>> {
    match key.code {
        KeyCode::Char(c) if key.modifiers.contains(KeyModifiers::CONTROL) => {
            ascii_control_byte(c).map(|byte| vec![byte])
        }
        KeyCode::Char(c) => {
            let mut bytes = [0; 4];
            Some(c.encode_utf8(&mut bytes).as_bytes().to_vec())
        }
        KeyCode::Enter => Some(b"\r".to_vec()),
        KeyCode::Backspace => Some(vec![0x7f]),
        KeyCode::Tab => Some(b"\t".to_vec()),
        KeyCode::Esc => Some(vec![0x1b]),
        KeyCode::Up => Some(b"\x1b[A".to_vec()),
        KeyCode::Down => Some(b"\x1b[B".to_vec()),
        KeyCode::Right => Some(b"\x1b[C".to_vec()),
        KeyCode::Left => Some(b"\x1b[D".to_vec()),
        KeyCode::Home => Some(b"\x1b[H".to_vec()),
        KeyCode::End => Some(b"\x1b[F".to_vec()),
        KeyCode::Delete => Some(b"\x1b[3~".to_vec()),
        _ => None,
    }
}

fn ascii_control_byte(c: char) -> Option<u8> {
    let lower = c.to_ascii_lowercase();
    if lower.is_ascii_lowercase() {
        Some((lower as u8) & 0x1f)
    } else {
        match lower {
            '4' => Some(0x1c),
            '[' => Some(0x1b),
            '\\' => Some(0x1c),
            ']' => Some(0x1d),
            '^' => Some(0x1e),
            '_' => Some(0x1f),
            _ => None,
        }
    }
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

struct StandaloneSshTabManager {
    render_tx: mpsc::UnboundedSender<()>,
    should_quit: Arc<AtomicBool>,
}

impl StandaloneSshTabManager {
    fn new(should_quit: Arc<AtomicBool>) -> Self {
        let (render_tx, _render_rx) = mpsc::unbounded_channel();
        Self {
            render_tx,
            should_quit,
        }
    }

    fn unsupported_tabs_error() -> anyhow::Error {
        anyhow!("SSH TUI does not host plugin tabs; use plugin-owned CLI commands instead")
    }
}

impl TabManager for StandaloneSshTabManager {
    fn open(&self, _title: String, _plugin_id: String, _context: Value) -> Result<()> {
        Err(Self::unsupported_tabs_error())
    }

    fn close_current(&self) -> Result<()> {
        self.quit()
    }

    fn set_title(&self, _title: String) -> Result<()> {
        Ok(())
    }

    fn request_render(&self) -> Result<()> {
        let _ = self.render_tx.send(());
        Ok(())
    }

    fn list_tabs(&self) -> Result<Vec<TabInfo>> {
        Ok(vec![TabInfo {
            index: 0,
            title: "SSH".to_string(),
            plugin_id: "ssh".to_string(),
            context: json!({}),
            is_active: true,
        }])
    }

    fn close_tab(&self, index: usize) -> Result<()> {
        if index == 0 {
            self.quit()
        } else {
            Err(anyhow!("SSH TUI has no tab {index}"))
        }
    }

    fn switch_to(&self, index: usize) -> Result<()> {
        if index == 0 {
            Ok(())
        } else {
            Err(anyhow!("SSH TUI has no tab {index}"))
        }
    }

    fn active_tab_index(&self) -> Result<usize> {
        Ok(0)
    }

    fn quit(&self) -> Result<()> {
        self.should_quit.store(true, Ordering::SeqCst);
        let _ = self.render_tx.send(());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preflight_redacts_password_auth_material() {
        let launch = SshTuiLaunch {
            profile_label: "prod".to_string(),
            config: Some(SshConfig::new(
                "prod.internal".to_string(),
                22,
                "deploy".to_string(),
                "super-secret-password".to_string(),
            )),
            source: SshTuiSource::Connection,
            fixture_path: None,
            purpose: "terminal".to_string(),
            readonly: false,
            restore: true,
            launch_plan: None,
        };

        let rendered = serde_json::to_string(&preflight_value(&launch)).unwrap();
        assert!(rendered.contains("password"));
        assert!(!rendered.contains("super-secret-password"));
    }

    #[test]
    fn preflight_uses_fixture_safe_metadata() {
        let fixture = format!(
            "{}/fixtures/ssh_tui_terminal_core.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let launch = SshTuiLaunch {
            profile_label: "fixture".to_string(),
            config: None,
            source: SshTuiSource::Fixture,
            fixture_path: Some(fixture),
            purpose: "terminal".to_string(),
            readonly: false,
            restore: true,
            launch_plan: None,
        };

        let value = preflight_value(&launch);
        assert_eq!(value["profile_label"], "fixture-ssh");
        assert_eq!(value["target"], "fixture@127.0.0.1:2222");
        assert_eq!(value["auth"]["method"], "agent");
        assert!(
            value["modes"]
                .as_array()
                .unwrap()
                .contains(&json!("sftp_browser"))
        );
        assert!(
            value["modes"]
                .as_array()
                .unwrap()
                .contains(&json!("forwarding_monitor"))
        );
    }

    #[test]
    fn fixture_loads_sftp_forwarding_and_metrics_metadata() {
        let fixture = format!(
            "{}/fixtures/ssh_tui_terminal_core.json",
            env!("CARGO_MANIFEST_DIR")
        );

        let data = load_fixture(&fixture).unwrap();
        assert_eq!(data.sftp_path, "/srv/app");
        assert_eq!(data.sftp_entries.len(), 3);
        assert!(
            data.sftp_entries
                .iter()
                .any(|entry| entry.name == "releases" && entry.is_dir)
        );
        assert_eq!(data.forward_rules.len(), 2);
        assert_eq!(data.forward_rules[0].status, "active");
        assert_eq!(data.metrics.unwrap().hostname, "fixture-ssh-host");
    }

    #[test]
    fn assist_snapshot_preview_redacts_terminal_and_status_context() {
        let mut app = SshTuiApp::new(fixture_launch()).unwrap();
        app.push_line("connected to fixture@127.0.0.1:2222");
        app.push_terminal_output(b"export PASSWORD=super-secret-token\r\n");
        app.status = "waiting: password=super-secret-status".to_string();

        let snapshot = app
            .build_assist_snapshot(&AssistContextPolicy::default())
            .unwrap();
        let preview_json = serde_json::to_string(&snapshot.preview()).unwrap();
        assert!(!preview_json.contains("super-secret"));
        assert!(!preview_json.contains("fixture@127.0.0.1"));

        let snapshot_json = serde_json::to_string(&snapshot).unwrap();
        assert!(!snapshot_json.contains("super-secret"));
        assert!(!snapshot_json.contains("fixture@127.0.0.1"));
        assert!(snapshot_json.contains("<redacted"));
        assert_eq!(snapshot.redaction, RedactionStatus::Applied);
    }

    #[test]
    fn escape_a_shares_current_session_without_opening_a_conversation_surface() {
        let mut app = SshTuiApp::new(fixture_launch()).unwrap();
        let store = temp_assist_store();
        app.assist_store = store.clone();
        let return_mode = app.mode;

        app.handle_key(KeyEvent::new(KeyCode::Char(']'), KeyModifiers::CONTROL));
        app.handle_key(KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE));

        assert_eq!(app.mode, return_mode);
        assert!(app.status.contains("session shared"));
        assert_eq!(
            app.assist_request.as_ref().unwrap().status,
            AssistRequestStatus::Pending
        );
        assert_eq!(
            app.assist_request.as_ref().unwrap().label,
            "Shared live SSH session"
        );
        let request_id = app.assist_request.as_ref().unwrap().id.clone();
        let detail = store.detail(&request_id).unwrap();
        assert!(detail.record.context.visible_screen.is_some());
        assert!(detail.record.context.transcript_tail.is_some());
    }

    #[test]
    fn external_agent_operation_is_loaded_into_local_review() {
        let mut app = SshTuiApp::new(fixture_launch()).unwrap();
        let store = temp_assist_store();
        app.assist_store = store.clone();

        app.share_current_session_with_agent();
        let request_id = app.assist_request.as_ref().unwrap().id.clone();
        let detail = store.detail(&request_id).unwrap();
        assert_eq!(detail.record.request.status, AssistRequestStatus::Pending);

        store
            .post_operation_request(
                &request_id,
                AssistResponse {
                    id: "assist:response:test".to_string(),
                    request_id: request_id.clone(),
                    agent: voidb_core::AgentPrincipal {
                        client_id: "agent".to_string(),
                        task_id: "task-1".to_string(),
                        instance_id: None,
                    },
                    created_at: Utc::now(),
                    summary: "inspect process state from a separate session".to_string(),
                    diagnosis: Some("need process and log context".to_string()),
                    actions: vec![AssistAction::RequestPermission {
                        permission: AssistPermission::AgentSideInspect,
                        reason: "run read-only diagnostics outside the human PTY".to_string(),
                        ttl_seconds: 300,
                    }],
                    requested_permissions: vec![AssistPermission::AgentSideInspect],
                    redaction: RedactionStatus::NotRequired,
                },
            )
            .unwrap();

        app.drain_service();

        assert_eq!(app.mode, Mode::AgentOperationReview);
        let response = app.assist_response.as_ref().unwrap();
        assert_eq!(response.request_id, request_id);
        assert!(operation_requests_agent_side_inspection(response));
        assert_eq!(
            app.assist_request.as_ref().unwrap().status,
            AssistRequestStatus::Responded
        );
    }

    #[test]
    fn assist_current_pty_command_requires_local_approval_and_supports_revoke() {
        let command = "printf __voidb_assist_takeover__";
        let (mut app, store, request_id) = fixture_app_with_current_pty_action(command);

        app.handle_key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE));

        assert_eq!(app.mode, Mode::Terminal);
        assert!(
            app.terminal_lines
                .iter()
                .any(|line| line.contains("__voidb_assist_takeover__")),
            "status={} owner={:?} audit={:?}",
            app.status,
            app.pty_input_owner,
            app.assist_control_audit
        );
        assert!(matches!(
            app.pty_input_owner,
            PtyInputOwnerState::AgentControl { .. }
        ));
        let detail = store.detail(&request_id).unwrap();
        assert_eq!(detail.record.action_confirmations.len(), 1);
        assert!(detail.record.action_confirmations[0].uses_current_pty);
        assert!(
            app.assist_control_audit
                .iter()
                .any(|event| event.outcome == AssistControlAuditOutcome::Executed)
        );

        app.handle_key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE));
        let detail = store.detail(&request_id).unwrap();
        assert_eq!(detail.record.action_confirmations.len(), 1);
        assert_eq!(
            app.terminal_lines
                .iter()
                .filter(|line| line.contains("__voidb_assist_takeover__"))
                .count(),
            1
        );

        app.handle_key(KeyEvent::new(KeyCode::Char('z'), KeyModifiers::NONE));
        assert_eq!(app.dropped_pty_input_bytes, 2);
        assert!(!app.terminal_lines.iter().any(|line| line.contains('z')));

        app.handle_key(KeyEvent::new(KeyCode::Char(']'), KeyModifiers::CONTROL));
        app.handle_key(KeyEvent::new(KeyCode::Char('v'), KeyModifiers::NONE));

        assert!(matches!(
            app.pty_input_owner,
            PtyInputOwnerState::HumanActive
        ));
        assert!(
            app.assist_control_audit
                .iter()
                .any(|event| event.outcome == AssistControlAuditOutcome::Revoked)
        );
    }

    #[test]
    fn operator_can_deny_an_agent_operation_without_writing_the_pty() {
        let command = "printf __voidb_agent_denied__";
        let (mut app, store, request_id) = fixture_app_with_current_pty_action(command);

        app.handle_key(KeyEvent::new(KeyCode::Char('n'), KeyModifiers::NONE));

        assert_eq!(app.mode, Mode::Terminal);
        assert!(
            !app.terminal_lines
                .iter()
                .any(|line| line.contains("__voidb_agent_denied__"))
        );
        let detail = store.detail(&request_id).unwrap();
        assert_eq!(detail.record.action_confirmations.len(), 1);
        assert_eq!(
            detail.record.action_confirmations[0].status,
            "denied_by_operator"
        );
    }

    #[test]
    fn operator_can_allow_one_agent_for_the_current_session() {
        let first = "printf __voidb_agent_auto_first__";
        let second = "printf __voidb_agent_auto_second__";
        let (mut app, store, request_id) = fixture_app_with_current_pty_action(first);

        app.handle_key(KeyEvent::new(KeyCode::Char('A'), KeyModifiers::SHIFT));
        assert_eq!(app.mode, Mode::Terminal);
        assert!(app.agent_auto_control.is_some());
        assert!(
            app.terminal_lines
                .iter()
                .any(|line| line.contains("__voidb_agent_auto_first__"))
        );

        let binding = app.assist_request.as_ref().unwrap().binding.clone();
        post_fixture_assist_response(
            &store,
            &request_id,
            vec![AssistAction::ProposedCommand {
                command: second.to_string(),
                rationale: "continue under current-session approval".to_string(),
                risk: voidb_core::AssistActionRisk::Review,
                target: AssistActionTarget::CurrentPty { binding },
            }],
            vec![AssistPermission::TakeControl],
        );
        app.drain_service();

        assert!(
            app.terminal_lines
                .iter()
                .any(|line| line.contains("__voidb_agent_auto_second__"))
        );
        app.handle_key(KeyEvent::new(KeyCode::Char(']'), KeyModifiers::CONTROL));
        app.handle_key(KeyEvent::new(KeyCode::Char('v'), KeyModifiers::NONE));
        assert!(app.agent_auto_control.is_none());
    }

    #[test]
    fn assist_current_pty_takeover_blocks_hard_risky_contexts() {
        let (mut password_app, _, _) =
            fixture_app_with_current_pty_action("printf __voidb_password_guard__");
        password_app.push_terminal_output(b"Password: ");
        password_app.handle_key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE));
        assert!(
            password_app.status.contains("password-like prompt"),
            "status={} owner={:?} audit={:?}",
            password_app.status,
            password_app.pty_input_owner,
            password_app.assist_control_audit
        );
        assert!(
            !password_app
                .terminal_lines
                .iter()
                .any(|line| line.contains("__voidb_password_guard__"))
        );
        assert!(matches!(
            password_app.pty_input_owner,
            PtyInputOwnerState::HumanActive
        ));

        let (mut pending_app, _, _) =
            fixture_app_with_current_pty_action("printf __voidb_pending_guard__");
        pending_app.pending_local_input_bytes = 3;
        pending_app.handle_key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE));
        assert!(pending_app.status.contains("local input"));
    }

    #[test]
    fn assist_current_pty_takeover_allows_human_reviewed_terminal_state_warnings() {
        let terminal_modes: &[(&[u8], &str)] = &[
            (b"\x1b[?1049h", "alternate-screen"),
            (b"\x1b=", "application-keypad"),
            (b"\x1b[?1h", "application-cursor"),
        ];

        for (sequence, expected_mode) in terminal_modes {
            let command = format!("printf __voidb_{expected_mode}_warning__");
            let (mut app, store, request_id) = fixture_app_with_current_pty_action(&command);
            app.push_terminal_output(sequence);

            let warning = app
                .current_pty_terminal_state_warning()
                .expect("terminal state warning");
            assert!(warning.contains(expected_mode), "warning={warning}");

            app.handle_key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE));

            assert!(
                app.terminal_lines
                    .iter()
                    .any(|line| line.contains(&command)),
                "mode={expected_mode} status={} owner={:?} audit={:?}",
                app.status,
                app.pty_input_owner,
                app.assist_control_audit
            );
            assert!(matches!(
                app.pty_input_owner,
                PtyInputOwnerState::AgentControl { .. }
            ));
            assert!(app.status.contains("terminal-state warning"));
            assert!(
                !app.assist_control_audit
                    .iter()
                    .any(|event| event.outcome == AssistControlAuditOutcome::Blocked)
            );
            let detail = store.detail(&request_id).unwrap();
            assert!(
                detail.record.action_confirmations[0]
                    .note
                    .contains("terminal-state warning")
            );
        }
    }

    #[test]
    fn assist_current_pty_takeover_blocks_stale_generation() {
        let mut app = SshTuiApp::new(fixture_launch()).unwrap();
        app.host_key_prompt = None;
        app.mode = Mode::Terminal;
        app.return_mode = Mode::Terminal;
        let store = temp_assist_store();
        app.assist_store = store.clone();
        let request_id = share_fixture_session(&mut app);
        let mut stale_binding = app.assist_request.as_ref().unwrap().binding.clone();
        stale_binding.generation += 1;
        post_fixture_assist_response(
            &store,
            &request_id,
            vec![AssistAction::ProposedCommand {
                command: "printf __voidb_stale_generation__".to_string(),
                rationale: "should not run after reconnect".to_string(),
                risk: voidb_core::AssistActionRisk::Review,
                target: AssistActionTarget::CurrentPty {
                    binding: stale_binding,
                },
            }],
            vec![AssistPermission::TakeControl],
        );
        app.drain_service();

        app.handle_key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE));

        assert!(app.status.contains("binding"));
        assert!(
            !app.terminal_lines
                .iter()
                .any(|line| line.contains("__voidb_stale_generation__"))
        );
        assert!(
            app.assist_control_audit
                .iter()
                .any(|event| event.outcome == AssistControlAuditOutcome::Blocked)
        );
    }

    #[test]
    fn assist_agent_side_action_confirmation_does_not_write_current_pty() {
        let mut app = SshTuiApp::new(fixture_launch()).unwrap();
        let store = temp_assist_store();
        app.assist_store = store.clone();
        let request_id = share_fixture_session(&mut app);
        let agent_session = app
            .assist_request
            .as_ref()
            .unwrap()
            .binding
            .agent_session_ref();
        post_fixture_assist_response(
            &store,
            &request_id,
            vec![AssistAction::ProposedCommand {
                command: "journalctl -n 20".to_string(),
                rationale: "read recent logs from a separate session".to_string(),
                risk: voidb_core::AssistActionRisk::Review,
                target: AssistActionTarget::AgentSideSession {
                    session: agent_session,
                },
            }],
            vec![AssistPermission::AgentSideInspect],
        );
        app.drain_service();

        app.handle_key(KeyEvent::new(KeyCode::Char('y'), KeyModifiers::NONE));

        assert!(app.status.contains("current PTY unchanged"));
        assert!(
            !app.terminal_lines
                .iter()
                .any(|line| line.contains("journalctl"))
        );
        let detail = store.detail(&request_id).unwrap();
        assert_eq!(detail.record.action_confirmations.len(), 1);
        assert!(!detail.record.action_confirmations[0].uses_current_pty);
        assert_eq!(
            detail.record.action_confirmations[0].status,
            "confirmed_agent_side_command"
        );
    }

    #[test]
    fn assist_forwarding_metadata_withholds_endpoint_summaries() {
        let mut app = SshTuiApp::new(fixture_launch()).unwrap();
        app.mode = Mode::Forwarding;
        app.forward_rules = vec![ForwardRuleView {
            id: 7,
            kind: "local".to_string(),
            summary: "127.0.0.1:15432 -> secret.internal:5432".to_string(),
            status: "active".to_string(),
            bytes_sent: 10,
            bytes_received: 20,
            active_connections: 1,
            total_connections: 2,
        }];

        let snapshot = app
            .build_assist_snapshot(&AssistContextPolicy::default())
            .unwrap();
        let metadata = serde_json::to_string(&snapshot.metadata).unwrap();

        assert!(!metadata.contains("secret.internal"));
        assert!(!metadata.contains("127.0.0.1:15432"));
        assert!(metadata.contains("endpoint_summary_redacted"));
    }

    #[test]
    fn assist_sftp_metadata_keeps_remote_path_and_redacts_local_path() {
        let mut app = SshTuiApp::new(fixture_launch()).unwrap();
        app.mode = Mode::Sftp;
        app.sftp_path = "/srv/app/releases".to_string();
        app.transfer_plan = Some(TransferPlanView {
            kind: TransferKind::Download,
            remote: "/srv/app/releases/config.toml".to_string(),
            local: Some("/Users/mini/Downloads/config.toml".to_string()),
            confirmed: false,
            progress: None,
        });

        let snapshot = app
            .build_assist_snapshot(&AssistContextPolicy::default())
            .unwrap();
        let metadata = serde_json::to_string(&snapshot.metadata).unwrap();

        assert!(metadata.contains("/srv/app/releases"));
        assert!(!metadata.contains("/Users/mini/Downloads"));
        assert_eq!(
            snapshot.metadata["mode"]["transfer_plan"]["local_path_redacted"],
            json!(true)
        );
    }

    #[test]
    fn evidence_redacts_secret_material_and_records_recovery_contract() {
        let launch = SshTuiLaunch {
            profile_label: "prod".to_string(),
            config: Some(SshConfig::new(
                "prod.internal".to_string(),
                22,
                "deploy".to_string(),
                "super-secret-password".to_string(),
            )),
            source: SshTuiSource::Connection,
            fixture_path: None,
            purpose: "terminal".to_string(),
            readonly: false,
            restore: true,
            launch_plan: None,
        };

        let evidence = build_ssh_tui_evidence(&launch).unwrap();
        let rendered = serde_json::to_string(&evidence).unwrap();
        assert!(!rendered.contains("super-secret-password"));
        assert_eq!(evidence["secret_leak_scan"]["passed"], true);
        assert_eq!(
            evidence["recovery_contract"]["disconnected_state_forwards_raw_input"],
            false
        );
        assert!(
            evidence["coverage"]
                .as_array()
                .unwrap()
                .contains(&json!("disconnect_reconnect"))
        );
        assert_eq!(
            evidence["external_agent_interaction"]["current_pty_control"]["revoke_escape"],
            json!("Ctrl+] then v")
        );
        assert_eq!(
            evidence["external_agent_interaction"]["session_share"]["conversation_surface"],
            false
        );
        assert_eq!(
            evidence["external_agent_interaction"]["human_reviewed_takeover_warnings"],
            json!(["alternate_screen_or_application_mode"])
        );
        assert!(
            !evidence["external_agent_interaction"]["blocked_takeover_contexts"]
                .as_array()
                .unwrap()
                .contains(&json!("alternate_screen_or_application_mode"))
        );
        assert!(
            evidence["coverage"]
                .as_array()
                .unwrap()
                .contains(&json!("current_pty_control_revoke"))
        );
    }

    #[test]
    fn disconnected_state_does_not_forward_keys_to_terminal() {
        let fixture = format!(
            "{}/fixtures/ssh_tui_terminal_core.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let launch = SshTuiLaunch {
            profile_label: "fixture".to_string(),
            config: None,
            source: SshTuiSource::Fixture,
            fixture_path: Some(fixture),
            purpose: "terminal".to_string(),
            readonly: false,
            restore: true,
            launch_plan: None,
        };
        let mut app = SshTuiApp::new(launch).unwrap();
        app.mode = Mode::Disconnected;
        app.host_key_prompt = None;
        let before = app.terminal_lines.clone();

        app.handle_key(KeyEvent::new(KeyCode::Char('x'), KeyModifiers::NONE));
        assert_eq!(app.terminal_lines, before);
        assert!(app.status.contains("recovery:"));

        app.handle_key(KeyEvent::new(KeyCode::Char('?'), KeyModifiers::NONE));
        assert_eq!(app.mode, Mode::Help);
        app.handle_key(KeyEvent::new(KeyCode::Char('z'), KeyModifiers::NONE));
        assert_eq!(app.mode, Mode::Disconnected);
    }

    #[test]
    fn terminal_output_parser_consumes_ansi_control_sequences() {
        let fixture = format!(
            "{}/fixtures/ssh_tui_terminal_core.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let launch = SshTuiLaunch {
            profile_label: "fixture".to_string(),
            config: None,
            source: SshTuiSource::Fixture,
            fixture_path: Some(fixture),
            purpose: "terminal".to_string(),
            readonly: false,
            restore: true,
            launch_plan: None,
        };
        let mut app = SshTuiApp::new(launch).unwrap();

        app.push_terminal_output(b"\x1b[2J\x1b[H\x1b[38;5;39msudo\x1b[0m kubectl\r\n");
        let rendered = app.terminal_screen_text_lines(80).join("\n");

        assert!(rendered.contains("sudo kubectl"));
        assert!(!rendered.contains('\x1b'));
        assert!(!rendered.contains("38;5;39m"));
    }

    #[test]
    fn terminal_output_renderer_preserves_remote_shell_colors() {
        let fixture = format!(
            "{}/fixtures/ssh_tui_terminal_core.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let launch = SshTuiLaunch {
            profile_label: "fixture".to_string(),
            config: None,
            source: SshTuiSource::Fixture,
            fixture_path: Some(fixture),
            purpose: "terminal".to_string(),
            readonly: false,
            restore: true,
            launch_plan: None,
        };
        let mut app = SshTuiApp::new(launch).unwrap();

        app.push_terminal_output(
            b"\x1b[2J\x1b[H\x1b[38;5;39msudo\x1b[0m \
              \x1b[1;4;32mkubectl\x1b[0m \
              \x1b[48;2;10;20;30mBG\x1b[0m\r\n",
        );
        let lines = app.terminal_screen_lines(80);

        let sudo = span_containing(&lines, "sudo");
        assert_eq!(sudo.style.fg, Some(Color::Indexed(39)));

        let kubectl = span_containing(&lines, "kubectl");
        assert_eq!(kubectl.style.fg, Some(Color::Indexed(2)));
        assert!(kubectl.style.add_modifier.contains(Modifier::BOLD));
        assert!(kubectl.style.add_modifier.contains(Modifier::UNDERLINED));

        let background = span_containing(&lines, "BG");
        assert_eq!(background.style.bg, Some(Color::Rgb(10, 20, 30)));
    }

    #[test]
    fn terminal_grid_size_uses_terminal_pane_inner_area() {
        let size = terminal_grid_size_for_area(Rect::new(0, 0, 120, 40));

        assert_eq!(size.cols, 118);
        assert_eq!(size.rows, 31);
    }

    #[test]
    fn terminal_text_sanitizer_strips_csi_and_osc_sequences() {
        let text = "a\x1b[38;5;39mb\x1b[0m\x1b]0;title\x07c\r\n";

        assert_eq!(sanitize_terminal_text(text), "abc");
    }

    #[test]
    fn remote_path_helpers_keep_root_and_relative_paths_stable() {
        assert_eq!(remote_child_path("/", "config.toml"), "/config.toml");
        assert_eq!(
            remote_child_path("/srv/app", "config.toml"),
            "/srv/app/config.toml"
        );
        assert_eq!(remote_child_path(".", "config.toml"), "config.toml");
        assert_eq!(remote_parent_path("/srv/app"), "/srv");
        assert_eq!(remote_parent_path("/srv"), "/");
        assert_eq!(remote_parent_path("config.toml"), ".");
    }

    #[test]
    fn forwarding_status_labels_are_stable() {
        assert_eq!(forward_status_label(&ForwardStatus::Starting), "starting");
        assert_eq!(forward_status_label(&ForwardStatus::Active), "active");
        assert_eq!(forward_status_label(&ForwardStatus::Stopped), "stopped");
        assert_eq!(
            forward_status_label(&ForwardStatus::Error("bind failed".to_string())),
            "error"
        );
    }

    #[test]
    fn key_conversion_keeps_ctrl_c_as_remote_input() {
        let key = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert_eq!(key_to_pty_bytes(key), Some(vec![0x03]));
    }

    #[test]
    fn terminal_paste_is_forwarded_as_one_utf8_payload() {
        let mut app = SshTuiApp::new(fixture_launch()).unwrap();
        app.mode = Mode::Terminal;
        app.host_key_prompt = None;
        app.pty_input_owner = PtyInputOwnerState::HumanActive;
        let pasted = "printf 'bulk 粘贴'\n";

        app.handle_paste(pasted);

        assert_eq!(app.forwarded_pty_writes, vec![pasted.as_bytes().to_vec()]);
        assert!(app.terminal_screen_lines(80).iter().any(|line| {
            line.spans
                .iter()
                .any(|span| span.content.contains("bulk 粘贴"))
        }));
    }

    #[test]
    fn paste_is_not_forwarded_outside_raw_terminal_mode() {
        let mut app = SshTuiApp::new(fixture_launch()).unwrap();
        app.mode = Mode::Sftp;

        app.handle_paste("rm -rf /\n");

        assert!(app.forwarded_pty_writes.is_empty());
    }

    #[test]
    fn ctrl_right_bracket_opens_local_escape_layer() {
        let key = KeyEvent::new(KeyCode::Char(']'), KeyModifiers::CONTROL);
        assert!(is_escape_layer_key(key));
    }

    #[test]
    fn ctrl_five_alias_opens_local_escape_layer() {
        let key = KeyEvent::new(KeyCode::Char('5'), KeyModifiers::CONTROL);
        assert!(is_escape_layer_key(key));
    }

    #[test]
    fn ctrl_backslash_remains_remote_input() {
        let key = KeyEvent::new(KeyCode::Char('\\'), KeyModifiers::CONTROL);
        assert!(!is_escape_layer_key(key));
        assert_eq!(key_to_pty_bytes(key), Some(vec![0x1c]));

        let legacy_terminal_key = KeyEvent::new(KeyCode::Char('4'), KeyModifiers::CONTROL);
        assert_eq!(key_to_pty_bytes(legacy_terminal_key), Some(vec![0x1c]));
    }

    #[test]
    fn safe_error_summary_is_single_line_and_bounded() {
        let message = format!("first line\n{}", "x".repeat(240));
        let summary = safe_error_summary(&message);
        assert!(!summary.contains('\n'));
        assert!(summary.len() <= 180);
    }

    fn fixture_launch() -> SshTuiLaunch {
        SshTuiLaunch {
            profile_label: "fixture".to_string(),
            config: None,
            source: SshTuiSource::Fixture,
            fixture_path: Some(format!(
                "{}/fixtures/ssh_tui_terminal_core.json",
                env!("CARGO_MANIFEST_DIR")
            )),
            purpose: "terminal".to_string(),
            readonly: false,
            restore: true,
            launch_plan: None,
        }
    }

    fn temp_assist_store() -> SshAssistStore {
        SshAssistStore::new(std::env::temp_dir().join(format!(
            "voidb-ssh-tui-assist-test-{}",
            uuid::Uuid::new_v4()
        )))
        .unwrap()
    }

    fn share_fixture_session(app: &mut SshTuiApp) -> String {
        app.share_current_session_with_agent();
        app.assist_request.as_ref().unwrap().id.clone()
    }

    fn fixture_app_with_current_pty_action(command: &str) -> (SshTuiApp, SshAssistStore, String) {
        let mut app = SshTuiApp::new(fixture_launch()).unwrap();
        app.host_key_prompt = None;
        app.mode = Mode::Terminal;
        app.return_mode = Mode::Terminal;
        app.status = "ready".to_string();
        let store = temp_assist_store();
        app.assist_store = store.clone();
        let request_id = share_fixture_session(&mut app);
        let binding = app.assist_request.as_ref().unwrap().binding.clone();
        post_fixture_assist_response(
            &store,
            &request_id,
            vec![AssistAction::ProposedCommand {
                command: command.to_string(),
                rationale: "exercise current PTY control".to_string(),
                risk: voidb_core::AssistActionRisk::Review,
                target: AssistActionTarget::CurrentPty { binding },
            }],
            vec![AssistPermission::TakeControl],
        );
        app.drain_service();
        (app, store, request_id)
    }

    fn post_fixture_assist_response(
        store: &SshAssistStore,
        request_id: &str,
        actions: Vec<AssistAction>,
        requested_permissions: Vec<AssistPermission>,
    ) {
        store
            .post_operation_request(
                request_id,
                AssistResponse {
                    id: format!("assist:response:{}", uuid::Uuid::new_v4()),
                    request_id: request_id.to_string(),
                    agent: voidb_core::AgentPrincipal {
                        client_id: "agent".to_string(),
                        task_id: "task-1".to_string(),
                        instance_id: None,
                    },
                    created_at: Utc::now(),
                    summary: "proposed controlled action".to_string(),
                    diagnosis: Some("requires explicit human confirmation".to_string()),
                    actions,
                    requested_permissions,
                    redaction: RedactionStatus::NotRequired,
                },
            )
            .unwrap();
    }

    fn span_containing<'a>(lines: &'a [Line<'static>], text: &str) -> &'a Span<'static> {
        lines
            .iter()
            .flat_map(|line| line.spans.iter())
            .find(|span| span.content.contains(text))
            .unwrap_or_else(|| panic!("span containing {text:?} not found"))
    }
}
