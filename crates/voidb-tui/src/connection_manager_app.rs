//! Native standalone Connection Manager terminal application.
//!
//! This application owns its state, rendering, input model, and persistence.
//! It does not implement `Plugin`, construct `ShellCapabilities`, or reuse the
//! router-hosted Connection Manager screen.

use std::collections::{BTreeSet, HashMap};
use std::io::Write;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow};
use crossterm::event::{self, KeyCode, KeyEvent, KeyModifiers};
use futures::StreamExt;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span, Text};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::{DefaultTerminal, Frame};
use serde_json::{Value, json};
use voidb_core::{
    AgentAuthorizationPresetKind, AppConfig, ConnectionConfig, ConnectionProfile, DatabaseType,
    LocalProfileStore, ProfileFormField, ProfileFormFieldKind, ProfileFormSchema,
};

use crate::profile_forms::{default_plugin_config, profile_form_schema};

const MIN_WIDTH: u16 = 72;
const MIN_HEIGHT: u16 = 20;
const NATIVE_PROFILE_SOURCE: &str = "native_profile_store";
const AUTHORIZATION_REFRESH_INTERVAL: Duration = Duration::from_secs(2);
const AUTHORIZATION_TTL_OPTIONS: &[u64] = &[5, 15, 30, 60];
const AUTHORIZATION_USE_OPTIONS: &[Option<u32>] = &[None, Some(1), Some(10), Some(25), Some(100)];

const PLUGINS: &[(&str, &str)] = &[
    ("mysql", "MySQL"),
    ("postgres", "PostgreSQL"),
    ("sqlite", "SQLite"),
    ("redis", "Redis"),
    ("ssh", "SSH"),
    ("docker", "Docker"),
    ("kubernetes", "Kubernetes"),
    ("webdav", "WebDAV"),
    ("s3", "S3"),
    ("elasticsearch", "Elasticsearch"),
    ("mongodb", "MongoDB"),
    ("duckdb", "DuckDB"),
    ("email", "Email"),
    ("jenkins", "Jenkins"),
];

type BackgroundResult = Receiver<std::result::Result<String, String>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScreenMode {
    Browse,
    Search,
    Edit,
    ConfirmDelete,
    Help,
    Credentials,
    Capabilities,
    Authorization,
    AuthorizationInbox,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CredentialMode {
    Unlock,
    Set,
}

#[derive(Debug)]
struct CredentialDialog {
    mode: CredentialMode,
    password: String,
    confirmation: String,
    active_field: usize,
    message: Option<String>,
}

impl CredentialDialog {
    fn new(mode: CredentialMode) -> Self {
        Self {
            mode,
            password: String::new(),
            confirmation: String::new(),
            active_field: 0,
            message: None,
        }
    }

    fn field_count(&self) -> usize {
        if self.mode == CredentialMode::Set {
            2
        } else {
            1
        }
    }

    fn value_mut(&mut self) -> &mut String {
        if self.active_field == 0 {
            &mut self.password
        } else {
            &mut self.confirmation
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EditorView {
    Form,
    Json,
}

#[derive(Debug)]
struct ProfileEditor {
    existing_profile_id: Option<String>,
    name: String,
    display_name: String,
    plugin_index: usize,
    config: Value,
    schema: ProfileFormSchema,
    view: EditorView,
    config_lines: Vec<String>,
    cursor_line: usize,
    cursor_col: usize,
    active_field: usize,
    message: Option<String>,
}

impl ProfileEditor {
    fn new() -> Self {
        let plugin_id = PLUGINS[0].0;
        let config = default_plugin_config(plugin_id);
        Self {
            existing_profile_id: None,
            name: String::new(),
            display_name: String::new(),
            plugin_index: 0,
            config_lines: pretty_json_lines(config.clone()),
            config,
            schema: profile_form_schema(plugin_id),
            view: EditorView::Form,
            cursor_line: 0,
            cursor_col: 0,
            active_field: 0,
            message: None,
        }
    }

    fn edit(profile: &ConnectionProfile, connection: ConnectionConfig) -> Self {
        let plugin_index = PLUGINS
            .iter()
            .position(|(id, _)| *id == profile.plugin_id)
            .unwrap_or(0);
        let config = connection.plugin_config.unwrap_or_else(|| json!({}));
        Self {
            existing_profile_id: Some(profile.id.clone()),
            name: profile.name.clone(),
            display_name: profile.display_name.clone().unwrap_or_default(),
            plugin_index,
            config_lines: pretty_json_lines(config.clone()),
            config,
            schema: profile_form_schema(&profile.plugin_id),
            view: EditorView::Form,
            cursor_line: 0,
            cursor_col: 0,
            active_field: 0,
            message: None,
        }
    }

    fn plugin_id(&self) -> &'static str {
        PLUGINS[self.plugin_index].0
    }

    fn plugin_label(&self) -> &'static str {
        PLUGINS[self.plugin_index].1
    }

    fn cycle_plugin(&mut self, forward: bool) {
        if self.existing_profile_id.is_some() {
            self.message =
                Some("Plugin type is immutable; create a new profile to change it".into());
            return;
        }
        self.plugin_index = if forward {
            (self.plugin_index + 1) % PLUGINS.len()
        } else if self.plugin_index == 0 {
            PLUGINS.len() - 1
        } else {
            self.plugin_index - 1
        };
        if self.existing_profile_id.is_none() {
            self.config = default_plugin_config(self.plugin_id());
            self.schema = profile_form_schema(self.plugin_id());
            self.config_lines = pretty_json_lines(self.config.clone());
            self.cursor_line = 0;
            self.cursor_col = 0;
            self.active_field = 0;
            self.message = None;
        }
    }

    fn field_count(&self) -> usize {
        match self.view {
            EditorView::Form => 3 + self.schema.visible_fields(&self.config).len(),
            EditorView::Json => 4,
        }
    }

    fn active_form_field(&self) -> Option<&ProfileFormField> {
        let index = self.active_field.checked_sub(3)?;
        self.schema.visible_fields(&self.config).get(index).copied()
    }

    fn form_field_display(&self, field: &ProfileFormField) -> String {
        match &field.kind {
            ProfileFormFieldKind::Select { options } => options
                .iter()
                .find(|option| option.matches_config(&field.path, &self.config))
                .map(|option| option.label.clone())
                .unwrap_or_else(|| "<invalid choice>".to_string()),
            ProfileFormFieldKind::Secret => self
                .config
                .pointer(&field.path)
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(|value| "•".repeat(value.chars().count()))
                .unwrap_or_else(|| "<not set>".to_string()),
            ProfileFormFieldKind::Boolean => self
                .config
                .pointer(&field.path)
                .and_then(Value::as_bool)
                .map(|value| if value { "Yes" } else { "No" }.to_string())
                .unwrap_or_else(|| "<not set>".to_string()),
            ProfileFormFieldKind::StringList => self
                .config
                .pointer(&field.path)
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "<empty>".to_string()),
            _ => scalar_text(self.config.pointer(&field.path))
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "<not set>".to_string()),
        }
    }

    fn form_field_help(&self, field: &ProfileFormField) -> String {
        let required = if field.required {
            "required"
        } else {
            "optional"
        };
        match &field.kind {
            ProfileFormFieldKind::Select { options } => format!(
                "{} · {} · valid values: {}",
                field.description,
                required,
                options
                    .iter()
                    .map(|option| {
                        let value = match &option.value {
                            Value::String(value) if value == &option.label => String::new(),
                            Value::String(value) => format!(" [{}]", value),
                            Value::Null => " [null]".to_string(),
                            value => format!(" [{}]", value),
                        };
                        format!("{}{}", option.label, value)
                    })
                    .collect::<Vec<_>>()
                    .join(" / ")
            ),
            ProfileFormFieldKind::Integer { minimum, maximum } => format!(
                "{} · {} · range {}..{}",
                field.description,
                required,
                minimum
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "any".into()),
                maximum
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "any".into())
            ),
            ProfileFormFieldKind::Secret => {
                format!("{} · {} · encrypted at rest", field.description, required)
            }
            _ => format!("{} · {}", field.description, required),
        }
    }

    fn toggle_view(&mut self) {
        match self.view {
            EditorView::Form => {
                self.config_lines = pretty_json_lines(self.config.clone());
                self.cursor_line = 0;
                self.cursor_col = 0;
                self.active_field = 3;
                self.view = EditorView::Json;
                self.message = None;
            }
            EditorView::Json => match serde_json::from_str::<Value>(&self.config_text()) {
                Ok(config) if config.is_object() => {
                    self.config = config;
                    self.active_field = 3.min(self.field_count().saturating_sub(1));
                    self.view = EditorView::Form;
                    self.message = None;
                }
                Ok(_) => {
                    self.message = Some("Plugin configuration must be a JSON object".to_string())
                }
                Err(error) => self.message = Some(format!("Invalid JSON: {error}")),
            },
        }
    }

    fn cycle_form_value(&mut self, forward: bool) {
        let Some(field) = self.active_form_field().cloned() else {
            return;
        };
        match &field.kind {
            ProfileFormFieldKind::Select { options } if !options.is_empty() => {
                let current = options
                    .iter()
                    .position(|option| option.matches_config(&field.path, &self.config))
                    .unwrap_or(0);
                let next = if forward {
                    (current + 1) % options.len()
                } else if current == 0 {
                    options.len() - 1
                } else {
                    current - 1
                };
                set_json_pointer(&mut self.config, &field.path, options[next].stored_value());
                self.active_field = self.active_field.min(self.field_count().saturating_sub(1));
                self.message = None;
            }
            ProfileFormFieldKind::Boolean => {
                let current = self
                    .config
                    .pointer(&field.path)
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                set_json_pointer(&mut self.config, &field.path, json!(!current));
                self.message = None;
            }
            _ => {}
        }
    }

    fn append_form_character(&mut self, character: char) {
        let Some(field) = self.active_form_field().cloned() else {
            return;
        };
        match field.kind {
            ProfileFormFieldKind::Text { .. } | ProfileFormFieldKind::Secret => {
                let mut value = self
                    .config
                    .pointer(&field.path)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                value.push(character);
                set_json_pointer(&mut self.config, &field.path, json!(value));
                self.message = None;
            }
            ProfileFormFieldKind::Integer { .. }
                if character.is_ascii_digit()
                    || (character == '-'
                        && scalar_text(self.config.pointer(&field.path))
                            .is_none_or(|value| value.is_empty())) =>
            {
                let mut value = scalar_text(self.config.pointer(&field.path)).unwrap_or_default();
                value.push(character);
                match value.parse::<i64>() {
                    Ok(number) => {
                        set_json_pointer(&mut self.config, &field.path, json!(number));
                        self.message = None;
                    }
                    Err(_) if value == "-" => {
                        self.message = Some("Continue typing the integer value".to_string())
                    }
                    Err(_) => self.message = Some(format!("{} must be an integer", field.label)),
                }
            }
            ProfileFormFieldKind::StringList => {
                let mut value = self.form_field_raw_text(&field);
                value.push(character);
                set_json_pointer(&mut self.config, &field.path, string_list_value(&value));
                self.message = None;
            }
            _ => {}
        }
    }

    fn backspace_form_value(&mut self) {
        let Some(field) = self.active_form_field().cloned() else {
            return;
        };
        match field.kind {
            ProfileFormFieldKind::Text { .. } | ProfileFormFieldKind::Secret => {
                let mut value = self.form_field_raw_text(&field);
                value.pop();
                set_json_pointer(
                    &mut self.config,
                    &field.path,
                    if value.is_empty() && !field.required {
                        Value::Null
                    } else {
                        json!(value)
                    },
                );
            }
            ProfileFormFieldKind::Integer { .. } => {
                let mut value = self.form_field_raw_text(&field);
                value.pop();
                let next = value.parse::<i64>().map(Value::from).unwrap_or(Value::Null);
                set_json_pointer(&mut self.config, &field.path, next);
            }
            ProfileFormFieldKind::StringList => {
                let mut value = self.form_field_raw_text(&field);
                value.pop();
                set_json_pointer(&mut self.config, &field.path, string_list_value(&value));
            }
            _ => {}
        }
        self.message = None;
    }

    fn clear_active_value(&mut self) {
        match self.active_field {
            1 => self.name.clear(),
            2 => self.display_name.clear(),
            3.. if self.view == EditorView::Form => {
                let Some(field) = self.active_form_field().cloned() else {
                    return;
                };
                let value = match field.kind {
                    ProfileFormFieldKind::Text { .. } | ProfileFormFieldKind::Secret => {
                        if field.required {
                            json!("")
                        } else {
                            Value::Null
                        }
                    }
                    ProfileFormFieldKind::Integer { .. } => Value::Null,
                    ProfileFormFieldKind::StringList => json!([]),
                    _ => return,
                };
                set_json_pointer(&mut self.config, &field.path, value);
                self.message = None;
            }
            _ => {}
        }
    }

    fn form_field_raw_text(&self, field: &ProfileFormField) -> String {
        match field.kind {
            ProfileFormFieldKind::StringList => self
                .config
                .pointer(&field.path)
                .and_then(Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join(", ")
                })
                .unwrap_or_default(),
            _ => scalar_text(self.config.pointer(&field.path)).unwrap_or_default(),
        }
    }

    fn config_text(&self) -> String {
        self.config_lines.join("\n")
    }

    fn insert_char(&mut self, character: char) {
        let line = &mut self.config_lines[self.cursor_line];
        let byte = byte_index(line, self.cursor_col);
        line.insert(byte, character);
        self.cursor_col += 1;
    }

    fn insert_newline(&mut self) {
        let line = &mut self.config_lines[self.cursor_line];
        let byte = byte_index(line, self.cursor_col);
        let tail = line.split_off(byte);
        self.cursor_line += 1;
        self.cursor_col = 0;
        self.config_lines.insert(self.cursor_line, tail);
    }

    fn backspace(&mut self) {
        if self.cursor_col > 0 {
            let line = &mut self.config_lines[self.cursor_line];
            let end = byte_index(line, self.cursor_col);
            let start = byte_index(line, self.cursor_col - 1);
            line.replace_range(start..end, "");
            self.cursor_col -= 1;
        } else if self.cursor_line > 0 {
            let tail = self.config_lines.remove(self.cursor_line);
            self.cursor_line -= 1;
            self.cursor_col = self.config_lines[self.cursor_line].chars().count();
            self.config_lines[self.cursor_line].push_str(&tail);
        }
    }

    fn move_vertical(&mut self, down: bool) {
        if down && self.cursor_line + 1 < self.config_lines.len() {
            self.cursor_line += 1;
        } else if !down && self.cursor_line > 0 {
            self.cursor_line -= 1;
        }
        self.cursor_col = self
            .cursor_col
            .min(self.config_lines[self.cursor_line].chars().count());
    }
}

#[derive(Debug, Clone)]
struct CapabilityItem {
    id: String,
    description: String,
    risk: String,
    interactive_execute: bool,
    capability_wide_allowed: bool,
    approval_fields: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AuthorizationStatusView {
    grant_id: String,
    profile_id: String,
    plugin_id: String,
    status: String,
    broker_health: String,
    allow_destructive: bool,
    expires_at: String,
    remaining_uses: Option<u32>,
    active_session_count: usize,
    capabilities: Vec<String>,
}

impl AuthorizationStatusView {
    fn badge(&self) -> &'static str {
        match self.status.as_str() {
            "expiring" => "EXPIRING",
            "exhausted" => "EXHAUSTED",
            "expired" => "EXPIRED",
            "stale" => "STALE",
            "broker_offline" => "BROKER OFFLINE",
            _ if self.allow_destructive => "EXECUTE",
            _ => "READ-ONLY",
        }
    }

    fn detail(&self) -> String {
        format!(
            "{} · broker {} · {} · {} active session{} · expires {}",
            self.badge(),
            self.broker_health,
            format_use_limit(self.remaining_uses),
            self.active_session_count,
            plural(self.active_session_count),
            self.expires_at
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthorizationAction {
    Authorize,
    Renew,
    RevokeProfile,
    RevokeAll,
}

#[derive(Debug)]
struct AuthorizationDialog {
    profile: ConnectionProfile,
    capabilities: Vec<CapabilityItem>,
    preset: AgentAuthorizationPresetKind,
    custom_selected: BTreeSet<String>,
    capability_selected: usize,
    ttl_index: usize,
    uses_index: usize,
    destructive_acknowledged: bool,
    advanced: bool,
    loading: bool,
    review_action: Option<AuthorizationAction>,
    message: Option<String>,
}

impl AuthorizationDialog {
    fn new(profile: ConnectionProfile) -> Self {
        Self {
            profile,
            capabilities: Vec::new(),
            preset: AgentAuthorizationPresetKind::ReadOnly,
            custom_selected: BTreeSet::new(),
            capability_selected: 0,
            ttl_index: 1,
            uses_index: 0,
            destructive_acknowledged: false,
            advanced: false,
            loading: true,
            review_action: None,
            message: None,
        }
    }

    fn ttl_minutes(&self) -> u64 {
        AUTHORIZATION_TTL_OPTIONS[self.ttl_index]
    }

    fn uses(&self) -> Option<u32> {
        AUTHORIZATION_USE_OPTIONS[self.uses_index]
    }

    fn cycle_preset(&mut self, forward: bool) {
        let presets = [
            AgentAuthorizationPresetKind::ReadOnly,
            AgentAuthorizationPresetKind::InteractiveExecute,
            AgentAuthorizationPresetKind::FullAccess,
            AgentAuthorizationPresetKind::Custom,
        ];
        let current = presets
            .iter()
            .position(|preset| *preset == self.preset)
            .unwrap_or(0);
        let next = if forward {
            (current + 1) % presets.len()
        } else if current == 0 {
            presets.len() - 1
        } else {
            current - 1
        };
        self.preset = presets[next];
        self.destructive_acknowledged = false;
        self.review_action = None;
        self.message = None;
    }

    fn selected_capabilities(&self) -> Vec<String> {
        let mut selected = match self.preset {
            AgentAuthorizationPresetKind::ReadOnly => self
                .capabilities
                .iter()
                .filter(|capability| capability.risk == "read_only")
                .map(|capability| capability.id.clone())
                .collect(),
            AgentAuthorizationPresetKind::InteractiveExecute => {
                interactive_execute_capabilities(&self.capabilities)
            }
            AgentAuthorizationPresetKind::FullAccess => self
                .capabilities
                .iter()
                .map(|capability| capability.id.clone())
                .collect(),
            AgentAuthorizationPresetKind::Custom => self.custom_selected.iter().cloned().collect(),
        };
        selected.sort();
        selected.dedup();
        selected
    }

    fn requires_destructive_acknowledgement(&self) -> bool {
        let selected = self.selected_capabilities();
        self.capabilities
            .iter()
            .any(|capability| selected.contains(&capability.id) && capability.risk != "read_only")
    }

    fn preset_label(&self) -> &'static str {
        match self.preset {
            AgentAuthorizationPresetKind::ReadOnly => "Read-only (recommended)",
            AgentAuthorizationPresetKind::InteractiveExecute => "Interactive/Execute",
            AgentAuthorizationPresetKind::FullAccess => "Full access",
            AgentAuthorizationPresetKind::Custom => "Custom",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
struct PendingAuthorizationView {
    id: String,
    principal_fingerprint: String,
    profile_id: String,
    plugin_id: String,
    scope: Value,
    risk: String,
    purpose: String,
    status: String,
    created_at: String,
    expires_at: String,
    timed_out: bool,
    decision_reason: Option<String>,
}

impl PendingAuthorizationView {
    fn capability_id(&self) -> &str {
        self.scope
            .get("capability_id")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
    }

    fn is_pending(&self) -> bool {
        self.status == "pending"
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GrantRevisionView {
    grant_id: String,
    revision: u64,
    principal_fingerprint: String,
    profile_id: String,
    plugin_id: String,
    expires_at: String,
    remaining_uses: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JitDecision {
    Once,
    Bounded,
    AddToGrant,
    Deny,
}

impl JitDecision {
    fn label(self) -> &'static str {
        match self {
            Self::Once => "Approve once",
            Self::Bounded => "Time-bounded",
            Self::AddToGrant => "Add to logical grant",
            Self::Deny => "Deny",
        }
    }

    fn cli_value(self) -> &'static str {
        match self {
            Self::Once => "once",
            Self::Bounded => "bounded",
            Self::AddToGrant => "add_to_grant",
            Self::Deny => "deny",
        }
    }

    fn cycle(self, forward: bool, has_grant: bool) -> Self {
        let choices = if has_grant {
            vec![Self::Once, Self::Bounded, Self::AddToGrant, Self::Deny]
        } else {
            vec![Self::Once, Self::Bounded, Self::Deny]
        };
        let index = choices.iter().position(|value| *value == self).unwrap_or(0);
        let next = if forward {
            (index + 1) % choices.len()
        } else if index == 0 {
            choices.len() - 1
        } else {
            index - 1
        };
        choices[next]
    }
}

#[derive(Debug)]
struct JitApprovalDialog {
    request: PendingAuthorizationView,
    decision: JitDecision,
    ttl_index: usize,
    uses_index: usize,
    grant_id: Option<String>,
    constraints_json: String,
    editing_constraints: bool,
    confirm: bool,
    message: Option<String>,
}

impl JitApprovalDialog {
    fn new(request: PendingAuthorizationView, revisions: &[GrantRevisionView]) -> Self {
        let grant_id = revisions
            .iter()
            .rev()
            .find(|revision| {
                revision.principal_fingerprint == request.principal_fingerprint
                    && revision.profile_id == request.profile_id
                    && revision.plugin_id == request.plugin_id
            })
            .map(|revision| revision.grant_id.clone());
        Self {
            request,
            decision: JitDecision::Bounded,
            ttl_index: 1,
            uses_index: 0,
            grant_id,
            constraints_json: String::new(),
            editing_constraints: false,
            confirm: false,
            message: None,
        }
    }

    fn ttl_minutes(&self) -> u64 {
        AUTHORIZATION_TTL_OPTIONS[self.ttl_index]
    }

    fn uses(&self) -> Option<u32> {
        AUTHORIZATION_USE_OPTIONS[self.uses_index]
    }
}

pub struct ConnectionManagerApp {
    store: LocalProfileStore,
    config: AppConfig,
    profiles: Vec<ConnectionProfile>,
    filtered_indices: Vec<usize>,
    selected: usize,
    list_state: ListState,
    mode: ScreenMode,
    search: String,
    editor: Option<ProfileEditor>,
    credential_dialog: Option<CredentialDialog>,
    active_master_password: Option<String>,
    status: String,
    test_rx: Option<BackgroundResult>,
    capability_rx: Option<BackgroundResult>,
    capabilities: Vec<CapabilityItem>,
    capability_selected: usize,
    authorization_dialog: Option<AuthorizationDialog>,
    authorization_catalog_rx: Option<BackgroundResult>,
    authorization_operation_rx: Option<BackgroundResult>,
    authorization_status_rx: Option<BackgroundResult>,
    authorization_statuses: HashMap<(String, String), AuthorizationStatusView>,
    authorization_supported_plugins: BTreeSet<String>,
    authorization_capability_catalog: HashMap<String, CapabilityItem>,
    pending_authorization_requests: Vec<PendingAuthorizationView>,
    grant_revisions: Vec<GrantRevisionView>,
    authorization_inbox_selected: usize,
    authorization_observed_at: Option<String>,
    authorization_snapshot_error: Option<String>,
    jit_approval_dialog: Option<JitApprovalDialog>,
    next_authorization_refresh: Instant,
    should_quit: bool,
}

impl ConnectionManagerApp {
    pub fn new(config: AppConfig) -> Result<Self> {
        let store = LocalProfileStore::default_store()?;
        let (config, active_master_password) = if config.requires_master_password() {
            match voidb_core::active_master_password_from_env()
                .ok()
                .and_then(|password| {
                    AppConfig::load_with_password(Some(&password))
                        .ok()
                        .map(|config| (config, password))
                }) {
                Some((config, password)) => (config, Some(password)),
                None => (config, None),
            }
        } else {
            (config, None)
        };
        let mut app = Self {
            store,
            config,
            profiles: Vec::new(),
            filtered_indices: Vec::new(),
            selected: 0,
            list_state: ListState::default(),
            mode: ScreenMode::Browse,
            search: String::new(),
            editor: None,
            credential_dialog: None,
            active_master_password,
            status: "Ready".to_string(),
            test_rx: None,
            capability_rx: None,
            capabilities: Vec::new(),
            capability_selected: 0,
            authorization_dialog: None,
            authorization_catalog_rx: None,
            authorization_operation_rx: None,
            authorization_status_rx: None,
            authorization_statuses: HashMap::new(),
            authorization_supported_plugins: PLUGINS
                .iter()
                .map(|(plugin_id, _)| (*plugin_id).to_string())
                .collect(),
            authorization_capability_catalog: HashMap::new(),
            pending_authorization_requests: Vec::new(),
            grant_revisions: Vec::new(),
            authorization_inbox_selected: 0,
            authorization_observed_at: None,
            authorization_snapshot_error: None,
            jit_approval_dialog: None,
            next_authorization_refresh: Instant::now(),
            should_quit: false,
        };
        app.refresh_profiles()?;
        if app.config.requires_master_password() && app.active_master_password.is_none() {
            app.status = "Profile credentials are locked; press m to unlock".to_string();
        } else if app.profiles.is_empty() {
            app.status = "No native profiles yet; press n to create one".to_string();
        }
        app.start_authorization_status_refresh();
        Ok(app)
    }

    pub async fn run(&mut self, terminal: &mut DefaultTerminal) -> Result<()> {
        terminal.draw(|frame| self.render(frame))?;
        let mut events = event::EventStream::new();
        let mut tick = tokio::time::interval(Duration::from_millis(100));

        while !self.should_quit {
            let dirty = tokio::select! {
                _ = tick.tick() => self.poll_background(),
                next = events.next() => {
                    match next {
                        Some(Ok(event::Event::Key(key)))
                            if key.kind == event::KeyEventKind::Press
                                || key.kind == event::KeyEventKind::Repeat => self.handle_key(key),
                        Some(Ok(event::Event::Paste(text))) => self.handle_paste(&text),
                        Some(Ok(event::Event::Resize(_, _))) => {}
                        Some(Ok(_)) => continue,
                        Some(Err(error)) => return Err(error.into()),
                        None => break,
                    }
                    self.poll_background();
                    true
                }
            };
            if dirty {
                terminal.draw(|frame| self.render(frame))?;
            }
        }
        Ok(())
    }

    fn refresh_profiles(&mut self) -> Result<()> {
        self.profiles = self
            .store
            .load_profiles()?
            .into_iter()
            .filter(is_native_profile)
            .collect();
        self.profiles.sort_by(|left, right| {
            left.plugin_id
                .cmp(&right.plugin_id)
                .then_with(|| left.name.to_lowercase().cmp(&right.name.to_lowercase()))
        });
        self.refilter();
        Ok(())
    }

    fn refilter(&mut self) {
        let needle = self.search.to_lowercase();
        self.filtered_indices = self
            .profiles
            .iter()
            .enumerate()
            .filter(|(_, profile)| {
                needle.is_empty()
                    || profile.name.to_lowercase().contains(&needle)
                    || profile.plugin_id.to_lowercase().contains(&needle)
                    || profile
                        .display_name
                        .as_deref()
                        .unwrap_or_default()
                        .to_lowercase()
                        .contains(&needle)
            })
            .map(|(index, _)| index)
            .collect();
        self.selected = self
            .selected
            .min(self.filtered_indices.len().saturating_sub(1));
        self.list_state
            .select((!self.filtered_indices.is_empty()).then_some(self.selected));
    }

    fn selected_profile(&self) -> Option<&ConnectionProfile> {
        self.filtered_indices
            .get(self.selected)
            .and_then(|index| self.profiles.get(*index))
    }

    fn handle_key(&mut self, key: KeyEvent) {
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('q') | KeyCode::Char('c'))
        {
            self.should_quit = true;
            return;
        }
        match self.mode {
            ScreenMode::Browse => self.handle_browse_key(key),
            ScreenMode::Search => self.handle_search_key(key),
            ScreenMode::Edit => self.handle_editor_key(key),
            ScreenMode::ConfirmDelete => self.handle_delete_key(key),
            ScreenMode::Help => {
                if matches!(key.code, KeyCode::Esc | KeyCode::Char('?') | KeyCode::Enter) {
                    self.mode = ScreenMode::Browse;
                }
            }
            ScreenMode::Credentials => self.handle_credential_key(key),
            ScreenMode::Capabilities => self.handle_capability_key(key),
            ScreenMode::Authorization => self.handle_authorization_key(key),
            ScreenMode::AuthorizationInbox => self.handle_authorization_inbox_key(key),
        }
    }

    fn handle_browse_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(true),
            KeyCode::Up | KeyCode::Char('k') => self.move_selection(false),
            KeyCode::Char('/') => {
                self.search.clear();
                self.mode = ScreenMode::Search;
            }
            KeyCode::Char('n') => self.begin_create(),
            KeyCode::Char('e') => self.begin_edit(),
            KeyCode::Char('d') if self.selected_profile().is_some() => {
                self.mode = ScreenMode::ConfirmDelete;
            }
            KeyCode::Char('r') => match self.refresh_profiles() {
                Ok(()) => self.status = format!("Reloaded {} native profiles", self.profiles.len()),
                Err(error) => self.status = format!("Refresh failed: {error}"),
            },
            KeyCode::Char('t') => self.start_test(),
            KeyCode::Char('c') => self.start_capability_load(),
            KeyCode::Char('a') => self.open_agent_authorization(None),
            KeyCode::Char('p') => {
                self.authorization_inbox_selected = 0;
                self.mode = ScreenMode::AuthorizationInbox;
                self.next_authorization_refresh = Instant::now();
                self.start_authorization_status_refresh();
            }
            KeyCode::Char('x') => {
                self.open_agent_authorization(Some(AuthorizationAction::RevokeAll))
            }
            KeyCode::Char('m') => self.open_credentials(),
            KeyCode::Char('?') => self.mode = ScreenMode::Help,
            KeyCode::Enter => self.show_guidance(),
            _ => {}
        }
    }

    fn handle_search_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc | KeyCode::Enter => self.mode = ScreenMode::Browse,
            KeyCode::Backspace => {
                self.search.pop();
                self.refilter();
            }
            KeyCode::Down => self.move_selection(true),
            KeyCode::Up => self.move_selection(false),
            KeyCode::Char(character) if !character.is_control() => {
                self.search.push(character);
                self.refilter();
            }
            _ => {}
        }
    }

    fn open_agent_authorization(&mut self, action: Option<AuthorizationAction>) {
        if action == Some(AuthorizationAction::RevokeAll) {
            let profile = self
                .selected_profile()
                .cloned()
                .unwrap_or(ConnectionProfile {
                    id: "global".into(),
                    name: "all profiles".into(),
                    plugin_id: "global".into(),
                    display_name: Some("All local agent grants".into()),
                    metadata: Value::Null,
                    default_options: Value::Null,
                    credential_refs: Vec::new(),
                    policy: Default::default(),
                });
            let mut dialog = AuthorizationDialog::new(profile);
            dialog.loading = false;
            dialog.review_action = action;
            self.authorization_dialog = Some(dialog);
            self.mode = ScreenMode::Authorization;
            return;
        }
        let Some(profile) = self.selected_profile().cloned() else {
            self.status = "Select a profile before authorizing agent access".to_string();
            return;
        };
        if self.config.requires_master_password() && self.active_master_password.is_none() {
            self.status = "Press m to unlock credentials before authorizing an agent".to_string();
            return;
        }
        let mut dialog = AuthorizationDialog::new(profile.clone());
        dialog.review_action = action;
        let (tx, rx) = mpsc::channel();
        self.authorization_catalog_rx = Some(rx);
        self.authorization_dialog = Some(dialog);
        self.mode = ScreenMode::Authorization;
        self.status = format!("Loading authorization catalog for {}...", profile.plugin_id);
        std::thread::spawn(move || {
            let result = run_capability_list(&profile.plugin_id);
            let _ = tx.send(result);
        });
    }

    fn handle_editor_key(&mut self, key: KeyEvent) {
        if key.code == KeyCode::Esc {
            self.editor = None;
            self.mode = ScreenMode::Browse;
            self.status = "Edit cancelled".to_string();
            return;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('s') {
            self.save_editor();
            return;
        }
        let Some(editor) = &mut self.editor else {
            self.mode = ScreenMode::Browse;
            return;
        };
        if key.code == KeyCode::F(2) {
            editor.toggle_view();
            return;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('u') {
            editor.clear_active_value();
            return;
        }
        let field_count = editor.field_count().max(1);
        match key.code {
            KeyCode::Tab => editor.active_field = (editor.active_field + 1) % field_count,
            KeyCode::BackTab => {
                editor.active_field = if editor.active_field == 0 {
                    field_count - 1
                } else {
                    editor.active_field - 1
                }
            }
            KeyCode::Left if editor.active_field == 0 => editor.cycle_plugin(false),
            KeyCode::Right if editor.active_field == 0 => editor.cycle_plugin(true),
            KeyCode::Up if editor.active_field == 0 => editor.cycle_plugin(false),
            KeyCode::Down if editor.active_field == 0 => editor.cycle_plugin(true),
            KeyCode::Left if editor.view == EditorView::Json && editor.active_field == 3 => {
                editor.cursor_col = editor.cursor_col.saturating_sub(1)
            }
            KeyCode::Right if editor.view == EditorView::Json && editor.active_field == 3 => {
                editor.cursor_col = (editor.cursor_col + 1)
                    .min(editor.config_lines[editor.cursor_line].chars().count())
            }
            KeyCode::Up if editor.view == EditorView::Json && editor.active_field == 3 => {
                editor.move_vertical(false)
            }
            KeyCode::Down if editor.view == EditorView::Json && editor.active_field == 3 => {
                editor.move_vertical(true)
            }
            KeyCode::Enter if editor.view == EditorView::Json && editor.active_field == 3 => {
                editor.insert_newline()
            }
            KeyCode::Backspace if editor.view == EditorView::Json && editor.active_field == 3 => {
                editor.backspace()
            }
            KeyCode::Left | KeyCode::Right | KeyCode::Enter
                if editor.view == EditorView::Form && editor.active_field >= 3 =>
            {
                editor.cycle_form_value(!matches!(key.code, KeyCode::Left));
            }
            KeyCode::Up if editor.view == EditorView::Form && editor.active_field >= 3 => {
                editor.active_field = editor.active_field.saturating_sub(1).max(3)
            }
            KeyCode::Down if editor.view == EditorView::Form && editor.active_field >= 3 => {
                editor.active_field = (editor.active_field + 1).min(field_count - 1)
            }
            KeyCode::Backspace if editor.view == EditorView::Form && editor.active_field >= 3 => {
                editor.backspace_form_value()
            }
            KeyCode::Backspace => {
                if editor.active_field == 1 {
                    editor.name.pop();
                } else if editor.active_field == 2 {
                    editor.display_name.pop();
                }
            }
            KeyCode::Char(character) if !character.is_control() => match editor.active_field {
                1 => editor.name.push(character),
                2 => editor.display_name.push(character),
                3.. if editor.view == EditorView::Form => editor.append_form_character(character),
                3 if editor.view == EditorView::Json => editor.insert_char(character),
                _ => {}
            },
            _ => {}
        }
    }

    fn handle_delete_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Char('y') | KeyCode::Enter => {
                if let Some(profile) = self.selected_profile().cloned() {
                    match self.store.delete_profile(&profile.id) {
                        Ok(true) => {
                            self.status = format!("Deleted native profile '{}'", profile.name);
                            let _ = self.refresh_profiles();
                        }
                        Ok(false) => self.status = "Profile was already removed".to_string(),
                        Err(error) => self.status = format!("Delete failed: {error}"),
                    }
                }
                self.mode = ScreenMode::Browse;
            }
            KeyCode::Char('n') | KeyCode::Esc => self.mode = ScreenMode::Browse,
            _ => {}
        }
    }

    fn handle_credential_key(&mut self, key: KeyEvent) {
        if key.code == KeyCode::Esc {
            self.credential_dialog = None;
            self.mode = ScreenMode::Browse;
            return;
        }
        let Some(dialog) = &mut self.credential_dialog else {
            self.mode = ScreenMode::Browse;
            return;
        };
        match key.code {
            KeyCode::Tab | KeyCode::Down => {
                dialog.active_field = (dialog.active_field + 1) % dialog.field_count()
            }
            KeyCode::BackTab | KeyCode::Up => {
                dialog.active_field = if dialog.active_field == 0 {
                    dialog.field_count() - 1
                } else {
                    dialog.active_field - 1
                }
            }
            KeyCode::Backspace => {
                dialog.value_mut().pop();
            }
            KeyCode::Enter => self.submit_credentials(),
            KeyCode::Char(character) if !character.is_control() => {
                dialog.value_mut().push(character)
            }
            _ => {}
        }
    }

    fn handle_capability_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => self.mode = ScreenMode::Browse,
            KeyCode::Down | KeyCode::Char('j') => {
                self.capability_selected =
                    (self.capability_selected + 1).min(self.capabilities.len().saturating_sub(1));
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.capability_selected = self.capability_selected.saturating_sub(1);
            }
            KeyCode::Enter => {
                if let (Some(profile), Some(capability)) = (
                    self.selected_profile(),
                    self.capabilities.get(self.capability_selected),
                ) {
                    self.status = format!(
                        "voidb-cli invoke run {} --profile id:{} --input '{{}}'",
                        capability.id, profile.id
                    );
                    self.mode = ScreenMode::Browse;
                }
            }
            _ => {}
        }
    }

    fn handle_authorization_key(&mut self, key: KeyEvent) {
        if self.authorization_operation_rx.is_some() {
            if key.code == KeyCode::Esc {
                self.status = "Authorization operation is still running".to_string();
            }
            return;
        }
        let existing = self.authorization_dialog.as_ref().and_then(|dialog| {
            self.authorization_statuses
                .get(&(dialog.profile.id.clone(), dialog.profile.plugin_id.clone()))
                .cloned()
        });
        let Some(dialog) = &mut self.authorization_dialog else {
            self.mode = ScreenMode::Browse;
            return;
        };
        if let Some(action) = dialog.review_action {
            match key.code {
                KeyCode::Esc => {
                    dialog.review_action = None;
                    dialog.message = None;
                }
                KeyCode::Enter => self.start_authorization_operation(action),
                _ => {}
            }
            return;
        }
        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => {
                self.authorization_dialog = None;
                self.mode = ScreenMode::Browse;
            }
            KeyCode::Char('a') => {
                dialog.advanced = !dialog.advanced;
                if !dialog.advanced {
                    dialog.preset = AgentAuthorizationPresetKind::ReadOnly;
                    dialog.destructive_acknowledged = false;
                    dialog.message = None;
                }
            }
            KeyCode::Left if dialog.advanced => dialog.cycle_preset(false),
            KeyCode::Right if dialog.advanced => dialog.cycle_preset(true),
            KeyCode::Down | KeyCode::Char('j') if dialog.advanced => {
                dialog.capability_selected = (dialog.capability_selected + 1)
                    .min(dialog.capabilities.len().saturating_sub(1));
            }
            KeyCode::Up | KeyCode::Char('k') if dialog.advanced => {
                dialog.capability_selected = dialog.capability_selected.saturating_sub(1);
            }
            KeyCode::Char(' ')
                if dialog.advanced && dialog.preset == AgentAuthorizationPresetKind::Custom =>
            {
                if let Some(capability) = dialog.capabilities.get(dialog.capability_selected)
                    && !dialog.custom_selected.remove(&capability.id)
                {
                    dialog.custom_selected.insert(capability.id.clone());
                }
            }
            KeyCode::Char('t') if dialog.advanced => {
                dialog.ttl_index = (dialog.ttl_index + 1) % AUTHORIZATION_TTL_OPTIONS.len();
            }
            KeyCode::Char('u') if dialog.advanced => {
                dialog.uses_index = (dialog.uses_index + 1) % AUTHORIZATION_USE_OPTIONS.len();
            }
            KeyCode::Char('d')
                if dialog.advanced && dialog.requires_destructive_acknowledgement() =>
            {
                dialog.destructive_acknowledged = !dialog.destructive_acknowledged;
            }
            KeyCode::Char('r') if existing.is_some() => {
                dialog.review_action = Some(AuthorizationAction::Renew);
            }
            KeyCode::Char('v') if existing.is_some() => {
                dialog.review_action = Some(AuthorizationAction::RevokeProfile);
            }
            KeyCode::Char('x') => {
                dialog.review_action = Some(AuthorizationAction::RevokeAll);
            }
            KeyCode::Enter if !dialog.loading => {
                let selected = dialog.selected_capabilities();
                if selected.is_empty() {
                    dialog.message = Some(match dialog.preset {
                        AgentAuthorizationPresetKind::InteractiveExecute => {
                            "Interactive/Execute is deferred for this plugin; choose Read-only or Custom"
                                .into()
                        }
                        _ => "Select at least one capability before review".into(),
                    });
                } else if dialog.requires_destructive_acknowledgement()
                    && !dialog.destructive_acknowledged
                {
                    dialog.message = Some(
                        "Press d to acknowledge this grant's destructive capability scope".into(),
                    );
                } else {
                    dialog.review_action = Some(AuthorizationAction::Authorize);
                    dialog.message = None;
                }
            }
            _ => {}
        }
    }

    fn handle_authorization_inbox_key(&mut self, key: KeyEvent) {
        if self.authorization_operation_rx.is_some() {
            self.status = "Authorization decision is still running".into();
            return;
        }
        if let Some(dialog) = &mut self.jit_approval_dialog {
            if dialog.confirm {
                match key.code {
                    KeyCode::Esc => {
                        dialog.confirm = false;
                        dialog.message = None;
                    }
                    KeyCode::Enter => self.start_jit_authorization_decision(),
                    _ => {}
                }
                return;
            }
            if dialog.editing_constraints {
                match key.code {
                    KeyCode::Esc | KeyCode::Enter => dialog.editing_constraints = false,
                    KeyCode::Backspace => {
                        dialog.constraints_json.pop();
                    }
                    KeyCode::Char(character) if !character.is_control() => {
                        dialog.constraints_json.push(character)
                    }
                    _ => {}
                }
                return;
            }
            match key.code {
                KeyCode::Esc => self.jit_approval_dialog = None,
                KeyCode::Left => {
                    dialog.decision = dialog.decision.cycle(false, dialog.grant_id.is_some())
                }
                KeyCode::Right => {
                    dialog.decision = dialog.decision.cycle(true, dialog.grant_id.is_some())
                }
                KeyCode::Char('t') => {
                    dialog.ttl_index = (dialog.ttl_index + 1) % AUTHORIZATION_TTL_OPTIONS.len()
                }
                KeyCode::Char('u') => {
                    dialog.uses_index = (dialog.uses_index + 1) % AUTHORIZATION_USE_OPTIONS.len()
                }
                KeyCode::Char('c')
                    if !matches!(dialog.decision, JitDecision::Deny)
                        && !matches!(
                            dialog.request.scope.get("kind").and_then(Value::as_str),
                            Some("exact_invocation")
                        ) =>
                {
                    dialog.editing_constraints = true;
                }
                KeyCode::Enter => {
                    if self.config.requires_master_password()
                        && self.active_master_password.is_none()
                    {
                        dialog.message =
                            Some("Credentials are locked; close and press m to unlock".into());
                    } else if !dialog.constraints_json.trim().is_empty()
                        && serde_json::from_str::<serde_json::Map<String, Value>>(
                            &dialog.constraints_json,
                        )
                        .is_err()
                    {
                        dialog.message = Some("Narrowing constraints must be a JSON object".into());
                    } else {
                        dialog.confirm = true;
                        dialog.message = None;
                    }
                }
                _ => {}
            }
            return;
        }

        match key.code {
            KeyCode::Esc | KeyCode::Char('q') => self.mode = ScreenMode::Browse,
            KeyCode::Down | KeyCode::Char('j') => {
                self.authorization_inbox_selected = (self.authorization_inbox_selected + 1)
                    .min(self.pending_authorization_requests.len().saturating_sub(1));
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.authorization_inbox_selected =
                    self.authorization_inbox_selected.saturating_sub(1);
            }
            KeyCode::Char('r') => {
                self.next_authorization_refresh = Instant::now();
                self.start_authorization_status_refresh();
                self.status = "Refreshing canonical approval inbox...".into();
            }
            KeyCode::Enter | KeyCode::Char('d') => {
                let Some(request) = self
                    .pending_authorization_requests
                    .get(self.authorization_inbox_selected)
                    .filter(|request| request.is_pending())
                    .cloned()
                else {
                    self.status = "Select a canonical pending request".into();
                    return;
                };
                let mut dialog = JitApprovalDialog::new(request, &self.grant_revisions);
                if key.code == KeyCode::Char('d') {
                    dialog.decision = JitDecision::Deny;
                }
                self.jit_approval_dialog = Some(dialog);
            }
            _ => {}
        }
    }

    fn start_jit_authorization_decision(&mut self) {
        let Some(dialog) = &self.jit_approval_dialog else {
            return;
        };
        let request_id = dialog.request.id.clone();
        let decision = dialog.decision;
        let ttl_minutes = dialog.ttl_minutes();
        let uses = dialog.uses();
        let grant_id = dialog.grant_id.clone();
        let constraints_json =
            (!dialog.constraints_json.trim().is_empty()).then(|| dialog.constraints_json.clone());
        let password = self.active_master_password.clone();
        let (tx, rx) = mpsc::channel();
        self.authorization_operation_rx = Some(rx);
        if let Some(dialog) = &mut self.jit_approval_dialog {
            dialog.message = Some("Applying canonical decision...".into());
        }
        std::thread::spawn(move || {
            let result = run_jit_authorization_decision(
                &request_id,
                decision,
                ttl_minutes,
                uses,
                grant_id.as_deref(),
                constraints_json.as_deref(),
                password.as_deref(),
            );
            let _ = tx.send(result);
        });
    }

    fn start_authorization_operation(&mut self, action: AuthorizationAction) {
        let Some(dialog) = &self.authorization_dialog else {
            return;
        };
        let profile = dialog.profile.clone();
        let capabilities = dialog.selected_capabilities();
        let ttl_minutes = dialog.ttl_minutes();
        let uses = dialog.uses();
        let preset = dialog.preset;
        let allow_destructive =
            dialog.requires_destructive_acknowledgement() && dialog.destructive_acknowledged;
        let existing = self
            .authorization_statuses
            .get(&(profile.id.clone(), profile.plugin_id.clone()))
            .cloned();
        let password = self.active_master_password.clone();
        let (tx, rx) = mpsc::channel();
        self.authorization_operation_rx = Some(rx);
        if let Some(dialog) = &mut self.authorization_dialog {
            dialog.message = Some("Working through the central authorization service...".into());
        }
        std::thread::spawn(move || {
            let result = match action {
                AuthorizationAction::Authorize => run_agent_authorize(
                    &profile,
                    password.as_deref(),
                    AgentAuthorizeRequest {
                        capabilities,
                        ttl_minutes,
                        uses,
                        preset,
                        allow_destructive,
                        replace: existing.is_some(),
                    },
                ),
                AuthorizationAction::Renew => existing
                    .as_ref()
                    .ok_or_else(|| "No grant is available to renew".to_string())
                    .and_then(|grant| run_agent_renew(&grant.grant_id, ttl_minutes, uses)),
                AuthorizationAction::RevokeProfile => run_agent_revoke_profile(&profile),
                AuthorizationAction::RevokeAll => {
                    run_agent_revoke_all().map(|count| format!("Revoked {count} agent grant(s)"))
                }
            };
            let _ = tx.send(result);
        });
    }

    fn handle_paste(&mut self, text: &str) {
        match self.mode {
            ScreenMode::Search => {
                self.search
                    .extend(text.chars().filter(|character| !character.is_control()));
                self.refilter();
            }
            ScreenMode::Edit => {
                for character in text.chars() {
                    let key = match character {
                        '\n' => KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE),
                        character => KeyEvent::new(KeyCode::Char(character), KeyModifiers::NONE),
                    };
                    self.handle_editor_key(key);
                }
            }
            ScreenMode::Credentials => {
                if let Some(dialog) = &mut self.credential_dialog {
                    dialog
                        .value_mut()
                        .extend(text.chars().filter(|character| !character.is_control()));
                }
            }
            _ => {}
        }
    }

    fn move_selection(&mut self, down: bool) {
        if self.filtered_indices.is_empty() {
            return;
        }
        self.selected = if down {
            (self.selected + 1).min(self.filtered_indices.len() - 1)
        } else {
            self.selected.saturating_sub(1)
        };
        self.list_state.select(Some(self.selected));
    }

    fn begin_edit(&mut self) {
        let Some(profile) = self.selected_profile().cloned() else {
            self.status = "No profile selected".to_string();
            return;
        };
        if self.config.requires_master_password() && self.active_master_password.is_none() {
            self.status = "Press m to unlock profile credentials before editing".to_string();
            return;
        }
        match self
            .store
            .native_connection(&profile, self.active_master_password.as_deref())
        {
            Ok(connection) => {
                self.editor = Some(ProfileEditor::edit(&profile, connection));
                self.mode = ScreenMode::Edit;
            }
            Err(error) => self.status = format!("Cannot edit profile: {error}"),
        }
    }

    fn begin_create(&mut self) {
        match create_profile_editor(&self.config, self.active_master_password.as_deref()) {
            Ok(editor) => {
                self.editor = Some(editor);
                self.mode = ScreenMode::Edit;
            }
            Err(message) => self.status = message.to_string(),
        }
    }

    fn save_editor(&mut self) {
        if self.config.requires_master_password() && self.active_master_password.is_none() {
            if let Some(editor) = &mut self.editor {
                editor.message = Some("Unlock credentials with m before saving".to_string());
            }
            return;
        }
        let Some(editor) = &mut self.editor else {
            return;
        };
        let profile_name = editor.name.trim().to_string();
        if profile_name.is_empty() {
            editor.message = Some("Name is required".to_string());
            editor.active_field = 1;
            return;
        }
        let plugin_config: Value = match editor.view {
            EditorView::Form => editor.config.clone(),
            EditorView::Json => match serde_json::from_str::<Value>(&editor.config_text()) {
                Ok(config) if config.is_object() => config,
                Ok(_) => {
                    editor.message = Some("Plugin configuration must be a JSON object".to_string());
                    return;
                }
                Err(error) => {
                    editor.message = Some(format!("Invalid JSON: {error}"));
                    return;
                }
            },
        };
        let violations = editor.schema.validate(&plugin_config);
        if let Some(violation) = violations.first() {
            editor.message = Some(format!("{}: {}", violation.path, violation.message));
            if let Some(index) = editor
                .schema
                .visible_fields(&plugin_config)
                .iter()
                .position(|field| field.path == violation.path)
            {
                editor.active_field = index + 3;
                editor.view = EditorView::Form;
                editor.config = plugin_config;
            }
            return;
        }
        let plugin_id = editor.plugin_id().to_string();
        let config = ConnectionConfig {
            name: profile_name,
            db_type: database_type_for_plugin(&plugin_id),
            plugin_id: Some(plugin_id),
            plugin_config: Some(plugin_config),
        };
        let display_name = (!editor.display_name.trim().is_empty())
            .then(|| editor.display_name.trim().to_string());
        match self.store.upsert_native_connection(
            editor.existing_profile_id.as_deref(),
            &config,
            display_name,
            self.active_master_password.as_deref(),
        ) {
            Ok(profile) => {
                self.status = format!(
                    "Saved native profile '{}'/{}",
                    profile.name, profile.plugin_id
                );
                self.editor = None;
                self.mode = ScreenMode::Browse;
                let _ = self.refresh_profiles();
                if let Some(index) = self
                    .filtered_indices
                    .iter()
                    .position(|index| self.profiles[*index].id == profile.id)
                {
                    self.selected = index;
                    self.list_state.select(Some(index));
                }
            }
            Err(error) => editor.message = Some(format!("Save failed: {error}")),
        }
    }

    fn open_credentials(&mut self) {
        let mode = if self.config.requires_master_password() {
            CredentialMode::Unlock
        } else {
            CredentialMode::Set
        };
        self.credential_dialog = Some(CredentialDialog::new(mode));
        self.mode = ScreenMode::Credentials;
    }

    fn submit_credentials(&mut self) {
        let Some(mut dialog) = self.credential_dialog.take() else {
            return;
        };
        let result = match dialog.mode {
            CredentialMode::Unlock => AppConfig::load_with_password(Some(&dialog.password))
                .map(|config| {
                    self.config = config;
                    self.active_master_password = Some(dialog.password.clone());
                    "Profile credentials unlocked for this session".to_string()
                })
                .map_err(|error| anyhow!(error)),
            CredentialMode::Set => {
                if dialog.password.is_empty() {
                    Err(anyhow!("Master password cannot be empty"))
                } else if dialog.password != dialog.confirmation {
                    Err(anyhow!("Master password confirmation does not match"))
                } else {
                    (|| -> Result<String> {
                        self.store.reencrypt_native_credentials(
                            self.active_master_password.as_deref(),
                            &dialog.password,
                        )?;
                        AppConfig::reencrypt_config_file(
                            self.active_master_password.as_deref(),
                            &dialog.password,
                        )?;
                        self.config = AppConfig::load_with_password(Some(&dialog.password))?;
                        self.active_master_password = Some(dialog.password.clone());
                        Ok(
                            "Native profile credentials protected with a master password"
                                .to_string(),
                        )
                    })()
                }
            }
        };
        match result {
            Ok(message) => {
                self.status = message;
                self.mode = ScreenMode::Browse;
            }
            Err(error) => {
                dialog.message = Some(error.to_string());
                self.credential_dialog = Some(dialog);
            }
        }
    }

    fn show_guidance(&mut self) {
        if let Some(profile) = self.selected_profile() {
            self.status = format!(
                "Profile id:{} | test: voidb-cli profile test id:{} --plugin {} | capabilities: c",
                profile.id, profile.id, profile.plugin_id
            );
        }
    }

    fn start_test(&mut self) {
        if self.test_rx.is_some() {
            self.status = "A profile test is already running".to_string();
            return;
        }
        let Some(profile) = self.selected_profile().cloned() else {
            self.status = "No profile selected".to_string();
            return;
        };
        if self.config.requires_master_password() && self.active_master_password.is_none() {
            self.status = "Press m to unlock profile credentials before testing".to_string();
            return;
        }
        let (tx, rx) = mpsc::channel();
        self.test_rx = Some(rx);
        self.status = format!("Testing {}/{}...", profile.plugin_id, profile.name);
        let password = self.active_master_password.clone();
        std::thread::spawn(move || {
            let result = run_profile_test(&profile, password.as_deref());
            let _ = tx.send(result);
        });
    }

    fn start_capability_load(&mut self) {
        if self.capability_rx.is_some() {
            return;
        }
        let Some(profile) = self.selected_profile().cloned() else {
            self.status = "No profile selected".to_string();
            return;
        };
        let (tx, rx) = mpsc::channel();
        self.capability_rx = Some(rx);
        self.capabilities.clear();
        self.capability_selected = 0;
        self.mode = ScreenMode::Capabilities;
        self.status = format!("Loading {} capabilities...", profile.plugin_id);
        std::thread::spawn(move || {
            let result = run_capability_list(&profile.plugin_id);
            let _ = tx.send(result);
        });
    }

    fn start_authorization_status_refresh(&mut self) {
        if self.authorization_status_rx.is_some()
            || Instant::now() < self.next_authorization_refresh
        {
            return;
        }
        let (tx, rx) = mpsc::channel();
        self.authorization_status_rx = Some(rx);
        self.next_authorization_refresh = Instant::now() + AUTHORIZATION_REFRESH_INTERVAL;
        std::thread::spawn(move || {
            let result = run_authorization_snapshot();
            let _ = tx.send(result);
        });
    }

    fn poll_background(&mut self) -> bool {
        let mut changed = false;
        self.start_authorization_status_refresh();
        if let Some(rx) = &self.test_rx {
            match rx.try_recv() {
                Ok(Ok(message)) => {
                    self.status = message;
                    self.test_rx = None;
                    changed = true;
                }
                Ok(Err(message)) => {
                    self.status = format!("Test failed: {message}");
                    self.test_rx = None;
                    changed = true;
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.status = "Profile test worker stopped".to_string();
                    self.test_rx = None;
                    changed = true;
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        if let Some(rx) = &self.capability_rx {
            match rx.try_recv() {
                Ok(Ok(payload)) => {
                    self.capabilities = parse_capabilities(&payload);
                    self.status = format!("Loaded {} capabilities", self.capabilities.len());
                    self.capability_rx = None;
                    changed = true;
                }
                Ok(Err(message)) => {
                    self.status = format!("Capability discovery failed: {message}");
                    self.capability_rx = None;
                    changed = true;
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.status = "Capability discovery worker stopped".to_string();
                    self.capability_rx = None;
                    changed = true;
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        if let Some(rx) = &self.authorization_catalog_rx {
            match rx.try_recv() {
                Ok(Ok(payload)) => {
                    let capabilities = parse_capabilities(&payload);
                    if let Some(dialog) = &mut self.authorization_dialog {
                        dialog.capabilities = capabilities;
                        dialog.loading = false;
                        dialog.message = if dialog.capabilities.is_empty() {
                            Some("This profile has no agent-ready capabilities".into())
                        } else {
                            None
                        };
                    }
                    self.authorization_catalog_rx = None;
                    changed = true;
                }
                Ok(Err(message)) => {
                    if let Some(dialog) = &mut self.authorization_dialog {
                        dialog.loading = false;
                        dialog.message = Some(format!("Capability catalog unavailable: {message}"));
                    }
                    self.authorization_catalog_rx = None;
                    changed = true;
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    if let Some(dialog) = &mut self.authorization_dialog {
                        dialog.loading = false;
                        dialog.message = Some("Capability catalog worker stopped".into());
                    }
                    self.authorization_catalog_rx = None;
                    changed = true;
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        if let Some(rx) = &self.authorization_operation_rx {
            match rx.try_recv() {
                Ok(Ok(message)) => {
                    self.status = message;
                    self.authorization_operation_rx = None;
                    self.authorization_dialog = None;
                    self.jit_approval_dialog = None;
                    if self.mode != ScreenMode::AuthorizationInbox {
                        self.mode = ScreenMode::Browse;
                    }
                    self.next_authorization_refresh = Instant::now();
                    self.start_authorization_status_refresh();
                    changed = true;
                }
                Ok(Err(message)) => {
                    if let Some(dialog) = &mut self.authorization_dialog {
                        dialog.review_action = None;
                        dialog.message = Some(format!("Authorization operation failed: {message}"));
                    }
                    if let Some(dialog) = &mut self.jit_approval_dialog {
                        dialog.confirm = false;
                        dialog.message = Some(format!("Authorization decision failed: {message}"));
                    }
                    self.authorization_operation_rx = None;
                    changed = true;
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    if let Some(dialog) = &mut self.authorization_dialog {
                        dialog.review_action = None;
                        dialog.message = Some("Authorization operation worker stopped".into());
                    }
                    if let Some(dialog) = &mut self.jit_approval_dialog {
                        dialog.confirm = false;
                        dialog.message = Some("Authorization decision worker stopped".into());
                    }
                    self.authorization_operation_rx = None;
                    changed = true;
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        if let Some(rx) = &self.authorization_status_rx {
            match rx.try_recv() {
                Ok(Ok(payload)) => {
                    self.authorization_statuses = parse_agent_statuses(&payload);
                    self.authorization_supported_plugins = parse_agent_supported_plugins(&payload);
                    self.authorization_capability_catalog = parse_capabilities(&payload)
                        .into_iter()
                        .map(|capability| (capability.id.clone(), capability))
                        .collect();
                    self.pending_authorization_requests = parse_pending_authorizations(&payload);
                    self.grant_revisions = parse_grant_revisions(&payload);
                    self.authorization_observed_at = parse_authorization_observed_at(&payload);
                    self.authorization_snapshot_error = None;
                    self.authorization_inbox_selected = self
                        .authorization_inbox_selected
                        .min(self.pending_authorization_requests.len().saturating_sub(1));
                    self.authorization_status_rx = None;
                    changed = true;
                }
                Ok(Err(message)) => {
                    self.authorization_snapshot_error = Some(message);
                    self.authorization_status_rx = None;
                    changed = true;
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.authorization_snapshot_error =
                        Some("authorization snapshot worker stopped".into());
                    self.authorization_status_rx = None;
                    changed = true;
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
        }
        changed
    }

    fn render(&mut self, frame: &mut Frame) {
        let area = frame.area();
        if area.width < MIN_WIDTH || area.height < MIN_HEIGHT {
            frame.render_widget(
                Paragraph::new(format!(
                    "VoidB Connection Manager\n\nTerminal too small\nMinimum: {MIN_WIDTH}x{MIN_HEIGHT}\nCurrent: {}x{}",
                    area.width, area.height
                ))
                .alignment(Alignment::Center)
                .style(Style::default().fg(Color::Yellow)),
                area,
            );
            return;
        }

        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Min(10),
                Constraint::Length(3),
            ])
            .split(area);
        self.render_header(frame, chunks[0]);
        self.render_main(frame, chunks[1]);
        self.render_footer(frame, chunks[2]);

        match self.mode {
            ScreenMode::Edit => self.render_editor(frame, area),
            ScreenMode::ConfirmDelete => self.render_delete_confirmation(frame, area),
            ScreenMode::Help => self.render_help(frame, area),
            ScreenMode::Credentials => self.render_credentials(frame, area),
            ScreenMode::Capabilities => self.render_capabilities(frame, area),
            ScreenMode::Authorization => self.render_authorization(frame, area),
            ScreenMode::AuthorizationInbox => self.render_authorization_inbox(frame, area),
            _ => {}
        }
    }

    fn render_header(&self, frame: &mut Frame, area: Rect) {
        let protection = if self.config.requires_master_password() {
            if self.active_master_password.is_some() {
                Span::styled("UNLOCKED", Style::default().fg(Color::Green))
            } else {
                Span::styled("LOCKED", Style::default().fg(Color::Yellow))
            }
        } else {
            Span::styled("DEFAULT KEY", Style::default().fg(Color::Yellow))
        };
        let title = Line::from(vec![
            Span::styled(
                " VoidB · Native Connection Manager ",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(
                "  {} profile{}  ·  ",
                self.profiles.len(),
                plural(self.profiles.len())
            )),
            protection,
        ]);
        frame.render_widget(
            Paragraph::new(title).block(Block::default().borders(Borders::ALL)),
            area,
        );
    }

    fn render_main(&mut self, frame: &mut Frame, area: Rect) {
        let columns = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(42), Constraint::Percentage(58)])
            .split(area);
        let items = self
            .filtered_indices
            .iter()
            .map(|index| {
                let profile = &self.profiles[*index];
                let authorization = self
                    .authorization_statuses
                    .get(&(profile.id.clone(), profile.plugin_id.clone()))
                    .map(AuthorizationStatusView::badge)
                    .unwrap_or_else(|| {
                        if self
                            .authorization_supported_plugins
                            .contains(&profile.plugin_id)
                        {
                            "OFF"
                        } else {
                            "UNSUPPORTED"
                        }
                    });
                ListItem::new(Line::from(vec![
                    Span::styled(
                        format!("{} ", protocol_icon(&profile.plugin_id)),
                        Style::default().fg(Color::Cyan),
                    ),
                    Span::styled(&profile.name, Style::default().add_modifier(Modifier::BOLD)),
                    Span::styled(
                        format!("  {}", profile.plugin_id),
                        Style::default().fg(Color::DarkGray),
                    ),
                    Span::styled(
                        format!("  [{authorization}]"),
                        Style::default().fg(if authorization == "OFF" {
                            Color::DarkGray
                        } else {
                            Color::Yellow
                        }),
                    ),
                ]))
            })
            .collect::<Vec<_>>();
        let title = if self.mode == ScreenMode::Search {
            format!(" Profiles · filter: {} ", self.search)
        } else {
            " Profiles ".to_string()
        };
        let list = List::new(items)
            .block(Block::default().title(title).borders(Borders::ALL))
            .highlight_symbol("▶ ")
            .highlight_style(Style::default().bg(Color::Rgb(30, 50, 65)).fg(Color::White));
        frame.render_stateful_widget(list, columns[0], &mut self.list_state);

        let details = if let Some(profile) = self.selected_profile() {
            let display = profile.display_name.as_deref().unwrap_or(&profile.name);
            let authorization = self
                .authorization_statuses
                .get(&(profile.id.clone(), profile.plugin_id.clone()));
            let authorization_detail = authorization
                .map(AuthorizationStatusView::detail)
                .unwrap_or_else(|| {
                    if self
                        .authorization_supported_plugins
                        .contains(&profile.plugin_id)
                    {
                        "OFF · no active grant".to_string()
                    } else {
                        "UNSUPPORTED · no agent-ready capabilities".to_string()
                    }
                });
            Text::from(vec![
                Line::from(Span::styled(
                    display,
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                )),
                Line::raw(""),
                detail_line("Name", &profile.name),
                detail_line("Plugin", &profile.plugin_id),
                detail_line("Profile ID", &profile.id),
                detail_line("Storage", "native profile + encrypted local config"),
                detail_line(
                    "Credential refs",
                    &profile.credential_refs.len().to_string(),
                ),
                detail_line("Agent access", &authorization_detail),
                Line::raw(""),
                Line::styled(
                    "This profile resolves directly from profiles.json and credentials.json.",
                    Style::default().fg(Color::Green),
                ),
                Line::raw(""),
                Line::styled("Next steps", Style::default().add_modifier(Modifier::BOLD)),
                Line::raw(format!(
                    "Test: voidb-cli profile test id:{} --plugin {}",
                    profile.id, profile.plugin_id
                )),
                Line::raw(format!(
                    "TUI:  voidb-cli {} tui --profile id:{}",
                    profile.plugin_id, profile.id
                )),
                Line::raw("Authorize/manage: press a"),
            ])
        } else if self.profiles.is_empty() {
            Text::from(vec![
                Line::styled(
                    "Create your first native profile",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
                Line::raw(""),
                Line::raw("Press n, choose a plugin, and complete its interactive form."),
                Line::raw("Authentication choices reveal only the fields they require."),
                Line::raw("Connection details are encrypted in credentials.json."),
                Line::raw("The old config.toml connection list is not used here."),
            ])
        } else {
            Text::from("No profiles match the current filter")
        };
        frame.render_widget(
            Paragraph::new(details).wrap(Wrap { trim: false }).block(
                Block::default()
                    .title(" Profile details ")
                    .borders(Borders::ALL),
            ),
            columns[1],
        );
    }

    fn render_footer(&self, frame: &mut Frame, area: Rect) {
        let help = match self.mode {
            ScreenMode::Search => "Type to filter · Enter/Esc finish · ↑↓ navigate",
            _ => {
                "n/e/d profile · t test · c capabilities · a manage agent access · x review revoke-all · m credentials · ? help"
            }
        };
        frame.render_widget(
            Paragraph::new(vec![
                Line::styled(&self.status, Style::default().fg(Color::Yellow)),
                Line::styled(help, Style::default().fg(Color::DarkGray)),
            ])
            .block(Block::default().borders(Borders::TOP)),
            area,
        );
    }

    fn render_editor(&self, frame: &mut Frame, area: Rect) {
        let Some(editor) = &self.editor else {
            return;
        };
        let popup = centered_rect(86, 86, area);
        frame.render_widget(Clear, popup);
        frame.render_widget(
            Block::default()
                .title(if editor.existing_profile_id.is_some() {
                    " Edit native profile "
                } else {
                    " New native profile "
                })
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
            popup,
        );
        let inner = popup.inner(ratatui::layout::Margin {
            horizontal: 2,
            vertical: 1,
        });
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Length(3),
                Constraint::Length(3),
                Constraint::Min(8),
                Constraint::Length(3),
            ])
            .split(inner);
        render_input(
            frame,
            rows[0],
            if editor.existing_profile_id.is_some() {
                "Connection type (fixed)"
            } else {
                "Connection type (←/→)"
            },
            &format!("{} · {}", editor.plugin_id(), editor.plugin_label()),
            editor.active_field == 0,
            false,
        );
        render_input(
            frame,
            rows[1],
            "Name (required)",
            &editor.name,
            editor.active_field == 1,
            false,
        );
        render_input(
            frame,
            rows[2],
            "Display name (optional)",
            &editor.display_name,
            editor.active_field == 2,
            false,
        );
        let default_message = match editor.view {
            EditorView::Form => {
                let visible = editor.schema.visible_fields(&editor.config);
                let active_index = editor.active_field.saturating_sub(3);
                let visible_height = rows[3].height.saturating_sub(2) as usize;
                let scroll = active_index.saturating_sub(visible_height.saturating_sub(1));
                let items = visible
                    .iter()
                    .enumerate()
                    .skip(scroll)
                    .take(visible_height)
                    .map(|(index, field)| {
                        let marker = if field.required { "*" } else { " " };
                        let label = format!("{marker} {:<24}", field.label);
                        ListItem::new(Line::from(vec![
                            Span::styled(label, Style::default().fg(Color::Cyan)),
                            Span::raw(editor.form_field_display(field)),
                        ]))
                        .style(if editor.active_field == index + 3 {
                            Style::default().bg(Color::Rgb(45, 55, 75)).fg(Color::White)
                        } else {
                            Style::default()
                        })
                    })
                    .collect::<Vec<_>>();
                frame.render_widget(
                    List::new(items).block(
                        Block::default()
                            .title(" Interactive configuration · F2 advanced JSON ")
                            .borders(Borders::ALL)
                            .border_style(if editor.active_field >= 3 {
                                Style::default().fg(Color::Yellow)
                            } else {
                                Style::default().fg(Color::DarkGray)
                            }),
                    ),
                    rows[3],
                );
                editor
                    .active_form_field()
                    .map(|field| {
                        format!(
                            "{} · Tab/↑↓ move · ←/→ choices · Ctrl+S save · F2 JSON",
                            editor.form_field_help(field)
                        )
                    })
                    .unwrap_or_else(|| match editor.active_field {
                        0 if editor.existing_profile_id.is_some() => {
                            "Connection type is fixed for an existing profile · Tab continues"
                                .to_string()
                        }
                        0 => "Choose the connection type first with ←/→ · Tab continues"
                            .to_string(),
                        1 => "Stable name used by CLI commands · unique within this connection type, ignoring case"
                            .to_string(),
                        2 => "Optional human-facing label · may be repeated".to_string(),
                        _ => {
                            "Tab fields · Ctrl+S save · F2 advanced JSON · Esc cancel".to_string()
                        }
                    })
            }
            EditorView::Json => {
                let visible_height = rows[3].height.saturating_sub(2) as usize;
                let scroll = editor
                    .cursor_line
                    .saturating_sub(visible_height.saturating_sub(1));
                let config = editor
                    .config_lines
                    .iter()
                    .skip(scroll)
                    .take(visible_height)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("\n");
                frame.render_widget(
                    Paragraph::new(config)
                        .block(
                            Block::default()
                                .title(" Advanced plugin configuration JSON · F2 form ")
                                .borders(Borders::ALL)
                                .border_style(if editor.active_field == 3 {
                                    Style::default().fg(Color::Yellow)
                                } else {
                                    Style::default().fg(Color::DarkGray)
                                }),
                        )
                        .wrap(Wrap { trim: false }),
                    rows[3],
                );
                if editor.active_field == 3 {
                    let x = rows[3]
                        .x
                        .saturating_add(1)
                        .saturating_add(editor.cursor_col as u16)
                        .min(rows[3].right().saturating_sub(2));
                    let y = rows[3]
                        .y
                        .saturating_add(1)
                        .saturating_add(editor.cursor_line.saturating_sub(scroll) as u16)
                        .min(rows[3].bottom().saturating_sub(2));
                    frame.set_cursor_position((x, y));
                }
                "Raw JSON mode · F2 validate and return to form · Ctrl+S save · Esc cancel"
                    .to_string()
            }
        };
        let message = editor.message.as_deref().unwrap_or(&default_message);
        frame.render_widget(
            Paragraph::new(message)
                .wrap(Wrap { trim: true })
                .style(Style::default().fg(if editor.message.is_some() {
                    Color::Red
                } else {
                    Color::DarkGray
                })),
            rows[4],
        );
    }

    fn render_delete_confirmation(&self, frame: &mut Frame, area: Rect) {
        let popup = centered_rect(58, 24, area);
        frame.render_widget(Clear, popup);
        let name = self
            .selected_profile()
            .map(|profile| profile.name.as_str())
            .unwrap_or("selected profile");
        frame.render_widget(
            Paragraph::new(format!(
                "Delete native profile '{name}' and its encrypted configuration?\n\nEnter/y confirm · n/Esc cancel"
            ))
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: true })
            .block(
                Block::default()
                    .title(" Confirm delete ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Red)),
            ),
            popup,
        );
    }

    fn render_help(&self, frame: &mut Frame, area: Rect) {
        let popup = centered_rect(76, 84, area);
        frame.render_widget(Clear, popup);
        let text = Text::from(vec![
            Line::raw("j/k or ↑/↓     Move selection"),
            Line::raw("n               Create native profile"),
            Line::raw("e               Edit selected profile"),
            Line::raw("Tab / Shift+Tab Navigate profile form fields"),
            Line::raw("←/→             Change enum, boolean, or authentication choice"),
            Line::raw("Ctrl+U          Clear the active text or numeric field"),
            Line::raw("F2              Toggle interactive form / advanced JSON"),
            Line::raw("Ctrl+S          Validate and save the profile"),
            Line::raw("d               Delete selected profile"),
            Line::raw("t               Test through voidb-cli profile test"),
            Line::raw("c               Browse plugin capabilities"),
            Line::raw("a               Quick read-only access for the selected profile"),
            Line::raw("p               Open canonical JIT approval inbox"),
            Line::raw("x               Review explicit revoke-all action"),
            Line::raw("a in access     Toggle simple and advanced authorization controls"),
            Line::raw("Advanced access Presets, TTL, uses, capabilities, renew/revoke"),
            Line::raw("/               Filter profiles"),
            Line::raw("m               Unlock or set master password"),
            Line::raw("r               Reload profile store"),
            Line::raw("Enter           Show copyable CLI guidance"),
            Line::raw("Ctrl+Q          Quit"),
            Line::raw(""),
            Line::styled(
                "Grant status is authorization; active sessions are counted separately.",
                Style::default().fg(Color::Green),
            ),
        ]);
        frame.render_widget(
            Paragraph::new(text).block(Block::default().title(" Help ").borders(Borders::ALL)),
            popup,
        );
    }

    fn render_credentials(&self, frame: &mut Frame, area: Rect) {
        let Some(dialog) = &self.credential_dialog else {
            return;
        };
        let popup = centered_rect(
            62,
            if dialog.mode == CredentialMode::Set {
                42
            } else {
                30
            },
            area,
        );
        frame.render_widget(Clear, popup);
        frame.render_widget(
            Block::default()
                .title(if dialog.mode == CredentialMode::Set {
                    " Protect native profile credentials "
                } else {
                    " Unlock native profile credentials "
                })
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
            popup,
        );
        let inner = popup.inner(ratatui::layout::Margin {
            horizontal: 2,
            vertical: 1,
        });
        let mut constraints = vec![Constraint::Length(3)];
        if dialog.mode == CredentialMode::Set {
            constraints.push(Constraint::Length(3));
        }
        constraints.push(Constraint::Min(2));
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints(constraints)
            .split(inner);
        render_input(
            frame,
            rows[0],
            "Master password",
            &dialog.password,
            dialog.active_field == 0,
            true,
        );
        if dialog.mode == CredentialMode::Set {
            render_input(
                frame,
                rows[1],
                "Confirm password",
                &dialog.confirmation,
                dialog.active_field == 1,
                true,
            );
        }
        let message_area = rows[rows.len() - 1];
        frame.render_widget(
            Paragraph::new(
                dialog
                    .message
                    .as_deref()
                    .unwrap_or("Enter submit · Tab switch field · Esc cancel"),
            )
            .style(Style::default().fg(if dialog.message.is_some() {
                Color::Red
            } else {
                Color::DarkGray
            })),
            message_area,
        );
    }

    fn render_capabilities(&mut self, frame: &mut Frame, area: Rect) {
        let popup = centered_rect(82, 76, area);
        frame.render_widget(Clear, popup);
        let items = if self.capability_rx.is_some() {
            vec![ListItem::new("Loading capability catalog...")]
        } else if self.capabilities.is_empty() {
            vec![ListItem::new("No capabilities reported for this plugin")]
        } else {
            self.capabilities
                .iter()
                .map(|capability| {
                    ListItem::new(vec![
                        Line::styled(
                            format!("{}  [{}]", capability.id, capability.risk),
                            Style::default().fg(Color::Cyan),
                        ),
                        Line::styled(&capability.description, Style::default().fg(Color::Gray)),
                    ])
                })
                .collect()
        };
        let mut state = ListState::default();
        if !self.capabilities.is_empty() {
            state.select(Some(self.capability_selected));
        }
        frame.render_stateful_widget(
            List::new(items)
                .highlight_symbol("▶ ")
                .highlight_style(Style::default().bg(Color::Rgb(30, 50, 65)))
                .block(
                    Block::default()
                        .title(" Capabilities · Enter command guidance · Esc close ")
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(Color::Cyan)),
                ),
            popup,
            &mut state,
        );
    }

    fn render_authorization(&self, frame: &mut Frame, area: Rect) {
        let Some(dialog) = &self.authorization_dialog else {
            return;
        };
        let popup = centered_rect(88, 88, area);
        frame.render_widget(Clear, popup);
        let title = format!(
            " Agent authorization · {}/{} ",
            dialog.profile.plugin_id, dialog.profile.name
        );
        frame.render_widget(
            Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Cyan)),
            popup,
        );
        let inner = popup.inner(ratatui::layout::Margin {
            horizontal: 2,
            vertical: 1,
        });
        let existing = self
            .authorization_statuses
            .get(&(dialog.profile.id.clone(), dialog.profile.plugin_id.clone()));
        if let Some(action) = dialog.review_action {
            let selected = dialog.selected_capabilities();
            let (heading, detail) = match action {
                AuthorizationAction::Authorize => (
                    if existing.is_some() {
                        "Review replacement"
                    } else {
                        "Review authorization"
                    },
                    format!(
                        "Preset: {}\nCapabilities: {}\nTTL: {} minutes\nUse limit: {}\nDestructive grant consent: {}\n\nThis does not acknowledge later destructive calls. Each call still requires --yes.",
                        dialog.preset_label(),
                        selected.join(", "),
                        dialog.ttl_minutes(),
                        format_use_limit(dialog.uses()),
                        if dialog.destructive_acknowledged {
                            "YES"
                        } else {
                            "no"
                        },
                    ),
                ),
                AuthorizationAction::Renew => (
                    "Review renewal",
                    format!(
                        "Keep immutable profile, plugin, capabilities, and destructive scope.\nNew TTL: {} minutes\nUse limit: {}",
                        dialog.ttl_minutes(),
                        format_use_limit(dialog.uses())
                    ),
                ),
                AuthorizationAction::RevokeProfile => (
                    "Review profile revoke",
                    "Close sessions and revoke only this immutable Profile ID and plugin grant."
                        .into(),
                ),
                AuthorizationAction::RevokeAll => (
                    "Review revoke all",
                    "Secondary global action: close sessions and revoke every local agent grant."
                        .into(),
                ),
            };
            frame.render_widget(
                Paragraph::new(Text::from(vec![
                    Line::styled(
                        heading,
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Line::raw(""),
                    Line::raw(detail),
                    Line::raw(""),
                    Line::styled(
                        "Enter confirm · Esc back",
                        Style::default().fg(Color::DarkGray),
                    ),
                    Line::styled(
                        dialog.message.as_deref().unwrap_or_default(),
                        Style::default().fg(Color::Yellow),
                    ),
                ]))
                .wrap(Wrap { trim: false }),
                inner,
            );
            return;
        }

        if !dialog.advanced {
            let rows = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3),
                    Constraint::Min(8),
                    Constraint::Length(4),
                ])
                .split(inner);
            let existing_text = existing
                .map(AuthorizationStatusView::detail)
                .unwrap_or_else(|| "OFF · no active grant".to_string());
            frame.render_widget(
                Paragraph::new(existing_text).block(
                    Block::default()
                        .title(" Current access ")
                        .borders(Borders::ALL),
                ),
                rows[0],
            );
            let read_only_count = dialog
                .capabilities
                .iter()
                .filter(|capability| capability.risk == "read_only")
                .count();
            let quick_access = if dialog.loading {
                "Loading the safe read-only capability set...".to_string()
            } else if read_only_count == 0 {
                "This plugin has no agent-ready read-only capabilities.".to_string()
            } else {
                format!(
                    "Allow read-only agent access\n\nProfile: {}/{}\nDuration: {} minutes\nBudget: {}\nSafe capabilities: {}\n\nCredentials stay inside the local broker. Write or destructive operations still require a specific approval.",
                    dialog.profile.plugin_id,
                    dialog.profile.name,
                    dialog.ttl_minutes(),
                    format_use_limit(dialog.uses()),
                    read_only_count,
                )
            };
            frame.render_widget(
                Paragraph::new(quick_access)
                    .wrap(Wrap { trim: true })
                    .block(
                        Block::default()
                            .title(" Quick read-only access · recommended ")
                            .borders(Borders::ALL)
                            .border_style(Style::default().fg(Color::Green)),
                    ),
                rows[1],
            );
            let controls = if existing.is_some() {
                "Enter review read-only access · r extend current · v revoke · a advanced · Esc close"
            } else {
                "Enter review and allow · a advanced · Esc close"
            };
            frame.render_widget(
                Paragraph::new(vec![
                    Line::styled(controls, Style::default().fg(Color::DarkGray)),
                    Line::styled(
                        dialog.message.as_deref().unwrap_or_default(),
                        Style::default().fg(Color::Yellow),
                    ),
                ])
                .wrap(Wrap { trim: true }),
                rows[2],
            );
            return;
        }

        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3),
                Constraint::Length(3),
                Constraint::Length(3),
                Constraint::Min(7),
                Constraint::Length(4),
            ])
            .split(inner);
        let existing_text = existing
            .map(AuthorizationStatusView::detail)
            .unwrap_or_else(|| "OFF · no active grant".to_string());
        frame.render_widget(
            Paragraph::new(existing_text).block(
                Block::default()
                    .title(" Current grant state ")
                    .borders(Borders::ALL),
            ),
            rows[0],
        );
        frame.render_widget(
            Paragraph::new(format!(
                "{}   ←/→ preset   t TTL={}m   u use-limit={}",
                dialog.preset_label(),
                dialog.ttl_minutes(),
                format_use_limit(dialog.uses())
            ))
            .block(Block::default().title(" Scope ").borders(Borders::ALL)),
            rows[1],
        );
        let acknowledgement = if dialog.requires_destructive_acknowledgement() {
            if dialog.destructive_acknowledged {
                "Destructive grant scope acknowledged: YES (d toggles)"
            } else {
                "Destructive grant scope requires acknowledgement (press d)"
            }
        } else {
            "No destructive grant acknowledgement required"
        };
        frame.render_widget(
            Paragraph::new(acknowledgement).style(Style::default().fg(
                if dialog.requires_destructive_acknowledgement() && !dialog.destructive_acknowledged
                {
                    Color::Yellow
                } else {
                    Color::Green
                },
            )),
            rows[2],
        );

        let selected = dialog.selected_capabilities();
        let items = if dialog.loading {
            vec![ListItem::new("Loading capability catalog...")]
        } else if dialog.capabilities.is_empty() {
            vec![ListItem::new("Unsupported: no agent-ready capabilities")]
        } else {
            dialog
                .capabilities
                .iter()
                .map(|capability| {
                    let checked = if selected.contains(&capability.id) {
                        "[x]"
                    } else {
                        "[ ]"
                    };
                    ListItem::new(format!("{checked} {} [{}]", capability.id, capability.risk))
                })
                .collect()
        };
        let mut state = ListState::default();
        if !dialog.capabilities.is_empty() {
            state.select(Some(dialog.capability_selected));
        }
        frame.render_stateful_widget(
            List::new(items)
                .highlight_symbol("▶ ")
                .highlight_style(Style::default().bg(Color::Rgb(30, 50, 65)))
                .block(
                    Block::default()
                        .title(if dialog.preset == AgentAuthorizationPresetKind::Custom {
                            " Capabilities · Space toggles Custom selection "
                        } else {
                            " Capabilities · preset-derived exact scope "
                        })
                        .borders(Borders::ALL),
                ),
            rows[3],
            &mut state,
        );
        let controls = if existing.is_some() {
            "Enter review authorize/replace · r renew · v revoke profile · x revoke all · a simple · Esc close"
        } else {
            "Enter review authorize · x revoke all · a simple · Esc close"
        };
        frame.render_widget(
            Paragraph::new(vec![
                Line::styled(controls, Style::default().fg(Color::DarkGray)),
                Line::styled(
                    dialog.message.as_deref().unwrap_or_default(),
                    Style::default().fg(Color::Yellow),
                ),
            ])
            .wrap(Wrap { trim: true }),
            rows[4],
        );
    }

    fn render_authorization_inbox(&self, frame: &mut Frame, area: Rect) {
        let popup = centered_rect(94, 92, area);
        frame.render_widget(Clear, popup);
        let pending_count = self
            .pending_authorization_requests
            .iter()
            .filter(|request| request.is_pending())
            .count();
        let title =
            format!(" JIT approval inbox · {pending_count} pending · canonical broker state ");
        frame.render_widget(
            Block::default()
                .title(title)
                .borders(Borders::ALL)
                .border_style(Style::default().fg(
                    if self.authorization_snapshot_error.is_some() {
                        Color::Yellow
                    } else {
                        Color::Cyan
                    },
                )),
            popup,
        );
        let inner = popup.inner(ratatui::layout::Margin {
            horizontal: 2,
            vertical: 1,
        });
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(2),
                Constraint::Min(8),
                Constraint::Length(7),
                Constraint::Length(2),
            ])
            .split(inner);
        let freshness = match (
            &self.authorization_observed_at,
            &self.authorization_snapshot_error,
        ) {
            (Some(observed), None) => format!("Canonical refresh: {observed}"),
            (Some(observed), Some(error)) => {
                format!("STALE snapshot from {observed} · refresh failed: {error}")
            }
            (None, Some(error)) => format!("Canonical broker unavailable: {error}"),
            (None, None) => "Loading canonical approval inbox...".into(),
        };
        frame.render_widget(
            Paragraph::new(freshness).style(Style::default().fg(
                if self.authorization_snapshot_error.is_some() {
                    Color::Yellow
                } else {
                    Color::Green
                },
            )),
            rows[0],
        );
        let items = if self.pending_authorization_requests.is_empty() {
            vec![ListItem::new("No authorization requests")]
        } else {
            self.pending_authorization_requests
                .iter()
                .map(|request| {
                    let principal = request
                        .principal_fingerprint
                        .chars()
                        .take(24)
                        .collect::<String>();
                    let decision = if request.timed_out {
                        "\n    Auto-denied: review window expired".to_string()
                    } else {
                        request
                            .decision_reason
                            .as_ref()
                            .map_or_else(String::new, |reason| {
                                format!("\n    Decision: {}", sanitize_display_text(reason))
                            })
                    };
                    ListItem::new(format!(
                        "[{}] {} · {}/{} · {} · agent {}\n    {}{}",
                        request.status.to_uppercase(),
                        request.capability_id(),
                        request.plugin_id,
                        request.profile_id,
                        request.risk,
                        principal,
                        sanitize_display_text(&request.purpose),
                        decision,
                    ))
                })
                .collect()
        };
        let mut state = ListState::default();
        if !self.pending_authorization_requests.is_empty() {
            state.select(Some(self.authorization_inbox_selected));
        }
        frame.render_stateful_widget(
            List::new(items)
                .highlight_symbol("▶ ")
                .highlight_style(Style::default().bg(Color::Rgb(30, 50, 65)))
                .block(
                    Block::default()
                        .title(" Requests grouped by principal and immutable profile ")
                        .borders(Borders::ALL),
                ),
            rows[1],
            &mut state,
        );
        let detail = self
            .pending_authorization_requests
            .get(self.authorization_inbox_selected)
            .map(|request| {
                let revisions = self
                    .grant_revisions
                    .iter()
                    .filter(|revision| {
                        revision.principal_fingerprint == request.principal_fingerprint
                            && revision.profile_id == request.profile_id
                            && revision.plugin_id == request.plugin_id
                    })
                    .map(|revision| {
                        format!(
                            "{} r{} · {} · expires {}",
                            revision.grant_id,
                            revision.revision,
                            format_use_limit(revision.remaining_uses),
                            revision.expires_at
                        )
                    })
                    .collect::<Vec<_>>();
                format!(
                    "Created: {} · Expires: {}\nRequested scope: {}\nImmutable revisions: {}",
                    request.created_at,
                    request.expires_at,
                    serde_json::to_string(&request.scope).unwrap_or_else(|_| "invalid".into()),
                    if revisions.is_empty() {
                        "none".into()
                    } else {
                        revisions.join(" | ")
                    }
                )
            })
            .unwrap_or_else(|| "No selected request".into());
        frame.render_widget(
            Paragraph::new(detail).wrap(Wrap { trim: true }).block(
                Block::default()
                    .title(" Canonical details and revision history ")
                    .borders(Borders::ALL),
            ),
            rows[2],
        );
        frame.render_widget(
            Paragraph::new("j/k select · Enter review · d deny review · r refresh · Esc close")
                .style(Style::default().fg(Color::DarkGray)),
            rows[3],
        );
        if let Some(dialog) = &self.jit_approval_dialog {
            self.render_jit_approval_dialog(frame, area, dialog);
        }
    }

    fn render_jit_approval_dialog(
        &self,
        frame: &mut Frame,
        area: Rect,
        dialog: &JitApprovalDialog,
    ) {
        let popup = centered_rect(82, 78, area);
        frame.render_widget(Clear, popup);
        let capability = self
            .authorization_capability_catalog
            .get(dialog.request.capability_id());
        let schema = capability
            .map(|item| {
                if item.approval_fields.is_empty() {
                    if item.capability_wide_allowed {
                        "Capability-wide approval is declared; no structured fields.".into()
                    } else {
                        "No compatible structured approval schema (fails closed).".into()
                    }
                } else {
                    format!(
                        "Declared review fields: {}",
                        item.approval_fields.join(" · ")
                    )
                }
            })
            .unwrap_or_else(|| {
                "Capability declaration unavailable (approval will fail closed).".into()
            });
        let decision_detail = match dialog.decision {
            JitDecision::Once => "One invocation/use, short bounded lifetime".into(),
            JitDecision::Bounded => format!(
                "{} minutes · {}",
                dialog.ttl_minutes(),
                format_use_limit(dialog.uses())
            ),
            JitDecision::AddToGrant => format!(
                "Amend {} · +{} minutes · {}",
                dialog.grant_id.as_deref().unwrap_or("no compatible grant"),
                dialog.ttl_minutes(),
                dialog.uses().map_or_else(
                    || "no use-count change".to_string(),
                    |uses| format!("+{uses} uses")
                )
            ),
            JitDecision::Deny => "Close request and start denial cooldown".into(),
        };
        let constraints = if dialog.editing_constraints {
            format!("{}█", dialog.constraints_json)
        } else if dialog.constraints_json.is_empty() {
            "<requested scope unchanged>".into()
        } else {
            dialog.constraints_json.clone()
        };
        let confirm = if dialog.confirm {
            "\nCONFIRM: Enter applies this single canonical decision · Esc back"
        } else {
            ""
        };
        let content = format!(
            "Agent: {}\nProfile/plugin: {}/{}\nCapability/risk: {} / {}\nPurpose: {}\nRequested scope: {}\n\n{}\n\nDecision: {} · {}\nNarrowing constraints: {}\n\n←/→ decision · t time · u uses · c edit constraints · Enter review · Esc back{}\n{}",
            dialog.request.principal_fingerprint,
            dialog.request.profile_id,
            dialog.request.plugin_id,
            dialog.request.capability_id(),
            dialog.request.risk,
            sanitize_display_text(&dialog.request.purpose),
            serde_json::to_string_pretty(&dialog.request.scope)
                .unwrap_or_else(|_| "invalid".into()),
            schema,
            dialog.decision.label(),
            decision_detail,
            constraints,
            confirm,
            dialog.message.as_deref().unwrap_or_default(),
        );
        frame.render_widget(
            Paragraph::new(content).wrap(Wrap { trim: false }).block(
                Block::default()
                    .title(" Core-owned JIT approval review ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(if dialog.confirm {
                        Color::Yellow
                    } else {
                        Color::Cyan
                    })),
            ),
            popup,
        );
    }
}

fn is_native_profile(profile: &ConnectionProfile) -> bool {
    profile.metadata.get("source").and_then(Value::as_str) == Some(NATIVE_PROFILE_SOURCE)
}

fn database_type_for_plugin(plugin_id: &str) -> DatabaseType {
    match plugin_id {
        "mysql" => DatabaseType::MySQL,
        "postgres" | "postgresql" => DatabaseType::PostgreSQL,
        "sqlite" => DatabaseType::SQLite,
        _ => DatabaseType::Plugin,
    }
}

fn scalar_text(value: Option<&Value>) -> Option<String> {
    match value? {
        Value::Null => None,
        Value::String(value) => Some(value.clone()),
        Value::Number(value) => Some(value.to_string()),
        Value::Bool(value) => Some(value.to_string()),
        _ => None,
    }
}

fn string_list_value(value: &str) -> Value {
    if value.trim().is_empty() {
        return json!([]);
    }
    Value::Array(
        value
            .split(',')
            .map(|item| Value::String(item.trim().to_string()))
            .collect(),
    )
}

fn set_json_pointer(root: &mut Value, pointer: &str, value: Value) {
    let segments = pointer
        .strip_prefix('/')
        .unwrap_or(pointer)
        .split('/')
        .filter(|segment| !segment.is_empty())
        .map(|segment| segment.replace("~1", "/").replace("~0", "~"))
        .collect::<Vec<_>>();
    if segments.is_empty() {
        *root = value;
        return;
    }
    if !root.is_object() {
        *root = json!({});
    }
    let mut current = root;
    for segment in &segments[..segments.len() - 1] {
        let object = current
            .as_object_mut()
            .expect("profile form paths only traverse objects");
        current = object.entry(segment.clone()).or_insert_with(|| json!({}));
        if !current.is_object() {
            *current = json!({});
        }
    }
    current
        .as_object_mut()
        .expect("profile form parent must be an object")
        .insert(segments.last().expect("non-empty path").clone(), value);
}

fn pretty_json_lines(value: Value) -> Vec<String> {
    serde_json::to_string_pretty(&value)
        .unwrap_or_else(|_| "{}".to_string())
        .lines()
        .map(str::to_string)
        .collect()
}

fn byte_index(value: &str, character_index: usize) -> usize {
    value
        .char_indices()
        .nth(character_index)
        .map(|(index, _)| index)
        .unwrap_or(value.len())
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
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
        .split(vertical[1])[1]
}

fn render_input(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    value: &str,
    active: bool,
    secret: bool,
) {
    let rendered = if secret {
        "•".repeat(value.chars().count())
    } else {
        value.to_string()
    };
    frame.render_widget(
        Paragraph::new(rendered).block(
            Block::default()
                .title(format!(" {title} "))
                .borders(Borders::ALL)
                .border_style(if active {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default().fg(Color::DarkGray)
                }),
        ),
        area,
    );
}

fn create_profile_editor(
    config: &AppConfig,
    active_master_password: Option<&str>,
) -> std::result::Result<ProfileEditor, &'static str> {
    if config.requires_master_password() && active_master_password.is_none() {
        Err("Press m to unlock profile credentials before creating a profile")
    } else {
        Ok(ProfileEditor::new())
    }
}

fn detail_line(label: &str, value: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{label}: "), Style::default().fg(Color::DarkGray)),
        Span::raw(value.to_string()),
    ])
}

fn plural(count: usize) -> &'static str {
    if count == 1 { "" } else { "s" }
}

fn format_use_limit(uses: Option<u32>) -> String {
    uses.map_or_else(
        || "unlimited uses".to_string(),
        |uses| format!("{uses} use{} left", plural(uses as usize)),
    )
}

fn protocol_icon(plugin_id: &str) -> &'static str {
    match plugin_id {
        "mysql" => "🐬",
        "postgres" => "🐘",
        "sqlite" => "▣",
        "redis" => "◆",
        "ssh" => "⌘",
        "docker" => "◫",
        "kubernetes" => "☸",
        "s3" => "▱",
        "email" => "✉",
        _ => "•",
    }
}

fn resolve_voidb_cli_binary() -> PathBuf {
    if let Ok(path) = std::env::var("VOIDB_CLI_BIN") {
        return path.into();
    }
    if let Ok(current) = std::env::current_exe()
        && let Some(directory) = current.parent()
    {
        let sibling = directory.join("voidb-cli");
        if sibling.exists() {
            return sibling;
        }
    }
    "voidb-cli".into()
}

fn run_profile_test(
    profile: &ConnectionProfile,
    master_password: Option<&str>,
) -> std::result::Result<String, String> {
    let mut command = std::process::Command::new(resolve_voidb_cli_binary());
    command.args([
        "profile",
        "test",
        &format!("id:{}", profile.id),
        "--plugin",
        &profile.plugin_id,
        "--format",
        "json",
    ]);
    if let Some(password) = master_password {
        command.env(voidb_core::VOIDB_MASTER_PASSWORD_ENV, password);
    }
    let output = command
        .output()
        .map_err(|error| format!("could not launch voidb-cli: {error}"))?;
    let value: Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| "voidb-cli did not return structured JSON".to_string())?;
    if value.get("ok").and_then(Value::as_bool) == Some(true) {
        let message = value
            .pointer("/data/message")
            .and_then(Value::as_str)
            .unwrap_or("connection succeeded");
        Ok(format!(
            "{}/{} OK: {message}",
            profile.plugin_id, profile.name
        ))
    } else {
        Err(value
            .pointer("/error/message")
            .and_then(Value::as_str)
            .unwrap_or("profile test failed")
            .to_string())
    }
}

struct AgentAuthorizeRequest {
    capabilities: Vec<String>,
    ttl_minutes: u64,
    uses: Option<u32>,
    preset: AgentAuthorizationPresetKind,
    allow_destructive: bool,
    replace: bool,
}

fn run_agent_authorize(
    profile: &ConnectionProfile,
    master_password: Option<&str>,
    request: AgentAuthorizeRequest,
) -> std::result::Result<String, String> {
    let password = master_password.ok_or_else(|| "credentials are locked".to_string())?;
    if request.capabilities.is_empty() {
        return Err("authorization capability scope is empty".into());
    }
    let mut command = std::process::Command::new(resolve_voidb_cli_binary());
    command.args(agent_authorize_args(profile, &request));
    command
        .env_remove(voidb_core::VOIDB_MASTER_PASSWORD_ENV)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|error| format!("could not launch voidb-cli: {error}"))?;
    child
        .stdin
        .take()
        .ok_or_else(|| "could not open the authorization password pipe".to_string())?
        .write_all(password.as_bytes())
        .map_err(|error| format!("could not send the authorization password: {error}"))?;
    let output = child
        .wait_with_output()
        .map_err(|error| format!("could not wait for voidb-cli: {error}"))?;
    let value: Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| String::from_utf8_lossy(&output.stderr).into_owned())?;
    if value.get("ok").and_then(Value::as_bool) == Some(true) {
        let grant_id = value
            .pointer("/data/grant/id")
            .and_then(Value::as_str)
            .unwrap_or("agent grant");
        Ok(format!(
            "Authorized {grant_id} for {}/{} · {} capabilities · {} min · {}",
            profile.plugin_id,
            profile.name,
            request.capabilities.len(),
            request.ttl_minutes,
            format_use_limit(request.uses),
        ))
    } else {
        Err(value
            .pointer("/error/message")
            .and_then(Value::as_str)
            .unwrap_or("voidb-cli rejected the authorization")
            .to_string())
    }
}

fn agent_authorize_args(
    profile: &ConnectionProfile,
    request: &AgentAuthorizeRequest,
) -> Vec<String> {
    let mut args = vec![
        "agent".into(),
        "authorize".into(),
        "--profile".into(),
        format!("id:{}", profile.id),
        "--plugin".into(),
        profile.plugin_id.clone(),
        "--ttl-minutes".into(),
        request.ttl_minutes.to_string(),
        "--preset".into(),
        match request.preset {
            AgentAuthorizationPresetKind::ReadOnly => "read_only".into(),
            AgentAuthorizationPresetKind::InteractiveExecute => "interactive_execute".into(),
            AgentAuthorizationPresetKind::FullAccess => "full_access".into(),
            AgentAuthorizationPresetKind::Custom => "custom".into(),
        },
        "--password-stdin".into(),
    ];
    if let Some(uses) = request.uses {
        args.extend(["--uses".into(), uses.to_string()]);
    }
    for capability in &request.capabilities {
        args.extend(["--capability".into(), capability.clone()]);
    }
    if request.allow_destructive {
        args.extend(["--allow-destructive".into(), "--yes".into()]);
    }
    if request.replace {
        args.push("--replace".into());
    }
    args
}

fn run_agent_renew(
    grant_id: &str,
    ttl_minutes: u64,
    uses: Option<u32>,
) -> std::result::Result<String, String> {
    let mut command = std::process::Command::new(resolve_voidb_cli_binary());
    command
        .args(["agent", "renew", grant_id, "--ttl-minutes"])
        .arg(ttl_minutes.to_string());
    if let Some(uses) = uses {
        command.arg("--uses").arg(uses.to_string());
    }
    let output = command
        .output()
        .map_err(|error| format!("could not launch voidb-cli: {error}"))?;
    let value: Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| String::from_utf8_lossy(&output.stderr).into_owned())?;
    if value.get("ok").and_then(Value::as_bool) == Some(true) {
        Ok(format!(
            "Renewed {grant_id} for {ttl_minutes} minutes with {}",
            format_use_limit(uses)
        ))
    } else {
        Err(value
            .pointer("/error/message")
            .and_then(Value::as_str)
            .unwrap_or("voidb-cli rejected the renewal")
            .to_string())
    }
}

fn run_agent_revoke_profile(profile: &ConnectionProfile) -> std::result::Result<String, String> {
    let output = std::process::Command::new(resolve_voidb_cli_binary())
        .args(["agent", "revoke", "--profile"])
        .arg(format!("id:{}", profile.id))
        .args(["--plugin", &profile.plugin_id])
        .output()
        .map_err(|error| format!("could not launch voidb-cli: {error}"))?;
    let value: Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| String::from_utf8_lossy(&output.stderr).into_owned())?;
    value
        .pointer("/data/count")
        .and_then(Value::as_u64)
        .map(|count| {
            format!(
                "Revoked {count} grant{} for {}/{}",
                if count == 1 { "" } else { "s" },
                profile.plugin_id,
                profile.name
            )
        })
        .ok_or_else(|| "voidb-cli did not return a scoped revoke count".to_string())
}

fn run_agent_revoke_all() -> std::result::Result<usize, String> {
    let output = std::process::Command::new(resolve_voidb_cli_binary())
        .args(["agent", "revoke", "--all"])
        .output()
        .map_err(|error| format!("could not launch voidb-cli: {error}"))?;
    let value: Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| String::from_utf8_lossy(&output.stderr).into_owned())?;
    value
        .pointer("/data/count")
        .and_then(Value::as_u64)
        .map(|count| count as usize)
        .ok_or_else(|| "voidb-cli did not return a revoke count".to_string())
}

fn run_agent_list() -> std::result::Result<String, String> {
    let output = std::process::Command::new(resolve_voidb_cli_binary())
        .args(["agent", "list"])
        .output()
        .map_err(|error| format!("could not launch voidb-cli: {error}"))?;
    if !output.status.success() && output.stdout.is_empty() {
        return Err(format!("voidb-cli exited with {}", output.status));
    }
    String::from_utf8(output.stdout).map_err(|error| error.to_string())
}

fn run_authorization_snapshot() -> std::result::Result<String, String> {
    let grants: Value = serde_json::from_str(&run_agent_list()?)
        .map_err(|_| "voidb-cli agent list returned invalid JSON".to_string())?;
    let output = std::process::Command::new(resolve_voidb_cli_binary())
        .args(["agent", "catalog"])
        .output()
        .map_err(|error| format!("could not launch voidb-cli: {error}"))?;
    let catalog: Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| String::from_utf8_lossy(&output.stderr).into_owned())?;
    let inbox_output = std::process::Command::new(resolve_voidb_cli_binary())
        .args(["agent", "request", "inbox"])
        .output()
        .map_err(|error| format!("could not launch voidb-cli: {error}"))?;
    let inbox: Value = serde_json::from_slice(&inbox_output.stdout)
        .map_err(|_| String::from_utf8_lossy(&inbox_output.stderr).into_owned())?;
    Ok(json!({ "agent": grants, "catalog": catalog, "inbox": inbox }).to_string())
}

fn run_jit_authorization_decision(
    request_id: &str,
    decision: JitDecision,
    ttl_minutes: u64,
    uses: Option<u32>,
    grant_id: Option<&str>,
    constraints_json: Option<&str>,
    master_password: Option<&str>,
) -> std::result::Result<String, String> {
    let mut command = std::process::Command::new(resolve_voidb_cli_binary());
    command
        .args(["agent", "request", "decide", request_id, "--decision"])
        .arg(decision.cli_value());
    if matches!(decision, JitDecision::Bounded) {
        command
            .arg("--ttl-seconds")
            .arg((ttl_minutes * 60).to_string());
        if let Some(uses) = uses {
            command.arg("--uses").arg(uses.to_string());
        }
    }
    if matches!(decision, JitDecision::AddToGrant) {
        let grant_id = grant_id.ok_or_else(|| "No compatible logical grant exists".to_string())?;
        command
            .arg("--grant")
            .arg(grant_id)
            .arg("--ttl-delta-seconds")
            .arg((ttl_minutes * 60).to_string())
            .arg("--uses-delta")
            .arg(uses.unwrap_or(0).to_string());
    }
    if let Some(constraints) = constraints_json {
        command.arg("--constraints-json").arg(constraints);
    }
    if matches!(decision, JitDecision::Deny) {
        command
            .arg("--reason")
            .arg("Denied from Connection Manager");
    }
    let password = master_password.ok_or_else(|| "credentials are locked".to_string())?;
    command.arg("--password-stdin");
    command
        .env_remove(voidb_core::VOIDB_MASTER_PASSWORD_ENV)
        .stdin(std::process::Stdio::piped());
    let mut child = command
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|error| format!("could not launch voidb-cli: {error}"))?;
    child
        .stdin
        .take()
        .ok_or_else(|| "could not open decision password pipe".to_string())?
        .write_all(password.as_bytes())
        .map_err(|error| format!("could not send decision password: {error}"))?;
    parse_jit_decision_output(
        child
            .wait_with_output()
            .map_err(|error| format!("could not wait for voidb-cli: {error}"))?,
        request_id,
        decision,
    )
}

fn parse_jit_decision_output(
    output: std::process::Output,
    request_id: &str,
    decision: JitDecision,
) -> std::result::Result<String, String> {
    let value: Value = serde_json::from_slice(&output.stdout)
        .map_err(|_| String::from_utf8_lossy(&output.stderr).into_owned())?;
    if value.get("ok").and_then(Value::as_bool) == Some(true) {
        let revision = value
            .pointer("/data/revision/revision")
            .and_then(Value::as_u64)
            .map(|revision| format!(" · revision {revision}"))
            .unwrap_or_default();
        Ok(format!(
            "{} request {request_id}{revision}",
            decision.label()
        ))
    } else {
        Err(value
            .pointer("/error/message")
            .and_then(Value::as_str)
            .unwrap_or("voidb-cli rejected the authorization decision")
            .to_string())
    }
}

fn parse_agent_statuses(payload: &str) -> HashMap<(String, String), AuthorizationStatusView> {
    let Ok(value) = serde_json::from_str::<Value>(payload) else {
        return HashMap::new();
    };
    let agent = value.get("agent").unwrap_or(&value);
    agent
        .pointer("/data/grants")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|grant| {
            let profile_id = grant.get("profile_id")?.as_str()?.to_string();
            let plugin_id = grant.get("plugin_id")?.as_str()?.to_string();
            let view = AuthorizationStatusView {
                grant_id: grant.get("id")?.as_str()?.to_string(),
                profile_id: profile_id.clone(),
                plugin_id: plugin_id.clone(),
                status: grant
                    .get("status")
                    .and_then(Value::as_str)
                    .unwrap_or("broker_offline")
                    .to_string(),
                broker_health: grant
                    .get("broker_health")
                    .and_then(Value::as_str)
                    .unwrap_or("offline")
                    .to_string(),
                allow_destructive: grant
                    .get("allow_destructive")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                expires_at: grant
                    .get("expires_at")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_string(),
                remaining_uses: grant
                    .get("remaining_uses")
                    .and_then(Value::as_u64)
                    .and_then(|value| u32::try_from(value).ok()),
                active_session_count: grant
                    .get("active_session_count")
                    .and_then(Value::as_u64)
                    .and_then(|value| usize::try_from(value).ok())
                    .unwrap_or(0),
                capabilities: grant
                    .get("capabilities")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect(),
            };
            Some(((profile_id, plugin_id), view))
        })
        .collect()
}

fn parse_agent_supported_plugins(payload: &str) -> BTreeSet<String> {
    let Ok(value) = serde_json::from_str::<Value>(payload) else {
        return BTreeSet::new();
    };
    value
        .pointer("/catalog/data/capabilities")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|capability| capability.get("plugin_id").and_then(Value::as_str))
        .map(str::to_string)
        .collect()
}

fn parse_pending_authorizations(payload: &str) -> Vec<PendingAuthorizationView> {
    let Ok(value) = serde_json::from_str::<Value>(payload) else {
        return Vec::new();
    };
    let mut requests = value
        .pointer("/inbox/data/requests")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|request| {
            Some(PendingAuthorizationView {
                id: request.get("id")?.as_str()?.to_string(),
                principal_fingerprint: request.get("principal_fingerprint")?.as_str()?.to_string(),
                profile_id: request.get("profile_id")?.as_str()?.to_string(),
                plugin_id: request.get("plugin_id")?.as_str()?.to_string(),
                scope: request.get("scope")?.clone(),
                risk: request
                    .get("risk")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_string(),
                purpose: request
                    .get("purpose")
                    .or_else(|| request.get("reason"))
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                status: request.get("status")?.as_str()?.to_string(),
                created_at: request.get("created_at")?.as_str()?.to_string(),
                expires_at: request.get("expires_at")?.as_str()?.to_string(),
                timed_out: request
                    .get("timed_out")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                decision_reason: request
                    .get("decision_reason")
                    .and_then(Value::as_str)
                    .map(str::to_string),
            })
        })
        .collect::<Vec<_>>();
    requests.sort_by_key(|request| (!request.is_pending(), request.created_at.clone()));
    requests
}

fn parse_grant_revisions(payload: &str) -> Vec<GrantRevisionView> {
    let Ok(value) = serde_json::from_str::<Value>(payload) else {
        return Vec::new();
    };
    value
        .pointer("/inbox/data/revisions")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|revision| {
            Some(GrantRevisionView {
                grant_id: revision.get("grant_id")?.as_str()?.to_string(),
                revision: revision.get("revision")?.as_u64()?,
                principal_fingerprint: revision.get("principal_fingerprint")?.as_str()?.to_string(),
                profile_id: revision.get("profile_id")?.as_str()?.to_string(),
                plugin_id: revision.get("plugin_id")?.as_str()?.to_string(),
                expires_at: revision.get("expires_at")?.as_str()?.to_string(),
                remaining_uses: revision
                    .get("remaining_uses")
                    .and_then(Value::as_u64)
                    .and_then(|value| u32::try_from(value).ok()),
            })
        })
        .collect()
}

fn parse_authorization_observed_at(payload: &str) -> Option<String> {
    serde_json::from_str::<Value>(payload)
        .ok()?
        .pointer("/inbox/data/observed_at")?
        .as_str()
        .map(str::to_string)
}

fn interactive_execute_capabilities(capabilities: &[CapabilityItem]) -> Vec<String> {
    capabilities
        .iter()
        .filter(|capability| capability.interactive_execute)
        .map(|capability| capability.id.clone())
        .collect()
}

fn run_capability_list(plugin_id: &str) -> std::result::Result<String, String> {
    let output = std::process::Command::new(resolve_voidb_cli_binary())
        .args(capability_list_args(plugin_id))
        .output()
        .map_err(|error| format!("could not launch voidb-cli: {error}"))?;
    if !output.status.success() && output.stdout.is_empty() {
        return Err(format!("voidb-cli exited with {}", output.status));
    }
    String::from_utf8(output.stdout).map_err(|error| error.to_string())
}

fn capability_list_args(plugin_id: &str) -> [&str; 6] {
    [
        "agent",
        "catalog",
        "--plugin",
        plugin_id,
        "--execution-mode",
        "stateless",
    ]
}

fn parse_capabilities(payload: &str) -> Vec<CapabilityItem> {
    let Ok(value) = serde_json::from_str::<Value>(payload) else {
        return Vec::new();
    };
    let candidates = value
        .pointer("/data/capabilities")
        .or_else(|| value.pointer("/catalog/data/capabilities"))
        .or_else(|| value.pointer("/data/items"))
        .or_else(|| value.get("capabilities"))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    candidates
        .into_iter()
        .filter_map(|item| {
            let id = item
                .get("qualified_id")
                .or_else(|| item.get("id"))
                .and_then(Value::as_str)?
                .to_string();
            Some(CapabilityItem {
                id,
                description: item
                    .get("description")
                    .and_then(Value::as_str)
                    .unwrap_or("No description")
                    .to_string(),
                risk: item
                    .get("risk")
                    .and_then(Value::as_str)
                    .unwrap_or("read_only")
                    .to_string(),
                interactive_execute: item
                    .pointer("/authorization/interactive_execute")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                capability_wide_allowed: item
                    .pointer("/authorization/capability_wide_allowed")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                approval_fields: item
                    .pointer("/authorization/approval_schema/fields")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .filter_map(|field| {
                        let label = field.get("label")?.as_str()?;
                        let path = field.get("path")?.as_str()?;
                        let constraint = field
                            .get("constraint")
                            .and_then(Value::as_str)
                            .unwrap_or("exact");
                        Some(format!("{label} ({path}, {constraint})"))
                    })
                    .collect(),
            })
        })
        .collect()
}

fn sanitize_display_text(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .take(240)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plugin_templates_are_valid_json_objects() {
        for (plugin_id, _) in PLUGINS {
            assert!(default_plugin_config(plugin_id).is_object());
        }
    }

    #[test]
    fn editor_handles_unicode_without_invalid_byte_offsets() {
        let mut editor = ProfileEditor::new();
        editor.config_lines = vec![String::new()];
        editor.insert_char('你');
        editor.insert_char('好');
        editor.backspace();
        assert_eq!(editor.config_lines, vec!["你"]);
        assert_eq!(editor.cursor_col, 1);
    }

    #[test]
    fn new_editor_starts_with_connection_type_before_name_and_display_name() {
        let mut editor = ProfileEditor::new();
        assert_eq!(editor.active_field, 0);
        editor.cycle_plugin(true);
        assert_eq!(editor.active_field, 0);
        editor.active_field = 1;
        editor.name = "prod".to_string();
        editor.active_field = 2;
        editor.display_name = "Production".to_string();
        assert_eq!(editor.name, "prod");
        assert_eq!(editor.display_name, "Production");
    }

    #[test]
    fn new_profile_editor_requires_an_unlocked_master_password() {
        let mut protected = AppConfig::default();
        protected
            .set_user_passphrase_protection("correct horse battery staple")
            .expect("protect config");

        assert_eq!(
            create_profile_editor(&protected, None)
                .expect_err("locked credentials must block profile creation"),
            "Press m to unlock profile credentials before creating a profile"
        );
        assert!(create_profile_editor(&protected, Some("session password")).is_ok());
        assert!(create_profile_editor(&AppConfig::default(), None).is_ok());
    }

    #[test]
    fn ssh_form_switches_authentication_fields_and_masks_password() {
        let mut editor = ProfileEditor::new();
        editor.plugin_index = PLUGINS
            .iter()
            .position(|(plugin_id, _)| *plugin_id == "ssh")
            .expect("ssh plugin");
        editor.config = default_plugin_config("ssh");
        editor.schema = profile_form_schema("ssh");
        editor.active_field = editor
            .schema
            .visible_fields(&editor.config)
            .iter()
            .position(|field| field.path == "/auth")
            .expect("auth field")
            + 3;

        editor.cycle_form_value(true);
        assert_eq!(editor.config["auth"]["type"], "Password");
        let password_index = editor
            .schema
            .visible_fields(&editor.config)
            .iter()
            .position(|field| field.path == "/auth/password")
            .expect("password field");
        editor.active_field = password_index + 3;
        editor.append_form_character('秘');
        editor.append_form_character('密');
        let password_field = editor.active_form_field().expect("password field");
        assert_eq!(editor.form_field_display(password_field), "••");
        assert_eq!(editor.config["auth"]["password"], "秘密");
        assert!(editor.schema.validate(&editor.config).is_empty());

        editor.active_field = editor
            .schema
            .visible_fields(&editor.config)
            .iter()
            .position(|field| field.path == "/auth")
            .expect("auth field")
            + 3;
        editor.cycle_form_value(true);
        assert_eq!(editor.config["auth"]["type"], "PublicKey");
        assert!(
            editor
                .schema
                .visible_fields(&editor.config)
                .iter()
                .any(|field| field.path == "/auth/private_key_path")
        );
        assert!(
            editor
                .schema
                .visible_fields(&editor.config)
                .iter()
                .all(|field| field.path != "/auth/password")
        );
    }

    #[test]
    fn advanced_json_roundtrips_back_into_the_form() {
        let mut editor = ProfileEditor::new();
        editor.toggle_view();
        assert_eq!(editor.view, EditorView::Json);
        editor.config_lines = pretty_json_lines(json!({
            "host": "db.internal",
            "port": 3306,
            "username": "app",
            "password": "",
            "database": "prod",
            "ssl_mode": "required"
        }));
        editor.toggle_view();
        assert_eq!(editor.view, EditorView::Form);
        assert_eq!(editor.config["host"], "db.internal");
        assert_eq!(editor.config["ssl_mode"], "required");
    }

    #[test]
    fn native_filter_rejects_compatibility_profiles() {
        let native = ConnectionProfile {
            id: "profile:native".into(),
            name: "native".into(),
            plugin_id: "sqlite".into(),
            display_name: None,
            metadata: json!({ "source": NATIVE_PROFILE_SOURCE }),
            default_options: Value::Null,
            credential_refs: Vec::new(),
            policy: Default::default(),
        };
        let mut compatibility = native.clone();
        compatibility.metadata = json!({ "source": "connection_config" });
        assert!(is_native_profile(&native));
        assert!(!is_native_profile(&compatibility));
    }

    #[test]
    fn authorization_presets_resolve_to_exact_capability_scopes() {
        let profile = ConnectionProfile {
            id: "profile:ssh".into(),
            name: "prod-shell".into(),
            plugin_id: "ssh".into(),
            display_name: None,
            metadata: json!({ "source": NATIVE_PROFILE_SOURCE }),
            default_options: Value::Null,
            credential_refs: Vec::new(),
            policy: Default::default(),
        };
        let mut dialog = AuthorizationDialog::new(profile);
        dialog.loading = false;
        dialog.capabilities = vec![
            CapabilityItem {
                id: "ssh.sftp_list".into(),
                description: "list".into(),
                risk: "read_only".into(),
                interactive_execute: false,
                capability_wide_allowed: true,
                approval_fields: Vec::new(),
            },
            CapabilityItem {
                id: "ssh.exec".into(),
                description: "exec".into(),
                risk: "destructive".into(),
                interactive_execute: true,
                capability_wide_allowed: true,
                approval_fields: Vec::new(),
            },
            CapabilityItem {
                id: "ssh.sftp_rm".into(),
                description: "remove".into(),
                risk: "destructive".into(),
                interactive_execute: false,
                capability_wide_allowed: true,
                approval_fields: Vec::new(),
            },
        ];

        assert!(!dialog.advanced);
        assert_eq!(dialog.preset_label(), "Read-only (recommended)");
        assert_eq!(dialog.selected_capabilities(), vec!["ssh.sftp_list"]);
        assert!(!dialog.requires_destructive_acknowledgement());
        dialog.advanced = true;
        dialog.cycle_preset(true);
        assert_eq!(
            dialog.preset,
            AgentAuthorizationPresetKind::InteractiveExecute
        );
        assert_eq!(dialog.selected_capabilities(), vec!["ssh.exec"]);
        assert!(dialog.requires_destructive_acknowledgement());
        dialog.cycle_preset(true);
        assert_eq!(dialog.preset, AgentAuthorizationPresetKind::FullAccess);
        assert_eq!(
            dialog.selected_capabilities(),
            vec!["ssh.exec", "ssh.sftp_list", "ssh.sftp_rm"]
        );
        assert!(dialog.requires_destructive_acknowledgement());
        dialog.cycle_preset(true);
        dialog.custom_selected.insert("ssh.sftp_rm".into());
        assert_eq!(dialog.selected_capabilities(), vec!["ssh.sftp_rm"]);
    }

    #[test]
    fn tui_execute_authorization_builds_explicit_password_free_arguments() {
        let profile = ConnectionProfile {
            id: "profile:ssh".into(),
            name: "prod-shell".into(),
            plugin_id: "ssh".into(),
            display_name: None,
            metadata: json!({ "source": NATIVE_PROFILE_SOURCE }),
            default_options: Value::Null,
            credential_refs: Vec::new(),
            policy: Default::default(),
        };
        let args = agent_authorize_args(
            &profile,
            &AgentAuthorizeRequest {
                capabilities: vec!["ssh.exec".into()],
                ttl_minutes: 15,
                uses: Some(10),
                preset: AgentAuthorizationPresetKind::InteractiveExecute,
                allow_destructive: true,
                replace: true,
            },
        );
        assert_eq!(
            args[0..6],
            [
                "agent",
                "authorize",
                "--profile",
                "id:profile:ssh",
                "--plugin",
                "ssh"
            ]
        );
        for expected in [
            "interactive_execute",
            "ssh.exec",
            "--password-stdin",
            "--allow-destructive",
            "--yes",
            "--replace",
        ] {
            assert!(args.iter().any(|arg| arg == expected), "missing {expected}");
        }

        let full_access_args = agent_authorize_args(
            &profile,
            &AgentAuthorizeRequest {
                capabilities: vec!["ssh.exec".into(), "ssh.sftp_list".into()],
                ttl_minutes: 15,
                uses: Some(10),
                preset: AgentAuthorizationPresetKind::FullAccess,
                allow_destructive: true,
                replace: false,
            },
        );
        assert!(full_access_args.iter().any(|arg| arg == "full_access"));
        assert!(full_access_args.iter().any(|arg| arg == "ssh.exec"));
        assert!(full_access_args.iter().any(|arg| arg == "ssh.sftp_list"));
        let encoded = args.join(" ");
        for forbidden in [
            "master_password",
            "VOIDB_MASTER_PASSWORD",
            "prod-shell-secret",
        ] {
            assert!(!encoded.contains(forbidden));
        }
    }

    #[test]
    fn agent_status_projection_is_bounded_and_ignores_broker_secrets() {
        let statuses = parse_agent_statuses(
            &json!({
                "ok": true,
                "data": {
                    "grants": [{
                        "id": "agent-grant:test",
                        "profile_id": "profile:ssh",
                        "plugin_id": "ssh",
                        "status": "active",
                        "broker_health": "online",
                        "allow_destructive": true,
                        "expires_at": "2026-07-12T10:00:00Z",
                        "remaining_uses": 8,
                        "active_session_count": 2,
                        "capabilities": ["ssh.exec"],
                        "token": "must-not-project",
                        "socket_path": "/tmp/must-not-project.sock"
                    }]
                }
            })
            .to_string(),
        );
        let status = statuses
            .get(&("profile:ssh".into(), "ssh".into()))
            .expect("status");
        assert_eq!(status.badge(), "EXECUTE");
        assert_eq!(status.active_session_count, 2);
        assert_eq!(status.capabilities, vec!["ssh.exec"]);
        let debug = format!("{status:?}");
        assert!(!debug.contains("must-not-project"));
        assert!(!debug.contains("socket"));
    }

    #[test]
    fn authorization_snapshot_classifies_supported_and_unsupported_plugins() {
        let payload = json!({
            "agent": { "data": { "grants": [] } },
            "catalog": {
                "data": {
                    "capabilities": [
                        { "plugin_id": "ssh", "id": "exec" },
                        { "plugin_id": "sqlite", "id": "query" }
                    ]
                }
            }
        })
        .to_string();
        let supported = parse_agent_supported_plugins(&payload);
        assert!(supported.contains("ssh"));
        assert!(supported.contains("sqlite"));
        assert!(!supported.contains("sync"));
    }

    #[test]
    fn authorization_dialog_requests_only_stateless_compatible_capabilities() {
        assert_eq!(
            capability_list_args("ssh"),
            [
                "agent",
                "catalog",
                "--plugin",
                "ssh",
                "--execution-mode",
                "stateless",
            ]
        );
    }

    #[test]
    fn jit_inbox_projection_groups_safe_requests_and_revisions() {
        let payload = json!({
            "catalog": { "data": { "capabilities": [{
                "qualified_id": "ssh.exec",
                "risk": "destructive",
                "authorization": {
                    "capability_wide_allowed": true,
                    "approval_schema": { "fields": [{
                        "path": "/cwd",
                        "label": "Working directory",
                        "constraint": "prefix"
                    }] }
                }
            }] } },
            "inbox": { "data": {
                "observed_at": "2026-07-12T06:00:00Z",
                "requests": [{
                    "id": "auth-request:00000000-0000-4000-8000-000000000001",
                    "principal_fingerprint": "agent-principal:abc",
                    "profile_id": "profile:ssh",
                    "plugin_id": "ssh",
                    "scope": { "kind": "capability", "capability_id": "ssh.exec" },
                    "risk": "destructive",
                    "purpose": "Deploy release 2026.07 to the production host",
                    "status": "pending",
                    "created_at": "2026-07-12T05:59:00Z",
                    "expires_at": "2026-07-12T06:04:00Z",
                    "token": "must-not-project"
                }],
                "revisions": [{
                    "grant_id": "agent-grant:test",
                    "revision": 2,
                    "principal_fingerprint": "agent-principal:abc",
                    "profile_id": "profile:ssh",
                    "plugin_id": "ssh",
                    "expires_at": "2026-07-12T07:00:00Z",
                    "remaining_uses": 4,
                    "socket_path": "/tmp/must-not-project.sock"
                }]
            } }
        })
        .to_string();
        let requests = parse_pending_authorizations(&payload);
        let revisions = parse_grant_revisions(&payload);
        let catalog = parse_capabilities(&payload);
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].capability_id(), "ssh.exec");
        assert_eq!(
            requests[0].purpose,
            "Deploy release 2026.07 to the production host"
        );
        assert_eq!(revisions.len(), 1);
        assert_eq!(revisions[0].revision, 2);
        assert_eq!(catalog[0].approval_fields.len(), 1);
        let debug = format!("{requests:?}{revisions:?}");
        assert!(!debug.contains("must-not-project"));
        assert!(!debug.contains("socket_path"));
    }

    #[test]
    fn jit_review_dialog_never_crosses_agent_revision_history() {
        let request = |principal: &str| PendingAuthorizationView {
            id: format!("auth-request:{principal}"),
            principal_fingerprint: principal.into(),
            profile_id: "profile:ssh".into(),
            plugin_id: "ssh".into(),
            scope: json!({ "kind": "capability", "capability_id": "ssh.exec" }),
            risk: "destructive".into(),
            purpose: "Inspect the remote process state for incident triage".into(),
            status: "pending".into(),
            created_at: "2026-07-12T06:00:00Z".into(),
            expires_at: "2026-07-12T06:05:00Z".into(),
            timed_out: false,
            decision_reason: None,
        };
        let revision = |principal: &str, grant: &str| GrantRevisionView {
            grant_id: grant.into(),
            revision: 1,
            principal_fingerprint: principal.into(),
            profile_id: "profile:ssh".into(),
            plugin_id: "ssh".into(),
            expires_at: "2026-07-12T07:00:00Z".into(),
            remaining_uses: Some(2),
        };
        let revisions = vec![
            revision("agent-principal:a", "agent-grant:a"),
            revision("agent-principal:b", "agent-grant:b"),
        ];
        let a = JitApprovalDialog::new(request("agent-principal:a"), &revisions);
        let b = JitApprovalDialog::new(request("agent-principal:b"), &revisions);
        assert_eq!(a.grant_id.as_deref(), Some("agent-grant:a"));
        assert_eq!(b.grant_id.as_deref(), Some("agent-grant:b"));
    }
}
