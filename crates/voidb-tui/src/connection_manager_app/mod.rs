//! Native standalone Connection Manager terminal application.
//!
//! This application owns its state, rendering, input model, and persistence.
//! It does not implement `Plugin`, construct `ShellCapabilities`, or reuse the
//! router-hosted Connection Manager screen.

mod actions;
mod background;
mod events;
mod render;
#[cfg(test)]
mod tests;

use std::collections::{BTreeSet, HashMap};
use std::sync::mpsc::Receiver;
use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::event;
use futures::StreamExt;
use ratatui::DefaultTerminal;
use ratatui::widgets::ListState;
use serde_json::{Value, json};
use voidb_core::{
    AgentAuthorizationPresetKind, AppConfig, ConnectionConfig, ConnectionProfile,
    LocalProfileStore, ProfileFormField, ProfileFormFieldKind, ProfileFormSchema,
};

use voidb_core::process_plugin::ProcessPluginCandidateState;

use crate::profile_forms::{default_plugin_config, profile_form_schema};

use background::installed_plugin_states;

const MIN_WIDTH: u16 = 72;
const MIN_HEIGHT: u16 = 20;
/// Idle backoff buckets for the background poll cadence (100/200/400/800 ms).
const POLL_INTERVAL_STEPS: u32 = 4;
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
    ConfirmPluginInstall,
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
    plugin_states: HashMap<String, ProcessPluginCandidateState>,
    plugin_install_target: Option<String>,
    plugin_install_rx: Option<(String, BackgroundResult)>,
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
            plugin_states: installed_plugin_states(),
            plugin_install_target: None,
            plugin_install_rx: None,
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
        // Adaptive background cadence: poll at 10 Hz while background work is
        // producing changes, backing off to ~1.25 Hz when idle so the loop
        // meets the docs/tui-interaction-performance.md idle budget. Key and
        // paste events always wake the loop immediately via the event stream.
        let mut idle_polls: u32 = 0;
        let mut applied_bucket: u32 = 0;
        let mut tick = tokio::time::interval(Self::poll_interval(applied_bucket));

        while !self.should_quit {
            let dirty = tokio::select! {
                _ = tick.tick() => {
                    let dirty = self.poll_background();
                    if dirty {
                        idle_polls = 0;
                    } else {
                        idle_polls = idle_polls.saturating_add(1);
                    }
                    let bucket = idle_polls.min(POLL_INTERVAL_STEPS - 1);
                    if bucket != applied_bucket {
                        applied_bucket = bucket;
                        tick = tokio::time::interval(Self::poll_interval(bucket));
                    }
                    dirty
                }
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
                    idle_polls = 0;
                    applied_bucket = 0;
                    tick = tokio::time::interval(Self::poll_interval(applied_bucket));
                    true
                }
            };
            if dirty {
                terminal.draw(|frame| self.render(frame))?;
            }
        }
        Ok(())
    }

    /// Background poll cadence for a given idle bucket: 100 ms doubling to an
    /// 800 ms ceiling.
    fn poll_interval(idle_bucket: u32) -> Duration {
        Duration::from_millis(100u64 << idle_bucket.min(POLL_INTERVAL_STEPS - 1))
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
}

fn is_native_profile(profile: &ConnectionProfile) -> bool {
    profile.metadata.get("source").and_then(Value::as_str) == Some(NATIVE_PROFILE_SOURCE)
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

fn plural(count: usize) -> &'static str {
    if count == 1 { "" } else { "s" }
}

fn format_use_limit(uses: Option<u32>) -> String {
    uses.map_or_else(
        || "unlimited uses".to_string(),
        |uses| format!("{uses} use{} left", plural(uses as usize)),
    )
}

fn interactive_execute_capabilities(capabilities: &[CapabilityItem]) -> Vec<String> {
    capabilities
        .iter()
        .filter(|capability| capability.interactive_execute)
        .map(|capability| capability.id.clone())
        .collect()
}
