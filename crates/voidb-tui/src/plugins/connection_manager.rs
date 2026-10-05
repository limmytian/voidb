//! Connection Manager Plugin
//!
//! This plugin provides the connection management UI.
//! It's the "home screen" of VoidB where users can:
//! - View all configured connections
//! - Add/Edit/Delete connections
//! - Test connections
//! - Show safe CLI/capability guidance for saved profiles

use anyhow::Result;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEventKind};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph};

type TestResultReceiver =
    Arc<std::sync::Mutex<std::sync::mpsc::Receiver<std::result::Result<String, String>>>>;
type CapabilityResultReceiver = Arc<
    std::sync::Mutex<
        std::sync::mpsc::Receiver<std::result::Result<Vec<CapabilityBrowserItem>, String>>,
    >,
>;
use ratatui::Frame;
use serde_json::Value;
use std::sync::Arc;

use voidb_core::plugin::connection_dialog::{ConnectionDialogComponent, DialogAction};
use voidb_core::widgets::{HelpEntry, HelpPopup, HelpSection};
use voidb_core::{
    ConnectionConfig, ConnectionManagerProfileEntry, ConnectionManagerProfileSource,
    CredentialMaterialState, CredentialMaterialSummary, CredentialProtectionMode,
    CredentialProtectionState, CredentialProtectionStore, DatabaseType, Event, LocalProfileStore,
    MasterPasswordSessionState, Plugin, PluginFactory, ShellCapabilities, config::AppConfig,
};

use super::connection_dialog::{ConnType, ConnectionDialog};

/// Connection Manager Plugin
pub struct ConnectionManagerPlugin {
    /// Shell capabilities
    caps: Option<ShellCapabilities>,
    /// List of connections
    connections: Vec<ConnectionConfig>,
    /// Selected index
    selected: usize,
    /// List state for rendering
    list_state: ListState,
    /// Status message to display
    status_message: Option<String>,
    /// Connection dialog (if open)
    dialog: Option<ConnectionDialog>,
    /// Custom connection dialog from plugin (if open)
    custom_dialog: Option<Box<dyn ConnectionDialogComponent>>,
    /// Pending delete confirmation (index)
    confirm_delete: Option<usize>,
    test_rx: Option<TestResultReceiver>,
    capability_rx: Option<CapabilityResultReceiver>,
    /// Test result receiver for in-dialog test connection
    dialog_test_rx: Option<TestResultReceiver>,
    /// Last render area for mouse mapping
    list_area: Option<Rect>,
    help_popup: Option<HelpPopup>,
    /// Type selector for new connection (plugin_id, selected_index)
    type_selector: Option<(Vec<ConnType>, usize)>,
    /// Search mode active
    search_active: bool,
    /// Search input buffer
    search_buffer: String,
    /// Filtered indices into self.connections (always used)
    filtered_indices: Vec<usize>,
    /// Composite key of the connection being edited (for rename detection)
    editing_key: Option<String>,
    /// Deferred save: config validated, waiting for next Tick to execute
    save_pending: Option<ConnectionConfig>,
    /// Command mode input buffer (vim-style `:` commands)
    command_buffer: Option<String>,
    /// Current credential protection state shown in the Connection Manager.
    credential_state: CredentialProtectionState,
    /// Master password kept only in memory after a successful TUI unlock/setup.
    active_master_password: Option<String>,
    /// Hidden master-password setup/unlock dialog.
    credential_dialog: Option<CredentialDialogState>,
    /// Number of profile views exposed by the core profile catalog adapter.
    profile_catalog_count: usize,
    /// Redacted profile views exposed by the core profile catalog adapter.
    profile_catalog_entries: Vec<ConnectionManagerProfileEntry>,
    /// Redacted profile catalog loading failure, if the profile store is unavailable.
    profile_catalog_error: Option<String>,
    capability_browser: Option<CapabilityBrowserState>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CredentialDialogMode {
    Unlock,
    Reencrypt,
}

#[derive(Debug, Clone)]
struct CredentialDialogState {
    mode: CredentialDialogMode,
    active_field: usize,
    password: String,
    confirm_password: String,
    message: Option<String>,
}

#[derive(Debug, Clone)]
struct CapabilityBrowserItem {
    qualified_id: String,
    description: String,
    risk: String,
    destructive: bool,
    streaming: bool,
    supports_dry_run: bool,
}

#[derive(Debug, Clone)]
struct CapabilityBrowserState {
    plugin_id: String,
    profile_ref: String,
    name: String,
    selected: usize,
    loading: bool,
    capabilities: Vec<CapabilityBrowserItem>,
    message: Option<String>,
}

impl CredentialDialogState {
    fn unlock() -> Self {
        Self {
            mode: CredentialDialogMode::Unlock,
            active_field: 0,
            password: String::new(),
            confirm_password: String::new(),
            message: None,
        }
    }

    fn reencrypt() -> Self {
        Self {
            mode: CredentialDialogMode::Reencrypt,
            active_field: 0,
            password: String::new(),
            confirm_password: String::new(),
            message: None,
        }
    }

    fn title(&self) -> &'static str {
        match self.mode {
            CredentialDialogMode::Unlock => " Unlock Master Password ",
            CredentialDialogMode::Reencrypt => " Protect Saved Credentials ",
        }
    }

    fn field_count(&self) -> usize {
        match self.mode {
            CredentialDialogMode::Unlock => 1,
            CredentialDialogMode::Reencrypt => 2,
        }
    }

    fn field_label(&self, index: usize) -> &'static str {
        match (self.mode, index) {
            (CredentialDialogMode::Unlock, 0) => "Master password",
            (CredentialDialogMode::Reencrypt, 0) => "New master password",
            (CredentialDialogMode::Reencrypt, 1) => "Confirm password",
            _ => "",
        }
    }

    fn field_value(&self, index: usize) -> &str {
        match (self.mode, index) {
            (CredentialDialogMode::Unlock, 0) | (CredentialDialogMode::Reencrypt, 0) => {
                &self.password
            }
            (CredentialDialogMode::Reencrypt, 1) => &self.confirm_password,
            _ => "",
        }
    }

    fn field_value_mut(&mut self, index: usize) -> Option<&mut String> {
        match (self.mode, index) {
            (CredentialDialogMode::Unlock, 0) | (CredentialDialogMode::Reencrypt, 0) => {
                Some(&mut self.password)
            }
            (CredentialDialogMode::Reencrypt, 1) => Some(&mut self.confirm_password),
            _ => None,
        }
    }

    fn push_char(&mut self, c: char) {
        if c.is_control() {
            return;
        }
        if let Some(value) = self.field_value_mut(self.active_field) {
            value.push(c);
        }
    }

    fn push_str(&mut self, text: &str) {
        for c in text.chars() {
            self.push_char(c);
        }
    }

    fn backspace(&mut self) {
        if let Some(value) = self.field_value_mut(self.active_field) {
            value.pop();
        }
    }

    fn next_field(&mut self) {
        self.active_field = (self.active_field + 1).min(self.field_count().saturating_sub(1));
    }

    fn prev_field(&mut self) {
        self.active_field = self.active_field.saturating_sub(1);
    }
}

impl ConnectionManagerPlugin {
    pub fn new() -> Self {
        Self {
            caps: None,
            connections: Vec::new(),
            selected: 0,
            list_state: ListState::default(),
            status_message: None,
            dialog: None,
            custom_dialog: None,
            confirm_delete: None,
            test_rx: None,
            capability_rx: None,
            dialog_test_rx: None,
            list_area: None,
            help_popup: None,
            type_selector: None,
            search_active: false,
            search_buffer: String::new(),
            filtered_indices: Vec::new(),
            editing_key: None,
            save_pending: None,
            command_buffer: None,
            credential_state: Self::default_credential_state(),
            active_master_password: None,
            credential_dialog: None,
            profile_catalog_count: 0,
            profile_catalog_entries: Vec::new(),
            profile_catalog_error: None,
            capability_browser: None,
        }
    }

    fn default_credential_state() -> CredentialProtectionState {
        CredentialProtectionState::new(
            CredentialProtectionStore::Config,
            CredentialProtectionMode::DefaultPassphrase,
            CredentialMaterialState::Absent,
            MasterPasswordSessionState::NotConfigured,
            CredentialMaterialSummary::default(),
        )
    }

    /// Sort connections by database type group, then by name within each group.
    fn sort_connections(connections: &mut [ConnectionConfig]) {
        connections.sort_by(|a, b| {
            let type_order = |dt: &DatabaseType| -> u8 {
                match dt {
                    DatabaseType::MySQL => 0,
                    DatabaseType::PostgreSQL => 1,
                    DatabaseType::SQLite => 2,
                    DatabaseType::Plugin => 3,
                }
            };
            type_order(&a.db_type)
                .cmp(&type_order(&b.db_type))
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });
    }

    /// Refilter connections based on search buffer.
    fn refilter(&mut self) {
        if self.search_buffer.is_empty() {
            self.filtered_indices = (0..self.connections.len()).collect();
        } else {
            let lower = self.search_buffer.to_lowercase();
            self.filtered_indices = self
                .connections
                .iter()
                .enumerate()
                .filter(|(_, conn)| {
                    conn.name.to_lowercase().contains(&lower)
                        || conn.db_type.as_str().to_lowercase().contains(&lower)
                        || conn
                            .plugin_id
                            .as_deref()
                            .unwrap_or("")
                            .to_lowercase()
                            .contains(&lower)
                })
                .map(|(i, _)| i)
                .collect();
        }
        self.selected = 0;
        self.list_state.select(if self.filtered_indices.is_empty() {
            None
        } else {
            Some(0)
        });
    }

    /// Get real connection index from filtered selection.
    fn selected_real_index(&self) -> Option<usize> {
        self.filtered_indices.get(self.selected).copied()
    }

    /// Build the list of connection types for the dialog.
    fn conn_types(&self) -> Vec<ConnType> {
        let mut types = vec![
            ConnType::builtin("MySQL", DatabaseType::MySQL, 3306, "root"),
            ConnType::builtin("PostgreSQL", DatabaseType::PostgreSQL, 5432, "postgres"),
            ConnType::builtin("SQLite", DatabaseType::SQLite, 0, ""),
            ConnType::plugin("Redis", "redis", 6379, "localhost", ""),
            ConnType::plugin("Email", "email", 993, "imap.gmail.com", ""),
            ConnType::plugin("SSH", "ssh", 22, "localhost", "root"),
            ConnType::plugin("Docker", "docker", 2375, "localhost", ""),
            ConnType::plugin("Kubernetes", "kubernetes", 0, "", ""),
            ConnType::plugin("WebDAV", "webdav", 443, "dav.example.com", ""),
            ConnType::plugin("S3", "s3", 443, "s3.amazonaws.com", ""),
            ConnType::plugin(
                "Elasticsearch",
                "elasticsearch",
                9200,
                "localhost",
                "elastic",
            ),
            ConnType::plugin("MongoDB", "mongodb", 27017, "localhost", ""),
            ConnType::plugin("DuckDB", "duckdb", 0, "", ""),
            ConnType::plugin("Jenkins", "jenkins", 443, "jenkins.example.com", ""),
        ];

        // Dynamically include discovered external process plugins that aren't already listed
        let discovery = voidb_core::discover_process_plugins();
        for candidate in discovery.candidates {
            if candidate.is_effective_available() {
                let id = &candidate.id;
                let already_present = types.iter().any(|ct| {
                    ct.plugin_id.as_deref() == Some(id.as_str())
                        || (ct.db_type == DatabaseType::Plugin && ct.label.eq_ignore_ascii_case(id))
                });
                if !already_present {
                    let label = candidate
                        .name
                        .clone()
                        .unwrap_or_else(|| id.clone());
                    types.push(ConnType::plugin(&label, id, 0, "localhost", ""));
                }
            }
        }

        types
    }

    fn plugin_id_for_connection(conn: &ConnectionConfig) -> Result<String> {
        let plugin_id = match conn.db_type {
            DatabaseType::MySQL => "mysql",
            DatabaseType::PostgreSQL => "postgres",
            DatabaseType::SQLite => "sqlite",
            DatabaseType::Plugin => conn.plugin_id.as_deref().unwrap_or("unknown"),
        };

        if plugin_id == "unknown" {
            Err(anyhow::anyhow!("Unsupported protocol: {}", conn.db_type))
        } else {
            Ok(plugin_id.to_string())
        }
    }

    fn profile_test_guidance(conn: &ConnectionConfig) -> String {
        format!(
            "Save {} first, then press `t` in the profile list or use `voidb-cli profile test {}`.",
            conn.display_name(),
            conn.display_name()
        )
    }

    fn profile_open_guidance(
        conn: &ConnectionConfig,
        plugin_id: &str,
        profile_ref: &str,
    ) -> String {
        format!(
            "Guidance for {}: `voidb-cli profile show {} --plugin {}`; press c for capabilities; plugin TUIs stay under `voidb-cli {} tui --profile {}`.",
            conn.display_name(),
            profile_ref,
            plugin_id,
            plugin_id,
            profile_ref
        )
    }

    /// Get protocol icon
    fn protocol_icon(protocol: &str) -> &'static str {
        match protocol.to_lowercase().as_str() {
            "mysql" | "mariadb" => "🐬",
            "postgres" | "postgresql" => "🐘",
            "sqlite" => "📦",
            "ssh" => "🔐",
            "redis" => "🔴",
            "mongodb" => "🍃",
            "email" => "📧",
            "docker" => "🐳",
            "kubernetes" => "☸",
            "webdav" => "☁",
            "s3" => "🪣",
            "elasticsearch" => "🔍",
            "duckdb" => "🦆",
            "jenkins" => "🧰",
            _ => "🔌",
        }
    }

    /// Save a connection to config.
    ///
    /// If `editing_key` is set, this is an edit operation: the old key entry is
    /// replaced (handles renames). Otherwise it's a new connection: conflict
    /// detection prevents silent overwrites.
    fn save_connection(&mut self, config: ConnectionConfig) -> Result<()> {
        let new_key = config.connection_key();
        let old_key = self.editing_key.take();

        // Load existing config
        let mut app_config = self.load_current_config()?;

        if let Some(ref ok) = old_key {
            // Edit mode: if the key changed, check for conflict with other connections
            if *ok != new_key
                && app_config
                    .connections
                    .iter()
                    .any(|c| c.connection_key() == new_key)
            {
                // Restore editing_key so the user can retry
                self.editing_key = old_key;
                return Err(anyhow::anyhow!(
                    "A {} connection named '{}' already exists",
                    config.effective_plugin_id(),
                    config.name
                ));
            }
            app_config.replace_connection(ok, config.clone());
        } else {
            // New connection: check for conflict
            if app_config
                .connections
                .iter()
                .any(|c| c.connection_key() == new_key)
            {
                return Err(anyhow::anyhow!(
                    "A {} connection named '{}' already exists",
                    config.effective_plugin_id(),
                    config.name
                ));
            }
            app_config.upsert_connection(config.clone());
        }

        // Save to disk (this clones + encrypts internally; our config is unchanged)
        self.save_current_config(&app_config)?;

        // Use the config we already have — it's the decrypted version
        let saved_connection = config;

        // Update in-memory registry with the decrypted version
        if let Some(caps) = &self.caps {
            let mut registry = caps
                .connections
                .try_write()
                .map_err(|e| anyhow::anyhow!("Failed to write connections: {}", e))?;
            if let Some(ref ok) = old_key {
                // Edit: remove old key, insert new
                registry.replace(ok, saved_connection);
            } else {
                registry.upsert(saved_connection);
            }
        }

        self.refresh_credential_state();

        Ok(())
    }

    /// Delete a connection from config
    fn delete_connection(&mut self, index: usize) -> Result<()> {
        if index >= self.connections.len() {
            return Err(anyhow::anyhow!("Invalid connection index"));
        }

        let conn_key = self.connections[index].connection_key();

        let mut app_config = self.load_current_config()?;
        app_config.remove_connection(&conn_key);
        self.save_current_config(&app_config)?;

        if let Some(caps) = &self.caps {
            let mut registry = caps
                .connections
                .try_write()
                .map_err(|e| anyhow::anyhow!("Failed to write connections: {}", e))?;
            registry.delete(&conn_key);
        }

        self.connections.remove(index);
        if self.selected >= self.connections.len() && self.selected > 0 {
            self.selected = self.connections.len() - 1;
        }
        self.list_state.select(if self.connections.is_empty() {
            None
        } else {
            Some(self.selected)
        });

        self.refresh_credential_state();

        Ok(())
    }

    fn load_current_config(&self) -> Result<AppConfig> {
        if let Some(password) = self.active_master_password.as_deref() {
            Ok(AppConfig::load_with_password(Some(password))?)
        } else {
            Ok(AppConfig::load()?)
        }
    }

    fn save_current_config(&self, app_config: &AppConfig) -> Result<()> {
        if let Some(password) = self.active_master_password.as_deref() {
            Ok(app_config.save_with_password(Some(password))?)
        } else {
            Ok(app_config.save()?)
        }
    }

    fn refresh_connections_from_config(&mut self, app_config: &AppConfig) -> Result<()> {
        let mut connections = app_config.connections.clone();
        Self::sort_connections(&mut connections);

        if let Some(caps) = &self.caps {
            let mut registry = caps
                .connections
                .try_write()
                .map_err(|e| anyhow::anyhow!("Failed to write connections: {}", e))?;
            for id in registry.ids() {
                registry.delete(&id);
            }
            for conn in &connections {
                registry.upsert(conn.clone());
            }
        }

        self.connections = connections;
        self.refilter();
        self.refresh_profile_catalog();
        Ok(())
    }

    fn refresh_profile_catalog(&mut self) {
        match LocalProfileStore::default_store()
            .and_then(|store| store.connection_manager_catalog(&self.connections))
        {
            Ok(catalog) => {
                self.profile_catalog_count = catalog.entries.len();
                self.profile_catalog_entries = catalog.entries;
                self.profile_catalog_error = None;
            }
            Err(error) => {
                self.profile_catalog_count = 0;
                self.profile_catalog_entries.clear();
                self.profile_catalog_error =
                    Some(format!("profile catalog unavailable: {}", error));
            }
        }
    }

    fn profile_entry_for_connection(
        &self,
        conn: &ConnectionConfig,
    ) -> Option<&ConnectionManagerProfileEntry> {
        let connection_key = conn.connection_key();
        let plugin_id = conn.effective_plugin_id();

        self.profile_catalog_entries
            .iter()
            .find(|entry| entry.legacy_connection_key.as_deref() == Some(connection_key.as_str()))
            .or_else(|| {
                self.profile_catalog_entries
                    .iter()
                    .find(|entry| entry.plugin_id == plugin_id && entry.name == conn.name)
            })
    }

    fn profile_entry_summary(entry: Option<&ConnectionManagerProfileEntry>) -> String {
        let Some(entry) = entry else {
            return "profile: unavailable".to_string();
        };

        let source = match entry.source {
            ConnectionManagerProfileSource::StoredProfile => "stored",
            ConnectionManagerProfileSource::LegacyConfigFallback => "legacy",
        };
        format!(
            "profile: {} | {} cred ref{}",
            source,
            entry.credential_ref_count,
            plural(entry.credential_ref_count)
        )
    }

    fn credential_state_from_config(&self, app_config: &AppConfig) -> CredentialProtectionState {
        let master_password = if app_config.requires_master_password() {
            MasterPasswordSessionState::Unlocked
        } else {
            MasterPasswordSessionState::NotConfigured
        };
        app_config.credential_protection_state(master_password)
    }

    fn locked_credential_state_from_raw() -> Result<CredentialProtectionState> {
        let path = AppConfig::config_path()?;
        let raw = AppConfig::load_raw_from_path(&path)?;
        let mut plugins = raw
            .connections
            .iter()
            .map(|conn| conn.effective_plugin_id().to_string())
            .collect::<Vec<_>>();
        plugins.sort();
        plugins.dedup();

        Ok(CredentialProtectionState::new(
            CredentialProtectionStore::Config,
            raw.credential_protection_mode(),
            if raw.connections.is_empty() {
                CredentialMaterialState::Absent
            } else {
                CredentialMaterialState::Unknown
            },
            MasterPasswordSessionState::Locked,
            CredentialMaterialSummary {
                credential_owner_count: raw.connections.len(),
                credential_item_count: 0,
                plugins,
            },
        ))
    }

    fn refresh_credential_state(&mut self) {
        self.credential_state = match self.load_current_config() {
            Ok(config) => self.credential_state_from_config(&config),
            Err(_) => Self::locked_credential_state_from_raw()
                .unwrap_or_else(|_| Self::default_credential_state()),
        };
    }

    fn credential_status_text(state: &CredentialProtectionState) -> String {
        if state.requires_reencryption() {
            return format!(
                "Credentials: weak default passphrase ({} item{} in {} connection{}). m: Protect",
                state.summary.credential_item_count,
                plural(state.summary.credential_item_count),
                state.summary.credential_owner_count,
                plural(state.summary.credential_owner_count)
            );
        }

        match (state.mode, state.master_password, state.material) {
            (CredentialProtectionMode::UserPassphrase, MasterPasswordSessionState::Locked, _) => {
                "Credentials: user passphrase locked. m: Unlock".to_string()
            }
            (CredentialProtectionMode::UserPassphrase, MasterPasswordSessionState::Unlocked, _) => {
                "Credentials: user passphrase unlocked. m: Re-encrypt".to_string()
            }
            (CredentialProtectionMode::UserPassphrase, _, _) => {
                "Credentials: user passphrase protected. m: Unlock".to_string()
            }
            (CredentialProtectionMode::Migrated, _, _) => {
                "Credentials: profile refs only. m: Set master password".to_string()
            }
            (_, _, CredentialMaterialState::Absent) => {
                "Credentials: no saved secrets. m: Set master password".to_string()
            }
            (_, _, CredentialMaterialState::Unknown) => {
                "Credentials: protection state locked or unknown. m: Unlock".to_string()
            }
            _ => "Credentials: default passphrase, no secret material. m: Set master password"
                .to_string(),
        }
    }

    fn open_credential_dialog(&mut self) {
        self.refresh_credential_state();
        self.credential_dialog = if self.credential_state.mode
            == CredentialProtectionMode::UserPassphrase
            && self.active_master_password.is_none()
        {
            Some(CredentialDialogState::unlock())
        } else {
            Some(CredentialDialogState::reencrypt())
        };
        self.status_message = None;
    }

    fn handle_credential_dialog_key(&mut self, code: KeyCode) {
        match code {
            KeyCode::Esc => {
                self.credential_dialog = None;
                self.status_message = Some("Credential action cancelled".to_string());
            }
            KeyCode::Tab | KeyCode::Down => {
                if let Some(dialog) = &mut self.credential_dialog {
                    dialog.next_field();
                }
            }
            KeyCode::BackTab | KeyCode::Up => {
                if let Some(dialog) = &mut self.credential_dialog {
                    dialog.prev_field();
                }
            }
            KeyCode::Backspace => {
                if let Some(dialog) = &mut self.credential_dialog {
                    dialog.backspace();
                }
            }
            KeyCode::Enter => {
                let should_submit = self
                    .credential_dialog
                    .as_ref()
                    .is_some_and(|dialog| dialog.active_field + 1 >= dialog.field_count());
                if should_submit {
                    self.submit_credential_dialog();
                } else if let Some(dialog) = &mut self.credential_dialog {
                    dialog.next_field();
                }
            }
            KeyCode::Char(c) => {
                if let Some(dialog) = &mut self.credential_dialog {
                    dialog.push_char(c);
                }
            }
            _ => {}
        }
    }

    fn submit_credential_dialog(&mut self) {
        let Some(mut dialog) = self.credential_dialog.take() else {
            return;
        };

        let result = match dialog.mode {
            CredentialDialogMode::Unlock => self.unlock_master_password(dialog.password.clone()),
            CredentialDialogMode::Reencrypt => {
                if dialog.password.is_empty() {
                    Err(anyhow::anyhow!("Master password cannot be empty"))
                } else if dialog.password != dialog.confirm_password {
                    Err(anyhow::anyhow!(
                        "Master password confirmation does not match"
                    ))
                } else {
                    self.reencrypt_with_master_password(dialog.password.clone())
                }
            }
        };

        match result {
            Ok(message) => {
                self.credential_dialog = None;
                self.status_message = Some(message);
            }
            Err(error) => {
                dialog.message = Some(format!("FAIL: {}", error));
                self.credential_dialog = Some(dialog);
            }
        }
    }

    fn unlock_master_password(&mut self, password: String) -> Result<String> {
        let app_config = AppConfig::load_with_password(Some(&password))?;
        self.active_master_password = Some(password);
        self.credential_state =
            app_config.credential_protection_state(MasterPasswordSessionState::Unlocked);
        self.refresh_connections_from_config(&app_config)?;
        Ok(format!(
            "Master password unlocked for this session; {} connection{} loaded",
            self.connections.len(),
            plural(self.connections.len())
        ))
    }

    fn reencrypt_with_master_password(&mut self, new_password: String) -> Result<String> {
        let result = AppConfig::reencrypt_config_file(
            self.active_master_password.as_deref(),
            new_password.as_str(),
        )?;
        let app_config = AppConfig::load_with_password(Some(&new_password))?;
        self.active_master_password = Some(new_password);
        self.credential_state =
            app_config.credential_protection_state(MasterPasswordSessionState::Unlocked);
        self.refresh_connections_from_config(&app_config)?;
        Ok(format!(
            "Credentials protected with user passphrase; {} item{} across {} connection{} re-encrypted",
            result.credential_summary.credential_item_count,
            plural(result.credential_summary.credential_item_count),
            result.credential_summary.credential_owner_count,
            plural(result.credential_summary.credential_owner_count)
        ))
    }

    /// Test the selected connection asynchronously
    fn test_connection(&mut self, index: usize) {
        if let Some(conn) = self.connections.get(index).cloned() {
            let Some(entry) = self.profile_entry_for_connection(&conn).cloned() else {
                self.test_rx = None;
                self.status_message = Some(format!(
                    "No profile route is available for {}; refresh or migrate profiles first",
                    conn.display_name()
                ));
                return;
            };

            if !entry.supports_test_route {
                self.test_rx = None;
                self.status_message = Some(format!(
                    "Profile '{}' has no local connection config to test",
                    entry.name
                ));
                return;
            }

            let (tx, rx) = std::sync::mpsc::channel();
            self.test_rx = Some(Arc::new(std::sync::Mutex::new(rx)));
            self.status_message = Some(format!(
                "Testing {} profile '{}'...",
                entry.plugin_id, entry.name
            ));

            let profile_ref = format!("id:{}", entry.profile_id);
            let plugin_id = entry.plugin_id.clone();
            let name = entry.name.clone();
            let render = self.caps.as_ref().map(|caps| caps.tabs.clone());

            std::thread::spawn(move || {
                let result = run_profile_test_command(&profile_ref, &plugin_id, &name);
                let _ = tx.send(result);
                if let Some(render) = render {
                    let _ = render.request_render();
                }
            });
        }
    }

    /// Test a connection config from dialog (returns receiver for async result)
    fn test_connection_config(&self, conn: ConnectionConfig) -> TestResultReceiver {
        let (tx, rx) = std::sync::mpsc::channel();
        let _ = tx.send(Err(format!("FAIL: {}", Self::profile_test_guidance(&conn))));
        Arc::new(std::sync::Mutex::new(rx))
    }

    /// Show CLI/capability guidance for the selected connection.
    fn open_selected_connection(&mut self) -> Result<()> {
        if let Some(real_idx) = self.selected_real_index()
            && let Some(conn) = self.connections.get(real_idx)
        {
            let plugin_id = Self::plugin_id_for_connection(conn)?;
            let profile_ref = self
                .profile_entry_for_connection(conn)
                .map(|entry| format!("id:{}", entry.profile_id))
                .unwrap_or_else(|| conn.display_name());
            self.status_message = Some(Self::profile_open_guidance(conn, &plugin_id, &profile_ref));
        }
        Ok(())
    }

    fn selected_profile_entry(&self) -> Option<ConnectionManagerProfileEntry> {
        let real_idx = self.selected_real_index()?;
        let conn = self.connections.get(real_idx)?;
        self.profile_entry_for_connection(conn).cloned()
    }

    fn open_capability_browser(&mut self) {
        let Some(entry) = self.selected_profile_entry() else {
            self.status_message =
                Some("No profile metadata is available for capability discovery".to_string());
            return;
        };

        let profile_ref = format!("id:{}", entry.profile_id);
        let plugin_id = entry.plugin_id.clone();
        let name = entry.name.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let render = self.caps.as_ref().map(|caps| caps.tabs.clone());

        self.capability_rx = Some(Arc::new(std::sync::Mutex::new(rx)));
        self.capability_browser = Some(CapabilityBrowserState {
            plugin_id: plugin_id.clone(),
            profile_ref,
            name,
            selected: 0,
            loading: true,
            capabilities: Vec::new(),
            message: Some("Loading capabilities...".to_string()),
        });

        std::thread::spawn(move || {
            let result = run_capability_list_command(&plugin_id);
            let _ = tx.send(result);
            if let Some(render) = render {
                let _ = render.request_render();
            }
        });
    }

    fn handle_capability_browser_key(&mut self, code: KeyCode) {
        let Some(browser) = &mut self.capability_browser else {
            return;
        };

        match code {
            KeyCode::Esc | KeyCode::Char('q') => {
                self.capability_browser = None;
                self.capability_rx = None;
                self.status_message = Some("Capability browser closed".to_string());
            }
            KeyCode::Char('j') | KeyCode::Down => {
                if !browser.capabilities.is_empty() {
                    browser.selected = (browser.selected + 1).min(browser.capabilities.len() - 1);
                }
            }
            KeyCode::Char('k') | KeyCode::Up => {
                browser.selected = browser.selected.saturating_sub(1);
            }
            KeyCode::Enter => {
                if let Some(capability) = browser.capabilities.get(browser.selected) {
                    self.status_message = Some(format!(
                        "Use `voidb-cli invoke describe {} --format json`; run with `voidb-cli invoke run {} --profile {} --input-json '{{}}' --format json`",
                        capability.qualified_id, capability.qualified_id, browser.profile_ref
                    ));
                }
            }
            KeyCode::Char('t') => {
                self.status_message = Some(format!(
                    "Plugin TUI is plugin-owned only: `voidb-cli {} tui --profile {}`",
                    browser.plugin_id, browser.profile_ref
                ));
            }
            _ => {}
        }
    }
}

impl Plugin for ConnectionManagerPlugin {
    fn id(&self) -> &str {
        "connection-manager"
    }

    fn name(&self) -> &str {
        "Connection Manager"
    }

    fn init(&mut self, caps: ShellCapabilities) -> Result<()> {
        // Load connections from registry
        let mut connections = caps
            .connections
            .try_read()
            .map_err(|e| anyhow::anyhow!("Failed to read connections: {}", e))?
            .list();
        Self::sort_connections(&mut connections);
        self.connections = connections;
        self.caps = Some(caps);
        self.refresh_credential_state();
        self.refresh_profile_catalog();

        // Initialize filtered indices and list state
        self.refilter();

        Ok(())
    }

    fn update(&mut self, frame: &mut Frame, area: Rect, event: Option<Event>) -> Result<()> {
        // Check for async test result
        let mut test_result = None;
        if let Some(rx) = &self.test_rx
            && let Ok(receiver) = rx.lock()
            && let Ok(result) = receiver.try_recv()
        {
            test_result = Some(result);
        }
        if let Some(result) = test_result {
            match result {
                Ok(msg) => self.status_message = Some(format!("OK: {}", msg)),
                Err(msg) => self.status_message = Some(format!("FAIL: {}", msg)),
            }
            self.test_rx = None;
        }

        let mut capability_result = None;
        if let Some(rx) = &self.capability_rx
            && let Ok(receiver) = rx.lock()
            && let Ok(result) = receiver.try_recv()
        {
            capability_result = Some(result);
        }
        if let Some(result) = capability_result {
            if let Some(browser) = &mut self.capability_browser {
                browser.loading = false;
                browser.selected = 0;
                match result {
                    Ok(capabilities) => {
                        browser.message = Some(format!(
                            "{} capabilit{} available",
                            capabilities.len(),
                            if capabilities.len() == 1 { "y" } else { "ies" }
                        ));
                        browser.capabilities = capabilities;
                    }
                    Err(message) => {
                        browser.message = Some(message);
                        browser.capabilities.clear();
                    }
                }
            }
            self.capability_rx = None;
        }

        // Check for dialog test result
        let mut dialog_test_result = None;
        if let Some(rx) = &self.dialog_test_rx
            && let Ok(receiver) = rx.lock()
            && let Ok(result) = receiver.try_recv()
        {
            dialog_test_result = Some(result);
        }
        if let Some(result) = dialog_test_result {
            let msg = match result {
                Ok(msg) => msg,
                Err(msg) => msg,
            };
            if let Some(custom) = &mut self.custom_dialog {
                custom.set_status_message(Some(msg));
            }
            self.dialog_test_rx = None;
        }

        // Execute deferred save (triggered by request_render after "Saving..." frame)
        if let Some(config) = self.save_pending.take() {
            match self.save_connection(config) {
                Ok(()) => {
                    self.custom_dialog = None;
                    self.dialog = None;
                    self.dialog_test_rx = None;
                    self.search_active = false;
                    self.search_buffer.clear();
                    self.status_message = Some("Connection saved successfully!".to_string());
                    let loaded = self
                        .caps
                        .as_ref()
                        .and_then(|c| c.connections.try_read().ok())
                        .map(|r| r.list());
                    if let Some(mut conns) = loaded {
                        Self::sort_connections(&mut conns);
                        self.connections = conns;
                        self.refilter();
                        self.refresh_profile_catalog();
                    }
                }
                Err(e) => {
                    self.status_message = Some(format!("Failed to save: {}", e));
                    if let Some(custom) = &mut self.custom_dialog {
                        custom.set_status_message(Some(format!("FAIL: {}", e)));
                    }
                }
            }
        }

        // Handle events
        if let Some(event) = event {
            // Handle mouse events
            if let Event::Mouse(mouse) = &event {
                match mouse.kind {
                    MouseEventKind::Down(MouseButton::Left) => {
                        if let Some(list_area) = self.list_area
                            && mouse.column >= list_area.x
                            && mouse.column < list_area.x + list_area.width
                            && mouse.row >= list_area.y
                            && mouse.row < list_area.y + list_area.height
                        {
                            // Map click to list item (account for border)
                            let inner_y = mouse.row.saturating_sub(list_area.y + 1);
                            let clicked = inner_y as usize;
                            if clicked < self.filtered_indices.len() {
                                self.selected = clicked;
                                self.list_state.select(Some(self.selected));
                            }
                        }
                    }
                    MouseEventKind::ScrollDown => {
                        if !self.filtered_indices.is_empty() {
                            self.selected =
                                (self.selected + 1).min(self.filtered_indices.len() - 1);
                            self.list_state.select(Some(self.selected));
                        }
                    }
                    MouseEventKind::ScrollUp => {
                        self.selected = self.selected.saturating_sub(1);
                        self.list_state.select(Some(self.selected));
                    }
                    MouseEventKind::Down(MouseButton::Middle) => {
                        // Middle click shows CLI guidance for the selected profile.
                        if let Some(ri) = self.selected_real_index()
                            && let Some(conn) = self.connections.get(ri)
                        {
                            self.status_message =
                                Some(format!("Guidance for {}...", conn.display_name()));
                        }
                        if let Err(e) = self.open_selected_connection() {
                            self.status_message = Some(format!("Failed: {}", e));
                        }
                    }
                    _ => {}
                }
            }

            if let Event::Paste(text) = &event
                && let Some(dialog) = &mut self.credential_dialog
            {
                dialog.push_str(text);
            } else
            // Forward paste events to active custom dialog (outside Key guard)
            if let Event::Paste(_) = &event {
                if let Some(custom) = &mut self.custom_dialog {
                    match custom.handle_event(event.clone()) {
                        DialogAction::Continue => {}
                        DialogAction::Save => match custom.build_config() {
                            Ok(config) => {
                                custom.set_status_message(Some("Saving...".to_string()));
                                self.save_pending = Some(config);
                                if let Some(caps) = &self.caps {
                                    let _ = caps.tabs.request_render();
                                }
                            }
                            Err(e) => {
                                custom.set_status_message(Some(format!("FAIL: {}", e)));
                            }
                        },
                        DialogAction::TestConnection => match custom.build_config() {
                            Ok(config) => {
                                custom
                                    .set_status_message(Some("Testing connection...".to_string()));
                                self.dialog_test_rx = Some(self.test_connection_config(config));
                            }
                            Err(e) => {
                                custom.set_status_message(Some(format!("FAIL: {}", e)));
                            }
                        },
                        DialogAction::Cancel => {
                            self.custom_dialog = None;
                            self.dialog_test_rx = None;
                            self.editing_key = None;
                            self.status_message = Some("Connection dialog cancelled".to_string());
                        }
                    }
                }
                // Paste handled, skip the Key event block below
            } else if let Event::Key(KeyEvent {
                code, modifiers, ..
            }) = event
            {
                if self.capability_browser.is_some() {
                    self.handle_capability_browser_key(code);
                } else
                // Help popup intercepts events
                if self.help_popup.is_some() {
                    match code {
                        KeyCode::Esc | KeyCode::Char('q') | KeyCode::Char('?') => {
                            self.help_popup = None
                        }
                        KeyCode::Char('j') | KeyCode::Down => {
                            if let Some(h) = &mut self.help_popup {
                                h.scroll_down(1);
                            }
                        }
                        KeyCode::Char('k') | KeyCode::Up => {
                            if let Some(h) = &mut self.help_popup {
                                h.scroll_up(1);
                            }
                        }
                        KeyCode::PageDown => {
                            if let Some(h) = &mut self.help_popup {
                                h.scroll_down(10);
                            }
                        }
                        KeyCode::PageUp => {
                            if let Some(h) = &mut self.help_popup {
                                h.scroll_up(10);
                            }
                        }
                        _ => {}
                    }
                } else
                // If credential dialog is open, keep all soft-global characters local.
                if self.credential_dialog.is_some() {
                    self.handle_credential_dialog_key(code);
                } else
                // If type selector is open, handle type selector events
                if let Some((types, selected_idx)) = &mut self.type_selector {
                    match code {
                        KeyCode::Esc => {
                            self.type_selector = None;
                            self.status_message = Some("Type selection cancelled".to_string());
                        }
                        KeyCode::Up | KeyCode::Char('k') => {
                            if *selected_idx > 0 {
                                *selected_idx -= 1;
                            }
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            if *selected_idx < types.len() - 1 {
                                *selected_idx += 1;
                            }
                        }
                        KeyCode::Enter => {
                            let conn_type = types[*selected_idx].clone();
                            self.type_selector = None;

                            // Try to create custom dialog from plugin
                            let custom_dialog = if let Some(ref plugin_id) = conn_type.plugin_id {
                                self.caps.as_ref().and_then(|c| {
                                    c.plugin_registry.create_connection_dialog(plugin_id, None)
                                })
                            } else {
                                // For built-in types (MySQL, PostgreSQL, SQLite)
                                let plugin_id = conn_type.db_type.protocol_name();
                                self.caps.as_ref().and_then(|c| {
                                    c.plugin_registry.create_connection_dialog(plugin_id, None)
                                })
                            };

                            if let Some(custom) = custom_dialog {
                                self.custom_dialog = Some(custom);
                            } else {
                                self.dialog = Some(ConnectionDialog::new_for_type(
                                    self.conn_types(),
                                    &conn_type,
                                ));
                            }
                        }
                        _ => {}
                    }
                } else
                // If custom dialog is open, handle custom dialog events
                if let Some(custom) = &mut self.custom_dialog {
                    match custom.handle_event(event.clone()) {
                        DialogAction::Continue => {
                            // Keep dialog open, do nothing
                        }
                        DialogAction::Save => match custom.build_config() {
                            Ok(config) => {
                                custom.set_status_message(Some("Saving...".to_string()));
                                self.save_pending = Some(config);
                                if let Some(caps) = &self.caps {
                                    let _ = caps.tabs.request_render();
                                }
                            }
                            Err(e) => {
                                custom.set_status_message(Some(format!("FAIL: {}", e)));
                            }
                        },
                        DialogAction::TestConnection => match custom.build_config() {
                            Ok(config) => {
                                custom
                                    .set_status_message(Some("Testing connection...".to_string()));
                                self.dialog_test_rx = Some(self.test_connection_config(config));
                            }
                            Err(e) => {
                                custom.set_status_message(Some(format!("FAIL: {}", e)));
                            }
                        },
                        DialogAction::Cancel => {
                            self.custom_dialog = None;
                            self.dialog_test_rx = None;
                            self.editing_key = None;
                            self.status_message = Some("Connection dialog cancelled".to_string());
                        }
                    }
                } else
                // If dialog is open, handle dialog events
                if let Some(dialog) = &mut self.dialog {
                    match code {
                        KeyCode::Esc => {
                            self.dialog = None;
                            self.editing_key = None;
                            self.status_message = Some("Connection dialog cancelled".to_string());
                        }
                        KeyCode::Enter => match dialog.build_config() {
                            Ok(config) => {
                                self.status_message = Some("Saving...".to_string());
                                self.save_pending = Some(config);
                                if let Some(caps) = &self.caps {
                                    let _ = caps.tabs.request_render();
                                }
                            }
                            Err(e) => {
                                self.status_message = Some(format!("Validation error: {}", e));
                            }
                        },
                        KeyCode::Tab => {
                            dialog.next_field();
                        }
                        KeyCode::BackTab => {
                            dialog.prev_field();
                        }
                        KeyCode::Backspace => {
                            dialog.delete_char();
                        }
                        KeyCode::Left if dialog.is_on_db_type_field() => {
                            dialog.cycle_db_type_prev();
                        }
                        KeyCode::Right if dialog.is_on_db_type_field() => {
                            dialog.cycle_db_type_next();
                        }
                        KeyCode::Char(c) => {
                            dialog.add_char(c);
                        }
                        _ => {}
                    }
                } else if self.confirm_delete.is_some() {
                    // Delete confirmation mode
                    match code {
                        KeyCode::Char('y') | KeyCode::Char('Y') => {
                            let idx = self.confirm_delete.take().unwrap();
                            match self.delete_connection(idx) {
                                Ok(_) => {
                                    self.status_message = Some("Connection deleted".to_string());
                                    self.refilter();
                                    self.refresh_profile_catalog();
                                }
                                Err(e) => {
                                    self.status_message = Some(format!("Delete failed: {}", e))
                                }
                            }
                        }
                        _ => {
                            self.confirm_delete = None;
                            self.status_message = Some("Delete cancelled".to_string());
                        }
                    }
                } else if self.search_active {
                    // Search mode: all chars go to buffer, special keys for navigation
                    match code {
                        KeyCode::Esc => {
                            self.search_active = false;
                            self.search_buffer.clear();
                            self.refilter();
                        }
                        KeyCode::Backspace => {
                            self.search_buffer.pop();
                            self.refilter();
                        }
                        KeyCode::Up => {
                            self.selected = self.selected.saturating_sub(1);
                            self.list_state.select(if self.filtered_indices.is_empty() {
                                None
                            } else {
                                Some(self.selected)
                            });
                        }
                        KeyCode::Down => {
                            if !self.filtered_indices.is_empty() {
                                self.selected =
                                    (self.selected + 1).min(self.filtered_indices.len() - 1);
                                self.list_state.select(Some(self.selected));
                            }
                        }
                        KeyCode::Enter => {
                            if let Some(ri) = self.selected_real_index() {
                                if let Some(conn) = self.connections.get(ri) {
                                    self.status_message =
                                        Some(format!("Guidance for {}...", conn.display_name()));
                                }
                                if let Err(e) = self.open_selected_connection() {
                                    self.status_message = Some(format!("Failed: {}", e));
                                }
                            }
                        }
                        KeyCode::Char(c) => {
                            self.search_buffer.push(c);
                            self.refilter();
                        }
                        _ => {}
                    }
                } else if self.command_buffer.is_some() {
                    // Command mode (vim-style :commands)
                    match code {
                        KeyCode::Esc => {
                            self.command_buffer = None;
                            self.status_message = None;
                        }
                        KeyCode::Backspace => {
                            let buf = self.command_buffer.as_mut().unwrap();
                            buf.pop();
                            if buf.is_empty() {
                                self.command_buffer = None;
                            }
                        }
                        KeyCode::Enter => {
                            let cmd = self.command_buffer.take().unwrap();
                            let cmd = cmd.trim();
                            match cmd {
                                "q" | "quit" => {
                                    if let Some(caps) = &self.caps {
                                        let _ = caps.tabs.quit();
                                    }
                                }
                                _ => {
                                    self.status_message = Some(format!("Unknown command: {}", cmd));
                                }
                            }
                        }
                        KeyCode::Char(c) => {
                            self.command_buffer.as_mut().unwrap().push(c);
                        }
                        _ => {}
                    }
                } else {
                    // Normal mode
                    match code {
                        KeyCode::Char('j') | KeyCode::Down => {
                            if !self.filtered_indices.is_empty() {
                                self.selected =
                                    (self.selected + 1).min(self.filtered_indices.len() - 1);
                                self.list_state.select(Some(self.selected));
                            }
                        }
                        KeyCode::Char('k') | KeyCode::Up => {
                            self.selected = self.selected.saturating_sub(1);
                            self.list_state.select(Some(self.selected));
                        }
                        KeyCode::Enter => {
                            if let Some(ri) = self.selected_real_index()
                                && let Some(conn) = self.connections.get(ri)
                            {
                                self.status_message =
                                    Some(format!("Guidance for {}...", conn.display_name()));
                            }
                            if let Err(e) = self.open_selected_connection() {
                                self.status_message = Some(format!("Failed: {}", e));
                            }
                        }
                        KeyCode::Char('q') if modifiers.contains(KeyModifiers::CONTROL) => {
                            // Let VoidB handle Ctrl+Q
                        }
                        KeyCode::Char('/') => {
                            self.search_active = true;
                            self.search_buffer.clear();
                            self.status_message = None;
                        }
                        KeyCode::Char(':') => {
                            self.command_buffer = Some(String::new());
                            self.status_message = None;
                        }
                        KeyCode::Char('n') => {
                            // Show type selector first
                            self.type_selector = Some((self.conn_types(), 0));
                            self.status_message = None;
                        }
                        KeyCode::Char('d') => {
                            if let Some(real_idx) = self.selected_real_index() {
                                let name = self.connections[real_idx].display_name();
                                self.confirm_delete = Some(real_idx);
                                self.status_message = Some(format!(
                                    "Delete '{}'? Press 'y' to confirm, any other key to cancel",
                                    name
                                ));
                            }
                        }
                        KeyCode::Char('e') => {
                            if let Some(real_idx) = self.selected_real_index() {
                                let conn = self.connections[real_idx].clone();
                                // Track the original key for rename detection
                                self.editing_key = Some(conn.connection_key());
                                // Try to create custom dialog from plugin
                                let custom_dialog = if let Some(plugin_id) = &conn.plugin_id {
                                    self.caps.as_ref().and_then(|c| {
                                        c.plugin_registry
                                            .create_connection_dialog(plugin_id, Some(&conn))
                                    })
                                } else {
                                    None
                                };

                                if let Some(custom) = custom_dialog {
                                    self.custom_dialog = Some(custom);
                                } else {
                                    self.dialog = Some(ConnectionDialog::from_config(
                                        &conn,
                                        self.conn_types(),
                                    ));
                                }
                                self.status_message = None;
                            }
                        }
                        KeyCode::Char('t') => {
                            if let Some(real_idx) = self.selected_real_index() {
                                self.test_connection(real_idx);
                            } else {
                                self.status_message = Some("No connection selected".to_string());
                            }
                        }
                        KeyCode::Char('c') => {
                            self.open_capability_browser();
                        }
                        KeyCode::Char('m') => {
                            self.open_credential_dialog();
                        }
                        KeyCode::Char('?') => {
                            self.help_popup = Some(HelpPopup::new(vec![
                                HelpSection {
                                    title: "Connection List",
                                    entries: vec![
                                        HelpEntry {
                                            key: "j / ↓",
                                            desc: "Move down",
                                        },
                                        HelpEntry {
                                            key: "k / ↑",
                                            desc: "Move up",
                                        },
                                        HelpEntry {
                                            key: "Enter",
                                            desc: "Show CLI guidance",
                                        },
                                        HelpEntry {
                                            key: "/",
                                            desc: "Search connections",
                                        },
                                        HelpEntry {
                                            key: "n",
                                            desc: "New connection",
                                        },
                                        HelpEntry {
                                            key: "e",
                                            desc: "Edit connection",
                                        },
                                        HelpEntry {
                                            key: "d",
                                            desc: "Delete connection",
                                        },
                                        HelpEntry {
                                            key: "t",
                                            desc: "Test connection",
                                        },
                                        HelpEntry {
                                            key: "c",
                                            desc: "Capability browser",
                                        },
                                        HelpEntry {
                                            key: "m",
                                            desc: "Master password",
                                        },
                                        HelpEntry {
                                            key: "r",
                                            desc: "Refresh list",
                                        },
                                        HelpEntry {
                                            key: "?",
                                            desc: "Toggle this help",
                                        },
                                    ],
                                },
                                HelpSection {
                                    title: "Global Shortcuts",
                                    entries: vec![
                                        HelpEntry {
                                            key: "q",
                                            desc: "Return to Home (already here)",
                                        },
                                        HelpEntry {
                                            key: "Ctrl+L",
                                            desc: "Tab Manager (list/switch/close tabs)",
                                        },
                                        HelpEntry {
                                            key: "Ctrl+Q",
                                            desc: "Quit VoidB",
                                        },
                                    ],
                                },
                            ]));
                        }
                        KeyCode::Char('r') => {
                            let loaded = self
                                .caps
                                .as_ref()
                                .and_then(|c| c.connections.try_read().ok())
                                .map(|r| r.list());
                            if let Some(mut conns) = loaded {
                                Self::sort_connections(&mut conns);
                                self.connections = conns;
                                self.refilter();
                                self.refresh_profile_catalog();
                            }
                            self.status_message = Some("Connections refreshed".to_string());
                        }
                        _ => {}
                    }
                }
            }
        }

        // Render UI
        self.render_ui(frame, area)?;

        // Render type selector on top if open
        if let Some((types, selected_idx)) = &self.type_selector {
            self.render_type_selector(frame, area, types, *selected_idx);
        }

        // Render custom dialog on top if open
        if let Some(custom) = &mut self.custom_dialog {
            custom.render(frame, area);
        }

        // Render default dialog on top if open
        if let Some(dialog) = &self.dialog {
            dialog.render(frame, area);
        }

        if let Some(help) = &self.help_popup {
            help.render(frame, area);
        }

        if let Some(browser) = &self.capability_browser {
            self.render_capability_browser(frame, area, browser);
        }

        if let Some(dialog) = &self.credential_dialog {
            self.render_credential_dialog(frame, area, dialog);
        }

        Ok(())
    }

    fn wants_raw_input(&self) -> bool {
        self.credential_dialog.is_some()
    }
}

impl ConnectionManagerPlugin {
    fn render_ui(&mut self, frame: &mut Frame, area: Rect) -> Result<()> {
        if self.search_active {
            // Layout: [Header | SearchBar | List | Status | Help]
            let chunks = Layout::vertical([
                Constraint::Length(3),
                Constraint::Length(1),
                Constraint::Min(0),
                Constraint::Length(1),
                Constraint::Length(2),
            ])
            .split(area);

            self.render_header(frame, chunks[0]);
            self.render_search_bar(frame, chunks[1]);
            self.list_area = Some(chunks[2]);
            self.render_connection_list(frame, chunks[2]);
            self.render_status(frame, chunks[3]);
            self.render_help(frame, chunks[4]);
        } else {
            // Layout: [Header | List | Status | Help]
            let chunks = Layout::vertical([
                Constraint::Length(3),
                Constraint::Min(0),
                Constraint::Length(1),
                Constraint::Length(2),
            ])
            .split(area);

            self.render_header(frame, chunks[0]);
            self.list_area = Some(chunks[1]);
            self.render_connection_list(frame, chunks[1]);
            self.render_status(frame, chunks[2]);
            self.render_help(frame, chunks[3]);
        }

        Ok(())
    }

    fn render_header(&self, frame: &mut Frame, area: Rect) {
        let count_text = if self.search_active && !self.search_buffer.is_empty() {
            format!(
                "{} of {} connections",
                self.filtered_indices.len(),
                self.connections.len()
            )
        } else {
            format!("{} connections configured", self.connections.len())
        };
        let credential_text = Self::credential_status_text(&self.credential_state);
        let profile_text = if let Some(error) = &self.profile_catalog_error {
            error.clone()
        } else {
            format!(
                "{} profile view{}",
                self.profile_catalog_count,
                plural(self.profile_catalog_count)
            )
        };
        let header = Paragraph::new(vec![
            Line::from(vec![
                Span::styled("🔌 ", Style::default().fg(Color::Yellow)),
                Span::styled(
                    "Connection Manager",
                    Style::default()
                        .fg(Color::Cyan)
                        .add_modifier(Modifier::BOLD),
                ),
            ]),
            Line::from(vec![Span::styled(
                format!("{} | {} | {}", count_text, profile_text, credential_text),
                Style::default().fg(Color::Gray),
            )]),
        ])
        .block(Block::default().borders(Borders::BOTTOM));

        frame.render_widget(header, area);
    }

    fn render_connection_list(&mut self, frame: &mut Frame, area: Rect) {
        if self.connections.is_empty() {
            // Empty state
            let empty = Paragraph::new(vec![
                Line::from(""),
                Line::from(vec![Span::styled(
                    "No connections configured",
                    Style::default()
                        .fg(Color::Gray)
                        .add_modifier(Modifier::ITALIC),
                )]),
                Line::from(""),
                Line::from(vec![Span::styled(
                    "Press 'n' to add a new connection",
                    Style::default().fg(Color::Yellow),
                )]),
            ])
            .block(Block::default().borders(Borders::ALL).title("Connections"));

            frame.render_widget(empty, area);
            return;
        }

        if self.filtered_indices.is_empty() && self.search_active {
            // No matches
            let empty = Paragraph::new(vec![
                Line::from(""),
                Line::from(vec![Span::styled(
                    "No matching connections",
                    Style::default()
                        .fg(Color::Gray)
                        .add_modifier(Modifier::ITALIC),
                )]),
            ])
            .block(Block::default().borders(Borders::ALL).title("Connections"));

            frame.render_widget(empty, area);
            return;
        }

        // Connection list (filtered)
        let items: Vec<ListItem> = self
            .filtered_indices
            .iter()
            .filter_map(|&idx| self.connections.get(idx))
            .map(|conn| {
                let icon_key = if conn.db_type == DatabaseType::Plugin {
                    conn.plugin_id.as_deref().unwrap_or("plugin").to_string()
                } else {
                    conn.db_type.to_string()
                };
                let protocol_icon = Self::protocol_icon(&icon_key);
                let content = format!("{} {}", protocol_icon, conn.display_name(),);
                let metadata = Self::profile_entry_summary(self.profile_entry_for_connection(conn));
                let content = format!("{}  [{}]", content, metadata);
                ListItem::new(content)
            })
            .collect();

        let title = if self.search_active && !self.search_buffer.is_empty() {
            format!(
                "Connections ({}/{})",
                self.filtered_indices.len(),
                self.connections.len()
            )
        } else {
            "Connections".to_string()
        };

        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title(title))
            .highlight_style(
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol("▶ ");

        frame.render_stateful_widget(list, area, &mut self.list_state);
    }

    fn render_search_bar(&self, frame: &mut Frame, area: Rect) {
        let search_line = Line::from(vec![
            Span::styled(" /: ", Style::default().fg(Color::Yellow)),
            if self.search_buffer.is_empty() {
                Span::styled(
                    "(type to filter)",
                    Style::default()
                        .fg(Color::DarkGray)
                        .add_modifier(Modifier::ITALIC),
                )
            } else {
                Span::styled(&self.search_buffer, Style::default().fg(Color::White))
            },
            Span::styled("▌", Style::default().fg(Color::Cyan)),
        ]);
        frame.render_widget(Paragraph::new(search_line), area);
    }

    fn render_status(&self, frame: &mut Frame, area: Rect) {
        if let Some(buf) = &self.command_buffer {
            let status = Paragraph::new(Line::from(vec![
                Span::styled(":", Style::default().fg(Color::White)),
                Span::styled(buf.as_str(), Style::default().fg(Color::White)),
                Span::styled("▌", Style::default().fg(Color::Yellow)),
            ]));
            frame.render_widget(status, area);
        } else if let Some(msg) = &self.status_message {
            let status = Paragraph::new(Line::from(vec![Span::styled(
                msg,
                Style::default().fg(Color::Yellow),
            )]));
            frame.render_widget(status, area);
        }
    }

    fn render_help(&self, frame: &mut Frame, area: Rect) {
        let help_text = if self.search_active {
            "↑↓: Navigate | Enter: Guidance | Esc: Exit search"
        } else if self.connections.is_empty() {
            "n: New connection | m: Master password | ?: Help | Ctrl+Q: Quit"
        } else {
            "↑↓/jk: Navigate | Enter: Guidance | /: Search | n/e/d/t/c | m: Master password | ?: Help"
        };

        let help = Paragraph::new(Line::from(vec![Span::styled(
            help_text,
            Style::default().fg(Color::Gray),
        )]))
        .block(Block::default().borders(Borders::TOP));

        frame.render_widget(help, area);
    }

    fn render_type_selector(
        &self,
        frame: &mut Frame,
        area: Rect,
        types: &[ConnType],
        selected: usize,
    ) {
        use ratatui::widgets::Clear;

        let dialog_width = 50u16;
        let dialog_height = (types.len() as u16 + 4).min(20);

        if area.width < dialog_width || area.height < dialog_height {
            return;
        }

        let x = (area.width.saturating_sub(dialog_width)) / 2;
        let y = (area.height.saturating_sub(dialog_height)) / 2;

        let dialog_area = Rect {
            x: area.x + x,
            y: area.y + y,
            width: dialog_width,
            height: dialog_height,
        };

        frame.render_widget(Clear, dialog_area);

        let block = Block::default()
            .borders(Borders::ALL)
            .title(" Select Connection Type ")
            .style(Style::default().bg(Color::Black));

        frame.render_widget(block, dialog_area);

        let inner = dialog_area.inner(ratatui::layout::Margin {
            horizontal: 2,
            vertical: 1,
        });

        // Render connection type list
        let items: Vec<Line> = types
            .iter()
            .enumerate()
            .map(|(i, ct)| {
                let icon = Self::protocol_icon(&ct.label.to_lowercase());
                let is_selected = i == selected;
                let style = if is_selected {
                    Style::default()
                        .fg(Color::Yellow)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::White)
                };
                let prefix = if is_selected { "▶ " } else { "  " };
                Line::from(vec![
                    Span::styled(prefix, style),
                    Span::raw(icon),
                    Span::raw(" "),
                    Span::styled(&ct.label, style),
                ])
            })
            .collect();

        let list_height = inner.height.saturating_sub(2);
        let chunks =
            Layout::vertical([Constraint::Length(list_height), Constraint::Length(2)]).split(inner);

        let paragraph = Paragraph::new(items);
        frame.render_widget(paragraph, chunks[0]);

        // Help text
        let help = Paragraph::new(Line::from(vec![
            Span::styled("↑↓/jk", Style::default().fg(Color::Yellow)),
            Span::raw(": Navigate | "),
            Span::styled("Enter", Style::default().fg(Color::Yellow)),
            Span::raw(": Select | "),
            Span::styled("Esc", Style::default().fg(Color::Yellow)),
            Span::raw(": Cancel"),
        ]));
        frame.render_widget(help, chunks[1]);
    }

    fn render_capability_browser(
        &self,
        frame: &mut Frame,
        area: Rect,
        browser: &CapabilityBrowserState,
    ) {
        let dialog_width = area.width.clamp(56, 96);
        let dialog_height = area.height.clamp(14, 26);

        if area.width < dialog_width || area.height < dialog_height {
            return;
        }

        let x = (area.width.saturating_sub(dialog_width)) / 2;
        let y = (area.height.saturating_sub(dialog_height)) / 2;
        let dialog_area = Rect {
            x: area.x + x,
            y: area.y + y,
            width: dialog_width,
            height: dialog_height,
        };

        frame.render_widget(Clear, dialog_area);
        let block = Block::default()
            .borders(Borders::ALL)
            .title(" Capability Browser ")
            .style(Style::default().bg(Color::Black));
        frame.render_widget(block, dialog_area);

        let inner = dialog_area.inner(ratatui::layout::Margin {
            horizontal: 2,
            vertical: 1,
        });
        let chunks = Layout::vertical([
            Constraint::Length(3),
            Constraint::Min(4),
            Constraint::Length(4),
        ])
        .split(inner);

        let header = vec![
            Line::from(vec![
                Span::styled("Plugin: ", Style::default().fg(Color::Gray)),
                Span::styled(&browser.plugin_id, Style::default().fg(Color::Cyan)),
                Span::raw("  "),
                Span::styled("Profile: ", Style::default().fg(Color::Gray)),
                Span::styled(&browser.name, Style::default().fg(Color::Yellow)),
            ]),
            Line::from(Span::styled(
                browser
                    .message
                    .as_deref()
                    .unwrap_or("Select a capability for command guidance."),
                if browser.loading {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default().fg(Color::Gray)
                },
            )),
            Line::from(Span::styled(
                "Enter: invoke guidance | t: plugin TUI command | q/Esc: close",
                Style::default().fg(Color::DarkGray),
            )),
        ];
        frame.render_widget(Paragraph::new(header), chunks[0]);

        let lines = if browser.loading {
            vec![Line::from(Span::styled(
                "Loading capability metadata...",
                Style::default().fg(Color::Yellow),
            ))]
        } else if browser.capabilities.is_empty() {
            vec![Line::from(Span::styled(
                "No capabilities returned for this plugin.",
                Style::default().fg(Color::Gray),
            ))]
        } else {
            browser
                .capabilities
                .iter()
                .enumerate()
                .map(|(index, capability)| {
                    let selected = index == browser.selected;
                    let style = if selected {
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::White)
                    };
                    let prefix = if selected { "> " } else { "  " };
                    let mut flags = vec![capability.risk.as_str()];
                    if capability.destructive {
                        flags.push("destructive");
                    }
                    if capability.streaming {
                        flags.push("streaming");
                    }
                    if capability.supports_dry_run {
                        flags.push("dry-run");
                    }
                    Line::from(vec![
                        Span::styled(prefix, style),
                        Span::styled(&capability.qualified_id, style),
                        Span::raw("  "),
                        Span::styled(
                            format!("[{}]", flags.join(", ")),
                            Style::default().fg(Color::Gray),
                        ),
                    ])
                })
                .collect()
        };
        frame.render_widget(Paragraph::new(lines), chunks[1]);

        let selected = browser.capabilities.get(browser.selected);
        let description = selected
            .map(|capability| capability.description.as_str())
            .unwrap_or("Connection Manager shows commands only; it does not execute capabilities or launch plugin TUIs.");
        let footer = Paragraph::new(vec![
            Line::from(Span::styled(description, Style::default().fg(Color::Gray))),
            Line::from(Span::styled(
                format!(
                    "Profile ref: {} | TUI command: voidb-cli {} tui --profile {}",
                    browser.profile_ref, browser.plugin_id, browser.profile_ref
                ),
                Style::default().fg(Color::DarkGray),
            )),
        ]);
        frame.render_widget(footer, chunks[2]);
    }

    fn render_credential_dialog(
        &self,
        frame: &mut Frame,
        area: Rect,
        dialog: &CredentialDialogState,
    ) {
        let dialog_width = area.width.clamp(42, 68);
        let dialog_height = 10u16;

        if area.width < dialog_width || area.height < dialog_height {
            return;
        }

        let x = (area.width.saturating_sub(dialog_width)) / 2;
        let y = (area.height.saturating_sub(dialog_height)) / 2;
        let dialog_area = Rect {
            x: area.x + x,
            y: area.y + y,
            width: dialog_width,
            height: dialog_height,
        };

        frame.render_widget(Clear, dialog_area);
        let block = Block::default()
            .borders(Borders::ALL)
            .title(dialog.title())
            .style(Style::default().bg(Color::Black));
        frame.render_widget(block, dialog_area);

        let inner = dialog_area.inner(ratatui::layout::Margin {
            horizontal: 2,
            vertical: 1,
        });

        let mut lines = Vec::new();
        let description = match dialog.mode {
            CredentialDialogMode::Unlock => "Enter the master password for this TUI session.",
            CredentialDialogMode::Reencrypt => {
                "Set a user master password and re-encrypt saved credential material."
            }
        };
        lines.push(Line::from(Span::styled(
            description,
            Style::default().fg(Color::Gray),
        )));
        lines.push(Line::from(""));

        for index in 0..dialog.field_count() {
            let selected = index == dialog.active_field;
            let style = if selected {
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            let mut masked = "*".repeat(dialog.field_value(index).chars().count());
            if selected {
                masked.push('_');
            }
            lines.push(Line::from(vec![
                Span::styled(format!("{}: ", dialog.field_label(index)), style),
                Span::styled(masked, style),
            ]));
        }

        lines.push(Line::from(""));
        if let Some(message) = &dialog.message {
            lines.push(Line::from(Span::styled(
                message.as_str(),
                Style::default().fg(Color::Red),
            )));
        } else {
            lines.push(Line::from(Span::styled(
                "Tab: Next | Enter: Submit | Esc: Cancel",
                Style::default().fg(Color::DarkGray),
            )));
        }

        frame.render_widget(Paragraph::new(lines), inner);
    }
}

fn plural(count: usize) -> &'static str {
    if count == 1 { "" } else { "s" }
}

fn run_profile_test_command(
    profile_ref: &str,
    plugin_id: &str,
    name: &str,
) -> std::result::Result<String, String> {
    let cli_bin = resolve_voidb_cli_binary();
    let output = std::process::Command::new(&cli_bin)
        .args([
            "profile",
            "test",
            profile_ref,
            "--plugin",
            plugin_id,
            "--format",
            "json",
        ])
        .output()
        .map_err(|error| {
            format!(
                "unable to launch profile test command '{}': {}",
                cli_bin.display(),
                error
            )
        })?;

    let value: Value = serde_json::from_slice(&output.stdout).map_err(|_| {
        format!(
            "profile test command exited with {} before producing JSON",
            output
                .status
                .code()
                .map(|code| code.to_string())
                .unwrap_or_else(|| "signal".to_string())
        )
    })?;

    if value.get("ok").and_then(Value::as_bool) == Some(true) {
        let message = value
            .pointer("/data/message")
            .and_then(Value::as_str)
            .unwrap_or("profile test succeeded");
        let duration_ms = value
            .pointer("/data/timing/duration_ms")
            .and_then(Value::as_u64);
        let timing = duration_ms
            .map(|duration| format!(" ({} ms)", duration))
            .unwrap_or_default();
        return Ok(format!(
            "{} profile '{}' OK: {}{}",
            plugin_id, name, message, timing
        ));
    }

    let code = value
        .pointer("/error/code")
        .and_then(Value::as_str)
        .unwrap_or("profile_test_failed");
    let message = value
        .pointer("/error/message")
        .and_then(Value::as_str)
        .unwrap_or("Profile test failed.");
    let diagnostic = value
        .pointer("/error/details/diagnostic")
        .and_then(Value::as_str);

    if let Some(diagnostic) = diagnostic {
        Err(format!(
            "{} profile '{}' failed: {} ({}) - {}",
            plugin_id, name, message, code, diagnostic
        ))
    } else {
        Err(format!(
            "{} profile '{}' failed: {} ({})",
            plugin_id, name, message, code
        ))
    }
}

fn run_capability_list_command(
    plugin_id: &str,
) -> std::result::Result<Vec<CapabilityBrowserItem>, String> {
    let cli_bin = resolve_voidb_cli_binary();
    let output = std::process::Command::new(&cli_bin)
        .args(["invoke", "list", plugin_id, "--format", "json"])
        .output()
        .map_err(|error| {
            format!(
                "unable to launch capability discovery command '{}': {}",
                cli_bin.display(),
                error
            )
        })?;

    let value: Value = serde_json::from_slice(&output.stdout).map_err(|_| {
        format!(
            "capability discovery exited with {} before producing JSON",
            output
                .status
                .code()
                .map(|code| code.to_string())
                .unwrap_or_else(|| "signal".to_string())
        )
    })?;

    if value.get("ok").and_then(Value::as_bool) != Some(true) {
        let code = value
            .pointer("/error/code")
            .and_then(Value::as_str)
            .unwrap_or("capability_discovery_failed");
        let message = value
            .pointer("/error/message")
            .and_then(Value::as_str)
            .unwrap_or("Capability discovery failed.");
        return Err(format!("{} ({})", message, code));
    }

    let capabilities = value
        .pointer("/data/capabilities")
        .and_then(Value::as_array)
        .ok_or_else(|| "capability discovery JSON did not include data.capabilities".to_string())?;

    Ok(capabilities
        .iter()
        .filter_map(|capability| {
            Some(CapabilityBrowserItem {
                qualified_id: capability.get("qualified_id")?.as_str()?.to_string(),
                description: capability
                    .get("description")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                risk: capability
                    .get("risk")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_string(),
                destructive: capability
                    .get("destructive")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                streaming: capability
                    .get("streaming")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                supports_dry_run: capability
                    .get("supports_dry_run")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            })
        })
        .collect())
}

fn resolve_voidb_cli_binary() -> std::path::PathBuf {
    if let Ok(path) = std::env::var("VOIDB_CLI_BIN") {
        return path.into();
    }

    if let Ok(current_exe) = std::env::current_exe()
        && let Some(dir) = current_exe.parent()
    {
        let sibling = dir.join("voidb-cli");
        if sibling.exists() {
            return sibling;
        }
    }

    "voidb-cli".into()
}

/// Factory for creating ConnectionManager plugin instances
pub struct ConnectionManagerPluginFactory;

impl PluginFactory for ConnectionManagerPluginFactory {
    fn create(&self, _context: Value) -> Result<Box<dyn Plugin>> {
        Ok(Box::new(ConnectionManagerPlugin::new()))
    }

    fn plugin_id(&self) -> &str {
        "connection-manager"
    }

    fn plugin_name(&self) -> &str {
        "Connection Manager"
    }

    fn description(&self) -> &str {
        "Manage database connections"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credential_state(
        mode: CredentialProtectionMode,
        material: CredentialMaterialState,
        master_password: MasterPasswordSessionState,
        item_count: usize,
    ) -> CredentialProtectionState {
        CredentialProtectionState::new(
            CredentialProtectionStore::Config,
            mode,
            material,
            master_password,
            CredentialMaterialSummary {
                credential_owner_count: usize::from(item_count > 0),
                credential_item_count: item_count,
                plugins: vec!["s3".into()],
            },
        )
    }

    #[test]
    fn credential_dialog_requests_raw_input() {
        let mut plugin = ConnectionManagerPlugin::new();

        assert!(!plugin.wants_raw_input());

        plugin.credential_dialog = Some(CredentialDialogState::unlock());

        assert!(plugin.wants_raw_input());
    }

    #[test]
    fn credential_status_warns_only_for_default_passphrase_material() {
        let default_with_secret = credential_state(
            CredentialProtectionMode::DefaultPassphrase,
            CredentialMaterialState::Present,
            MasterPasswordSessionState::NotConfigured,
            2,
        );
        let protected = credential_state(
            CredentialProtectionMode::UserPassphrase,
            CredentialMaterialState::Present,
            MasterPasswordSessionState::Unlocked,
            2,
        );
        let default_without_secret = credential_state(
            CredentialProtectionMode::DefaultPassphrase,
            CredentialMaterialState::Absent,
            MasterPasswordSessionState::NotConfigured,
            0,
        );
        let protected_without_secret = credential_state(
            CredentialProtectionMode::UserPassphrase,
            CredentialMaterialState::Absent,
            MasterPasswordSessionState::Unlocked,
            0,
        );

        assert!(
            ConnectionManagerPlugin::credential_status_text(&default_with_secret)
                .contains("weak default passphrase")
        );
        assert!(
            !ConnectionManagerPlugin::credential_status_text(&protected)
                .contains("weak default passphrase")
        );
        assert!(
            !ConnectionManagerPlugin::credential_status_text(&default_without_secret)
                .contains("weak default passphrase")
        );
        assert!(
            ConnectionManagerPlugin::credential_status_text(&protected_without_secret)
                .contains("user passphrase unlocked")
        );
    }

    #[test]
    fn credential_status_text_is_redacted_to_counts() {
        let mut state = credential_state(
            CredentialProtectionMode::DefaultPassphrase,
            CredentialMaterialState::Present,
            MasterPasswordSessionState::NotConfigured,
            2,
        );
        state.summary.plugins = vec!["s3".into(), "private-plugin".into()];

        let text = ConnectionManagerPlugin::credential_status_text(&state);

        assert!(text.contains("2 items"));
        assert!(text.contains("1 connection"));
        assert!(!text.contains("s3"));
        assert!(!text.contains("private-plugin"));
        assert!(!text.contains("secret"));
    }

    #[test]
    fn credential_dialog_masks_password_values() {
        let mut dialog = CredentialDialogState::reencrypt();
        dialog.push_str("secret");
        dialog.next_field();
        dialog.push_str("secret");

        assert_eq!(dialog.field_value(0), "secret");
        assert_eq!(dialog.field_value(1), "secret");
        assert_eq!(dialog.field_label(0), "New master password");
        assert_eq!(dialog.field_label(1), "Confirm password");
    }
}
