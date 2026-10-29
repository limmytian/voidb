use std::sync::mpsc;
use std::time::Instant;

use anyhow::{Result, anyhow};
use serde_json::Value;
use voidb_core::{AppConfig, ConnectionConfig, ConnectionProfile, DatabaseType};

use super::ConnectionManagerApp;
use super::background::{
    AgentAuthorizeRequest, can_install_missing_plugin, installed_plugin_states,
    run_agent_authorize, run_agent_renew, run_agent_revoke_all, run_agent_revoke_profile,
    run_authorization_snapshot, run_capability_list, run_jit_authorization_decision,
    run_profile_test,
};
use super::{
    AUTHORIZATION_REFRESH_INTERVAL, AuthorizationAction, AuthorizationDialog, CredentialDialog,
    CredentialMode, EditorView, ProfileEditor, ScreenMode,
};

impl ConnectionManagerApp {
    pub(super) fn open_agent_authorization(&mut self, action: Option<AuthorizationAction>) {
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

    pub(super) fn start_jit_authorization_decision(&mut self) {
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

    pub(super) fn start_authorization_operation(&mut self, action: AuthorizationAction) {
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

    pub(super) fn begin_edit(&mut self) {
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

    pub(super) fn begin_create(&mut self) {
        match create_profile_editor(&self.config, self.active_master_password.as_deref()) {
            Ok(editor) => {
                self.editor = Some(editor);
                self.mode = ScreenMode::Edit;
            }
            Err(message) => self.status = message.to_string(),
        }
    }

    pub(super) fn save_editor(&mut self) {
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

    pub(super) fn open_credentials(&mut self) {
        let mode = if self.config.requires_master_password() {
            CredentialMode::Unlock
        } else {
            CredentialMode::Set
        };
        self.credential_dialog = Some(CredentialDialog::new(mode));
        self.mode = ScreenMode::Credentials;
    }

    pub(super) fn submit_credentials(&mut self) {
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

    pub(super) fn offer_selected_plugin_install(&mut self) {
        if self.plugin_install_rx.is_some() {
            self.status = "A plugin installation is already running".into();
            return;
        }
        let Some(profile) = self.selected_profile() else {
            self.status = "Select a profile to install its plugin".into();
            return;
        };
        let plugin_id = profile.plugin_id.clone();
        self.plugin_states = installed_plugin_states();
        if !can_install_missing_plugin(&plugin_id, self.plugin_states.get(&plugin_id).copied()) {
            self.status = format!(
                "Plugin '{plugin_id}' is already present or is not an official installable plugin; inspect with voidb-cli plugin describe {plugin_id}"
            );
            return;
        }
        self.plugin_install_target = Some(plugin_id);
        self.mode = ScreenMode::ConfirmPluginInstall;
    }

    pub(super) fn show_guidance(&mut self) {
        if let Some(profile) = self.selected_profile() {
            self.status = format!(
                "Profile id:{} | test: voidb-cli profile test id:{} --plugin {} | capabilities: c",
                profile.id, profile.id, profile.plugin_id
            );
        }
    }

    pub(super) fn start_test(&mut self) {
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

    pub(super) fn start_capability_load(&mut self) {
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

    pub(super) fn start_authorization_status_refresh(&mut self) {
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
}

fn database_type_for_plugin(plugin_id: &str) -> DatabaseType {
    match plugin_id {
        "mysql" => DatabaseType::MySQL,
        "postgres" | "postgresql" => DatabaseType::PostgreSQL,
        "sqlite" => DatabaseType::SQLite,
        _ => DatabaseType::Plugin,
    }
}

pub(super) fn create_profile_editor(
    config: &AppConfig,
    active_master_password: Option<&str>,
) -> std::result::Result<ProfileEditor, &'static str> {
    if config.requires_master_password() && active_master_password.is_none() {
        Err("Press m to unlock profile credentials before creating a profile")
    } else {
        Ok(ProfileEditor::new())
    }
}
