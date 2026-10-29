use std::sync::mpsc;
use std::time::Instant;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use serde_json::Value;

use super::ConnectionManagerApp;
use super::background::{can_install_missing_plugin, installed_plugin_states, run_plugin_install};
use super::{
    AUTHORIZATION_TTL_OPTIONS, AUTHORIZATION_USE_OPTIONS, AgentAuthorizationPresetKind,
    AuthorizationAction, EditorView, JitApprovalDialog, JitDecision, ScreenMode,
};

impl ConnectionManagerApp {
    pub(super) fn handle_key(&mut self, key: KeyEvent) {
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
            ScreenMode::ConfirmPluginInstall => self.handle_plugin_install_key(key),
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
            KeyCode::Char('r') => {
                self.plugin_states = installed_plugin_states();
                match self.refresh_profiles() {
                    Ok(()) => {
                        self.status = format!("Reloaded {} native profiles", self.profiles.len())
                    }
                    Err(error) => self.status = format!("Refresh failed: {error}"),
                }
            }
            KeyCode::Char('i') => self.offer_selected_plugin_install(),
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

    pub(super) fn handle_paste(&mut self, text: &str) {
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

    fn handle_plugin_install_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc | KeyCode::Char('n') => {
                self.plugin_install_target = None;
                self.mode = ScreenMode::Browse;
            }
            KeyCode::Enter | KeyCode::Char('y') => {
                let Some(plugin_id) = self.plugin_install_target.take() else {
                    self.mode = ScreenMode::Browse;
                    return;
                };
                self.mode = ScreenMode::Browse;
                self.plugin_states = installed_plugin_states();
                if self.plugin_install_rx.is_some()
                    || !can_install_missing_plugin(
                        &plugin_id,
                        self.plugin_states.get(&plugin_id).copied(),
                    )
                {
                    self.status = "Plugin state changed; refresh and try again".into();
                    return;
                }
                let (tx, rx) = mpsc::channel();
                self.status = format!("Downloading and installing '{plugin_id}'...");
                self.plugin_install_rx = Some((plugin_id.clone(), rx));
                std::thread::spawn(move || {
                    let _ = tx.send(run_plugin_install(&plugin_id));
                });
            }
            _ => {}
        }
    }
}
