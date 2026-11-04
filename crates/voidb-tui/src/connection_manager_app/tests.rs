use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
use ratatui::backend::TestBackend;

use super::actions::create_profile_editor;
use super::background::{
    AgentAuthorizeRequest, agent_authorize_args, build_authorization_snapshot,
    can_install_missing_plugin, capability_list_args, parse_agent_statuses,
    parse_agent_supported_plugins, parse_capabilities, parse_grant_revisions,
    parse_pending_authorizations, parse_plugin_install_response,
};
use super::events::paste_into_editor;
use super::*;

#[test]
fn poll_interval_backs_off_and_caps_at_eight_hundred_ms() {
    assert_eq!(
        ConnectionManagerApp::poll_interval(0),
        Duration::from_millis(100)
    );
    assert_eq!(
        ConnectionManagerApp::poll_interval(1),
        Duration::from_millis(200)
    );
    assert_eq!(
        ConnectionManagerApp::poll_interval(2),
        Duration::from_millis(400)
    );
    assert_eq!(
        ConnectionManagerApp::poll_interval(3),
        Duration::from_millis(800)
    );
    // Saturates instead of growing without bound.
    assert_eq!(
        ConnectionManagerApp::poll_interval(50),
        Duration::from_millis(800)
    );
}

#[test]
fn authorization_snapshot_refresh_is_short_only_while_authorization_is_visible() {
    assert_eq!(
        authorization_refresh_interval(ScreenMode::Authorization),
        AUTHORIZATION_REFRESH_INTERVAL
    );
    assert_eq!(
        authorization_refresh_interval(ScreenMode::AuthorizationInbox),
        AUTHORIZATION_REFRESH_INTERVAL
    );
    for mode in [
        ScreenMode::Browse,
        ScreenMode::Search,
        ScreenMode::Edit,
        ScreenMode::ConfirmDelete,
        ScreenMode::ConfirmPluginInstall,
        ScreenMode::Help,
        ScreenMode::Credentials,
        ScreenMode::Capabilities,
    ] {
        assert_eq!(
            authorization_refresh_interval(mode),
            AUTHORIZATION_IDLE_REFRESH_INTERVAL
        );
    }
}

#[test]
fn profile_list_inner_area_respects_minimal_terminal_size() {
    // Too small: no hit area at all.
    assert_eq!(profile_list_inner_area(Rect::new(0, 0, 40, 10)), None);
    assert_eq!(
        profile_list_inner_area(Rect::new(0, 0, MIN_WIDTH - 1, MIN_HEIGHT)),
        None
    );
    // The exact minimum still renders, so it hit-tests.
    assert!(profile_list_inner_area(Rect::new(0, 0, MIN_WIDTH, MIN_HEIGHT)).is_some());

    let (_, main, _) = terminal_layout(Rect::new(0, 0, 100, 30));
    let (profiles, _) = main_columns(main);
    let expected = Block::default().borders(Borders::ALL).inner(profiles);
    assert_eq!(
        profile_list_inner_area(Rect::new(0, 0, 100, 30)),
        Some(expected)
    );
}

#[test]
fn profile_row_index_maps_visible_rows_and_rejects_off_list_rows() {
    let inner = Rect::new(0, 4, 30, 5);
    // Above the list and below the list are misses.
    assert_eq!(profile_row_index(inner, 0, 8, 3), None);
    assert_eq!(profile_row_index(inner, 0, 8, 9), None);
    // Rows inside the list map to offset + row delta.
    assert_eq!(profile_row_index(inner, 0, 8, 4), Some(0));
    assert_eq!(profile_row_index(inner, 0, 8, 6), Some(2));
    // Scrolled list: offset shifts the mapping.
    assert_eq!(profile_row_index(inner, 3, 8, 4), Some(3));
    // A hit that maps past the end of the item list is not a row.
    assert_eq!(profile_row_index(inner, 4, 8, 8), None);
    // Empty list never maps.
    assert_eq!(profile_row_index(inner, 0, 0, 4), None);
}

#[test]
fn editor_is_dirty_tracks_unsaved_changes_only() {
    let mut editor = ProfileEditor::new();
    assert!(!editor.is_dirty());
    editor.name.push('x');
    assert!(editor.is_dirty());

    // Toggling the Form/JSON view changes no profile data.
    let mut editor = ProfileEditor::new();
    editor.toggle_view();
    assert!(!editor.is_dirty());

    // Cycling the plugin on a new profile replaces the whole config.
    let mut editor = ProfileEditor::new();
    editor.cycle_plugin(true);
    assert!(editor.is_dirty());
}

#[test]
fn editor_paste_drops_line_breaks_outside_json_text() {
    // Name field: pasted newlines are dropped instead of hitting Enter.
    let mut editor = ProfileEditor::new();
    editor.active_field = 1;
    paste_into_editor(&mut editor, "prod\ndb");
    assert_eq!(editor.name, "proddb");

    // A bare newline must not cycle a form select field value.
    let mut editor = ProfileEditor::new();
    editor.active_field = 3;
    let before = editor.config.clone();
    paste_into_editor(&mut editor, "\n");
    assert_eq!(editor.config, before);

    // JSON text field: newlines are content and split the line.
    let mut editor = ProfileEditor::new();
    editor.toggle_view();
    let lines_before = editor.config_lines.len();
    paste_into_editor(&mut editor, "x\ny");
    assert_eq!(editor.config_lines.len(), lines_before + 1);
}

#[test]
fn display_col_accounts_for_wide_characters() {
    assert_eq!(display_col("abc", 2), 2);
    // Each CJK char occupies two display columns.
    assert_eq!(display_col("你好", 1), 2);
    assert_eq!(display_col("你好", 2), 4);
    // Mixed text: prefix width, not char count.
    assert_eq!(display_col("a你b", 3), 4);
    // Out-of-range index saturates to the full line width.
    assert_eq!(display_col("ab", 10), 2);
}

#[test]
fn stepped_selection_wraps_and_pages() {
    let len = 12;
    assert_eq!(stepped_selection(0, len, 1), 1);
    // Wraps from the last item back to the first.
    assert_eq!(stepped_selection(len - 1, len, 1), 0);
    // Wraps backwards from the first item to the last.
    assert_eq!(stepped_selection(0, len, -1), len - 1);
    // Page steps wrap around the ends.
    assert_eq!(stepped_selection(5, len, 10), 3);
    assert_eq!(stepped_selection(5, len, -10), 7);
    // Empty lists stay at zero.
    assert_eq!(stepped_selection(0, 0, 1), 0);
}

#[test]
fn editor_text_caret_inserts_and_deletes_at_position() {
    let mut editor = ProfileEditor::new();
    editor.active_field = 1;
    for character in "abc".chars() {
        editor.insert_text_char(character);
    }
    assert_eq!(editor.name, "abc");
    // Move in front of 'b' and insert there.
    editor.caret_left();
    editor.insert_text_char('X');
    assert_eq!(editor.name, "abXc");
    assert_eq!(editor.name_cursor, 3);
    // Backspace removes the char before the caret.
    editor.backspace_text();
    assert_eq!(editor.name, "abc");
    // Home/Delete operate relative to the caret.
    editor.caret_home();
    editor.delete_text_forward();
    assert_eq!(editor.name, "bc");
    assert_eq!(editor.name_cursor, 0);
    editor.caret_end();
    assert_eq!(editor.name_cursor, 2);
    // The two fields keep independent carets.
    editor.active_field = 2;
    editor.insert_text_char('d');
    assert_eq!(editor.display_name, "d");
    assert_eq!(editor.name, "bc");
}

#[test]
fn contextual_install_only_accepts_missing_official_plugins() {
    assert!(can_install_missing_plugin("mysql", None));
    assert!(!can_install_missing_plugin("../mysql", None));
    assert!(!can_install_missing_plugin("custom-plugin", None));
    for state in [
        ProcessPluginCandidateState::Available,
        ProcessPluginCandidateState::Disabled,
        ProcessPluginCandidateState::Invalid,
        ProcessPluginCandidateState::Incompatible,
        ProcessPluginCandidateState::Failed,
    ] {
        assert!(!can_install_missing_plugin("mysql", Some(state)));
    }
}

#[test]
fn installer_response_rejects_error_envelopes_even_with_zero_exit_status() {
    let response = json!({"ok": false, "error": {"message": "No compatible artifact"}});
    assert_eq!(
        parse_plugin_install_response("mysql", &response),
        Err("No compatible artifact".into())
    );
}

#[test]
fn installer_response_requires_the_requested_available_plugin() {
    let mut response = json!({"ok": true, "data": {"plugin": {
        "id": "mysql", "candidate_state": "available"
    }}});
    assert!(parse_plugin_install_response("mysql", &response).is_ok());
    assert!(parse_plugin_install_response("postgres", &response).is_err());
    response["data"]["plugin"]["candidate_state"] = json!("disabled");
    assert!(parse_plugin_install_response("mysql", &response).is_err());
    assert!(parse_plugin_install_response("mysql", &json!({"ok": true})).is_err());
}

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
fn snapshot_payload_parses_once_into_all_views() {
    let payload = json!({
        "agent": { "data": { "grants": [] } },
        "catalog": {
            "data": {
                "capabilities": [
                    { "plugin_id": "ssh", "id": "exec" }
                ]
            }
        },
        "inbox": { "data": {
            "observed_at": "2026-11-04T00:00:00Z",
            "requests": [{
                "id": "auth-request:00000000-0000-4000-8000-000000000001",
                "principal_fingerprint": "agent-principal:abc",
                "profile_id": "profile:ssh",
                "plugin_id": "ssh",
                "scope": { "kind": "capability", "capability_id": "ssh.exec" },
                "risk": "low",
                "purpose": "triage",
                "status": "pending",
                "created_at": "2026-11-04T00:00:00Z",
                "expires_at": "2026-11-04T00:05:00Z"
            }]
        } }
    })
    .to_string();
    let snapshot = build_authorization_snapshot(&payload);
    assert!(snapshot.supported_plugins.contains("ssh"));
    assert_eq!(snapshot.capabilities.len(), 1);
    assert_eq!(snapshot.pending_requests.len(), 1);
    assert_eq!(
        snapshot.observed_at.as_deref(),
        Some("2026-11-04T00:00:00Z")
    );
    assert!(snapshot.statuses.is_empty());
    assert!(snapshot.grant_revisions.is_empty());
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

// ---------------------------------------------------------------------------
// Headless interaction driver: real key/paste/mouse events into the app,
// plus TestBackend render assertions.
// ---------------------------------------------------------------------------

fn plain_key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn char_key(character: char) -> KeyEvent {
    KeyEvent::new(KeyCode::Char(character), KeyModifiers::NONE)
}

fn ctrl_s() -> KeyEvent {
    KeyEvent::new(KeyCode::Char('s'), KeyModifiers::CONTROL)
}

fn press(app: &mut ConnectionManagerApp, code: KeyCode) {
    app.handle_key(plain_key(code));
}

fn temp_store(label: &str) -> LocalProfileStore {
    let dir = std::env::temp_dir().join(format!("voidb-tui-tests-{}-{label}", std::process::id()));
    let _ = std::fs::create_dir_all(&dir);
    LocalProfileStore::new(dir.join("profiles.json"), dir.join("credentials.json"))
}

/// App with an isolated store, no master password, and no background workers.
/// Credential encryption falls back to the 0600 file secret instead of the OS
/// keyring so tests never trigger keychain authorization prompts.
fn test_app(label: &str) -> ConnectionManagerApp {
    // SAFETY: single-threaded env mutation during test setup; `set_var` is
    // unsafe since Rust 1.87 (same pattern as the sync plugin e2e harness).
    unsafe {
        std::env::set_var("VOIDB_DISABLE_KEYRING", "1");
    }
    ConnectionManagerApp::from_parts(AppConfig::default(), temp_store(label), None)
        .expect("test app")
}

/// App seeded with profiles created through the real editor flow.
fn seeded_app(label: &str, names: &[&str]) -> ConnectionManagerApp {
    let mut app = test_app(label);
    for name in names {
        press(&mut app, KeyCode::Char('n'));
        press(&mut app, KeyCode::Tab);
        for character in name.chars() {
            app.handle_key(char_key(character));
        }
        app.handle_key(ctrl_s());
    }
    app
}

fn render_app(app: &mut ConnectionManagerApp, width: u16, height: u16) -> ratatui::buffer::Buffer {
    let mut terminal = ratatui::Terminal::new(TestBackend::new(width, height)).expect("terminal");
    terminal.draw(|frame| app.render(frame)).expect("draw");
    terminal.backend().buffer().clone()
}

fn buffer_text(buffer: &ratatui::buffer::Buffer) -> String {
    let width = buffer.area.width as usize;
    let mut lines: Vec<String> = vec![String::new(); buffer.area.height as usize];
    for (index, cell) in buffer.content.iter().enumerate() {
        lines[index / width].push_str(cell.symbol());
    }
    lines.join("\n")
}

fn mouse_event(kind: MouseEventKind, column: u16, row: u16) -> MouseEvent {
    MouseEvent {
        kind,
        column,
        row,
        modifiers: KeyModifiers::NONE,
    }
}

#[test]
fn browse_navigation_wraps_pages_and_jumps() {
    let mut app = seeded_app("nav", &["alpha", "beta", "gamma"]);
    // Saving selects the most recently saved profile.
    assert_eq!(app.selected, 2);
    press(&mut app, KeyCode::Char('g'));
    assert_eq!(app.selected, 0);
    press(&mut app, KeyCode::Char('k')); // wrap backwards to the last item
    assert_eq!(app.selected, 2);
    press(&mut app, KeyCode::Char('j')); // wrap forwards to the first item
    assert_eq!(app.selected, 0);
    press(&mut app, KeyCode::End);
    assert_eq!(app.selected, 2);
    press(&mut app, KeyCode::Char('g'));
    assert_eq!(app.selected, 0);
    press(&mut app, KeyCode::Char('G'));
    assert_eq!(app.selected, 2);
    press(&mut app, KeyCode::Home);
    assert_eq!(app.selected, 0);
    // Page steps wrap within the 3-item list: +10 lands on 10 % 3 = 1.
    press(&mut app, KeyCode::PageDown);
    assert_eq!(app.selected, 1);
    press(&mut app, KeyCode::PageUp);
    assert_eq!(app.selected, 0);
    press(&mut app, KeyCode::Char('q'));
    assert!(app.should_quit);
}

#[test]
fn search_filters_esc_clears_then_exits() {
    let mut app = seeded_app("search", &["alpha", "beta"]);
    press(&mut app, KeyCode::Char('/'));
    assert_eq!(app.mode, ScreenMode::Search);
    app.handle_key(char_key('b'));
    assert_eq!(app.filtered_indices.len(), 1);
    // Esc clears the non-empty filter and stays in search mode.
    press(&mut app, KeyCode::Esc);
    assert_eq!(app.mode, ScreenMode::Search);
    assert!(app.search.is_empty());
    assert_eq!(app.filtered_indices.len(), 2);
    // Esc from an empty filter returns to Browse.
    press(&mut app, KeyCode::Esc);
    assert_eq!(app.mode, ScreenMode::Browse);
    // Pasted text filters with control characters stripped.
    press(&mut app, KeyCode::Char('/'));
    app.handle_paste("al\n");
    assert_eq!(app.search, "al");
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.mode, ScreenMode::Browse);
    assert_eq!(app.filtered_indices.len(), 1);
}

#[test]
fn delete_confirmation_requires_explicit_y() {
    let mut app = seeded_app("delete", &["alpha", "beta"]);
    press(&mut app, KeyCode::Char('g')); // select the first profile (alpha)
    press(&mut app, KeyCode::Char('d'));
    assert_eq!(app.mode, ScreenMode::ConfirmDelete);
    // Enter is the safe default: it keeps the profile.
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.mode, ScreenMode::Browse);
    assert_eq!(app.profiles.len(), 2);
    press(&mut app, KeyCode::Char('d'));
    press(&mut app, KeyCode::Char('y'));
    assert_eq!(app.mode, ScreenMode::Browse);
    assert_eq!(app.profiles.len(), 1);
    assert_eq!(app.profiles[0].name, "beta");
    assert_eq!(app.status_kind, StatusKind::Success);
}

#[test]
fn plugin_install_declines_on_enter_without_spawning() {
    let mut app = seeded_app("install", &["alpha"]);
    // The offer path rescans the real plugin directory, so drive the confirm
    // state directly to keep the test environment-independent.
    app.plugin_install_target = Some("mysql".into());
    app.mode = ScreenMode::ConfirmPluginInstall;
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.mode, ScreenMode::Browse);
    assert!(app.plugin_install_rx.is_none());
    assert!(app.plugin_install_target.is_none());
}

#[test]
fn editor_esc_with_unsaved_work_confirms_discard() {
    let mut app = test_app("discard");
    press(&mut app, KeyCode::Char('n'));
    assert_eq!(app.mode, ScreenMode::Edit);
    press(&mut app, KeyCode::Tab);
    for character in "draft".chars() {
        app.handle_key(char_key(character));
    }
    press(&mut app, KeyCode::Esc);
    assert_eq!(app.mode, ScreenMode::ConfirmDiscard);
    // Enter keeps editing and preserves the work.
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.mode, ScreenMode::Edit);
    assert_eq!(app.editor.as_ref().expect("editor").name, "draft");
    // Explicit y discards everything.
    press(&mut app, KeyCode::Esc);
    app.handle_key(char_key('y'));
    assert_eq!(app.mode, ScreenMode::Browse);
    assert!(app.editor.is_none());
    assert!(app.profiles.is_empty());
}

#[test]
fn editor_paste_lands_at_caret_and_ctrl_s_saves() {
    let mut app = test_app("paste-save");
    press(&mut app, KeyCode::Char('n'));
    press(&mut app, KeyCode::Tab);
    app.handle_paste("pro");
    app.handle_paste("d\nx"); // line break is dropped outside the JSON field
    assert_eq!(app.editor.as_ref().expect("editor").name, "prodx");
    app.handle_key(ctrl_s());
    assert_eq!(app.mode, ScreenMode::Browse);
    assert_eq!(app.profiles.len(), 1);
    assert_eq!(app.profiles[0].name, "prodx");
    assert_eq!(app.status_kind, StatusKind::Success);
}

#[test]
fn capability_overlay_navigates_and_wraps() {
    let mut app = seeded_app("caps", &["alpha"]);
    app.capabilities = vec![
        CapabilityItem {
            id: "cap-a".into(),
            description: "A".into(),
            risk: "low".into(),
            interactive_execute: false,
            capability_wide_allowed: false,
            approval_fields: vec![],
        },
        CapabilityItem {
            id: "cap-b".into(),
            description: "B".into(),
            risk: "low".into(),
            interactive_execute: false,
            capability_wide_allowed: false,
            approval_fields: vec![],
        },
    ];
    app.mode = ScreenMode::Capabilities;
    press(&mut app, KeyCode::Char('j'));
    assert_eq!(app.capability_selected, 1);
    press(&mut app, KeyCode::Char('j')); // wrap
    assert_eq!(app.capability_selected, 0);
    press(&mut app, KeyCode::PageUp);
    assert_eq!(app.capability_selected, 0);
    // Enter closes the overlay with guidance in the status line.
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.mode, ScreenMode::Browse);
}

#[test]
fn inbox_navigation_wraps_without_background_work() {
    let mut app = test_app("inbox");
    app.pending_authorization_requests = vec![
        PendingAuthorizationView {
            id: "req-1".into(),
            principal_fingerprint: "fp-1".into(),
            profile_id: "p1".into(),
            plugin_id: "mysql".into(),
            scope: json!({}),
            risk: "low".into(),
            purpose: "triage".into(),
            status: "pending".into(),
            created_at: "2026-11-04T00:00:00Z".into(),
            decision_reason: None,
            expires_at: "2026-11-04T01:00:00Z".into(),
            timed_out: false,
        },
        PendingAuthorizationView {
            id: "req-2".into(),
            principal_fingerprint: "fp-2".into(),
            profile_id: "p2".into(),
            plugin_id: "redis".into(),
            scope: json!({}),
            risk: "low".into(),
            purpose: "triage".into(),
            status: "pending".into(),
            created_at: "2026-11-04T00:00:00Z".into(),
            decision_reason: None,
            expires_at: "2026-11-04T01:00:00Z".into(),
            timed_out: false,
        },
    ];
    app.mode = ScreenMode::AuthorizationInbox;
    press(&mut app, KeyCode::Char('j'));
    assert_eq!(app.authorization_inbox_selected, 1);
    press(&mut app, KeyCode::Char('j')); // wrap
    assert_eq!(app.authorization_inbox_selected, 0);
    press(&mut app, KeyCode::Char('k')); // wrap backwards
    assert_eq!(app.authorization_inbox_selected, 1);
    press(&mut app, KeyCode::Esc);
    assert_eq!(app.mode, ScreenMode::Browse);
    assert!(app.authorization_status_rx.is_none());
}

#[test]
fn credentials_dialog_opens_pastes_and_closes() {
    let mut app = seeded_app("creds", &["alpha"]);
    press(&mut app, KeyCode::Char('m'));
    assert!(app.credential_dialog.is_some());
    app.handle_paste("pw");
    press(&mut app, KeyCode::Esc);
    assert!(app.credential_dialog.is_none());
    assert_eq!(app.mode, ScreenMode::Browse);
}

#[test]
fn help_overlay_lists_core_bindings_and_mouse() {
    let mut app = test_app("help");
    press(&mut app, KeyCode::Char('?'));
    assert_eq!(app.mode, ScreenMode::Help);
    let text = buffer_text(&render_app(&mut app, 100, 30));
    for needle in [
        "Mouse",
        "Copy CLI guidance",
        "Ctrl+C / Ctrl+Q",
        "Esc clears",
    ] {
        assert!(text.contains(needle), "help overlay is missing '{needle}'");
    }
    // Any of the documented close keys returns to Browse.
    press(&mut app, KeyCode::Char('?'));
    assert_eq!(app.mode, ScreenMode::Browse);
}

#[test]
fn browse_render_shows_profiles_details_and_guidance() {
    let mut app = seeded_app("render", &["alpha", "beta"]);
    let text = buffer_text(&render_app(&mut app, 100, 30));
    assert!(text.contains("alpha"));
    assert!(text.contains("beta"));
    assert!(text.contains("Profile details"));
    assert!(text.contains("vb mysql tui --profile"));
    assert!(text.contains("Enter copies these commands to the clipboard"));
    assert!(text.contains("Saved native profile"));
}

#[test]
fn small_terminal_renders_the_size_notice() {
    let mut app = test_app("small");
    let text = buffer_text(&render_app(&mut app, 40, 10));
    assert!(text.contains("Terminal too small"));
    assert!(text.contains("Minimum: 72x20"));
}

#[test]
fn mouse_click_selects_and_wheel_navigates() {
    let mut app = seeded_app("mouse", &["alpha", "beta", "gamma"]);
    // A real render seeds the hit-test geometry.
    let _ = render_app(&mut app, 100, 30);
    // The list viewport starts at y=4 (header rows + top border): row 5 is
    // the second visible profile.
    assert!(app.handle_mouse(mouse_event(MouseEventKind::Down(MouseButton::Left), 10, 5)));
    assert_eq!(app.selected, 1);
    // Motion never changes state.
    assert!(!app.handle_mouse(mouse_event(MouseEventKind::Moved, 30, 6)));
    assert_eq!(app.selected, 1);
    assert!(app.handle_mouse(mouse_event(MouseEventKind::ScrollDown, 10, 5)));
    assert_eq!(app.selected, 2);
    assert!(app.handle_mouse(mouse_event(MouseEventKind::ScrollUp, 10, 5)));
    assert_eq!(app.selected, 1);
}

#[test]
fn quit_keys_terminate_the_app() {
    let mut app = test_app("quit");
    app.handle_key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL));
    assert!(app.should_quit);
}
