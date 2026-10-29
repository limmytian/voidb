use super::actions::create_profile_editor;
use super::background::{
    AgentAuthorizeRequest, agent_authorize_args, can_install_missing_plugin, capability_list_args,
    parse_agent_statuses, parse_agent_supported_plugins, parse_capabilities, parse_grant_revisions,
    parse_pending_authorizations, parse_plugin_install_response,
};
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
