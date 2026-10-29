use chrono::Utc;
use serde_json::Value;
use std::io::{self, Write};
use tokio::sync::watch;
use voidb_core::capability::{
    CapabilityDefinition, CapabilityError, CapabilityErrorCategory, CapabilityExecutionMode,
    CapabilityInvocation, CapabilityInvocationResult, CapabilityPolicyDecision,
    CapabilityRiskLevel, ConnectionProfileRef, CredentialClass, CredentialRef,
    InvocationConnectionTarget, InvocationControls, InvocationOutputPage, InvocationStatus,
    InvocationStreamEvent, RedactionStatus, TargetSystemFailure,
};
use voidb_core::plugin::cli::{CliContext, CliPlugin};
use voidb_core::{
    AuditEvent, AuditEventStatus, AuditOperation, DEFAULT_INVOCATION_OUTPUT_BYTES,
    DEFAULT_INVOCATION_TIMEOUT_MS, MAX_INVOCATION_CURSOR_BYTES, MAX_INVOCATION_PAGE_LIMIT,
    ProcessPluginCandidateState, ProcessPluginDiscovery, audit_json_summary,
};
#[cfg(feature = "sync")]
use voidb_plugin_sync::sync_capabilities;

use super::audit::*;
use super::discovery::*;
use super::execution::*;
use super::handlers::*;
use super::output::*;
use super::profiles::*;
use super::*;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde_json::json;
use voidb_core::config::AppConfig;
use voidb_core::{
    ConnectionConfig, DatabaseType, PolicyDecisionOutcome, PolicyReason, ProcessPluginRoot,
    ProcessPluginRootKind, discover_process_plugins_from_roots, migrated_profile_from_connection,
};

fn encoded_audit_context(event: &AuditEvent) -> String {
    serde_json::to_string(&json!({
        "metadata": &event.metadata,
        "error": &event.error,
        "redaction": event.redaction,
    }))
    .expect("serialize audit context")
}

#[test]
fn parses_qualified_capability_refs() {
    assert_eq!(
        parse_capability_ref("sqlite.query").expect("parse"),
        ("sqlite".into(), "query".into())
    );
    let error = parse_capability_ref("query").expect_err("unqualified");
    assert_eq!(error.code, "validation.capability_ref_unqualified");
}

#[test]
fn lists_builtin_capabilities() {
    let discovery = catalog_fixture_discovery();
    let capabilities = supported_capabilities(&discovery);

    assert!(
        capabilities
            .iter()
            .any(|capability| capability.qualified_id() == "sqlite.query")
    );
    assert!(
        capabilities
            .iter()
            .any(|capability| capability.qualified_id() == "sqlite.explain")
    );
    assert!(
        capabilities
            .iter()
            .any(|capability| capability.qualified_id() == "redis.get")
    );
    assert!(
        capabilities
            .iter()
            .any(|capability| capability.qualified_id() == "mysql.query")
    );
    assert!(
        capabilities
            .iter()
            .any(|capability| capability.qualified_id() == "postgres.query")
    );
    assert!(
        capabilities
            .iter()
            .any(|capability| capability.qualified_id() == "duckdb.query")
    );
    assert!(
        capabilities
            .iter()
            .any(|capability| capability.qualified_id() == "ssh.exec")
    );
    assert!(
        capabilities
            .iter()
            .any(|capability| capability.qualified_id() == "sync.status")
    );
}

#[tokio::test]
async fn sync_builtin_honors_caller_cancellation_before_loading_state() {
    let capability = sync_capabilities()
        .into_iter()
        .find(|capability| capability.id == "diagnostics")
        .expect("Sync diagnostics");
    let connection = ConnectionConfig {
        name: "local".into(),
        db_type: DatabaseType::Plugin,
        plugin_id: Some("sync".into()),
        plugin_config: None,
    };
    let invocation = CapabilityInvocation {
        id: "sync-cancelled".into(),
        plugin_id: "sync".into(),
        capability_id: "diagnostics".into(),
        connection: InvocationConnectionTarget::Stateless,
        input: json!({}),
        controls: InvocationControls::default(),
        actor: None,
        requested_at: Utc::now(),
    };
    let (_cancel_tx, cancel_rx) = watch::channel(true);
    let error = invoke_builtin_capability(&capability, &connection, invocation, cancel_rx)
        .await
        .expect_err("cancelled before dispatch");
    assert_eq!(error.category, CapabilityErrorCategory::Cancellation);
    assert_eq!(error.code, "cancellation.requested");
}

#[test]
fn classifies_every_builtin_capability_execution_mode() {
    use voidb_core::CapabilityExecutionMode;

    let capabilities = supported_capabilities(&catalog_fixture_discovery());
    assert_eq!(capabilities.len(), 68);
    assert!(capabilities.iter().all(|capability| {
        !capability.supports_session_execution() || capability.session_handoff.is_some()
    }));

    let session_only = capabilities
        .iter()
        .filter(|capability| capability.execution_mode == CapabilityExecutionMode::SessionOnly)
        .map(CapabilityDefinition::qualified_id)
        .collect::<Vec<_>>();
    assert_eq!(
        session_only,
        vec![
            "redis.monitor_read",
            "redis.pubsub_read",
            "redis.stream_read",
            "ssh.forward_open",
            "ssh.forward_status",
            "ssh.terminal_read",
            "ssh.terminal_resize",
            "ssh.terminal_signal",
            "ssh.terminal_snapshot",
            "ssh.terminal_write",
        ]
    );

    let both = capabilities
        .iter()
        .filter(|capability| capability.execution_mode == CapabilityExecutionMode::Both)
        .map(CapabilityDefinition::qualified_id)
        .collect::<Vec<_>>();
    assert_eq!(
        both,
        vec![
            "duckdb.exec",
            "duckdb.query",
            "mysql.exec",
            "mysql.query",
            "postgres.exec",
            "postgres.query",
            "redis.exec",
            "sqlite.exec",
            "sqlite.query",
            "ssh.exec",
            "ssh.sftp_list",
        ]
    );
}

#[test]
fn sql_plugins_share_transfer_authorization_and_session_contracts() {
    let catalogs = [
        (
            "postgres",
            resolved_authorization_capabilities(Some("postgres"))
                .expect("postgres fixture catalog"),
        ),
        (
            "mysql",
            resolved_authorization_capabilities(Some("mysql")).expect("mysql fixture catalog"),
        ),
        (
            "sqlite",
            resolved_authorization_capabilities(Some("sqlite")).expect("sqlite fixture catalog"),
        ),
        (
            "duckdb",
            resolved_authorization_capabilities(Some("duckdb")).expect("duckdb fixture catalog"),
        ),
    ];

    for (plugin, capabilities) in catalogs {
        voidb_core::validate_sql_capability_contract(plugin, &capabilities)
            .unwrap_or_else(|violations| panic!("{plugin}: {violations:?}"));
        assert_eq!(capabilities.len(), 9, "{plugin}");

        let export = capabilities
            .iter()
            .find(|capability| capability.id == "export_query")
            .unwrap();
        assert!(export.streaming, "{plugin}");
        assert!(!export.destructive, "{plugin}");
        assert!(!export.authorization.capability_wide_allowed, "{plugin}");
        let export_paths = export
            .authorization
            .approval_schema
            .as_ref()
            .unwrap()
            .fields
            .iter()
            .map(|field| field.path.as_str())
            .collect::<Vec<_>>();
        let expected_export_paths = if plugin == "mysql" {
            vec!["/sql", "/database", "/local_root", "/local_path"]
        } else {
            vec!["/sql", "/local_root", "/local_path"]
        };
        assert_eq!(export_paths, expected_export_paths, "{plugin}");

        let import = capabilities
            .iter()
            .find(|capability| capability.id == "import_apply")
            .unwrap();
        assert!(import.destructive, "{plugin}");
        assert!(import.supports_dry_run, "{plugin}");
        assert!(import.authorization.interactive_execute, "{plugin}");
        assert!(!import.authorization.capability_wide_allowed, "{plugin}");
        assert_eq!(
            import.input_schema["required"],
            json!(["table", "format", "local_root", "local_path"]),
            "{plugin}"
        );

        let exec = capabilities
            .iter()
            .find(|capability| capability.id == "exec")
            .unwrap();
        assert!(exec.execution_mode.supports_session(), "{plugin}");
        assert_eq!(
            exec.session_handoff.as_ref().unwrap().purpose,
            voidb_core::PluginSessionPurpose::DatabaseTransaction,
            "{plugin}"
        );
    }
}

#[test]
fn generated_builtin_catalog_snapshot_covers_every_plugin_and_mode() {
    let mut snapshot = std::collections::BTreeMap::<String, [usize; 4]>::new();
    for capability in supported_capabilities(&catalog_fixture_discovery()) {
        let counts = snapshot.entry(capability.plugin_id.clone()).or_default();
        counts[0] += 1;
        match capability.execution_mode {
            CapabilityExecutionMode::Stateless => counts[1] += 1,
            CapabilityExecutionMode::SessionOnly => counts[2] += 1,
            CapabilityExecutionMode::Both => counts[3] += 1,
        }
    }

    assert_eq!(
        serde_json::to_value(snapshot).expect("serialize catalog snapshot"),
        json!({
            "duckdb": [9, 7, 0, 2],
            "mysql": [9, 7, 0, 2],
            "postgres": [9, 7, 0, 2],
            "redis": [11, 7, 3, 1],
            "sqlite": [9, 7, 0, 2],
            "ssh": [15, 6, 7, 2],
            "sync": [6, 6, 0, 0],
        })
    );
}

#[test]
fn execution_mode_filters_include_capabilities_supported_by_both_transports() {
    let definitions =
        resolved_authorization_capabilities(Some("ssh")).expect("ssh fixture catalog");
    let terminal = find_capability(&definitions, "terminal_read");
    let exec = find_capability(&definitions, "exec");
    let diagnostics = find_capability(&definitions, "diagnostics");

    assert!(capability_matches_execution_modes(
        exec,
        &[CapabilityExecutionMode::Stateless]
    ));
    assert!(capability_matches_execution_modes(
        exec,
        &[CapabilityExecutionMode::SessionOnly]
    ));
    assert!(capability_matches_execution_modes(
        exec,
        &[CapabilityExecutionMode::Both]
    ));
    assert!(!capability_matches_execution_modes(
        terminal,
        &[CapabilityExecutionMode::Stateless]
    ));
    assert!(capability_matches_execution_modes(
        terminal,
        &[CapabilityExecutionMode::SessionOnly]
    ));
    assert!(capability_matches_execution_modes(
        diagnostics,
        &[CapabilityExecutionMode::Stateless]
    ));
    assert!(!capability_matches_execution_modes(
        diagnostics,
        &[CapabilityExecutionMode::SessionOnly]
    ));

    let list = InvokeCliPlugin::new()
        .commands()
        .into_iter()
        .find(|command| command.get_name() == "list")
        .expect("list command")
        .try_get_matches_from([
            "list",
            "--execution-mode",
            "stateless",
            "--execution-mode",
            "session_only",
            "--format",
            "table",
        ])
        .expect("mode filters parse");
    assert_eq!(
        execution_mode_filters(&list),
        vec![
            CapabilityExecutionMode::Stateless,
            CapabilityExecutionMode::SessionOnly,
        ]
    );
    assert_eq!(
        catalog_output_format(&list).expect("table format"),
        InvokeCatalogOutputFormat::Table
    );
}

#[test]
fn capability_summaries_include_execution_mode_and_handoff() {
    let terminal = resolved_authorization_capabilities(Some("ssh"))
        .expect("ssh fixture catalog")
        .into_iter()
        .find(|capability| capability.id == "terminal_read")
        .expect("terminal capability");
    let encoded = serde_json::to_value(CapabilitySummary::from(terminal))
        .expect("serialize capability summary");

    assert_eq!(encoded["execution_mode"], "session_only");
    assert_eq!(
        encoded["session_handoff"]["purpose"]["kind"],
        "interactive_terminal"
    );
    assert!(
        encoded["session_handoff"]["capabilities"]
            .as_array()
            .is_some_and(|capabilities| capabilities.len() == 5)
    );
    let keys = encoded
        .as_object()
        .expect("summary object")
        .keys()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        keys,
        [
            "authorization",
            "connection_required",
            "default_timeout_ms",
            "description",
            "destructive",
            "execution_mode",
            "id",
            "permissions",
            "plugin_id",
            "qualified_id",
            "required_secret_classes",
            "risk",
            "session_handoff",
            "streaming",
            "supports_dry_run",
            "supports_session",
            "supports_stateless",
        ]
        .into_iter()
        .map(str::to_string)
        .collect()
    );
    assert_eq!(encoded["supports_stateless"], false);
    assert_eq!(encoded["supports_session"], true);
    assert!(encoded["permissions"].is_array());
    assert!(encoded["required_secret_classes"].is_array());

    let table = capability_list_table(&[CapabilitySummary::from(
        resolved_authorization_capabilities(Some("ssh"))
            .expect("ssh fixture catalog")
            .into_iter()
            .find(|capability| capability.id == "terminal_read")
            .expect("terminal capability"),
    )]);
    assert!(table.starts_with("Capability\tMode\tRisk\tStream\tProfile\tSession purpose"));
    assert!(table.contains("ssh.terminal_read\tsession_only"));
    assert!(table.contains("interactive_terminal"));
}

#[tokio::test]
async fn session_only_one_shot_failure_precedes_profile_resolution_and_guides_handoff() {
    let ctx = CliContext::new(AppConfig::default());
    let error = run_invocation_with_discovery_and_profiles(
        &ctx,
        InvokeRunOptions {
            capability_ref: "ssh.terminal_read".into(),
            profile_ref: "name:missing-profile".into(),
            input: json!({}),
            timeout_ms: None,
            dry_run: false,
            destructive_ack: false,
            page_limit: None,
            page_cursor: None,
        },
        &catalog_fixture_discovery(),
        &[],
    )
    .await
    .expect_err("session-only capability must not reach profile resolution");

    assert_eq!(error.code, "validation.execution_mode_mismatch");
    assert_eq!(error.details["declared_execution_mode"], "session_only");
    assert_eq!(
        error.details["session_handoff"]["purpose"]["kind"],
        "interactive_terminal"
    );
    let authorize = error.details["authorize_args"]
        .as_array()
        .expect("authorize command");
    assert!(authorize.iter().any(|argument| argument == "session_only"));
    assert!(
        authorize
            .iter()
            .any(|argument| argument == "ssh.terminal_read")
    );
    let session_open = error.details["session_open_args"]
        .as_array()
        .expect("session open command");
    assert!(
        session_open
            .iter()
            .any(|argument| argument == "interactive_terminal")
    );
    let encoded = serde_json::to_string(&*error).expect("serialize handoff error");
    for forbidden in ["master_password", "password-stdin", "credential_value"] {
        assert!(!encoded.contains(forbidden));
    }
    assert!(!encoded.contains("profile was not found"));
}

#[test]
fn side_effecting_live_start_guidance_requests_grant_and_open_acknowledgements() {
    let definitions =
        resolved_authorization_capabilities(Some("ssh")).expect("ssh fixture catalog");
    let capability = find_capability(&definitions, "terminal_read");
    let guidance =
        session_handoff_guidance(capability, "id:profile:test", &catalog_fixture_discovery());

    assert_eq!(guidance["requires_destructive_acknowledgement"], true);
    assert_eq!(guidance["requires_start_acknowledgement"], false);
    assert_eq!(guidance["requires_destructive_grant"], true);
    let authorize = guidance["authorize_args"]
        .as_array()
        .expect("authorize args");
    assert!(
        authorize
            .iter()
            .any(|argument| argument == "--allow-destructive")
    );
    let open = guidance["session_open_args"]
        .as_array()
        .expect("session open args");
    assert!(open.iter().any(|argument| argument == "session"));
}

#[test]
fn ssh_release_candidate_catalog_is_bounded_and_gated() {
    let discovery = catalog_fixture_discovery();
    let ssh = capabilities_for_plugin("ssh", &discovery).expect("ssh capabilities");

    for id in ["exec", "sftp_put", "sftp_mkdir", "sftp_rm"] {
        let capability = find_capability(&ssh, id);
        assert!(capability.destructive, "ssh.{id} is destructive");
        assert!(
            capability.supports_dry_run,
            "ssh.{id} supports dry-run promotion gate"
        );
        assert_eq!(capability.risk, CapabilityRiskLevel::Destructive);
    }

    let ssh_exec = find_capability(&ssh, "exec");
    assert_eq!(ssh_exec.default_timeout_ms, Some(30_000));
    assert_eq!(
        ssh_exec.input_schema["properties"]["max_stdout_bytes"]["maximum"],
        json!(1024 * 1024)
    );
    assert_eq!(
        ssh_exec.output_schema["properties"]["stdout_truncated"]["type"],
        "boolean"
    );

    let ssh_list = find_capability(&ssh, "sftp_list");
    assert_eq!(
        ssh_list.output_schema["properties"]["limit"]["maximum"],
        json!(1_000)
    );
    assert_eq!(
        ssh_list.output_schema["properties"]["next_cursor"]["type"][0],
        "string"
    );

    let diagnostics = find_capability(&ssh, "diagnostics");
    let encoded = serde_json::to_string(diagnostics).expect("serialize diagnostics");
    assert!(!encoded.contains("password"));
    assert!(!encoded.contains("private_key_path"));
    assert!(!encoded.contains("host"));
}

#[test]
fn local_filesystem_boundary_capability_policy_is_scoped_and_explicit() {
    let discovery = catalog_fixture_discovery();
    let ssh = capabilities_for_plugin("ssh", &discovery).expect("ssh capabilities");

    let get = find_capability(&ssh, "sftp_get");
    assert_eq!(get.risk, CapabilityRiskLevel::Mutating);
    assert!(!get.authorization.capability_wide_allowed);
    assert_permission(get, "local.write");

    let put = find_capability(&ssh, "sftp_put");
    assert_eq!(put.risk, CapabilityRiskLevel::Destructive);
    assert!(!put.authorization.capability_wide_allowed);
    assert_permission(put, "local.read");

    for capability in [get, put] {
        let fields = &capability
            .authorization
            .approval_schema
            .as_ref()
            .expect("local path approval schema")
            .fields;
        assert!(fields.iter().any(|field| field.path == "/local_root"));
        assert!(fields.iter().any(|field| field.path == "/local_path"));
    }
}

#[test]
fn duckdb_and_redis_release_readiness_catalog_is_bounded_and_gated() {
    let discovery = catalog_fixture_discovery();
    let duckdb = capabilities_for_plugin("duckdb", &discovery).expect("duckdb capabilities");
    let redis = capabilities_for_plugin("redis", &discovery).expect("redis capabilities");

    for id in ["query", "explain", "tables", "describe_table"] {
        let capability = find_capability(&duckdb, id);
        assert!(!capability.destructive, "duckdb.{id} is read-only");
        assert!(!capability.supports_dry_run);
        assert_eq!(capability.risk, CapabilityRiskLevel::ReadOnly);
        assert_permission(capability, "connection.read");
    }

    let duckdb_exec = find_capability(&duckdb, "exec");
    assert!(duckdb_exec.destructive);
    assert!(duckdb_exec.supports_dry_run);
    assert_eq!(duckdb_exec.risk, CapabilityRiskLevel::Destructive);
    assert_permission(duckdb_exec, "sql.exec");
    assert_eq!(
        duckdb_exec.output_schema["properties"]["mutation_gate"]["type"],
        "object"
    );
    assert_eq!(
        duckdb_exec.output_schema["properties"]["rows_affected"]["type"],
        "integer"
    );

    let duckdb_query = find_capability(&duckdb, "query");
    assert_eq!(
        duckdb_query.output_schema["properties"]["row_limit"]["maximum"],
        json!(1_000)
    );
    assert_eq!(
        duckdb_query.output_schema["properties"]["next_cursor"]["type"][0],
        "string"
    );
    assert_eq!(
        duckdb_query.output_schema["properties"]["source_row_count"]["type"],
        "integer"
    );

    for id in ["keys", "get", "ttl", "info"] {
        let capability = find_capability(&redis, id);
        assert!(!capability.destructive, "redis.{id} is read-only");
        assert!(!capability.supports_dry_run);
        assert_eq!(capability.risk, CapabilityRiskLevel::ReadOnly);
        assert_permission(capability, "connection.read");
        assert_permission(capability, &format!("redis.{id}"));
    }

    for id in ["set", "del", "expire", "exec"] {
        let capability = find_capability(&redis, id);
        assert!(capability.destructive, "redis.{id} is destructive");
        assert!(
            capability.supports_dry_run,
            "redis.{id} supports dry-run promotion gate"
        );
        assert_eq!(capability.risk, CapabilityRiskLevel::Destructive);
        assert_permission(capability, "connection.write");
        assert_permission(capability, &format!("redis.{id}"));
    }

    let redis_keys = find_capability(&redis, "keys");
    assert_eq!(
        redis_keys.output_schema["properties"]["limit"]["maximum"],
        json!(200)
    );
    assert_eq!(
        redis_keys.output_schema["properties"]["next_cursor"]["type"][0],
        "string"
    );

    let redis_get = find_capability(&redis, "get");
    assert_eq!(
        redis_get.output_schema["properties"]["string_byte_limit"]["type"],
        "integer"
    );
    assert_eq!(
        redis_get.output_schema["properties"]["collection_item_limit"]["type"],
        "integer"
    );
    assert_eq!(
        redis_get.output_schema["properties"]["collection_has_more"]["type"],
        "boolean"
    );

    let redis_exec = find_capability(&redis, "exec");
    assert_eq!(
        redis_exec.output_schema["properties"]["output_truncated"]["type"],
        "boolean"
    );
    assert_eq!(
        redis_exec.output_schema["properties"]["output_byte_limit"]["type"],
        "integer"
    );
}

#[test]
fn success_envelope_is_versioned_for_agents() {
    let value = serde_json::to_value(success_envelope(InvokeListData {
        capabilities: Vec::new(),
    }))
    .expect("serialize envelope");

    assert_eq!(value["ok"], true);
    assert_eq!(value["schema_version"], INVOKE_CLI_SCHEMA_VERSION);
    assert_eq!(value["command"], "invoke");
    assert_eq!(value["warnings"], json!([]));
}

#[test]
fn error_envelope_is_versioned_for_agents() {
    let error = capability_error(
        CapabilityErrorCategory::Timeout,
        "timeout.invocation_timed_out",
        "Capability invocation exceeded the requested timeout.",
        json!({ "timeout_ms": 1_000 }),
        None,
        true,
    );
    let value = serde_json::to_value(JsonErrorEnvelope {
        ok: false,
        schema_version: INVOKE_CLI_SCHEMA_VERSION,
        command: "invoke",
        exit_code: exit_code_for_error(&error),
        error,
    })
    .expect("serialize envelope");

    assert_eq!(value["ok"], false);
    assert_eq!(value["schema_version"], INVOKE_CLI_SCHEMA_VERSION);
    assert_eq!(value["command"], "invoke");
    assert_eq!(value["exit_code"], 5);
    assert_eq!(value["error"]["category"], "timeout");
    assert_eq!(value["error"]["code"], "timeout.invocation_timed_out");
    assert_eq!(value["error"]["retryable"], true);
}

#[test]
fn parses_positive_timeout_durations_and_rejects_invalid_values() {
    assert_eq!(parse_duration_ms("250ms").expect("milliseconds"), 250);
    assert_eq!(parse_duration_ms("10s").expect("seconds"), 10_000);
    assert_eq!(parse_duration_ms("2m").expect("minutes"), 120_000);
    assert_eq!(parse_duration_ms("1h").expect("hours"), 3_600_000);

    let unit_error = parse_duration_ms("500").expect_err("unit required");
    assert_eq!(unit_error.code, "validation.timeout_unit_required");

    for invalid in ["0ms", "1.5s", "18446744073709551615h"] {
        let error = parse_duration_ms(invalid).expect_err("invalid timeout");
        assert_eq!(error.category, CapabilityErrorCategory::Validation);
        assert_eq!(error.code, "validation.timeout_invalid");
    }
}

#[test]
fn effective_timeout_prefers_override_and_rejects_zero() {
    let capability = resolved_authorization_capabilities(Some("sqlite"))
        .expect("sqlite fixture catalog")
        .into_iter()
        .find(|capability| capability.id == "query")
        .expect("sqlite query");

    assert_eq!(
        effective_timeout_ms(&capability, None).expect("default timeout"),
        (Some(30_000), InvokeTimeoutSource::CapabilityDefault)
    );
    assert_eq!(
        effective_timeout_ms(&capability, Some(750)).expect("override timeout"),
        (Some(750), InvokeTimeoutSource::Override)
    );
    let mut without_default = capability.clone();
    without_default.default_timeout_ms = None;
    assert_eq!(
        effective_timeout_ms(&without_default, None).expect("core timeout"),
        (
            Some(DEFAULT_INVOCATION_TIMEOUT_MS),
            InvokeTimeoutSource::CoreDefault
        )
    );
    let error = effective_timeout_ms(&capability, Some(0)).expect_err("zero timeout");
    assert_eq!(error.code, "validation.timeout_invalid");
}

#[test]
fn validates_caller_owned_ids_and_pagination_bounds() {
    validate_public_control_id("agent:run_01.part-2", "call-id").expect("public id");
    for invalid in ["", "contains space", "slash/not-allowed", "非-ascii"] {
        let error = validate_public_control_id(invalid, "call-id").expect_err("invalid id");
        assert_eq!(error.code, "validation.control_id_invalid");
    }

    validate_pagination_bounds(Some(MAX_INVOCATION_PAGE_LIMIT), Some("cursor"))
        .expect("bounded pagination");
    assert_eq!(
        validate_pagination_bounds(Some(0), None)
            .expect_err("zero page")
            .code,
        "validation.page_limit_invalid"
    );
    assert_eq!(
        validate_pagination_bounds(None, Some(&"x".repeat(MAX_INVOCATION_CURSOR_BYTES + 1)))
            .expect_err("large cursor")
            .code,
        "validation.page_cursor_too_large"
    );
}

#[test]
fn rejects_oversized_final_result_without_partial_payload() {
    let result = CapabilityInvocationResult {
        invocation_id: "caller-owned-01".into(),
        status: InvocationStatus::Succeeded,
        output: json!({ "payload": "x".repeat(256) }),
        output_summary: json!({ "rows": 1 }),
        page: Some(InvocationOutputPage {
            next_cursor: Some("next-page".into()),
        }),
    };

    let error = enforce_invocation_output_limit(&result, 32).expect_err("bounded result");
    assert_eq!(error.code, "plugin.output_limit_exceeded");
    assert_eq!(error.details["max_output_bytes"], 32);
    assert_eq!(error.details["continuation_available"], true);
    assert_eq!(error.details["next_cursor"], "next-page");
    assert!(error.details["serialized_bytes"].as_u64().unwrap() > 32);
    assert!(
        !serde_json::to_string(&error)
            .unwrap()
            .contains(&"x".repeat(64))
    );
}

#[test]
fn ndjson_events_are_sequenced_under_partial_writes_and_terminal_error() {
    #[derive(Default)]
    struct ChunkedWriter {
        bytes: Vec<u8>,
    }

    impl Write for ChunkedWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            let count = bytes.len().min(3);
            self.bytes.extend_from_slice(&bytes[..count]);
            Ok(count)
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    let mut emitter = NdjsonEmitter::new(ChunkedWriter::default(), "invoke-stream".into());
    emitter
        .emit(InvocationStreamEvent::Start {
            capability_ref: "fixture.stream".into(),
            timeout_ms: Some(1_000),
        })
        .expect("start");
    emitter
        .emit(InvocationStreamEvent::Data {
            value: json!({ "partial": true }),
        })
        .expect("partial data");
    emitter
        .emit(InvocationStreamEvent::Progress {
            message: Some("halfway".into()),
            fraction: Some(0.5),
            current: Some(1),
            total: Some(2),
        })
        .expect("progress");
    emitter
        .emit(InvocationStreamEvent::Warning {
            warning: json!({ "code": "fixture.warning" }),
        })
        .expect("warning");
    emitter
        .emit(InvocationStreamEvent::Error {
            error: capability_error(
                CapabilityErrorCategory::Cancellation,
                "cancellation.invocation_cancelled",
                "Invocation was cancelled.",
                Value::Null,
                None,
                false,
            ),
        })
        .expect("error");
    emitter
        .emit(InvocationStreamEvent::End {
            status: InvocationStatus::Cancelled,
            duration_ms: Some(25),
        })
        .expect("end");

    let output = String::from_utf8(emitter.writer.bytes).expect("utf-8 NDJSON");
    let events = output
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("NDJSON event"))
        .collect::<Vec<_>>();
    assert_eq!(events.len(), 6);
    assert_eq!(
        events
            .iter()
            .map(|event| event["sequence"].as_u64().expect("sequence"))
            .collect::<Vec<_>>(),
        vec![0, 1, 2, 3, 4, 5]
    );
    assert_eq!(events[0]["type"], "start");
    assert_eq!(events[1]["type"], "data");
    assert_eq!(events[2]["type"], "progress");
    assert_eq!(events[3]["type"], "warning");
    assert_eq!(events[4]["type"], "error");
    assert_eq!(events[5]["type"], "end");
    assert_eq!(events[5]["data"]["status"], "cancelled");
}

#[test]
fn profile_matcher_accepts_bare_immutable_profile_id() {
    let profile = migrated_profile_from_connection(&sqlite_connection("local", ":memory:"));

    assert!(profile_matches_ref(&profile, &profile.id));
}

#[tokio::test]
async fn dry_run_requires_capability_support() {
    let ctx = CliContext::new(AppConfig {
        connections: vec![sqlite_connection("local", ":memory:")],
        settings: Default::default(),
        ..Default::default()
    });

    let error = run_invocation(
        &ctx,
        InvokeRunOptions {
            capability_ref: "sqlite.query".into(),
            profile_ref: "local".into(),
            input: json!({ "sql": "select 1" }),
            timeout_ms: None,
            dry_run: true,
            destructive_ack: false,
            page_limit: None,
            page_cursor: None,
        },
    )
    .await
    .expect_err("dry-run unsupported");

    assert_eq!(error.category, CapabilityErrorCategory::Validation);
    assert_eq!(error.code, "validation.dry_run_not_supported");
    assert_eq!(error.details["qualified_id"], "sqlite.query");
}

#[tokio::test]
async fn rejects_invalid_input_before_handler_execution() {
    let ctx = CliContext::new(AppConfig {
        connections: vec![sqlite_connection("local", ":memory:")],
        settings: Default::default(),
        ..Default::default()
    });

    let error = run_invocation(
        &ctx,
        InvokeRunOptions {
            capability_ref: "sqlite.query".into(),
            profile_ref: "local".into(),
            input: json!({ "sql": 42 }),
            timeout_ms: None,
            dry_run: false,
            destructive_ack: false,
            page_limit: None,
            page_cursor: None,
        },
    )
    .await
    .expect_err("schema rejected");

    assert_eq!(error.category, CapabilityErrorCategory::Validation);
    assert_eq!(error.code, "validation.input_schema_failed");
}

#[tokio::test]
async fn external_dry_run_requires_plugin_runtime_after_policy_validation() {
    for (connection, capability_ref, input) in [
        (
            redis_connection(),
            "redis.set",
            json!({"key":"agent:test", "value":"value"}),
        ),
        (ssh_connection(), "ssh.exec", json!({"command":"uptime"})),
        (
            postgres_legacy_connection(),
            "postgres.exec",
            json!({"sql":"create table items(id integer)"}),
        ),
        (
            duckdb_connection("analytics", ":memory:"),
            "duckdb.exec",
            json!({"sql":"create table items(id integer)"}),
        ),
    ] {
        let profile_ref = connection.name.clone();
        let ctx = CliContext::new(AppConfig {
            connections: vec![connection],
            ..Default::default()
        });
        // A metadata-only candidate cannot execute; the service owns dry-run output.
        let error = run_invocation_with_discovery(
            &ctx,
            InvokeRunOptions {
                capability_ref: capability_ref.into(),
                profile_ref,
                input,
                timeout_ms: None,
                dry_run: true,
                destructive_ack: false,
                page_limit: None,
                page_cursor: None,
            },
            &catalog_fixture_discovery(),
        )
        .await
        .expect_err("runtime must be present even for a service dry-run");
        assert_eq!(
            error.error.code,
            "unavailable.process_plugin_command_unresolved"
        );
        assert_eq!(
            error.policy_decision.unwrap().outcome,
            PolicyDecisionOutcome::DryRunOnly
        );
    }
}

#[test]
fn ssh_policy_denials_have_redacted_audit_context() {
    {
        let (capability_ref, profile_ref, input, sensitive_value) = (
            "ssh.exec",
            "shell",
            json!({ "command": "cat /etc/shadow" }),
            "cat /etc/shadow",
        );
        let decision = CapabilityPolicyDecision {
            outcome: PolicyDecisionOutcome::RequiresAcknowledgement,
            risk: CapabilityRiskLevel::Destructive,
            reason: PolicyReason {
                category: CapabilityErrorCategory::Policy,
                code: "policy.destructive_denied_by_default".into(),
                message: "Profile policy blocks this destructive capability.".into(),
                details: json!({
                    "qualified_id": capability_ref,
                    "profile": profile_ref
                }),
                redaction: RedactionStatus::NotRequired,
            },
            required_approval: None,
            matched_approval_id: None,
        };
        let error = capability_error(
            CapabilityErrorCategory::Policy,
            "policy.destructive_denied_by_default",
            "Profile policy blocks this destructive capability.",
            json!({
                "qualified_id": capability_ref,
                "profile": profile_ref
            }),
            None,
            false,
        );
        let event = invoke_error_audit_event(
            Some(capability_ref),
            Some(profile_ref),
            Some(audit_json_summary(&input)),
            None,
            Some(&decision),
            &error,
        );

        assert_eq!(event.status, AuditEventStatus::Blocked);
        assert_eq!(
            event.metadata["policy_decision"]["outcome"],
            "requires_acknowledgement"
        );
        let encoded = encoded_audit_context(&event);
        assert!(!encoded.contains(sensitive_value));
    }
}

#[test]
fn local_filesystem_boundary_audit_denials_keep_only_opaque_scope_metadata() {
    {
        let (capability_ref, profile_ref, input, local_root, relative_path) = (
            "ssh.sftp_get",
            "shell",
            json!({
                "remote_path": "/remote/report.txt",
                "local_root": "/Users/private/approved-downloads",
                "local_path": "../outside.txt",
            }),
            "/Users/private/approved-downloads",
            "../outside.txt",
        );
        let error = CapabilityError {
            category: CapabilityErrorCategory::Permission,
            code: "permission.local_path_outside_scope".into(),
            message: "Local path access is outside the approved scope.".into(),
            details: json!({
                "local_scope_id": "local-scope:invoke-test",
                "access": "scan_directory",
            }),
            target: None,
            retryable: false,
            redaction: RedactionStatus::Applied,
        };
        let event = invoke_error_audit_event(
            Some(capability_ref),
            Some(profile_ref),
            Some(audit_json_summary(&input)),
            None,
            None,
            &error,
        );
        let encoded = serde_json::to_string(&event).expect("serialize local path audit");

        assert_eq!(event.status, AuditEventStatus::Blocked);
        assert_eq!(
            event.error.as_ref().unwrap().code,
            "permission.local_path_outside_scope"
        );
        assert!(encoded.contains("local-scope:invoke-test"));
        assert!(!encoded.contains(local_root));
        assert!(!encoded.contains(relative_path));
        assert!(!encoded.contains(".voidb-stage-"));
    }
}

#[test]
fn mutation_policy_denials_have_redacted_audit_context() {
    for (capability_ref, profile_ref, input, sensitive_value) in [
        (
            "ssh.exec",
            "shell",
            json!({
                "command": "rm -rf /tmp/test; echo ada@example.com"
            }),
            "ada@example.com",
        ),
        (
            "postgres.exec",
            "warehouse",
            json!({
                "sql": "DELETE FROM users WHERE email = 'ada@example.com'"
            }),
            "ada@example.com",
        ),
    ] {
        let decision = CapabilityPolicyDecision {
            outcome: PolicyDecisionOutcome::RequiresAcknowledgement,
            risk: CapabilityRiskLevel::Destructive,
            reason: PolicyReason {
                category: CapabilityErrorCategory::Policy,
                code: "policy.destructive_denied_by_default".into(),
                message: "Profile policy blocks this destructive capability.".into(),
                details: json!({
                    "qualified_id": capability_ref,
                    "profile": profile_ref
                }),
                redaction: RedactionStatus::NotRequired,
            },
            required_approval: None,
            matched_approval_id: None,
        };
        let error = capability_error(
            CapabilityErrorCategory::Policy,
            "policy.destructive_denied_by_default",
            "Profile policy blocks this destructive capability.",
            json!({
                "qualified_id": capability_ref,
                "profile": profile_ref
            }),
            None,
            false,
        );
        let event = invoke_error_audit_event(
            Some(capability_ref),
            Some(profile_ref),
            Some(audit_json_summary(&input)),
            None,
            Some(&decision),
            &error,
        );

        assert_eq!(event.status, AuditEventStatus::Blocked);
        assert_eq!(
            event.metadata["policy_decision"]["outcome"],
            "requires_acknowledgement"
        );
        let encoded = encoded_audit_context(&event);
        assert!(!encoded.contains(sensitive_value));
    }
}

#[tokio::test]
async fn destructive_ssh_exec_requires_ack_or_dry_run() {
    let ctx = CliContext::new(AppConfig {
        connections: vec![ssh_connection()],
        settings: Default::default(),
        ..Default::default()
    });

    let error = run_invocation(
        &ctx,
        InvokeRunOptions {
            capability_ref: "ssh.exec".into(),
            profile_ref: "shell".into(),
            input: json!({ "command": "touch /tmp/voidb-agent-test" }),
            timeout_ms: None,
            dry_run: false,
            destructive_ack: false,
            page_limit: None,
            page_cursor: None,
        },
    )
    .await
    .expect_err("destructive denied");

    assert_eq!(error.category, CapabilityErrorCategory::Policy);
    assert_eq!(error.code, "policy.destructive_denied_by_default");
    assert_eq!(error.details["qualified_id"], "ssh.exec");
}

#[test]
fn redacts_ssh_target_errors_with_connection_config() {
    let connection = ssh_public_key_connection();
    let error = capability_error(
        CapabilityErrorCategory::TargetSystem,
        "ssh.host_key_unknown",
        "ssh.host_key_unknown: bastion.internal.example /home/deploy/.ssh/id_ed25519 key-passphrase",
        json!({
            "host": "bastion.internal.example",
            "private_key_path": "/home/deploy/.ssh/id_ed25519",
            "passphrase": "key-passphrase"
        }),
        Some(TargetSystemFailure {
            system: Some("ssh".into()),
            code: Some("ssh.host_key_unknown".into()),
            message: Some(
                "bastion.internal.example rejected /home/deploy/.ssh/id_ed25519 key-passphrase"
                    .into(),
            ),
        }),
        false,
    );

    let redacted = redact_error(error, &connection);
    let encoded = serde_json::to_string(&redacted).expect("serialize");

    assert_eq!(redacted.redaction, RedactionStatus::Applied);
    assert!(!encoded.contains("bastion.internal.example"));
    assert!(!encoded.contains("/home/deploy/.ssh/id_ed25519"));
    assert!(!encoded.contains("key-passphrase"));
}

#[cfg(unix)]
#[test]
fn lists_process_plugin_capabilities_from_discovery() {
    let fixture = ProcessFixture::new("success");
    let capabilities = supported_capabilities(&fixture.discovery);

    assert!(
        capabilities
            .iter()
            .any(|capability| capability.qualified_id() == "fixture.echo")
    );
}

#[cfg(unix)]
#[tokio::test]
async fn invokes_process_plugin_from_discovery_fixture() {
    if crate::run_development_fixture_in_child(
        "builtin::invoke::tests::invokes_process_plugin_from_discovery_fixture",
    ) {
        return;
    }
    let fixture = ProcessFixture::new("success");
    let ctx = CliContext::new(AppConfig {
        connections: vec![process_connection()],
        settings: Default::default(),
        ..Default::default()
    });

    let profiles = voidb_core::connection_configs_to_profiles(&ctx.config.connections);
    let data = run_invocation_with_discovery_and_profiles_with_id(
        &ctx,
        InvokeRunOptions {
            capability_ref: "fixture.echo".into(),
            profile_ref: "fixture-profile".into(),
            input: json!({ "message": "hello" }),
            timeout_ms: None,
            dry_run: false,
            destructive_ack: false,
            page_limit: None,
            page_cursor: None,
        },
        &fixture.discovery,
        &profiles,
        "caller-owned-process-01".into(),
        false,
        "cancel-process-01".into(),
        DEFAULT_INVOCATION_OUTPUT_BYTES,
        watch::channel(false).1,
        None,
    )
    .await
    .expect("invoke process plugin");
    let encoded = serde_json::to_string(&data).expect("serialize data");

    assert_eq!(data.plugin_id, "fixture");
    assert_eq!(data.invocation_id, "caller-owned-process-01");
    assert_eq!(data.status, voidb_core::InvocationStatus::Succeeded);
    assert_eq!(data.output["ok"], true);
    assert_eq!(data.runtime.kind, "process_plugin");
    assert_eq!(data.runtime.transport, Some("stdio-jsonrpc"));
    assert_eq!(data.timing.timeout_ms, Some(1_000));
    assert_eq!(
        data.timing.timeout_source,
        InvokeTimeoutSource::CapabilityDefault
    );
    assert_eq!(data.credential_refs.len(), 1);
    assert!(!encoded.contains("super-secret"));
}

#[cfg(unix)]
#[tokio::test]
async fn process_plugin_target_failure_is_structured_and_redacted() {
    if crate::run_development_fixture_in_child(
        "builtin::invoke::tests::process_plugin_target_failure_is_structured_and_redacted",
    ) {
        return;
    }
    let fixture = ProcessFixture::new("target_failure");
    let ctx = CliContext::new(AppConfig {
        connections: vec![process_connection()],
        settings: Default::default(),
        ..Default::default()
    });

    let error = run_invocation_with_discovery(
        &ctx,
        InvokeRunOptions {
            capability_ref: "fixture.echo".into(),
            profile_ref: "fixture-profile".into(),
            input: json!({ "message": "hello" }),
            timeout_ms: Some(1_000),
            dry_run: false,
            destructive_ack: false,
            page_limit: None,
            page_cursor: None,
        },
        &fixture.discovery,
    )
    .await
    .expect_err("target failure");
    let encoded = serde_json::to_string(&*error).expect("serialize error");

    assert_eq!(error.category, CapabilityErrorCategory::TargetSystem);
    assert_eq!(error.code, "fixture.target_failed");
    assert_eq!(error.redaction, RedactionStatus::Applied);
    assert!(!encoded.contains("super-secret"));
}

#[test]
fn redacts_redis_target_errors_with_connection_config() {
    let connection = redis_connection();
    let error = capability_error(
        CapabilityErrorCategory::TargetSystem,
        "redis.connect_failed",
        "failed redis://:redis-secret@redis.internal.example/0",
        Value::Null,
        Some(TargetSystemFailure {
            system: Some("redis".into()),
            code: None,
            message: Some("redis-secret at redis.internal.example".into()),
        }),
        false,
    );

    let redacted = redact_error(error, &connection);
    let encoded = serde_json::to_string(&redacted).expect("serialize");

    assert_eq!(redacted.redaction, RedactionStatus::Applied);
    assert!(!encoded.contains("redis-secret"));
    assert!(!encoded.contains("redis.internal.example"));
}

#[test]
fn invoke_error_audit_event_keeps_redacted_error_and_input_shape_only() {
    let connection = redis_connection();
    let error = redact_error(
        capability_error(
            CapabilityErrorCategory::TargetSystem,
            "redis.connect_failed",
            "failed redis://:redis-secret@redis.internal.example/0",
            json!({ "password": "redis-secret" }),
            Some(TargetSystemFailure {
                system: Some("redis".into()),
                code: None,
                message: Some("redis-secret at redis.internal.example".into()),
            }),
            false,
        ),
        &connection,
    );
    let event = invoke_error_audit_event(
        Some("redis.set"),
        Some("cache"),
        Some(audit_json_summary(&json!({
            "key": "agent:test",
            "password": "redis-secret"
        }))),
        None,
        None,
        &error,
    );
    let encoded = serde_json::to_string(&event).expect("serialize audit event");

    assert_eq!(event.plugin_id.as_deref(), Some("redis"));
    assert_eq!(event.capability_id.as_deref(), Some("set"));
    assert_eq!(event.status, AuditEventStatus::Failed);
    assert!(encoded.contains("\"fields\""));
    assert!(!encoded.contains("redis-secret"));
    assert!(!encoded.contains("redis.internal.example"));
    assert!(!encoded.contains("agent:test"));
}

#[test]
fn invoke_policy_errors_are_audit_blocked() {
    let decision = CapabilityPolicyDecision {
        outcome: PolicyDecisionOutcome::RequiresAcknowledgement,
        risk: CapabilityRiskLevel::Destructive,
        reason: PolicyReason {
            category: CapabilityErrorCategory::Policy,
            code: "policy.destructive_denied_by_default".into(),
            message: "Profile policy blocks this destructive capability.".into(),
            details: json!({
                "qualified_id": "sqlite.exec",
                "profile": "local"
            }),
            redaction: RedactionStatus::NotRequired,
        },
        required_approval: None,
        matched_approval_id: None,
    };
    let error = capability_error(
        CapabilityErrorCategory::Policy,
        "policy.destructive_denied_by_default",
        "Profile policy blocks this destructive capability.",
        Value::Null,
        None,
        false,
    );
    let event = invoke_error_audit_event(
        Some("sqlite.exec"),
        Some("local"),
        Some(audit_json_summary(&json!({ "sql": "delete from users" }))),
        None,
        Some(&decision),
        &error,
    );
    let encoded = serde_json::to_string(&event).expect("serialize audit event");

    assert_eq!(event.status, AuditEventStatus::Blocked);
    assert_eq!(
        event.metadata["policy_decision"]["outcome"],
        "requires_acknowledgement"
    );
    assert_eq!(
        event.metadata["policy_decision"]["reason"]["code"],
        "policy.destructive_denied_by_default"
    );
    assert!(!encoded.contains("delete from users"));
}

#[test]
fn credential_grant_audit_events_link_refs_without_secret_material() {
    let connection = redis_connection();
    let error = redact_error(
        capability_error(
            CapabilityErrorCategory::TargetSystem,
            "redis.command_failed",
            "failed with redis-secret",
            json!({ "token": "redis-secret" }),
            Some(TargetSystemFailure {
                system: Some("redis".into()),
                code: Some("ERR".into()),
                message: Some("redis-secret".into()),
            }),
            false,
        ),
        &connection,
    );
    let grant = InvokeGrantAuditData {
        grant_id: "grant-01".into(),
        invocation_id: "invoke-01".into(),
        profile: ConnectionProfileRef::Name("cache".into()),
        plugin_id: "redis".into(),
        capability_id: "set".into(),
        credential_refs: vec![CredentialRef {
            id: "credential-ref-01".into(),
            class: CredentialClass::Password,
            label: Some("password".into()),
        }],
    };

    let event = credential_grant_audit_event(
        AuditOperation::CredentialGrantUsed,
        AuditEventStatus::Failed,
        &grant,
        Some(&error),
    );
    let encoded = serde_json::to_string(&event).expect("serialize grant event");

    assert_eq!(event.invocation_id.as_deref(), Some("invoke-01"));
    assert_eq!(event.grant_id.as_deref(), Some("grant-01"));
    assert_eq!(event.credential_refs[0].id, "credential-ref-01");
    assert_eq!(
        event.error.as_ref().map(|error| error.code.as_str()),
        Some("redis.command_failed")
    );
    assert!(!encoded.contains("redis-secret"));
}

#[test]
fn invoke_error_audit_event_records_post_grant_refs() {
    let error = capability_error(
        CapabilityErrorCategory::Timeout,
        "timeout.invocation_timed_out",
        "Capability timed out.",
        Value::Null,
        None,
        true,
    );
    let grant = InvokeGrantAuditData {
        grant_id: "grant-02".into(),
        invocation_id: "invoke-02".into(),
        profile: ConnectionProfileRef::Name("cache".into()),
        plugin_id: "redis".into(),
        capability_id: "set".into(),
        credential_refs: vec![CredentialRef {
            id: "credential-ref-02".into(),
            class: CredentialClass::Token,
            label: Some("token".into()),
        }],
    };
    let event = invoke_error_audit_event(
        Some("redis.set"),
        Some("cache"),
        Some(audit_json_summary(&json!({
            "key": "agent:test",
            "value": "token-value"
        }))),
        Some(&grant),
        None,
        &error,
    );
    let encoded = serde_json::to_string(&event).expect("serialize audit event");

    assert_eq!(event.status, AuditEventStatus::TimedOut);
    assert_eq!(event.invocation_id.as_deref(), Some("invoke-02"));
    assert_eq!(event.grant_id.as_deref(), Some("grant-02"));
    assert_eq!(event.credential_refs[0].id, "credential-ref-02");
    assert!(!encoded.contains("agent:test"));
    assert!(!encoded.contains("token-value"));
}

fn find_capability<'a>(
    capabilities: &'a [CapabilityDefinition],
    id: &str,
) -> &'a CapabilityDefinition {
    capabilities
        .iter()
        .find(|capability| capability.id == id)
        .unwrap_or_else(|| panic!("missing capability {id}"))
}

fn assert_permission(capability: &CapabilityDefinition, permission: &str) {
    assert!(
        capability
            .permissions
            .iter()
            .any(|candidate| candidate == permission),
        "{} missing permission {}",
        capability.qualified_id(),
        permission
    );
}

fn sqlite_connection(name: &str, path: &str) -> ConnectionConfig {
    ConnectionConfig {
        name: name.into(),
        db_type: DatabaseType::SQLite,
        plugin_id: None,
        plugin_config: Some(json!({ "path": path })),
    }
}

fn redis_connection() -> ConnectionConfig {
    ConnectionConfig {
        name: "cache".into(),
        db_type: DatabaseType::Plugin,
        plugin_id: Some("redis".into()),
        plugin_config: Some(json!({
            "host": "redis.internal.example",
            "port": 6379,
            "password": "redis-secret"
        })),
    }
}

fn postgres_legacy_connection() -> ConnectionConfig {
    ConnectionConfig {
        name: "warehouse".into(),
        db_type: DatabaseType::PostgreSQL,
        plugin_id: None,
        plugin_config: Some(json!({
            "host": "pg.internal.example",
            "port": 5432,
            "username": "agent",
            "password": "pg-secret",
            "database": "warehouse"
        })),
    }
}

fn duckdb_connection(name: &str, path: &str) -> ConnectionConfig {
    ConnectionConfig {
        name: name.into(),
        db_type: DatabaseType::Plugin,
        plugin_id: Some("duckdb".into()),
        plugin_config: Some(json!({ "path": path })),
    }
}

fn ssh_connection() -> ConnectionConfig {
    ConnectionConfig {
        name: "shell".into(),
        db_type: DatabaseType::Plugin,
        plugin_id: Some("ssh".into()),
        plugin_config: Some(json!({
            "host": "192.0.2.1",
            "port": 22,
            "username": "agent",
            "auth": {
                "type": "Password",
                "password": "ssh-secret"
            }
        })),
    }
}

fn ssh_public_key_connection() -> ConnectionConfig {
    ConnectionConfig {
        name: "shell-key".into(),
        db_type: DatabaseType::Plugin,
        plugin_id: Some("ssh".into()),
        plugin_config: Some(json!({
            "host": "bastion.internal.example",
            "port": 22,
            "username": "deploy",
            "auth": {
                "type": "PublicKey",
                "private_key_path": "/home/deploy/.ssh/id_ed25519",
                "passphrase": "key-passphrase"
            }
        })),
    }
}

#[cfg(unix)]
fn process_connection() -> ConnectionConfig {
    ConnectionConfig {
        name: "fixture-profile".into(),
        db_type: DatabaseType::Plugin,
        plugin_id: Some("fixture".into()),
        plugin_config: Some(json!({
            "endpoint": "fixture.internal.example",
            "password": "super-secret"
        })),
    }
}

fn catalog_fixture_discovery() -> ProcessPluginDiscovery {
    let mut discovery = authorization_discovery();
    discovery
        .candidates
        .retain(|candidate| !matches!(candidate.id.as_str(), "mongodb" | "elasticsearch"));
    discovery
}

#[cfg(unix)]
struct ProcessFixture {
    _temp: TempDir,
    discovery: ProcessPluginDiscovery,
}

#[cfg(unix)]
impl ProcessFixture {
    fn new(mode: &str) -> Self {
        let temp = TempDir::new("invoke-runtime");
        write_fixture_plugin(temp.path(), mode);
        let discovery = discover_process_plugins_from_roots(vec![ProcessPluginRoot::new(
            temp.path(),
            ProcessPluginRootKind::EnvPath,
            0,
        )]);
        assert!(
            discovery
                .candidates
                .iter()
                .any(|candidate| candidate.id == "fixture"
                    && candidate.state == ProcessPluginCandidateState::Available)
        );
        Self {
            _temp: temp,
            discovery,
        }
    }
}

#[cfg(unix)]
struct TempDir {
    path: PathBuf,
}

#[cfg(unix)]
impl TempDir {
    fn new(label: &str) -> Self {
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);

        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "voidb-invoke-process-{label}-{}-{id}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(unix)]
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[cfg(unix)]
fn write_fixture_plugin(root: &Path, mode: &str) {
    let plugin_dir = root.join("fixture");
    let schemas = plugin_dir.join("schemas");
    let bin = plugin_dir.join("bin");
    fs::create_dir_all(&schemas).expect("create schemas");
    fs::create_dir_all(&bin).expect("create bin");
    fs::write(schemas.join("profile.schema.json"), r#"{"type":"object"}"#)
        .expect("write profile schema");
    fs::write(
        schemas.join("echo-input.schema.json"),
        r#"{"type":"object","additionalProperties":true}"#,
    )
    .expect("write input schema");
    fs::write(
        schemas.join("echo-output.schema.json"),
        r#"{"type":"object","additionalProperties":true}"#,
    )
    .expect("write output schema");

    let script = bin.join("fixture-runtime");
    fs::write(&script, fixture_script()).expect("write script");
    make_executable(&script);

    let manifest = format!(
        r#"
id = "fixture"
name = "Fixture"
version = "0.1.0"
protocol_version = "1"

[runtime]
command = "fixture-runtime"
args = ["{mode}"]
transport = "stdio-jsonrpc"

[connections]
profile_schema = "schemas/profile.schema.json"
secret_classes = ["password"]

[[capabilities]]
id = "echo"
description = "Echo input."
input_schema = "schemas/echo-input.schema.json"
output_schema = "schemas/echo-output.schema.json"
permissions = ["connection.read"]
destructive = false
streaming = false
connection_required = true
required_secret_classes = ["password"]
supports_dry_run = false
default_timeout_ms = 1000
"#
    );
    fs::write(plugin_dir.join("plugin.toml"), manifest).expect("write manifest");
}

#[cfg(unix)]
fn fixture_script() -> &'static str {
    r#"#!/bin/sh
mode="$1"
while IFS= read -r line; do
  case "$line" in
    *voidb.initialize*)
      echo '{"jsonrpc":"2.0","id":"initialize","result":{"plugin_id":"fixture","protocol_version":"1","status":"ready"}}'
      ;;
    *voidb.health*)
      echo '{"jsonrpc":"2.0","id":"health","result":{"status":"ready","active_invocations":0}}'
      ;;
    *voidb.invoke*)
      invocation_id=$(printf '%s\n' "$line" | /usr/bin/sed -n 's/.*"invocation":.*"id":"\([^"]*\)".*/\1/p')
      case "$mode" in
        success)
          echo "{\"jsonrpc\":\"2.0\",\"id\":\"invoke\",\"result\":{\"invocation_id\":\"$invocation_id\",\"status\":\"succeeded\",\"output\":{\"ok\":true},\"output_summary\":{\"ok\":true}}}"
          ;;
        target_failure)
          echo '{"jsonrpc":"2.0","id":"invoke","error":{"code":-32010,"message":"Target failed","data":{"category":"target_system","code":"fixture.target_failed","message":"Target failed.","details":{},"retryable":false,"redaction":"applied"}}}'
          ;;
      esac
      ;;
  esac
done
"#
}

#[cfg(unix)]
fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = fs::metadata(path).expect("metadata").permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(path, permissions).expect("chmod");
}
