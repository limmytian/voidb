use serde_json::{Value, json};
use voidb_core::agent_authorization::AgentPrincipal;
use voidb_core::capability::{
    CapabilityAuthorizationMetadata, CapabilityDefinition, CapabilityExecutionMode,
    CapabilityRiskLevel,
};
use voidb_core::plugin::cli::CliPlugin;
use voidb_core::process_plugin::{
    ProcessPluginRoot, ProcessPluginRootKind, discover_process_plugins_from_roots,
};

use super::handlers::{
    McpServer, annotations_for_risk, broker_failure_result, grant_required_result,
    mcp_tool_for_capability, run_argv, stateless_catalog,
};
use super::wire::{INVALID_PARAMS, INVALID_REQUEST, MCP_PROTOCOL_VERSION, METHOD_NOT_FOUND};

fn empty_catalog_server() -> McpServer {
    McpServer::new(
        None,
        discover_process_plugins_from_roots(vec![ProcessPluginRoot::new(
            std::env::temp_dir().join(format!("voidb-mcp-tests-{}", uuid::Uuid::new_v4())),
            ProcessPluginRootKind::EnvPath,
            0,
        )]),
    )
}

fn request_line(id: u64, method: &str, params: Value) -> String {
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}).to_string()
}

fn parse_result(response: &str) -> Value {
    serde_json::from_str(response).expect("valid JSON-RPC response")
}

async fn initialized_server() -> McpServer {
    let mut server = empty_catalog_server();
    let responses = server
        .handle_frame(
            request_line(
                1,
                "initialize",
                json!({"protocolVersion": MCP_PROTOCOL_VERSION}),
            )
            .as_bytes(),
        )
        .await;
    assert_eq!(responses.len(), 1);
    let response = parse_result(&responses[0]);
    assert_eq!(response["result"]["protocolVersion"], MCP_PROTOCOL_VERSION);
    assert_eq!(response["result"]["serverInfo"]["name"], "voidb");
    let notifications = server
        .handle_frame(br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#)
        .await;
    assert!(notifications.is_empty());
    server
}

#[tokio::test]
async fn initializes_and_answers_ping() {
    let mut server = initialized_server().await;
    let responses = server
        .handle_frame(request_line(2, "ping", json!({})).as_bytes())
        .await;
    assert_eq!(responses.len(), 1);
    assert_eq!(parse_result(&responses[0])["result"], json!({}));
}

#[tokio::test]
async fn rejects_requests_before_initialize() {
    let mut server = empty_catalog_server();
    let responses = server
        .handle_frame(request_line(1, "tools/list", json!({})).as_bytes())
        .await;
    assert_eq!(
        parse_result(&responses[0])["error"]["code"],
        INVALID_REQUEST
    );
}

#[tokio::test]
async fn unsupported_protocol_version_falls_back_to_pinned_revision() {
    let mut server = empty_catalog_server();
    let responses = server
        .handle_frame(
            request_line(1, "initialize", json!({"protocolVersion": "1999-01-01"})).as_bytes(),
        )
        .await;
    let response = parse_result(&responses[0]);
    assert_eq!(response["result"]["protocolVersion"], MCP_PROTOCOL_VERSION);
}

#[tokio::test]
async fn unknown_method_is_method_not_found() {
    let mut server = initialized_server().await;
    let responses = server
        .handle_frame(request_line(3, "prompts/list", json!({})).as_bytes())
        .await;
    assert_eq!(
        parse_result(&responses[0])["error"]["code"],
        METHOD_NOT_FOUND
    );
}

#[tokio::test]
async fn malformed_frame_is_a_parse_error() {
    let mut server = empty_catalog_server();
    let responses = server.handle_frame(b"not json").await;
    assert_eq!(parse_result(&responses[0])["error"]["code"], -32700);
}

#[tokio::test]
async fn non_20_jsonrpc_is_rejected() {
    let mut server = empty_catalog_server();
    let responses = server
        .handle_frame(br#"{"jsonrpc":"1.0","id":1,"method":"ping"}"#)
        .await;
    assert_eq!(
        parse_result(&responses[0])["error"]["code"],
        INVALID_REQUEST
    );
}

#[tokio::test]
async fn tools_list_returns_valid_shape_even_with_empty_catalog() {
    let mut server = initialized_server().await;
    let responses = server
        .handle_frame(request_line(4, "tools/list", json!({})).as_bytes())
        .await;
    let response = parse_result(&responses[0]);
    assert!(response["result"]["tools"].is_array());
}

#[tokio::test]
async fn tools_call_unknown_tool_is_invalid_params() {
    let mut server = initialized_server().await;
    let responses = server
        .handle_frame(
            request_line(
                5,
                "tools/call",
                json!({"name": "nope.missing", "arguments": {}}),
            )
            .as_bytes(),
        )
        .await;
    assert_eq!(parse_result(&responses[0])["error"]["code"], INVALID_PARAMS);
}

#[tokio::test]
async fn tools_call_rejects_non_object_arguments() {
    let mut server = initialized_server().await;
    let responses = server
        .handle_frame(
            request_line(6, "tools/call", json!({"name": "a.b", "arguments": 42})).as_bytes(),
        )
        .await;
    assert_eq!(parse_result(&responses[0])["error"]["code"], INVALID_PARAMS);
}

#[test]
fn annotations_map_risk_levels() {
    assert_eq!(
        annotations_for_risk(CapabilityRiskLevel::ReadOnly),
        json!({"readOnlyHint": true})
    );
    assert_eq!(
        annotations_for_risk(CapabilityRiskLevel::Mutating),
        json!({})
    );
    assert_eq!(
        annotations_for_risk(CapabilityRiskLevel::Destructive),
        json!({"destructiveHint": true})
    );
    assert_eq!(
        annotations_for_risk(CapabilityRiskLevel::ExternalSideEffect),
        json!({"destructiveHint": true})
    );
}

#[test]
fn tool_definition_embeds_schema_and_profile_hint() {
    let mut capability = test_capability(CapabilityExecutionMode::Stateless);
    capability.connection_required = true;
    let tool = mcp_tool_for_capability(&capability);
    assert_eq!(tool["name"], "fixture.get");
    assert_eq!(tool["inputSchema"], capability.input_schema);
    assert_eq!(tool["annotations"], json!({"readOnlyHint": true}));
    assert!(
        tool["description"]
            .as_str()
            .unwrap()
            .contains("voidb_profile")
    );
}

#[test]
fn stateless_catalog_drops_session_only_capabilities() {
    let capabilities = vec![
        test_capability(CapabilityExecutionMode::Stateless),
        test_capability(CapabilityExecutionMode::SessionOnly),
        test_capability(CapabilityExecutionMode::Both),
    ];
    let catalog = stateless_catalog(capabilities);
    let modes: Vec<CapabilityExecutionMode> = catalog.iter().map(|c| c.execution_mode).collect();
    assert!(!modes.contains(&CapabilityExecutionMode::SessionOnly));
    assert_eq!(modes.len(), 2);
}

#[test]
fn run_argv_matches_agent_exec_shape() {
    let argv = run_argv("fixture.get", "id:profile-1", &json!({"key": "v"}), false);
    assert_eq!(
        argv,
        vec![
            "invoke",
            "run",
            "fixture.get",
            "--profile",
            "id:profile-1",
            "--input-json",
            "{\"key\":\"v\"}",
            "--format",
            "json",
        ]
    );
    let acknowledged = run_argv("fixture.exec", "id:profile-1", &json!({}), true);
    assert_eq!(acknowledged.last().map(String::as_str), Some("--yes"));
}

#[test]
fn grant_required_result_carries_guidance() {
    let result = grant_required_result("fixture.get", "system:fixture");
    assert_eq!(result["isError"], true);
    assert_eq!(
        result["structuredContent"]["error"]["code"],
        "authorization.grant_required"
    );
    let cli_args = result["structuredContent"]["guidance"]["cli_args"]
        .as_array()
        .expect("cli args");
    assert!(cli_args.contains(&json!("vb")));
    assert!(cli_args.contains(&json!("agent")));
    assert!(cli_args.contains(&json!("authorize")));
}

#[test]
fn broker_failure_result_is_a_retryable_execution_error() {
    let result = broker_failure_result("agent broker unreachable: no socket");
    assert_eq!(result["isError"], true);
    assert_eq!(result["structuredContent"]["error"]["retryable"], true);
}

#[test]
fn broker_responses_map_to_tool_results() {
    let ok = crate::agent_broker::BrokerResponse {
        protocol_version: 2,
        ok: true,
        exit_code: 0,
        stdout:
            r#"{"ok":true,"schema_version":"1","command":"invoke","data":{"output":{"rows":1}}}"#
                .into(),
        stderr: String::new(),
        error: None,
        error_code: None,
        data: None,
        remaining_uses: Some(4),
        expires_at: chrono::Utc::now(),
    };
    let result = super::handlers::tool_result_from_broker_response(&ok);
    assert_eq!(result["isError"], false);
    assert_eq!(result["structuredContent"]["output"], json!({"rows": 1}));

    let denied = crate::agent_broker::BrokerResponse {
        protocol_version: 2,
        ok: false,
        exit_code: 3,
        stdout: String::new(),
        stderr: "agent grant is read-only".into(),
        error: Some("policy denied".into()),
        error_code: Some("policy.read_only".into()),
        data: None,
        remaining_uses: None,
        expires_at: chrono::Utc::now(),
    };
    let result = super::handlers::tool_result_from_broker_response(&denied);
    assert_eq!(result["isError"], true);
    assert_eq!(
        result["structuredContent"]["error"]["code"],
        "policy.read_only"
    );
}

#[test]
fn serve_principal_requires_client_and_task_together() {
    let plugin = super::McpCliPlugin::new();
    let command = &plugin.commands()[0];
    let matches = command
        .clone()
        .try_get_matches_from(["serve", "--instance-id", "i1"])
        .expect("parses");
    assert!(super::mcp_principal(&matches).is_err());

    let matches = command
        .clone()
        .try_get_matches_from(["serve"])
        .expect("parses");
    assert_eq!(super::mcp_principal(&matches).unwrap(), None);

    let matches = command
        .clone()
        .try_get_matches_from(["serve", "--client-id", "mcp-client", "--task-id", "task-1"])
        .expect("parses");
    let principal = super::mcp_principal(&matches).unwrap().expect("principal");
    assert_eq!(principal.client_id, "mcp-client");
    assert_eq!(principal.task_id, "task-1");
    assert_eq!(
        principal,
        AgentPrincipal {
            client_id: "mcp-client".into(),
            task_id: "task-1".into(),
            instance_id: None,
        }
    );
}

fn test_capability(execution_mode: CapabilityExecutionMode) -> CapabilityDefinition {
    CapabilityDefinition {
        plugin_id: "fixture".into(),
        id: "get".into(),
        description: "Get a fixture value.".into(),
        input_schema: json!({"type": "object"}),
        output_schema: json!({"type": "object"}),
        permissions: vec![],
        authorization: CapabilityAuthorizationMetadata::default(),
        risk: CapabilityRiskLevel::ReadOnly,
        destructive: false,
        streaming: false,
        execution_mode,
        session_handoff: None,
        connection_required: false,
        required_secret_classes: vec![],
        supports_dry_run: false,
        default_timeout_ms: Some(1000),
    }
}
