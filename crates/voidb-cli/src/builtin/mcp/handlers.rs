//! MCP request handling for `vb mcp serve`.
//!
//! The server is a grant client, not a credential holder: it never receives
//! the master password and never decrypts profiles. `tools/call` finds an
//! active agent grant exactly like `vb agent exec` and forwards the call as a
//! broker `Run` request, which the broker executes in a scoped child process.
//! Denied or missing grants come back as MCP execution errors with structured
//! guidance, never as protocol failures.

use serde_json::{Value, json};
use voidb_core::agent_authorization::AgentPrincipal;
use voidb_core::capability::{CapabilityDefinition, CapabilityExecutionMode, CapabilityRiskLevel};
use voidb_core::process_plugin::ProcessPluginDiscovery;

use crate::agent_broker::{
    BrokerRequest, BrokerResponse, find_agent_exec_grant, send_request,
};

use super::wire::{
    INTERNAL_ERROR, INVALID_PARAMS, INVALID_REQUEST, MCP_PROTOCOL_VERSION, METHOD_NOT_FOUND,
    JsonRpcFrame, PARSE_ERROR, RESOURCE_NOT_FOUND, SUPPORTED_PROTOCOL_VERSIONS, failure,
    failure_with_data, success,
};

#[cfg(feature = "full")]
pub(crate) const CAPABILITY_MATRIX_URI: &str = "voidb://capability-matrix";
pub(crate) const PROFILES_URI: &str = "voidb://profiles";

/// Reserved tool arguments stripped before the capability input is forwarded.
pub(crate) const RESERVED_PROFILE_ARGUMENT: &str = "voidb_profile";
pub(crate) const RESERVED_DESTRUCTIVE_ACK_ARGUMENT: &str = "voidb_acknowledge_destructive";

pub(crate) struct McpServer {
    initialized: bool,
    principal: Option<AgentPrincipal>,
    discovery: ProcessPluginDiscovery,
}

impl McpServer {
    pub(crate) fn new(principal: Option<AgentPrincipal>, discovery: ProcessPluginDiscovery) -> Self {
        Self {
            initialized: false,
            principal,
            discovery,
        }
    }

    /// Handles one newline-delimited frame and returns zero or one response
    /// line. Notifications produce no response.
    pub(crate) async fn handle_frame(&mut self, frame: &[u8]) -> Vec<String> {
        let Ok(parsed) = serde_json::from_slice::<JsonRpcFrame>(frame) else {
            return vec![failure(&Value::Null, PARSE_ERROR, "parse error: invalid JSON frame")];
        };
        if parsed.jsonrpc.as_deref() != Some("2.0") {
            return vec![failure(
                parsed.id.as_ref().unwrap_or(&Value::Null),
                INVALID_REQUEST,
                "jsonrpc must be \"2.0\"",
            )];
        }
        if parsed.is_notification() {
            if parsed.method == "notifications/initialized" {
                self.initialized = true;
            }
            // Other notifications (cancelled, unknown) are ignored per spec.
            return Vec::new();
        }
        let id = parsed.id.clone().unwrap_or(Value::Null);
        if parsed.method == "initialize" {
            return vec![self.handle_initialize(&id, &parsed.params)];
        }
        if !self.initialized {
            return vec![failure(
                &id,
                INVALID_REQUEST,
                "server not initialized; send 'initialize' first",
            )];
        }
        match parsed.method.as_str() {
            "ping" => vec![success(&id, json!({}))],
            "tools/list" => vec![self.handle_tools_list(&id)],
            "tools/call" => vec![self.handle_tools_call(&id, &parsed.params).await],
            "resources/list" => vec![self.handle_resources_list(&id)],
            "resources/read" => vec![self.handle_resources_read(&id, &parsed.params).await],
            other => vec![failure(&id, METHOD_NOT_FOUND, format!("unknown method: {other}"))],
        }
    }

    fn handle_initialize(&self, id: &Value, params: &Value) -> String {
        let requested = params.get("protocolVersion").and_then(Value::as_str).unwrap_or("");
        let negotiated = if SUPPORTED_PROTOCOL_VERSIONS.contains(&requested) {
            requested.to_owned()
        } else {
            MCP_PROTOCOL_VERSION.to_owned()
        };
        success(
            id,
            json!({
                "protocolVersion": negotiated,
                "capabilities": {
                    "tools": {"listChanged": false},
                    "resources": {"listChanged": false},
                },
                "serverInfo": {
                    "name": "voidb",
                    "title": "VoidB Capability Gateway",
                    "version": env!("CARGO_PKG_VERSION"),
                },
                "instructions": "VoidB exposes installed capability catalogs as tools. Tool calls require an active agent grant: run 'vb agent authorize' (human approval) or 'vb agent exec' (one-shot) first. Destructive tools additionally need an allow-destructive grant plus the 'voidb_acknowledge_destructive' argument. Pass 'voidb_profile' to select a connection profile.",
            }),
        )
    }

    fn handle_tools_list(&self, id: &Value) -> String {
        let tools: Vec<Value> = supported_catalog(&self.discovery)
            .iter()
            .map(mcp_tool_for_capability)
            .collect();
        success(id, json!({ "tools": tools }))
    }

    async fn handle_tools_call(&mut self, id: &Value, params: &Value) -> String {
        let Some(name) = params.get("name").and_then(Value::as_str) else {
            return failure(id, INVALID_PARAMS, "tools/call requires a tool name");
        };
        let arguments = params.get("arguments").cloned().unwrap_or_else(|| json!({}));
        let Value::Object(mut arguments) = arguments else {
            return failure(id, INVALID_PARAMS, "tools/call arguments must be an object");
        };
        let profile_argument = arguments
            .remove(RESERVED_PROFILE_ARGUMENT)
            .and_then(|value| value.as_str().map(str::to_owned));
        let acknowledge = arguments
            .remove(RESERVED_DESTRUCTIVE_ACK_ARGUMENT)
            .and_then(|value| value.as_bool())
            .unwrap_or(false);
        let input = Value::Object(arguments);

        let Some(capability) = supported_catalog(&self.discovery)
            .into_iter()
            .find(|capability| capability.qualified_id() == name)
        else {
            return failure(id, INVALID_PARAMS, format!("Unknown tool: {name}"));
        };
        let profile_ref = if capability.connection_required {
            resolve_profile_argument(profile_argument.as_deref(), &capability.plugin_id)
        } else {
            // Connection-independent capabilities always execute under the
            // plugin's local system authorization scope; a requested profile
            // would be rejected by the invoke path.
            format!("system:{}", capability.plugin_id)
        };
        let argv = run_argv(name, &profile_ref, &input, acknowledge);

        let grant = match find_agent_exec_grant(&argv, self.principal.as_ref()).await {
            Ok(Some(grant)) => grant,
            Ok(None) => return success(id, grant_required_result(name, &profile_ref)),
            Err(error) => {
                return success(id, broker_failure_result(&format!("grant lookup failed: {error}")))
            }
        };
        let response = match send_request(
            &grant,
            BrokerRequest::Run {
                token: grant.token.clone(),
                argv,
            },
        )
        .await
        {
            Ok(response) => response,
            Err(error) => {
                return success(id, broker_failure_result(&format!("agent broker unreachable: {error}")))
            }
        };
        success(id, tool_result_from_broker_response(&response))
    }

    fn handle_resources_list(&self, id: &Value) -> String {
        #[allow(unused_mut)]
        let mut resources = vec![json!({
            "uri": PROFILES_URI,
            "name": "Connection Profiles",
            "mimeType": "application/json",
            "description": "Redacted profile references (ids, names, plugin ids). Never credentials or host details.",
        })];
        #[cfg(feature = "full")]
        resources.insert(
            0,
            json!({
                "uri": CAPABILITY_MATRIX_URI,
                "name": "Agent Capability Matrix",
                "mimeType": "text/markdown",
                "description": "Generated built-in Agent capability and experience inventory.",
            }),
        );
        success(id, json!({ "resources": resources }))
    }

    async fn handle_resources_read(&self, id: &Value, params: &Value) -> String {
        let Some(uri) = params.get("uri").and_then(Value::as_str) else {
            return failure(id, INVALID_PARAMS, "resources/read requires a uri");
        };
        match uri {
            PROFILES_URI => match read_profile_resources() {
                Ok(text) => success(
                    id,
                    json!({
                        "contents": [{"uri": uri, "mimeType": "application/json", "text": text}],
                    }),
                ),
                Err(_) => failure_with_data(
                    id,
                    INTERNAL_ERROR,
                    "profile store unavailable",
                    Some(json!({ "uri": uri })),
                ),
            },
            #[cfg(feature = "full")]
            CAPABILITY_MATRIX_URI => match crate::builtin::capability_matrix::build() {
                Ok(matrix) => success(
                    id,
                    json!({
                        "contents": [{
                            "uri": uri,
                            "mimeType": "text/markdown",
                            "text": crate::builtin::capability_matrix::render_markdown(&matrix),
                        }],
                    }),
                ),
                Err(_) => failure_with_data(
                    id,
                    INTERNAL_ERROR,
                    "capability matrix unavailable",
                    Some(json!({ "uri": uri })),
                ),
            },
            other => failure_with_data(
                id,
                RESOURCE_NOT_FOUND,
                "resource not found",
                Some(json!({ "uri": other })),
            ),
        }
    }
}

/// Resolves the requested profile to the immutable `id:<uuid>` form the
/// broker requires, mirroring `vb agent exec`. Unresolvable refs pass through
/// unchanged so the scoped child reports the standard
/// `validation.profile_ref_not_found` error.
fn resolve_profile_argument(requested: Option<&str>, plugin_id: &str) -> String {
    let Some(requested) = requested else {
        return format!("system:{plugin_id}");
    };
    let store = match voidb_core::LocalProfileStore::default_store() {
        Ok(store) => store,
        Err(_) => return requested.to_owned(),
    };
    let profiles = match store.load_profiles() {
        Ok(profiles) => profiles,
        Err(_) => return requested.to_owned(),
    };
    profiles
        .iter()
        .find(|profile| {
            profile.plugin_id == plugin_id
                && crate::builtin::invoke::profiles::profile_matches_ref(profile, requested)
        })
        .map(|profile| format!("id:{}", profile.id))
        .unwrap_or_else(|| requested.to_owned())
}

fn supported_catalog(discovery: &ProcessPluginDiscovery) -> Vec<CapabilityDefinition> {
    stateless_catalog(crate::builtin::invoke::discovery::supported_capabilities(
        discovery,
    ))
}

/// The MVP exposes stateless tools only; session-only capabilities fail
/// closed outside a broker session and would be dead tools.
pub(crate) fn stateless_catalog(
    capabilities: Vec<CapabilityDefinition>,
) -> Vec<CapabilityDefinition> {
    capabilities
        .into_iter()
        .filter(|capability| capability.execution_mode != CapabilityExecutionMode::SessionOnly)
        .collect()
}

/// Maps the stable VoidB risk levels onto MCP tool annotation hints. Hints are
/// advisory; enforcement always happens in the broker.
pub(crate) fn annotations_for_risk(risk: CapabilityRiskLevel) -> Value {
    match risk {
        CapabilityRiskLevel::ReadOnly => json!({ "readOnlyHint": true }),
        CapabilityRiskLevel::Mutating => json!({}),
        CapabilityRiskLevel::Destructive | CapabilityRiskLevel::ExternalSideEffect => {
            json!({ "destructiveHint": true })
        }
    }
}

pub(crate) fn mcp_tool_for_capability(capability: &CapabilityDefinition) -> Value {
    let input_schema = if capability.input_schema.is_object() {
        capability.input_schema.clone()
    } else {
        json!({ "type": "object" })
    };
    let mut description = capability.description.clone();
    if capability.connection_required {
        description.push_str(
            "\n\nVoidB: pass the optional 'voidb_profile' argument (profile id or name) to \
             choose the connection profile; without it the call targets the plugin's \
             system profile.",
        );
    }
    json!({
        "name": capability.qualified_id(),
        "description": description,
        "inputSchema": input_schema,
        "annotations": annotations_for_risk(capability.risk),
    })
}

pub(crate) fn run_argv(
    capability: &str,
    profile_ref: &str,
    input: &Value,
    acknowledge_destructive: bool,
) -> Vec<String> {
    let mut argv = vec![
        "invoke".to_string(),
        "run".to_string(),
        capability.to_string(),
        "--profile".to_string(),
        profile_ref.to_string(),
        "--input-json".to_string(),
        input.to_string(),
        "--format".to_string(),
        "json".to_string(),
    ];
    if acknowledge_destructive {
        argv.push("--yes".to_string());
    }
    argv
}

/// Builds the execution-error result for a call that has no active grant.
pub(crate) fn grant_required_result(capability: &str, profile_ref: &str) -> Value {
    let (plugin_id, capability_id) = capability.split_once('.').unwrap_or((capability, ""));
    json!({
        "content": [{
            "type": "text",
            "text": format!(
                "No active agent grant covers {capability}. Authorize it with 'vb agent authorize', then retry the tool call."
            ),
        }],
        "isError": true,
        "structuredContent": {
            "ok": false,
            "error": {
                "category": "auth",
                "code": "authorization.grant_required",
                "retryable": true,
                "message": format!("No active agent grant covers {capability} for this principal."),
            },
            "guidance": {
                "cli_args": [
                    "vb", "agent", "authorize",
                    "--profile", profile_ref,
                    "--plugin", plugin_id,
                    "--capability", capability_id,
                ],
            },
        },
    })
}

/// Builds the execution-error result for a broker-level failure (offline
/// broker, rejected grant, or a denied child execution).
pub(crate) fn broker_failure_result(message: &str) -> Value {
    json!({
        "content": [{"type": "text", "text": message.to_string()}],
        "isError": true,
        "structuredContent": {
            "ok": false,
            "error": {
                "category": "internal",
                "code": "internal.agent_broker_unavailable",
                "retryable": true,
                "message": message.to_string(),
            },
        },
    })
}

/// Converts a broker `Run` response into an MCP tool result. The broker
/// already executed `invoke run --format json` in a scoped child, so stdout is
/// the standard VoidB JSON envelope.
pub(crate) fn tool_result_from_broker_response(response: &BrokerResponse) -> Value {
    let stdout = response.stdout.trim();
    let parsed = parse_envelope(stdout);
    let envelope_ok = parsed
        .as_ref()
        .and_then(|envelope| envelope.get("ok"))
        .and_then(Value::as_bool)
        .unwrap_or(true);
    if response.ok && envelope_ok {
        let mut result = json!({
            "content": [{"type": "text", "text": stdout}],
            "isError": false,
        });
        let structured = parsed
            .as_ref()
            .and_then(|envelope| envelope.get("data"))
            .filter(|value| value.is_object())
            .cloned();
        if let Some(structured) = structured {
            result["structuredContent"] = structured;
        }
        result
    } else {
        let structured = parsed.unwrap_or_else(|| {
            json!({
                "ok": false,
                "error": {
                    "code": response.error_code.clone().unwrap_or_else(|| "internal.agent_broker".into()),
                    "message": response.error.clone().unwrap_or_default(),
                },
            })
        });
        let text = if !stdout.is_empty() {
            stdout.to_string()
        } else {
            let stderr = response.stderr.trim();
            if stderr.is_empty() {
                response
                    .error
                    .clone()
                    .unwrap_or_else(|| "agent broker execution failed".to_string())
            } else {
                stderr.to_string()
            }
        };
        json!({
            "content": [{"type": "text", "text": text}],
            "isError": true,
            "structuredContent": structured,
        })
    }
}

/// Parses the scoped child's JSON envelope, tolerating log lines that leak
/// around it on stdout (development builds emit tracing before the envelope).
fn parse_envelope(stdout: &str) -> Option<Value> {
    if let Ok(value) = serde_json::from_str(stdout) {
        return Some(value);
    }
    stdout
        .char_indices()
        .filter(|(_, byte)| *byte == '{')
        .find_map(|(index, _)| serde_json::from_str::<Value>(&stdout[index..]).ok())
        .filter(Value::is_object)
}

fn read_profile_resources() -> Result<String, ()> {
    let store = voidb_core::LocalProfileStore::default_store().map_err(|_| ())?;
    let profiles = store.load_profiles().map_err(|_| ())?;
    let references: Vec<Value> = profiles
        .iter()
        .map(|profile| {
            json!({
                "id": profile.id,
                "name": profile.name,
                "plugin_id": profile.plugin_id,
                "display_name": profile.display_name,
            })
        })
        .collect();
    serde_json::to_string_pretty(&references).map_err(|_| ())
}
