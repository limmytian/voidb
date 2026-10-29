#![cfg_attr(not(unix), allow(unused_imports))]

use anyhow::{Context, anyhow, bail};
use chrono::Utc;
use clap::{Arg, ArgAction, ArgMatches, Command};
use serde_json::{Value, json};
use uuid::Uuid;
use voidb_core::{
    AGENT_BROKER_PROTOCOL_VERSION, AgentPrincipal, AgentSessionCallRequest,
    AgentSessionCallStatusRequest, AgentSessionCallWaitRequest, AgentSessionCancelRequest,
    AgentSessionCloseAgentRequest, AgentSessionConcurrency, AgentSessionListRequest,
    AgentSessionOpenRequest, AgentSessionRef, AgentSessionRenewRequest, AgentSessionStatusRequest,
    CapabilityExecutionMode, PluginSessionPurpose, validate_agent_session_call_id,
};

use super::ledger::AgentGrantFile;
use super::runtime::{
    ensure_capability_wide_authorization_allowed, ensure_grant_execution_mode,
    ensure_jit_operation_allowed, ensure_unix, grant_uses_exhausted, load_grants, send_request,
};
use super::wire::{BrokerRequest, BrokerResponse};

pub(super) fn session_command() -> Command {
    let grant = || Arg::new("grant").long("grant").required(true);
    let session_id = || Arg::new("session-id").required(true);
    let generation = || {
        Arg::new("generation")
            .long("generation")
            .default_value("1")
            .value_parser(clap::value_parser!(u64))
    };
    Command::new("session")
        .about("Open and operate grant-scoped persistent plugin sessions")
        .subcommand_required(true)
        .subcommand(
            Command::new("open")
                .arg(grant())
                .arg(Arg::new("purpose").long("purpose").required(true))
                .arg(
                    Arg::new("capability")
                        .long("capability")
                        .action(ArgAction::Append),
                )
                .arg(
                    Arg::new("lease-seconds")
                        .long("lease-seconds")
                        .default_value("300")
                        .value_parser(clap::value_parser!(u64)),
                )
                .arg(
                    Arg::new("input-json")
                        .long("input-json")
                        .default_value("{}"),
                )
                .arg(
                    Arg::new("multiplexed")
                        .long("multiplexed")
                        .action(ArgAction::SetTrue),
                )
                .arg(
                    Arg::new("yes")
                        .long("yes")
                        .help("Acknowledge side effects caused by starting this live session")
                        .action(ArgAction::SetTrue),
                ),
        )
        .subcommand(
            Command::new("call")
                .arg(grant())
                .arg(session_id())
                .arg(generation())
                .arg(Arg::new("capability").long("capability").required(true))
                .arg(
                    Arg::new("call-id")
                        .long("call-id")
                        .value_name("ID")
                        .help("Caller-owned stable ID; supply it before launch when another process may cancel the call"),
                )
                .arg(
                    Arg::new("input-json")
                        .long("input-json")
                        .default_value("{}"),
                )
                .arg(Arg::new("yes").long("yes").action(ArgAction::SetTrue))
                .arg(
                    Arg::new("timeout-ms")
                        .long("timeout-ms")
                        .value_parser(clap::value_parser!(u64)),
                )
                .arg(
                    Arg::new("output-limit-bytes")
                        .long("output-limit-bytes")
                        .default_value("65536")
                        .value_parser(clap::value_parser!(usize)),
                ),
        )
        .subcommand(
            Command::new("start")
                .about("Start a session call and return its lifecycle immediately")
                .arg(grant())
                .arg(session_id())
                .arg(generation())
                .arg(Arg::new("capability").long("capability").required(true))
                .arg(
                    Arg::new("call-id")
                        .long("call-id")
                        .value_name("ID")
                        .help("Caller-owned stable ID; generated when omitted"),
                )
                .arg(
                    Arg::new("input-json")
                        .long("input-json")
                        .default_value("{}"),
                )
                .arg(Arg::new("yes").long("yes").action(ArgAction::SetTrue))
                .arg(
                    Arg::new("timeout-ms")
                        .long("timeout-ms")
                        .value_parser(clap::value_parser!(u64)),
                )
                .arg(
                    Arg::new("output-limit-bytes")
                        .long("output-limit-bytes")
                        .default_value("65536")
                        .value_parser(clap::value_parser!(usize)),
                ),
        )
        .subcommand(
            Command::new("status")
                .arg(grant())
                .arg(session_id())
                .arg(generation())
                .arg(
                    Arg::new("call-id")
                        .long("call-id")
                        .value_name("ID")
                        .help("Inspect one asynchronous call instead of session health"),
                ),
        )
        .subcommand(
            Command::new("wait")
                .about("Wait for one asynchronous call without blocking broker control traffic")
                .arg(grant())
                .arg(session_id())
                .arg(generation())
                .arg(Arg::new("call-id").long("call-id").required(true))
                .arg(
                    Arg::new("wait-timeout-ms")
                        .long("wait-timeout-ms")
                        .value_name("MILLISECONDS")
                        .value_parser(clap::value_parser!(u64)),
                ),
        )
        .subcommand(
            Command::new("list")
                .arg(grant())
                .arg(Arg::new("purpose").long("purpose"))
                .arg(
                    Arg::new("include-terminal")
                        .long("include-terminal")
                        .action(ArgAction::SetTrue),
                ),
        )
        .subcommand(
            Command::new("renew")
                .arg(grant())
                .arg(session_id())
                .arg(generation())
                .arg(
                    Arg::new("lease-seconds")
                        .long("lease-seconds")
                        .required(true)
                        .value_parser(clap::value_parser!(u64)),
                ),
        )
        .subcommand(
            Command::new("cancel")
                .arg(grant())
                .arg(session_id())
                .arg(generation())
                .arg(Arg::new("call-id").long("call-id").required(true))
                .arg(
                    Arg::new("timeout-ms")
                        .long("timeout-ms")
                        .value_name("MILLISECONDS")
                        .value_parser(clap::value_parser!(u64)),
                ),
        )
        .subcommand(
            Command::new("close")
                .arg(grant())
                .arg(session_id())
                .arg(generation())
                .arg(
                    Arg::new("reason")
                        .long("reason")
                        .default_value("user_closed"),
                )
                .arg(
                    Arg::new("timeout-ms")
                        .long("timeout-ms")
                        .value_name("MILLISECONDS")
                        .value_parser(clap::value_parser!(u64)),
                ),
        )
}

pub(super) async fn run_session_command(matches: &ArgMatches) -> anyhow::Result<i32> {
    ensure_unix()?;
    let (operation_name, operation) = matches
        .subcommand()
        .expect("session command requires an operation");
    let grant_id = operation
        .get_one::<String>("grant")
        .expect("required by clap");
    let grant = load_grants(true)?
        .into_iter()
        .find(|grant| grant.id == *grant_id)
        .ok_or_else(|| anyhow!("active agent grant '{grant_id}' was not found"))?;
    ensure_grant_principal(&grant, operation)?;
    let token = grant.token.clone();
    let request = match matches.subcommand_name().expect("subcommand") {
        "open" => BrokerRequest::SessionOpen {
            token,
            request: AgentSessionOpenRequest {
                purpose: parse_session_purpose(
                    operation
                        .get_one::<String>("purpose")
                        .expect("required by clap"),
                )?,
                capabilities: operation
                    .get_many::<String>("capability")
                    .map(|values| values.cloned().collect())
                    .unwrap_or_default(),
                lease_seconds: *operation
                    .get_one::<u64>("lease-seconds")
                    .expect("defaulted by clap"),
                concurrency: if operation.get_flag("multiplexed") {
                    AgentSessionConcurrency::Multiplexed
                } else {
                    AgentSessionConcurrency::Serialized
                },
                destructive_acknowledged: operation.get_flag("yes"),
                input: parse_session_json(operation, "input-json")?,
            },
        },
        "call" => BrokerRequest::SessionCall {
            token,
            request: session_call_request(operation)?,
        },
        "start" => BrokerRequest::SessionCallStart {
            token,
            request: session_call_request(operation)?,
        },
        "status" => {
            if let Some(call_id) = operation.get_one::<String>("call-id") {
                BrokerRequest::SessionCallStatus {
                    token,
                    request: AgentSessionCallStatusRequest {
                        session: session_ref(operation),
                        call_id: validated_session_call_id(call_id.clone())?,
                    },
                }
            } else {
                BrokerRequest::SessionStatus {
                    token,
                    request: AgentSessionStatusRequest {
                        session: session_ref(operation),
                    },
                }
            }
        }
        "wait" => BrokerRequest::SessionCallWait {
            token,
            request: AgentSessionCallWaitRequest {
                session: session_ref(operation),
                call_id: validated_session_call_id(
                    operation
                        .get_one::<String>("call-id")
                        .expect("required by clap")
                        .clone(),
                )?,
                timeout_ms: operation.get_one::<u64>("wait-timeout-ms").copied(),
            },
        },
        "list" => BrokerRequest::SessionList {
            token,
            request: AgentSessionListRequest {
                purpose: operation
                    .get_one::<String>("purpose")
                    .map(|purpose| parse_session_purpose(purpose))
                    .transpose()?,
                include_terminal: operation.get_flag("include-terminal"),
            },
        },
        "renew" => BrokerRequest::SessionRenew {
            token,
            request: AgentSessionRenewRequest {
                session: session_ref(operation),
                lease_seconds: *operation
                    .get_one::<u64>("lease-seconds")
                    .expect("required by clap"),
            },
        },
        "cancel" => BrokerRequest::SessionCancel {
            token,
            request: AgentSessionCancelRequest {
                session: session_ref(operation),
                call_id: validated_session_call_id(
                    operation
                        .get_one::<String>("call-id")
                        .expect("required by clap")
                        .clone(),
                )?,
                timeout_ms: operation.get_one::<u64>("timeout-ms").copied(),
            },
        },
        "close" => BrokerRequest::SessionClose {
            token,
            request: AgentSessionCloseAgentRequest {
                session: session_ref(operation),
                reason: operation
                    .get_one::<String>("reason")
                    .expect("defaulted by clap")
                    .clone(),
                timeout_ms: operation.get_one::<u64>("timeout-ms").copied(),
            },
        },
        _ => unreachable!("clap enforces session operations"),
    };
    let call_id = match &request {
        BrokerRequest::SessionCall { request, .. }
        | BrokerRequest::SessionCallStart { request, .. } => Some(request.call_id.clone()),
        BrokerRequest::SessionCallStatus { request, .. } => Some(request.call_id.clone()),
        BrokerRequest::SessionCallWait { request, .. } => Some(request.call_id.clone()),
        BrokerRequest::SessionCancel { request, .. } => Some(request.call_id.clone()),
        _ => None,
    };
    let response = send_session_request(&grant, request).await?;
    let error = response.error.as_ref().map(|message| {
        json!({
            "code": response.error_code.as_deref().unwrap_or("session.host_error"),
            "message": message,
        })
    });
    let message = session_response_message(operation_name, &response);
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "protocol_version": response.protocol_version,
            "operation": operation_name,
            "ok": response.ok,
            "data": response.data,
            "error": error,
            "message": message,
            "call_id": call_id,
            "grant": {
                "id": grant.id,
                "remaining_uses": response.remaining_uses,
                "expires_at": response.expires_at,
            }
        }))?
    );
    Ok(response.exit_code)
}

fn session_response_message(operation: &str, response: &BrokerResponse) -> Option<&'static str> {
    if !response.ok {
        return None;
    }
    match operation {
        "start" => Some("Call accepted; use status or wait with the returned call ID."),
        "wait"
            if response
                .data
                .as_ref()
                .and_then(|data| data.get("wait_timed_out"))
                .and_then(Value::as_bool)
                == Some(true) =>
        {
            Some("Call is still active; repeat wait or issue cancel/close.")
        }
        "wait" => Some("Call reached a terminal state."),
        "cancel" => Some("Cancellation was accepted or had already been requested."),
        "close" => Some("Session close completed; associated calls are terminal."),
        _ => None,
    }
}

async fn send_session_request(
    grant: &AgentGrantFile,
    request: BrokerRequest,
) -> anyhow::Result<BrokerResponse> {
    let requires_async_lifecycle = request_requires_current_broker_protocol(&request);
    if requires_async_lifecycle {
        let negotiated = send_request(
            grant,
            BrokerRequest::Inspect {
                token: grant.token.clone(),
            },
        )
        .await?;
        if !negotiated.ok {
            return Ok(negotiated);
        }
        if negotiated.protocol_version < AGENT_BROKER_PROTOCOL_VERSION {
            return Ok(BrokerResponse {
                protocol_version: negotiated.protocol_version,
                ok: false,
                exit_code: 6,
                stdout: String::new(),
                stderr: String::new(),
                error: Some(
                    "The active broker supports synchronous session calls only; renew the grant to launch a current broker before using start/status/wait."
                        .into(),
                ),
                error_code: Some("session.protocol_unsupported".into()),
                data: Some(json!({
                    "required_protocol_version": AGENT_BROKER_PROTOCOL_VERSION,
                    "selected_protocol_version": negotiated.protocol_version,
                })),
                remaining_uses: negotiated.remaining_uses,
                expires_at: negotiated.expires_at,
            });
        }
    }
    send_request(grant, request).await
}

pub(super) fn request_requires_current_broker_protocol(request: &BrokerRequest) -> bool {
    matches!(
        request,
        BrokerRequest::SessionCallStart { .. }
            | BrokerRequest::SessionCallStatus { .. }
            | BrokerRequest::SessionCallWait { .. }
    )
}

pub(super) fn session_call_request(
    matches: &ArgMatches,
) -> anyhow::Result<AgentSessionCallRequest> {
    Ok(AgentSessionCallRequest {
        session: session_ref(matches),
        call_id: session_call_id(matches)?,
        capability: matches
            .get_one::<String>("capability")
            .expect("required by clap")
            .clone(),
        input: parse_session_json(matches, "input-json")?,
        destructive_acknowledged: matches.get_flag("yes"),
        timeout_ms: matches.get_one::<u64>("timeout-ms").copied(),
        output_limit_bytes: *matches
            .get_one::<usize>("output-limit-bytes")
            .expect("defaulted by clap"),
    })
}

pub(super) fn session_ref(matches: &ArgMatches) -> AgentSessionRef {
    AgentSessionRef::new(
        matches
            .get_one::<String>("session-id")
            .expect("required by clap"),
        *matches
            .get_one::<u64>("generation")
            .expect("defaulted by clap"),
    )
}

pub(super) fn session_call_id(matches: &ArgMatches) -> anyhow::Result<String> {
    validated_session_call_id(
        matches
            .get_one::<String>("call-id")
            .cloned()
            .unwrap_or_else(|| format!("call:{}", Uuid::new_v4())),
    )
}

fn validated_session_call_id(call_id: String) -> anyhow::Result<String> {
    validate_agent_session_call_id(&call_id).map_err(anyhow::Error::from)?;
    Ok(call_id)
}

pub(super) fn ensure_grant_principal(
    grant: &AgentGrantFile,
    matches: &ArgMatches,
) -> anyhow::Result<()> {
    let Some(expected) = grant.principal_fingerprint.as_deref() else {
        return Ok(());
    };
    let client_id = matches
        .get_one::<String>("client-id")
        .ok_or_else(|| anyhow!("JIT grant execution requires --client-id and --task-id"))?;
    let task_id = matches
        .get_one::<String>("task-id")
        .ok_or_else(|| anyhow!("JIT grant execution requires --client-id and --task-id"))?;
    let principal = AgentPrincipal {
        client_id: client_id.clone(),
        task_id: task_id.clone(),
        instance_id: matches.get_one::<String>("instance-id").cloned(),
    };
    if principal.fingerprint()?.as_str() != expected {
        bail!("agent principal is outside the JIT grant binding");
    }
    Ok(())
}

pub(super) fn parse_session_json(matches: &ArgMatches, name: &str) -> anyhow::Result<Value> {
    let raw = matches.get_one::<String>(name).expect("defaulted by clap");
    serde_json::from_str(raw).with_context(|| format!("parse --{} JSON", name.replace('_', "-")))
}

fn parse_session_purpose(value: &str) -> anyhow::Result<PluginSessionPurpose> {
    Ok(match value {
        "interactive_terminal" => PluginSessionPurpose::InteractiveTerminal,
        "file_transfer" => PluginSessionPurpose::FileTransfer,
        "port_forward" => PluginSessionPurpose::PortForward,
        "database_query" => PluginSessionPurpose::DatabaseQuery,
        "database_transaction" => PluginSessionPurpose::DatabaseTransaction,
        "cache_command" => PluginSessionPurpose::CacheCommand,
        "log_stream" => PluginSessionPurpose::LogStream,
        "watch_stream" => PluginSessionPurpose::WatchStream,
        "infrastructure_client" => PluginSessionPurpose::InfrastructureClient,
        "sync_client" => PluginSessionPurpose::SyncClient,
        "capability_invocation" => PluginSessionPurpose::CapabilityInvocation,
        custom if custom.starts_with("plugin_defined:") => PluginSessionPurpose::PluginDefined(
            custom.trim_start_matches("plugin_defined:").to_owned(),
        ),
        _ => bail!("unsupported session purpose '{value}'"),
    })
}

pub(super) fn command_allowed(grant: &AgentGrantFile, argv: &[String]) -> anyhow::Result<()> {
    if grant.expires_at <= Utc::now() || grant_uses_exhausted(grant) {
        bail!("agent grant has expired or has no remaining uses");
    }
    if has_long_option(argv, "--input-file") {
        bail!("agent grants require inline --input-json; local input files are not allowed");
    }
    if has_long_option(argv, "--yes") && !grant.allow_destructive {
        bail!("agent grant does not permit destructive acknowledgements");
    }
    match argv {
        [group, command, profile_ref, rest @ ..] if group == "profile" && command == "test" => {
            ensure_profile_ref(grant, profile_ref)?;
            let plugin = scoped_option_value(rest, "--plugin", None)?;
            if plugin != grant.plugin_id {
                bail!("command plugin is outside the agent grant scope");
            }
            Ok(())
        }
        [group, command, capability, rest @ ..] if group == "invoke" && command == "run" => {
            let capability_plugin = capability
                .split_once('.')
                .map(|(plugin, _)| plugin)
                .ok_or_else(|| anyhow!("invoke capability must be qualified"))?;
            if capability_plugin != grant.plugin_id {
                bail!("capability plugin is outside the agent grant scope");
            }
            if !grant.capabilities.iter().any(|allowed| {
                allowed == "*"
                    || allowed == capability
                    || allowed == capability.split_once('.').unwrap().1
            }) {
                bail!("capability is outside the agent grant scope");
            }
            ensure_grant_execution_mode(grant, capability, CapabilityExecutionMode::Stateless)?;
            let profile_ref = scoped_option_value(rest, "--profile", Some("-p"))?;
            ensure_profile_ref(grant, profile_ref)?;
            if grant.authorization_scopes.is_empty() {
                ensure_capability_wide_authorization_allowed(grant, capability)?;
            } else {
                let input = scoped_option_value(rest, "--input-json", None)?;
                let input: Value = serde_json::from_str(input)
                    .context("JIT authorization requires valid inline JSON input")?;
                ensure_jit_operation_allowed(grant, capability, input)?;
            }
            Ok(())
        }
        _ => bail!("agent grants only permit 'profile test' and 'invoke run' commands"),
    }
}

fn scoped_option_value<'a>(
    args: &'a [String],
    long: &str,
    short: Option<&str>,
) -> anyhow::Result<&'a str> {
    let mut values = Vec::new();
    let mut index = 0;
    while index < args.len() {
        let argument = &args[index];
        if argument == long || short.is_some_and(|short| argument == short) {
            let value = args
                .get(index + 1)
                .ok_or_else(|| anyhow!("{long} requires a value"))?;
            values.push(value.as_str());
            index += 2;
            continue;
        }
        if let Some(value) = argument.strip_prefix(&format!("{long}=")) {
            values.push(value);
        } else if let Some(short) = short
            && let Some(value) = argument.strip_prefix(short)
            && !value.is_empty()
        {
            values.push(value.strip_prefix('=').unwrap_or(value));
        }
        index += 1;
    }
    match values.as_slice() {
        [value] if !value.is_empty() => Ok(value),
        [] => bail!("command must include exactly one {long}"),
        _ => bail!("command must not repeat {long}"),
    }
}

pub(super) fn has_long_option(args: &[String], option: &str) -> bool {
    args.iter()
        .any(|argument| argument == option || argument.starts_with(&format!("{option}=")))
}

fn ensure_profile_ref(grant: &AgentGrantFile, profile_ref: &str) -> anyhow::Result<()> {
    let matches =
        profile_ref == grant.profile_id || profile_ref == format!("id:{}", grant.profile_id);
    if matches {
        Ok(())
    } else {
        bail!("agent commands must use the immutable granted Profile ID")
    }
}
