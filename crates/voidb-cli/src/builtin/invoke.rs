//! Built-in generic capability invocation CLI.
//!
//! This command is the first agent-facing path that invokes capability handlers
//! by `<plugin>.<capability>` instead of through plugin-specific CLI commands.

use std::future::Future;
use std::io::{self, Write};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use chrono::Utc;
use clap::{Arg, ArgAction, ArgMatches, Command};
use serde::Serialize;
use serde_json::{Value, json};
use tokio::sync::{mpsc, watch};
use uuid::Uuid;
use voidb_core::capability::{
    CapabilityAuthorizationMetadata, CapabilityDefinition, CapabilityError,
    CapabilityErrorCategory, CapabilityExecutionMode, CapabilityInvocation,
    CapabilityInvocationResult, CapabilityPolicyDecision, CapabilityPolicyRequest,
    CapabilityRiskLevel, ConnectionInstancePurpose, ConnectionProfile, ConnectionProfileRef,
    CredentialClass, CredentialGrant, CredentialRef, InstanceReusePolicy,
    InvocationAcknowledgement, InvocationConnectionTarget, InvocationControls,
    InvocationOutputPage, InvocationStatus, InvocationStreamEnvelope, InvocationStreamEvent,
    Pagination, RedactionStatus, TargetSystemFailure,
};
use voidb_core::plugin::cli::{CliContext, CliPlugin};
use voidb_core::{
    AuditEvent, AuditEventStatus, AuditEventStore, AuditOperation, ConnectionConfig,
    DEFAULT_INVOCATION_OUTPUT_BYTES, DEFAULT_INVOCATION_PAGE_LIMIT, DEFAULT_INVOCATION_TIMEOUT_MS,
    LocalAuditStore, LocalProfileStore, MAX_INVOCATION_CURSOR_BYTES, MAX_INVOCATION_OUTPUT_BYTES,
    MAX_INVOCATION_PAGE_LIMIT, ProcessPluginCandidate, ProcessPluginCandidateState,
    ProcessPluginDiscovery, ProcessPluginRuntimeHost, VoidbError, audit_json_summary,
    discover_process_plugins, evaluate_capability_policy, grant_credentials_for_invocation,
    local_cli_actor, profile_names_equal, redact_text_with_json,
};
#[cfg(feature = "docker")]
use voidb_plugin_docker::{DockerConfig, docker_capabilities, invoke_docker_capability};
#[cfg(feature = "duckdb")]
use voidb_plugin_duckdb::{DuckDbConfig, duckdb_capabilities, invoke_duckdb_capability};
#[cfg(feature = "elasticsearch")]
use voidb_plugin_elasticsearch::{
    EsConfig, elasticsearch_capabilities, invoke_elasticsearch_capability,
};
#[cfg(feature = "kubernetes")]
use voidb_plugin_kubernetes::{K8sConfig, invoke_kubernetes_capability, kubernetes_capabilities};
#[cfg(feature = "mongodb")]
use voidb_plugin_mongodb::{MongoConfig, invoke_mongodb_capability, mongodb_capabilities};
#[cfg(feature = "mysql")]
use voidb_plugin_mysql::{MySqlConfig, invoke_mysql_capability, mysql_capabilities};
#[cfg(feature = "postgres")]
use voidb_plugin_postgres::{PostgresConfig, invoke_postgres_capability, postgres_capabilities};
#[cfg(feature = "redis")]
use voidb_plugin_redis::{RedisConfig, invoke_redis_capability, redis_capabilities};
#[cfg(feature = "s3")]
use voidb_plugin_s3::{config::S3Config, invoke_s3_capability, s3_capabilities};
#[cfg(feature = "sqlite")]
use voidb_plugin_sqlite::{SqliteConfig, invoke_sqlite_capability, sqlite_capabilities};
#[cfg(feature = "ssh")]
use voidb_plugin_ssh::{SshConfig, invoke_ssh_capability, ssh_capabilities};
#[cfg(feature = "sync")]
use voidb_plugin_sync::{invoke_sync_capability, sync_capabilities};

const SUPPORTED_INVOKE_PLUGINS: &[&str] = &[
    #[cfg(feature = "sqlite")]
    "sqlite",
    #[cfg(feature = "redis")]
    "redis",
    #[cfg(feature = "mysql")]
    "mysql",
    #[cfg(feature = "postgres")]
    "postgres",
    #[cfg(feature = "duckdb")]
    "duckdb",
    #[cfg(feature = "ssh")]
    "ssh",
    #[cfg(feature = "s3")]
    "s3",
    #[cfg(feature = "docker")]
    "docker",
    #[cfg(feature = "kubernetes")]
    "kubernetes",
    #[cfg(feature = "mongodb")]
    "mongodb",
    #[cfg(feature = "elasticsearch")]
    "elasticsearch",
    #[cfg(feature = "sync")]
    "sync",
];
const INVOKE_CLI_SCHEMA_VERSION: u32 = 1;
const INVOCATION_STREAM_CHANNEL_CAPACITY: usize = 32;
const INVOCATION_CANCEL_GRACE_MS: u64 = 2_000;
const MAX_PUBLIC_CONTROL_ID_BYTES: usize = 128;

pub struct InvokeCliPlugin;

impl InvokeCliPlugin {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl CliPlugin for InvokeCliPlugin {
    fn plugin_id(&self) -> &str {
        "invoke"
    }

    fn name(&self) -> &str {
        "Generic Capability Invocation"
    }

    fn commands(&self) -> Vec<Command> {
        vec![
            Command::new("list")
                .about("List generic capability metadata")
                .arg(format_arg())
                .arg(execution_mode_arg())
                .arg(
                    Arg::new("plugin")
                        .value_name("PLUGIN_ID")
                        .help("Only list capabilities for one plugin"),
                ),
            Command::new("describe")
                .about("Describe one generic capability as JSON")
                .arg(capability_arg())
                .arg(format_arg()),
            Command::new("matrix")
                .about("Generate the canonical built-in Agent capability and experience matrix")
                .arg(
                    Arg::new("format")
                        .long("format")
                        .value_name("FORMAT")
                        .value_parser(["json", "markdown"])
                        .default_value("markdown")
                        .help("Output stable JSON or the canonical generated Markdown document"),
                ),
            Command::new("run")
                .about("Invoke one generic capability as JSON")
                .arg(capability_arg())
                .arg(
                    Arg::new("profile")
                        .long("profile")
                        .short('p')
                        .required(true)
                        .value_name("PROFILE_REF")
                        .help("Profile ref: <name>, id:<profile-id>, or name:<name>"),
                )
                .arg(
                    Arg::new("input-json")
                        .long("input-json")
                        .value_name("JSON")
                        .conflicts_with("input-file")
                        .help("Inline JSON object for capability input"),
                )
                .arg(
                    Arg::new("input-file")
                        .long("input-file")
                        .value_name("PATH")
                        .help("Path to a JSON input file"),
                )
                .arg(
                    Arg::new("timeout-ms")
                        .long("timeout-ms")
                        .value_name("MILLISECONDS")
                        .conflicts_with("timeout")
                        .help("Execution timeout in milliseconds (legacy-compatible)"),
                )
                .arg(
                    Arg::new("timeout")
                        .long("timeout")
                        .value_name("DURATION")
                        .conflicts_with("timeout-ms")
                        .help("Execution timeout such as 250ms, 10s, 2m, or 1h"),
                )
                .arg(
                    Arg::new("dry-run")
                        .long("dry-run")
                        .action(ArgAction::SetTrue)
                        .help("Request dry-run behavior when the capability supports it"),
                )
                .arg(
                    Arg::new("yes")
                        .long("yes")
                        .action(ArgAction::SetTrue)
                        .help("Explicitly acknowledge a destructive invocation"),
                )
                .arg(
                    Arg::new("page-limit")
                        .long("page-limit")
                        .value_name("LIMIT")
                        .value_parser(clap::value_parser!(u32))
                        .help("Optional result page limit for paginated capabilities"),
                )
                .arg(
                    Arg::new("page-cursor")
                        .long("page-cursor")
                        .value_name("CURSOR")
                        .help("Optional result page cursor for paginated capabilities"),
                )
                .arg(
                    Arg::new("call-id")
                        .long("call-id")
                        .value_name("ID")
                        .help("Caller-owned public invocation ID; generated when omitted"),
                )
                .arg(
                    Arg::new("cancellation-token")
                        .long("cancellation-token")
                        .value_name("TOKEN")
                        .help("Opaque caller-owned cancellation token; never emitted or audited"),
                )
                .arg(
                    Arg::new("max-output-bytes")
                        .long("max-output-bytes")
                        .value_name("BYTES")
                        .value_parser(clap::value_parser!(u64))
                        .help("Maximum serialized invocation result size"),
                )
                .arg(run_format_arg()),
        ]
    }

    async fn execute(
        &self,
        command: &str,
        matches: &ArgMatches,
        ctx: &CliContext,
    ) -> Result<(), VoidbError> {
        match command {
            "list" => handle_list(matches),
            "describe" => handle_describe(matches),
            "matrix" => handle_matrix(matches),
            "run" => handle_run(matches, ctx).await,
            _ => Err(VoidbError::Plugin(format!("Unknown command: {}", command))),
        }
    }
}

fn handle_matrix(matches: &ArgMatches) -> Result<(), VoidbError> {
    #[cfg(not(feature = "full"))]
    {
        let _ = matches;
        Err(VoidbError::Plugin(
            "Capability matrix generation requires the 'full' feature flag: cargo run -p voidb-cli --features full -- invoke matrix".into(),
        ))
    }
    #[cfg(feature = "full")]
    {
        let matrix = super::capability_matrix::build()?;
        match matches.get_one::<String>("format").map(String::as_str) {
            Some("json") => print_json(&matrix),
            Some("markdown") | None => {
                println!("{}", super::capability_matrix::render_markdown(&matrix));
                Ok(())
            }
            Some(other) => Err(VoidbError::Plugin(format!(
                "Unsupported capability matrix format '{other}'"
            ))),
        }
    }
}

fn capability_arg() -> Arg {
    Arg::new("capability")
        .required(true)
        .value_name("PLUGIN.CAPABILITY")
        .help("Qualified capability ref, for example sqlite.query or redis.get")
}

fn format_arg() -> Arg {
    Arg::new("format")
        .long("format")
        .value_name("FORMAT")
        .value_parser(["json", "table"])
        .default_value("json")
        .help("Output format; json is stable for agents, table is human-readable")
}

fn execution_mode_arg() -> Arg {
    Arg::new("execution-mode")
        .long("execution-mode")
        .value_name("MODE")
        .value_parser(["stateless", "session_only", "both"])
        .action(ArgAction::Append)
        .help("Filter by supported execution mode; repeat to select multiple modes")
}

fn run_format_arg() -> Arg {
    Arg::new("format")
        .long("format")
        .value_name("FORMAT")
        .value_parser(["json", "ndjson"])
        .default_value("json")
        .help("Output format: legacy json or versioned streaming ndjson")
}

fn catalog_output_format(matches: &ArgMatches) -> Result<InvokeCatalogOutputFormat, VoidbError> {
    match matches.get_one::<String>("format").map(String::as_str) {
        Some("json") | None => Ok(InvokeCatalogOutputFormat::Json),
        Some("table") => Ok(InvokeCatalogOutputFormat::Table),
        Some(other) => Err(VoidbError::Plugin(format!(
            "Unsupported invoke catalog output format '{}'; use --format json or --format table",
            other
        ))),
    }
}

fn handle_list(matches: &ArgMatches) -> Result<(), VoidbError> {
    let format = catalog_output_format(matches)?;
    let plugin_filter = matches.get_one::<String>("plugin").map(String::as_str);
    let execution_modes = execution_mode_filters(matches);
    let discovery = discover_process_plugins();
    let capabilities = supported_capabilities(&discovery)
        .into_iter()
        .filter(|capability| plugin_filter.is_none_or(|plugin| capability.plugin_id == plugin))
        .filter(|capability| capability_matches_execution_modes(capability, &execution_modes))
        .map(CapabilitySummary::from)
        .collect::<Vec<_>>();

    match format {
        InvokeCatalogOutputFormat::Json => {
            print_json(&success_envelope(InvokeListData { capabilities }))
        }
        InvokeCatalogOutputFormat::Table => {
            println!("{}", capability_list_table(&capabilities));
            Ok(())
        }
    }
}

fn handle_describe(matches: &ArgMatches) -> Result<(), VoidbError> {
    let format = catalog_output_format(matches)?;
    let capability_ref = matches
        .get_one::<String>("capability")
        .expect("required by clap");
    let discovery = discover_process_plugins();

    match resolve_capability(capability_ref, &discovery) {
        Ok(capability) => match format {
            InvokeCatalogOutputFormat::Json => {
                print_json(&success_envelope(InvokeDescribeData { capability }))
            }
            InvokeCatalogOutputFormat::Table => {
                println!("{}", capability_description_table(&capability));
                Ok(())
            }
        },
        Err(error) => print_json(&JsonErrorEnvelope {
            ok: false,
            schema_version: INVOKE_CLI_SCHEMA_VERSION,
            command: "invoke",
            exit_code: exit_code_for_error(&error),
            error: *error,
        }),
    }
}

fn execution_mode_filters(matches: &ArgMatches) -> Vec<CapabilityExecutionMode> {
    matches
        .get_many::<String>("execution-mode")
        .into_iter()
        .flatten()
        .map(|mode| match mode.as_str() {
            "stateless" => CapabilityExecutionMode::Stateless,
            "session_only" => CapabilityExecutionMode::SessionOnly,
            "both" => CapabilityExecutionMode::Both,
            _ => unreachable!("clap validates execution modes"),
        })
        .collect()
}

fn capability_matches_execution_modes(
    capability: &CapabilityDefinition,
    filters: &[CapabilityExecutionMode],
) -> bool {
    filters.is_empty()
        || filters.iter().any(|filter| match filter {
            CapabilityExecutionMode::Stateless => capability.supports_stateless_execution(),
            CapabilityExecutionMode::SessionOnly => capability.supports_session_execution(),
            CapabilityExecutionMode::Both => {
                capability.execution_mode == CapabilityExecutionMode::Both
            }
        })
}

pub(crate) fn resolved_capability_risk(
    capability_ref: &str,
) -> Result<CapabilityRiskLevel, String> {
    let discovery = discover_process_plugins();
    resolve_capability(capability_ref, &discovery)
        .map(|capability| capability.effective_risk())
        .map_err(|error| error.message)
}

pub(crate) fn resolved_authorization_capabilities(
    plugin_id: Option<&str>,
) -> Result<Vec<CapabilityDefinition>, String> {
    let discovery = discover_process_plugins();
    match plugin_id {
        Some(plugin_id) => {
            capabilities_for_plugin(plugin_id, &discovery).map_err(|error| error.message)
        }
        None => Ok(supported_capabilities(&discovery)),
    }
}

async fn handle_run(matches: &ArgMatches, ctx: &CliContext) -> Result<(), VoidbError> {
    let output_format = run_output_format(matches);
    let (invocation_id, call_id_error) = match matches.get_one::<String>("call-id") {
        Some(call_id) => match validate_public_control_id(call_id, "call-id") {
            Ok(()) => (call_id.clone(), None),
            Err(error) => (next_invocation_id(), Some(error)),
        },
        None => (next_invocation_id(), None),
    };
    let capability_ref = matches
        .get_one::<String>("capability")
        .expect("required by clap");
    let mut ndjson = (output_format == InvokeOutputFormat::Ndjson)
        .then(|| NdjsonEmitter::new(io::stdout(), invocation_id.clone()));
    let parsed = match call_id_error.map_or_else(|| run_options_from_matches(matches), Err) {
        Ok(options) => options,
        Err(error) => {
            if let Some(emitter) = ndjson.as_mut() {
                emitter.emit(InvocationStreamEvent::Start {
                    capability_ref: capability_ref.clone(),
                    timeout_ms: None,
                })?;
            }
            append_invoke_error_audit(
                Some(capability_ref),
                matches.get_one::<String>("profile").map(String::as_str),
                None,
                None,
                None,
                &error,
            )?;
            let envelope = JsonErrorEnvelope {
                ok: false,
                schema_version: INVOKE_CLI_SCHEMA_VERSION,
                command: "invoke",
                exit_code: exit_code_for_error(&error),
                error: *error,
            };
            return print_run_error(output_format, ndjson.as_mut(), envelope);
        }
    };
    let options = parsed.invocation;
    let audit_context = InvokeAuditContext::from_options(&options, parsed.max_output_bytes);
    let effective_timeout_ms = preview_effective_timeout_ms(&options);
    if let Some(emitter) = ndjson.as_mut() {
        emitter.emit(InvocationStreamEvent::Start {
            capability_ref: capability_ref.clone(),
            timeout_ms: effective_timeout_ms,
        })?;
    }

    if output_format == InvokeOutputFormat::Json {
        eprintln!("invocation_id={invocation_id} timeout_ms={effective_timeout_ms:?}");
    }
    let (cancel_tx, cancel_rx) = watch::channel(false);
    let (stream_tx, mut stream_rx) = if output_format == InvokeOutputFormat::Ndjson {
        let (tx, rx) = mpsc::channel(INVOCATION_STREAM_CHANNEL_CAPACITY);
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };
    let invocation = run_invocation_with_id(
        ctx,
        options,
        invocation_id.clone(),
        output_format == InvokeOutputFormat::Ndjson,
        parsed.cancellation_token,
        parsed.max_output_bytes,
        cancel_rx,
        stream_tx,
    );
    tokio::pin!(invocation);
    let mut cancel_deadline = None;
    let result = loop {
        tokio::select! {
            result = &mut invocation => break result,
            event = receive_stream_event(&mut stream_rx) => {
                if let Some(event) = event {
                    ndjson
                        .as_mut()
                        .expect("stream receiver requires NDJSON emitter")
                        .emit(event)?;
                }
            }
            signal = tokio::signal::ctrl_c() => {
                if signal.is_err() {
                    continue;
                }
                if cancel_deadline.is_some() {
                    break Err(InvokeRunError::from(Box::new(invocation_cancelled_error(
                        &invocation_id,
                        "second_interrupt",
                    ))));
                }
                let _ = cancel_tx.send(true);
                cancel_deadline = Some(tokio::time::Instant::now() + Duration::from_millis(INVOCATION_CANCEL_GRACE_MS));
            }
            _ = wait_for_cancel_deadline(cancel_deadline), if cancel_deadline.is_some() => {
                break Err(InvokeRunError::from(Box::new(invocation_cancelled_error(
                    &invocation_id,
                    "grace_expired",
                ))));
            }
        }
    };
    if let Some(receiver) = stream_rx.as_mut() {
        while let Ok(event) = receiver.try_recv() {
            ndjson
                .as_mut()
                .expect("stream receiver requires NDJSON emitter")
                .emit(event)?;
        }
    }

    match result {
        Ok(data) => {
            append_credential_grant_success_audit(&data)?;
            append_invoke_success_audit(&data, &audit_context)?;
            print_run_success(output_format, ndjson.as_mut(), data)
        }
        Err(error) => {
            append_credential_grant_failure_audit(&error)?;
            append_invoke_error_audit(
                Some(&audit_context.capability_ref),
                Some(&audit_context.profile_ref),
                Some(audit_context.input_summary.clone()),
                error.grant.as_ref(),
                error.policy_decision.as_ref(),
                &error,
            )?;
            let exit_code = exit_code_for_error(&error);
            let error = error.into_error();
            let envelope = JsonErrorEnvelope {
                ok: false,
                schema_version: INVOKE_CLI_SCHEMA_VERSION,
                command: "invoke",
                exit_code,
                error,
            };
            print_run_error(output_format, ndjson.as_mut(), envelope)
        }
    }
}

async fn receive_stream_event(
    receiver: &mut Option<mpsc::Receiver<InvocationStreamEvent>>,
) -> Option<InvocationStreamEvent> {
    match receiver {
        Some(receiver) => receiver.recv().await,
        None => std::future::pending().await,
    }
}

async fn wait_for_cancel_deadline(deadline: Option<tokio::time::Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

fn invocation_cancelled_error(invocation_id: &str, fallback: &str) -> CapabilityError {
    capability_error(
        CapabilityErrorCategory::Cancellation,
        "cancellation.requested",
        "Caller requested capability invocation cancellation.",
        json!({
            "invocation_id": invocation_id,
            "fallback": fallback,
        }),
        None,
        false,
    )
}

fn run_options_from_matches(
    matches: &ArgMatches,
) -> Result<ParsedInvokeRunOptions, Box<CapabilityError>> {
    let capability_ref = matches
        .get_one::<String>("capability")
        .expect("required by clap")
        .to_string();
    let profile_ref = matches
        .get_one::<String>("profile")
        .expect("required by clap")
        .to_string();
    let input = parse_input(matches)?;
    let timeout_ms = parse_timeout_override(matches)?;
    let dry_run = matches.get_flag("dry-run");
    let destructive_ack = matches.get_flag("yes");
    let page_limit = matches.get_one::<u32>("page-limit").copied();
    let page_cursor = matches.get_one::<String>("page-cursor").cloned();
    validate_pagination_bounds(page_limit, page_cursor.as_deref())?;
    let cancellation_token = matches
        .get_one::<String>("cancellation-token")
        .cloned()
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    validate_public_control_id(&cancellation_token, "cancellation-token")?;
    let max_output_bytes = matches
        .get_one::<u64>("max-output-bytes")
        .copied()
        .unwrap_or(DEFAULT_INVOCATION_OUTPUT_BYTES);
    if max_output_bytes == 0 || max_output_bytes > MAX_INVOCATION_OUTPUT_BYTES {
        return Err(Box::new(capability_error(
            CapabilityErrorCategory::Validation,
            "validation.max_output_bytes_invalid",
            "Invocation output limit must be positive and within the host maximum.",
            json!({
                "requested_bytes": max_output_bytes,
                "maximum_bytes": MAX_INVOCATION_OUTPUT_BYTES,
            }),
            None,
            false,
        )));
    }

    Ok(ParsedInvokeRunOptions {
        invocation: InvokeRunOptions {
            capability_ref,
            profile_ref,
            input,
            timeout_ms,
            dry_run,
            destructive_ack,
            page_limit,
            page_cursor,
        },
        cancellation_token,
        max_output_bytes,
    })
}

fn validate_pagination_bounds(
    page_limit: Option<u32>,
    page_cursor: Option<&str>,
) -> Result<(), Box<CapabilityError>> {
    if page_limit.is_some_and(|limit| limit == 0 || limit > MAX_INVOCATION_PAGE_LIMIT) {
        return Err(Box::new(capability_error(
            CapabilityErrorCategory::Validation,
            "validation.page_limit_invalid",
            "Invocation page limit must be positive and within the host maximum.",
            json!({ "maximum": MAX_INVOCATION_PAGE_LIMIT }),
            None,
            false,
        )));
    }
    if page_cursor.is_some_and(|cursor| cursor.len() > MAX_INVOCATION_CURSOR_BYTES) {
        return Err(Box::new(capability_error(
            CapabilityErrorCategory::Validation,
            "validation.page_cursor_too_large",
            "Invocation page cursor exceeds the host byte limit.",
            json!({ "maximum_bytes": MAX_INVOCATION_CURSOR_BYTES }),
            None,
            false,
        )));
    }
    Ok(())
}

fn validate_public_control_id(value: &str, argument: &str) -> Result<(), Box<CapabilityError>> {
    let valid = !value.is_empty()
        && value.len() <= MAX_PUBLIC_CONTROL_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'));
    if valid {
        return Ok(());
    }
    Err(Box::new(capability_error(
        CapabilityErrorCategory::Validation,
        "validation.control_id_invalid",
        "Invocation control IDs must use public ASCII identifier characters.",
        json!({
            "argument": argument,
            "maximum_bytes": MAX_PUBLIC_CONTROL_ID_BYTES,
            "allowed": "A-Z a-z 0-9 - _ . :",
        }),
        None,
        false,
    )))
}

fn parse_timeout_override(matches: &ArgMatches) -> Result<Option<u64>, Box<CapabilityError>> {
    if let Some(raw) = matches.get_one::<String>("timeout-ms") {
        return parse_positive_duration_value(raw, 1, "timeout-ms").map(Some);
    }
    if let Some(raw) = matches.get_one::<String>("timeout") {
        return parse_duration_ms(raw).map(Some);
    }
    Ok(None)
}

fn parse_duration_ms(raw: &str) -> Result<u64, Box<CapabilityError>> {
    let value = raw.trim();
    let (number, multiplier) = if let Some(number) = value.strip_suffix("ms") {
        (number, 1)
    } else if let Some(number) = value.strip_suffix('s') {
        (number, 1_000)
    } else if let Some(number) = value.strip_suffix('m') {
        (number, 60_000)
    } else if let Some(number) = value.strip_suffix('h') {
        (number, 3_600_000)
    } else {
        return Err(Box::new(capability_error(
            CapabilityErrorCategory::Validation,
            "validation.timeout_unit_required",
            "Invocation timeout requires an explicit unit.",
            json!({
                "argument": "timeout",
                "accepted": ["<n>ms", "<n>s", "<n>m", "<n>h"],
            }),
            None,
            false,
        )));
    };
    parse_positive_duration_value(number, multiplier, "timeout")
}

fn parse_positive_duration_value(
    number: &str,
    multiplier: u64,
    argument: &str,
) -> Result<u64, Box<CapabilityError>> {
    let parsed = number.parse::<u64>().ok();
    let timeout_ms = parsed.and_then(|value| value.checked_mul(multiplier));
    match timeout_ms {
        Some(timeout_ms) if timeout_ms > 0 => Ok(timeout_ms),
        _ => Err(Box::new(capability_error(
            CapabilityErrorCategory::Validation,
            "validation.timeout_invalid",
            "Invocation timeout must be a positive duration.",
            json!({
                "argument": argument,
                "accepted": ["MILLISECONDS", "<n>ms", "<n>s", "<n>m", "<n>h"],
            }),
            None,
            false,
        ))),
    }
}

fn parse_input(matches: &ArgMatches) -> Result<Value, Box<CapabilityError>> {
    if let Some(input_json) = matches.get_one::<String>("input-json") {
        return serde_json::from_str(input_json).map_err(|error| {
            Box::new(capability_error(
                CapabilityErrorCategory::Validation,
                "validation.input_json_invalid",
                "Inline input JSON could not be parsed.",
                json!({ "message": error.to_string() }),
                None,
                false,
            ))
        });
    }

    if let Some(input_file) = matches.get_one::<String>("input-file") {
        let content = std::fs::read_to_string(input_file).map_err(|error| {
            Box::new(capability_error(
                CapabilityErrorCategory::Validation,
                "validation.input_file_unreadable",
                "Input JSON file could not be read.",
                json!({ "path": input_file, "message": error.to_string() }),
                None,
                false,
            ))
        })?;
        return serde_json::from_str(&content).map_err(|error| {
            Box::new(capability_error(
                CapabilityErrorCategory::Validation,
                "validation.input_json_invalid",
                "Input JSON file could not be parsed.",
                json!({ "path": input_file, "message": error.to_string() }),
                None,
                false,
            ))
        });
    }

    Ok(json!({}))
}

#[cfg(all(test, feature = "full"))]
#[allow(clippy::result_large_err)]
async fn run_invocation(
    ctx: &CliContext,
    options: InvokeRunOptions,
) -> Result<InvokeRunData, InvokeRunError> {
    let (_cancel_tx, cancel_rx) = watch::channel(false);
    run_invocation_with_id(
        ctx,
        options,
        next_invocation_id(),
        false,
        Uuid::new_v4().to_string(),
        DEFAULT_INVOCATION_OUTPUT_BYTES,
        cancel_rx,
        None,
    )
    .await
}

#[allow(clippy::result_large_err)]
#[allow(clippy::too_many_arguments)]
async fn run_invocation_with_id(
    ctx: &CliContext,
    options: InvokeRunOptions,
    invocation_id: String,
    stream: bool,
    cancellation_token: String,
    max_output_bytes: u64,
    cancellation: watch::Receiver<bool>,
    stream_events: Option<mpsc::Sender<InvocationStreamEvent>>,
) -> Result<InvokeRunData, InvokeRunError> {
    let discovery = discover_process_plugins();
    let profiles = profiles_from_context(ctx)?;
    run_invocation_with_discovery_and_profiles_with_id(
        ctx,
        options,
        &discovery,
        &profiles,
        invocation_id,
        stream,
        cancellation_token,
        max_output_bytes,
        cancellation,
        stream_events,
    )
    .await
}

#[cfg(all(test, feature = "full"))]
#[allow(clippy::result_large_err)]
async fn run_invocation_with_discovery(
    ctx: &CliContext,
    options: InvokeRunOptions,
    discovery: &ProcessPluginDiscovery,
) -> Result<InvokeRunData, InvokeRunError> {
    let profiles = voidb_core::connection_configs_to_profiles(&ctx.config.connections);
    run_invocation_with_discovery_and_profiles(ctx, options, discovery, &profiles).await
}

#[cfg(all(test, feature = "full"))]
#[allow(clippy::result_large_err)]
async fn run_invocation_with_discovery_and_profiles(
    ctx: &CliContext,
    options: InvokeRunOptions,
    discovery: &ProcessPluginDiscovery,
    profiles: &[ConnectionProfile],
) -> Result<InvokeRunData, InvokeRunError> {
    run_invocation_with_discovery_and_profiles_with_id(
        ctx,
        options,
        discovery,
        profiles,
        next_invocation_id(),
        false,
        Uuid::new_v4().to_string(),
        DEFAULT_INVOCATION_OUTPUT_BYTES,
        watch::channel(false).1,
        None,
    )
    .await
}

#[allow(clippy::result_large_err)]
#[allow(clippy::too_many_arguments)]
async fn run_invocation_with_discovery_and_profiles_with_id(
    ctx: &CliContext,
    options: InvokeRunOptions,
    discovery: &ProcessPluginDiscovery,
    profiles: &[ConnectionProfile],
    invocation_id: String,
    stream: bool,
    cancellation_token: String,
    max_output_bytes: u64,
    cancellation: watch::Receiver<bool>,
    stream_events: Option<mpsc::Sender<InvocationStreamEvent>>,
) -> Result<InvokeRunData, InvokeRunError> {
    let started = Instant::now();
    let capability = resolve_capability(&options.capability_ref, discovery)?;
    ensure_stateless_execution(&capability, &options.profile_ref, discovery)?;
    let (timeout_ms, timeout_source) =
        effective_timeout_ms(&capability, options.timeout_ms).map_err(InvokeRunError::from)?;
    let (profile, connection) =
        resolve_native_profile_connection(ctx, profiles, &options.profile_ref, &capability)?;

    validate_input_schema(&capability, &options.input)?;
    let requested_at = Utc::now();
    let controls = InvocationControls {
        timeout_ms,
        cancellation_token: Some(cancellation_token),
        max_output_bytes: Some(max_output_bytes),
        dry_run: options.dry_run,
        acknowledgement: options.destructive_ack.then(|| InvocationAcknowledgement {
            actor: local_cli_actor(),
            acknowledged_at: requested_at,
            reason: Some("cli --yes".into()),
            approval_id: None,
        }),
        approval_refs: Vec::new(),
        stream,
        page: invocation_page(options.page_limit, options.page_cursor),
    };
    let invocation = CapabilityInvocation {
        id: invocation_id,
        plugin_id: capability.plugin_id.clone(),
        capability_id: capability.id.clone(),
        connection: if capability.connection_required {
            InvocationConnectionTarget::FromProfile {
                profile: ConnectionProfileRef::Id(profile.id.clone()),
                purpose: ConnectionInstancePurpose::CapabilityInvocation,
                reuse: InstanceReusePolicy::Allow,
                options: Value::Null,
            }
        } else {
            InvocationConnectionTarget::Stateless
        },
        input: options.input,
        controls,
        actor: None,
        requested_at,
    };
    let policy_decision = evaluate_invoke_policy(&profile, &capability, &invocation);
    let policy_warnings = policy_warnings(&policy_decision);
    if let Some(error) = policy_decision.error() {
        return Err(InvokeRunError::with_policy(error, policy_decision));
    }

    let credential_grant =
        match grant_credentials_for_invocation(&profile, &capability, &invocation, requested_at) {
            Ok(grant) => grant,
            Err(error) => return Err(InvokeRunError::with_policy(error, policy_decision)),
        };
    let grant_audit = InvokeGrantAuditData {
        grant_id: credential_grant.id.clone(),
        invocation_id: invocation.id.clone(),
        profile: credential_grant.profile.clone(),
        plugin_id: credential_grant.plugin_id.clone(),
        capability_id: capability.id.clone(),
        credential_refs: credential_grant.credential_refs.clone(),
    };
    let result = invoke_capability(
        &capability,
        &connection,
        invocation,
        &credential_grant,
        discovery,
        cancellation,
        stream_events,
    )
    .await;
    let duration_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;

    match result {
        Ok(result) => {
            let serialized_bytes = enforce_invocation_output_limit(&result, max_output_bytes)
                .map_err(|error| {
                    InvokeRunError::with_grant(error, grant_audit.clone(), policy_decision.clone())
                })?;
            let continuation_available = result
                .page
                .as_ref()
                .and_then(|page| page.next_cursor.as_ref())
                .is_some();
            let (result, redaction) = redact_result(result, &connection);
            let runtime = runtime_summary(&capability);
            Ok(InvokeRunData {
                invocation_id: result.invocation_id,
                grant_id: grant_audit.grant_id,
                plugin_id: capability.plugin_id.clone(),
                capability_id: capability.id.clone(),
                profile: ConnectionProfileRef::Id(profile.id),
                status: result.status,
                output: result.output,
                output_summary: result.output_summary,
                page: result.page,
                timing: InvokeTiming {
                    duration_ms,
                    timeout_ms,
                    timeout_source,
                },
                credential_refs: grant_audit.credential_refs,
                redaction,
                runtime,
                output_limits: InvokeOutputLimits {
                    max_bytes: max_output_bytes,
                    serialized_bytes,
                    truncated: false,
                    continuation_available,
                },
                policy_decision,
                warnings: policy_warnings,
            })
        }
        Err(error) => Err(InvokeRunError::with_grant(
            redact_error(error, &connection),
            grant_audit,
            policy_decision,
        )),
    }
}

#[allow(clippy::result_large_err)]
fn ensure_stateless_execution(
    capability: &CapabilityDefinition,
    profile_ref: &str,
    discovery: &ProcessPluginDiscovery,
) -> Result<(), Box<CapabilityError>> {
    if capability.supports_stateless_execution() {
        return Ok(());
    }

    Err(Box::new(capability_error(
        CapabilityErrorCategory::Validation,
        "validation.execution_mode_mismatch",
        "Capability is session-only and cannot run through one-shot invoke.",
        session_handoff_guidance(capability, profile_ref, discovery),
        None,
        false,
    )))
}

pub(crate) fn session_handoff_guidance(
    capability: &CapabilityDefinition,
    profile_ref: &str,
    discovery: &ProcessPluginDiscovery,
) -> Value {
    let handoff_capabilities = capability
        .session_handoff
        .as_ref()
        .map(|handoff| handoff.capabilities.clone())
        .filter(|capabilities| !capabilities.is_empty())
        .unwrap_or_else(|| vec![capability.qualified_id()]);
    let requires_destructive_acknowledgement = handoff_capabilities.iter().any(|capability_ref| {
        resolve_capability(capability_ref, discovery)
            .is_ok_and(|definition| definition.requires_acknowledgement())
    });
    let requires_start_acknowledgement = capability
        .session_handoff
        .as_ref()
        .and_then(|handoff| handoff.live_session.as_ref())
        .is_some_and(|contract| contract.start_requires_acknowledgement());
    let requires_destructive_grant =
        requires_destructive_acknowledgement || requires_start_acknowledgement;
    let mut authorize_args = vec![
        "voidb-cli".to_string(),
        "agent".into(),
        "authorize".into(),
        "--profile".into(),
        profile_ref.to_string(),
        "--plugin".into(),
        capability.plugin_id.clone(),
        "--execution-mode".into(),
        "session_only".into(),
    ];
    for capability_ref in &handoff_capabilities {
        authorize_args.extend(["--capability".into(), capability_ref.clone()]);
    }
    if requires_destructive_grant {
        authorize_args.extend(["--allow-destructive".into(), "--yes".into()]);
    }

    let mut session_open_args = vec![
        "voidb-cli".to_string(),
        "agent".into(),
        "session".into(),
        "open".into(),
        "--grant".into(),
        "<grant-id>".into(),
    ];
    if let Some(handoff) = &capability.session_handoff {
        session_open_args.extend([
            "--purpose".into(),
            session_purpose_cli_name(&handoff.purpose),
        ]);
    }
    for capability_ref in &handoff_capabilities {
        session_open_args.extend(["--capability".into(), capability_ref.clone()]);
    }
    session_open_args.extend([
        "--lease-seconds".into(),
        "300".into(),
        "--input-json".into(),
        "{}".into(),
    ]);
    if requires_start_acknowledgement {
        session_open_args.push("--yes".into());
    }

    json!({
        "capability": capability.qualified_id(),
        "requested_execution_mode": "stateless",
        "declared_execution_mode": capability.execution_mode,
        "session_handoff": capability.session_handoff,
        "authorize_args": authorize_args,
        "session_open_args": session_open_args,
        "requires_destructive_acknowledgement": requires_destructive_acknowledgement,
        "requires_destructive_grant": requires_destructive_grant,
        "requires_start_acknowledgement": requires_start_acknowledgement,
    })
}

fn effective_timeout_ms(
    capability: &CapabilityDefinition,
    requested_timeout_ms: Option<u64>,
) -> Result<(Option<u64>, InvokeTimeoutSource), Box<CapabilityError>> {
    let (timeout_ms, source) = match requested_timeout_ms {
        Some(timeout_ms) => (Some(timeout_ms), InvokeTimeoutSource::Override),
        None => capability.default_timeout_ms.map_or(
            (
                Some(DEFAULT_INVOCATION_TIMEOUT_MS),
                InvokeTimeoutSource::CoreDefault,
            ),
            |timeout_ms| (Some(timeout_ms), InvokeTimeoutSource::CapabilityDefault),
        ),
    };
    if timeout_ms == Some(0) {
        return Err(Box::new(capability_error(
            CapabilityErrorCategory::Validation,
            "validation.timeout_invalid",
            "Invocation timeout must be a positive duration.",
            json!({
                "plugin_id": capability.plugin_id,
                "capability_id": capability.id,
                "source": source,
            }),
            None,
            false,
        )));
    }
    Ok((timeout_ms, source))
}

fn preview_effective_timeout_ms(options: &InvokeRunOptions) -> Option<u64> {
    let discovery = discover_process_plugins();
    resolve_capability(&options.capability_ref, &discovery)
        .ok()
        .and_then(|capability| effective_timeout_ms(&capability, options.timeout_ms).ok())
        .and_then(|(timeout_ms, _)| timeout_ms)
}

fn invocation_page(page_limit: Option<u32>, page_cursor: Option<String>) -> Option<Pagination> {
    if page_limit.is_none() && page_cursor.is_none() {
        return None;
    }

    Some(Pagination {
        limit: page_limit.unwrap_or(DEFAULT_INVOCATION_PAGE_LIMIT),
        cursor: page_cursor,
    })
}

#[allow(clippy::result_large_err)]
fn enforce_invocation_output_limit(
    result: &CapabilityInvocationResult,
    max_output_bytes: u64,
) -> Result<u64, CapabilityError> {
    let serialized_bytes = serde_json::to_vec(result)
        .map_err(|error| {
            capability_error(
                CapabilityErrorCategory::Internal,
                "internal.invocation_result_encode_failed",
                "Capability invocation result could not be encoded for output bounds checking.",
                json!({ "message": error.to_string() }),
                None,
                false,
            )
        })?
        .len() as u64;
    if serialized_bytes <= max_output_bytes {
        return Ok(serialized_bytes);
    }
    let next_cursor = result
        .page
        .as_ref()
        .and_then(|page| page.next_cursor.as_ref());
    Err(capability_error(
        CapabilityErrorCategory::Plugin,
        "plugin.output_limit_exceeded",
        "Capability invocation result exceeded the caller's output byte limit.",
        json!({
            "max_output_bytes": max_output_bytes,
            "serialized_bytes": serialized_bytes,
            "continuation_available": next_cursor.is_some(),
            "next_cursor": next_cursor,
        }),
        None,
        false,
    ))
}

#[allow(clippy::result_large_err)]
fn validate_input_schema(
    capability: &CapabilityDefinition,
    input: &Value,
) -> Result<(), Box<CapabilityError>> {
    jsonschema::validate(&capability.input_schema, input).map_err(|error| {
        Box::new(capability_error(
            CapabilityErrorCategory::Validation,
            "validation.input_schema_failed",
            "Capability input did not match its JSON schema.",
            json!({
                "plugin_id": capability.plugin_id,
                "capability_id": capability.id,
                "schema_error": error.to_string(),
            }),
            None,
            false,
        ))
    })
}

fn evaluate_invoke_policy(
    profile: &ConnectionProfile,
    capability: &CapabilityDefinition,
    invocation: &CapabilityInvocation,
) -> CapabilityPolicyDecision {
    evaluate_capability_policy(
        profile,
        capability,
        &CapabilityPolicyRequest {
            invocation_id: invocation.id.clone(),
            actor: invocation.actor.clone().unwrap_or_else(local_cli_actor),
            plugin_id: capability.plugin_id.clone(),
            capability_id: capability.id.clone(),
            risk: capability.effective_risk(),
            requested_at: invocation.requested_at,
            profile: Some(profile.profile_ref()),
            dry_run: invocation.controls.dry_run,
            acknowledgement: invocation.controls.acknowledgement.clone(),
            approvals: Vec::new(),
            input_summary: audit_json_summary(&invocation.input),
        },
    )
}

fn policy_warnings(policy_decision: &CapabilityPolicyDecision) -> Vec<InvokeWarning> {
    if policy_decision.reason.code == "policy.destructive_invocation_acknowledged" {
        vec![InvokeWarning {
            code: policy_decision.reason.code.clone(),
            message: policy_decision.reason.message.clone(),
            details: policy_decision.reason.details.clone(),
        }]
    } else {
        Vec::new()
    }
}

async fn invoke_builtin_capability(
    capability: &CapabilityDefinition,
    connection: &ConnectionConfig,
    invocation: CapabilityInvocation,
    mut cancellation: watch::Receiver<bool>,
) -> Result<CapabilityInvocationResult, CapabilityError> {
    let invocation = invoke_builtin_capability_inner(capability, connection, invocation);
    tokio::pin!(invocation);
    tokio::select! {
        biased;
        _ = cancellation_requested(&mut cancellation) => Err(capability_error(
            CapabilityErrorCategory::Cancellation,
            "cancellation.requested",
            "Caller requested capability invocation cancellation.",
            json!({
                "plugin_id": capability.plugin_id,
                "capability_id": capability.id,
            }),
            None,
            false,
        )),
        result = &mut invocation => result,
    }
}

async fn invoke_builtin_capability_inner(
    capability: &CapabilityDefinition,
    connection: &ConnectionConfig,
    invocation: CapabilityInvocation,
) -> Result<CapabilityInvocationResult, CapabilityError> {
    let timeout_ms = invocation.controls.timeout_ms;
    match capability.plugin_id.as_str() {
        #[cfg(feature = "sqlite")]
        "sqlite" => {
            let config = parse_sqlite_config(connection).map_err(|error| *error)?;
            invoke_with_timeout(
                invoke_sqlite_capability(&config, invocation),
                timeout_ms,
                &capability.plugin_id,
                &capability.id,
            )
            .await
        }
        #[cfg(feature = "redis")]
        "redis" => {
            let config = parse_redis_config(connection).map_err(|error| *error)?;
            invoke_with_timeout(
                invoke_redis_capability(&config, invocation),
                timeout_ms,
                &capability.plugin_id,
                &capability.id,
            )
            .await
        }
        #[cfg(feature = "mysql")]
        "mysql" => {
            let config = parse_mysql_config(connection).map_err(|error| *error)?;
            invoke_with_timeout(
                invoke_mysql_capability(&config, invocation),
                timeout_ms,
                &capability.plugin_id,
                &capability.id,
            )
            .await
        }
        #[cfg(feature = "postgres")]
        "postgres" => {
            let config = parse_postgres_config(connection).map_err(|error| *error)?;
            invoke_with_timeout(
                invoke_postgres_capability(&config, invocation),
                timeout_ms,
                &capability.plugin_id,
                &capability.id,
            )
            .await
        }
        #[cfg(feature = "duckdb")]
        "duckdb" => {
            let config = parse_duckdb_config(connection).map_err(|error| *error)?;
            invoke_with_timeout(
                invoke_duckdb_capability(&config, invocation),
                timeout_ms,
                &capability.plugin_id,
                &capability.id,
            )
            .await
        }
        #[cfg(feature = "ssh")]
        "ssh" => {
            let config = parse_ssh_config(connection).map_err(|error| *error)?;
            invoke_with_timeout(
                invoke_ssh_capability(&config, invocation),
                timeout_ms,
                &capability.plugin_id,
                &capability.id,
            )
            .await
        }
        #[cfg(feature = "s3")]
        "s3" => {
            let config = parse_s3_config(connection).map_err(|error| *error)?;
            invoke_with_timeout(
                invoke_s3_capability(&config, invocation),
                timeout_ms,
                &capability.plugin_id,
                &capability.id,
            )
            .await
        }
        #[cfg(feature = "docker")]
        "docker" => {
            let config = parse_docker_config(connection).map_err(|error| *error)?;
            invoke_with_timeout(
                invoke_docker_capability(&config, invocation),
                timeout_ms,
                &capability.plugin_id,
                &capability.id,
            )
            .await
        }
        #[cfg(feature = "kubernetes")]
        "kubernetes" => {
            let config = parse_kubernetes_config(connection).map_err(|error| *error)?;
            invoke_with_timeout(
                invoke_kubernetes_capability(&config, invocation),
                timeout_ms,
                &capability.plugin_id,
                &capability.id,
            )
            .await
        }
        #[cfg(feature = "mongodb")]
        "mongodb" => {
            let config = parse_mongodb_config(connection).map_err(|error| *error)?;
            invoke_with_timeout(
                invoke_mongodb_capability(&config, invocation),
                timeout_ms,
                &capability.plugin_id,
                &capability.id,
            )
            .await
        }
        #[cfg(feature = "elasticsearch")]
        "elasticsearch" => {
            let config = parse_elasticsearch_config(connection).map_err(|error| *error)?;
            invoke_with_timeout(
                invoke_elasticsearch_capability(&config, invocation),
                timeout_ms,
                &capability.plugin_id,
                &capability.id,
            )
            .await
        }
        #[cfg(feature = "sync")]
        "sync" => {
            invoke_with_timeout(
                invoke_sync_capability(invocation),
                timeout_ms,
                &capability.plugin_id,
                &capability.id,
            )
            .await
        }
        plugin_id => Err(capability_error(
            CapabilityErrorCategory::Unavailable,
            "unavailable.plugin_not_found",
            "Generic invoke only supports selected built-in plugins.",
            json!({ "plugin_id": plugin_id, "supported_plugins": SUPPORTED_INVOKE_PLUGINS }),
            None,
            true,
        )),
    }
}

async fn invoke_capability(
    capability: &CapabilityDefinition,
    connection: &ConnectionConfig,
    invocation: CapabilityInvocation,
    credential_grant: &CredentialGrant,
    discovery: &ProcessPluginDiscovery,
    cancellation: watch::Receiver<bool>,
    stream_events: Option<mpsc::Sender<InvocationStreamEvent>>,
) -> Result<CapabilityInvocationResult, CapabilityError> {
    if is_builtin_invoke_plugin(&capability.plugin_id) {
        return invoke_builtin_capability(capability, connection, invocation, cancellation).await;
    }

    let candidate =
        select_available_process_candidate(discovery, &capability.plugin_id).map_err(|e| *e)?;
    let host = ProcessPluginRuntimeHost::new(candidate.clone());
    host.invoke_controlled(invocation, credential_grant, cancellation, stream_events)
        .await
}

async fn cancellation_requested(cancellation: &mut watch::Receiver<bool>) {
    while !*cancellation.borrow() {
        if cancellation.changed().await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

async fn invoke_with_timeout<F>(
    future: F,
    timeout_ms: Option<u64>,
    plugin_id: &str,
    capability_id: &str,
) -> Result<CapabilityInvocationResult, CapabilityError>
where
    F: Future<Output = Result<CapabilityInvocationResult, CapabilityError>>,
{
    let Some(timeout_ms) = timeout_ms else {
        return future.await;
    };

    match tokio::time::timeout(Duration::from_millis(timeout_ms), future).await {
        Ok(result) => result,
        Err(_) => Err(capability_error(
            CapabilityErrorCategory::Timeout,
            "timeout.invocation_timed_out",
            "Capability invocation exceeded the effective timeout.",
            json!({
                "plugin_id": plugin_id,
                "capability_id": capability_id,
                "timeout_ms": timeout_ms,
            }),
            None,
            true,
        )),
    }
}

#[cfg(feature = "sqlite")]
fn parse_sqlite_config(
    connection: &ConnectionConfig,
) -> Result<SqliteConfig, Box<CapabilityError>> {
    parse_plugin_config(connection, "sqlite", "SQLite")
}

#[cfg(feature = "redis")]
fn parse_redis_config(connection: &ConnectionConfig) -> Result<RedisConfig, Box<CapabilityError>> {
    parse_plugin_config(connection, "redis", "Redis")
}

#[cfg(feature = "mysql")]
fn parse_mysql_config(connection: &ConnectionConfig) -> Result<MySqlConfig, Box<CapabilityError>> {
    parse_plugin_config(connection, "mysql", "MySQL")
}

#[cfg(feature = "postgres")]
fn parse_postgres_config(
    connection: &ConnectionConfig,
) -> Result<PostgresConfig, Box<CapabilityError>> {
    parse_plugin_config_with_aliases(connection, &["postgres", "postgresql"], "PostgreSQL")
}

#[cfg(feature = "duckdb")]
fn parse_duckdb_config(
    connection: &ConnectionConfig,
) -> Result<DuckDbConfig, Box<CapabilityError>> {
    parse_plugin_config(connection, "duckdb", "DuckDB")
}

#[cfg(feature = "ssh")]
fn parse_ssh_config(connection: &ConnectionConfig) -> Result<SshConfig, Box<CapabilityError>> {
    parse_plugin_config(connection, "ssh", "SSH")
}

#[cfg(feature = "s3")]
fn parse_s3_config(connection: &ConnectionConfig) -> Result<S3Config, Box<CapabilityError>> {
    parse_plugin_config(connection, "s3", "S3")
}

#[cfg(feature = "docker")]
fn parse_docker_config(
    connection: &ConnectionConfig,
) -> Result<DockerConfig, Box<CapabilityError>> {
    parse_plugin_config(connection, "docker", "Docker")
}

#[cfg(feature = "kubernetes")]
fn parse_kubernetes_config(
    connection: &ConnectionConfig,
) -> Result<K8sConfig, Box<CapabilityError>> {
    parse_plugin_config_with_aliases(connection, &["kubernetes", "k8s"], "Kubernetes")
}

#[cfg(feature = "mongodb")]
fn parse_mongodb_config(
    connection: &ConnectionConfig,
) -> Result<MongoConfig, Box<CapabilityError>> {
    parse_plugin_config(connection, "mongodb", "MongoDB")
}

#[cfg(feature = "elasticsearch")]
fn parse_elasticsearch_config(
    connection: &ConnectionConfig,
) -> Result<EsConfig, Box<CapabilityError>> {
    parse_plugin_config(connection, "elasticsearch", "Elasticsearch")
}

fn parse_plugin_config<T>(
    connection: &ConnectionConfig,
    expected_plugin_id: &str,
    label: &str,
) -> Result<T, Box<CapabilityError>>
where
    T: serde::de::DeserializeOwned,
{
    parse_plugin_config_with_aliases(connection, &[expected_plugin_id], label)
}

fn parse_plugin_config_with_aliases<T>(
    connection: &ConnectionConfig,
    expected_plugin_ids: &[&str],
    label: &str,
) -> Result<T, Box<CapabilityError>>
where
    T: serde::de::DeserializeOwned,
{
    if !expected_plugin_ids
        .iter()
        .any(|expected| connection.effective_plugin_id() == *expected)
    {
        return Err(Box::new(capability_error(
            CapabilityErrorCategory::Validation,
            "validation.profile_plugin_mismatch",
            "Profile plugin does not match requested capability.",
            json!({
                "expected_plugin_id": expected_plugin_ids[0],
                "expected_plugin_ids": expected_plugin_ids,
                "actual_plugin_id": connection.effective_plugin_id(),
            }),
            None,
            false,
        )));
    }

    let Some(plugin_config) = &connection.plugin_config else {
        return Err(Box::new(capability_error(
            CapabilityErrorCategory::Credential,
            "credential.legacy_plugin_config_missing",
            "Legacy profile does not contain plugin_config required for invocation.",
            json!({ "plugin_id": expected_plugin_ids[0] }),
            None,
            false,
        )));
    };

    serde_json::from_value(plugin_config.clone()).map_err(|error| {
        Box::new(capability_error(
            CapabilityErrorCategory::Validation,
            "validation.legacy_plugin_config_invalid",
            "Legacy plugin_config could not be decoded for invocation.",
            json!({ "plugin_id": expected_plugin_ids[0], "label": label, "message": error.to_string() }),
            None,
            false,
        ))
    })
}

fn resolve_capability(
    capability_ref: &str,
    discovery: &ProcessPluginDiscovery,
) -> Result<CapabilityDefinition, Box<CapabilityError>> {
    let (plugin_id, capability_id) = parse_capability_ref(capability_ref)?;
    let capabilities = capabilities_for_plugin(&plugin_id, discovery)?;

    capabilities
        .into_iter()
        .find(|capability| capability.id == capability_id)
        .ok_or_else(|| {
            Box::new(capability_error(
                CapabilityErrorCategory::Unavailable,
                "unavailable.capability_not_found",
                "Capability was not found for the selected plugin.",
                json!({
                    "plugin_id": plugin_id,
                    "capability_id": capability_id,
                }),
                None,
                true,
            ))
        })
}

fn parse_capability_ref(capability_ref: &str) -> Result<(String, String), Box<CapabilityError>> {
    let Some((plugin_id, capability_id)) = capability_ref.split_once('.') else {
        return Err(Box::new(capability_error(
            CapabilityErrorCategory::Validation,
            "validation.capability_ref_unqualified",
            "Capability reference must be qualified as <plugin>.<capability>.",
            json!({ "capability_ref": capability_ref }),
            None,
            false,
        )));
    };

    if plugin_id.is_empty() || capability_id.is_empty() || capability_id.contains('.') {
        return Err(Box::new(capability_error(
            CapabilityErrorCategory::Validation,
            "validation.capability_ref_invalid",
            "Capability reference must contain exactly one plugin and capability segment.",
            json!({ "capability_ref": capability_ref }),
            None,
            false,
        )));
    }

    Ok((plugin_id.to_string(), capability_id.to_string()))
}

fn capabilities_for_plugin(
    plugin_id: &str,
    discovery: &ProcessPluginDiscovery,
) -> Result<Vec<CapabilityDefinition>, Box<CapabilityError>> {
    match plugin_id {
        #[cfg(feature = "sqlite")]
        "sqlite" => Ok(sqlite_capabilities()),
        #[cfg(feature = "redis")]
        "redis" => Ok(redis_capabilities()),
        #[cfg(feature = "mysql")]
        "mysql" => Ok(mysql_capabilities()),
        #[cfg(feature = "postgres")]
        "postgres" => Ok(postgres_capabilities()),
        #[cfg(feature = "duckdb")]
        "duckdb" => Ok(duckdb_capabilities()),
        #[cfg(feature = "ssh")]
        "ssh" => Ok(ssh_capabilities()),
        #[cfg(feature = "s3")]
        "s3" => Ok(s3_capabilities()),
        #[cfg(feature = "docker")]
        "docker" => Ok(docker_capabilities()),
        #[cfg(feature = "kubernetes")]
        "kubernetes" => Ok(kubernetes_capabilities()),
        #[cfg(feature = "mongodb")]
        "mongodb" => Ok(mongodb_capabilities()),
        #[cfg(feature = "elasticsearch")]
        "elasticsearch" => Ok(elasticsearch_capabilities()),
        #[cfg(feature = "sync")]
        "sync" => Ok(sync_capabilities()),
        _ => {
            let candidate = select_available_process_candidate(discovery, plugin_id)?;
            process_capability_definitions(candidate)
        }
    }
}

pub(crate) fn builtin_capabilities() -> Vec<CapabilityDefinition> {
    let mut capabilities = Vec::new();
    #[cfg(feature = "sqlite")]
    capabilities.extend(sqlite_capabilities());
    #[cfg(feature = "redis")]
    capabilities.extend(redis_capabilities());
    #[cfg(feature = "mysql")]
    capabilities.extend(mysql_capabilities());
    #[cfg(feature = "postgres")]
    capabilities.extend(postgres_capabilities());
    #[cfg(feature = "duckdb")]
    capabilities.extend(duckdb_capabilities());
    #[cfg(feature = "ssh")]
    capabilities.extend(ssh_capabilities());
    #[cfg(feature = "s3")]
    capabilities.extend(s3_capabilities());
    #[cfg(feature = "docker")]
    capabilities.extend(docker_capabilities());
    #[cfg(feature = "kubernetes")]
    capabilities.extend(kubernetes_capabilities());
    #[cfg(feature = "mongodb")]
    capabilities.extend(mongodb_capabilities());
    #[cfg(feature = "elasticsearch")]
    capabilities.extend(elasticsearch_capabilities());
    #[cfg(feature = "sync")]
    capabilities.extend(sync_capabilities());
    capabilities.sort_by_key(CapabilityDefinition::qualified_id);
    capabilities
}

fn supported_capabilities(discovery: &ProcessPluginDiscovery) -> Vec<CapabilityDefinition> {
    let mut capabilities = builtin_capabilities();
    for candidate in &discovery.candidates {
        if candidate.state == ProcessPluginCandidateState::Available
            && !is_builtin_invoke_plugin(&candidate.id)
            && let Ok(process_capabilities) = process_capability_definitions(candidate)
        {
            capabilities.extend(process_capabilities);
        }
    }
    capabilities.sort_by_key(CapabilityDefinition::qualified_id);
    capabilities
}

fn is_builtin_invoke_plugin(plugin_id: &str) -> bool {
    SUPPORTED_INVOKE_PLUGINS.contains(&plugin_id)
}

fn select_available_process_candidate<'a>(
    discovery: &'a ProcessPluginDiscovery,
    plugin_id: &str,
) -> Result<&'a ProcessPluginCandidate, Box<CapabilityError>> {
    let candidates = discovery.candidates_for_id(plugin_id);
    let Some(candidate) = candidates
        .iter()
        .copied()
        .find(|candidate| candidate.state == ProcessPluginCandidateState::Available)
        .or_else(|| candidates.first().copied())
    else {
        return Err(Box::new(capability_error(
            CapabilityErrorCategory::Unavailable,
            "unavailable.plugin_not_found",
            "Generic invoke supports built-in plugins and available process plugins.",
            json!({
                "plugin_id": plugin_id,
                "built_in_plugins": SUPPORTED_INVOKE_PLUGINS,
            }),
            None,
            true,
        )));
    };

    if candidate.state != ProcessPluginCandidateState::Available {
        return Err(Box::new(capability_error(
            CapabilityErrorCategory::Unavailable,
            "unavailable.process_plugin_candidate_not_available",
            "Discovered process-plugin candidate is not available for invocation.",
            json!({
                "plugin_id": plugin_id,
                "state": candidate.state,
                "diagnostics": candidate.diagnostics,
            }),
            None,
            true,
        )));
    }

    Ok(candidate)
}

fn process_capability_definitions(
    candidate: &ProcessPluginCandidate,
) -> Result<Vec<CapabilityDefinition>, Box<CapabilityError>> {
    let manifest = candidate.manifest.as_ref().ok_or_else(|| {
        Box::new(capability_error(
            CapabilityErrorCategory::Unavailable,
            "unavailable.process_plugin_manifest_missing",
            "Discovered process-plugin candidate does not have a decoded manifest.",
            json!({ "plugin_id": candidate.id }),
            None,
            false,
        ))
    })?;

    manifest
        .capabilities
        .iter()
        .map(|capability| {
            let input_label = format!("capabilities.{}.input_schema", capability.id);
            let output_label = format!("capabilities.{}.output_schema", capability.id);
            Ok(CapabilityDefinition {
                plugin_id: manifest.id.clone(),
                id: capability.id.clone(),
                description: capability.description.clone(),
                input_schema: schema_value(candidate, &input_label, &capability.input_schema)?,
                output_schema: schema_value(candidate, &output_label, &capability.output_schema)?,
                permissions: capability.permissions.clone(),
                authorization: capability.authorization.clone(),
                risk: capability.risk.unwrap_or_else(|| {
                    CapabilityRiskLevel::from_destructive(capability.destructive)
                }),
                destructive: capability.destructive,
                streaming: capability.streaming,
                execution_mode: capability.execution_mode,
                session_handoff: capability.session_handoff.clone(),
                connection_required: capability.connection_required,
                required_secret_classes: capability
                    .required_secret_classes
                    .iter()
                    .map(|class| credential_class_from_manifest(class))
                    .collect(),
                supports_dry_run: capability.supports_dry_run,
                default_timeout_ms: capability.default_timeout_ms,
            })
        })
        .collect()
}

fn schema_value(
    candidate: &ProcessPluginCandidate,
    label: &str,
    schema_ref: &str,
) -> Result<Value, Box<CapabilityError>> {
    if schema_ref.contains("://") {
        return Ok(json!({}));
    }

    let path = candidate.resolved_schema_paths.get(label).ok_or_else(|| {
        Box::new(capability_error(
            CapabilityErrorCategory::Internal,
            "internal.process_plugin_schema_not_resolved",
            "Process-plugin schema was not resolved during discovery.",
            json!({
                "plugin_id": candidate.id,
                "schema": label,
            }),
            None,
            false,
        ))
    })?;

    let content = std::fs::read_to_string(path).map_err(|error| {
        Box::new(capability_error(
            CapabilityErrorCategory::Internal,
            "internal.process_plugin_schema_unreadable",
            "Resolved process-plugin schema could not be read.",
            json!({
                "plugin_id": candidate.id,
                "schema": label,
                "message": error.to_string(),
            }),
            None,
            false,
        ))
    })?;

    serde_json::from_str(&content).map_err(|error| {
        Box::new(capability_error(
            CapabilityErrorCategory::Internal,
            "internal.process_plugin_schema_json_invalid",
            "Resolved process-plugin schema is not valid JSON.",
            json!({
                "plugin_id": candidate.id,
                "schema": label,
                "message": error.to_string(),
            }),
            None,
            false,
        ))
    })
}

fn credential_class_from_manifest(class: &str) -> CredentialClass {
    match class {
        "password" => CredentialClass::Password,
        "token" => CredentialClass::Token,
        "api_key" | "apikey" | "api-key" => CredentialClass::ApiKey,
        "private_key" | "private-key" => CredentialClass::PrivateKey,
        "client_certificate" | "client-certificate" => CredentialClass::ClientCertificate,
        "cloud_access_key" | "cloud-access-key" => CredentialClass::CloudAccessKey,
        "cloud_secret_key" | "cloud-secret-key" => CredentialClass::CloudSecretKey,
        other => CredentialClass::Other(other.into()),
    }
}

fn runtime_summary(capability: &CapabilityDefinition) -> InvokeRuntimeSummary {
    if is_builtin_invoke_plugin(&capability.plugin_id) {
        InvokeRuntimeSummary {
            kind: "builtin",
            transport: None,
        }
    } else {
        InvokeRuntimeSummary {
            kind: "process_plugin",
            transport: Some("stdio-jsonrpc"),
        }
    }
}

fn resolve_native_profile_connection(
    ctx: &CliContext,
    profiles: &[ConnectionProfile],
    profile_ref: &str,
    capability: &CapabilityDefinition,
) -> Result<(ConnectionProfile, ConnectionConfig), Box<CapabilityError>> {
    let plugin_id = capability.plugin_id.as_str();
    if !capability.connection_required {
        let profile = connectionless_profile(plugin_id);
        if !profile_matches_ref(&profile, profile_ref) {
            return Err(Box::new(capability_error(
                CapabilityErrorCategory::Validation,
                "validation.system_profile_ref_invalid",
                "Connection-independent capabilities use the local system authorization scope.",
                json!({
                    "profile_ref": profile_ref,
                    "expected": ["local", "name:local", format!("id:{}", profile.id)],
                    "plugin_id": plugin_id
                }),
                None,
                false,
            )));
        }
        return Ok((
            profile,
            ConnectionConfig {
                name: "local".into(),
                db_type: voidb_core::DatabaseType::Plugin,
                plugin_id: Some(plugin_id.into()),
                plugin_config: None,
            },
        ));
    }
    let matches = profiles
        .iter()
        .filter(|profile| profile_matches_plugin(profile, plugin_id))
        .filter(|profile| profile_matches_ref(profile, profile_ref))
        .cloned()
        .collect::<Vec<_>>();
    let profile = match matches.len() {
        0 => {
            return Err(Box::new(capability_error(
                CapabilityErrorCategory::Validation,
                "validation.profile_ref_not_found",
                "Profile reference did not match a saved native profile for this capability.",
                json!({ "profile_ref": profile_ref, "plugin_id": plugin_id }),
                None,
                false,
            )));
        }
        1 => matches[0].clone(),
        _ => {
            return Err(Box::new(capability_error(
                CapabilityErrorCategory::Conflict,
                "conflict.profile_ref_ambiguous",
                "Profile reference matched multiple profiles; pass id:<profile-id>.",
                json!({ "profile_ref": profile_ref, "plugin_id": plugin_id }),
                None,
                false,
            )));
        }
    };
    let master_password = ctx
        .credential_master_password()
        .map_err(profile_store_error)?;
    let connection = match LocalProfileStore::default_store()
        .and_then(|store| store.native_connection(&profile, master_password))
    {
        Ok(connection) => connection,
        Err(native_error) => {
            let legacy_key = profile
                .metadata
                .get("legacy_connection_key")
                .and_then(Value::as_str);
            match legacy_key.and_then(|key| {
                ctx.config
                    .connections
                    .iter()
                    .find(|connection| connection.connection_key() == key)
            }) {
                Some(connection) => connection.clone(),
                None => return Err(profile_store_error(native_error)),
            }
        }
    };
    Ok((profile, connection))
}

fn connectionless_profile(plugin_id: &str) -> ConnectionProfile {
    ConnectionProfile {
        id: format!("system:{plugin_id}"),
        name: "local".into(),
        plugin_id: plugin_id.into(),
        display_name: Some(format!("Local {plugin_id} control surface")),
        metadata: json!({
            "scope": "local_system",
            "connection_required": false
        }),
        default_options: Value::Null,
        credential_refs: Vec::new(),
        policy: Default::default(),
    }
}

fn profiles_from_context(ctx: &CliContext) -> Result<Vec<ConnectionProfile>, Box<CapabilityError>> {
    #[cfg(not(test))]
    let _ = ctx;
    let store = LocalProfileStore::default_store().map_err(profile_store_error)?;
    let profiles = store.load_profiles().map_err(profile_store_error)?;
    #[cfg(test)]
    if !ctx.config.connections.is_empty() {
        return Ok(voidb_core::connection_configs_to_profiles(
            &ctx.config.connections,
        ));
    }
    Ok(profiles)
}

fn profile_store_error(error: VoidbError) -> Box<CapabilityError> {
    Box::new(capability_error(
        CapabilityErrorCategory::Internal,
        "internal.profile_store_unavailable",
        "Local profile store could not be loaded.",
        json!({ "message": error.to_string() }),
        None,
        false,
    ))
}

fn profile_matches_ref(profile: &ConnectionProfile, profile_ref: &str) -> bool {
    if let Some(id) = profile_ref.strip_prefix("id:") {
        return profile.id == id;
    }
    if profile.id == profile_ref {
        return true;
    }

    let name = profile_ref
        .strip_prefix("name:")
        .or_else(|| profile_ref.strip_prefix("alias:"))
        .unwrap_or(profile_ref);
    profile_names_equal(&profile.name, name)
}

fn profile_matches_plugin(profile: &ConnectionProfile, plugin_id: &str) -> bool {
    profile.plugin_id == plugin_id
        || profile.metadata["legacy_plugin_id"]
            .as_str()
            .is_some_and(|legacy_plugin_id| legacy_plugin_id == plugin_id)
}

fn redact_result(
    mut result: CapabilityInvocationResult,
    connection: &ConnectionConfig,
) -> (CapabilityInvocationResult, RedactionStatus) {
    let Some(plugin_config) = &connection.plugin_config else {
        return (result, RedactionStatus::NotRequired);
    };

    let (output, output_status) = redact_value_with_config(&result.output, plugin_config);
    let (output_summary, summary_status) =
        redact_value_with_config(&result.output_summary, plugin_config);
    result.output = output;
    result.output_summary = output_summary;

    let status = if output_status == RedactionStatus::Applied
        || summary_status == RedactionStatus::Applied
    {
        RedactionStatus::Applied
    } else {
        RedactionStatus::NotRequired
    };

    (result, status)
}

fn redact_error(mut error: CapabilityError, connection: &ConnectionConfig) -> CapabilityError {
    let Some(plugin_config) = &connection.plugin_config else {
        return error;
    };

    let (message, message_status) = redact_text_with_json(&error.message, plugin_config);
    let (details, details_status) = redact_value_with_config(&error.details, plugin_config);
    let (target, target_status) = redact_target_failure(error.target, plugin_config);
    error.message = message;
    error.details = details;
    error.target = target;

    if error.redaction == RedactionStatus::Applied
        || message_status == RedactionStatus::Applied
        || details_status == RedactionStatus::Applied
        || target_status == RedactionStatus::Applied
    {
        error.redaction = RedactionStatus::Applied;
    }

    error
}

fn redact_target_failure(
    target: Option<TargetSystemFailure>,
    plugin_config: &Value,
) -> (Option<TargetSystemFailure>, RedactionStatus) {
    let Some(mut target) = target else {
        return (None, RedactionStatus::NotRequired);
    };

    let mut status = RedactionStatus::NotRequired;
    if let Some(message) = target.message {
        let (message, message_status) = redact_text_with_json(&message, plugin_config);
        if message_status == RedactionStatus::Applied {
            status = RedactionStatus::Applied;
        }
        target.message = Some(message);
    }

    (Some(target), status)
}

fn redact_value_with_config(value: &Value, plugin_config: &Value) -> (Value, RedactionStatus) {
    match value {
        Value::String(text) => {
            let (redacted, status) = redact_text_with_json(text, plugin_config);
            (Value::String(redacted), status)
        }
        Value::Array(items) => {
            let mut status = RedactionStatus::NotRequired;
            let items = items
                .iter()
                .map(|item| {
                    let (item, item_status) = redact_value_with_config(item, plugin_config);
                    if item_status == RedactionStatus::Applied {
                        status = RedactionStatus::Applied;
                    }
                    item
                })
                .collect();
            (Value::Array(items), status)
        }
        Value::Object(map) => {
            let mut status = RedactionStatus::NotRequired;
            let map = map
                .iter()
                .map(|(key, value)| {
                    let (value, value_status) = redact_value_with_config(value, plugin_config);
                    if value_status == RedactionStatus::Applied {
                        status = RedactionStatus::Applied;
                    }
                    (key.clone(), value)
                })
                .collect();
            (Value::Object(map), status)
        }
        _ => (value.clone(), RedactionStatus::NotRequired),
    }
}

fn capability_error(
    category: CapabilityErrorCategory,
    code: &str,
    message: &str,
    details: Value,
    target: Option<TargetSystemFailure>,
    retryable: bool,
) -> CapabilityError {
    CapabilityError {
        category,
        code: code.to_string(),
        message: message.to_string(),
        details,
        target,
        retryable,
        redaction: RedactionStatus::NotRequired,
    }
}

fn exit_code_for_error(error: &CapabilityError) -> u8 {
    match error.category {
        CapabilityErrorCategory::Validation => 2,
        CapabilityErrorCategory::Auth
        | CapabilityErrorCategory::Credential
        | CapabilityErrorCategory::Permission
        | CapabilityErrorCategory::Policy => 3,
        CapabilityErrorCategory::Unavailable => 4,
        CapabilityErrorCategory::Timeout | CapabilityErrorCategory::Transport => 5,
        CapabilityErrorCategory::TargetSystem => 6,
        CapabilityErrorCategory::Conflict => 7,
        CapabilityErrorCategory::Cancellation => 8,
        CapabilityErrorCategory::Plugin | CapabilityErrorCategory::Internal => 1,
    }
}

fn next_invocation_id() -> String {
    format!("invoke-{}", Uuid::new_v4())
}

fn success_envelope<T: Serialize>(data: T) -> JsonSuccessEnvelope<T> {
    JsonSuccessEnvelope {
        ok: true,
        schema_version: INVOKE_CLI_SCHEMA_VERSION,
        command: "invoke",
        data,
        warnings: Vec::new(),
    }
}

fn print_json(value: &impl Serialize) -> Result<(), VoidbError> {
    let output = serde_json::to_string_pretty(value)
        .map_err(|e| VoidbError::Plugin(format!("Failed to serialize JSON output: {}", e)))?;
    println!("{}", output);
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InvokeOutputFormat {
    Json,
    Ndjson,
}

fn run_output_format(matches: &ArgMatches) -> InvokeOutputFormat {
    match matches.get_one::<String>("format").map(String::as_str) {
        Some("ndjson") => InvokeOutputFormat::Ndjson,
        Some("json") | None => InvokeOutputFormat::Json,
        Some(_) => unreachable!("format is constrained by clap"),
    }
}

struct NdjsonEmitter<W> {
    writer: W,
    invocation_id: String,
    next_sequence: u64,
}

impl<W: Write> NdjsonEmitter<W> {
    fn new(writer: W, invocation_id: String) -> Self {
        Self {
            writer,
            invocation_id,
            next_sequence: 0,
        }
    }

    fn emit(&mut self, event: InvocationStreamEvent) -> Result<(), VoidbError> {
        let envelope =
            InvocationStreamEnvelope::new(self.next_sequence, self.invocation_id.clone(), event);
        serde_json::to_writer(&mut self.writer, &envelope).map_err(|error| {
            VoidbError::Plugin(format!("Failed to serialize NDJSON output: {error}"))
        })?;
        self.writer.write_all(b"\n").map_err(|error| {
            VoidbError::Plugin(format!("Failed to write NDJSON output: {error}"))
        })?;
        self.writer.flush().map_err(|error| {
            VoidbError::Plugin(format!("Failed to flush NDJSON output: {error}"))
        })?;
        self.next_sequence = self
            .next_sequence
            .checked_add(1)
            .ok_or_else(|| VoidbError::Plugin("NDJSON sequence number overflowed".into()))?;
        Ok(())
    }
}

fn print_run_success<W: Write>(
    output_format: InvokeOutputFormat,
    ndjson: Option<&mut NdjsonEmitter<W>>,
    data: InvokeRunData,
) -> Result<(), VoidbError> {
    if output_format == InvokeOutputFormat::Json {
        return print_json(&success_envelope(data));
    }

    let emitter = ndjson.expect("NDJSON emitter exists for NDJSON output");
    for warning in &data.warnings {
        emitter.emit(InvocationStreamEvent::Warning {
            warning: serialize_output_value(warning)?,
        })?;
    }
    let status = data.status;
    let duration_ms = data.timing.duration_ms;
    emitter.emit(InvocationStreamEvent::Data {
        value: serialize_output_value(&data)?,
    })?;
    emitter.emit(InvocationStreamEvent::End {
        status,
        duration_ms: Some(duration_ms),
    })
}

fn print_run_error<W: Write>(
    output_format: InvokeOutputFormat,
    ndjson: Option<&mut NdjsonEmitter<W>>,
    envelope: JsonErrorEnvelope,
) -> Result<(), VoidbError> {
    if output_format == InvokeOutputFormat::Json {
        return print_json(&envelope);
    }

    let status = invocation_status_for_error(&envelope.error);
    let emitter = ndjson.expect("NDJSON emitter exists for NDJSON output");
    emitter.emit(InvocationStreamEvent::Error {
        error: envelope.error,
    })?;
    emitter.emit(InvocationStreamEvent::End {
        status,
        duration_ms: None,
    })
}

fn serialize_output_value(value: &impl Serialize) -> Result<Value, VoidbError> {
    serde_json::to_value(value)
        .map_err(|error| VoidbError::Plugin(format!("Failed to serialize invoke output: {error}")))
}

fn invocation_status_for_error(error: &CapabilityError) -> InvocationStatus {
    match error.category {
        CapabilityErrorCategory::Timeout => InvocationStatus::TimedOut,
        CapabilityErrorCategory::Cancellation => InvocationStatus::Cancelled,
        _ => InvocationStatus::Failed,
    }
}

#[derive(Debug)]
struct InvokeRunOptions {
    capability_ref: String,
    profile_ref: String,
    input: Value,
    timeout_ms: Option<u64>,
    dry_run: bool,
    destructive_ack: bool,
    page_limit: Option<u32>,
    page_cursor: Option<String>,
}

#[derive(Debug)]
struct ParsedInvokeRunOptions {
    invocation: InvokeRunOptions,
    cancellation_token: String,
    max_output_bytes: u64,
}

#[derive(Debug, Clone)]
struct InvokeAuditContext {
    capability_ref: String,
    profile_ref: String,
    input_summary: Value,
    controls: Value,
}

impl InvokeAuditContext {
    fn from_options(options: &InvokeRunOptions, max_output_bytes: u64) -> Self {
        Self {
            capability_ref: options.capability_ref.clone(),
            profile_ref: options.profile_ref.clone(),
            input_summary: audit_json_summary(&options.input),
            controls: json!({
                "timeout_ms": options.timeout_ms,
                "dry_run": options.dry_run,
                "destructive_ack": options.destructive_ack,
                "page_limit": options.page_limit,
                "page_cursor_present": options.page_cursor.is_some(),
                "max_output_bytes": max_output_bytes,
            }),
        }
    }
}

#[derive(Debug, Clone)]
struct InvokeRunError {
    error: Box<CapabilityError>,
    grant: Option<InvokeGrantAuditData>,
    policy_decision: Option<CapabilityPolicyDecision>,
}

impl InvokeRunError {
    fn with_policy(error: CapabilityError, policy_decision: CapabilityPolicyDecision) -> Self {
        Self {
            error: Box::new(error),
            grant: None,
            policy_decision: Some(policy_decision),
        }
    }

    fn with_grant(
        error: CapabilityError,
        grant: InvokeGrantAuditData,
        policy_decision: CapabilityPolicyDecision,
    ) -> Self {
        Self {
            error: Box::new(error),
            grant: Some(grant),
            policy_decision: Some(policy_decision),
        }
    }

    fn into_error(self) -> CapabilityError {
        *self.error
    }
}

impl From<Box<CapabilityError>> for InvokeRunError {
    fn from(error: Box<CapabilityError>) -> Self {
        Self {
            error,
            grant: None,
            policy_decision: None,
        }
    }
}

impl std::ops::Deref for InvokeRunError {
    type Target = CapabilityError;

    fn deref(&self) -> &Self::Target {
        &self.error
    }
}

#[derive(Debug, Clone)]
struct InvokeGrantAuditData {
    grant_id: String,
    invocation_id: String,
    profile: ConnectionProfileRef,
    plugin_id: String,
    capability_id: String,
    credential_refs: Vec<CredentialRef>,
}

impl InvokeGrantAuditData {
    fn from_run_data(data: &InvokeRunData) -> Self {
        Self {
            grant_id: data.grant_id.clone(),
            invocation_id: data.invocation_id.clone(),
            profile: data.profile.clone(),
            plugin_id: data.plugin_id.clone(),
            capability_id: data.capability_id.clone(),
            credential_refs: data.credential_refs.clone(),
        }
    }
}

fn append_credential_grant_success_audit(data: &InvokeRunData) -> Result<(), VoidbError> {
    let grant = InvokeGrantAuditData::from_run_data(data);
    append_audit_event(credential_grant_audit_event(
        AuditOperation::CredentialGrantIssued,
        AuditEventStatus::Succeeded,
        &grant,
        None,
    ))?;
    append_audit_event(credential_grant_audit_event(
        AuditOperation::CredentialGrantUsed,
        data.status.into(),
        &grant,
        None,
    ))?;
    append_audit_event(credential_grant_audit_event(
        AuditOperation::CredentialGrantReleased,
        AuditEventStatus::Succeeded,
        &grant,
        None,
    ))
}

fn append_credential_grant_failure_audit(error: &InvokeRunError) -> Result<(), VoidbError> {
    let Some(grant) = &error.grant else {
        return Ok(());
    };
    append_audit_event(credential_grant_audit_event(
        AuditOperation::CredentialGrantIssued,
        AuditEventStatus::Succeeded,
        grant,
        None,
    ))?;
    append_audit_event(credential_grant_audit_event(
        AuditOperation::CredentialGrantUsed,
        audit_status_for_error(error),
        grant,
        Some(&**error),
    ))?;
    append_audit_event(credential_grant_audit_event(
        AuditOperation::CredentialGrantReleased,
        AuditEventStatus::Succeeded,
        grant,
        None,
    ))
}

fn credential_grant_audit_event(
    operation: AuditOperation,
    status: AuditEventStatus,
    grant: &InvokeGrantAuditData,
    error: Option<&CapabilityError>,
) -> AuditEvent {
    let mut event = AuditEvent::new(operation, status);
    event.invocation_id = Some(grant.invocation_id.clone());
    event.grant_id = Some(grant.grant_id.clone());
    event.profile = Some(grant.profile.clone());
    event.plugin_id = Some(grant.plugin_id.clone());
    event.capability_id = Some(grant.capability_id.clone());
    event.credential_refs = grant.credential_refs.clone();
    event.metadata = json!({
        "grant_id": grant.grant_id.as_str(),
        "scope": "capability_invocation",
        "credential_ref_count": grant.credential_refs.len(),
        "outcome_status": status,
    });
    if let Some(error) = error {
        event.error = Some(error.clone());
        event.redaction = error.redaction;
    }
    event
}

fn append_invoke_success_audit(
    data: &InvokeRunData,
    context: &InvokeAuditContext,
) -> Result<(), VoidbError> {
    append_audit_event(invoke_success_audit_event(data, context))
}

fn invoke_success_audit_event(data: &InvokeRunData, context: &InvokeAuditContext) -> AuditEvent {
    let mut event = AuditEvent::new(AuditOperation::CapabilityInvoke, data.status.into());
    event.invocation_id = Some(data.invocation_id.clone());
    event.grant_id = Some(data.grant_id.clone());
    event.profile = Some(data.profile.clone());
    event.plugin_id = Some(data.plugin_id.clone());
    event.capability_id = Some(data.capability_id.clone());
    event.duration_ms = Some(data.timing.duration_ms);
    event.credential_refs = data.credential_refs.clone();
    event.metadata = json!({
        "capability_ref": context.capability_ref,
        "profile_ref": context.profile_ref,
        "grant_id": data.grant_id.as_str(),
        "input_summary": context.input_summary,
        "output_summary": data.output_summary,
        "controls": context.controls,
        "policy_decision": data.policy_decision,
        "runtime": data.runtime,
        "output_limits": data.output_limits,
        "warnings": data.warnings,
    });
    event.redaction = data.redaction;
    event
}

fn append_invoke_error_audit(
    capability_ref: Option<&str>,
    profile_ref: Option<&str>,
    input_summary: Option<Value>,
    grant: Option<&InvokeGrantAuditData>,
    policy_decision: Option<&CapabilityPolicyDecision>,
    error: &CapabilityError,
) -> Result<(), VoidbError> {
    append_audit_event(invoke_error_audit_event(
        capability_ref,
        profile_ref,
        input_summary,
        grant,
        policy_decision,
        error,
    ))
}

fn invoke_error_audit_event(
    capability_ref: Option<&str>,
    profile_ref: Option<&str>,
    input_summary: Option<Value>,
    grant: Option<&InvokeGrantAuditData>,
    policy_decision: Option<&CapabilityPolicyDecision>,
    error: &CapabilityError,
) -> AuditEvent {
    let (plugin_id, capability_id) = capability_ref
        .and_then(split_qualified_capability_ref)
        .unwrap_or((None, None));
    let mut event = AuditEvent::new(
        AuditOperation::CapabilityInvoke,
        audit_status_for_error(error),
    );
    event.invocation_id = grant.map(|grant| grant.invocation_id.clone());
    event.grant_id = grant.map(|grant| grant.grant_id.clone());
    event.profile = grant.map(|grant| grant.profile.clone());
    event.plugin_id = grant.map(|grant| grant.plugin_id.clone()).or(plugin_id);
    event.capability_id = grant
        .map(|grant| grant.capability_id.clone())
        .or(capability_id);
    event.credential_refs = grant
        .map(|grant| grant.credential_refs.clone())
        .unwrap_or_default();
    event.metadata = json!({
        "capability_ref": capability_ref,
        "profile_ref": profile_ref,
        "grant_id": grant.map(|grant| grant.grant_id.as_str()),
        "input_summary": input_summary,
        "policy_decision": policy_decision,
    });
    event.error = Some(error.clone());
    event.redaction = error.redaction;
    event
}

fn append_audit_event(event: AuditEvent) -> Result<(), VoidbError> {
    LocalAuditStore::default_store()?.append(&event)
}

fn split_qualified_capability_ref(
    capability_ref: &str,
) -> Option<(Option<String>, Option<String>)> {
    let (plugin_id, capability_id) = capability_ref.split_once('.')?;
    Some((Some(plugin_id.into()), Some(capability_id.into())))
}

fn audit_status_for_error(error: &CapabilityError) -> AuditEventStatus {
    match error.category {
        CapabilityErrorCategory::Policy | CapabilityErrorCategory::Permission => {
            AuditEventStatus::Blocked
        }
        CapabilityErrorCategory::Timeout => AuditEventStatus::TimedOut,
        CapabilityErrorCategory::Cancellation => AuditEventStatus::Cancelled,
        _ => AuditEventStatus::Failed,
    }
}

#[derive(Debug, Serialize)]
struct JsonSuccessEnvelope<T> {
    ok: bool,
    schema_version: u32,
    command: &'static str,
    data: T,
    warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
struct JsonErrorEnvelope {
    ok: bool,
    schema_version: u32,
    command: &'static str,
    exit_code: u8,
    error: CapabilityError,
}

#[derive(Debug, Serialize)]
struct InvokeListData {
    capabilities: Vec<CapabilitySummary>,
}

#[derive(Debug, Serialize)]
struct InvokeDescribeData {
    capability: CapabilityDefinition,
}

#[derive(Debug, Clone, Serialize)]
struct CapabilitySummary {
    qualified_id: String,
    plugin_id: String,
    id: String,
    description: String,
    permissions: Vec<String>,
    authorization: CapabilityAuthorizationMetadata,
    risk: CapabilityRiskLevel,
    destructive: bool,
    streaming: bool,
    execution_mode: CapabilityExecutionMode,
    supports_stateless: bool,
    supports_session: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_handoff: Option<voidb_core::CapabilitySessionHandoff>,
    connection_required: bool,
    required_secret_classes: Vec<CredentialClass>,
    supports_dry_run: bool,
    default_timeout_ms: Option<u64>,
}

impl From<CapabilityDefinition> for CapabilitySummary {
    fn from(capability: CapabilityDefinition) -> Self {
        let risk = capability.effective_risk();
        let supports_stateless = capability.supports_stateless_execution();
        let supports_session = capability.supports_session_execution();
        Self {
            qualified_id: capability.qualified_id(),
            plugin_id: capability.plugin_id,
            id: capability.id,
            description: capability.description,
            permissions: capability.permissions,
            authorization: capability.authorization,
            risk,
            destructive: capability.destructive,
            streaming: capability.streaming,
            execution_mode: capability.execution_mode,
            supports_stateless,
            supports_session,
            session_handoff: capability.session_handoff,
            connection_required: capability.connection_required,
            required_secret_classes: capability.required_secret_classes,
            supports_dry_run: capability.supports_dry_run,
            default_timeout_ms: capability.default_timeout_ms,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InvokeCatalogOutputFormat {
    Json,
    Table,
}

fn capability_list_table(capabilities: &[CapabilitySummary]) -> String {
    let mut lines = vec!["Capability\tMode\tRisk\tStream\tProfile\tSession purpose".to_string()];
    for capability in capabilities {
        let purpose = capability
            .session_handoff
            .as_ref()
            .map(|handoff| session_purpose_cli_name(&handoff.purpose))
            .unwrap_or_else(|| "-".into());
        lines.push(format!(
            "{}\t{}\t{}\t{}\t{}\t{}",
            table_cell(&capability.qualified_id),
            execution_mode_name(capability.execution_mode),
            risk_name(capability.risk),
            capability.streaming,
            capability.connection_required,
            table_cell(&purpose),
        ));
    }
    lines.join("\n")
}

fn capability_description_table(capability: &CapabilityDefinition) -> String {
    let handoff = capability
        .session_handoff
        .as_ref()
        .map(|handoff| {
            format!(
                "{} [{}]",
                session_purpose_cli_name(&handoff.purpose),
                handoff.capabilities.join(",")
            )
        })
        .unwrap_or_else(|| "-".into());
    [
        "Field\tValue".to_string(),
        format!("capability\t{}", table_cell(&capability.qualified_id())),
        format!("description\t{}", table_cell(&capability.description)),
        format!(
            "execution_mode\t{}",
            execution_mode_name(capability.execution_mode)
        ),
        format!("risk\t{}", risk_name(capability.effective_risk())),
        format!("streaming\t{}", capability.streaming),
        format!("connection_required\t{}", capability.connection_required),
        format!("supports_dry_run\t{}", capability.supports_dry_run),
        format!(
            "default_timeout_ms\t{}",
            capability
                .default_timeout_ms
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".into())
        ),
        format!(
            "permissions\t{}",
            table_cell(&capability.permissions.join(","))
        ),
        format!("session_handoff\t{}", table_cell(&handoff)),
    ]
    .join("\n")
}

fn table_cell(value: &str) -> String {
    value.replace(['\t', '\n', '\r'], " ")
}

fn execution_mode_name(mode: CapabilityExecutionMode) -> &'static str {
    match mode {
        CapabilityExecutionMode::Stateless => "stateless",
        CapabilityExecutionMode::SessionOnly => "session_only",
        CapabilityExecutionMode::Both => "both",
    }
}

fn risk_name(risk: CapabilityRiskLevel) -> &'static str {
    match risk {
        CapabilityRiskLevel::ReadOnly => "read_only",
        CapabilityRiskLevel::Mutating => "mutating",
        CapabilityRiskLevel::Destructive => "destructive",
        CapabilityRiskLevel::ExternalSideEffect => "external_side_effect",
    }
}

pub(crate) fn session_purpose_cli_name(purpose: &voidb_core::PluginSessionPurpose) -> String {
    use voidb_core::PluginSessionPurpose;

    match purpose {
        PluginSessionPurpose::InteractiveTerminal => "interactive_terminal".into(),
        PluginSessionPurpose::FileTransfer => "file_transfer".into(),
        PluginSessionPurpose::PortForward => "port_forward".into(),
        PluginSessionPurpose::DatabaseQuery => "database_query".into(),
        PluginSessionPurpose::DatabaseTransaction => "database_transaction".into(),
        PluginSessionPurpose::CacheCommand => "cache_command".into(),
        PluginSessionPurpose::LogStream => "log_stream".into(),
        PluginSessionPurpose::WatchStream => "watch_stream".into(),
        PluginSessionPurpose::InfrastructureClient => "infrastructure_client".into(),
        PluginSessionPurpose::SyncClient => "sync_client".into(),
        PluginSessionPurpose::CapabilityInvocation => "capability_invocation".into(),
        PluginSessionPurpose::PluginDefined(value) => format!("plugin_defined:{value}"),
    }
}

#[derive(Debug, Serialize)]
struct InvokeRunData {
    invocation_id: String,
    grant_id: String,
    plugin_id: String,
    capability_id: String,
    profile: ConnectionProfileRef,
    status: voidb_core::InvocationStatus,
    output: Value,
    output_summary: Value,
    page: Option<InvocationOutputPage>,
    timing: InvokeTiming,
    credential_refs: Vec<voidb_core::CredentialRef>,
    redaction: RedactionStatus,
    runtime: InvokeRuntimeSummary,
    output_limits: InvokeOutputLimits,
    policy_decision: CapabilityPolicyDecision,
    warnings: Vec<InvokeWarning>,
}

#[derive(Debug, Serialize)]
struct InvokeTiming {
    duration_ms: u64,
    timeout_ms: Option<u64>,
    timeout_source: InvokeTimeoutSource,
}

#[derive(Debug, Serialize)]
struct InvokeOutputLimits {
    max_bytes: u64,
    serialized_bytes: u64,
    truncated: bool,
    continuation_available: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum InvokeTimeoutSource {
    Override,
    CapabilityDefault,
    CoreDefault,
}

#[derive(Debug, Serialize)]
struct InvokeWarning {
    code: String,
    message: String,
    details: Value,
}

#[derive(Debug, Clone, Serialize)]
struct InvokeRuntimeSummary {
    kind: &'static str,
    transport: Option<&'static str>,
}

#[cfg(all(test, feature = "full"))]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use serde_json::json;
    use voidb_core::config::AppConfig;
    use voidb_core::{
        ConnectionConfig, DatabaseType, PolicyDecisionOutcome, PolicyReason, ProcessPluginRoot,
        ProcessPluginRootKind, discover_process_plugins_from_roots,
        migrated_profile_from_connection,
    };
    use voidb_plugin_duckdb::{DuckDbConfig, DuckDbService};
    use voidb_plugin_sqlite::{SqliteConfig, SqliteService};

    use super::*;

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
        let discovery = empty_discovery();
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
                .any(|capability| capability.qualified_id() == "s3.list")
        );
        assert!(
            capabilities
                .iter()
                .any(|capability| capability.qualified_id() == "docker.list_containers")
        );
        assert!(
            capabilities
                .iter()
                .any(|capability| capability.qualified_id() == "kubernetes.list")
        );
        assert!(
            capabilities
                .iter()
                .any(|capability| capability.qualified_id() == "mongodb.find")
        );
        assert!(
            capabilities
                .iter()
                .any(|capability| capability.qualified_id() == "elasticsearch.search")
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

        let capabilities = supported_capabilities(&empty_discovery());
        assert_eq!(capabilities.len(), 141);
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
                "docker.attach_input",
                "docker.attach_read",
                "docker.attach_resize",
                "docker.events_follow",
                "docker.exec_input",
                "docker.exec_read",
                "docker.exec_resize",
                "docker.exec_signal",
                "docker.logs_follow",
                "docker.stats_follow",
                "elasticsearch.search_stream_read",
                "kubernetes.exec_input",
                "kubernetes.exec_read",
                "kubernetes.exec_resize",
                "kubernetes.logs_follow",
                "kubernetes.port_forward_events",
                "kubernetes.watch_events",
                "mongodb.change_stream_read",
                "mongodb.cursor_read",
                "redis.monitor_read",
                "redis.pubsub_read",
                "redis.stream_read",
                "s3.transfer",
                "s3.transfer_status",
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
                "mongodb.run_command",
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
            ("postgres", postgres_capabilities()),
            ("mysql", mysql_capabilities()),
            ("sqlite", sqlite_capabilities()),
            ("duckdb", duckdb_capabilities()),
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
        for capability in supported_capabilities(&empty_discovery()) {
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
                "docker": [18, 8, 10, 0],
                "duckdb": [9, 7, 0, 2],
                "elasticsearch": [11, 10, 1, 0],
                "kubernetes": [16, 10, 6, 0],
                "mongodb": [15, 12, 2, 1],
                "mysql": [9, 7, 0, 2],
                "postgres": [9, 7, 0, 2],
                "redis": [11, 7, 3, 1],
                "s3": [13, 11, 2, 0],
                "sqlite": [9, 7, 0, 2],
                "ssh": [15, 6, 7, 2],
                "sync": [6, 6, 0, 0],
            })
        );
    }

    #[test]
    fn execution_mode_filters_include_capabilities_supported_by_both_transports() {
        let definitions = ssh_capabilities();
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
        let terminal = ssh_capabilities()
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
            ssh_capabilities()
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
            &empty_discovery(),
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
        let definitions = kubernetes_capabilities();
        let capability = find_capability(&definitions, "port_forward_events");
        let guidance = session_handoff_guidance(capability, "id:profile:test", &empty_discovery());

        assert_eq!(guidance["requires_destructive_acknowledgement"], false);
        assert_eq!(guidance["requires_start_acknowledgement"], true);
        assert_eq!(guidance["requires_destructive_grant"], true);
        let authorize = guidance["authorize_args"]
            .as_array()
            .expect("authorize args");
        assert!(
            authorize
                .iter()
                .any(|argument| argument == "--allow-destructive")
        );
        assert!(authorize.iter().any(|argument| argument == "--yes"));
        let open = guidance["session_open_args"]
            .as_array()
            .expect("session open args");
        assert!(open.iter().any(|argument| argument == "--yes"));
    }

    #[test]
    fn storage_and_ssh_release_candidate_catalog_is_bounded_and_gated() {
        let discovery = empty_discovery();
        let s3 = capabilities_for_plugin("s3", &discovery).expect("s3 capabilities");
        let ssh = capabilities_for_plugin("ssh", &discovery).expect("ssh capabilities");

        for id in ["put", "delete", "mkdir"] {
            let capability = find_capability(&s3, id);
            assert!(capability.destructive, "s3.{id} is destructive");
            assert!(
                capability.supports_dry_run,
                "s3.{id} supports dry-run promotion gate"
            );
            assert_eq!(capability.risk, CapabilityRiskLevel::Destructive);
            assert_permission(capability, "connection.write");
            assert_permission(capability, &format!("s3.{id}"));
        }

        let s3_list = find_capability(&s3, "list");
        assert_eq!(
            s3_list.output_schema["properties"]["limit"]["maximum"],
            json!(500)
        );
        assert_eq!(
            s3_list.output_schema["properties"]["next_cursor"]["type"][0],
            "string"
        );
        let s3_get = find_capability(&s3, "get");
        assert_eq!(
            s3_get.input_schema["properties"]["max_bytes"]["maximum"],
            json!(1024 * 1024)
        );
        assert!(
            s3_get
                .output_schema
                .to_string()
                .contains("content_truncated")
        );

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
    fn storage_plugins_map_to_one_fail_closed_transfer_lifecycle() {
        let s3 = voidb_plugin_s3::s3_transfer_contract();
        s3.validate().expect("valid S3 transfer contract");

        assert_eq!(s3.protocol_version, 1);
        assert!(
            s3.chunking
                .modes
                .contains(&voidb_core::AgentTransferChunkMode::Multipart)
        );
        assert_eq!(s3.resume.mode, voidb_core::AgentTransferResumeMode::Exact);

        for capabilities in [s3_capabilities()] {
            for capability in capabilities {
                if matches!(
                    capability.id.as_str(),
                    "transfer" | "transfer_status" | "lock_acquire" | "lock_release"
                ) {
                    let handoff = capability
                        .session_handoff
                        .expect("stateful transfer capability requires a session handoff");
                    assert_eq!(
                        handoff.purpose,
                        voidb_core::PluginSessionPurpose::FileTransfer
                    );
                    assert!(
                        handoff
                            .capabilities
                            .contains(&format!("{}.transfer", capability.plugin_id))
                    );
                    assert!(
                        handoff
                            .capabilities
                            .contains(&format!("{}.transfer_status", capability.plugin_id))
                    );
                    let validator = jsonschema::validator_for(&capability.output_schema)
                        .expect("transfer output schema compiles");
                    if capability.id == "transfer_status" {
                        assert!(validator.is_valid(&json!({
                            "active": false,
                            "event": null
                        })));
                    }
                } else {
                    assert!(capability.session_handoff.is_none());
                }
            }
        }
    }

    #[test]
    fn local_filesystem_boundary_capability_policy_is_scoped_and_explicit() {
        let discovery = empty_discovery();
        let s3 = capabilities_for_plugin("s3", &discovery).expect("s3 capabilities");
        let ssh = capabilities_for_plugin("ssh", &discovery).expect("ssh capabilities");

        for capability in [
            find_capability(&s3, "sync_plan"),
        ] {
            assert_eq!(capability.risk, CapabilityRiskLevel::ReadOnly);
            assert!(!capability.authorization.capability_wide_allowed);
            assert_permission(capability, "local.scan");
            let required = capability.input_schema["required"]
                .as_array()
                .expect("local scope required fields");
            for field in ["local_root", "local_path"] {
                assert!(required.iter().any(|value| value == field));
            }
        }

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
        let discovery = empty_discovery();
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
    fn container_and_document_beta_catalog_is_bounded_and_gated() {
        let discovery = empty_discovery();
        let docker = capabilities_for_plugin("docker", &discovery).expect("docker capabilities");
        let kubernetes =
            capabilities_for_plugin("kubernetes", &discovery).expect("kubernetes capabilities");
        let mongodb = capabilities_for_plugin("mongodb", &discovery).expect("mongodb capabilities");
        let elasticsearch = capabilities_for_plugin("elasticsearch", &discovery)
            .expect("elasticsearch capabilities");

        let docker_action = find_capability(&docker, "container_action");
        assert!(docker_action.destructive);
        assert!(docker_action.supports_dry_run);
        assert_eq!(docker_action.risk, CapabilityRiskLevel::Destructive);
        assert_permission(docker_action, "connection.write");
        assert_permission(docker_action, "docker.containers.lifecycle");
        assert_output_page_contract(find_capability(&docker, "list_containers"), 500);
        assert_output_page_contract(find_capability(&docker, "list_images"), 500);
        assert_eq!(
            find_capability(&docker, "logs").input_schema["properties"]["tail"]["maximum"],
            json!(5_000)
        );
        assert_eq!(
            find_capability(&docker, "logs").input_schema["properties"]["max_bytes"]["maximum"],
            json!(1024 * 1024)
        );
        assert_eq!(
            find_capability(&docker, "inspect_container").output_schema["properties"]["raw_omitted"]
                ["type"],
            "boolean"
        );

        for id in ["delete", "scale", "restart", "apply"] {
            let capability = find_capability(&kubernetes, id);
            assert!(capability.destructive, "kubernetes.{id} is destructive");
            assert!(
                capability.supports_dry_run,
                "kubernetes.{id} supports dry-run promotion gate"
            );
            assert_eq!(capability.risk, CapabilityRiskLevel::Destructive);
            assert_permission(capability, "connection.write");
        }
        assert_output_page_contract(find_capability(&kubernetes, "namespaces"), 500);
        assert_output_page_contract(find_capability(&kubernetes, "list"), 500);
        assert_eq!(
            find_capability(&kubernetes, "get_yaml").input_schema["properties"]["max_bytes"]["maximum"],
            json!(1024 * 1024)
        );
        assert_eq!(
            find_capability(&kubernetes, "logs").input_schema["properties"]["tail"]["maximum"],
            json!(5_000)
        );

        for id in ["insert", "update", "delete", "create_index", "run_command"] {
            let capability = find_capability(&mongodb, id);
            assert!(capability.destructive, "mongodb.{id} is destructive");
            assert!(
                capability.supports_dry_run,
                "mongodb.{id} supports dry-run promotion gate"
            );
            assert_eq!(capability.risk, CapabilityRiskLevel::Destructive);
            assert_permission(capability, "connection.write");
        }
        assert_output_page_contract(find_capability(&mongodb, "databases"), 500);
        assert_output_page_contract(find_capability(&mongodb, "find"), 500);
        assert_output_page_contract(find_capability(&mongodb, "aggregate"), 500);
        let mongo_aggregate = find_capability(&mongodb, "aggregate");
        assert!(!mongo_aggregate.destructive);
        assert!(!mongo_aggregate.supports_dry_run);

        let raw_api = find_capability(&elasticsearch, "raw_api");
        assert!(raw_api.destructive);
        assert!(raw_api.supports_dry_run);
        assert_eq!(raw_api.risk, CapabilityRiskLevel::Destructive);
        assert_permission(raw_api, "connection.write");
        assert_permission(raw_api, "elasticsearch.raw_api");
        assert_output_page_contract(find_capability(&elasticsearch, "indices"), 500);
        assert_output_page_contract(find_capability(&elasticsearch, "search"), 500);
        assert_eq!(
            find_capability(&elasticsearch, "mapping").output_schema["properties"]["raw_omitted"]["type"],
            "boolean"
        );
        assert!(raw_api.output_schema.to_string().contains("body_summary"));
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
        let capability = sqlite_capabilities()
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

    #[tokio::test]
    async fn invokes_sqlite_query_from_legacy_profile() {
        let path = temp_db_path();
        seed_sqlite(
            &path,
            "create table users(id integer primary key, name text);
             insert into users(name) values ('Ada');",
        )
        .await;
        let ctx = CliContext::new(AppConfig {
            connections: vec![sqlite_connection("local", &path)],
            settings: Default::default(),
            ..Default::default()
        });

        let data = run_invocation_with_discovery(
            &ctx,
            InvokeRunOptions {
                capability_ref: "sqlite.query".into(),
                profile_ref: "local".into(),
                input: json!({ "sql": "select name from users" }),
                timeout_ms: Some(5_000),
                dry_run: false,
                destructive_ack: false,
                page_limit: None,
                page_cursor: None,
            },
            &empty_discovery(),
        )
        .await
        .expect("invoke sqlite query");

        assert_eq!(data.plugin_id, "sqlite");
        assert_eq!(data.status, voidb_core::InvocationStatus::Succeeded);
        assert_eq!(data.output["statements"][0]["rows"][0]["name"], "Ada");
        let envelope = serde_json::to_value(success_envelope(&data)).expect("serialize envelope");
        assert_eq!(envelope["ok"], true);
        assert_eq!(envelope["schema_version"], INVOKE_CLI_SCHEMA_VERSION);
        assert_eq!(envelope["command"], "invoke");
        assert_eq!(envelope["warnings"], json!([]));
        assert_eq!(envelope["data"]["plugin_id"], "sqlite");
        assert_eq!(envelope["data"]["capability_id"], "query");
        assert_eq!(envelope["data"]["status"], "succeeded");
        assert_eq!(envelope["data"]["timing"]["timeout_ms"], 5_000);
        assert_eq!(envelope["data"]["timing"]["timeout_source"], "override");
        assert_eq!(envelope["data"]["redaction"], "not_required");
        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn invokes_sqlite_explain_from_legacy_profile() {
        let path = temp_db_path();
        seed_sqlite(
            &path,
            "create table users(id integer primary key, name text);
             insert into users(name) values ('Ada');",
        )
        .await;
        let ctx = CliContext::new(AppConfig {
            connections: vec![sqlite_connection("local", &path)],
            settings: Default::default(),
            ..Default::default()
        });

        let data = run_invocation_with_discovery(
            &ctx,
            InvokeRunOptions {
                capability_ref: "sqlite.explain".into(),
                profile_ref: "local".into(),
                input: json!({ "sql": "select name from users" }),
                timeout_ms: None,
                dry_run: false,
                destructive_ack: false,
                page_limit: None,
                page_cursor: None,
            },
            &empty_discovery(),
        )
        .await
        .expect("invoke sqlite explain");

        assert_eq!(data.plugin_id, "sqlite");
        assert_eq!(data.capability_id, "explain");
        assert_eq!(data.output["analyze"], false);
        assert_eq!(data.output["dialect"], "sqlite");
        assert_eq!(data.output["explained_statement_count"], 1);
        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn invokes_sqlite_query_from_migrated_profile() {
        let path = temp_db_path();
        seed_sqlite(
            &path,
            "create table users(id integer primary key, name text);
             insert into users(name) values ('Grace');",
        )
        .await;
        let connection = sqlite_connection("local", &path);
        let migrated_profile = migrated_profile_from_connection(&connection);
        let profile_id = migrated_profile.id.clone();
        let ctx = CliContext::new(AppConfig {
            connections: vec![connection],
            settings: Default::default(),
            ..Default::default()
        });

        let data = run_invocation_with_discovery_and_profiles(
            &ctx,
            InvokeRunOptions {
                capability_ref: "sqlite.query".into(),
                profile_ref: format!("id:{}", profile_id),
                input: json!({ "sql": "select name from users" }),
                timeout_ms: Some(5_000),
                dry_run: false,
                destructive_ack: false,
                page_limit: None,
                page_cursor: None,
            },
            &empty_discovery(),
            &[migrated_profile],
        )
        .await
        .expect("invoke sqlite query through migrated profile");

        assert_eq!(data.plugin_id, "sqlite");
        assert_eq!(data.profile, ConnectionProfileRef::Id(profile_id));
        assert_eq!(data.output["statements"][0]["rows"][0]["name"], "Grace");
        let _ = fs::remove_file(path);
    }

    #[test]
    fn profile_matcher_accepts_bare_immutable_profile_id() {
        let profile = migrated_profile_from_connection(&sqlite_connection("local", ":memory:"));

        assert!(profile_matches_ref(&profile, &profile.id));
    }

    #[tokio::test]
    async fn destructive_sqlite_exec_requires_ack_or_dry_run() {
        let path = temp_db_path();
        seed_sqlite(
            &path,
            "create table users(id integer primary key, name text);",
        )
        .await;
        let ctx = CliContext::new(AppConfig {
            connections: vec![sqlite_connection("local", &path)],
            settings: Default::default(),
            ..Default::default()
        });

        let error = run_invocation(
            &ctx,
            InvokeRunOptions {
                capability_ref: "sqlite.exec".into(),
                profile_ref: "local".into(),
                input: json!({ "sql": "insert into users(name) values ('Ada')" }),
                timeout_ms: None,
                dry_run: false,
                destructive_ack: false,
                page_limit: None,
                page_cursor: None,
            },
        )
        .await
        .expect_err("destructive denied");

        assert_eq!(error.code, "policy.destructive_denied_by_default");
        assert_eq!(exit_code_for_error(&error), 3);
        let error_envelope = serde_json::to_value(JsonErrorEnvelope {
            ok: false,
            schema_version: INVOKE_CLI_SCHEMA_VERSION,
            command: "invoke",
            exit_code: exit_code_for_error(&error),
            error: (*error).clone(),
        })
        .expect("serialize error envelope");
        assert_eq!(error_envelope["ok"], false);
        assert_eq!(error_envelope["command"], "invoke");
        assert_eq!(error_envelope["exit_code"], 3);
        assert_eq!(error_envelope["error"]["category"], "policy");
        assert_eq!(
            error_envelope["error"]["code"],
            "policy.destructive_denied_by_default"
        );

        let data = run_invocation_with_discovery(
            &ctx,
            InvokeRunOptions {
                capability_ref: "sqlite.exec".into(),
                profile_ref: "local".into(),
                input: json!({ "sql": "insert into users(name) values ('Ada')" }),
                timeout_ms: None,
                dry_run: false,
                destructive_ack: true,
                page_limit: None,
                page_cursor: None,
            },
            &empty_discovery(),
        )
        .await
        .expect("destructive acknowledged");

        assert_eq!(data.output_summary["rows_affected"], 1);
        assert_eq!(data.output["mutation_gate"]["acknowledged"], true);
        assert_eq!(data.output_summary["mutation_gate"]["dry_run"], false);
        assert_eq!(
            data.policy_decision.reason.code,
            "policy.destructive_invocation_acknowledged"
        );
        assert_eq!(
            data.warnings[0].code,
            "policy.destructive_invocation_acknowledged"
        );
        let _ = fs::remove_file(path);
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
    async fn redis_dry_run_does_not_open_target_connection() {
        let ctx = CliContext::new(AppConfig {
            connections: vec![redis_connection()],
            settings: Default::default(),
            ..Default::default()
        });

        let data = run_invocation_with_discovery(
            &ctx,
            InvokeRunOptions {
                capability_ref: "redis.set".into(),
                profile_ref: "cache".into(),
                input: json!({ "key": "agent:test", "value": "value" }),
                timeout_ms: None,
                dry_run: true,
                destructive_ack: false,
                page_limit: None,
                page_cursor: None,
            },
            &empty_discovery(),
        )
        .await
        .expect("redis dry-run");

        assert_eq!(data.output["dry_run"], true);
        assert_eq!(data.output["operation"], "set");
    }

    #[tokio::test]
    async fn ssh_exec_dry_run_does_not_open_target_connection() {
        let ctx = CliContext::new(AppConfig {
            connections: vec![ssh_connection()],
            settings: Default::default(),
            ..Default::default()
        });

        let data = run_invocation(
            &ctx,
            InvokeRunOptions {
                capability_ref: "ssh.exec".into(),
                profile_ref: "shell".into(),
                input: json!({ "command": "rm -rf /tmp/nope" }),
                timeout_ms: None,
                dry_run: true,
                destructive_ack: false,
                page_limit: None,
                page_cursor: None,
            },
        )
        .await
        .expect("ssh exec dry-run");

        assert_eq!(data.plugin_id, "ssh");
        assert_eq!(data.output["dry_run"], true);
        assert_eq!(data.output["operation"], "exec");
        assert_eq!(data.runtime.kind, "builtin");
    }

    #[tokio::test]
    async fn s3_put_dry_run_does_not_open_target_connection() {
        let ctx = CliContext::new(AppConfig {
            connections: vec![s3_connection()],
            settings: Default::default(),
            ..Default::default()
        });

        let data = run_invocation(
            &ctx,
            InvokeRunOptions {
                capability_ref: "s3.put".into(),
                profile_ref: "objects".into(),
                input: json!({
                    "bucket": "missing-bucket",
                    "key": "agent/probe.txt",
                    "content_text": "hello"
                }),
                timeout_ms: None,
                dry_run: true,
                destructive_ack: false,
                page_limit: None,
                page_cursor: None,
            },
        )
        .await
        .expect("s3 put dry-run");

        assert_eq!(data.plugin_id, "s3");
        assert_eq!(data.output["dry_run"], true);
        assert_eq!(data.output["operation"], "put");
        assert_eq!(data.output_summary["dry_run"], true);
        assert_eq!(data.output_summary["operation"], "put");
        assert_eq!(data.runtime.kind, "builtin");
        let encoded = serde_json::to_string(&data).expect("serialize data");
        assert!(!encoded.contains("hello"));
    }

    #[tokio::test]
    async fn destructive_storage_invocations_require_ack_or_dry_run() {
        let s3_ctx = CliContext::new(AppConfig {
            connections: vec![s3_connection()],
            settings: Default::default(),
            ..Default::default()
        });

        let s3_error = run_invocation(
            &s3_ctx,
            InvokeRunOptions {
                capability_ref: "s3.delete".into(),
                profile_ref: "objects".into(),
                input: json!({
                    "bucket": "missing-bucket",
                    "key": "agent/probe.txt"
                }),
                timeout_ms: None,
                dry_run: false,
                destructive_ack: false,
                page_limit: None,
                page_cursor: None,
            },
        )
        .await
        .expect_err("s3 destructive denied");

        assert_eq!(s3_error.category, CapabilityErrorCategory::Policy);
        assert_eq!(s3_error.code, "policy.destructive_denied_by_default");
        assert_eq!(s3_error.details["qualified_id"], "s3.delete");
    }

    #[test]
    fn storage_and_ssh_policy_denials_have_redacted_audit_context() {
        for (capability_ref, profile_ref, input, sensitive_value) in [
            (
                "s3.put",
                "objects",
                json!({
                    "bucket": "release-candidate",
                    "key": "agent/probe.txt",
                    "content_text": "payload-secret"
                }),
                "payload-secret",
            ),
            (
                "ssh.exec",
                "shell",
                json!({ "command": "cat /etc/shadow" }),
                "cat /etc/shadow",
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

    #[test]
    fn local_filesystem_boundary_audit_denials_keep_only_opaque_scope_metadata() {
        for (capability_ref, profile_ref, input, local_root, relative_path) in [
            (
                "ssh.sftp_get",
                "shell",
                json!({
                    "remote_path": "/remote/report.txt",
                    "local_root": "/Users/private/approved-downloads",
                    "local_path": "../outside.txt",
                }),
                "/Users/private/approved-downloads",
                "../outside.txt",
            ),
            (
                "s3.sync_plan",
                "objects",
                json!({
                    "bucket": "reports",
                    "local_root": "/Volumes/private/数据",
                    "local_path": "财务/预算",
                }),
                "/Volumes/private/数据",
                "财务/预算",
            ),
        ] {
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
                "docker.container_action",
                "docker",
                json!({ "id": "prod-container-123", "action": "remove" }),
                "prod-container-123",
            ),
            (
                "kubernetes.apply",
                "cluster",
                json!({
                    "yaml": "apiVersion: v1\nkind: Secret\nmetadata:\n  name: prod-secret\n"
                }),
                "prod-secret",
            ),
            (
                "mongodb.insert",
                "mongo",
                json!({
                    "database": "app",
                    "collection": "users",
                    "document": { "email": "ada@example.com", "role": "admin" }
                }),
                "ada@example.com",
            ),
            (
                "elasticsearch.raw_api",
                "search",
                json!({
                    "method": "POST",
                    "path": "/users/_doc/1",
                    "body": { "email": "ada@example.com", "role": "admin" }
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
    async fn docker_container_action_dry_run_does_not_open_daemon_connection() {
        let ctx = CliContext::new(AppConfig {
            connections: vec![docker_connection()],
            settings: Default::default(),
            ..Default::default()
        });

        let data = run_invocation(
            &ctx,
            InvokeRunOptions {
                capability_ref: "docker.container_action".into(),
                profile_ref: "docker".into(),
                input: json!({ "id": "abc123", "action": "restart" }),
                timeout_ms: None,
                dry_run: true,
                destructive_ack: false,
                page_limit: None,
                page_cursor: None,
            },
        )
        .await
        .expect("docker dry-run");

        assert_eq!(data.plugin_id, "docker");
        assert_eq!(data.output["dry_run"], true);
        assert_eq!(data.output["operation"], "container_action");
        assert_eq!(data.output_summary["dry_run"], true);
        assert_eq!(data.runtime.kind, "builtin");
    }

    #[tokio::test]
    async fn kubernetes_apply_dry_run_does_not_open_cluster_connection() {
        let ctx = CliContext::new(AppConfig {
            connections: vec![kubernetes_connection()],
            settings: Default::default(),
            ..Default::default()
        });

        let data = run_invocation(
            &ctx,
            InvokeRunOptions {
                capability_ref: "kubernetes.apply".into(),
                profile_ref: "cluster".into(),
                input: json!({
                    "yaml": "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: agent-probe\n"
                }),
                timeout_ms: None,
                dry_run: true,
                destructive_ack: false,
                page_limit: None,
                page_cursor: None,
            },
        )
        .await
        .expect("kubernetes apply dry-run");

        assert_eq!(data.plugin_id, "kubernetes");
        assert_eq!(data.output["dry_run"], true);
        assert_eq!(data.output["operation"], "apply");
        assert_eq!(data.output["details"]["kind"], "ConfigMap");
        assert_eq!(data.runtime.kind, "builtin");
        let encoded = serde_json::to_string(&data).expect("serialize data");
        assert!(!encoded.contains("cluster-token"));
    }

    #[tokio::test]
    async fn mongodb_insert_dry_run_does_not_open_target_connection() {
        let ctx = CliContext::new(AppConfig {
            connections: vec![mongodb_connection()],
            settings: Default::default(),
            ..Default::default()
        });

        let data = run_invocation(
            &ctx,
            InvokeRunOptions {
                capability_ref: "mongodb.insert".into(),
                profile_ref: "mongo".into(),
                input: json!({
                    "database": "app",
                    "collection": "users",
                    "document": { "email": "ada@example.com", "role": "admin" }
                }),
                timeout_ms: None,
                dry_run: true,
                destructive_ack: false,
                page_limit: None,
                page_cursor: None,
            },
        )
        .await
        .expect("mongodb insert dry-run");
        let encoded = serde_json::to_string(&data).expect("serialize data");

        assert_eq!(data.plugin_id, "mongodb");
        assert_eq!(data.output["dry_run"], true);
        assert_eq!(data.output["operation"], "insert");
        assert_eq!(data.output_summary["dry_run"], true);
        assert_eq!(data.runtime.kind, "builtin");
        assert!(!encoded.contains("ada@example.com"));
        assert!(!encoded.contains("mongo-secret"));
    }

    #[tokio::test]
    async fn elasticsearch_raw_api_dry_run_does_not_open_target_connection() {
        let ctx = CliContext::new(AppConfig {
            connections: vec![elasticsearch_connection()],
            settings: Default::default(),
            ..Default::default()
        });

        let data = run_invocation(
            &ctx,
            InvokeRunOptions {
                capability_ref: "elasticsearch.raw_api".into(),
                profile_ref: "search".into(),
                input: json!({
                    "method": "POST",
                    "path": "/users/_doc/1",
                    "body": { "email": "ada@example.com", "role": "admin" }
                }),
                timeout_ms: None,
                dry_run: true,
                destructive_ack: false,
                page_limit: None,
                page_cursor: None,
            },
        )
        .await
        .expect("elasticsearch raw_api dry-run");
        let encoded = serde_json::to_string(&data).expect("serialize data");

        assert_eq!(data.plugin_id, "elasticsearch");
        assert_eq!(data.output["dry_run"], true);
        assert_eq!(data.output["operation"], "raw_api");
        assert_eq!(data.output_summary["dry_run"], true);
        assert_eq!(data.runtime.kind, "builtin");
        assert!(!encoded.contains("ada@example.com"));
        assert!(!encoded.contains("es-token"));
    }

    #[tokio::test]
    async fn destructive_operations_require_ack_or_dry_run_for_operations_plugins() {
        let docker_ctx = CliContext::new(AppConfig {
            connections: vec![docker_connection()],
            settings: Default::default(),
            ..Default::default()
        });

        let docker_error = run_invocation(
            &docker_ctx,
            InvokeRunOptions {
                capability_ref: "docker.container_action".into(),
                profile_ref: "docker".into(),
                input: json!({ "id": "abc123", "action": "remove" }),
                timeout_ms: None,
                dry_run: false,
                destructive_ack: false,
                page_limit: None,
                page_cursor: None,
            },
        )
        .await
        .expect_err("docker destructive denied");

        assert_eq!(docker_error.category, CapabilityErrorCategory::Policy);
        assert_eq!(docker_error.code, "policy.destructive_denied_by_default");
        assert_eq!(
            docker_error.details["qualified_id"],
            "docker.container_action"
        );

        let k8s_ctx = CliContext::new(AppConfig {
            connections: vec![kubernetes_connection()],
            settings: Default::default(),
            ..Default::default()
        });

        let k8s_error = run_invocation(
            &k8s_ctx,
            InvokeRunOptions {
                capability_ref: "kubernetes.delete".into(),
                profile_ref: "cluster".into(),
                input: json!({
                    "resource_type": "pod",
                    "name": "agent-probe",
                    "namespace": "default"
                }),
                timeout_ms: None,
                dry_run: false,
                destructive_ack: false,
                page_limit: None,
                page_cursor: None,
            },
        )
        .await
        .expect_err("kubernetes destructive denied");

        assert_eq!(k8s_error.category, CapabilityErrorCategory::Policy);
        assert_eq!(k8s_error.code, "policy.destructive_denied_by_default");
        assert_eq!(k8s_error.details["qualified_id"], "kubernetes.delete");
    }

    #[tokio::test]
    async fn destructive_document_invocations_require_ack_or_dry_run() {
        let mongo_ctx = CliContext::new(AppConfig {
            connections: vec![mongodb_connection()],
            settings: Default::default(),
            ..Default::default()
        });

        let mongo_error = run_invocation(
            &mongo_ctx,
            InvokeRunOptions {
                capability_ref: "mongodb.insert".into(),
                profile_ref: "mongo".into(),
                input: json!({
                    "database": "app",
                    "collection": "users",
                    "document": { "name": "Ada" }
                }),
                timeout_ms: None,
                dry_run: false,
                destructive_ack: false,
                page_limit: None,
                page_cursor: None,
            },
        )
        .await
        .expect_err("mongodb destructive denied");

        assert_eq!(mongo_error.category, CapabilityErrorCategory::Policy);
        assert_eq!(mongo_error.code, "policy.destructive_denied_by_default");
        assert_eq!(mongo_error.details["qualified_id"], "mongodb.insert");

        let es_ctx = CliContext::new(AppConfig {
            connections: vec![elasticsearch_connection()],
            settings: Default::default(),
            ..Default::default()
        });

        let es_error = run_invocation(
            &es_ctx,
            InvokeRunOptions {
                capability_ref: "elasticsearch.raw_api".into(),
                profile_ref: "search".into(),
                input: json!({
                    "method": "DELETE",
                    "path": "/users/_doc/1"
                }),
                timeout_ms: None,
                dry_run: false,
                destructive_ack: false,
                page_limit: None,
                page_cursor: None,
            },
        )
        .await
        .expect_err("elasticsearch destructive denied");

        assert_eq!(es_error.category, CapabilityErrorCategory::Policy);
        assert_eq!(es_error.code, "policy.destructive_denied_by_default");
        assert_eq!(es_error.details["qualified_id"], "elasticsearch.raw_api");
    }

    #[tokio::test]
    async fn postgres_exec_dry_run_accepts_legacy_postgresql_profile() {
        let ctx = CliContext::new(AppConfig {
            connections: vec![postgres_legacy_connection()],
            settings: Default::default(),
            ..Default::default()
        });

        let data = run_invocation(
            &ctx,
            InvokeRunOptions {
                capability_ref: "postgres.exec".into(),
                profile_ref: "warehouse".into(),
                input: json!({ "sql": "drop table audit_log" }),
                timeout_ms: None,
                dry_run: true,
                destructive_ack: false,
                page_limit: None,
                page_cursor: None,
            },
        )
        .await
        .expect("postgres exec dry-run");

        assert_eq!(data.plugin_id, "postgres");
        assert_eq!(data.output["dry_run"], true);
        assert_eq!(data.output["operation"], "exec");
        assert_eq!(data.runtime.kind, "builtin");
    }

    #[tokio::test]
    async fn invokes_duckdb_query_from_legacy_profile() {
        let path = temp_duckdb_path();
        seed_duckdb(
            &path,
            "create table users(id integer primary key, name varchar);
             insert into users values (1, 'Ada');",
        )
        .await;
        let ctx = CliContext::new(AppConfig {
            connections: vec![duckdb_connection("analytics", &path)],
            settings: Default::default(),
            ..Default::default()
        });

        let data = run_invocation(
            &ctx,
            InvokeRunOptions {
                capability_ref: "duckdb.query".into(),
                profile_ref: "analytics".into(),
                input: json!({ "sql": "select name from users" }),
                timeout_ms: Some(5_000),
                dry_run: false,
                destructive_ack: false,
                page_limit: None,
                page_cursor: None,
            },
        )
        .await
        .expect("invoke duckdb query");

        assert_eq!(data.plugin_id, "duckdb");
        assert_eq!(data.status, voidb_core::InvocationStatus::Succeeded);
        assert_eq!(data.output["statements"][0]["rows"][0]["name"], "Ada");
        assert_eq!(data.runtime.kind, "builtin");
        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn duckdb_exec_dry_run_does_not_open_target_connection() {
        let ctx = CliContext::new(AppConfig {
            connections: vec![duckdb_connection(
                "analytics",
                "/no/such/directory/voidb-dry-run.duckdb",
            )],
            settings: Default::default(),
            ..Default::default()
        });

        let data = run_invocation(
            &ctx,
            InvokeRunOptions {
                capability_ref: "duckdb.exec".into(),
                profile_ref: "analytics".into(),
                input: json!({ "sql": "drop table scratch" }),
                timeout_ms: None,
                dry_run: true,
                destructive_ack: false,
                page_limit: None,
                page_cursor: None,
            },
        )
        .await
        .expect("duckdb exec dry-run");

        assert_eq!(data.plugin_id, "duckdb");
        assert_eq!(data.output["dry_run"], true);
        assert_eq!(data.output["operation"], "exec");
        assert_eq!(data.runtime.kind, "builtin");
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

    #[tokio::test]
    async fn pre_cancelled_in_process_invocation_terminates_structurally() {
        let path = temp_db_path();
        seed_sqlite(&path, "create table items(id integer);").await;
        let ctx = CliContext::new(AppConfig {
            connections: vec![sqlite_connection("local", &path)],
            settings: Default::default(),
            ..Default::default()
        });
        let profiles = voidb_core::connection_configs_to_profiles(&ctx.config.connections);
        let (cancel_tx, cancel_rx) = watch::channel(false);
        cancel_tx.send(true).expect("pre-cancel");

        let error = run_invocation_with_discovery_and_profiles_with_id(
            &ctx,
            InvokeRunOptions {
                capability_ref: "sqlite.query".into(),
                profile_ref: "local".into(),
                input: json!({ "sql": "select * from items" }),
                timeout_ms: Some(1_000),
                dry_run: false,
                destructive_ack: false,
                page_limit: Some(10),
                page_cursor: None,
            },
            &empty_discovery(),
            &profiles,
            "caller-owned-builtin-01".into(),
            false,
            "cancel-builtin-01".into(),
            DEFAULT_INVOCATION_OUTPUT_BYTES,
            cancel_rx,
            None,
        )
        .await
        .expect_err("cancelled builtin");

        assert_eq!(error.category, CapabilityErrorCategory::Cancellation);
        assert_eq!(error.code, "cancellation.requested");
        assert_eq!(
            error
                .grant
                .as_ref()
                .map(|grant| grant.invocation_id.as_str()),
            Some("caller-owned-builtin-01")
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn process_plugin_target_failure_is_structured_and_redacted() {
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

    fn assert_output_page_contract(capability: &CapabilityDefinition, max_limit: u32) {
        assert_eq!(
            capability.output_schema["properties"]["limit"]["maximum"],
            json!(max_limit),
            "{} should expose a bounded page limit",
            capability.qualified_id()
        );
        assert_eq!(
            capability.output_schema["properties"]["next_cursor"]["type"][0],
            "string",
            "{} should expose a cursor continuation",
            capability.qualified_id()
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

    fn s3_connection() -> ConnectionConfig {
        ConnectionConfig {
            name: "objects".into(),
            db_type: DatabaseType::Plugin,
            plugin_id: Some("s3".into()),
            plugin_config: Some(json!({
                "provider": {
                    "type": "Aws",
                    "region": "us-east-1"
                },
                "bucket": null,
                "auth": {
                    "type": "Auto"
                },
                "timeout": 30
            })),
        }
    }

    fn docker_connection() -> ConnectionConfig {
        ConnectionConfig {
            name: "docker".into(),
            db_type: DatabaseType::Plugin,
            plugin_id: Some("docker".into()),
            plugin_config: Some(json!({
                "connection": {
                    "type": "Socket",
                    "path": "/no/such/docker.sock"
                },
                "timeout": 1
            })),
        }
    }

    fn kubernetes_connection() -> ConnectionConfig {
        ConnectionConfig {
            name: "cluster".into(),
            db_type: DatabaseType::Plugin,
            plugin_id: Some("kubernetes".into()),
            plugin_config: Some(json!({
                "connection": {
                    "type": "Direct",
                    "api_url": "https://127.0.0.1:1",
                    "auth": {
                        "type": "Token",
                        "token": "cluster-token"
                    },
                    "verify_ssl": false,
                    "ca_cert": null
                },
                "default_namespace": "default",
                "timeout": 1
            })),
        }
    }

    fn mongodb_connection() -> ConnectionConfig {
        ConnectionConfig {
            name: "mongo".into(),
            db_type: DatabaseType::Plugin,
            plugin_id: Some("mongodb".into()),
            plugin_config: Some(json!({
                "uri": "mongodb://user:mongo-secret@127.0.0.1:1/app",
                "default_db": "app",
                "auth": {
                    "type": "Password",
                    "username": "user",
                    "password": "mongo-secret",
                    "auth_db": "admin"
                },
                "timeout": 1
            })),
        }
    }

    fn elasticsearch_connection() -> ConnectionConfig {
        ConnectionConfig {
            name: "search".into(),
            db_type: DatabaseType::Plugin,
            plugin_id: Some("elasticsearch".into()),
            plugin_config: Some(json!({
                "urls": ["https://search.example.invalid:9200"],
                "auth": {
                    "type": "Bearer",
                    "token": "es-token"
                },
                "timeout": 1,
                "verify_ssl": false
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

    fn temp_db_path() -> String {
        static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

        let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        std::env::temp_dir()
            .join(format!(
                "voidb-invoke-sqlite-{}-{}.db",
                std::process::id(),
                id
            ))
            .to_string_lossy()
            .into_owned()
    }

    fn temp_duckdb_path() -> String {
        static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

        let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        std::env::temp_dir()
            .join(format!(
                "voidb-invoke-duckdb-{}-{}.duckdb",
                std::process::id(),
                id
            ))
            .to_string_lossy()
            .into_owned()
    }

    fn empty_discovery() -> ProcessPluginDiscovery {
        ProcessPluginDiscovery {
            roots: Vec::new(),
            candidates: Vec::new(),
        }
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
      invocation_id=$(printf '%s\n' "$line" | /usr/bin/sed -n 's/.*"invocation":{"id":"\([^"]*\)".*/\1/p')
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

    async fn seed_sqlite(path: &str, sql: &str) {
        let mut service = SqliteService::new_direct(&SqliteConfig::new(path.into()))
            .expect("create sqlite service");
        service.execute_query(sql).await.expect("seed sqlite");
    }

    async fn seed_duckdb(path: &str, sql: &str) {
        let mut service = DuckDbService::new_direct(&DuckDbConfig::new(path.into()))
            .expect("create duckdb service");
        service.execute_query(sql).await.expect("seed duckdb");
    }
}
