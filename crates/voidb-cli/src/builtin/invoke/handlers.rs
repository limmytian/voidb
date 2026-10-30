use clap::ArgMatches;
use serde_json::{Value, json};
use std::io;
use std::time::Duration;
use tokio::sync::{mpsc, watch};
use uuid::Uuid;
use voidb_core::capability::{
    CapabilityDefinition, CapabilityError, CapabilityErrorCategory, CapabilityExecutionMode,
    InvocationStreamEvent,
};
use voidb_core::plugin::cli::CliContext;
use voidb_core::{
    DEFAULT_INVOCATION_OUTPUT_BYTES, MAX_INVOCATION_CURSOR_BYTES, MAX_INVOCATION_OUTPUT_BYTES,
    MAX_INVOCATION_PAGE_LIMIT, VoidbError, discover_process_plugins,
};

use super::audit::{
    InvokeAuditContext, InvokeRunError, append_credential_grant_failure_audit,
    append_credential_grant_success_audit, append_invoke_error_audit, append_invoke_success_audit,
};
use super::discovery::supported_capabilities;
use crate::builtin::json_output::print_json;
use super::execution::{
    InvokeRunOptions, ParsedInvokeRunOptions, next_invocation_id, preview_effective_timeout_ms,
    resolve_capability, run_invocation_with_id,
};
use super::output::{
    CapabilitySummary, InvokeCatalogOutputFormat, InvokeDescribeData, InvokeListData,
    InvokeOutputFormat, JsonErrorEnvelope, NdjsonEmitter, capability_description_table,
    capability_error, capability_list_table, exit_code_for_error, print_run_error,
    print_run_success, run_output_format, success_envelope,
};
use super::{
    INVOCATION_CANCEL_GRACE_MS, INVOCATION_STREAM_CHANNEL_CAPACITY, INVOKE_CLI_SCHEMA_VERSION,
    MAX_PUBLIC_CONTROL_ID_BYTES,
};

pub(super) fn handle_matrix(matches: &ArgMatches) -> Result<(), VoidbError> {
    #[cfg(not(feature = "full"))]
    {
        let _ = matches;
        Err(VoidbError::Plugin(
            "Capability matrix generation requires the 'full' feature flag: cargo run -p voidb-cli --features full -- invoke matrix".into(),
        ))
    }
    #[cfg(feature = "full")]
    {
        let matrix = crate::builtin::capability_matrix::build()?;
        match matches.get_one::<String>("format").map(String::as_str) {
            Some("json") => print_json(&matrix),
            Some("markdown") | None => {
                println!(
                    "{}",
                    crate::builtin::capability_matrix::render_markdown(&matrix)
                );
                Ok(())
            }
            Some(other) => Err(VoidbError::Plugin(format!(
                "Unsupported capability matrix format '{other}'"
            ))),
        }
    }
}

pub(super) fn catalog_output_format(
    matches: &ArgMatches,
) -> Result<InvokeCatalogOutputFormat, VoidbError> {
    match matches.get_one::<String>("format").map(String::as_str) {
        Some("json") | None => Ok(InvokeCatalogOutputFormat::Json),
        Some("table") => Ok(InvokeCatalogOutputFormat::Table),
        Some(other) => Err(VoidbError::Plugin(format!(
            "Unsupported invoke catalog output format '{}'; use --format json or --format table",
            other
        ))),
    }
}

pub(super) fn handle_list(matches: &ArgMatches) -> Result<(), VoidbError> {
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

pub(super) fn handle_describe(matches: &ArgMatches) -> Result<(), VoidbError> {
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

pub(super) fn execution_mode_filters(matches: &ArgMatches) -> Vec<CapabilityExecutionMode> {
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

pub(super) fn capability_matches_execution_modes(
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

pub(super) async fn handle_run(matches: &ArgMatches, ctx: &CliContext) -> Result<(), VoidbError> {
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

pub(super) fn validate_pagination_bounds(
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

pub(super) fn validate_public_control_id(
    value: &str,
    argument: &str,
) -> Result<(), Box<CapabilityError>> {
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

pub(super) fn parse_duration_ms(raw: &str) -> Result<u64, Box<CapabilityError>> {
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
