use chrono::Utc;
use serde::Serialize;
use serde_json::{Value, json};
#[cfg(feature = "sync")]
use std::time::Duration;
use std::time::Instant;
use tokio::sync::{mpsc, watch};
use uuid::Uuid;
#[cfg(all(test, feature = "full"))]
use voidb_core::DEFAULT_INVOCATION_OUTPUT_BYTES;
use voidb_core::capability::{
    CapabilityDefinition, CapabilityError, CapabilityErrorCategory, CapabilityInvocation,
    CapabilityInvocationResult, CapabilityPolicyDecision, CapabilityPolicyRequest,
    ConnectionInstancePurpose, ConnectionProfile, ConnectionProfileRef, CredentialClass,
    CredentialGrant, InstanceReusePolicy, InvocationAcknowledgement, InvocationConnectionTarget,
    InvocationControls, InvocationOutputPage, InvocationStreamEvent, Pagination, RedactionStatus,
};
use voidb_core::plugin::cli::CliContext;
use voidb_core::{
    ConnectionConfig, DEFAULT_INVOCATION_PAGE_LIMIT, DEFAULT_INVOCATION_TIMEOUT_MS,
    ProcessPluginCandidate, ProcessPluginDiscovery, ProcessPluginRuntimeHost, audit_json_summary,
    discover_process_plugins, evaluate_capability_policy, grant_credentials_for_invocation,
    local_cli_actor,
};
#[cfg(feature = "sync")]
use voidb_plugin_sync::invoke_sync_capability;

use super::SUPPORTED_INVOKE_PLUGINS;
use super::audit::{InvokeGrantAuditData, InvokeRunError};
#[cfg(all(test, feature = "full"))]
use super::discovery::authorization_discovery;
use super::discovery::{
    capabilities_for_plugin, is_builtin_invoke_plugin, select_available_process_candidate,
};
use super::output::{capability_error, session_purpose_cli_name};
use super::profiles::{
    profiles_from_context, redact_error, redact_result, resolve_native_profile_connection,
};

#[cfg(all(test, feature = "full"))]
#[allow(clippy::result_large_err)]
pub(super) async fn run_invocation(
    ctx: &CliContext,
    options: InvokeRunOptions,
) -> Result<InvokeRunData, InvokeRunError> {
    run_invocation_with_discovery(ctx, options, &authorization_discovery()).await
}

#[allow(clippy::result_large_err)]
#[allow(clippy::too_many_arguments)]
pub(super) async fn run_invocation_with_id(
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
pub(super) async fn run_invocation_with_discovery(
    ctx: &CliContext,
    options: InvokeRunOptions,
    discovery: &ProcessPluginDiscovery,
) -> Result<InvokeRunData, InvokeRunError> {
    let profiles = voidb_core::connection_configs_to_profiles(&ctx.config.connections);
    run_invocation_with_discovery_and_profiles(ctx, options, discovery, &profiles).await
}

#[cfg(all(test, feature = "full"))]
#[allow(clippy::result_large_err)]
pub(super) async fn run_invocation_with_discovery_and_profiles(
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
pub(super) async fn run_invocation_with_discovery_and_profiles_with_id(
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

pub(super) fn effective_timeout_ms(
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

pub(super) fn preview_effective_timeout_ms(options: &InvokeRunOptions) -> Option<u64> {
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
pub(super) fn enforce_invocation_output_limit(
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

pub(super) async fn invoke_builtin_capability(
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
    _connection: &ConnectionConfig,
    invocation: CapabilityInvocation,
) -> Result<CapabilityInvocationResult, CapabilityError> {
    #[cfg(feature = "sync")]
    {
        let timeout_ms = invocation.controls.timeout_ms;
        if capability.plugin_id == "sync" {
            return invoke_with_timeout(
                invoke_sync_capability(invocation),
                timeout_ms,
                &capability.plugin_id,
                &capability.id,
            )
            .await;
        }
    }
    let _ = invocation;
    Err(capability_error(
        CapabilityErrorCategory::Unavailable,
        "unavailable.plugin_not_found",
        "Generic invoke only supports selected built-in plugins.",
        json!({ "plugin_id": capability.plugin_id, "supported_plugins": SUPPORTED_INVOKE_PLUGINS }),
        None,
        true,
    ))
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

#[cfg(feature = "sync")]
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

pub(super) fn resolve_capability(
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

pub(super) fn parse_capability_ref(
    capability_ref: &str,
) -> Result<(String, String), Box<CapabilityError>> {
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

pub(super) fn schema_value(
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

pub(super) fn credential_class_from_manifest(class: &str) -> CredentialClass {
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

pub(super) fn next_invocation_id() -> String {
    format!("invoke-{}", Uuid::new_v4())
}

#[derive(Debug)]
pub(super) struct InvokeRunOptions {
    pub(super) capability_ref: String,
    pub(super) profile_ref: String,
    pub(super) input: Value,
    pub(super) timeout_ms: Option<u64>,
    pub(super) dry_run: bool,
    pub(super) destructive_ack: bool,
    pub(super) page_limit: Option<u32>,
    pub(super) page_cursor: Option<String>,
}

#[derive(Debug)]
pub(super) struct ParsedInvokeRunOptions {
    pub(super) invocation: InvokeRunOptions,
    pub(super) cancellation_token: String,
    pub(super) max_output_bytes: u64,
}

#[derive(Debug, Serialize)]
pub(super) struct InvokeRunData {
    pub(super) invocation_id: String,
    pub(super) grant_id: String,
    pub(super) plugin_id: String,
    pub(super) capability_id: String,
    pub(super) profile: ConnectionProfileRef,
    pub(super) status: voidb_core::InvocationStatus,
    pub(super) output: Value,
    pub(super) output_summary: Value,
    pub(super) page: Option<InvocationOutputPage>,
    pub(super) timing: InvokeTiming,
    pub(super) credential_refs: Vec<voidb_core::CredentialRef>,
    pub(super) redaction: RedactionStatus,
    pub(super) runtime: InvokeRuntimeSummary,
    pub(super) output_limits: InvokeOutputLimits,
    pub(super) policy_decision: CapabilityPolicyDecision,
    pub(super) warnings: Vec<InvokeWarning>,
}

#[derive(Debug, Serialize)]
pub(super) struct InvokeTiming {
    pub(super) duration_ms: u64,
    pub(super) timeout_ms: Option<u64>,
    pub(super) timeout_source: InvokeTimeoutSource,
}

#[derive(Debug, Serialize)]
pub(super) struct InvokeOutputLimits {
    max_bytes: u64,
    serialized_bytes: u64,
    truncated: bool,
    continuation_available: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum InvokeTimeoutSource {
    Override,
    CapabilityDefault,
    CoreDefault,
}

#[derive(Debug, Serialize)]
pub(super) struct InvokeWarning {
    code: String,
    message: String,
    details: Value,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct InvokeRuntimeSummary {
    pub(super) kind: &'static str,
    pub(super) transport: Option<&'static str>,
}
