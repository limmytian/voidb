#![allow(clippy::result_large_err)]

use std::collections::{BTreeMap, BTreeSet};

use chrono::Utc;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use voidb_core::{
    CapabilityApprovalField, CapabilityApprovalRiskEmphasis, CapabilityApprovalSchema,
    CapabilityApprovalValueType, CapabilityAuthorizationMetadata, CapabilityConstraintKind,
    CapabilityDefinition, CapabilityError, CapabilityErrorCategory, CapabilityExecutionMode,
    CapabilityInvocation, CapabilityInvocationResult, CapabilityRiskLevel, InvocationOutputPage,
    InvocationStatus, OBJECT_SYNC_PAYLOAD_VERSION, OBJECT_SYNC_SCHEMA_VERSION, RedactionStatus,
};

use crate::client::{ObjectSummary, SyncClient};
use crate::config::{SyncAgentReplay, SyncConfig};
use crate::error::SyncError;
use crate::ops::{self, LoginInput, ObjectConflictResolutionInput, RecoverInput};
use crate::token_store::{self, TokenStoreStatus};

const PLUGIN_ID: &str = "sync";
const AGENT_SCHEMA_VERSION: u32 = 1;
const DEFAULT_PLAN_LIMIT: usize = 100;
const MAX_PLAN_LIMIT: usize = 500;
const MAX_PLAN_SOURCE_ITEMS: usize = 10_000;
const MAX_AGENT_REPLAYS: usize = 256;
const DEFAULT_PASSWORD_ENV: &str = "VOIDB_SYNC_PASSWORD";
const DEFAULT_RECOVERY_CODE_ENV: &str = "VOIDB_SYNC_RECOVERY_CODE";
const DEFAULT_NEW_PASSWORD_ENV: &str = "VOIDB_SYNC_NEW_PASSWORD";

#[derive(Debug, Clone)]
struct PlanItem {
    id: String,
    object_kind: String,
    object_id: String,
    action: &'static str,
    local_object_version: Option<u64>,
    local_server_revision: Option<u64>,
    remote_object_version: Option<u64>,
    remote_server_revision: Option<u64>,
    remote_schema_version: Option<u32>,
    compatible: bool,
    deleted: bool,
    reason: &'static str,
}

#[derive(Debug)]
struct SyncPlan {
    id: String,
    direction: String,
    items: Vec<PlanItem>,
}

pub fn sync_capabilities() -> Vec<CapabilityDefinition> {
    vec![
        capability(
            "status",
            "Return local Sync readiness, redacted pending-work counts, and compatibility metadata without network access.",
            empty_input_schema(),
            status_output_schema(),
            vec!["sync.status"],
            Some(5_000),
        ),
        capability(
            "diagnostics",
            "Check the configured Sync endpoint and return only redacted connectivity and compatibility diagnostics.",
            json!({
                "type": "object",
                "properties": {
                    "check_connectivity": {
                        "type": "boolean",
                        "default": true,
                        "description": "When false, report configuration readiness without a network request."
                    }
                },
                "additionalProperties": false
            }),
            diagnostics_output_schema(),
            vec!["sync.diagnostics"],
            Some(10_000),
        ),
        capability(
            "plan",
            "Build a stable, bounded metadata-only Sync decision plan from local mappings and authenticated remote summaries.",
            plan_input_schema(),
            plan_output_schema("items"),
            vec!["sync.plan"],
            Some(30_000),
        ),
        capability(
            "diff",
            "Return a stable, bounded metadata-only page of non-no-op Sync differences.",
            plan_input_schema(),
            plan_output_schema("differences"),
            vec!["sync.diff"],
            Some(30_000),
        ),
        guarded_capability(
            "conflict_resolve",
            "Resolve exactly one opaque object conflict after a dry-run preview, typed confirmation, acknowledgement, and replay check.",
            conflict_resolution_input_schema(),
            guarded_output_schema(),
            vec!["sync.conflict.resolve"],
            conflict_resolution_approval_schema(),
            CapabilityRiskLevel::Destructive,
            Some(120_000),
        ),
        guarded_capability(
            "recovery",
            "Retry object sync or perform an explicit reset, rebootstrap, or account recovery after a dry-run preview and typed confirmation.",
            recovery_input_schema(),
            guarded_output_schema(),
            vec!["sync.recovery"],
            recovery_approval_schema(),
            CapabilityRiskLevel::Destructive,
            Some(180_000),
        ),
    ]
}

pub async fn invoke_sync_capability(
    invocation: CapabilityInvocation,
) -> Result<CapabilityInvocationResult, CapabilityError> {
    if invocation.plugin_id != PLUGIN_ID {
        return Err(capability_error(
            CapabilityErrorCategory::Validation,
            "validation.plugin_mismatch",
            "Invocation plugin_id does not match Sync.",
            json!({ "expected": PLUGIN_ID, "actual": invocation.plugin_id }),
            false,
        ));
    }
    let config = SyncConfig::load().map_err(|error| {
        redacted_sync_error(
            "sync.config_unavailable",
            "Local Sync configuration could not be loaded.",
            &error,
            false,
        )
    })?;
    invoke_sync_capability_with_config(&config, invocation).await
}

pub async fn invoke_sync_capability_with_config(
    config: &SyncConfig,
    invocation: CapabilityInvocation,
) -> Result<CapabilityInvocationResult, CapabilityError> {
    match invocation.capability_id.as_str() {
        "status" => invoke_status(config, invocation.id),
        "diagnostics" => invoke_diagnostics(config, invocation).await,
        "plan" => invoke_plan(config, invocation, false).await,
        "diff" => invoke_plan(config, invocation, true).await,
        "conflict_resolve" => invoke_conflict_resolution(config, invocation).await,
        "recovery" => invoke_recovery(config, invocation).await,
        other => Err(capability_error(
            CapabilityErrorCategory::Unavailable,
            "unavailable.capability_not_found",
            "Sync capability was not found.",
            json!({ "capability_id": other }),
            false,
        )),
    }
}

fn invoke_status(
    config: &SyncConfig,
    invocation_id: String,
) -> Result<CapabilityInvocationResult, CapabilityError> {
    let token_status = token_store::status(config).unwrap_or_else(|_| TokenStoreStatus {
        present: false,
        backend: crate::token_store::TokenStoreBackend::None,
        mode: "unavailable",
        keyring_error: Some("token_store_error".into()),
    });
    let output = local_status(config, &token_status);
    let summary = json!({
        "ready": output["configuration"]["ready"],
        "pending_work_count": output["pending_work"]["total"],
        "conflict_count": output["pending_work"]["conflicts"],
        "redaction": "withheld"
    });
    Ok(result(invocation_id, output, summary))
}

async fn invoke_diagnostics(
    config: &SyncConfig,
    invocation: CapabilityInvocation,
) -> Result<CapabilityInvocationResult, CapabilityError> {
    let check_connectivity = invocation
        .input
        .get("check_connectivity")
        .and_then(Value::as_bool)
        .unwrap_or(true);
    let configured = config.server_url.is_some();
    let (connectivity, failure_code) = if !check_connectivity {
        ("not_checked", None)
    } else if let Some(server_url) = config.server_url.as_deref() {
        match SyncClient::new(server_url).healthz().await {
            Ok(true) => ("reachable", None),
            Ok(false) => ("unhealthy", Some("health_check_failed")),
            Err(error) => ("unreachable", Some(redacted_failure_code(&error))),
        }
    } else {
        ("not_configured", Some("server_not_configured"))
    };
    let output = json!({
        "configuration_ready": configuration_ready(config),
        "connectivity": connectivity,
        "network_checked": check_connectivity && configured,
        "failure_code": failure_code,
        "compatibility": compatibility_metadata(connectivity == "reachable"),
        "redaction": "withheld"
    });
    let summary = json!({
        "configuration_ready": output["configuration_ready"],
        "connectivity": connectivity,
        "failure_code": failure_code,
        "redaction": "withheld"
    });
    Ok(result(invocation.id, output, summary))
}

async fn invoke_plan(
    config: &SyncConfig,
    invocation: CapabilityInvocation,
    differences_only: bool,
) -> Result<CapabilityInvocationResult, CapabilityError> {
    let direction = invocation
        .input
        .get("direction")
        .and_then(Value::as_str)
        .unwrap_or("bidirectional");
    let object_kind = invocation.input.get("object_kind").and_then(Value::as_str);
    let server_url = config.server_url.as_deref().ok_or_else(|| {
        capability_error(
            CapabilityErrorCategory::Validation,
            "validation.sync_not_configured",
            "Sync plan requires a configured server.",
            json!({ "missing": "server" }),
            false,
        )
    })?;
    let token = token_store::load_token(config)
        .map_err(|error| {
            redacted_sync_error(
                "sync.token_store_unavailable",
                "Sync authentication state could not be loaded.",
                &error,
                false,
            )
        })?
        .ok_or_else(|| {
            capability_error(
                CapabilityErrorCategory::Credential,
                "credential.sync_token_missing",
                "Sync plan requires an enrolled device token.",
                json!({ "handoff": "voidb sync login" }),
                false,
            )
        })?;
    let remote = SyncClient::new(server_url)
        .with_token(token)
        .list_objects(true)
        .await
        .map_err(|error| {
            redacted_sync_error(
                "sync.plan_remote_metadata_failed",
                "Remote Sync metadata could not be listed.",
                &error,
                true,
            )
        })?;
    let mut plan = build_sync_plan(config, &remote, direction, object_kind)?;
    if differences_only {
        plan.items.retain(|item| item.action != "no_op");
    }
    paginated_plan_result(invocation, plan, differences_only)
}

fn build_sync_plan(
    config: &SyncConfig,
    remote: &[ObjectSummary],
    direction: &str,
    object_kind: Option<&str>,
) -> Result<SyncPlan, CapabilityError> {
    if !matches!(direction, "upload" | "download" | "bidirectional") {
        return Err(capability_error(
            CapabilityErrorCategory::Validation,
            "validation.sync_direction_invalid",
            "Sync plan direction is invalid.",
            json!({ "allowed": ["upload", "download", "bidirectional"] }),
            false,
        ));
    }
    if config.object_mappings.len().saturating_add(remote.len()) > MAX_PLAN_SOURCE_ITEMS {
        return Err(capability_error(
            CapabilityErrorCategory::Plugin,
            "plugin.sync_plan_source_limit_exceeded",
            "Sync plan metadata exceeded the bounded source-item limit.",
            json!({ "maximum_items": MAX_PLAN_SOURCE_ITEMS }),
            false,
        ));
    }

    let local = config
        .object_mappings
        .values()
        .filter(|mapping| object_kind.is_none_or(|kind| mapping.object_kind == kind))
        .map(|mapping| (mapping.object_id.as_str(), mapping))
        .collect::<BTreeMap<_, _>>();
    let remote = remote
        .iter()
        .filter(|summary| object_kind.is_none_or(|kind| summary.object_kind == kind))
        .map(|summary| (summary.object_id.as_str(), summary))
        .collect::<BTreeMap<_, _>>();
    let object_ids = local
        .keys()
        .chain(remote.keys())
        .copied()
        .collect::<BTreeSet<_>>();
    let mut items = Vec::with_capacity(object_ids.len());
    for object_id in object_ids {
        let local = local.get(object_id).copied();
        let remote = remote.get(object_id).copied();
        let conflict = config
            .object_conflicts
            .values()
            .find(|conflict| conflict.object_id == object_id);
        let object_kind = local
            .map(|mapping| mapping.object_kind.as_str())
            .or_else(|| remote.map(|summary| summary.object_kind.as_str()))
            .unwrap_or("unknown");
        let (mut action, mut reason) = plan_decision(local, remote, conflict.is_some());
        if (direction == "upload" && action == "download")
            || (direction == "download" && action == "upload")
        {
            action = "no_op";
            reason = "direction_filtered";
        }
        let deleted = remote.is_some_and(|summary| summary.deleted);
        let identity = format!(
            "{direction}\n{object_kind}\n{object_id}\n{action}\n{}\n{}\n{}\n{}\n{}\n{deleted}",
            local
                .map(|mapping| mapping.object_version)
                .unwrap_or_default(),
            local
                .map(|mapping| mapping.server_revision)
                .unwrap_or_default(),
            remote
                .map(|summary| summary.object_version)
                .unwrap_or_default(),
            remote
                .map(|summary| summary.server_revision)
                .unwrap_or_default(),
            remote
                .map(|summary| summary.schema_version)
                .unwrap_or_default(),
        );
        let compatible = remote
            .map(|summary| summary.schema_version == OBJECT_SYNC_SCHEMA_VERSION)
            .unwrap_or(true);
        items.push(PlanItem {
            id: format!("sync-item-{}", short_hash(identity.as_bytes())),
            object_kind: object_kind.to_string(),
            object_id: object_id.to_string(),
            action,
            local_object_version: local.map(|mapping| mapping.object_version),
            local_server_revision: local.map(|mapping| mapping.server_revision),
            remote_object_version: remote.map(|summary| summary.object_version),
            remote_server_revision: remote.map(|summary| summary.server_revision),
            remote_schema_version: remote.map(|summary| summary.schema_version),
            compatible,
            deleted,
            reason,
        });
    }
    let mut plan_material = format!("{direction}\n");
    for item in &items {
        plan_material.push_str(&format!(
            "{}\n{}\n{}\n{}\n",
            item.id, item.object_kind, item.object_id, item.action
        ));
    }
    Ok(SyncPlan {
        id: format!("sync-plan-{}", short_hash(plan_material.as_bytes())),
        direction: direction.into(),
        items,
    })
}

fn plan_decision(
    local: Option<&crate::config::SyncObjectMapping>,
    remote: Option<&ObjectSummary>,
    has_conflict: bool,
) -> (&'static str, &'static str) {
    if has_conflict {
        return ("conflict", "recorded_conflict");
    }
    if remote.is_some_and(|summary| summary.schema_version != OBJECT_SYNC_SCHEMA_VERSION) {
        return ("conflict", "schema_version_unsupported");
    }
    match (local, remote) {
        (Some(_), None) => ("upload", "local_only"),
        (None, Some(_)) => ("download", "remote_only"),
        (Some(local), Some(remote))
            if local.server_revision == remote.server_revision
                && local.object_version == remote.object_version =>
        {
            ("no_op", "versions_match")
        }
        (Some(local), Some(remote))
            if remote.server_revision > local.server_revision
                && local.object_version > remote.object_version =>
        {
            ("conflict", "local_and_remote_advanced")
        }
        (Some(local), Some(remote)) if remote.server_revision > local.server_revision => {
            ("download", "remote_revision_advanced")
        }
        (Some(local), Some(remote)) if local.object_version > remote.object_version => {
            ("upload", "local_version_advanced")
        }
        (Some(_), Some(_)) => ("download", "remote_version_advanced"),
        (None, None) => ("no_op", "missing"),
    }
}

fn paginated_plan_result(
    invocation: CapabilityInvocation,
    plan: SyncPlan,
    differences_only: bool,
) -> Result<CapabilityInvocationResult, CapabilityError> {
    let (limit, offset) = plan_page(&invocation, &plan.id)?;
    if offset > plan.items.len() {
        return Err(capability_error(
            CapabilityErrorCategory::Validation,
            "validation.sync_plan_cursor_out_of_range",
            "Sync plan cursor offset is outside the current plan.",
            json!({ "total": plan.items.len() }),
            false,
        ));
    }
    let end = offset.saturating_add(limit).min(plan.items.len());
    let page_items = plan.items[offset..end]
        .iter()
        .map(plan_item_json)
        .collect::<Vec<_>>();
    let next_cursor = (end < plan.items.len()).then(|| format!("{}:{end}", plan.id));
    let mut counts = BTreeMap::<&str, usize>::new();
    for item in &plan.items {
        *counts.entry(item.action).or_default() += 1;
    }
    let field = if differences_only {
        "differences"
    } else {
        "items"
    };
    let output = json!({
        "plan_id": plan.id,
        "direction": plan.direction,
        "total": plan.items.len(),
        "offset": offset,
        "count": page_items.len(),
        "counts": counts,
        (field): page_items,
        "metadata_only": true,
        "redaction": "withheld"
    });
    let summary = json!({
        "plan_id": output["plan_id"],
        "total": output["total"],
        "count": output["count"],
        "counts": output["counts"],
        "metadata_only": true,
        "redaction": "withheld"
    });
    Ok(result_with_page(
        invocation.id,
        output,
        summary,
        Some(InvocationOutputPage { next_cursor }),
    ))
}

fn plan_page(
    invocation: &CapabilityInvocation,
    plan_id: &str,
) -> Result<(usize, usize), CapabilityError> {
    let limit = invocation
        .controls
        .page
        .as_ref()
        .map(|page| page.limit as usize)
        .unwrap_or(DEFAULT_PLAN_LIMIT)
        .clamp(1, MAX_PLAN_LIMIT);
    let Some(cursor) = invocation
        .controls
        .page
        .as_ref()
        .and_then(|page| page.cursor.as_deref())
    else {
        return Ok((limit, 0));
    };
    let (cursor_plan, offset) = cursor.rsplit_once(':').ok_or_else(|| {
        capability_error(
            CapabilityErrorCategory::Validation,
            "validation.sync_plan_cursor_invalid",
            "Sync plan cursor is invalid.",
            json!({}),
            false,
        )
    })?;
    let offset = offset.parse::<usize>().map_err(|_| {
        capability_error(
            CapabilityErrorCategory::Validation,
            "validation.sync_plan_cursor_invalid",
            "Sync plan cursor is invalid.",
            json!({}),
            false,
        )
    })?;
    if cursor_plan != plan_id {
        return Err(capability_error(
            CapabilityErrorCategory::Conflict,
            "conflict.sync_plan_changed",
            "Sync metadata changed after the previous plan page.",
            json!({ "expected_plan_id": plan_id }),
            true,
        ));
    }
    Ok((limit, offset))
}

fn plan_item_json(item: &PlanItem) -> Value {
    json!({
        "id": item.id,
        "object_kind": item.object_kind,
        "object_id": item.object_id,
        "action": item.action,
        "local_object_version": item.local_object_version,
        "local_server_revision": item.local_server_revision,
        "remote_object_version": item.remote_object_version,
        "remote_server_revision": item.remote_server_revision,
        "remote_schema_version": item.remote_schema_version,
        "compatible": item.compatible,
        "deleted": item.deleted,
        "reason": item.reason,
        "content": "withheld"
    })
}

async fn invoke_conflict_resolution(
    config: &SyncConfig,
    invocation: CapabilityInvocation,
) -> Result<CapabilityInvocationResult, CapabilityError> {
    let mode = required_string(&invocation.input, "mode")?;
    if !matches!(
        mode.as_str(),
        "keep_remote" | "keep_local_force" | "merge" | "delete_tombstone"
    ) {
        return Err(validation_error(
            "validation.sync_resolution_mode_invalid",
            "Sync conflict resolution mode is invalid.",
            json!({
                "allowed": ["keep_remote", "keep_local_force", "merge", "delete_tombstone"]
            }),
        ));
    }
    let object_kind = required_string(&invocation.input, "object_kind")?;
    let object_id = required_string(&invocation.input, "object_id")?;
    let replay_context = if invocation.controls.dry_run {
        None
    } else {
        require_mutation_acknowledgement(&invocation)?;
        let idempotency_key = validate_idempotency_key(&invocation.input)?;
        let fingerprint = mutation_fingerprint("conflict_resolve", &invocation.input);
        if let Some(result) = replay_result(config, &idempotency_key, &fingerprint)? {
            return Ok(result_with_page(
                invocation.id,
                result,
                json!({
                    "operation": "conflict_resolve",
                    "idempotent_replay": true,
                    "redaction": "withheld"
                }),
                None,
            ));
        }
        Some((idempotency_key, fingerprint))
    };
    let conflict = config
        .object_conflicts
        .values()
        .find(|conflict| conflict.object_kind == object_kind && conflict.object_id == object_id)
        .ok_or_else(|| {
            capability_error(
                CapabilityErrorCategory::Conflict,
                "conflict.sync_object_not_found",
                "The requested opaque Sync conflict is no longer present.",
                json!({ "object_kind": object_kind, "object_id": object_id }),
                false,
            )
        })?;
    let current_server_revision = conflict.current_server_revision;
    let plan_id = conflict_resolution_plan_id(
        &mode,
        &object_kind,
        &object_id,
        current_server_revision,
        conflict.current_object_version,
    );
    let confirmation =
        conflict_confirmation(&mode, &object_kind, &object_id, current_server_revision);
    let preview = json!({
        "plan_id": plan_id,
        "operation": "conflict_resolve",
        "mode": mode,
        "object_kind": object_kind,
        "object_id": object_id,
        "current_server_revision": current_server_revision,
        "current_object_version": conflict.current_object_version,
        "required_confirmation": confirmation,
        "content": "withheld",
        "redaction": "withheld"
    });
    if invocation.controls.dry_run {
        return Ok(guarded_preview_result(invocation.id, preview));
    }

    require_guarded_execution(&invocation, &plan_id, &confirmation)?;
    let (idempotency_key, fingerprint) =
        replay_context.expect("non-dry-run replay context initialized");

    let session = login_session_from_env(config, &invocation.input).await?;
    let input = ObjectConflictResolutionInput {
        object_kind: object_kind.clone(),
        object_id: object_id.clone(),
        current_server_revision: Some(current_server_revision),
        acknowledge_delete: mode == "delete_tombstone",
    };
    let resolved = match mode.as_str() {
        "keep_remote" => ops::resolve_keep_remote(session, config.clone(), input).await,
        "keep_local_force" => ops::resolve_keep_local_force(session, config.clone(), input).await,
        "merge" => ops::resolve_merge(session, config.clone(), input).await,
        "delete_tombstone" => ops::resolve_delete_tombstone(session, config.clone(), input).await,
        _ => unreachable!("mode validated"),
    }
    .map_err(|error| {
        redacted_sync_error(
            "sync.conflict_resolution_failed",
            "Sync conflict resolution failed.",
            &error,
            matches!(error, SyncError::Network(_) | SyncError::Server { .. }),
        )
    })?;
    let (ok, mut next_config) = resolved;
    let output = json!({
        "operation": "conflict_resolve",
        "mode": ok.mode,
        "object_kind": ok.object_kind,
        "object_id": ok.object_id,
        "previous_server_revision": ok.previous_server_revision,
        "server_revision": ok.server_revision,
        "object_version": ok.object_version,
        "unavailable": ok.unavailable,
        "idempotent_replay": false,
        "redaction": "withheld"
    });
    store_replay(
        &mut next_config,
        &idempotency_key,
        "conflict_resolve",
        &fingerprint,
        output.clone(),
    )?;
    Ok(result_with_page(
        invocation.id,
        output,
        json!({
            "operation": "conflict_resolve",
            "mode": mode,
            "object_kind": object_kind,
            "object_id": object_id,
            "idempotent_replay": false,
            "redaction": "withheld"
        }),
        None,
    ))
}

async fn invoke_recovery(
    config: &SyncConfig,
    invocation: CapabilityInvocation,
) -> Result<CapabilityInvocationResult, CapabilityError> {
    let operation = required_string(&invocation.input, "operation")?;
    if !matches!(
        operation.as_str(),
        "retry" | "reset" | "rebootstrap" | "recover_access"
    ) {
        return Err(validation_error(
            "validation.sync_recovery_operation_invalid",
            "Sync recovery operation is invalid.",
            json!({ "allowed": ["retry", "reset", "rebootstrap", "recover_access"] }),
        ));
    }
    let retry_operation = invocation
        .input
        .get("retry_operation")
        .and_then(Value::as_str)
        .map(str::to_string);
    if operation == "retry"
        && !retry_operation
            .as_deref()
            .is_some_and(|value| matches!(value, "push_objects" | "pull_objects"))
    {
        return Err(validation_error(
            "validation.sync_retry_operation_required",
            "Retry requires push_objects or pull_objects.",
            json!({ "allowed": ["push_objects", "pull_objects"] }),
        ));
    }
    let replay_context = if invocation.controls.dry_run {
        None
    } else {
        require_mutation_acknowledgement(&invocation)?;
        let idempotency_key = validate_idempotency_key(&invocation.input)?;
        let fingerprint = mutation_fingerprint("recovery", &invocation.input);
        if let Some(result) = replay_result(config, &idempotency_key, &fingerprint)? {
            return Ok(result_with_page(
                invocation.id,
                result,
                json!({
                    "operation": operation,
                    "idempotent_replay": true,
                    "redaction": "withheld"
                }),
                None,
            ));
        }
        Some((idempotency_key, fingerprint))
    };
    let plan_id = recovery_plan_id(config, &operation, retry_operation.as_deref());
    let confirmation = recovery_confirmation(
        &operation,
        retry_operation.as_deref(),
        config.object_mappings.len(),
        &plan_id,
    );
    let preview = json!({
        "plan_id": plan_id,
        "operation": operation,
        "retry_operation": retry_operation,
        "mapping_count": config.object_mappings.len(),
        "conflict_count": config.object_conflicts.len(),
        "required_confirmation": confirmation,
        "effects": recovery_effects(&operation),
        "content": "withheld",
        "redaction": "withheld"
    });
    if invocation.controls.dry_run {
        return Ok(guarded_preview_result(invocation.id, preview));
    }

    require_guarded_execution(&invocation, &plan_id, &confirmation)?;
    let (idempotency_key, fingerprint) =
        replay_context.expect("non-dry-run replay context initialized");

    let (mut next_config, mut output) =
        match operation.as_str() {
            "retry" => {
                let session = login_session_from_env(config, &invocation.input).await?;
                match retry_operation.as_deref() {
                    Some("push_objects") => {
                        let (ok, config) = ops::push_objects(session, config.clone())
                            .await
                            .map_err(|error| {
                                redacted_sync_error(
                                    "sync.retry_failed",
                                    "Sync object retry failed.",
                                    &error,
                                    true,
                                )
                            })?;
                        (
                            config,
                            json!({
                                "operation": "retry",
                                "retry_operation": "push_objects",
                                "objects": ok.objects,
                                "bytes": ok.bytes
                            }),
                        )
                    }
                    Some("pull_objects") => {
                        let (ok, config) = ops::pull_objects(session, config.clone())
                            .await
                            .map_err(|error| {
                                redacted_sync_error(
                                    "sync.retry_failed",
                                    "Sync object retry failed.",
                                    &error,
                                    true,
                                )
                            })?;
                        (
                            config,
                            json!({
                                "operation": "retry",
                                "retry_operation": "pull_objects",
                                "objects": ok.objects,
                                "imported_profiles": ok.imported_profiles,
                                "imported_credential_refs": ok.imported_credential_refs,
                                "imported_credential_records": ok.imported_credential_records,
                                "unavailable": ok.unavailable
                            }),
                        )
                    }
                    _ => unreachable!("retry operation validated"),
                }
            }
            "reset" => {
                let mut config = config.clone();
                config.last_revision = 0;
                config.last_revisions.clear();
                config.last_synced_at = None;
                config.object_conflicts.clear();
                config.periodic_sync.last_run_at = None;
                config.periodic_sync.last_status = Some("reset".into());
                let mapping_count = config.object_mappings.len();
                (
                    config,
                    json!({
                        "operation": "reset",
                        "mappings_retained": true,
                        "mapping_count": mapping_count
                    }),
                )
            }
            "rebootstrap" => {
                let mut config = config.clone();
                let removed_mappings = config.object_mappings.len();
                let removed_conflicts = config.object_conflicts.len();
                config.last_revision = 0;
                config.last_revisions.clear();
                config.last_synced_at = None;
                config.object_mappings.clear();
                config.object_conflicts.clear();
                config.periodic_sync.enabled = false;
                config.periodic_sync.last_run_at = None;
                config.periodic_sync.last_status = Some("rebootstrap_required".into());
                (
                    config,
                    json!({
                        "operation": "rebootstrap",
                        "removed_mappings": removed_mappings,
                        "removed_conflicts": removed_conflicts,
                        "periodic_disabled": true
                    }),
                )
            }
            "recover_access" => {
                let server_url = config.server_url.clone().ok_or_else(|| {
                    validation_error(
                        "validation.sync_server_missing",
                        "Sync account recovery requires a configured server.",
                        json!({}),
                    )
                })?;
                let email = config.email.clone().ok_or_else(|| {
                    validation_error(
                        "validation.sync_account_missing",
                        "Sync account recovery requires a configured account.",
                        json!({}),
                    )
                })?;
                let device_name = config
                    .device_name
                    .clone()
                    .unwrap_or_else(|| "voidb-agent-recovery".into());
                let recovery_code = secret_from_named_env(
                    &invocation.input,
                    "recovery_code_env",
                    DEFAULT_RECOVERY_CODE_ENV,
                )?;
                let new_password = secret_from_named_env(
                    &invocation.input,
                    "new_password_env",
                    DEFAULT_NEW_PASSWORD_ENV,
                )?;
                let recovered = ops::recover_password(RecoverInput {
                    server_url,
                    email,
                    recovery_code,
                    new_password,
                    device_name,
                })
                .await
                .map_err(|error| {
                    redacted_sync_error(
                        "sync.account_recovery_failed",
                        "Sync account recovery failed.",
                        &error,
                        false,
                    )
                })?;
                let mut config = recovered.config;
                let token_status = token_store::save_token(&mut config, &recovered.session.token)
                    .map_err(|error| {
                    redacted_sync_error(
                        "sync.recovery_token_store_failed",
                        "Recovered Sync token could not be stored.",
                        &error,
                        false,
                    )
                })?;
                (
                    config,
                    json!({
                        "operation": "recover_access",
                        "token_store": token_status.backend.as_str(),
                        "token_present": token_status.present
                    }),
                )
            }
            _ => unreachable!("operation validated"),
        };
    output["idempotent_replay"] = json!(false);
    output["redaction"] = json!("withheld");
    store_replay(
        &mut next_config,
        &idempotency_key,
        "recovery",
        &fingerprint,
        output.clone(),
    )?;
    Ok(result_with_page(
        invocation.id,
        output,
        json!({
            "operation": operation,
            "retry_operation": retry_operation,
            "idempotent_replay": false,
            "redaction": "withheld"
        }),
        None,
    ))
}

fn guarded_preview_result(invocation_id: String, preview: Value) -> CapabilityInvocationResult {
    result_with_page(
        invocation_id,
        json!({
            "dry_run": true,
            "would_execute": false,
            "preview": preview,
            "idempotent_replay": false,
            "redaction": "withheld"
        }),
        json!({
            "dry_run": true,
            "would_execute": false,
            "plan_id": preview["plan_id"],
            "operation": preview["operation"],
            "redaction": "withheld"
        }),
        None,
    )
}

fn require_guarded_execution(
    invocation: &CapabilityInvocation,
    expected_plan_id: &str,
    expected_confirmation: &str,
) -> Result<(), CapabilityError> {
    require_mutation_acknowledgement(invocation)?;
    let plan_id = required_string(&invocation.input, "plan_id")?;
    let confirmation = required_string(&invocation.input, "confirmation")?;
    if plan_id != expected_plan_id || confirmation != expected_confirmation {
        return Err(capability_error(
            CapabilityErrorCategory::Conflict,
            "conflict.sync_preview_changed",
            "Sync state or typed confirmation does not match the current preview.",
            json!({ "expected_plan_id": expected_plan_id }),
            true,
        ));
    }
    Ok(())
}

fn require_mutation_acknowledgement(
    invocation: &CapabilityInvocation,
) -> Result<(), CapabilityError> {
    if invocation.controls.acknowledgement.is_some() {
        return Ok(());
    }
    Err(capability_error(
        CapabilityErrorCategory::Policy,
        "policy.sync_acknowledgement_required",
        "Sync mutation requires explicit invocation acknowledgement.",
        json!({}),
        false,
    ))
}

async fn login_session_from_env(
    config: &SyncConfig,
    input: &Value,
) -> Result<crate::session::Session, CapabilityError> {
    let server_url = config.server_url.clone().ok_or_else(|| {
        validation_error(
            "validation.sync_server_missing",
            "Sync mutation requires a configured server.",
            json!({}),
        )
    })?;
    let email = config.email.clone().ok_or_else(|| {
        validation_error(
            "validation.sync_account_missing",
            "Sync mutation requires a configured account.",
            json!({}),
        )
    })?;
    let device_name = config
        .device_name
        .clone()
        .unwrap_or_else(|| "voidb-agent".into());
    let password = secret_from_named_env(input, "password_env", DEFAULT_PASSWORD_ENV)?;
    ops::login(LoginInput {
        server_url,
        email,
        password,
        device_name,
    })
    .await
    .map(|ok| ok.session)
    .map_err(|error| {
        redacted_sync_error(
            "sync.credential_handoff_failed",
            "Sync credential handoff failed.",
            &error,
            false,
        )
    })
}

fn secret_from_named_env(
    input: &Value,
    field: &str,
    default_name: &str,
) -> Result<String, CapabilityError> {
    let name = input
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or(default_name);
    validate_env_name(name)?;
    std::env::var(name).map_err(|_| {
        capability_error(
            CapabilityErrorCategory::Credential,
            "credential.sync_handoff_missing",
            "Required Sync credential handoff is unavailable.",
            json!({ "field": field, "handoff": "environment" }),
            false,
        )
    })
}

fn validate_env_name(name: &str) -> Result<(), CapabilityError> {
    let valid = !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_');
    if valid {
        Ok(())
    } else {
        Err(validation_error(
            "validation.sync_credential_env_invalid",
            "Credential handoff environment names must use uppercase ASCII letters, digits, and underscores.",
            json!({}),
        ))
    }
}

fn validate_idempotency_key(input: &Value) -> Result<String, CapabilityError> {
    let key = required_string(input, "idempotency_key")?;
    let valid = (8..=128).contains(&key.len())
        && key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'));
    if valid {
        Ok(key)
    } else {
        Err(validation_error(
            "validation.sync_idempotency_key_invalid",
            "Sync idempotency keys must be 8-128 public identifier characters.",
            json!({}),
        ))
    }
}

fn replay_result(
    config: &SyncConfig,
    idempotency_key: &str,
    fingerprint: &str,
) -> Result<Option<Value>, CapabilityError> {
    let Some(replay) = config.agent_replays.get(idempotency_key) else {
        return Ok(None);
    };
    if replay.fingerprint != fingerprint {
        return Err(capability_error(
            CapabilityErrorCategory::Conflict,
            "conflict.sync_idempotency_key_reused",
            "Sync idempotency key was already used for a different operation.",
            json!({ "idempotency_key": idempotency_key }),
            false,
        ));
    }
    let mut result = replay.result.clone();
    result["idempotent_replay"] = json!(true);
    Ok(Some(result))
}

fn store_replay(
    config: &mut SyncConfig,
    idempotency_key: &str,
    capability_id: &str,
    fingerprint: &str,
    result: Value,
) -> Result<(), CapabilityError> {
    if config.agent_replays.len() >= MAX_AGENT_REPLAYS {
        let oldest = config
            .agent_replays
            .iter()
            .min_by(|left, right| left.1.completed_at.cmp(&right.1.completed_at))
            .map(|(key, _)| key.clone());
        if let Some(oldest) = oldest {
            config.agent_replays.remove(&oldest);
        }
    }
    config.agent_replays.insert(
        idempotency_key.into(),
        SyncAgentReplay {
            capability_id: capability_id.into(),
            fingerprint: fingerprint.into(),
            completed_at: Utc::now().to_rfc3339(),
            result,
        },
    );
    config.save().map_err(|error| {
        redacted_sync_error(
            "sync.replay_ledger_write_failed",
            "Sync replay ledger could not be written.",
            &error,
            false,
        )
    })
}

fn mutation_fingerprint(capability_id: &str, input: &Value) -> String {
    let material = serde_json::to_vec(&json!({
        "capability_id": capability_id,
        "input": input
    }))
    .unwrap_or_default();
    format!("sha256:{}", hex::encode(Sha256::digest(material)))
}

fn conflict_resolution_plan_id(
    mode: &str,
    object_kind: &str,
    object_id: &str,
    server_revision: u64,
    object_version: u64,
) -> String {
    let material =
        format!("{mode}\n{object_kind}\n{object_id}\n{server_revision}\n{object_version}");
    format!("sync-resolve-{}", short_hash(material.as_bytes()))
}

fn conflict_confirmation(
    mode: &str,
    object_kind: &str,
    object_id: &str,
    server_revision: u64,
) -> String {
    format!("SYNC RESOLVE {mode} {object_kind} {object_id} REV {server_revision}")
}

fn recovery_plan_id(config: &SyncConfig, operation: &str, retry_operation: Option<&str>) -> String {
    let mut revisions = config.last_revisions.iter().collect::<Vec<_>>();
    revisions.sort_by_key(|(kind, _)| *kind);
    let material = format!(
        "{operation}\n{}\n{}\n{}\n{}\n{:?}",
        retry_operation.unwrap_or("-"),
        config.last_revision,
        config.object_mappings.len(),
        config.object_conflicts.len(),
        revisions
    );
    format!("sync-recovery-{}", short_hash(material.as_bytes()))
}

fn recovery_confirmation(
    operation: &str,
    retry_operation: Option<&str>,
    mapping_count: usize,
    plan_id: &str,
) -> String {
    match operation {
        "retry" => format!(
            "SYNC RETRY {} {plan_id}",
            retry_operation.unwrap_or("unknown")
        ),
        "reset" => format!("SYNC RESET BOOKKEEPING {plan_id}"),
        "rebootstrap" => format!("SYNC REBOOTSTRAP {mapping_count} OBJECTS {plan_id}"),
        "recover_access" => format!("SYNC RECOVER ACCESS {plan_id}"),
        _ => unreachable!("operation validated"),
    }
}

fn recovery_effects(operation: &str) -> Vec<&'static str> {
    match operation {
        "retry" => vec!["authenticated object sync", "remote side effects possible"],
        "reset" => vec![
            "clear revisions",
            "clear conflict markers",
            "retain mappings",
        ],
        "rebootstrap" => vec![
            "clear revisions",
            "clear mappings",
            "clear conflict markers",
            "disable periodic sync",
        ],
        "recover_access" => vec![
            "rotate account password",
            "rewrap data-encryption key",
            "replace local device token",
        ],
        _ => Vec::new(),
    }
}

fn short_hash(material: &[u8]) -> String {
    let digest = hex::encode(Sha256::digest(material));
    digest[..24].to_string()
}

fn required_string(input: &Value, field: &str) -> Result<String, CapabilityError> {
    input
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| {
            validation_error(
                "validation.sync_input_required",
                "Required Sync capability input is missing.",
                json!({ "field": field }),
            )
        })
}

fn local_status(config: &SyncConfig, token_status: &TokenStoreStatus) -> Value {
    let mut counts = BTreeMap::<String, usize>::new();
    let mut unavailable = 0usize;
    let mut never_uploaded = 0usize;
    for mapping in config.object_mappings.values() {
        *counts.entry(mapping.object_kind.clone()).or_default() += 1;
        unavailable += usize::from(mapping.unavailable);
        never_uploaded += usize::from(mapping.server_revision == 0);
    }
    let conflict_count = config.object_conflicts.len();
    let total = conflict_count + unavailable + never_uploaded;
    let token_failure = token_status
        .keyring_error
        .as_deref()
        .map(|_| "token_store_degraded");
    json!({
        "configuration": {
            "ready": configuration_ready(config),
            "server_configured": config.server_url.is_some(),
            "account_configured": config.email.is_some(),
            "device_configured": config.device_id.is_some(),
            "token": if token_status.present { "present" } else { "not_set" },
            "token_store": token_status.backend.as_str(),
            "token_store_mode": token_status.mode,
            "failure_code": token_failure
        },
        "last_sync": {
            "at": config.last_synced_at,
            "periodic_status": config.periodic_sync.last_status,
            "periodic_enabled": config.periodic_sync.enabled
        },
        "pending_work": {
            "total": total,
            "conflicts": conflict_count,
            "unavailable": unavailable,
            "never_uploaded": never_uploaded,
            "by_kind": counts
        },
        "compatibility": compatibility_metadata(false),
        "connectivity": "not_checked",
        "redaction": "withheld"
    })
}

fn configuration_ready(config: &SyncConfig) -> bool {
    config.server_url.is_some()
        && config.email.is_some()
        && config.device_id.is_some()
        && config.device_name.is_some()
}

fn compatibility_metadata(server_reachable: bool) -> Value {
    json!({
        "plugin_version": env!("CARGO_PKG_VERSION"),
        "agent_schema_version": AGENT_SCHEMA_VERSION,
        "object_payload_version": OBJECT_SYNC_PAYLOAD_VERSION,
        "server_protocol": if server_reachable { "health_endpoint_only" } else { "not_checked" },
        "server_version": "not_reported",
        "compatible": Value::Null
    })
}

fn redacted_failure_code(error: &SyncError) -> &'static str {
    match error {
        SyncError::Unauthorized | SyncError::NotLoggedIn => "authentication_required",
        SyncError::Conflict { .. } | SyncError::ObjectConflict { .. } => "conflict",
        SyncError::Server { .. } => "server_error",
        SyncError::Network(_) => "network_error",
        SyncError::Config(_) => "configuration_error",
        SyncError::Crypto(_) => "cryptography_error",
        SyncError::Bundle(_) => "bundle_error",
        SyncError::Other(_) => "internal_error",
    }
}

fn capability(
    id: &str,
    description: &str,
    input_schema: Value,
    output_schema: Value,
    permissions: Vec<&str>,
    default_timeout_ms: Option<u64>,
) -> CapabilityDefinition {
    CapabilityDefinition {
        plugin_id: PLUGIN_ID.into(),
        id: id.into(),
        description: description.into(),
        input_schema,
        output_schema,
        permissions: permissions.into_iter().map(str::to_string).collect(),
        authorization: CapabilityAuthorizationMetadata::declared().with_note(
            "This connection-independent Sync operation returns schema-shaped metadata and never exports tokens, keys, decrypted bundles, or live handles.",
        ),
        risk: CapabilityRiskLevel::ReadOnly,
        destructive: false,
        streaming: false,
        execution_mode: CapabilityExecutionMode::Stateless,
        session_handoff: None,
        connection_required: false,
        required_secret_classes: Vec::new(),
        supports_dry_run: false,
        default_timeout_ms,
    }
}

#[allow(clippy::too_many_arguments)]
fn guarded_capability(
    id: &str,
    description: &str,
    input_schema: Value,
    output_schema: Value,
    permissions: Vec<&str>,
    approval_schema: CapabilityApprovalSchema,
    risk: CapabilityRiskLevel,
    default_timeout_ms: Option<u64>,
) -> CapabilityDefinition {
    CapabilityDefinition {
        plugin_id: PLUGIN_ID.into(),
        id: id.into(),
        description: description.into(),
        input_schema,
        output_schema,
        permissions: permissions.into_iter().map(str::to_string).collect(),
        authorization: CapabilityAuthorizationMetadata::declared()
            .with_interactive_execute()
            .without_capability_wide()
            .with_approval_schema(approval_schema)
            .with_note(
                "Preview is read-only. Execution requires exact structured approval, typed confirmation, acknowledgement, an idempotency key, and protected environment credential handoff when cryptographic state is needed.",
            ),
        risk,
        destructive: true,
        streaming: false,
        execution_mode: CapabilityExecutionMode::Stateless,
        session_handoff: None,
        connection_required: false,
        required_secret_classes: Vec::new(),
        supports_dry_run: true,
        default_timeout_ms,
    }
}

fn empty_input_schema() -> Value {
    json!({
        "type": "object",
        "properties": {},
        "additionalProperties": false
    })
}

fn plan_input_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "direction": {
                "type": "string",
                "enum": ["upload", "download", "bidirectional"],
                "default": "bidirectional"
            },
            "object_kind": {
                "type": "string",
                "enum": [
                    "profile", "credential_ref", "profile_policy",
                    "plugin_compatibility", "credential_record", "app_preference"
                ]
            }
        },
        "additionalProperties": false
    })
}

fn plan_output_schema(field: &str) -> Value {
    json!({
        "type": "object",
        "required": [
            "plan_id", "direction", "total", "offset", "count", "counts",
            field, "metadata_only", "redaction"
        ],
        "properties": {
            "plan_id": { "type": "string" },
            "direction": { "type": "string" },
            "total": { "type": "integer", "minimum": 0 },
            "offset": { "type": "integer", "minimum": 0 },
            "count": { "type": "integer", "minimum": 0, "maximum": MAX_PLAN_LIMIT },
            "counts": { "type": "object" },
            (field): {
                "type": "array",
                "maxItems": MAX_PLAN_LIMIT,
                "items": {
                    "type": "object",
                    "required": [
                        "id", "object_kind", "object_id", "action", "deleted",
                        "reason", "content"
                    ],
                    "properties": {
                        "id": { "type": "string" },
                        "object_kind": { "type": "string" },
                        "object_id": { "type": "string" },
                        "action": {
                            "type": "string",
                            "enum": ["upload", "download", "no_op", "conflict"]
                        },
                        "local_object_version": { "type": ["integer", "null"] },
                        "local_server_revision": { "type": ["integer", "null"] },
                        "remote_object_version": { "type": ["integer", "null"] },
                        "remote_server_revision": { "type": ["integer", "null"] },
                        "remote_schema_version": { "type": ["integer", "null"] },
                        "compatible": { "type": "boolean" },
                        "deleted": { "type": "boolean" },
                        "reason": { "type": "string" },
                        "content": { "const": "withheld" }
                    },
                    "additionalProperties": false
                }
            },
            "metadata_only": { "const": true },
            "redaction": { "const": "withheld" }
        },
        "additionalProperties": false
    })
}

fn conflict_resolution_input_schema() -> Value {
    json!({
        "type": "object",
        "required": ["mode", "object_kind", "object_id"],
        "properties": {
            "mode": {
                "type": "string",
                "enum": ["keep_remote", "keep_local_force", "merge", "delete_tombstone"]
            },
            "object_kind": {
                "type": "string",
                "enum": [
                    "profile", "credential_ref", "profile_policy",
                    "plugin_compatibility", "credential_record", "app_preference"
                ]
            },
            "object_id": { "type": "string", "minLength": 1, "maxLength": 255 },
            "plan_id": { "type": "string", "minLength": 1, "maxLength": 128 },
            "confirmation": { "type": "string", "minLength": 1, "maxLength": 1024 },
            "idempotency_key": { "type": "string", "minLength": 8, "maxLength": 128 },
            "password_env": { "type": "string", "minLength": 1, "maxLength": 128 }
        },
        "additionalProperties": false
    })
}

fn recovery_input_schema() -> Value {
    json!({
        "type": "object",
        "required": ["operation"],
        "properties": {
            "operation": {
                "type": "string",
                "enum": ["retry", "reset", "rebootstrap", "recover_access"]
            },
            "retry_operation": {
                "type": "string",
                "enum": ["push_objects", "pull_objects"]
            },
            "plan_id": { "type": "string", "minLength": 1, "maxLength": 128 },
            "confirmation": { "type": "string", "minLength": 1, "maxLength": 1024 },
            "idempotency_key": { "type": "string", "minLength": 8, "maxLength": 128 },
            "password_env": { "type": "string", "minLength": 1, "maxLength": 128 },
            "recovery_code_env": { "type": "string", "minLength": 1, "maxLength": 128 },
            "new_password_env": { "type": "string", "minLength": 1, "maxLength": 128 }
        },
        "additionalProperties": false
    })
}

fn guarded_output_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "dry_run": { "type": "boolean" },
            "would_execute": { "type": "boolean" },
            "preview": { "type": "object" },
            "operation": { "type": "string" },
            "mode": { "type": "string" },
            "object_kind": { "type": "string" },
            "object_id": { "type": "string" },
            "idempotent_replay": { "type": "boolean" },
            "redaction": { "const": "withheld" }
        },
        "additionalProperties": true
    })
}

fn conflict_resolution_approval_schema() -> CapabilityApprovalSchema {
    CapabilityApprovalSchema::v1(vec![
        approval_field(
            "/mode",
            "Resolution mode",
            CapabilityApprovalValueType::String,
            true,
        ),
        approval_field(
            "/object_kind",
            "Object kind",
            CapabilityApprovalValueType::String,
            true,
        ),
        approval_field(
            "/object_id",
            "Opaque object ID",
            CapabilityApprovalValueType::ResourceId,
            true,
        ),
        approval_field(
            "/plan_id",
            "Preview plan ID",
            CapabilityApprovalValueType::ResourceId,
            true,
        ),
        approval_field(
            "/confirmation",
            "Typed confirmation",
            CapabilityApprovalValueType::String,
            true,
        ),
        approval_field(
            "/idempotency_key",
            "Idempotency key",
            CapabilityApprovalValueType::ResourceId,
            true,
        ),
    ])
}

fn recovery_approval_schema() -> CapabilityApprovalSchema {
    CapabilityApprovalSchema::v1(vec![
        approval_field(
            "/operation",
            "Recovery operation",
            CapabilityApprovalValueType::String,
            true,
        ),
        approval_field(
            "/retry_operation",
            "Retry operation",
            CapabilityApprovalValueType::String,
            false,
        ),
        approval_field(
            "/plan_id",
            "Preview plan ID",
            CapabilityApprovalValueType::ResourceId,
            true,
        ),
        approval_field(
            "/confirmation",
            "Typed confirmation",
            CapabilityApprovalValueType::String,
            true,
        ),
        approval_field(
            "/idempotency_key",
            "Idempotency key",
            CapabilityApprovalValueType::ResourceId,
            true,
        ),
    ])
}

fn approval_field(
    path: &str,
    label: &str,
    value_type: CapabilityApprovalValueType,
    required: bool,
) -> CapabilityApprovalField {
    let field = CapabilityApprovalField::new(path, label, value_type)
        .with_constraint(CapabilityConstraintKind::Exact)
        .with_risk_emphasis(CapabilityApprovalRiskEmphasis::Destructive);
    if required { field.required() } else { field }
}

fn status_output_schema() -> Value {
    json!({
        "type": "object",
        "required": ["configuration", "last_sync", "pending_work", "compatibility", "connectivity", "redaction"],
        "properties": {
            "configuration": { "type": "object" },
            "last_sync": { "type": "object" },
            "pending_work": { "type": "object" },
            "compatibility": { "type": "object" },
            "connectivity": { "const": "not_checked" },
            "redaction": { "const": "withheld" }
        },
        "additionalProperties": false
    })
}

fn diagnostics_output_schema() -> Value {
    json!({
        "type": "object",
        "required": ["configuration_ready", "connectivity", "network_checked", "compatibility", "redaction"],
        "properties": {
            "configuration_ready": { "type": "boolean" },
            "connectivity": {
                "type": "string",
                "enum": ["not_checked", "not_configured", "reachable", "unhealthy", "unreachable"]
            },
            "network_checked": { "type": "boolean" },
            "failure_code": { "type": ["string", "null"] },
            "compatibility": { "type": "object" },
            "redaction": { "const": "withheld" }
        },
        "additionalProperties": false
    })
}

fn result(
    invocation_id: String,
    output: Value,
    output_summary: Value,
) -> CapabilityInvocationResult {
    result_with_page(invocation_id, output, output_summary, None)
}

fn result_with_page(
    invocation_id: String,
    output: Value,
    output_summary: Value,
    page: Option<InvocationOutputPage>,
) -> CapabilityInvocationResult {
    CapabilityInvocationResult {
        invocation_id,
        status: InvocationStatus::Succeeded,
        output,
        output_summary,
        page,
    }
}

fn validation_error(code: &str, message: &str, details: Value) -> CapabilityError {
    capability_error(
        CapabilityErrorCategory::Validation,
        code,
        message,
        details,
        false,
    )
}

fn redacted_sync_error(
    code: &str,
    message: &str,
    error: &SyncError,
    retryable: bool,
) -> CapabilityError {
    let mut result = capability_error(
        CapabilityErrorCategory::Plugin,
        code,
        message,
        json!({ "failure_code": redacted_failure_code(error) }),
        retryable,
    );
    result.redaction = RedactionStatus::Withheld;
    result
}

fn capability_error(
    category: CapabilityErrorCategory,
    code: &str,
    message: &str,
    details: Value,
    retryable: bool,
) -> CapabilityError {
    CapabilityError {
        category,
        code: code.into(),
        message: message.into(),
        details,
        target: None,
        retryable,
        redaction: RedactionStatus::Withheld,
    }
}

#[cfg(test)]
mod tests {
    use axum::{Json, Router, http::StatusCode, routing::get};
    use chrono::Utc;
    use voidb_core::{CapabilityInvocation, InvocationConnectionTarget, InvocationControls};

    use super::*;
    use crate::config::{SyncObjectConflict, SyncObjectMapping};

    fn invocation(capability_id: &str, input: Value) -> CapabilityInvocation {
        CapabilityInvocation {
            id: format!("sync-{capability_id}"),
            plugin_id: PLUGIN_ID.into(),
            capability_id: capability_id.into(),
            connection: InvocationConnectionTarget::Stateless,
            input,
            controls: InvocationControls::default(),
            actor: None,
            requested_at: Utc::now(),
        }
    }

    #[test]
    fn catalog_exposes_only_connectionless_read_capabilities() {
        let capabilities = sync_capabilities();
        assert_eq!(
            capabilities
                .iter()
                .map(|capability| capability.id.as_str())
                .collect::<Vec<_>>(),
            vec![
                "status",
                "diagnostics",
                "plan",
                "diff",
                "conflict_resolve",
                "recovery"
            ]
        );
        assert!(capabilities.iter().all(|capability| {
            capability.authorization.declared
                && !capability.connection_required
                && capability.required_secret_classes.is_empty()
        }));
        assert!(capabilities[..4].iter().all(|capability| {
            capability.risk == CapabilityRiskLevel::ReadOnly && !capability.supports_dry_run
        }));
        assert!(capabilities[4..].iter().all(|capability| {
            capability.risk == CapabilityRiskLevel::Destructive
                && capability.destructive
                && capability.supports_dry_run
                && capability.authorization.approval_schema.is_some()
                && !capability.authorization.capability_wide_allowed
        }));
    }

    #[tokio::test]
    async fn status_is_bounded_and_never_exports_local_ids_or_ciphertext() {
        let mut config = SyncConfig {
            server_url: Some("https://sync.example.invalid".into()),
            email: Some("person@example.invalid".into()),
            device_id: Some("device-secret-shaped-id".into()),
            device_name: Some("laptop".into()),
            last_synced_at: Some("2026-07-25T00:00:00Z".into()),
            ..SyncConfig::default()
        };
        config.object_mappings.insert(
            "local-secret-id".into(),
            SyncObjectMapping {
                local_kind: "profile".into(),
                local_id: "prod-database".into(),
                object_kind: "profile".into(),
                object_id: "opaque-object-id".into(),
                object_version: 1,
                server_revision: 0,
                unavailable: false,
                updated_at: None,
                cached_ciphertext: Some("ciphertext-must-not-escape".into()),
                unavailable_reason: None,
            },
        );
        config.object_conflicts.insert(
            "profile:opaque-object-id".into(),
            SyncObjectConflict {
                object_kind: "profile".into(),
                object_id: "opaque-object-id".into(),
                local_kind: Some("profile".into()),
                local_id: Some("prod-database".into()),
                attempted_base_server_revision: 1,
                current_server_revision: 2,
                attempted_object_version: 1,
                current_object_version: 2,
                detected_at: "2026-07-25T00:00:00Z".into(),
                server_updated_at: None,
                redaction: "withheld".into(),
                unavailable_reason: Some("object_revision_conflict".into()),
            },
        );

        let result = invoke_sync_capability_with_config(&config, invocation("status", json!({})))
            .await
            .expect("status");
        let encoded = serde_json::to_string(&result).expect("serialize");
        assert_eq!(result.output["pending_work"]["total"], 2);
        assert_eq!(result.output["pending_work"]["by_kind"]["profile"], 1);
        assert!(!encoded.contains("person@example.invalid"));
        assert!(!encoded.contains("device-secret-shaped-id"));
        assert!(!encoded.contains("prod-database"));
        assert!(!encoded.contains("opaque-object-id"));
        assert!(!encoded.contains("ciphertext-must-not-escape"));
    }

    #[tokio::test]
    async fn diagnostics_can_be_forced_offline() {
        let config = SyncConfig {
            server_url: Some("https://sync.example.invalid".into()),
            email: Some("person@example.invalid".into()),
            device_id: Some("device".into()),
            device_name: Some("laptop".into()),
            ..SyncConfig::default()
        };
        let result = invoke_sync_capability_with_config(
            &config,
            invocation("diagnostics", json!({ "check_connectivity": false })),
        )
        .await
        .expect("diagnostics");
        assert_eq!(result.output["configuration_ready"], true);
        assert_eq!(result.output["connectivity"], "not_checked");
        assert_eq!(result.output["network_checked"], false);
        assert_eq!(result.output["redaction"], "withheld");
    }

    #[tokio::test]
    async fn diagnostics_reports_unavailable_without_exposing_endpoint_details() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("reserve port");
        let address = listener.local_addr().expect("address");
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => break,
                    accepted = listener.accept() => match accepted {
                        Ok((stream, _)) => drop(stream),
                        Err(_) => break,
                    }
                }
            }
        });
        let config = SyncConfig {
            server_url: Some(format!("http://{address}/private-sync-path")),
            email: Some("person@example.invalid".into()),
            device_id: Some("device".into()),
            device_name: Some("laptop".into()),
            ..SyncConfig::default()
        };
        let result = invoke_sync_capability_with_config(
            &config,
            invocation("diagnostics", json!({ "check_connectivity": true })),
        )
        .await
        .expect("unavailable diagnostics are a successful redacted report");
        let encoded = serde_json::to_string(&result).expect("serialize");
        let connectivity = result.output["connectivity"]
            .as_str()
            .expect("connectivity");
        let failure_code = result.output["failure_code"]
            .as_str()
            .expect("failure code");
        assert!(
            matches!(
                (connectivity, failure_code),
                ("unreachable", "network_error") | ("unhealthy", "health_check_failed")
            ),
            "unexpected unavailable endpoint result: {connectivity}/{failure_code}"
        );
        assert!(!encoded.contains("private-sync-path"));
        assert!(!encoded.contains("person@example.invalid"));
        let _ = shutdown_tx.send(());
        server.await.expect("offline fixture");
    }

    #[tokio::test]
    async fn expired_token_error_is_redacted() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let address = listener.local_addr().expect("address");
        let app = Router::new().route(
            "/v1/objects",
            get(|| async {
                (
                    StatusCode::UNAUTHORIZED,
                    Json(json!({
                        "code": "token_expired",
                        "message": "server-secret-detail"
                    })),
                )
            }),
        );
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve");
        });
        let error = SyncClient::new(format!("http://{address}"))
            .with_token("expired-secret-token".into())
            .list_objects(true)
            .await
            .expect_err("expired token");
        let error = redacted_sync_error(
            "sync.plan_remote_metadata_failed",
            "Remote Sync metadata could not be listed.",
            &error,
            false,
        );
        let encoded = serde_json::to_string(&error).expect("serialize");
        assert_eq!(error.details["failure_code"], "authentication_required");
        assert!(!encoded.contains("expired-secret-token"));
        assert!(!encoded.contains("server-secret-detail"));
        server.abort();
    }

    #[test]
    fn plan_is_stable_metadata_only_and_paginates() {
        let mut config = SyncConfig::default();
        config.object_mappings.insert(
            "local-profile".into(),
            SyncObjectMapping {
                local_kind: "profile".into(),
                local_id: "prod-secret-alias".into(),
                object_kind: "profile".into(),
                object_id: "sync_profile_opaque".into(),
                object_version: 3,
                server_revision: 2,
                unavailable: false,
                updated_at: None,
                cached_ciphertext: Some("local-ciphertext".into()),
                unavailable_reason: None,
            },
        );
        let remote = vec![
            ObjectSummary {
                object_id: "sync_profile_opaque".into(),
                object_kind: "profile".into(),
                schema_version: OBJECT_SYNC_SCHEMA_VERSION,
                object_version: 3,
                server_revision: 2,
                deleted: false,
                manifest: json!({ "secret_metadata": "must-not-escape" }),
            },
            ObjectSummary {
                object_id: "sync_pref_remote".into(),
                object_kind: "app_preference".into(),
                schema_version: OBJECT_SYNC_SCHEMA_VERSION,
                object_version: 1,
                server_revision: 1,
                deleted: false,
                manifest: json!({ "ciphertext": "must-not-escape" }),
            },
        ];
        let first = build_sync_plan(&config, &remote, "bidirectional", None).expect("plan");
        let second = build_sync_plan(&config, &remote, "bidirectional", None).expect("plan");
        assert_eq!(first.id, second.id);
        assert_eq!(first.items.len(), 2);
        assert_eq!(
            first
                .items
                .iter()
                .find(|item| item.object_id == "sync_profile_opaque")
                .map(|item| item.action),
            Some("no_op")
        );
        assert_eq!(
            first
                .items
                .iter()
                .find(|item| item.object_id == "sync_pref_remote")
                .map(|item| item.action),
            Some("download")
        );

        let mut invocation = invocation("plan", json!({}));
        invocation.controls.page = Some(voidb_core::Pagination {
            limit: 1,
            cursor: None,
        });
        let result = paginated_plan_result(invocation, first, false).expect("page");
        let encoded = serde_json::to_string(&result).expect("serialize");
        assert_eq!(result.output["count"], 1);
        assert!(result.page.unwrap().next_cursor.is_some());
        assert!(!encoded.contains("prod-secret-alias"));
        assert!(!encoded.contains("must-not-escape"));
        assert!(!encoded.contains("local-ciphertext"));
    }

    #[test]
    fn plan_quarantines_unsupported_remote_schema_versions() {
        let remote = vec![ObjectSummary {
            object_id: "sync_profile_future".into(),
            object_kind: "profile".into(),
            schema_version: OBJECT_SYNC_SCHEMA_VERSION + 1,
            object_version: 9,
            server_revision: 9,
            deleted: false,
            manifest: json!({ "profile_alias": "must-not-escape" }),
        }];
        let plan =
            build_sync_plan(&SyncConfig::default(), &remote, "bidirectional", None).expect("plan");
        assert_eq!(plan.items.len(), 1);
        assert_eq!(plan.items[0].action, "conflict");
        assert_eq!(plan.items[0].reason, "schema_version_unsupported");
        assert!(!plan.items[0].compatible);
        let encoded = serde_json::to_string(&plan_item_json(&plan.items[0])).expect("serialize");
        assert!(!encoded.contains("must-not-escape"));
    }

    #[tokio::test]
    async fn conflict_and_recovery_preview_do_not_mutate_or_read_credentials() {
        let mut config = SyncConfig::default();
        config.object_conflicts.insert(
            "profile:sync_profile_opaque".into(),
            SyncObjectConflict {
                object_kind: "profile".into(),
                object_id: "sync_profile_opaque".into(),
                local_kind: Some("profile".into()),
                local_id: Some("local-secret-id".into()),
                attempted_base_server_revision: 2,
                current_server_revision: 3,
                attempted_object_version: 1,
                current_object_version: 2,
                detected_at: "2026-07-25T00:00:00Z".into(),
                server_updated_at: None,
                redaction: "withheld".into(),
                unavailable_reason: Some("object_revision_conflict".into()),
            },
        );
        let mut resolve = invocation(
            "conflict_resolve",
            json!({
                "mode": "keep_remote",
                "object_kind": "profile",
                "object_id": "sync_profile_opaque"
            }),
        );
        resolve.controls.dry_run = true;
        let preview = invoke_sync_capability_with_config(&config, resolve)
            .await
            .expect("preview");
        assert_eq!(preview.output["dry_run"], true);
        assert_eq!(preview.output["would_execute"], false);
        assert_eq!(preview.output["preview"]["current_server_revision"], 3);
        assert_eq!(config.object_conflicts.len(), 1);

        let mut recovery = invocation(
            "recovery",
            json!({
                "operation": "rebootstrap"
            }),
        );
        recovery.controls.dry_run = true;
        let recovery_preview = invoke_sync_capability_with_config(&config, recovery)
            .await
            .expect("recovery preview");
        assert_eq!(recovery_preview.output["dry_run"], true);
        assert_eq!(
            recovery_preview.output["preview"]["operation"],
            "rebootstrap"
        );
        assert_eq!(config.object_conflicts.len(), 1);
    }

    #[test]
    fn replay_ledger_rejects_key_reuse_with_a_different_fingerprint() {
        let mut config = SyncConfig::default();
        config.agent_replays.insert(
            "agent-key-0001".into(),
            SyncAgentReplay {
                capability_id: "recovery".into(),
                fingerprint: "sha256:first".into(),
                completed_at: "2026-07-25T00:00:00Z".into(),
                result: json!({
                    "operation": "reset",
                    "idempotent_replay": false,
                    "redaction": "withheld"
                }),
            },
        );
        let replay = replay_result(&config, "agent-key-0001", "sha256:first").expect("replay");
        assert_eq!(replay.unwrap()["idempotent_replay"], true);
        let error = replay_result(&config, "agent-key-0001", "sha256:other")
            .expect_err("fingerprint mismatch");
        assert_eq!(error.code, "conflict.sync_idempotency_key_reused");
    }
}
