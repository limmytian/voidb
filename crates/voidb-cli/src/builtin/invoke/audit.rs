use serde_json::{Value, json};
use voidb_core::capability::{
    CapabilityError, CapabilityErrorCategory, CapabilityPolicyDecision, ConnectionProfileRef,
    CredentialRef,
};
use voidb_core::{
    AuditEvent, AuditEventStatus, AuditEventStore, AuditOperation, LocalAuditStore, VoidbError,
    audit_json_summary,
};

use super::execution::{InvokeRunData, InvokeRunOptions};

#[derive(Debug, Clone)]
pub(super) struct InvokeAuditContext {
    pub(super) capability_ref: String,
    pub(super) profile_ref: String,
    pub(super) input_summary: Value,
    pub(super) controls: Value,
}

impl InvokeAuditContext {
    pub(super) fn from_options(options: &InvokeRunOptions, max_output_bytes: u64) -> Self {
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
pub(super) struct InvokeRunError {
    pub(super) error: Box<CapabilityError>,
    pub(super) grant: Option<InvokeGrantAuditData>,
    pub(super) policy_decision: Option<CapabilityPolicyDecision>,
}

impl InvokeRunError {
    pub(super) fn with_policy(
        error: CapabilityError,
        policy_decision: CapabilityPolicyDecision,
    ) -> Self {
        Self {
            error: Box::new(error),
            grant: None,
            policy_decision: Some(policy_decision),
        }
    }

    pub(super) fn with_grant(
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

    pub(super) fn into_error(self) -> CapabilityError {
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
pub(super) struct InvokeGrantAuditData {
    pub(super) grant_id: String,
    pub(super) invocation_id: String,
    pub(super) profile: ConnectionProfileRef,
    pub(super) plugin_id: String,
    pub(super) capability_id: String,
    pub(super) credential_refs: Vec<CredentialRef>,
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

pub(super) fn append_credential_grant_success_audit(
    data: &InvokeRunData,
) -> Result<(), VoidbError> {
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

pub(super) fn append_credential_grant_failure_audit(
    error: &InvokeRunError,
) -> Result<(), VoidbError> {
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

pub(super) fn credential_grant_audit_event(
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

pub(super) fn append_invoke_success_audit(
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

pub(super) fn append_invoke_error_audit(
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

pub(super) fn invoke_error_audit_event(
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
