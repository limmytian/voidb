#![cfg_attr(not(unix), allow(unused_imports))]

use chrono::{DateTime, Utc};
use serde_json::json;
use voidb_core::{
    AgentSessionRef, AuditEvent, AuditEventStatus, AuditOperation, ConnectionProfileRef,
    PluginSessionPurpose, RedactionStatus,
};
#[cfg(not(test))]
use voidb_core::{AuditEventStore, LocalAuditStore};

use super::ledger::AgentGrantFile;
use super::wire::BrokerResponse;

#[derive(Default)]
pub(super) struct AgentSessionAuditContext<'a> {
    pub(super) session: Option<&'a AgentSessionRef>,
    pub(super) call_id: Option<&'a str>,
    pub(super) capability: Option<&'a str>,
    pub(super) purpose: Option<&'a PluginSessionPurpose>,
}

pub(super) fn build_agent_session_audit_event(
    grant: &AgentGrantFile,
    operation: AuditOperation,
    response: &BrokerResponse,
    context: AgentSessionAuditContext<'_>,
    started_at: DateTime<Utc>,
) -> AuditEvent {
    let status = if response.ok {
        AuditEventStatus::Succeeded
    } else {
        match response.error_code.as_deref() {
            Some("session.timeout")
            | Some("session.expired")
            | Some("session.control_timeout")
            | Some("session.close_timeout") => AuditEventStatus::TimedOut,
            Some("session.cancelled") => AuditEventStatus::Cancelled,
            _ => AuditEventStatus::Failed,
        }
    };
    let mut event = AuditEvent::new(operation, status);
    event.grant_id = Some(grant.id.clone());
    event.profile = Some(ConnectionProfileRef::Id(grant.profile_id.clone()));
    event.plugin_id = Some(grant.plugin_id.clone());
    event.capability_id = context.capability.map(str::to_owned);
    event.duration_ms = Some(
        Utc::now()
            .signed_duration_since(started_at)
            .num_milliseconds()
            .max(0) as u64,
    );
    event.metadata = json!({
        "session_id": context.session.map(|reference| reference.session_id.as_str()),
        "generation": context.session.map(|reference| reference.generation),
        "call_id": context.call_id,
        "protocol_version": response.protocol_version,
        "purpose": context.purpose,
        "remaining_uses": response.remaining_uses,
        "grant_expires_at": response.expires_at,
        "error_code": response.error_code,
    });
    event.redaction = RedactionStatus::Applied;
    event
}

#[cfg(not(test))]
pub(super) fn append_agent_session_audit(
    grant: &AgentGrantFile,
    operation: AuditOperation,
    response: &BrokerResponse,
    context: AgentSessionAuditContext<'_>,
    started_at: DateTime<Utc>,
) {
    let event = build_agent_session_audit_event(grant, operation, response, context, started_at);
    if let Ok(store) = LocalAuditStore::default_store() {
        let _ = store.append(&event);
    }
}

#[cfg(test)]
pub(super) fn append_agent_session_audit(
    grant: &AgentGrantFile,
    operation: AuditOperation,
    response: &BrokerResponse,
    context: AgentSessionAuditContext<'_>,
    started_at: DateTime<Utc>,
) {
    let _ = build_agent_session_audit_event(grant, operation, response, context, started_at);
}

#[cfg(not(test))]
pub(super) fn append_agent_audit(
    grant: &AgentGrantFile,
    operation: AuditOperation,
    metadata: serde_json::Value,
) {
    let mut event = AuditEvent::new(operation, AuditEventStatus::Succeeded);
    event.grant_id = Some(grant.id.clone());
    event.profile = Some(ConnectionProfileRef::Id(grant.profile_id.clone()));
    event.plugin_id = Some(grant.plugin_id.clone());
    event.metadata = metadata;
    event.redaction = RedactionStatus::NotRequired;
    if let Ok(store) = LocalAuditStore::default_store() {
        let _ = store.append(&event);
    }
}

#[cfg(test)]
pub(super) fn append_agent_audit(
    _grant: &AgentGrantFile,
    _operation: AuditOperation,
    _metadata: serde_json::Value,
) {
}
