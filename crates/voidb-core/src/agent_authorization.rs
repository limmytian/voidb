//! Frontend-safe agent authorization contracts.
//!
//! These types are the shared boundary between the central authorization
//! service and human-facing clients. Plugins may contribute capability risk,
//! preset recommendations, and semantic session purposes, but they never own
//! grant persistence, broker health evaluation, or policy decisions.

use std::collections::BTreeMap;

use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::session::PluginSessionPurpose;
use crate::{
    CapabilityAuthorizationMetadata, CapabilityConstraintKind, CapabilityExecutionMode,
    CapabilityId, CapabilityJitSupport, CapabilityRiskLevel, CapabilitySessionHandoff,
    ConnectionProfileId, PluginId,
};

pub const DEFAULT_AGENT_GRANT_TTL_MINUTES: u64 = 15;
pub const MAX_AGENT_GRANT_TTL_MINUTES: u64 = 60;
/// Time-bounded grants are unlimited by default. Callers may still opt into a
/// finite use budget.
pub const DEFAULT_AGENT_GRANT_USES: Option<u32> = None;
pub const MAX_AGENT_GRANT_USES: u32 = 100;
pub const DEFAULT_AGENT_GRANT_EXPIRING_WINDOW_SECONDS: i64 = 120;
pub const DEFAULT_AUTHORIZATION_REQUEST_TTL_SECONDS: i64 = 300;
pub const MAX_AUTHORIZATION_REQUEST_TTL_SECONDS: i64 = 900;

pub type AgentAuthorizationRequestId = String;
pub type AgentGrantId = String;
pub type AgentGrantRevisionId = String;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentPrincipal {
    pub client_id: String,
    pub task_id: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<String>,
}

impl AgentPrincipal {
    pub fn validate(&self) -> Result<(), AgentAuthorizationError> {
        for (name, value) in [
            ("client_id", self.client_id.as_str()),
            ("task_id", self.task_id.as_str()),
        ] {
            if value.trim().is_empty() || value.len() > 255 {
                return Err(AgentAuthorizationError::InvalidPrincipal(format!(
                    "{name} must contain 1 to 255 characters"
                )));
            }
        }
        if self
            .instance_id
            .as_ref()
            .is_some_and(|value| value.trim().is_empty() || value.len() > 255)
        {
            return Err(AgentAuthorizationError::InvalidPrincipal(
                "instance_id must be absent or contain 1 to 255 characters".into(),
            ));
        }
        Ok(())
    }

    /// Stable opaque binding used in filenames, deduplication keys, and audit
    /// projections. The component values need not be logged.
    pub fn fingerprint(&self) -> Result<String, AgentAuthorizationError> {
        self.validate()?;
        Ok(prefixed_fingerprint(
            "agent-principal",
            &serde_json::to_value(self).expect("principal serialization cannot fail"),
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentAuthorizationRequestStatus {
    Pending,
    Approved,
    Denied,
    Expired,
    Cancelled,
    Superseded,
}

impl AgentAuthorizationRequestStatus {
    pub fn is_terminal(self) -> bool {
        !matches!(self, Self::Pending)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AgentAuthorizationScope {
    Capability {
        capability_id: CapabilityId,
    },
    Constrained {
        capability_id: CapabilityId,
        constraints: BTreeMap<String, Value>,
    },
    ExactInvocation {
        capability_id: CapabilityId,
        normalized_input: Value,
        invocation_fingerprint: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedAgentOperation {
    pub capability_id: CapabilityId,
    pub input: Value,
    pub fingerprint: String,
}

pub fn normalize_agent_operation(
    capability_id: impl Into<CapabilityId>,
    input: Value,
) -> Result<NormalizedAgentOperation, AgentAuthorizationError> {
    let capability_id = capability_id.into();
    if capability_id.trim().is_empty() {
        return Err(AgentAuthorizationError::InvalidRequest(
            "normalized operation requires a capability ID".into(),
        ));
    }
    let canonical_input = canonicalize_value(&input);
    let fingerprint = prefixed_fingerprint(
        "agent-invocation",
        &serde_json::json!({
            "capability_id": capability_id,
            "input": canonical_input,
        }),
    );
    Ok(NormalizedAgentOperation {
        capability_id,
        input: canonical_input,
        fingerprint,
    })
}

pub fn authorize_normalized_operation(
    metadata: &CapabilityAuthorizationMetadata,
    scope: &AgentAuthorizationScope,
    operation: &NormalizedAgentOperation,
) -> Result<(), AgentAuthorizationError> {
    if !matches!(metadata.jit_support(), CapabilityJitSupport::Supported) {
        return Err(AgentAuthorizationError::PolicyDenied(
            "capability does not declare compatible JIT authorization metadata".into(),
        ));
    }
    if scope.capability_id() != operation.capability_id {
        return Err(AgentAuthorizationError::BindingMismatch);
    }
    match scope {
        AgentAuthorizationScope::Capability { .. } => {
            if metadata.capability_wide_allowed {
                Ok(())
            } else {
                Err(AgentAuthorizationError::PolicyDenied(
                    "capability-wide JIT approval is disabled".into(),
                ))
            }
        }
        AgentAuthorizationScope::ExactInvocation {
            normalized_input,
            invocation_fingerprint,
            ..
        } => {
            if canonicalize_value(normalized_input) == operation.input
                && invocation_fingerprint == &operation.fingerprint
            {
                Ok(())
            } else {
                Err(AgentAuthorizationError::PolicyDenied(
                    "normalized invocation does not match the exact approval".into(),
                ))
            }
        }
        AgentAuthorizationScope::Constrained { constraints, .. } => {
            let schema = metadata.approval_schema.as_ref().ok_or_else(|| {
                AgentAuthorizationError::PolicyDenied(
                    "constrained approval requires a compatible plugin schema".into(),
                )
            })?;
            schema
                .validate()
                .map_err(AgentAuthorizationError::PolicyDenied)?;
            for (path, approved_value) in constraints {
                let field = schema
                    .fields
                    .iter()
                    .find(|field| field.path == *path)
                    .ok_or_else(|| {
                        AgentAuthorizationError::PolicyDenied(format!(
                            "constraint path '{path}' is not declared by the plugin"
                        ))
                    })?;
                let actual = operation.input.pointer(path).ok_or_else(|| {
                    AgentAuthorizationError::PolicyDenied(format!(
                        "normalized operation omits constrained field '{path}'"
                    ))
                })?;
                if !constraint_allows(field.constraint, approved_value, actual) {
                    return Err(AgentAuthorizationError::PolicyDenied(format!(
                        "normalized field '{path}' is outside the approved constraint"
                    )));
                }
            }
            for field in schema.fields.iter().filter(|field| field.required) {
                if !constraints.contains_key(&field.path) {
                    return Err(AgentAuthorizationError::PolicyDenied(format!(
                        "approval omits required constraint '{}'",
                        field.path
                    )));
                }
            }
            Ok(())
        }
    }
}

fn constraint_allows(kind: CapabilityConstraintKind, approved: &Value, actual: &Value) -> bool {
    match kind {
        CapabilityConstraintKind::Exact => approved == actual,
        CapabilityConstraintKind::Prefix => approved
            .as_str()
            .zip(actual.as_str())
            .is_some_and(|(prefix, actual)| actual.starts_with(prefix)),
        CapabilityConstraintKind::Subset => approved
            .as_array()
            .zip(actual.as_array())
            .is_some_and(|(approved, actual)| actual.iter().all(|value| approved.contains(value))),
        CapabilityConstraintKind::Maximum => approved
            .as_f64()
            .zip(actual.as_f64())
            .is_some_and(|(maximum, actual)| actual <= maximum),
    }
}

impl AgentAuthorizationScope {
    pub fn capability_id(&self) -> &str {
        match self {
            Self::Capability { capability_id }
            | Self::Constrained { capability_id, .. }
            | Self::ExactInvocation { capability_id, .. } => capability_id,
        }
    }

    pub fn canonical_fingerprint(&self) -> String {
        prefixed_fingerprint(
            "agent-scope",
            &serde_json::to_value(self).expect("scope serialization cannot fail"),
        )
    }

    /// Structural narrowing check. Constraint-specific prefix/subset/maximum
    /// semantics are evaluated against the plugin declaration during policy
    /// enforcement; this method prevents a decision from changing capability
    /// or widening the requested scope shape.
    pub fn can_narrow_to(&self, approved: &Self) -> bool {
        if self.capability_id() != approved.capability_id() {
            return false;
        }
        match (self, approved) {
            (Self::Capability { .. }, _) => true,
            (
                Self::Constrained { constraints, .. },
                Self::Constrained {
                    constraints: approved,
                    ..
                },
            ) => constraints.keys().all(|key| approved.contains_key(key)),
            (Self::Constrained { .. }, Self::ExactInvocation { .. }) => true,
            (
                Self::ExactInvocation {
                    invocation_fingerprint,
                    ..
                },
                Self::ExactInvocation {
                    invocation_fingerprint: approved,
                    ..
                },
            ) => invocation_fingerprint == approved,
            _ => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentAuthorizationRequest {
    pub id: AgentAuthorizationRequestId,
    pub broker_instance_id: String,
    pub principal: AgentPrincipal,
    pub profile_id: ConnectionProfileId,
    pub plugin_id: PluginId,
    pub scope: AgentAuthorizationScope,
    pub risk: CapabilityRiskLevel,
    #[serde(alias = "reason")]
    pub purpose: String,
    pub status: AgentAuthorizationRequestStatus,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub request_fingerprint: String,

    #[serde(default)]
    pub timed_out: bool,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_reason: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_at: Option<DateTime<Utc>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_grant_id: Option<AgentGrantId>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_revision: Option<u64>,
}

impl AgentAuthorizationRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        id: AgentAuthorizationRequestId,
        broker_instance_id: String,
        principal: AgentPrincipal,
        profile_id: ConnectionProfileId,
        plugin_id: PluginId,
        scope: AgentAuthorizationScope,
        risk: CapabilityRiskLevel,
        purpose: String,
        created_at: DateTime<Utc>,
        expires_at: DateTime<Utc>,
    ) -> Result<Self, AgentAuthorizationError> {
        principal.validate()?;
        if id.trim().is_empty() || broker_instance_id.trim().is_empty() {
            return Err(AgentAuthorizationError::InvalidRequest(
                "request and broker instance IDs are required".into(),
            ));
        }
        if profile_id.trim().is_empty()
            || plugin_id.trim().is_empty()
            || scope.capability_id().trim().is_empty()
        {
            return Err(AgentAuthorizationError::InvalidRequest(
                "profile, plugin, and capability bindings are required".into(),
            ));
        }
        if purpose.trim().is_empty() || purpose.len() > 1000 {
            return Err(AgentAuthorizationError::InvalidRequest(
                "purpose must contain 1 to 1000 characters".into(),
            ));
        }
        let ttl = expires_at - created_at;
        if ttl <= Duration::zero() || ttl > Duration::seconds(MAX_AUTHORIZATION_REQUEST_TTL_SECONDS)
        {
            return Err(AgentAuthorizationError::InvalidRequest(
                "request TTL is outside the supported bound".into(),
            ));
        }
        let request_fingerprint = request_fingerprint(
            &broker_instance_id,
            &principal,
            &profile_id,
            &plugin_id,
            &scope,
            &purpose,
        )?;
        Ok(Self {
            id,
            broker_instance_id,
            principal,
            profile_id,
            plugin_id,
            scope,
            risk,
            purpose,
            status: AgentAuthorizationRequestStatus::Pending,
            created_at,
            expires_at,
            request_fingerprint,
            timed_out: false,
            decision_reason: None,
            decided_at: None,
            approved_grant_id: None,
            approved_revision: None,
        })
    }

    pub fn expire_at(&mut self, now: DateTime<Utc>) -> bool {
        if self.status == AgentAuthorizationRequestStatus::Pending && self.expires_at <= now {
            self.deny_for_timeout(now);
            true
        } else {
            false
        }
    }

    fn deny_for_timeout(&mut self, now: DateTime<Utc>) {
        self.status = AgentAuthorizationRequestStatus::Denied;
        self.timed_out = true;
        self.decision_reason = Some("Authorization request timed out before approval.".to_string());
        self.decided_at = Some(now);
    }

    pub fn decide(
        &mut self,
        decision: &AgentAuthorizationDecision,
    ) -> Result<(), AgentAuthorizationError> {
        if self.status != AgentAuthorizationRequestStatus::Pending {
            return Err(AgentAuthorizationError::AlreadyDecided);
        }
        if decision.request_id != self.id {
            return Err(AgentAuthorizationError::BindingMismatch);
        }
        if decision.decided_at >= self.expires_at {
            self.deny_for_timeout(decision.decided_at);
            return Err(AgentAuthorizationError::Expired);
        }
        self.status = match &decision.outcome {
            AgentAuthorizationDecisionOutcome::Deny { reason } => {
                self.decision_reason = Some(reason.clone());
                AgentAuthorizationRequestStatus::Denied
            }
            AgentAuthorizationDecisionOutcome::Approve { scope, .. } => {
                if !self.scope.can_narrow_to(scope) {
                    return Err(AgentAuthorizationError::ScopeWidening);
                }
                AgentAuthorizationRequestStatus::Approved
            }
        };
        self.decided_at = Some(decision.decided_at);
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentAuthorizationDecision {
    pub request_id: AgentAuthorizationRequestId,
    pub decided_at: DateTime<Utc>,
    pub outcome: AgentAuthorizationDecisionOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AgentAuthorizationDecisionOutcome {
    Deny {
        reason: String,
    },
    Approve {
        scope: AgentAuthorizationScope,
        grant: AgentGrantAmendment,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AgentGrantAmendment {
    Once,
    Bounded {
        ttl_seconds: u64,
        #[serde(default)]
        uses: Option<u32>,
    },
    AddToGrant {
        grant_id: AgentGrantId,
        ttl_delta_seconds: u64,
        uses_delta: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentLogicalGrant {
    pub id: AgentGrantId,
    pub principal: AgentPrincipal,
    pub profile_id: ConnectionProfileId,
    pub plugin_id: PluginId,
    pub current_revision: u64,
    pub created_at: DateTime<Utc>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentGrantRevision {
    pub id: AgentGrantRevisionId,
    pub grant_id: AgentGrantId,
    pub revision: u64,
    pub source_request_id: AgentAuthorizationRequestId,
    pub principal_fingerprint: String,
    pub profile_id: ConnectionProfileId,
    pub plugin_id: PluginId,
    pub scope: AgentAuthorizationScope,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    #[serde(default)]
    pub total_uses: Option<u32>,

    #[serde(default)]
    pub remaining_uses: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrontendAuthorizationRequest {
    pub id: AgentAuthorizationRequestId,
    pub principal_fingerprint: String,
    pub profile_id: ConnectionProfileId,
    pub plugin_id: PluginId,
    pub scope: AgentAuthorizationScope,
    pub risk: CapabilityRiskLevel,
    #[serde(alias = "reason")]
    pub purpose: String,
    pub status: AgentAuthorizationRequestStatus,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,

    #[serde(default)]
    pub timed_out: bool,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_reason: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<AgentGrantId>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_revision: Option<u64>,
}

impl TryFrom<&AgentAuthorizationRequest> for FrontendAuthorizationRequest {
    type Error = AgentAuthorizationError;

    fn try_from(request: &AgentAuthorizationRequest) -> Result<Self, Self::Error> {
        Ok(Self {
            id: request.id.clone(),
            principal_fingerprint: request.principal.fingerprint()?,
            profile_id: request.profile_id.clone(),
            plugin_id: request.plugin_id.clone(),
            scope: request.scope.clone(),
            risk: request.risk,
            purpose: request.purpose.clone(),
            status: request.status,
            created_at: request.created_at,
            expires_at: request.expires_at,
            timed_out: request.timed_out,
            decision_reason: request.decision_reason.clone(),
            grant_id: request.approved_grant_id.clone(),
            grant_revision: request.approved_revision,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentAuthorizationAuditAction {
    Request,
    Review,
    Approve,
    Deny,
    Expire,
    Cancel,
    Amend,
    Consume,
    Revoke,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentAuthorizationAuditProjection {
    pub action: AgentAuthorizationAuditAction,
    pub request_id: AgentAuthorizationRequestId,
    pub principal_fingerprint: String,
    pub profile_id: ConnectionProfileId,
    pub plugin_id: PluginId,
    pub scope_fingerprint: String,
    pub occurred_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AgentAuthorizationError {
    #[error("invalid agent principal: {0}")]
    InvalidPrincipal(String),
    #[error("invalid authorization request: {0}")]
    InvalidRequest(String),
    #[error("authorization request has expired")]
    Expired,
    #[error("authorization request already has a terminal decision")]
    AlreadyDecided,
    #[error("authorization binding mismatch")]
    BindingMismatch,
    #[error("approved scope widens or changes the requested scope")]
    ScopeWidening,
    #[error("authorization policy denied the operation: {0}")]
    PolicyDenied(String),
}

fn request_fingerprint(
    broker_instance_id: &str,
    principal: &AgentPrincipal,
    profile_id: &str,
    plugin_id: &str,
    scope: &AgentAuthorizationScope,
    purpose: &str,
) -> Result<String, AgentAuthorizationError> {
    let value = serde_json::json!({
        "broker_instance_id": broker_instance_id,
        "principal": principal,
        "profile_id": profile_id,
        "plugin_id": plugin_id,
        "scope": scope,
        "purpose": purpose,
    });
    principal.validate()?;
    Ok(prefixed_fingerprint("agent-request", &value))
}

fn prefixed_fingerprint(prefix: &str, value: &Value) -> String {
    let canonical = canonical_json(value);
    let digest = Sha256::digest(canonical.as_bytes());
    format!("{prefix}:{}", hex::encode(digest))
}

fn canonical_json(value: &Value) -> String {
    match value {
        Value::Object(map) => {
            let sorted = map
                .iter()
                .map(|(key, value)| (key.clone(), canonical_json(value)))
                .collect::<BTreeMap<_, _>>();
            let body = sorted
                .into_iter()
                .map(|(key, value)| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(&key).expect("key serialization cannot fail"),
                        value
                    )
                })
                .collect::<Vec<_>>()
                .join(",");
            format!("{{{body}}}")
        }
        Value::Array(values) => format!(
            "[{}]",
            values
                .iter()
                .map(canonical_json)
                .collect::<Vec<_>>()
                .join(",")
        ),
        _ => serde_json::to_string(value).expect("JSON serialization cannot fail"),
    }
}

fn canonicalize_value(value: &Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, value)| (key.clone(), canonicalize_value(value)))
                .collect(),
        ),
        Value::Array(values) => Value::Array(values.iter().map(canonicalize_value).collect()),
        _ => value.clone(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentAuthorizationPresetKind {
    ReadOnly,
    InteractiveExecute,
    FullAccess,
    Custom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentAuthorizationSupportStatus {
    Supported,
    Deferred,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentAuthorizationSupportSummary {
    pub status: AgentAuthorizationSupportStatus,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentBrokerHealth {
    Online,
    Starting,
    Offline,
    StaleSocket,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentGrantStatus {
    Active,
    Expiring,
    Exhausted,
    Expired,
    Stale,
    BrokerOffline,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentAuthorizationCapability {
    pub id: CapabilityId,
    pub risk: CapabilityRiskLevel,

    #[serde(default)]
    pub streaming: bool,

    #[serde(default)]
    pub execution_mode: CapabilityExecutionMode,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_handoff: Option<CapabilitySessionHandoff>,

    #[serde(default)]
    pub session_purposes: Vec<PluginSessionPurpose>,
}

impl AgentAuthorizationCapability {
    pub fn requires_destructive_acknowledgement(&self) -> bool {
        self.risk.requires_acknowledgement()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentAuthorizationPresetDefinition {
    pub kind: AgentAuthorizationPresetKind,
    pub label: String,
    pub description: String,

    /// Transport boundary for this exact preset projection. Stateless is the
    /// compatibility default for catalogs created before mode-aware grants.
    #[serde(default)]
    pub execution_mode: CapabilityExecutionMode,

    #[serde(default)]
    pub recommended: bool,

    /// Exact qualified capability IDs selected by this preset. An empty list
    /// never means every capability.
    #[serde(default)]
    pub capabilities: Vec<CapabilityId>,

    #[serde(default)]
    pub session_purposes: Vec<PluginSessionPurpose>,

    #[serde(default)]
    pub requires_destructive_acknowledgement: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentAuthorizationPluginCatalog {
    pub plugin_id: PluginId,
    pub support: AgentAuthorizationSupportSummary,

    #[serde(default)]
    pub capabilities: Vec<AgentAuthorizationCapability>,

    #[serde(default)]
    pub presets: Vec<AgentAuthorizationPresetDefinition>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrontendAgentGrant {
    pub id: String,
    pub profile_id: ConnectionProfileId,
    pub profile_name: String,
    pub plugin_id: PluginId,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preset: Option<AgentAuthorizationPresetKind>,

    #[serde(default)]
    pub capabilities: Vec<CapabilityId>,

    /// Transport boundary enforced by the broker. Legacy grants deserialize
    /// as stateless so they cannot silently gain persistent-session access.
    #[serde(default)]
    pub execution_mode: CapabilityExecutionMode,

    #[serde(rename = "allow_destructive", alias = "destructive_acknowledged")]
    pub destructive_acknowledged: bool,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    /// `None` means the grant is bounded only by time.
    #[serde(default)]
    pub remaining_uses: Option<u32>,
    pub broker_health: AgentBrokerHealth,
    pub active_session_count: usize,
}

impl FrontendAgentGrant {
    pub fn status_at(&self, now: DateTime<Utc>) -> AgentGrantStatus {
        self.status_at_with_window(
            now,
            Duration::seconds(DEFAULT_AGENT_GRANT_EXPIRING_WINDOW_SECONDS),
        )
    }

    pub fn status_at_with_window(
        &self,
        now: DateTime<Utc>,
        expiring_window: Duration,
    ) -> AgentGrantStatus {
        if self.expires_at <= now {
            AgentGrantStatus::Expired
        } else if self.remaining_uses == Some(0) {
            AgentGrantStatus::Exhausted
        } else {
            match self.broker_health {
                AgentBrokerHealth::StaleSocket => AgentGrantStatus::Stale,
                AgentBrokerHealth::Offline => AgentGrantStatus::BrokerOffline,
                AgentBrokerHealth::Online | AgentBrokerHealth::Starting => {
                    if self.expires_at - now <= expiring_window {
                        AgentGrantStatus::Expiring
                    } else {
                        AgentGrantStatus::Active
                    }
                }
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentAuthorizationProfileSummary {
    pub profile_id: ConnectionProfileId,
    pub profile_name: String,
    pub plugin_id: PluginId,
    pub support: AgentAuthorizationSupportSummary,
    pub broker_health: AgentBrokerHealth,
    pub active_session_count: usize,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant_status: Option<AgentGrantStatus>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<FrontendAgentGrant>,

    pub refreshed_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use serde_json::json;

    use super::*;

    fn grant(now: DateTime<Utc>) -> FrontendAgentGrant {
        FrontendAgentGrant {
            id: "agent-grant:test".into(),
            profile_id: "profile:test".into(),
            profile_name: "prod-shell".into(),
            plugin_id: "ssh".into(),
            preset: Some(AgentAuthorizationPresetKind::InteractiveExecute),
            capabilities: vec!["ssh.exec".into()],
            execution_mode: CapabilityExecutionMode::Stateless,
            destructive_acknowledged: true,
            issued_at: now,
            expires_at: now + Duration::minutes(15),
            remaining_uses: Some(10),
            broker_health: AgentBrokerHealth::Online,
            active_session_count: 1,
        }
    }

    #[test]
    fn grant_status_distinguishes_time_uses_and_broker_health() {
        let now = Utc.with_ymd_and_hms(2026, 7, 12, 9, 0, 0).unwrap();
        assert_eq!(grant(now).status_at(now), AgentGrantStatus::Active);

        let mut expiring = grant(now);
        expiring.expires_at = now + Duration::seconds(90);
        assert_eq!(expiring.status_at(now), AgentGrantStatus::Expiring);

        let mut exhausted = grant(now);
        exhausted.remaining_uses = Some(0);
        assert_eq!(exhausted.status_at(now), AgentGrantStatus::Exhausted);

        let mut time_only = grant(now);
        time_only.remaining_uses = None;
        assert_eq!(time_only.status_at(now), AgentGrantStatus::Active);

        let mut expired = grant(now);
        expired.expires_at = now;
        assert_eq!(expired.status_at(now), AgentGrantStatus::Expired);

        let mut stale = grant(now);
        stale.broker_health = AgentBrokerHealth::StaleSocket;
        assert_eq!(stale.status_at(now), AgentGrantStatus::Stale);

        let mut offline = grant(now);
        offline.broker_health = AgentBrokerHealth::Offline;
        assert_eq!(offline.status_at(now), AgentGrantStatus::BrokerOffline);
    }

    #[test]
    fn public_projection_contains_no_broker_or_credential_secrets() {
        let now = Utc.with_ymd_and_hms(2026, 7, 12, 9, 0, 0).unwrap();
        let encoded = serde_json::to_value(grant(now)).unwrap();
        for forbidden in [
            "token",
            "socket_path",
            "master_password",
            "credential",
            "decrypted_config",
        ] {
            assert_eq!(encoded.get(forbidden), None, "unexpected {forbidden}");
        }
        assert_eq!(encoded["preset"], json!("interactive_execute"));
        assert_eq!(encoded["broker_health"], json!("online"));
        assert_eq!(encoded["execution_mode"], json!("stateless"));
    }

    #[test]
    fn full_access_preset_has_a_stable_serialized_name() {
        assert_eq!(
            serde_json::to_value(AgentAuthorizationPresetKind::FullAccess).unwrap(),
            json!("full_access")
        );
    }

    #[test]
    fn empty_preset_scope_never_implies_all_capabilities() {
        let preset = AgentAuthorizationPresetDefinition {
            kind: AgentAuthorizationPresetKind::Custom,
            label: "Custom".into(),
            description: "Explicit capability selection".into(),
            execution_mode: CapabilityExecutionMode::Stateless,
            recommended: false,
            capabilities: Vec::new(),
            session_purposes: Vec::new(),
            requires_destructive_acknowledgement: false,
        };
        assert!(preset.capabilities.is_empty());
    }

    #[test]
    fn legacy_authorization_projections_default_to_stateless() {
        let now = Utc.with_ymd_and_hms(2026, 7, 12, 9, 0, 0).unwrap();
        let mut legacy_grant = serde_json::to_value(grant(now)).unwrap();
        legacy_grant
            .as_object_mut()
            .unwrap()
            .remove("execution_mode");
        let decoded: FrontendAgentGrant = serde_json::from_value(legacy_grant).unwrap();
        assert_eq!(decoded.execution_mode, CapabilityExecutionMode::Stateless);

        let legacy_preset = json!({
            "kind": "read_only",
            "label": "Read-only",
            "description": "Legacy preset",
            "recommended": true,
            "capabilities": ["ssh.sftp_list"],
            "session_purposes": [],
            "requires_destructive_acknowledgement": false
        });
        let decoded: AgentAuthorizationPresetDefinition =
            serde_json::from_value(legacy_preset).unwrap();
        assert_eq!(decoded.execution_mode, CapabilityExecutionMode::Stateless);

        let legacy_capability = json!({
            "id": "ssh.sftp_list",
            "risk": "read_only",
            "streaming": false,
            "session_purposes": []
        });
        let decoded: AgentAuthorizationCapability =
            serde_json::from_value(legacy_capability).unwrap();
        assert_eq!(decoded.execution_mode, CapabilityExecutionMode::Stateless);
        assert!(decoded.session_handoff.is_none());
    }

    fn principal() -> AgentPrincipal {
        AgentPrincipal {
            client_id: "agent-desktop".into(),
            task_id: "task-87".into(),
            instance_id: Some("instance-a".into()),
        }
    }

    fn request(now: DateTime<Utc>, scope: AgentAuthorizationScope) -> AgentAuthorizationRequest {
        AgentAuthorizationRequest::new(
            "auth-request:01JZ8V1E0YH6S5J4M3K2N1P0RA".into(),
            "broker-instance:01JZ8V1E0YH6S5J4M3K2N1P0RA".into(),
            principal(),
            "profile:ssh-prod".into(),
            "ssh".into(),
            scope,
            CapabilityRiskLevel::Destructive,
            "Run a deployment diagnostic".into(),
            now,
            now + Duration::seconds(DEFAULT_AUTHORIZATION_REQUEST_TTL_SECONDS),
        )
        .unwrap()
    }

    #[test]
    fn request_fingerprint_is_canonical_and_bound_to_principal() {
        let now = Utc.with_ymd_and_hms(2026, 7, 12, 9, 0, 0).unwrap();
        let first = request(
            now,
            AgentAuthorizationScope::Constrained {
                capability_id: "ssh.exec".into(),
                constraints: BTreeMap::from([
                    ("/cwd".into(), json!("/srv/app")),
                    ("/shell".into(), json!(false)),
                ]),
            },
        );
        let second = request(
            now,
            AgentAuthorizationScope::Constrained {
                capability_id: "ssh.exec".into(),
                constraints: BTreeMap::from([
                    ("/shell".into(), json!(false)),
                    ("/cwd".into(), json!("/srv/app")),
                ]),
            },
        );
        assert_eq!(first.request_fingerprint, second.request_fingerprint);

        let mut other = second;
        other.principal.task_id = "another-task".into();
        other.request_fingerprint = request_fingerprint(
            &other.broker_instance_id,
            &other.principal,
            &other.profile_id,
            &other.plugin_id,
            &other.scope,
            &other.purpose,
        )
        .unwrap();
        assert_ne!(first.request_fingerprint, other.request_fingerprint);

        let mut other_purpose = first.clone();
        other_purpose.purpose = "Collect uptime for incident INC-42".into();
        other_purpose.request_fingerprint = request_fingerprint(
            &other_purpose.broker_instance_id,
            &other_purpose.principal,
            &other_purpose.profile_id,
            &other_purpose.plugin_id,
            &other_purpose.scope,
            &other_purpose.purpose,
        )
        .unwrap();
        assert_ne!(first.request_fingerprint, other_purpose.request_fingerprint);
    }

    #[test]
    fn request_timeout_is_an_automatic_denial_with_a_safe_reason() {
        let now = Utc.with_ymd_and_hms(2026, 7, 12, 9, 0, 0).unwrap();
        let mut request = request(
            now,
            AgentAuthorizationScope::Capability {
                capability_id: "ssh.exec".into(),
            },
        );

        assert!(request.expire_at(request.expires_at));
        assert_eq!(request.status, AgentAuthorizationRequestStatus::Denied);
        assert!(request.timed_out);
        assert_eq!(
            request.decision_reason.as_deref(),
            Some("Authorization request timed out before approval.")
        );

        let projection = FrontendAuthorizationRequest::try_from(&request).unwrap();
        assert!(projection.timed_out);
        assert_eq!(projection.status, AgentAuthorizationRequestStatus::Denied);
    }

    #[test]
    fn decision_is_single_use_and_cannot_widen_scope() {
        let now = Utc.with_ymd_and_hms(2026, 7, 12, 9, 0, 0).unwrap();
        let mut request = request(
            now,
            AgentAuthorizationScope::ExactInvocation {
                capability_id: "ssh.exec".into(),
                normalized_input: json!({"argv": ["uptime"]}),
                invocation_fingerprint: "invocation:abc".into(),
            },
        );
        let widened = AgentAuthorizationDecision {
            request_id: request.id.clone(),
            decided_at: now + Duration::seconds(1),
            outcome: AgentAuthorizationDecisionOutcome::Approve {
                scope: AgentAuthorizationScope::Capability {
                    capability_id: "ssh.exec".into(),
                },
                grant: AgentGrantAmendment::Once,
            },
        };
        assert_eq!(
            request.decide(&widened),
            Err(AgentAuthorizationError::ScopeWidening)
        );
        assert_eq!(request.status, AgentAuthorizationRequestStatus::Pending);

        let approved = AgentAuthorizationDecision {
            request_id: request.id.clone(),
            decided_at: now + Duration::seconds(2),
            outcome: AgentAuthorizationDecisionOutcome::Approve {
                scope: request.scope.clone(),
                grant: AgentGrantAmendment::Once,
            },
        };
        request.decide(&approved).unwrap();
        assert_eq!(request.status, AgentAuthorizationRequestStatus::Approved);
        assert_eq!(
            request.decide(&approved),
            Err(AgentAuthorizationError::AlreadyDecided)
        );
    }

    #[test]
    fn frontend_request_redacts_raw_principal_and_broker_binding() {
        let now = Utc.with_ymd_and_hms(2026, 7, 12, 9, 0, 0).unwrap();
        let request = request(
            now,
            AgentAuthorizationScope::Capability {
                capability_id: "ssh.exec".into(),
            },
        );
        let projection = FrontendAuthorizationRequest::try_from(&request).unwrap();
        let encoded = serde_json::to_value(&projection).unwrap();
        assert_eq!(
            encoded["purpose"],
            Value::String("Run a deployment diagnostic".into())
        );
        assert_eq!(encoded.get("reason"), None);
        for forbidden in [
            "principal",
            "broker_instance_id",
            "master_password",
            "credential",
            "token",
        ] {
            assert_eq!(encoded.get(forbidden), None, "unexpected {forbidden}");
        }
        assert!(
            encoded["principal_fingerprint"]
                .as_str()
                .unwrap()
                .starts_with("agent-principal:")
        );

        let mut legacy = serde_json::to_value(&request).unwrap();
        let object = legacy.as_object_mut().unwrap();
        let purpose = object.remove("purpose").unwrap();
        object.insert("reason".into(), purpose);
        let decoded: AgentAuthorizationRequest = serde_json::from_value(legacy).unwrap();
        assert_eq!(decoded.purpose, request.purpose);
    }

    #[test]
    fn normalized_operation_enforces_exact_and_structured_approvals() {
        use crate::{
            CapabilityApprovalField, CapabilityApprovalRiskEmphasis, CapabilityApprovalSchema,
            CapabilityApprovalValueType, CapabilityConstraintKind,
        };

        let operation = normalize_agent_operation(
            "ssh.exec",
            json!({"cwd": "/srv/app/releases/42", "argv": ["uptime"]}),
        )
        .unwrap();
        let metadata = CapabilityAuthorizationMetadata::declared().with_approval_schema(
            CapabilityApprovalSchema::v1(vec![CapabilityApprovalField {
                path: "/cwd".into(),
                label: "Working directory".into(),
                description: None,
                value_type: CapabilityApprovalValueType::Path,
                required: true,
                constraint: CapabilityConstraintKind::Prefix,
                risk_emphasis: CapabilityApprovalRiskEmphasis::Normal,
            }]),
        );
        let constrained = AgentAuthorizationScope::Constrained {
            capability_id: "ssh.exec".into(),
            constraints: BTreeMap::from([("/cwd".into(), json!("/srv/app"))]),
        };
        authorize_normalized_operation(&metadata, &constrained, &operation).unwrap();

        let substituted =
            normalize_agent_operation("ssh.exec", json!({"cwd": "/etc", "argv": ["uptime"]}))
                .unwrap();
        assert!(authorize_normalized_operation(&metadata, &constrained, &substituted).is_err());

        let exact = AgentAuthorizationScope::ExactInvocation {
            capability_id: operation.capability_id.clone(),
            normalized_input: operation.input.clone(),
            invocation_fingerprint: operation.fingerprint.clone(),
        };
        authorize_normalized_operation(&metadata, &exact, &operation).unwrap();
        let replay_substitution = normalize_agent_operation(
            "ssh.exec",
            json!({"cwd": "/srv/app/releases/42", "argv": ["whoami"]}),
        )
        .unwrap();
        assert!(authorize_normalized_operation(&metadata, &exact, &replay_substitution).is_err());
    }
}
