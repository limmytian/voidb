//! Capability-first domain model.
//!
//! These types define the stable boundary between saved connection profiles,
//! runtime connection instances, and individual capability invocations. They do
//! not replace the current `ConnectionConfig` persistence format yet; they are
//! the public model new CLI and process-plugin work should converge on.

use std::collections::BTreeMap;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::live_session::AgentLiveSessionContract;
use crate::session::PluginSessionPurpose;

pub type ActorId = String;
pub type ApprovalId = String;
pub type CapabilityId = String;
pub type CancellationToken = String;
pub type ConnectionInstanceId = String;
pub type ConnectionProfileId = String;
pub type ConnectionProfileName = String;
pub type CredentialGrantId = String;
pub type CredentialRefId = String;
pub type ErrorCode = String;
pub type InvocationId = String;
pub type PermissionId = String;
pub type PluginId = String;
pub type PolicyReasonCode = String;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ConnectionProfileRef {
    Id(ConnectionProfileId),
    #[serde(alias = "alias")]
    Name(ConnectionProfileName),
}

impl ConnectionProfileRef {
    pub fn id(id: impl Into<ConnectionProfileId>) -> Self {
        Self::Id(id.into())
    }

    pub fn name(name: impl Into<ConnectionProfileName>) -> Self {
        Self::Name(name.into())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConnectionProfile {
    pub id: ConnectionProfileId,
    #[serde(alias = "alias")]
    pub name: ConnectionProfileName,
    pub plugin_id: PluginId,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,

    /// Non-secret, plugin-defined profile metadata.
    #[serde(default)]
    pub metadata: Value,

    /// Plugin-defined defaults for invocations created from this profile.
    #[serde(default)]
    pub default_options: Value,

    /// References to brokered credentials. Plaintext secrets do not belong in
    /// this structure or in agent-facing CLI output.
    #[serde(default)]
    pub credential_refs: Vec<CredentialRef>,

    #[serde(default)]
    pub policy: ConnectionProfilePolicy,
}

impl ConnectionProfile {
    pub fn profile_ref(&self) -> ConnectionProfileRef {
        ConnectionProfileRef::Id(self.id.clone())
    }

    pub fn name_ref(&self) -> ConnectionProfileRef {
        ConnectionProfileRef::Name(self.name.clone())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialRef {
    pub id: CredentialRefId,
    pub class: CredentialClass,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CredentialGrant {
    pub id: CredentialGrantId,
    pub profile: ConnectionProfileRef,
    pub plugin_id: PluginId,
    pub scope: CredentialGrantScope,
    pub issued_at: DateTime<Utc>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,

    #[serde(default)]
    pub credential_refs: Vec<CredentialRef>,

    #[serde(default)]
    pub redaction: RedactionStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CredentialGrantScope {
    Invocation { invocation_id: InvocationId },
    RuntimeInstance { instance_id: ConnectionInstanceId },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum CredentialClass {
    Password,
    Token,
    ApiKey,
    PrivateKey,
    ClientCertificate,
    CloudAccessKey,
    CloudSecretKey,
    Other(String),
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityRiskLevel {
    #[default]
    ReadOnly,
    Mutating,
    Destructive,
    ExternalSideEffect,
}

/// Declares where a capability can be executed.
///
/// `Stateless` remains the compatibility default for descriptors created
/// before execution-mode metadata was introduced.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityExecutionMode {
    #[default]
    Stateless,
    SessionOnly,
    Both,
}

impl CapabilityExecutionMode {
    pub fn supports_stateless(self) -> bool {
        matches!(self, Self::Stateless | Self::Both)
    }

    pub fn supports_session(self) -> bool {
        matches!(self, Self::SessionOnly | Self::Both)
    }
}

/// Structured guidance for opening a persistent session that can execute a
/// capability. Capability IDs are fully qualified so clients do not need to
/// infer a plugin namespace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilitySessionHandoff {
    pub purpose: PluginSessionPurpose,

    #[serde(default)]
    pub capabilities: Vec<CapabilityId>,

    /// Optional bounded live-session protocol exposed through generic catalog
    /// discovery and enforced by the agent session broker at open time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub live_session: Option<AgentLiveSessionContract>,
}

impl CapabilitySessionHandoff {
    pub fn new(
        purpose: PluginSessionPurpose,
        capabilities: impl IntoIterator<Item = impl Into<CapabilityId>>,
    ) -> Self {
        Self {
            purpose,
            capabilities: capabilities.into_iter().map(Into::into).collect(),
            live_session: None,
        }
    }

    pub fn with_live_session(mut self, contract: AgentLiveSessionContract) -> Self {
        self.live_session = Some(contract);
        self
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityAuthorizationMetadata {
    /// True only when the plugin intentionally reviewed this capability for
    /// central authorization. Missing metadata fails closed to Custom-only.
    #[serde(default)]
    pub declared: bool,

    /// Membership in the narrow Interactive/Execute preset. This never means
    /// every destructive capability in the plugin.
    #[serde(default)]
    pub interactive_execute: bool,

    #[serde(default)]
    pub session_purposes: Vec<PluginSessionPurpose>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,

    /// Declarative, non-secret fields that Core may render and enforce for a
    /// JIT authorization request. A missing or incompatible schema disables
    /// constrained and exact-invocation JIT approval for this capability.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_schema: Option<CapabilityApprovalSchema>,

    /// Whether Core may offer a whole-capability JIT approval when no
    /// structured constraint is supplied. Undeclared metadata always fails
    /// closed regardless of this value.
    #[serde(default)]
    pub capability_wide_allowed: bool,
}

impl CapabilityAuthorizationMetadata {
    pub fn declared() -> Self {
        Self {
            declared: true,
            capability_wide_allowed: true,
            ..Self::default()
        }
    }

    pub fn with_interactive_execute(mut self) -> Self {
        self.interactive_execute = true;
        self
    }

    pub fn with_session_purposes(mut self, purposes: Vec<PluginSessionPurpose>) -> Self {
        self.session_purposes = purposes;
        self
    }

    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.note = Some(note.into());
        self
    }

    pub fn with_approval_schema(mut self, schema: CapabilityApprovalSchema) -> Self {
        self.approval_schema = Some(schema);
        self
    }

    pub fn without_capability_wide(mut self) -> Self {
        self.capability_wide_allowed = false;
        self
    }

    /// Resolve JIT support without trusting plugin UI or plugin policy code.
    pub fn jit_support(&self) -> CapabilityJitSupport {
        if !self.declared {
            return CapabilityJitSupport::Unsupported {
                reason: "authorization metadata is undeclared".into(),
            };
        }
        if let Some(schema) = &self.approval_schema
            && let Err(reason) = schema.validate()
        {
            return CapabilityJitSupport::Unsupported { reason };
        }
        if self.capability_wide_allowed || self.approval_schema.is_some() {
            CapabilityJitSupport::Supported
        } else {
            CapabilityJitSupport::Unsupported {
                reason: "capability-wide approval is disabled and no approval schema is declared"
                    .into(),
            }
        }
    }
}

pub const CAPABILITY_APPROVAL_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityApprovalSchema {
    pub version: u32,

    #[serde(default)]
    pub fields: Vec<CapabilityApprovalField>,
}

impl CapabilityApprovalSchema {
    pub fn v1(fields: Vec<CapabilityApprovalField>) -> Self {
        Self {
            version: CAPABILITY_APPROVAL_SCHEMA_VERSION,
            fields,
        }
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.version != CAPABILITY_APPROVAL_SCHEMA_VERSION {
            return Err(format!(
                "unsupported approval schema version {}",
                self.version
            ));
        }
        let mut paths = std::collections::BTreeSet::new();
        for field in &self.fields {
            field.validate()?;
            if !paths.insert(field.path.as_str()) {
                return Err(format!("duplicate approval field path '{}'", field.path));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityApprovalField {
    /// RFC 6901 JSON pointer into the normalized invocation input.
    pub path: String,
    pub label: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    pub value_type: CapabilityApprovalValueType,

    #[serde(default)]
    pub required: bool,

    #[serde(default)]
    pub constraint: CapabilityConstraintKind,

    #[serde(default)]
    pub risk_emphasis: CapabilityApprovalRiskEmphasis,
}

impl CapabilityApprovalField {
    pub fn new(
        path: impl Into<String>,
        label: impl Into<String>,
        value_type: CapabilityApprovalValueType,
    ) -> Self {
        Self {
            path: path.into(),
            label: label.into(),
            description: None,
            value_type,
            required: false,
            constraint: CapabilityConstraintKind::Exact,
            risk_emphasis: CapabilityApprovalRiskEmphasis::Normal,
        }
    }

    pub fn required(mut self) -> Self {
        self.required = true;
        self
    }

    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    pub fn with_constraint(mut self, constraint: CapabilityConstraintKind) -> Self {
        self.constraint = constraint;
        self
    }

    pub fn with_risk_emphasis(mut self, emphasis: CapabilityApprovalRiskEmphasis) -> Self {
        self.risk_emphasis = emphasis;
        self
    }

    pub fn validate(&self) -> Result<(), String> {
        if !self.path.starts_with('/') || self.path.contains("//") {
            return Err(format!(
                "approval field path '{}' must be a non-empty JSON pointer",
                self.path
            ));
        }
        if self.label.trim().is_empty() {
            return Err(format!("approval field '{}' has an empty label", self.path));
        }
        if matches!(self.value_type, CapabilityApprovalValueType::Secret) {
            return Err(format!(
                "approval field '{}' cannot declare secret data",
                self.path
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityApprovalValueType {
    String,
    StringList,
    Integer,
    Boolean,
    ResourceId,
    Path,
    CommandArgv,
    Json,
    /// Reserved so incompatible process plugins deserialize and fail closed
    /// instead of silently treating secret material as displayable text.
    Secret,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityConstraintKind {
    #[default]
    Exact,
    Prefix,
    Subset,
    Maximum,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityApprovalRiskEmphasis {
    #[default]
    Normal,
    PrivilegeEscalation,
    Destructive,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CapabilityJitSupport {
    Supported,
    Unsupported { reason: String },
}

impl CapabilityRiskLevel {
    pub fn from_destructive(destructive: bool) -> Self {
        if destructive {
            Self::Destructive
        } else {
            Self::ReadOnly
        }
    }

    pub fn requires_scoped_approval(self) -> bool {
        !matches!(self, Self::ReadOnly)
    }

    pub fn requires_acknowledgement(self) -> bool {
        matches!(self, Self::Destructive | Self::ExternalSideEffect)
    }

    pub fn has_target_side_effects(self) -> bool {
        !matches!(self, Self::ReadOnly)
    }
}

#[cfg(test)]
mod authorization_metadata_tests {
    use super::*;

    #[test]
    fn approval_schema_rejects_secrets_duplicates_and_unknown_versions() {
        let field = CapabilityApprovalField {
            path: "/command".into(),
            label: "Command".into(),
            description: None,
            value_type: CapabilityApprovalValueType::CommandArgv,
            required: true,
            constraint: CapabilityConstraintKind::Exact,
            risk_emphasis: CapabilityApprovalRiskEmphasis::Normal,
        };
        assert!(
            CapabilityApprovalSchema::v1(vec![field.clone()])
                .validate()
                .is_ok()
        );
        assert!(
            CapabilityApprovalSchema::v1(vec![field.clone(), field])
                .validate()
                .unwrap_err()
                .contains("duplicate")
        );

        let secret = CapabilityApprovalField {
            path: "/password".into(),
            label: "Password".into(),
            description: None,
            value_type: CapabilityApprovalValueType::Secret,
            required: true,
            constraint: CapabilityConstraintKind::Exact,
            risk_emphasis: CapabilityApprovalRiskEmphasis::Normal,
        };
        assert!(
            CapabilityApprovalSchema::v1(vec![secret])
                .validate()
                .unwrap_err()
                .contains("secret")
        );
        assert!(
            CapabilityApprovalSchema {
                version: CAPABILITY_APPROVAL_SCHEMA_VERSION + 1,
                fields: Vec::new(),
            }
            .validate()
            .unwrap_err()
            .contains("unsupported")
        );
    }

    #[test]
    fn undeclared_or_incompatible_metadata_fails_closed() {
        assert!(matches!(
            CapabilityAuthorizationMetadata::default().jit_support(),
            CapabilityJitSupport::Unsupported { .. }
        ));
        assert_eq!(
            CapabilityAuthorizationMetadata::declared().jit_support(),
            CapabilityJitSupport::Supported
        );
        let incompatible = CapabilityAuthorizationMetadata::declared().with_approval_schema(
            CapabilityApprovalSchema {
                version: CAPABILITY_APPROVAL_SCHEMA_VERSION + 1,
                fields: Vec::new(),
            },
        );
        assert!(matches!(
            incompatible.jit_support(),
            CapabilityJitSupport::Unsupported { .. }
        ));
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionProfilePolicy {
    #[serde(default)]
    pub allowed_capabilities: Vec<CapabilityId>,

    #[serde(default)]
    pub denied_capabilities: Vec<CapabilityId>,

    #[serde(default)]
    pub allow_destructive_by_default: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConnectionInstanceDescriptor {
    pub id: ConnectionInstanceId,
    pub profile: ConnectionProfileRef,
    pub plugin_id: PluginId,
    pub purpose: ConnectionInstancePurpose,
    pub lifecycle: ConnectionInstanceLifecycle,
    pub created_at: DateTime<Utc>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<ActorRef>,

    /// Plugin-provided, non-secret metadata for observability and audit trails.
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ConnectionInstancePurpose {
    CapabilityInvocation,
    InteractiveSession,
    Tunnel,
    BackgroundWorker,
    PoolMember,
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionInstanceLifecycle {
    Starting,
    Ready,
    Busy,
    Draining,
    Closed,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapabilityInvocation {
    pub id: InvocationId,
    pub plugin_id: PluginId,
    pub capability_id: CapabilityId,
    pub connection: InvocationConnectionTarget,

    /// Input validated against the capability input schema before execution.
    #[serde(default)]
    pub input: Value,

    #[serde(default)]
    pub controls: InvocationControls,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<ActorRef>,

    pub requested_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapabilityDefinition {
    pub plugin_id: PluginId,
    pub id: CapabilityId,
    pub description: String,

    #[serde(default)]
    pub input_schema: Value,

    #[serde(default)]
    pub output_schema: Value,

    #[serde(default)]
    pub permissions: Vec<PermissionId>,

    #[serde(default)]
    pub authorization: CapabilityAuthorizationMetadata,

    /// Stable policy classification. The legacy `destructive` flag remains
    /// serialized for compatibility and is folded into `effective_risk()`.
    #[serde(default)]
    pub risk: CapabilityRiskLevel,

    #[serde(default)]
    pub destructive: bool,

    #[serde(default)]
    pub streaming: bool,

    /// Whether this operation is available as a one-shot invocation, through
    /// a persistent plugin session, or through both transports.
    #[serde(default)]
    pub execution_mode: CapabilityExecutionMode,

    /// Optional structured session-opening guidance. This is intentionally
    /// descriptive and never grants session access by itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_handoff: Option<CapabilitySessionHandoff>,

    #[serde(default)]
    pub connection_required: bool,

    #[serde(default)]
    pub required_secret_classes: Vec<CredentialClass>,

    #[serde(default)]
    pub supports_dry_run: bool,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_timeout_ms: Option<u64>,
}

impl CapabilityDefinition {
    pub fn qualified_id(&self) -> String {
        format!("{}.{}", self.plugin_id, self.id)
    }

    pub fn effective_risk(&self) -> CapabilityRiskLevel {
        if self.destructive && self.risk == CapabilityRiskLevel::ReadOnly {
            CapabilityRiskLevel::Destructive
        } else {
            self.risk
        }
    }

    pub fn requires_acknowledgement(&self) -> bool {
        self.destructive || self.effective_risk().requires_acknowledgement()
    }

    pub fn supports_stateless_execution(&self) -> bool {
        self.execution_mode.supports_stateless()
    }

    pub fn supports_session_execution(&self) -> bool {
        self.execution_mode.supports_session()
    }

    pub fn default_approval_requirement(
        &self,
        profile: Option<ConnectionProfileRef>,
    ) -> Option<CapabilityApprovalRequirement> {
        let risk = self.effective_risk();
        risk.requires_scoped_approval()
            .then(|| CapabilityApprovalRequirement {
                scope: ApprovalScope::Capability {
                    plugin_id: self.plugin_id.clone(),
                    capability_id: self.id.clone(),
                    profile,
                },
                risk,
                requires_acknowledgement: risk.requires_acknowledgement(),
                ttl_seconds: None,
            })
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapabilityPolicyRequest {
    pub invocation_id: InvocationId,
    pub actor: ActorRef,
    pub plugin_id: PluginId,
    pub capability_id: CapabilityId,
    pub risk: CapabilityRiskLevel,
    pub requested_at: DateTime<Utc>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<ConnectionProfileRef>,

    #[serde(default)]
    pub dry_run: bool,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acknowledgement: Option<InvocationAcknowledgement>,

    #[serde(default)]
    pub approvals: Vec<ScopedApproval>,

    #[serde(default)]
    pub input_summary: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapabilityPolicyDecision {
    pub outcome: PolicyDecisionOutcome,
    pub risk: CapabilityRiskLevel,
    pub reason: PolicyReason,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required_approval: Option<CapabilityApprovalRequirement>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched_approval_id: Option<ApprovalId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyDecisionOutcome {
    Allow,
    Deny,
    RequiresApproval,
    RequiresAcknowledgement,
    DryRunOnly,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyReason {
    pub category: CapabilityErrorCategory,
    pub code: PolicyReasonCode,
    pub message: String,

    #[serde(default)]
    pub details: Value,

    #[serde(default)]
    pub redaction: RedactionStatus,
}

impl CapabilityPolicyDecision {
    pub fn error(&self) -> Option<CapabilityError> {
        match self.outcome {
            PolicyDecisionOutcome::Allow | PolicyDecisionOutcome::DryRunOnly => None,
            PolicyDecisionOutcome::Deny
            | PolicyDecisionOutcome::RequiresApproval
            | PolicyDecisionOutcome::RequiresAcknowledgement => Some(CapabilityError {
                category: self.reason.category,
                code: self.reason.code.clone(),
                message: self.reason.message.clone(),
                details: self.reason.details.clone(),
                target: None,
                retryable: false,
                redaction: self.reason.redaction,
            }),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityApprovalRequirement {
    pub scope: ApprovalScope,
    pub risk: CapabilityRiskLevel,

    #[serde(default)]
    pub requires_acknowledgement: bool,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ApprovalScope {
    Profile {
        profile: ConnectionProfileRef,
    },
    Capability {
        plugin_id: PluginId,
        capability_id: CapabilityId,

        #[serde(default, skip_serializing_if = "Option::is_none")]
        profile: Option<ConnectionProfileRef>,
    },
    Invocation {
        invocation_id: InvocationId,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopedApproval {
    pub id: ApprovalId,
    pub actor: ActorRef,
    pub scope: ApprovalScope,
    pub risk: CapabilityRiskLevel,
    pub issued_at: DateTime<Utc>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl ScopedApproval {
    pub fn status_at(&self, at: DateTime<Utc>) -> ScopedApprovalStatus {
        if self.revoked_at.is_some_and(|revoked_at| revoked_at <= at) {
            ScopedApprovalStatus::Revoked
        } else if self.expires_at.is_some_and(|expires_at| expires_at <= at) {
            ScopedApprovalStatus::Expired
        } else {
            ScopedApprovalStatus::Active
        }
    }

    pub fn is_active_at(&self, at: DateTime<Utc>) -> bool {
        self.status_at(at) == ScopedApprovalStatus::Active
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScopedApprovalStatus {
    Active,
    Expired,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvocationAcknowledgement {
    pub actor: ActorRef,
    pub acknowledged_at: DateTime<Utc>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<ApprovalId>,
}

pub fn evaluate_capability_policy(
    profile: &ConnectionProfile,
    capability: &CapabilityDefinition,
    request: &CapabilityPolicyRequest,
) -> CapabilityPolicyDecision {
    let capability_id = capability.id.as_str();
    let qualified_id = capability.qualified_id();
    let risk = capability.effective_risk();
    let profile_ref = request
        .profile
        .clone()
        .unwrap_or_else(|| profile.profile_ref());
    let required_approval = capability.default_approval_requirement(Some(profile_ref.clone()));

    if capability_list_contains(
        &profile.policy.denied_capabilities,
        capability_id,
        &qualified_id,
    ) {
        return CapabilityPolicyDecision {
            outcome: PolicyDecisionOutcome::Deny,
            risk,
            reason: policy_reason(
                CapabilityErrorCategory::Policy,
                "policy.capability_denied",
                "Profile policy denies this capability.",
                serde_json::json!({
                    "profile": profile_ref,
                    "plugin_id": capability.plugin_id,
                    "capability_id": capability.id,
                    "qualified_id": qualified_id,
                    "risk": risk,
                }),
            ),
            required_approval,
            matched_approval_id: None,
        };
    }

    if request.dry_run && !capability.supports_dry_run {
        return CapabilityPolicyDecision {
            outcome: PolicyDecisionOutcome::Deny,
            risk,
            reason: policy_reason(
                CapabilityErrorCategory::Validation,
                "validation.dry_run_not_supported",
                "Capability does not support dry-run execution.",
                serde_json::json!({
                    "profile": profile_ref,
                    "plugin_id": capability.plugin_id,
                    "capability_id": capability.id,
                    "qualified_id": qualified_id,
                    "dry_run": true,
                    "supports_dry_run": false,
                    "risk": risk,
                }),
            ),
            required_approval,
            matched_approval_id: None,
        };
    }

    if !risk.requires_scoped_approval() {
        return CapabilityPolicyDecision {
            outcome: PolicyDecisionOutcome::Allow,
            risk,
            reason: policy_reason(
                CapabilityErrorCategory::Policy,
                "policy.read_only_allowed",
                "Read-only capability is allowed by default.",
                serde_json::json!({
                    "profile": profile_ref,
                    "plugin_id": capability.plugin_id,
                    "capability_id": capability.id,
                    "qualified_id": qualified_id,
                    "risk": risk,
                }),
            ),
            required_approval: None,
            matched_approval_id: None,
        };
    }

    if request.dry_run && capability.supports_dry_run {
        return CapabilityPolicyDecision {
            outcome: PolicyDecisionOutcome::DryRunOnly,
            risk,
            reason: policy_reason(
                CapabilityErrorCategory::Policy,
                "policy.dry_run_allowed",
                "Dry-run is allowed without target mutation.",
                serde_json::json!({
                    "profile": profile_ref,
                    "plugin_id": capability.plugin_id,
                    "capability_id": capability.id,
                    "qualified_id": qualified_id,
                    "dry_run": true,
                    "risk": risk,
                }),
            ),
            required_approval,
            matched_approval_id: None,
        };
    }

    let matched_approval_id = required_approval.as_ref().and_then(|requirement| {
        request
            .approvals
            .iter()
            .find(|approval| approval_satisfies_requirement(approval, requirement, request))
            .map(|approval| approval.id.clone())
    });

    let explicitly_allowed = profile.policy.allow_destructive_by_default
        || capability_list_contains(
            &profile.policy.allowed_capabilities,
            capability_id,
            &qualified_id,
        )
        || matched_approval_id.is_some();

    if explicitly_allowed {
        if capability.requires_acknowledgement() && request.acknowledgement.is_none() {
            return CapabilityPolicyDecision {
                outcome: PolicyDecisionOutcome::RequiresAcknowledgement,
                risk,
                reason: policy_reason(
                    CapabilityErrorCategory::Policy,
                    "policy.destructive_denied_by_default",
                    "Profile policy blocks destructive capability execution by default.",
                    serde_json::json!({
                        "profile": profile_ref,
                        "plugin_id": capability.plugin_id,
                        "capability_id": capability.id,
                        "qualified_id": qualified_id,
                        "destructive": capability.destructive,
                        "risk": risk,
                    }),
                ),
                required_approval,
                matched_approval_id,
            };
        }

        return CapabilityPolicyDecision {
            outcome: PolicyDecisionOutcome::Allow,
            risk,
            reason: policy_reason(
                CapabilityErrorCategory::Policy,
                "policy.approval_allowed",
                "Capability is allowed by profile policy or scoped approval.",
                serde_json::json!({
                    "profile": profile_ref,
                    "plugin_id": capability.plugin_id,
                    "capability_id": capability.id,
                    "qualified_id": qualified_id,
                    "acknowledged": request.acknowledgement.is_some(),
                    "risk": risk,
                }),
            ),
            required_approval,
            matched_approval_id,
        };
    }

    if capability.requires_acknowledgement() && request.acknowledgement.is_some() {
        return CapabilityPolicyDecision {
            outcome: PolicyDecisionOutcome::Allow,
            risk,
            reason: policy_reason(
                CapabilityErrorCategory::Policy,
                "policy.destructive_invocation_acknowledged",
                "Destructive capability was allowed for this invocation only.",
                serde_json::json!({
                    "profile": profile_ref,
                    "plugin_id": capability.plugin_id,
                    "capability_id": capability.id,
                    "qualified_id": qualified_id,
                    "acknowledged": true,
                    "risk": risk,
                }),
            ),
            required_approval,
            matched_approval_id: request
                .acknowledgement
                .as_ref()
                .and_then(|acknowledgement| acknowledgement.approval_id.clone()),
        };
    }

    let (outcome, code, message) = if capability.requires_acknowledgement() {
        (
            PolicyDecisionOutcome::RequiresAcknowledgement,
            "policy.destructive_denied_by_default",
            "Profile policy blocks destructive capability execution by default.",
        )
    } else {
        (
            PolicyDecisionOutcome::RequiresApproval,
            "policy.approval_required",
            "Scoped approval is required before execution.",
        )
    };

    CapabilityPolicyDecision {
        outcome,
        risk,
        reason: policy_reason(
            CapabilityErrorCategory::Policy,
            code,
            message,
            serde_json::json!({
                "profile": profile_ref,
                "plugin_id": capability.plugin_id,
                "capability_id": capability.id,
                "qualified_id": qualified_id,
                "destructive": capability.destructive,
                "risk": risk,
            }),
        ),
        required_approval,
        matched_approval_id: None,
    }
}

fn approval_satisfies_requirement(
    approval: &ScopedApproval,
    requirement: &CapabilityApprovalRequirement,
    request: &CapabilityPolicyRequest,
) -> bool {
    approval.is_active_at(request.requested_at)
        && approval.risk == requirement.risk
        && approval.scope == requirement.scope
        && (!requirement.requires_acknowledgement || request.acknowledgement.is_some())
}

fn policy_reason(
    category: CapabilityErrorCategory,
    code: &str,
    message: &str,
    details: Value,
) -> PolicyReason {
    PolicyReason {
        category,
        code: code.into(),
        message: message.into(),
        details,
        redaction: RedactionStatus::NotRequired,
    }
}

#[allow(clippy::result_large_err)]
pub fn evaluate_profile_policy(
    profile: &ConnectionProfile,
    capability: &CapabilityDefinition,
) -> Result<(), CapabilityError> {
    let capability_id = capability.id.as_str();
    let qualified_id = capability.qualified_id();

    if capability_list_contains(
        &profile.policy.denied_capabilities,
        capability_id,
        &qualified_id,
    ) {
        return Err(CapabilityError {
            category: CapabilityErrorCategory::Policy,
            code: "policy.capability_denied".into(),
            message: "Profile policy denies this capability.".into(),
            details: serde_json::json!({
                "profile": profile.profile_ref(),
                "plugin_id": capability.plugin_id,
                "capability_id": capability.id,
                "qualified_id": qualified_id,
            }),
            target: None,
            retryable: false,
            redaction: RedactionStatus::NotRequired,
        });
    }

    let effective_risk = capability.effective_risk();

    if capability.requires_acknowledgement()
        && !profile.policy.allow_destructive_by_default
        && !capability_list_contains(
            &profile.policy.allowed_capabilities,
            capability_id,
            &qualified_id,
        )
    {
        return Err(CapabilityError {
            category: CapabilityErrorCategory::Policy,
            code: "policy.destructive_denied_by_default".into(),
            message: "Profile policy blocks destructive capability execution by default.".into(),
            details: serde_json::json!({
                "profile": profile.profile_ref(),
                "plugin_id": capability.plugin_id,
                "capability_id": capability.id,
                "qualified_id": qualified_id,
                "destructive": true,
                "risk": effective_risk,
            }),
            target: None,
            retryable: false,
            redaction: RedactionStatus::NotRequired,
        });
    }

    Ok(())
}

#[allow(clippy::result_large_err)]
pub fn grant_credentials_for_invocation(
    profile: &ConnectionProfile,
    capability: &CapabilityDefinition,
    invocation: &CapabilityInvocation,
    issued_at: DateTime<Utc>,
) -> Result<CredentialGrant, CapabilityError> {
    if profile.plugin_id != capability.plugin_id || invocation.plugin_id != capability.plugin_id {
        return Err(CapabilityError {
            category: CapabilityErrorCategory::Validation,
            code: "validation.plugin_mismatch".into(),
            message: "Profile, capability, and invocation plugin IDs must match.".into(),
            details: serde_json::json!({
                "profile_plugin_id": profile.plugin_id,
                "capability_plugin_id": capability.plugin_id,
                "invocation_plugin_id": invocation.plugin_id,
            }),
            target: None,
            retryable: false,
            redaction: RedactionStatus::NotRequired,
        });
    }

    let granted_refs = capability
        .required_secret_classes
        .iter()
        .filter_map(|required_class| {
            profile
                .credential_refs
                .iter()
                .find(|credential_ref| credential_ref.class == *required_class)
                .cloned()
        })
        .collect::<Vec<_>>();

    let missing_classes = capability
        .required_secret_classes
        .iter()
        .filter(|required_class| {
            !granted_refs
                .iter()
                .any(|credential_ref| credential_ref.class == **required_class)
        })
        .cloned()
        .collect::<Vec<_>>();

    if !missing_classes.is_empty() {
        return Err(CapabilityError {
            category: CapabilityErrorCategory::Credential,
            code: "credential.required_ref_missing".into(),
            message:
                "Profile does not expose all credential references required by the capability."
                    .into(),
            details: serde_json::json!({
                "profile": profile.profile_ref(),
                "plugin_id": capability.plugin_id,
                "capability_id": capability.id,
                "missing_classes": missing_classes,
            }),
            target: None,
            retryable: false,
            redaction: RedactionStatus::NotRequired,
        });
    }

    Ok(CredentialGrant {
        id: format!("grant:{}", invocation.id),
        profile: profile.profile_ref(),
        plugin_id: capability.plugin_id.clone(),
        scope: CredentialGrantScope::Invocation {
            invocation_id: invocation.id.clone(),
        },
        issued_at,
        expires_at: None,
        credential_refs: granted_refs,
        redaction: RedactionStatus::NotRequired,
    })
}

fn capability_list_contains(
    capability_list: &[CapabilityId],
    capability_id: &str,
    qualified_id: &str,
) -> bool {
    capability_list
        .iter()
        .any(|listed| listed == capability_id || listed == qualified_id)
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapabilityInvocationResult {
    pub invocation_id: InvocationId,
    pub status: InvocationStatus,

    #[serde(default)]
    pub output: Value,

    #[serde(default)]
    pub output_summary: Value,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<InvocationOutputPage>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvocationOutputPage {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InvocationAuditRecord {
    pub invocation_id: InvocationId,
    pub actor: ActorRef,
    pub plugin_id: PluginId,
    pub capability_id: CapabilityId,
    pub connection: InvocationConnectionTarget,
    pub timing: InvocationTiming,
    pub status: InvocationStatus,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<ConnectionProfileRef>,

    #[serde(default)]
    pub credential_refs: Vec<CredentialRef>,

    /// Redacted, schema-shaped input metadata. Raw invocation input may include
    /// target data and must not be copied here without redaction.
    #[serde(default)]
    pub input_summary: Value,

    /// Redacted output metadata, such as row counts, object counts, or stream
    /// frame counts.
    #[serde(default)]
    pub output_summary: Value,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<CapabilityError>,

    #[serde(default)]
    pub redaction: RedactionStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvocationTiming {
    pub requested_at: DateTime<Utc>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<DateTime<Utc>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at: Option<DateTime<Utc>>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InvocationStatus {
    Accepted,
    Running,
    Succeeded,
    Failed,
    Cancelled,
    TimedOut,
}

/// Version of the line-delimited invocation event protocol.
pub const INVOCATION_STREAM_PROTOCOL_VERSION: u32 = 1;

/// Fallback deadline for capabilities that do not declare a manifest default.
pub const DEFAULT_INVOCATION_TIMEOUT_MS: u64 = 30_000;

/// Default and hard bounds for one terminal invocation result.
pub const DEFAULT_INVOCATION_OUTPUT_BYTES: u64 = 4 * 1024 * 1024;
pub const MAX_INVOCATION_OUTPUT_BYTES: u64 = 16 * 1024 * 1024;

/// Shared pagination bounds for generic invocation controls.
pub const DEFAULT_INVOCATION_PAGE_LIMIT: u32 = 100;
pub const MAX_INVOCATION_PAGE_LIMIT: u32 = 1_000;
pub const MAX_INVOCATION_CURSOR_BYTES: usize = 4_096;

/// One independently decodable line in the invocation NDJSON protocol.
///
/// Sequence numbers start at zero and increase by one for every event emitted
/// by a caller. The tagged event payload keeps the protocol extensible without
/// changing the legacy single-document JSON result envelope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InvocationStreamEnvelope {
    pub protocol_version: u32,
    pub sequence: u64,
    pub invocation_id: InvocationId,

    #[serde(flatten)]
    pub event: InvocationStreamEvent,
}

impl InvocationStreamEnvelope {
    pub fn new(
        sequence: u64,
        invocation_id: impl Into<InvocationId>,
        event: InvocationStreamEvent,
    ) -> Self {
        Self {
            protocol_version: INVOCATION_STREAM_PROTOCOL_VERSION,
            sequence,
            invocation_id: invocation_id.into(),
            event,
        }
    }
}

/// Stable event kinds emitted by the invocation NDJSON protocol.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum InvocationStreamEvent {
    Start {
        capability_ref: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        timeout_ms: Option<u64>,
    },
    Data {
        value: Value,
    },
    Progress {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        message: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fraction: Option<f64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        current: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        total: Option<u64>,
    },
    Warning {
        warning: Value,
    },
    Error {
        error: CapabilityError,
    },
    End {
        status: InvocationStatus,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        duration_ms: Option<u64>,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapabilityError {
    pub category: CapabilityErrorCategory,
    pub code: ErrorCode,
    pub message: String,

    #[serde(default)]
    pub details: Value,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<TargetSystemFailure>,

    #[serde(default)]
    pub retryable: bool,

    #[serde(default)]
    pub redaction: RedactionStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapabilityErrorCategory {
    Validation,
    Auth,
    Permission,
    Credential,
    Policy,
    Transport,
    Timeout,
    Cancellation,
    Plugin,
    TargetSystem,
    Conflict,
    Unavailable,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetSystemFailure {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub system: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RedactionStatus {
    #[default]
    NotRequired,
    Applied,
    Withheld,
    FailedClosed,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InvocationConnectionTarget {
    /// The capability does not need a connection profile or runtime instance.
    Stateless,

    /// The plugin receives a profile reference and decides whether to create or
    /// reuse an instance according to the requested reuse policy.
    FromProfile {
        profile: ConnectionProfileRef,
        purpose: ConnectionInstancePurpose,
        reuse: InstanceReusePolicy,

        #[serde(default)]
        options: Value,
    },

    /// The caller intentionally targets an already-created runtime instance.
    ExistingInstance { instance_id: ConnectionInstanceId },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstanceReusePolicy {
    /// Always create a fresh runtime instance for this invocation.
    Never,

    /// Let the plugin reuse a suitable existing instance or create a new one.
    #[default]
    Allow,

    /// Require a compatible existing instance; fail if none is available.
    Require,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InvocationControls {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cancellation_token: Option<CancellationToken>,

    #[serde(default)]
    pub dry_run: bool,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acknowledgement: Option<InvocationAcknowledgement>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub approval_refs: Vec<ApprovalId>,

    #[serde(default)]
    pub stream: bool,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_bytes: Option<u64>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page: Option<Pagination>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pagination {
    pub limit: u32,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cursor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActorRef {
    pub id: ActorId,
    pub actor_type: ActorType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorType {
    Human,
    Agent,
    System,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn invocation_stream_envelope_is_versioned_and_round_trips() {
        let envelope = InvocationStreamEnvelope::new(
            2,
            "invoke-01",
            InvocationStreamEvent::Progress {
                message: Some("loading".into()),
                fraction: Some(0.4),
                current: Some(4),
                total: Some(10),
            },
        );
        let value = serde_json::to_value(&envelope).expect("serialize stream envelope");

        assert_eq!(
            value["protocol_version"],
            INVOCATION_STREAM_PROTOCOL_VERSION
        );
        assert_eq!(value["sequence"], 2);
        assert_eq!(value["invocation_id"], "invoke-01");
        assert_eq!(value["type"], "progress");
        assert_eq!(value["data"]["current"], 4);
        assert_eq!(
            serde_json::from_value::<InvocationStreamEnvelope>(value)
                .expect("deserialize stream envelope"),
            envelope
        );
    }

    #[test]
    fn profile_exposes_id_and_name_refs() {
        let profile = ConnectionProfile {
            id: "profile-01".into(),
            name: "prod-db".into(),
            plugin_id: "mysql".into(),
            display_name: None,
            metadata: json!({ "host": "db.example.com", "port": 3306 }),
            default_options: Value::Null,
            credential_refs: vec![CredentialRef {
                id: "cred-01".into(),
                class: CredentialClass::Password,
                label: Some("database password".into()),
            }],
            policy: ConnectionProfilePolicy::default(),
        };

        assert_eq!(
            profile.profile_ref(),
            ConnectionProfileRef::id("profile-01")
        );
        assert_eq!(profile.name_ref(), ConnectionProfileRef::name("prod-db"));
    }

    #[test]
    fn profile_json_uses_name_and_reads_existing_alias_records() {
        let existing = json!({
            "id": "profile-existing",
            "alias": "Prod",
            "plugin_id": "ssh",
            "metadata": null,
            "default_options": null,
            "credential_refs": [],
            "policy": {}
        });

        let profile: ConnectionProfile =
            serde_json::from_value(existing).expect("existing alias record remains readable");
        let encoded = serde_json::to_value(&profile).expect("serialize profile");

        assert_eq!(profile.name, "Prod");
        assert_eq!(encoded["name"], "Prod");
        assert!(encoded.get("alias").is_none());
        assert_eq!(
            serde_json::to_value(ConnectionProfileRef::name("Prod")).expect("serialize ref"),
            json!({ "kind": "name", "value": "Prod" })
        );
        let old_ref: ConnectionProfileRef = serde_json::from_value(json!({
            "kind": "alias",
            "value": "Prod"
        }))
        .expect("existing alias ref remains readable");
        assert_eq!(old_ref, ConnectionProfileRef::name("Prod"));
    }

    #[test]
    fn one_profile_can_back_multiple_runtime_instances() {
        let profile_ref = ConnectionProfileRef::name("prod-ssh");
        let created_at = DateTime::parse_from_rfc3339("2026-07-04T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);

        let terminal = ConnectionInstanceDescriptor {
            id: "inst-terminal".into(),
            profile: profile_ref.clone(),
            plugin_id: "ssh".into(),
            purpose: ConnectionInstancePurpose::InteractiveSession,
            lifecycle: ConnectionInstanceLifecycle::Ready,
            created_at,
            owner: None,
            labels: BTreeMap::new(),
        };
        let tunnel = ConnectionInstanceDescriptor {
            id: "inst-tunnel".into(),
            profile: profile_ref.clone(),
            plugin_id: "ssh".into(),
            purpose: ConnectionInstancePurpose::Tunnel,
            lifecycle: ConnectionInstanceLifecycle::Ready,
            created_at,
            owner: None,
            labels: BTreeMap::new(),
        };

        assert_eq!(terminal.profile, tunnel.profile);
        assert_ne!(terminal.id, tunnel.id);
    }

    #[test]
    fn invocation_serializes_machine_readable_connection_target() {
        let invocation = CapabilityInvocation {
            id: "invoke-01".into(),
            plugin_id: "sqlite".into(),
            capability_id: "query".into(),
            connection: InvocationConnectionTarget::FromProfile {
                profile: ConnectionProfileRef::name("local-dev"),
                purpose: ConnectionInstancePurpose::CapabilityInvocation,
                reuse: InstanceReusePolicy::Never,
                options: Value::Null,
            },
            input: json!({ "sql": "select 1" }),
            controls: InvocationControls {
                timeout_ms: Some(5_000),
                cancellation_token: Some("cancel-01".into()),
                dry_run: false,
                acknowledgement: None,
                approval_refs: Vec::new(),
                stream: false,
                max_output_bytes: Some(DEFAULT_INVOCATION_OUTPUT_BYTES),
                page: None,
            },
            actor: Some(ActorRef {
                id: "agent:test".into(),
                actor_type: ActorType::Agent,
            }),
            requested_at: DateTime::parse_from_rfc3339("2026-07-04T00:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
        };

        let encoded = serde_json::to_value(invocation).unwrap();

        assert_eq!(encoded["connection"]["kind"], "from_profile");
        assert_eq!(encoded["connection"]["reuse"], "never");
        assert_eq!(
            encoded["connection"]["purpose"]["kind"],
            "capability_invocation"
        );
        assert_eq!(encoded["actor"]["actor_type"], "agent");
    }

    #[test]
    fn agent_invocations_can_request_fresh_instances_from_one_profile() {
        let requested_at = DateTime::parse_from_rfc3339("2026-07-04T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let profile = ConnectionProfileRef::name("local-dev");
        let first = CapabilityInvocation {
            id: "invoke-a".into(),
            plugin_id: "sqlite".into(),
            capability_id: "query".into(),
            connection: InvocationConnectionTarget::FromProfile {
                profile: profile.clone(),
                purpose: ConnectionInstancePurpose::CapabilityInvocation,
                reuse: InstanceReusePolicy::Never,
                options: Value::Null,
            },
            input: json!({ "sql": "select count(*) from users" }),
            controls: InvocationControls::default(),
            actor: Some(ActorRef {
                id: "agent:test".into(),
                actor_type: ActorType::Agent,
            }),
            requested_at,
        };
        let second = CapabilityInvocation {
            id: "invoke-b".into(),
            input: json!({ "sql": "select name from users limit 1" }),
            ..first.clone()
        };

        let InvocationConnectionTarget::FromProfile {
            profile: first_profile,
            reuse: first_reuse,
            ..
        } = &first.connection
        else {
            panic!("expected profile-backed invocation");
        };
        let InvocationConnectionTarget::FromProfile {
            profile: second_profile,
            reuse: second_reuse,
            ..
        } = &second.connection
        else {
            panic!("expected profile-backed invocation");
        };

        assert_eq!(first_profile, second_profile);
        assert_eq!(*first_reuse, InstanceReusePolicy::Never);
        assert_eq!(*second_reuse, InstanceReusePolicy::Never);
        assert_ne!(first.id, second.id);
    }

    #[test]
    fn capability_definition_exposes_qualified_id() {
        let definition = CapabilityDefinition {
            plugin_id: "redis".into(),
            id: "get".into(),
            description: "Fetch one key.".into(),
            input_schema: json!({ "type": "object" }),
            output_schema: json!({ "type": "object" }),
            permissions: vec!["connection.read".into(), "redis.get".into()],
            authorization: CapabilityAuthorizationMetadata::default(),
            risk: CapabilityRiskLevel::ReadOnly,
            destructive: false,
            streaming: false,
            execution_mode: CapabilityExecutionMode::Stateless,
            session_handoff: None,
            connection_required: true,
            required_secret_classes: vec![CredentialClass::Password],
            supports_dry_run: false,
            default_timeout_ms: Some(30_000),
        };

        assert_eq!(definition.qualified_id(), "redis.get");
    }

    #[test]
    fn capability_execution_mode_is_backward_compatible_and_serialized() {
        let legacy = json!({
            "plugin_id": "redis",
            "id": "get",
            "description": "Fetch one key."
        });
        let definition: CapabilityDefinition =
            serde_json::from_value(legacy).expect("deserialize legacy descriptor");

        assert_eq!(
            definition.execution_mode,
            CapabilityExecutionMode::Stateless
        );
        assert!(definition.supports_stateless_execution());
        assert!(!definition.supports_session_execution());
        assert!(definition.session_handoff.is_none());

        let encoded = serde_json::to_value(&definition).expect("serialize descriptor");
        assert_eq!(encoded["execution_mode"], "stateless");
        assert!(encoded.get("session_handoff").is_none());
    }

    #[test]
    fn capability_session_handoff_round_trips_as_structured_metadata() {
        let definition = CapabilityDefinition {
            plugin_id: "ssh".into(),
            id: "terminal_read".into(),
            description: "Read terminal output.".into(),
            input_schema: Value::Null,
            output_schema: Value::Null,
            permissions: vec!["ssh.terminal.read".into()],
            authorization: CapabilityAuthorizationMetadata::default(),
            risk: CapabilityRiskLevel::ReadOnly,
            destructive: false,
            streaming: true,
            execution_mode: CapabilityExecutionMode::SessionOnly,
            session_handoff: Some(CapabilitySessionHandoff::new(
                PluginSessionPurpose::InteractiveTerminal,
                ["ssh.terminal_read", "ssh.terminal_snapshot"],
            )),
            connection_required: true,
            required_secret_classes: Vec::new(),
            supports_dry_run: false,
            default_timeout_ms: None,
        };

        assert!(!definition.supports_stateless_execution());
        assert!(definition.supports_session_execution());
        let encoded = serde_json::to_value(&definition).expect("serialize descriptor");
        assert_eq!(encoded["execution_mode"], "session_only");
        assert_eq!(
            encoded["session_handoff"]["capabilities"],
            json!(["ssh.terminal_read", "ssh.terminal_snapshot"])
        );
        let decoded: CapabilityDefinition =
            serde_json::from_value(encoded).expect("deserialize descriptor");
        assert_eq!(decoded, definition);
    }

    #[test]
    fn capability_risk_falls_back_to_legacy_destructive_flag() {
        let definition = CapabilityDefinition {
            plugin_id: "redis".into(),
            id: "del".into(),
            description: "Delete one key.".into(),
            input_schema: Value::Null,
            output_schema: Value::Null,
            permissions: vec!["connection.write".into()],
            authorization: CapabilityAuthorizationMetadata::default(),
            risk: CapabilityRiskLevel::ReadOnly,
            destructive: true,
            streaming: false,
            execution_mode: CapabilityExecutionMode::Stateless,
            session_handoff: None,
            connection_required: true,
            required_secret_classes: Vec::new(),
            supports_dry_run: true,
            default_timeout_ms: None,
        };

        let requirement =
            definition.default_approval_requirement(Some(ConnectionProfileRef::name("cache")));

        assert_eq!(
            definition.effective_risk(),
            CapabilityRiskLevel::Destructive
        );
        assert!(definition.requires_acknowledgement());
        let requirement = requirement.expect("destructive capability requires approval");
        assert_eq!(requirement.risk, CapabilityRiskLevel::Destructive);
        assert!(requirement.requires_acknowledgement);
        assert!(matches!(
            requirement.scope,
            ApprovalScope::Capability {
                ref plugin_id,
                ref capability_id,
                profile: Some(ConnectionProfileRef::Name(ref name))
            } if plugin_id == "redis" && capability_id == "del" && name == "cache"
        ));
    }

    #[test]
    fn profile_policy_denies_destructive_capabilities_by_default() {
        let profile = ConnectionProfile {
            id: "profile-01".into(),
            name: "cache".into(),
            plugin_id: "redis".into(),
            display_name: None,
            metadata: Value::Null,
            default_options: Value::Null,
            credential_refs: Vec::new(),
            policy: ConnectionProfilePolicy::default(),
        };
        let capability = CapabilityDefinition {
            plugin_id: "redis".into(),
            id: "set".into(),
            description: "Set one key.".into(),
            input_schema: Value::Null,
            output_schema: Value::Null,
            permissions: vec!["connection.write".into()],
            authorization: CapabilityAuthorizationMetadata::default(),
            risk: CapabilityRiskLevel::Destructive,
            destructive: true,
            streaming: false,
            execution_mode: CapabilityExecutionMode::Stateless,
            session_handoff: None,
            connection_required: true,
            required_secret_classes: Vec::new(),
            supports_dry_run: true,
            default_timeout_ms: None,
        };

        let error = evaluate_profile_policy(&profile, &capability).expect_err("policy denied");

        assert_eq!(error.category, CapabilityErrorCategory::Policy);
        assert_eq!(error.code, "policy.destructive_denied_by_default");
        assert_eq!(error.details["capability_id"], "set");
        assert_eq!(error.redaction, RedactionStatus::NotRequired);
    }

    #[test]
    fn profile_policy_denies_external_side_effects_by_default() {
        let profile = ConnectionProfile {
            id: "profile-01".into(),
            name: "ci".into(),
            plugin_id: "jenkins".into(),
            display_name: None,
            metadata: Value::Null,
            default_options: Value::Null,
            credential_refs: Vec::new(),
            policy: ConnectionProfilePolicy::default(),
        };
        let capability = CapabilityDefinition {
            plugin_id: "jenkins".into(),
            id: "trigger".into(),
            description: "Trigger one CI job.".into(),
            input_schema: Value::Null,
            output_schema: Value::Null,
            permissions: vec!["jenkins.job.trigger".into()],
            authorization: CapabilityAuthorizationMetadata::default(),
            risk: CapabilityRiskLevel::ExternalSideEffect,
            destructive: false,
            streaming: false,
            execution_mode: CapabilityExecutionMode::Stateless,
            session_handoff: None,
            connection_required: true,
            required_secret_classes: Vec::new(),
            supports_dry_run: true,
            default_timeout_ms: None,
        };

        let error = evaluate_profile_policy(&profile, &capability).expect_err("policy denied");

        assert_eq!(error.category, CapabilityErrorCategory::Policy);
        assert_eq!(error.code, "policy.destructive_denied_by_default");
        assert_eq!(error.details["risk"], "external_side_effect");
    }

    #[test]
    fn profile_policy_allows_explicit_destructive_capability() {
        let profile = ConnectionProfile {
            id: "profile-01".into(),
            name: "cache".into(),
            plugin_id: "redis".into(),
            display_name: None,
            metadata: Value::Null,
            default_options: Value::Null,
            credential_refs: Vec::new(),
            policy: ConnectionProfilePolicy {
                allowed_capabilities: vec!["redis.set".into()],
                denied_capabilities: Vec::new(),
                allow_destructive_by_default: false,
            },
        };
        let capability = CapabilityDefinition {
            plugin_id: "redis".into(),
            id: "set".into(),
            description: "Set one key.".into(),
            input_schema: Value::Null,
            output_schema: Value::Null,
            permissions: vec!["connection.write".into()],
            authorization: CapabilityAuthorizationMetadata::default(),
            risk: CapabilityRiskLevel::Destructive,
            destructive: true,
            streaming: false,
            execution_mode: CapabilityExecutionMode::Stateless,
            session_handoff: None,
            connection_required: true,
            required_secret_classes: Vec::new(),
            supports_dry_run: true,
            default_timeout_ms: None,
        };

        evaluate_profile_policy(&profile, &capability).expect("policy allows explicit capability");
    }

    #[test]
    fn scoped_approval_status_tracks_ttl_and_revocation() {
        let issued_at = DateTime::parse_from_rfc3339("2026-07-04T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let expires_at = issued_at + chrono::Duration::minutes(15);
        let actor = ActorRef {
            id: "agent:test".into(),
            actor_type: ActorType::Agent,
        };
        let approval = ScopedApproval {
            id: "approval-01".into(),
            actor,
            scope: ApprovalScope::Capability {
                plugin_id: "s3".into(),
                capability_id: "delete".into(),
                profile: Some(ConnectionProfileRef::name("assets")),
            },
            risk: CapabilityRiskLevel::Destructive,
            issued_at,
            expires_at: Some(expires_at),
            revoked_at: None,
            reason: Some("cleanup window".into()),
        };

        assert_eq!(approval.status_at(issued_at), ScopedApprovalStatus::Active);
        assert_eq!(
            approval.status_at(expires_at),
            ScopedApprovalStatus::Expired
        );

        let revoked = ScopedApproval {
            revoked_at: Some(issued_at + chrono::Duration::minutes(5)),
            ..approval
        };
        assert_eq!(
            revoked.status_at(issued_at + chrono::Duration::minutes(6)),
            ScopedApprovalStatus::Revoked
        );
        assert!(!revoked.is_active_at(issued_at + chrono::Duration::minutes(6)));
    }

    #[test]
    fn policy_decision_serializes_redacted_reason_fields() {
        let decision = CapabilityPolicyDecision {
            outcome: PolicyDecisionOutcome::RequiresApproval,
            risk: CapabilityRiskLevel::Mutating,
            reason: PolicyReason {
                category: CapabilityErrorCategory::Policy,
                code: "policy.approval_required".into(),
                message: "Scoped approval is required before execution.".into(),
                details: json!({
                    "profile": "assets",
                    "target": "<redacted:credential>"
                }),
                redaction: RedactionStatus::Applied,
            },
            required_approval: Some(CapabilityApprovalRequirement {
                scope: ApprovalScope::Capability {
                    plugin_id: "s3".into(),
                    capability_id: "put".into(),
                    profile: Some(ConnectionProfileRef::name("assets")),
                },
                risk: CapabilityRiskLevel::Mutating,
                requires_acknowledgement: false,
                ttl_seconds: Some(300),
            }),
            matched_approval_id: None,
        };

        let encoded = serde_json::to_value(decision).unwrap();
        let encoded_text = serde_json::to_string(&encoded).unwrap();

        assert_eq!(encoded["outcome"], "requires_approval");
        assert_eq!(encoded["risk"], "mutating");
        assert_eq!(encoded["reason"]["redaction"], "applied");
        assert_eq!(encoded["required_approval"]["ttl_seconds"], 300);
        assert!(encoded_text.contains("<redacted:credential>"));
        assert!(!encoded_text.contains("secret-token"));
    }

    #[test]
    fn capability_policy_allows_acknowledged_destructive_invocation() {
        let requested_at = DateTime::parse_from_rfc3339("2026-07-04T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let profile = profile("profile-01", "cache", "redis");
        let capability = destructive_capability("redis", "del");
        let actor = ActorRef {
            id: "local-cli".into(),
            actor_type: ActorType::Human,
        };
        let request = policy_request(
            &capability,
            Some(profile.profile_ref()),
            requested_at,
            false,
            Some(InvocationAcknowledgement {
                actor,
                acknowledged_at: requested_at,
                reason: Some("cli --yes".into()),
                approval_id: None,
            }),
            Vec::new(),
        );

        let decision = evaluate_capability_policy(&profile, &capability, &request);

        assert_eq!(decision.outcome, PolicyDecisionOutcome::Allow);
        assert_eq!(
            decision.reason.code,
            "policy.destructive_invocation_acknowledged"
        );
        assert!(decision.error().is_none());
    }

    #[test]
    fn capability_policy_denials_override_acknowledgement() {
        let requested_at = DateTime::parse_from_rfc3339("2026-07-04T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut profile = profile("profile-01", "cache", "redis");
        profile.policy.denied_capabilities = vec!["redis.del".into()];
        let capability = destructive_capability("redis", "del");
        let actor = ActorRef {
            id: "local-cli".into(),
            actor_type: ActorType::Human,
        };
        let request = policy_request(
            &capability,
            Some(profile.profile_ref()),
            requested_at,
            false,
            Some(InvocationAcknowledgement {
                actor,
                acknowledged_at: requested_at,
                reason: Some("cli --yes".into()),
                approval_id: None,
            }),
            Vec::new(),
        );

        let decision = evaluate_capability_policy(&profile, &capability, &request);
        let error = decision.error().expect("policy error");

        assert_eq!(decision.outcome, PolicyDecisionOutcome::Deny);
        assert_eq!(decision.reason.code, "policy.capability_denied");
        assert_eq!(error.category, CapabilityErrorCategory::Policy);
        assert_eq!(error.code, "policy.capability_denied");
    }

    #[test]
    fn capability_policy_blocks_destructive_without_acknowledgement() {
        let requested_at = DateTime::parse_from_rfc3339("2026-07-04T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let profile = profile("profile-01", "cache", "redis");
        let capability = destructive_capability("redis", "del");
        let request = policy_request(
            &capability,
            Some(profile.profile_ref()),
            requested_at,
            false,
            None,
            Vec::new(),
        );

        let decision = evaluate_capability_policy(&profile, &capability, &request);
        let error = decision.error().expect("policy error");

        assert_eq!(
            decision.outcome,
            PolicyDecisionOutcome::RequiresAcknowledgement
        );
        assert_eq!(error.category, CapabilityErrorCategory::Policy);
        assert_eq!(error.code, "policy.destructive_denied_by_default");
    }

    #[test]
    fn capability_policy_folds_destructive_read_only_risk_mismatch() {
        let requested_at = DateTime::parse_from_rfc3339("2026-07-04T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let profile = profile("profile-01", "cache", "redis");
        let mut capability = destructive_capability("redis", "del");
        capability.risk = CapabilityRiskLevel::ReadOnly;
        let request = policy_request(
            &capability,
            Some(profile.profile_ref()),
            requested_at,
            false,
            None,
            Vec::new(),
        );

        let decision = evaluate_capability_policy(&profile, &capability, &request);

        assert_eq!(
            capability.effective_risk(),
            CapabilityRiskLevel::Destructive
        );
        assert_eq!(decision.risk, CapabilityRiskLevel::Destructive);
        assert_eq!(
            decision.outcome,
            PolicyDecisionOutcome::RequiresAcknowledgement
        );
        assert_eq!(decision.reason.details["risk"], "destructive");
    }

    #[test]
    fn capability_policy_rejects_unsupported_dry_run_before_acknowledgement() {
        let requested_at = DateTime::parse_from_rfc3339("2026-07-04T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let profile = profile("profile-01", "cache", "redis");
        let mut capability = destructive_capability("redis", "del");
        capability.supports_dry_run = false;
        let actor = ActorRef {
            id: "local-cli".into(),
            actor_type: ActorType::Human,
        };
        let request = policy_request(
            &capability,
            Some(profile.profile_ref()),
            requested_at,
            true,
            Some(InvocationAcknowledgement {
                actor,
                acknowledged_at: requested_at,
                reason: Some("cli --yes".into()),
                approval_id: None,
            }),
            Vec::new(),
        );

        let decision = evaluate_capability_policy(&profile, &capability, &request);
        let error = decision.error().expect("validation error");

        assert_eq!(decision.outcome, PolicyDecisionOutcome::Deny);
        assert_eq!(error.category, CapabilityErrorCategory::Validation);
        assert_eq!(error.code, "validation.dry_run_not_supported");
    }

    #[test]
    fn capability_policy_rejects_expired_and_revoked_approvals() {
        let requested_at = DateTime::parse_from_rfc3339("2026-07-04T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let profile = profile("profile-01", "assets", "s3");
        let capability = mutating_capability("s3", "put");
        let actor = ActorRef {
            id: "agent:test".into(),
            actor_type: ActorType::Agent,
        };
        let expired_approval = ScopedApproval {
            id: "approval-expired".into(),
            actor: actor.clone(),
            scope: ApprovalScope::Capability {
                plugin_id: "s3".into(),
                capability_id: "put".into(),
                profile: Some(profile.profile_ref()),
            },
            risk: CapabilityRiskLevel::Mutating,
            issued_at: requested_at - chrono::Duration::minutes(20),
            expires_at: Some(requested_at - chrono::Duration::minutes(1)),
            revoked_at: None,
            reason: Some("old upload window".into()),
        };
        let revoked_approval = ScopedApproval {
            id: "approval-revoked".into(),
            revoked_at: Some(requested_at - chrono::Duration::minutes(1)),
            ..expired_approval.clone()
        };

        for approval in [expired_approval, revoked_approval] {
            let request = policy_request(
                &capability,
                Some(profile.profile_ref()),
                requested_at,
                false,
                None,
                vec![approval],
            );

            let decision = evaluate_capability_policy(&profile, &capability, &request);

            assert_eq!(decision.outcome, PolicyDecisionOutcome::RequiresApproval);
            assert_eq!(decision.reason.code, "policy.approval_required");
            assert_eq!(decision.matched_approval_id, None);
        }
    }

    #[test]
    fn capability_policy_reason_does_not_echo_input_summary() {
        let requested_at = DateTime::parse_from_rfc3339("2026-07-04T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let profile = profile("profile-01", "cache", "redis");
        let capability = destructive_capability("redis", "del");
        let mut request = policy_request(
            &capability,
            Some(profile.profile_ref()),
            requested_at,
            false,
            None,
            Vec::new(),
        );
        request.input_summary = json!({
            "fields": ["password"],
            "sample": "redis-secret"
        });

        let decision = evaluate_capability_policy(&profile, &capability, &request);
        let encoded = serde_json::to_string(&decision).expect("serialize decision");

        assert_eq!(
            decision.outcome,
            PolicyDecisionOutcome::RequiresAcknowledgement
        );
        assert!(!encoded.contains("redis-secret"));
        assert!(!encoded.contains("password"));
    }

    #[test]
    fn capability_policy_allows_destructive_dry_run_only() {
        let requested_at = DateTime::parse_from_rfc3339("2026-07-04T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let profile = profile("profile-01", "cache", "redis");
        let capability = destructive_capability("redis", "del");
        let request = policy_request(
            &capability,
            Some(profile.profile_ref()),
            requested_at,
            true,
            None,
            Vec::new(),
        );

        let decision = evaluate_capability_policy(&profile, &capability, &request);

        assert_eq!(decision.outcome, PolicyDecisionOutcome::DryRunOnly);
        assert_eq!(decision.reason.code, "policy.dry_run_allowed");
        assert!(decision.error().is_none());
    }

    #[test]
    fn capability_policy_accepts_active_scoped_approval() {
        let requested_at = DateTime::parse_from_rfc3339("2026-07-04T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let mut profile = profile("profile-01", "cache", "redis");
        profile.policy.allowed_capabilities = vec!["redis.del".into()];
        let capability = destructive_capability("redis", "del");
        let actor = ActorRef {
            id: "agent:test".into(),
            actor_type: ActorType::Agent,
        };
        let approval = ScopedApproval {
            id: "approval-01".into(),
            actor: actor.clone(),
            scope: ApprovalScope::Capability {
                plugin_id: "redis".into(),
                capability_id: "del".into(),
                profile: Some(profile.profile_ref()),
            },
            risk: CapabilityRiskLevel::Destructive,
            issued_at: requested_at,
            expires_at: Some(requested_at + chrono::Duration::minutes(10)),
            revoked_at: None,
            reason: Some("maintenance".into()),
        };
        let request = policy_request(
            &capability,
            Some(profile.profile_ref()),
            requested_at,
            false,
            Some(InvocationAcknowledgement {
                actor,
                acknowledged_at: requested_at,
                reason: None,
                approval_id: Some("approval-01".into()),
            }),
            vec![approval],
        );

        let decision = evaluate_capability_policy(&profile, &capability, &request);

        assert_eq!(decision.outcome, PolicyDecisionOutcome::Allow);
        assert_eq!(decision.matched_approval_id.as_deref(), Some("approval-01"));
    }

    #[test]
    fn credential_grant_contains_references_without_secret_material() {
        let issued_at = DateTime::parse_from_rfc3339("2026-07-04T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let profile = ConnectionProfile {
            id: "profile-01".into(),
            name: "cache".into(),
            plugin_id: "redis".into(),
            display_name: None,
            metadata: Value::Null,
            default_options: Value::Null,
            credential_refs: vec![CredentialRef {
                id: "cred-password".into(),
                class: CredentialClass::Password,
                label: Some("password".into()),
            }],
            policy: ConnectionProfilePolicy::default(),
        };
        let capability = CapabilityDefinition {
            plugin_id: "redis".into(),
            id: "get".into(),
            description: "Get one key.".into(),
            input_schema: Value::Null,
            output_schema: Value::Null,
            permissions: vec!["connection.read".into()],
            authorization: CapabilityAuthorizationMetadata::default(),
            risk: CapabilityRiskLevel::ReadOnly,
            destructive: false,
            streaming: false,
            execution_mode: CapabilityExecutionMode::Stateless,
            session_handoff: None,
            connection_required: true,
            required_secret_classes: vec![CredentialClass::Password],
            supports_dry_run: false,
            default_timeout_ms: None,
        };
        let invocation = CapabilityInvocation {
            id: "invoke-01".into(),
            plugin_id: "redis".into(),
            capability_id: "get".into(),
            connection: InvocationConnectionTarget::FromProfile {
                profile: profile.profile_ref(),
                purpose: ConnectionInstancePurpose::CapabilityInvocation,
                reuse: InstanceReusePolicy::Allow,
                options: Value::Null,
            },
            input: json!({ "key": "users:1" }),
            controls: InvocationControls::default(),
            actor: None,
            requested_at: issued_at,
        };

        let grant = grant_credentials_for_invocation(&profile, &capability, &invocation, issued_at)
            .expect("grant credentials");
        let encoded = serde_json::to_string(&grant).expect("serialize grant");

        assert_eq!(grant.id, "grant:invoke-01");
        assert_eq!(grant.credential_refs[0].id, "cred-password");
        assert!(matches!(
            grant.scope,
            CredentialGrantScope::Invocation { ref invocation_id } if invocation_id == "invoke-01"
        ));
        assert!(!encoded.contains("secret"));
        assert!(!encoded.contains("users:1"));
    }

    #[test]
    fn credential_grant_reports_missing_required_class() {
        let issued_at = DateTime::parse_from_rfc3339("2026-07-04T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let profile = ConnectionProfile {
            id: "profile-01".into(),
            name: "cache".into(),
            plugin_id: "redis".into(),
            display_name: None,
            metadata: Value::Null,
            default_options: Value::Null,
            credential_refs: Vec::new(),
            policy: ConnectionProfilePolicy::default(),
        };
        let capability = CapabilityDefinition {
            plugin_id: "redis".into(),
            id: "get".into(),
            description: "Get one key.".into(),
            input_schema: Value::Null,
            output_schema: Value::Null,
            permissions: vec!["connection.read".into()],
            authorization: CapabilityAuthorizationMetadata::default(),
            risk: CapabilityRiskLevel::ReadOnly,
            destructive: false,
            streaming: false,
            execution_mode: CapabilityExecutionMode::Stateless,
            session_handoff: None,
            connection_required: true,
            required_secret_classes: vec![CredentialClass::Password],
            supports_dry_run: false,
            default_timeout_ms: None,
        };
        let invocation = CapabilityInvocation {
            id: "invoke-01".into(),
            plugin_id: "redis".into(),
            capability_id: "get".into(),
            connection: InvocationConnectionTarget::FromProfile {
                profile: profile.profile_ref(),
                purpose: ConnectionInstancePurpose::CapabilityInvocation,
                reuse: InstanceReusePolicy::Allow,
                options: Value::Null,
            },
            input: Value::Null,
            controls: InvocationControls::default(),
            actor: None,
            requested_at: issued_at,
        };

        let error = grant_credentials_for_invocation(&profile, &capability, &invocation, issued_at)
            .expect_err("missing credential class");

        assert_eq!(error.category, CapabilityErrorCategory::Credential);
        assert_eq!(error.code, "credential.required_ref_missing");
        assert_eq!(error.details["missing_classes"][0]["kind"], "password");
    }

    #[test]
    fn audit_record_serializes_redacted_target_failure() {
        let requested_at = DateTime::parse_from_rfc3339("2026-07-04T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let completed_at = DateTime::parse_from_rfc3339("2026-07-04T00:00:02Z")
            .unwrap()
            .with_timezone(&Utc);
        let record = InvocationAuditRecord {
            invocation_id: "invoke-02".into(),
            actor: ActorRef {
                id: "agent:test".into(),
                actor_type: ActorType::Agent,
            },
            plugin_id: "postgres".into(),
            capability_id: "query".into(),
            connection: InvocationConnectionTarget::FromProfile {
                profile: ConnectionProfileRef::name("prod-db"),
                purpose: ConnectionInstancePurpose::CapabilityInvocation,
                reuse: InstanceReusePolicy::Allow,
                options: Value::Null,
            },
            timing: InvocationTiming {
                requested_at,
                started_at: Some(requested_at),
                completed_at: Some(completed_at),
                duration_ms: Some(2_000),
                timeout_ms: Some(30_000),
            },
            status: InvocationStatus::Failed,
            profile: Some(ConnectionProfileRef::name("prod-db")),
            credential_refs: vec![CredentialRef {
                id: "cred-01".into(),
                class: CredentialClass::Password,
                label: None,
            }],
            input_summary: json!({
                "schema": "query-input",
                "fields": ["sql"],
                "redacted_fields": ["sql"]
            }),
            output_summary: Value::Null,
            error: Some(CapabilityError {
                category: CapabilityErrorCategory::TargetSystem,
                code: "postgres.syntax_error".into(),
                message: "Target system rejected the query.".into(),
                details: Value::Null,
                target: Some(TargetSystemFailure {
                    system: Some("postgres".into()),
                    code: Some("42601".into()),
                    message: Some("syntax error at or near \"from\"".into()),
                }),
                retryable: false,
                redaction: RedactionStatus::Applied,
            }),
            redaction: RedactionStatus::Applied,
        };

        let encoded = serde_json::to_value(record).unwrap();

        assert_eq!(encoded["status"], "failed");
        assert_eq!(encoded["redaction"], "applied");
        assert_eq!(encoded["error"]["category"], "target_system");
        assert_eq!(encoded["error"]["target"]["system"], "postgres");
        assert_eq!(encoded["credential_refs"][0]["class"]["kind"], "password");
    }

    #[test]
    fn capability_error_categories_are_stable_snake_case() {
        let error = CapabilityError {
            category: CapabilityErrorCategory::Permission,
            code: "policy.denied".into(),
            message: "Invocation denied by policy.".into(),
            details: Value::Null,
            target: None,
            retryable: false,
            redaction: RedactionStatus::FailedClosed,
        };

        let encoded = serde_json::to_value(error).unwrap();

        assert_eq!(encoded["category"], "permission");
        assert_eq!(encoded["redaction"], "failed_closed");
    }

    fn profile(id: &str, name: &str, plugin_id: &str) -> ConnectionProfile {
        ConnectionProfile {
            id: id.into(),
            name: name.into(),
            plugin_id: plugin_id.into(),
            display_name: None,
            metadata: Value::Null,
            default_options: Value::Null,
            credential_refs: Vec::new(),
            policy: ConnectionProfilePolicy::default(),
        }
    }

    fn destructive_capability(plugin_id: &str, id: &str) -> CapabilityDefinition {
        CapabilityDefinition {
            plugin_id: plugin_id.into(),
            id: id.into(),
            description: "Delete target state.".into(),
            input_schema: Value::Null,
            output_schema: Value::Null,
            permissions: vec!["target.delete".into()],
            authorization: CapabilityAuthorizationMetadata::default(),
            risk: CapabilityRiskLevel::Destructive,
            destructive: true,
            streaming: false,
            execution_mode: CapabilityExecutionMode::Stateless,
            session_handoff: None,
            connection_required: true,
            required_secret_classes: Vec::new(),
            supports_dry_run: true,
            default_timeout_ms: None,
        }
    }

    fn mutating_capability(plugin_id: &str, id: &str) -> CapabilityDefinition {
        CapabilityDefinition {
            plugin_id: plugin_id.into(),
            id: id.into(),
            description: "Update target state.".into(),
            input_schema: Value::Null,
            output_schema: Value::Null,
            permissions: vec!["target.write".into()],
            authorization: CapabilityAuthorizationMetadata::default(),
            risk: CapabilityRiskLevel::Mutating,
            destructive: false,
            streaming: false,
            execution_mode: CapabilityExecutionMode::Stateless,
            session_handoff: None,
            connection_required: true,
            required_secret_classes: Vec::new(),
            supports_dry_run: true,
            default_timeout_ms: None,
        }
    }

    fn policy_request(
        capability: &CapabilityDefinition,
        profile: Option<ConnectionProfileRef>,
        requested_at: DateTime<Utc>,
        dry_run: bool,
        acknowledgement: Option<InvocationAcknowledgement>,
        approvals: Vec<ScopedApproval>,
    ) -> CapabilityPolicyRequest {
        CapabilityPolicyRequest {
            invocation_id: "invoke-policy".into(),
            actor: ActorRef {
                id: "agent:test".into(),
                actor_type: ActorType::Agent,
            },
            plugin_id: capability.plugin_id.clone(),
            capability_id: capability.id.clone(),
            risk: capability.effective_risk(),
            requested_at,
            profile,
            dry_run,
            acknowledgement,
            approvals,
            input_summary: json!({ "shape": "test" }),
        }
    }
}
