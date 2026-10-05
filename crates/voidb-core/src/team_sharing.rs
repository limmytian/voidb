//! Governed team profile sharing model.
//!
//! Team sharing builds on object sync, but it is not the same boundary as
//! personal multi-device sync. Shared collections can carry profile, policy,
//! plugin-compatibility, and credential-reference objects. Credential material,
//! unwrapped keys, master passwords, and device-local sync state stay local.

use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use thiserror::Error;

use crate::audit::{AuditEvent, AuditEventStatus, AuditOperation};
use crate::capability::{
    ActorId, ActorRef, ActorType, CredentialClass, CredentialRefId, PluginId, RedactionStatus,
};
use crate::object_sync::{
    validate_sync_object_id, ObjectSyncError, SyncCredentialRefPayload, SyncObjectId,
    SyncObjectKind, SyncPluginCompatibilityPayload, SyncProfilePayload, SyncProfilePolicyPayload,
    OBJECT_SYNC_PAYLOAD_VERSION,
};

pub const TEAM_SHARE_SCHEMA_VERSION: u32 = 1;
pub const TEAM_SHARE_COLLECTION_ID_PREFIX: &str = "share_collection_";
pub const TEAM_SHARE_MEMBER_ID_PREFIX: &str = "share_member_";
pub const TEAM_SHARE_INVITE_ID_PREFIX: &str = "share_invite_";

pub type TeamShareCollectionId = String;
pub type TeamShareInviteId = String;
pub type TeamShareMemberId = String;
pub type TeamSharePrincipalId = String;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TeamShareError {
    #[error("team share id for {kind:?} must start with '{expected_prefix}'")]
    InvalidOpaqueIdPrefix {
        kind: TeamShareOpaqueIdKind,
        expected_prefix: &'static str,
    },

    #[error("team share id must contain opaque id characters after its prefix")]
    EmptyOpaqueIdBody,

    #[error("team share id contains a non-opaque character: '{0}'")]
    InvalidOpaqueIdCharacter(char),

    #[error("sync object id for shared {object_kind:?} is invalid: {source}")]
    InvalidSyncObject {
        object_kind: SyncObjectKind,
        source: ObjectSyncError,
    },

    #[error("team share object kind {kind:?} is not directly shareable")]
    NonShareableObjectKind {
        kind: SyncObjectKind,
        decision: TeamShareObjectDecision,
    },

    #[error("shared profile object reference mismatch for {field}")]
    ObjectReferenceMismatch { field: &'static str },

    #[error("team share invite is not pending")]
    InviteNotPending,

    #[error("team share invite expired at {expires_at}")]
    InviteExpired { expires_at: DateTime<Utc> },

    #[error("team share invite recipient does not match accepting actor")]
    InviteRecipientMismatch,

    #[error("team share invite does not belong to this collection")]
    InviteCollectionMismatch,

    #[error("team share owner role cannot be granted by invite")]
    OwnerInviteNotAllowed,

    #[error("team share member was not found")]
    MemberNotFound,

    #[error("team share member is not allowed to create invites")]
    InviterNotAuthorized,

    #[error("team share member is not allowed to revoke access")]
    RevokerNotAuthorized,

    #[error("team share owner access cannot be revoked through this flow")]
    OwnerCannotBeRevoked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TeamShareOpaqueIdKind {
    Collection,
    Invite,
    Member,
    Principal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TeamShareObjectDecision {
    Share,
    RequireLocalCredentialReenrollment,
    RejectDeviceLocal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TeamShareField {
    ProfileId,
    ProfileName,
    PluginId,
    DisplayName,
    ProfileMetadata,
    DefaultOptions,
    CredentialReferenceId,
    CredentialReferenceClass,
    CredentialReferenceLabel,
    ProfilePolicy,
    PluginCompatibility,
    CredentialMaterial,
    MasterPassword,
    UnwrappedKeyMaterial,
    DeviceLocalSyncState,
    RuntimeSessionState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TeamShareFieldDecision {
    Share,
    ShareAfterRedaction,
    RequireLocalReenrollment,
    Reject,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeamShareFieldRule {
    pub field: TeamShareField,
    pub decision: TeamShareFieldDecision,
    pub reason_code: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeamSharePolicy {
    pub schema_version: u32,
    pub field_rules: Vec<TeamShareFieldRule>,
}

impl Default for TeamSharePolicy {
    fn default() -> Self {
        Self {
            schema_version: TEAM_SHARE_SCHEMA_VERSION,
            field_rules: default_team_share_field_rules(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeamShareActor {
    pub actor_type: ActorType,
    pub actor_id: ActorId,
}

impl TeamShareActor {
    pub fn new(actor: ActorRef) -> Self {
        Self {
            actor_type: actor.actor_type,
            actor_id: actor.id,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TeamShareMemberRole {
    Owner,
    Maintainer,
    Consumer,
    Auditor,
}

impl TeamShareMemberRole {
    pub fn can_import_profiles(self) -> bool {
        !matches!(self, Self::Auditor)
    }

    pub fn can_modify_collection(self) -> bool {
        matches!(self, Self::Owner | Self::Maintainer)
    }

    pub fn can_revoke_access(self) -> bool {
        matches!(self, Self::Owner | Self::Maintainer)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TeamSharePrincipalKind {
    User,
    Group,
    ServiceAccount,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeamSharePrincipal {
    pub kind: TeamSharePrincipalKind,
    pub opaque_id: TeamSharePrincipalId,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeamShareMember {
    pub member_id: TeamShareMemberId,
    pub principal: TeamSharePrincipal,
    pub role: TeamShareMemberRole,
    pub added_at: DateTime<Utc>,
    pub added_by: TeamShareActor,
    pub redaction: RedactionStatus,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TeamShareCollection {
    pub payload_version: u32,
    pub collection_id: TeamShareCollectionId,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,

    pub owner: TeamShareMember,

    #[serde(default)]
    pub members: Vec<TeamShareMember>,

    #[serde(default)]
    pub profiles: Vec<TeamShareProfileObject>,

    #[serde(default)]
    pub policy: TeamSharePolicy,

    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub updated_by: TeamShareActor,
    pub redaction: RedactionStatus,
}

impl TeamShareCollection {
    pub fn new(
        collection_id: impl Into<TeamShareCollectionId>,
        owner: TeamShareMember,
        created_at: DateTime<Utc>,
        updated_by: TeamShareActor,
    ) -> Result<Self, TeamShareError> {
        let collection_id = collection_id.into();
        validate_team_share_opaque_id(TeamShareOpaqueIdKind::Collection, &collection_id)?;
        validate_team_share_member(&owner)?;
        validate_team_share_actor(&updated_by)?;

        Ok(Self {
            payload_version: OBJECT_SYNC_PAYLOAD_VERSION,
            collection_id,
            display_name: None,
            owner,
            members: Vec::new(),
            profiles: Vec::new(),
            policy: TeamSharePolicy::default(),
            created_at,
            updated_at: created_at,
            updated_by,
            redaction: RedactionStatus::Withheld,
        })
    }

    pub fn member_count(&self) -> u64 {
        self.members.len() as u64 + 1
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeamShareCollectionManifest {
    pub schema_version: u32,
    pub collection_id: TeamShareCollectionId,
    pub updated_at: DateTime<Utc>,
    pub updated_by: TeamShareActor,
    pub member_count: u64,
    pub profile_count: u64,
    pub object_counts: BTreeMap<String, u64>,
    pub redaction: RedactionStatus,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TeamShareProfileObject {
    pub profile_object_id: SyncObjectId,
    pub profile: SyncProfilePayload,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<TeamShareProfilePolicyObject>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugin_compatibility: Option<TeamSharePluginCompatibilityObject>,

    #[serde(default)]
    pub credential_refs: Vec<TeamShareCredentialRefObject>,

    #[serde(default)]
    pub credential_requirements: Vec<TeamShareCredentialRequirement>,

    pub redaction: RedactionStatus,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TeamShareProfilePolicyObject {
    pub object_id: SyncObjectId,
    pub payload: SyncProfilePolicyPayload,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeamSharePluginCompatibilityObject {
    pub object_id: SyncObjectId,
    pub payload: SyncPluginCompatibilityPayload,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TeamShareCredentialRefObject {
    pub object_id: SyncObjectId,
    pub payload: SyncCredentialRefPayload,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeamShareCredentialRequirement {
    pub profile_object_id: SyncObjectId,
    pub credential_ref_object_id: SyncObjectId,
    pub credential_ref_id: CredentialRefId,
    pub class: CredentialClass,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,

    pub decision: TeamShareFieldDecision,
    pub reason_code: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TeamShareProfileObjectInput {
    pub profile_object_id: SyncObjectId,
    pub profile: SyncProfilePayload,
    pub policy: Option<TeamShareProfilePolicyObject>,
    pub plugin_compatibility: Option<TeamSharePluginCompatibilityObject>,
    pub credential_refs: Vec<TeamShareCredentialRefObject>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeamShareImportContext {
    #[serde(default)]
    pub installed_plugins: BTreeMap<PluginId, String>,

    #[serde(default)]
    pub enrolled_credential_ref_ids: BTreeSet<CredentialRefId>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeamShareImportPlan {
    pub collection_id: TeamShareCollectionId,
    pub actions: Vec<TeamShareImportAction>,
    pub blocked: Vec<TeamShareImportBlock>,
    pub redaction: RedactionStatus,
}

impl TeamShareImportPlan {
    pub fn requires_user_action(&self) -> bool {
        self.actions.iter().any(|action| {
            matches!(
                action.kind,
                TeamShareImportActionKind::RequireCredentialReenrollment
                    | TeamShareImportActionKind::MarkProfileUnavailable
            )
        }) || !self.blocked.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeamShareImportAction {
    pub profile_object_id: SyncObjectId,
    pub kind: TeamShareImportActionKind,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<TeamShareImportActionReason>,

    pub redaction: RedactionStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TeamShareImportActionKind {
    ImportProfile,
    ApplyProfilePolicy,
    CheckPluginCompatibility,
    BindLocalCredential,
    RequireCredentialReenrollment,
    MarkProfileUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TeamShareImportActionReason {
    MissingPlugin,
    IncompatiblePluginVersion,
    CredentialReenrollmentRequired,
    LocalCredentialAvailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeamShareImportBlock {
    pub profile_object_id: Option<SyncObjectId>,
    pub reason: TeamShareImportBlockReason,
    pub redaction: RedactionStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TeamShareImportBlockReason {
    InvalidCollectionId,
    InvalidSharedObject,
    NonShareableObjectKind,
    PolicyReferenceMismatch,
    CredentialReferenceMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeamShareInvite {
    pub invite_id: TeamShareInviteId,
    pub collection_id: TeamShareCollectionId,
    pub invited_by_member_id: TeamShareMemberId,
    pub invited_by: TeamShareActor,
    pub recipient: TeamSharePrincipal,
    pub role: TeamShareMemberRole,
    pub created_at: DateTime<Utc>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,

    pub status: TeamShareInviteStatus,
    pub redaction: RedactionStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TeamShareInviteStatus {
    Pending,
    Accepted,
    Revoked,
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeamShareInviteInput {
    pub invite_id: TeamShareInviteId,
    pub collection_id: TeamShareCollectionId,
    pub invited_by_member_id: TeamShareMemberId,
    pub invited_by: TeamShareActor,
    pub recipient: TeamSharePrincipal,
    pub role: TeamShareMemberRole,
    pub created_at: DateTime<Utc>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeamShareInviteAcceptance {
    pub invite_id: TeamShareInviteId,
    pub collection_id: TeamShareCollectionId,
    pub accepted_by: TeamShareActor,
    pub accepted_at: DateTime<Utc>,
    pub role: TeamShareMemberRole,
    pub import_plan: TeamShareImportPlan,
    pub imported_profile_count: u64,
    pub unavailable_profile_count: u64,
    pub credential_reenrollment_count: u64,
    pub blocked_count: u64,
    pub redaction: RedactionStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeamShareRevocationInput {
    pub target: TeamShareRevocationTarget,
    pub revoked_by_member_id: TeamShareMemberId,
    pub revoked_by: TeamShareActor,
    pub revoked_at: DateTime<Utc>,
    pub reason: TeamShareRevocationReason,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeamShareRevocation {
    pub collection_id: TeamShareCollectionId,
    pub target: TeamShareRevocationTarget,
    pub revoked_by_member_id: TeamShareMemberId,
    pub revoked_by: TeamShareActor,
    pub revoked_at: DateTime<Utc>,
    pub reason: TeamShareRevocationReason,
    pub redaction: RedactionStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TeamShareRevocationTarget {
    Member { member_id: TeamShareMemberId },
    Invite { invite_id: TeamShareInviteId },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TeamShareRevocationReason {
    AccessNoLongerRequired,
    InviteCancelled,
    CredentialReenrollmentFailed,
    PolicyViolation,
    CollectionRotated,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeamShareActivityRecord {
    pub operation: TeamShareActivityOperation,
    pub collection_id: TeamShareCollectionId,
    pub occurred_at: DateTime<Utc>,
    pub actor: TeamShareActor,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invite_id: Option<TeamShareInviteId>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_id: Option<TeamShareMemberId>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revocation_target: Option<TeamShareRevocationTarget>,

    pub profile_count: u64,
    pub unavailable_profile_count: u64,
    pub credential_reenrollment_count: u64,
    pub blocked_count: u64,
    pub redaction: RedactionStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TeamShareActivityOperation {
    InviteCreated,
    InviteAccepted,
    ImportPlanned,
    ImportBlocked,
    AccessRevoked,
    CredentialReenrollmentRequired,
}

impl TeamShareActivityOperation {
    pub fn audit_operation(self) -> AuditOperation {
        match self {
            Self::InviteCreated => AuditOperation::TeamShareInviteCreated,
            Self::InviteAccepted => AuditOperation::TeamShareInviteAccepted,
            Self::ImportPlanned => AuditOperation::TeamShareImportPlanned,
            Self::ImportBlocked => AuditOperation::TeamShareImportBlocked,
            Self::AccessRevoked => AuditOperation::TeamShareAccessRevoked,
            Self::CredentialReenrollmentRequired => {
                AuditOperation::TeamShareCredentialReenrollmentRequired
            }
        }
    }
}

pub fn team_share_object_decision(kind: SyncObjectKind) -> TeamShareObjectDecision {
    match kind {
        SyncObjectKind::Profile
        | SyncObjectKind::CredentialRef
        | SyncObjectKind::ProfilePolicy
        | SyncObjectKind::PluginCompatibility => TeamShareObjectDecision::Share,
        SyncObjectKind::CredentialRecord => {
            TeamShareObjectDecision::RequireLocalCredentialReenrollment
        }
        SyncObjectKind::AppPreference => TeamShareObjectDecision::RejectDeviceLocal,
    }
}

pub fn default_team_share_field_rules() -> Vec<TeamShareFieldRule> {
    use TeamShareField::*;
    use TeamShareFieldDecision::*;

    vec![
        field_rule(ProfileId, Share, "share.profile_id"),
        field_rule(ProfileName, Share, "share.profile_name"),
        field_rule(PluginId, Share, "share.plugin_id"),
        field_rule(DisplayName, Share, "share.display_name"),
        field_rule(
            ProfileMetadata,
            ShareAfterRedaction,
            "share.profile_metadata.redacted",
        ),
        field_rule(
            DefaultOptions,
            ShareAfterRedaction,
            "share.default_options.redacted",
        ),
        field_rule(
            CredentialReferenceId,
            Share,
            "share.credential_reference_id",
        ),
        field_rule(
            CredentialReferenceClass,
            Share,
            "share.credential_reference_class",
        ),
        field_rule(
            CredentialReferenceLabel,
            ShareAfterRedaction,
            "share.credential_reference_label.redacted",
        ),
        field_rule(ProfilePolicy, Share, "share.profile_policy"),
        field_rule(PluginCompatibility, Share, "share.plugin_compatibility"),
        field_rule(
            CredentialMaterial,
            RequireLocalReenrollment,
            "share.credential_material.reenroll_locally",
        ),
        field_rule(MasterPassword, Reject, "share.master_password.reject"),
        field_rule(
            UnwrappedKeyMaterial,
            Reject,
            "share.unwrapped_key_material.reject",
        ),
        field_rule(
            DeviceLocalSyncState,
            Reject,
            "share.device_local_sync_state.reject",
        ),
        field_rule(
            RuntimeSessionState,
            Reject,
            "share.runtime_session_state.reject",
        ),
    ]
}

pub fn team_share_profile_object(
    input: TeamShareProfileObjectInput,
) -> Result<TeamShareProfileObject, TeamShareError> {
    validate_shareable_sync_object(SyncObjectKind::Profile, &input.profile_object_id)?;

    if let Some(policy_ref) = input.profile.policy_ref.as_deref() {
        let Some(policy) = input.policy.as_ref() else {
            return Err(TeamShareError::ObjectReferenceMismatch {
                field: "profile.policy_ref",
            });
        };
        if policy.object_id != policy_ref {
            return Err(TeamShareError::ObjectReferenceMismatch {
                field: "profile.policy_ref",
            });
        }
    }

    if let Some(compatibility_ref) = input.profile.compatibility_ref.as_deref() {
        let Some(plugin_compatibility) = input.plugin_compatibility.as_ref() else {
            return Err(TeamShareError::ObjectReferenceMismatch {
                field: "profile.compatibility_ref",
            });
        };
        if plugin_compatibility.object_id != compatibility_ref {
            return Err(TeamShareError::ObjectReferenceMismatch {
                field: "profile.compatibility_ref",
            });
        }
    }

    if let Some(policy) = input.policy.as_ref() {
        validate_shareable_sync_object(SyncObjectKind::ProfilePolicy, &policy.object_id)?;
        if policy.payload.profile_object_id != input.profile_object_id {
            return Err(TeamShareError::ObjectReferenceMismatch {
                field: "policy.profile_object_id",
            });
        }
    }

    if let Some(plugin_compatibility) = input.plugin_compatibility.as_ref() {
        validate_shareable_sync_object(
            SyncObjectKind::PluginCompatibility,
            &plugin_compatibility.object_id,
        )?;
        if plugin_compatibility.payload.plugin_id != input.profile.profile.plugin_id {
            return Err(TeamShareError::ObjectReferenceMismatch {
                field: "plugin_compatibility.plugin_id",
            });
        }
    }

    let mut credential_requirements = Vec::new();
    let mut redaction = input.profile.redaction;
    for credential_ref in &input.credential_refs {
        validate_shareable_sync_object(SyncObjectKind::CredentialRef, &credential_ref.object_id)?;
        if credential_ref.payload.profile_object_id != input.profile_object_id {
            return Err(TeamShareError::ObjectReferenceMismatch {
                field: "credential_ref.profile_object_id",
            });
        }
        redaction = combine_redaction(redaction, credential_ref.payload.redaction);
        credential_requirements.push(TeamShareCredentialRequirement {
            profile_object_id: input.profile_object_id.clone(),
            credential_ref_object_id: credential_ref.object_id.clone(),
            credential_ref_id: credential_ref.payload.credential_ref.id.clone(),
            class: credential_ref.payload.credential_ref.class.clone(),
            label: credential_ref.payload.credential_ref.label.clone(),
            decision: TeamShareFieldDecision::RequireLocalReenrollment,
            reason_code: "share.credential_material.reenroll_locally".into(),
        });
    }

    if !credential_requirements.is_empty() {
        redaction = combine_redaction(redaction, RedactionStatus::Withheld);
    }

    let object = TeamShareProfileObject {
        profile_object_id: input.profile_object_id,
        profile: input.profile,
        policy: input.policy,
        plugin_compatibility: input.plugin_compatibility,
        credential_refs: input.credential_refs,
        credential_requirements,
        redaction,
    };
    validate_team_share_profile_object(&object)?;
    Ok(object)
}

pub fn team_share_collection_manifest(
    collection: &TeamShareCollection,
) -> Result<TeamShareCollectionManifest, TeamShareError> {
    validate_team_share_opaque_id(TeamShareOpaqueIdKind::Collection, &collection.collection_id)?;
    validate_team_share_actor(&collection.updated_by)?;
    validate_team_share_member(&collection.owner)?;
    for member in &collection.members {
        validate_team_share_member(member)?;
    }

    let mut object_counts = BTreeMap::new();
    for profile in &collection.profiles {
        validate_team_share_profile_object(profile)?;
        count_object(&mut object_counts, SyncObjectKind::Profile);
        for credential_ref in &profile.credential_refs {
            validate_shareable_sync_object(
                SyncObjectKind::CredentialRef,
                &credential_ref.object_id,
            )?;
            count_object(&mut object_counts, SyncObjectKind::CredentialRef);
        }
        if profile.policy.is_some() {
            count_object(&mut object_counts, SyncObjectKind::ProfilePolicy);
        }
        if profile.plugin_compatibility.is_some() {
            count_object(&mut object_counts, SyncObjectKind::PluginCompatibility);
        }
    }

    Ok(TeamShareCollectionManifest {
        schema_version: TEAM_SHARE_SCHEMA_VERSION,
        collection_id: collection.collection_id.clone(),
        updated_at: collection.updated_at,
        updated_by: collection.updated_by.clone(),
        member_count: collection.member_count(),
        profile_count: collection.profiles.len() as u64,
        object_counts,
        redaction: collection.redaction,
    })
}

pub fn plan_team_share_import(
    collection: &TeamShareCollection,
    context: &TeamShareImportContext,
) -> TeamShareImportPlan {
    let mut actions = Vec::new();
    let mut blocked = Vec::new();

    if validate_team_share_opaque_id(TeamShareOpaqueIdKind::Collection, &collection.collection_id)
        .is_err()
    {
        blocked.push(TeamShareImportBlock {
            profile_object_id: None,
            reason: TeamShareImportBlockReason::InvalidCollectionId,
            redaction: RedactionStatus::FailedClosed,
        });
    }

    for profile in &collection.profiles {
        if let Err(error) = validate_team_share_profile_object(profile) {
            blocked.push(TeamShareImportBlock {
                profile_object_id: Some(profile.profile_object_id.clone()),
                reason: import_block_reason_for_error(&error),
                redaction: RedactionStatus::FailedClosed,
            });
            continue;
        }

        actions.push(TeamShareImportAction {
            profile_object_id: profile.profile_object_id.clone(),
            kind: TeamShareImportActionKind::ImportProfile,
            reason: None,
            redaction: profile.redaction,
        });

        if profile.policy.is_some() {
            actions.push(TeamShareImportAction {
                profile_object_id: profile.profile_object_id.clone(),
                kind: TeamShareImportActionKind::ApplyProfilePolicy,
                reason: None,
                redaction: RedactionStatus::NotRequired,
            });
        }

        let plugin_id = &profile.profile.profile.plugin_id;
        actions.push(TeamShareImportAction {
            profile_object_id: profile.profile_object_id.clone(),
            kind: TeamShareImportActionKind::CheckPluginCompatibility,
            reason: None,
            redaction: RedactionStatus::NotRequired,
        });
        if let Some(installed_version) = context.installed_plugins.get(plugin_id) {
            if let Some(plugin_compatibility) = profile.plugin_compatibility.as_ref()
                && !plugin_version_satisfies_minimum(
                    installed_version,
                    plugin_compatibility.payload.minimum_plugin_version.as_deref(),
                )
            {
                actions.push(TeamShareImportAction {
                    profile_object_id: profile.profile_object_id.clone(),
                    kind: TeamShareImportActionKind::MarkProfileUnavailable,
                    reason: Some(TeamShareImportActionReason::IncompatiblePluginVersion),
                    redaction: RedactionStatus::NotRequired,
                });
            }
        } else {
            actions.push(TeamShareImportAction {
                profile_object_id: profile.profile_object_id.clone(),
                kind: TeamShareImportActionKind::MarkProfileUnavailable,
                reason: Some(TeamShareImportActionReason::MissingPlugin),
                redaction: RedactionStatus::NotRequired,
            });
        }

        for requirement in &profile.credential_requirements {
            let kind = if context
                .enrolled_credential_ref_ids
                .contains(&requirement.credential_ref_id)
            {
                TeamShareImportActionKind::BindLocalCredential
            } else {
                TeamShareImportActionKind::RequireCredentialReenrollment
            };
            actions.push(TeamShareImportAction {
                profile_object_id: profile.profile_object_id.clone(),
                kind,
                reason: Some(if kind == TeamShareImportActionKind::BindLocalCredential {
                    TeamShareImportActionReason::LocalCredentialAvailable
                } else {
                    TeamShareImportActionReason::CredentialReenrollmentRequired
                }),
                redaction: RedactionStatus::Withheld,
            });
        }
    }

    let redaction = if blocked.is_empty() {
        collection.redaction
    } else {
        RedactionStatus::FailedClosed
    };

    TeamShareImportPlan {
        collection_id: collection.collection_id.clone(),
        actions,
        blocked,
        redaction,
    }
}

pub fn create_team_share_invite(
    collection: &TeamShareCollection,
    input: TeamShareInviteInput,
) -> Result<TeamShareInvite, TeamShareError> {
    if input.role == TeamShareMemberRole::Owner {
        return Err(TeamShareError::OwnerInviteNotAllowed);
    }
    if input.collection_id != collection.collection_id {
        return Err(TeamShareError::InviteCollectionMismatch);
    }
    let inviter_role = member_role(collection, &input.invited_by_member_id)
        .ok_or(TeamShareError::MemberNotFound)?;
    if !inviter_role.can_modify_collection() {
        return Err(TeamShareError::InviterNotAuthorized);
    }
    validate_team_share_opaque_id(TeamShareOpaqueIdKind::Invite, &input.invite_id)?;
    validate_team_share_opaque_id(TeamShareOpaqueIdKind::Collection, &input.collection_id)?;
    validate_team_share_opaque_id(TeamShareOpaqueIdKind::Member, &input.invited_by_member_id)?;
    validate_team_share_actor(&input.invited_by)?;
    validate_team_share_opaque_id(
        TeamShareOpaqueIdKind::Principal,
        &input.recipient.opaque_id,
    )?;

    Ok(TeamShareInvite {
        invite_id: input.invite_id,
        collection_id: input.collection_id,
        invited_by_member_id: input.invited_by_member_id,
        invited_by: input.invited_by,
        recipient: input.recipient,
        role: input.role,
        created_at: input.created_at,
        expires_at: input.expires_at,
        status: TeamShareInviteStatus::Pending,
        redaction: RedactionStatus::Withheld,
    })
}

pub fn accept_team_share_invite(
    invite: &TeamShareInvite,
    collection: &TeamShareCollection,
    context: &TeamShareImportContext,
    accepted_by: TeamShareActor,
    accepted_at: DateTime<Utc>,
) -> Result<TeamShareInviteAcceptance, TeamShareError> {
    if invite.status != TeamShareInviteStatus::Pending {
        return Err(TeamShareError::InviteNotPending);
    }
    if invite.collection_id != collection.collection_id {
        return Err(TeamShareError::InviteCollectionMismatch);
    }
    if let Some(expires_at) = invite.expires_at
        && accepted_at > expires_at
    {
        return Err(TeamShareError::InviteExpired { expires_at });
    }
    validate_team_share_actor(&accepted_by)?;
    if accepted_by.actor_id != invite.recipient.opaque_id {
        return Err(TeamShareError::InviteRecipientMismatch);
    }

    let import_plan = plan_team_share_import(collection, context);
    let imported_profile_count = import_plan
        .actions
        .iter()
        .filter(|action| action.kind == TeamShareImportActionKind::ImportProfile)
        .count() as u64;
    let unavailable_profile_count = import_plan
        .actions
        .iter()
        .filter(|action| action.kind == TeamShareImportActionKind::MarkProfileUnavailable)
        .count() as u64;
    let credential_reenrollment_count = import_plan
        .actions
        .iter()
        .filter(|action| {
            action.kind == TeamShareImportActionKind::RequireCredentialReenrollment
        })
        .count() as u64;
    let blocked_count = import_plan.blocked.len() as u64;
    let redaction = combine_redaction(invite.redaction, import_plan.redaction);

    Ok(TeamShareInviteAcceptance {
        invite_id: invite.invite_id.clone(),
        collection_id: invite.collection_id.clone(),
        accepted_by,
        accepted_at,
        role: invite.role,
        import_plan,
        imported_profile_count,
        unavailable_profile_count,
        credential_reenrollment_count,
        blocked_count,
        redaction,
    })
}

pub fn revoke_team_share_access(
    collection: &TeamShareCollection,
    input: TeamShareRevocationInput,
) -> Result<TeamShareRevocation, TeamShareError> {
    validate_team_share_actor(&input.revoked_by)?;
    let revoker_role = member_role(collection, &input.revoked_by_member_id)
        .ok_or(TeamShareError::MemberNotFound)?;
    if !revoker_role.can_revoke_access() {
        return Err(TeamShareError::RevokerNotAuthorized);
    }

    match &input.target {
        TeamShareRevocationTarget::Member { member_id } => {
            validate_team_share_opaque_id(TeamShareOpaqueIdKind::Member, member_id)?;
            let target_role =
                member_role(collection, member_id).ok_or(TeamShareError::MemberNotFound)?;
            if target_role == TeamShareMemberRole::Owner {
                return Err(TeamShareError::OwnerCannotBeRevoked);
            }
        }
        TeamShareRevocationTarget::Invite { invite_id } => {
            validate_team_share_opaque_id(TeamShareOpaqueIdKind::Invite, invite_id)?;
        }
    }

    Ok(TeamShareRevocation {
        collection_id: collection.collection_id.clone(),
        target: input.target,
        revoked_by_member_id: input.revoked_by_member_id,
        revoked_by: input.revoked_by,
        revoked_at: input.revoked_at,
        reason: input.reason,
        redaction: RedactionStatus::Withheld,
    })
}

pub fn team_share_invite_created_activity(invite: &TeamShareInvite) -> TeamShareActivityRecord {
    TeamShareActivityRecord {
        operation: TeamShareActivityOperation::InviteCreated,
        collection_id: invite.collection_id.clone(),
        occurred_at: invite.created_at,
        actor: invite.invited_by.clone(),
        invite_id: Some(invite.invite_id.clone()),
        member_id: Some(invite.invited_by_member_id.clone()),
        revocation_target: None,
        profile_count: 0,
        unavailable_profile_count: 0,
        credential_reenrollment_count: 0,
        blocked_count: 0,
        redaction: invite.redaction,
    }
}

pub fn team_share_acceptance_activities(
    acceptance: &TeamShareInviteAcceptance,
) -> Vec<TeamShareActivityRecord> {
    let mut activities = vec![
        TeamShareActivityRecord {
            operation: TeamShareActivityOperation::InviteAccepted,
            collection_id: acceptance.collection_id.clone(),
            occurred_at: acceptance.accepted_at,
            actor: acceptance.accepted_by.clone(),
            invite_id: Some(acceptance.invite_id.clone()),
            member_id: None,
            revocation_target: None,
            profile_count: acceptance.imported_profile_count,
            unavailable_profile_count: acceptance.unavailable_profile_count,
            credential_reenrollment_count: acceptance.credential_reenrollment_count,
            blocked_count: acceptance.blocked_count,
            redaction: acceptance.redaction,
        },
        TeamShareActivityRecord {
            operation: if acceptance.blocked_count == 0 {
                TeamShareActivityOperation::ImportPlanned
            } else {
                TeamShareActivityOperation::ImportBlocked
            },
            collection_id: acceptance.collection_id.clone(),
            occurred_at: acceptance.accepted_at,
            actor: acceptance.accepted_by.clone(),
            invite_id: Some(acceptance.invite_id.clone()),
            member_id: None,
            revocation_target: None,
            profile_count: acceptance.imported_profile_count,
            unavailable_profile_count: acceptance.unavailable_profile_count,
            credential_reenrollment_count: acceptance.credential_reenrollment_count,
            blocked_count: acceptance.blocked_count,
            redaction: acceptance.import_plan.redaction,
        },
    ];

    if acceptance.credential_reenrollment_count > 0 {
        activities.push(TeamShareActivityRecord {
            operation: TeamShareActivityOperation::CredentialReenrollmentRequired,
            collection_id: acceptance.collection_id.clone(),
            occurred_at: acceptance.accepted_at,
            actor: acceptance.accepted_by.clone(),
            invite_id: Some(acceptance.invite_id.clone()),
            member_id: None,
            revocation_target: None,
            profile_count: acceptance.imported_profile_count,
            unavailable_profile_count: acceptance.unavailable_profile_count,
            credential_reenrollment_count: acceptance.credential_reenrollment_count,
            blocked_count: acceptance.blocked_count,
            redaction: RedactionStatus::Withheld,
        });
    }

    activities
}

pub fn team_share_revocation_activity(
    revocation: &TeamShareRevocation,
) -> TeamShareActivityRecord {
    let (invite_id, member_id) = match &revocation.target {
        TeamShareRevocationTarget::Invite { invite_id } => (Some(invite_id.clone()), None),
        TeamShareRevocationTarget::Member { member_id } => (None, Some(member_id.clone())),
    };

    TeamShareActivityRecord {
        operation: TeamShareActivityOperation::AccessRevoked,
        collection_id: revocation.collection_id.clone(),
        occurred_at: revocation.revoked_at,
        actor: revocation.revoked_by.clone(),
        invite_id,
        member_id,
        revocation_target: Some(revocation.target.clone()),
        profile_count: 0,
        unavailable_profile_count: 0,
        credential_reenrollment_count: 0,
        blocked_count: 0,
        redaction: revocation.redaction,
    }
}

pub fn team_share_activity_metadata(activity: &TeamShareActivityRecord) -> Value {
    json!({
        "collection_id": &activity.collection_id,
        "invite_id": &activity.invite_id,
        "member_id": &activity.member_id,
        "revocation_target": &activity.revocation_target,
        "profile_count": activity.profile_count,
        "unavailable_profile_count": activity.unavailable_profile_count,
        "credential_reenrollment_count": activity.credential_reenrollment_count,
        "blocked_count": activity.blocked_count,
        "redaction": activity.redaction,
    })
}

pub fn team_share_activity_audit_event(
    activity: &TeamShareActivityRecord,
    status: AuditEventStatus,
) -> AuditEvent {
    let mut event = AuditEvent::new(activity.operation.audit_operation(), status);
    event.timestamp = activity.occurred_at;
    event.actor = ActorRef {
        id: activity.actor.actor_id.clone(),
        actor_type: activity.actor.actor_type,
    };
    event.metadata = team_share_activity_metadata(activity);
    event.redaction = activity.redaction;
    event
}

pub fn validate_team_share_opaque_id(
    kind: TeamShareOpaqueIdKind,
    opaque_id: &str,
) -> Result<(), TeamShareError> {
    let expected_prefix = match kind {
        TeamShareOpaqueIdKind::Collection => TEAM_SHARE_COLLECTION_ID_PREFIX,
        TeamShareOpaqueIdKind::Invite => TEAM_SHARE_INVITE_ID_PREFIX,
        TeamShareOpaqueIdKind::Member => TEAM_SHARE_MEMBER_ID_PREFIX,
        TeamShareOpaqueIdKind::Principal => "principal_",
    };
    let Some(body) = opaque_id.strip_prefix(expected_prefix) else {
        return Err(TeamShareError::InvalidOpaqueIdPrefix {
            kind,
            expected_prefix,
        });
    };
    if body.is_empty() {
        return Err(TeamShareError::EmptyOpaqueIdBody);
    }
    for ch in body.chars() {
        if !ch.is_ascii_alphanumeric() && ch != '_' && ch != '-' {
            return Err(TeamShareError::InvalidOpaqueIdCharacter(ch));
        }
    }
    Ok(())
}

pub fn validate_shareable_sync_object(
    kind: SyncObjectKind,
    object_id: &str,
) -> Result<(), TeamShareError> {
    let decision = team_share_object_decision(kind);
    if decision != TeamShareObjectDecision::Share {
        return Err(TeamShareError::NonShareableObjectKind { kind, decision });
    }
    validate_sync_object_id(kind, object_id).map_err(|source| TeamShareError::InvalidSyncObject {
        object_kind: kind,
        source,
    })
}

pub fn validate_team_share_profile_object(
    object: &TeamShareProfileObject,
) -> Result<(), TeamShareError> {
    validate_shareable_sync_object(SyncObjectKind::Profile, &object.profile_object_id)?;

    match (object.profile.policy_ref.as_deref(), object.policy.as_ref()) {
        (Some(policy_ref), Some(policy)) if policy.object_id == policy_ref => {}
        (None, None) => {}
        _ => {
            return Err(TeamShareError::ObjectReferenceMismatch {
                field: "profile.policy_ref",
            });
        }
    }

    match (
        object.profile.compatibility_ref.as_deref(),
        object.plugin_compatibility.as_ref(),
    ) {
        (Some(compatibility_ref), Some(plugin_compatibility))
            if plugin_compatibility.object_id == compatibility_ref => {}
        (None, None) => {}
        _ => {
            return Err(TeamShareError::ObjectReferenceMismatch {
                field: "profile.compatibility_ref",
            });
        }
    }

    if let Some(policy) = object.policy.as_ref() {
        validate_shareable_sync_object(SyncObjectKind::ProfilePolicy, &policy.object_id)?;
        if policy.payload.profile_object_id != object.profile_object_id {
            return Err(TeamShareError::ObjectReferenceMismatch {
                field: "policy.profile_object_id",
            });
        }
    }

    if let Some(plugin_compatibility) = object.plugin_compatibility.as_ref() {
        validate_shareable_sync_object(
            SyncObjectKind::PluginCompatibility,
            &plugin_compatibility.object_id,
        )?;
        if plugin_compatibility.payload.plugin_id != object.profile.profile.plugin_id {
            return Err(TeamShareError::ObjectReferenceMismatch {
                field: "plugin_compatibility.plugin_id",
            });
        }
    }

    let expected_credential_refs = object
        .profile
        .profile
        .credential_ref_ids
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let mut actual_credential_refs = BTreeSet::new();
    for credential_ref in &object.credential_refs {
        validate_shareable_sync_object(SyncObjectKind::CredentialRef, &credential_ref.object_id)?;
        if credential_ref.payload.profile_object_id != object.profile_object_id {
            return Err(TeamShareError::ObjectReferenceMismatch {
                field: "credential_ref.profile_object_id",
            });
        }
        actual_credential_refs.insert(credential_ref.payload.credential_ref.id.clone());
    }
    if expected_credential_refs != actual_credential_refs {
        return Err(TeamShareError::ObjectReferenceMismatch {
            field: "profile.credential_ref_ids",
        });
    }

    Ok(())
}

fn field_rule(
    field: TeamShareField,
    decision: TeamShareFieldDecision,
    reason_code: &str,
) -> TeamShareFieldRule {
    TeamShareFieldRule {
        field,
        decision,
        reason_code: reason_code.into(),
    }
}

fn count_object(counts: &mut BTreeMap<String, u64>, kind: SyncObjectKind) {
    *counts.entry(kind.manifest_key().to_string()).or_insert(0) += 1;
}

fn combine_redaction(left: RedactionStatus, right: RedactionStatus) -> RedactionStatus {
    use RedactionStatus::*;

    match (left, right) {
        (FailedClosed, _) | (_, FailedClosed) => FailedClosed,
        (Withheld, _) | (_, Withheld) => Withheld,
        (Applied, _) | (_, Applied) => Applied,
        (NotRequired, NotRequired) => NotRequired,
    }
}

fn validate_team_share_member(member: &TeamShareMember) -> Result<(), TeamShareError> {
    validate_team_share_opaque_id(TeamShareOpaqueIdKind::Member, &member.member_id)?;
    validate_team_share_opaque_id(
        TeamShareOpaqueIdKind::Principal,
        &member.principal.opaque_id,
    )
}

fn validate_team_share_actor(actor: &TeamShareActor) -> Result<(), TeamShareError> {
    validate_team_share_opaque_id(TeamShareOpaqueIdKind::Principal, &actor.actor_id)
}

fn member_role(
    collection: &TeamShareCollection,
    member_id: &str,
) -> Option<TeamShareMemberRole> {
    if collection.owner.member_id == member_id {
        return Some(collection.owner.role);
    }
    collection
        .members
        .iter()
        .find(|member| member.member_id == member_id)
        .map(|member| member.role)
}

fn plugin_version_satisfies_minimum(installed: &str, minimum: Option<&str>) -> bool {
    let Some(minimum) = minimum else {
        return true;
    };
    let Some(installed_segments) = parse_numeric_version(installed) else {
        return false;
    };
    let Some(minimum_segments) = parse_numeric_version(minimum) else {
        return false;
    };
    compare_numeric_versions(&installed_segments, &minimum_segments) != std::cmp::Ordering::Less
}

fn parse_numeric_version(value: &str) -> Option<Vec<u64>> {
    let core = value.split(['-', '+']).next().unwrap_or(value);
    let segments = core
        .split('.')
        .map(str::parse::<u64>)
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    (!segments.is_empty()).then_some(segments)
}

fn compare_numeric_versions(left: &[u64], right: &[u64]) -> std::cmp::Ordering {
    let len = left.len().max(right.len());
    for index in 0..len {
        let left_segment = left.get(index).copied().unwrap_or_default();
        let right_segment = right.get(index).copied().unwrap_or_default();
        match left_segment.cmp(&right_segment) {
            std::cmp::Ordering::Equal => {}
            ordering => return ordering,
        }
    }
    std::cmp::Ordering::Equal
}

fn import_block_reason_for_error(error: &TeamShareError) -> TeamShareImportBlockReason {
    match error {
        TeamShareError::NonShareableObjectKind { .. } => {
            TeamShareImportBlockReason::NonShareableObjectKind
        }
        TeamShareError::ObjectReferenceMismatch { field }
            if field.contains("policy") || *field == "profile.policy_ref" =>
        {
            TeamShareImportBlockReason::PolicyReferenceMismatch
        }
        TeamShareError::ObjectReferenceMismatch { field }
            if field.contains("credential_ref") || *field == "profile.credential_ref_ids" =>
        {
            TeamShareImportBlockReason::CredentialReferenceMismatch
        }
        _ => TeamShareImportBlockReason::InvalidSharedObject,
    }
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};
    use serde_json::{json, Value};

    use super::*;
    use crate::capability::{ConnectionProfile, ConnectionProfilePolicy, CredentialRef};
    use crate::object_sync::{
        sync_credential_ref_payload, sync_profile_payload, sync_profile_policy_payload,
    };

    fn actor() -> TeamShareActor {
        actor_for("principal_01JZ8V1E0YH6S5J4M3K2N1P0Q9")
    }

    fn actor_for(id: &str) -> TeamShareActor {
        TeamShareActor::new(ActorRef {
            id: id.into(),
            actor_type: ActorType::Human,
        })
    }

    fn owner() -> TeamShareMember {
        TeamShareMember {
            member_id: "share_member_01JZ8V1E0YH6S5J4M3K2N1P0Q9".into(),
            principal: TeamSharePrincipal {
                kind: TeamSharePrincipalKind::User,
                opaque_id: "principal_01JZ8V1E0YH6S5J4M3K2N1P0Q9".into(),
            },
            role: TeamShareMemberRole::Owner,
            added_at: Utc.with_ymd_and_hms(2026, 7, 4, 18, 0, 0).unwrap(),
            added_by: actor(),
            redaction: RedactionStatus::Withheld,
        }
    }

    fn consumer_member() -> TeamShareMember {
        TeamShareMember {
            member_id: "share_member_01JZ8V1E0YH6S5J4M3K2N1P0RA".into(),
            principal: TeamSharePrincipal {
                kind: TeamSharePrincipalKind::User,
                opaque_id: "principal_01JZ8V1E0YH6S5J4M3K2N1P0RA".into(),
            },
            role: TeamShareMemberRole::Consumer,
            added_at: Utc.with_ymd_and_hms(2026, 7, 4, 18, 10, 0).unwrap(),
            added_by: actor(),
            redaction: RedactionStatus::Withheld,
        }
    }

    fn invite_for(collection: &TeamShareCollection) -> TeamShareInvite {
        create_team_share_invite(
            collection,
            TeamShareInviteInput {
                invite_id: "share_invite_01JZ8V1E0YH6S5J4M3K2N1P0Q9".into(),
                collection_id: collection.collection_id.clone(),
                invited_by_member_id: collection.owner.member_id.clone(),
                invited_by: actor(),
                recipient: TeamSharePrincipal {
                    kind: TeamSharePrincipalKind::User,
                    opaque_id: "principal_01JZ8V1E0YH6S5J4M3K2N1P0QB".into(),
                },
                role: TeamShareMemberRole::Consumer,
                created_at: Utc.with_ymd_and_hms(2026, 7, 4, 18, 20, 0).unwrap(),
                expires_at: Some(Utc.with_ymd_and_hms(2026, 7, 4, 19, 20, 0).unwrap()),
            },
        )
        .expect("invite")
    }

    fn profile() -> ConnectionProfile {
        ConnectionProfile {
            id: "profile:local-prod".into(),
            name: "prod-db".into(),
            plugin_id: "mysql".into(),
            display_name: Some("Production DB".into()),
            metadata: json!({
                "host": "db.internal.example",
                "legacy_connection_key": "mysql::prod-db"
            }),
            default_options: json!({
                "url": "mysql://app_user:super-secret@db.internal.example/prod",
                "limit": 100
            }),
            credential_refs: vec![CredentialRef {
                id: "credential:prod-db:password".into(),
                class: CredentialClass::Password,
                label: Some("primary password".into()),
            }],
            policy: ConnectionProfilePolicy {
                allowed_capabilities: vec!["query".into()],
                denied_capabilities: vec!["exec".into()],
                allow_destructive_by_default: false,
            },
        }
    }

    fn shared_profile_object() -> TeamShareProfileObject {
        let profile = profile();
        let profile_payload = sync_profile_payload(
            &profile,
            Some("sync_policy_01JZ8V1E0YH6S5J4M3K2N1P0Q9".into()),
            Some("sync_plugin_01JZ8V1E0YH6S5J4M3K2N1P0Q9".into()),
        );
        let credential_ref = sync_credential_ref_payload(
            "sync_profile_01JZ8V1E0YH6S5J4M3K2N1P0Q9",
            &profile.credential_refs[0],
        );

        team_share_profile_object(TeamShareProfileObjectInput {
            profile_object_id: "sync_profile_01JZ8V1E0YH6S5J4M3K2N1P0Q9".into(),
            profile: profile_payload,
            policy: Some(TeamShareProfilePolicyObject {
                object_id: "sync_policy_01JZ8V1E0YH6S5J4M3K2N1P0Q9".into(),
                payload: sync_profile_policy_payload(
                    "sync_profile_01JZ8V1E0YH6S5J4M3K2N1P0Q9",
                    &profile.policy,
                ),
            }),
            plugin_compatibility: Some(TeamSharePluginCompatibilityObject {
                object_id: "sync_plugin_01JZ8V1E0YH6S5J4M3K2N1P0Q9".into(),
                payload: SyncPluginCompatibilityPayload {
                    payload_version: OBJECT_SYNC_PAYLOAD_VERSION,
                    plugin_id: "mysql".into(),
                    profile_schema_id: "mysql.profile.v1".into(),
                    profile_schema_version: 1,
                    minimum_plugin_version: Some("0.1.0".into()),
                    capability_contracts: vec!["sql.query.v1".into()],
                },
            }),
            credential_refs: vec![TeamShareCredentialRefObject {
                object_id: "sync_credref_01JZ8V1E0YH6S5J4M3K2N1P0Q9".into(),
                payload: credential_ref,
            }],
        })
        .expect("shareable profile object")
    }

    fn collection() -> TeamShareCollection {
        let mut collection = TeamShareCollection::new(
            "share_collection_01JZ8V1E0YH6S5J4M3K2N1P0Q9",
            owner(),
            Utc.with_ymd_and_hms(2026, 7, 4, 18, 0, 0).unwrap(),
            actor(),
        )
        .expect("collection");
        collection.display_name = Some("Production database access".into());
        collection.profiles.push(shared_profile_object());
        collection
    }

    #[test]
    fn field_rules_reject_secret_and_device_local_state() {
        let rules = default_team_share_field_rules();
        let decision_for = |field| {
            rules
                .iter()
                .find(|rule| rule.field == field)
                .map(|rule| rule.decision)
        };

        assert_eq!(
            decision_for(TeamShareField::CredentialMaterial),
            Some(TeamShareFieldDecision::RequireLocalReenrollment)
        );
        assert_eq!(
            decision_for(TeamShareField::MasterPassword),
            Some(TeamShareFieldDecision::Reject)
        );
        assert_eq!(
            decision_for(TeamShareField::DeviceLocalSyncState),
            Some(TeamShareFieldDecision::Reject)
        );
    }

    #[test]
    fn object_policy_requires_reenrollment_instead_of_sharing_credential_records() {
        assert_eq!(
            team_share_object_decision(SyncObjectKind::Profile),
            TeamShareObjectDecision::Share
        );
        assert_eq!(
            team_share_object_decision(SyncObjectKind::CredentialRecord),
            TeamShareObjectDecision::RequireLocalCredentialReenrollment
        );
        assert_eq!(
            team_share_object_decision(SyncObjectKind::AppPreference),
            TeamShareObjectDecision::RejectDeviceLocal
        );
        assert!(matches!(
            validate_shareable_sync_object(
                SyncObjectKind::CredentialRecord,
                "sync_credrec_01JZ8V1E0YH6S5J4M3K2N1P0Q9"
            ),
            Err(TeamShareError::NonShareableObjectKind { .. })
        ));
    }

    #[test]
    fn profile_object_turns_credential_refs_into_reenrollment_requirements() {
        let object = shared_profile_object();
        let encoded = serde_json::to_string(&object).expect("serialize shared object");

        assert_eq!(object.redaction, RedactionStatus::Withheld);
        assert_eq!(object.credential_requirements.len(), 1);
        assert_eq!(
            object.credential_requirements[0].decision,
            TeamShareFieldDecision::RequireLocalReenrollment
        );
        assert!(!encoded.contains("super-secret"));
        assert!(!encoded.contains("db.internal.example"));
        assert!(!encoded.contains("mysql::prod-db"));
        assert!(!encoded.contains("credential_record"));
        assert!(!encoded.contains("sync_credrec"));
        assert!(!encoded.contains("sync.toml"));
    }

    #[test]
    fn profile_object_fails_closed_on_mismatched_policy_reference() {
        let profile = profile();
        let profile_payload = sync_profile_payload(
            &profile,
            Some("sync_policy_01JZ8V1E0YH6S5J4M3K2N1P0Q9".into()),
            None,
        );

        let error = team_share_profile_object(TeamShareProfileObjectInput {
            profile_object_id: "sync_profile_01JZ8V1E0YH6S5J4M3K2N1P0Q9".into(),
            profile: profile_payload,
            policy: Some(TeamShareProfilePolicyObject {
                object_id: "sync_policy_99JZ8V1E0YH6S5J4M3K2N1P0Q9".into(),
                payload: sync_profile_policy_payload(
                    "sync_profile_01JZ8V1E0YH6S5J4M3K2N1P0Q9",
                    &profile.policy,
                ),
            }),
            plugin_compatibility: None,
            credential_refs: Vec::new(),
        })
        .unwrap_err();

        assert!(matches!(
            error,
            TeamShareError::ObjectReferenceMismatch {
                field: "profile.policy_ref"
            }
        ));
    }

    #[test]
    fn manifest_exposes_only_opaque_collection_metadata() {
        let collection = collection();
        let manifest = team_share_collection_manifest(&collection).expect("manifest");
        let encoded = serde_json::to_string(&manifest).expect("serialize manifest");

        assert_eq!(manifest.profile_count, 1);
        assert_eq!(manifest.member_count, 1);
        assert_eq!(manifest.object_counts.get("profile"), Some(&1));
        assert_eq!(manifest.object_counts.get("credential_ref"), Some(&1));
        assert!(encoded.contains("share_collection_01JZ8V1E0YH6S5J4M3K2N1P0Q9"));
        assert!(!encoded.contains("Production database access"));
        assert!(!encoded.contains("prod-db"));
        assert!(!encoded.contains("mysql"));
        assert!(!encoded.contains("db.internal.example"));
    }

    #[test]
    fn import_plan_requires_local_credentials_and_marks_missing_plugins_unavailable() {
        let collection = collection();
        let plan = plan_team_share_import(&collection, &TeamShareImportContext::default());
        let kinds = plan
            .actions
            .iter()
            .map(|action| action.kind)
            .collect::<Vec<_>>();

        assert!(plan.requires_user_action());
        assert!(plan.blocked.is_empty());
        assert!(kinds.contains(&TeamShareImportActionKind::ImportProfile));
        assert!(kinds.contains(&TeamShareImportActionKind::CheckPluginCompatibility));
        assert!(kinds.contains(&TeamShareImportActionKind::MarkProfileUnavailable));
        assert!(kinds.contains(&TeamShareImportActionKind::RequireCredentialReenrollment));
        assert!(plan.actions.iter().any(|action| {
            action.kind == TeamShareImportActionKind::MarkProfileUnavailable
                && action.reason == Some(TeamShareImportActionReason::MissingPlugin)
        }));
        assert_eq!(plan.redaction, RedactionStatus::Withheld);
    }

    #[test]
    fn import_plan_fails_closed_on_forged_credential_ref_links() {
        let mut collection = collection();
        collection.profiles[0].credential_refs[0].payload.profile_object_id =
            "sync_profile_99JZ8V1E0YH6S5J4M3K2N1P0Q9".into();

        let plan = plan_team_share_import(&collection, &TeamShareImportContext::default());

        assert!(plan.actions.is_empty());
        assert_eq!(plan.redaction, RedactionStatus::FailedClosed);
        assert_eq!(plan.blocked.len(), 1);
        assert_eq!(
            plan.blocked[0].reason,
            TeamShareImportBlockReason::CredentialReferenceMismatch
        );
    }

    #[test]
    fn import_plan_binds_existing_local_credential_refs() {
        let collection = collection();
        let mut context = TeamShareImportContext::default();
        context
            .installed_plugins
            .insert("mysql".into(), "0.1.0".into());
        context
            .enrolled_credential_ref_ids
            .insert("credential:prod-db:password".into());

        let plan = plan_team_share_import(&collection, &context);
        let kinds = plan
            .actions
            .iter()
            .map(|action| action.kind)
            .collect::<Vec<_>>();

        assert!(!kinds.contains(&TeamShareImportActionKind::MarkProfileUnavailable));
        assert!(!kinds.contains(&TeamShareImportActionKind::RequireCredentialReenrollment));
        assert!(kinds.contains(&TeamShareImportActionKind::BindLocalCredential));
    }

    #[test]
    fn import_plan_marks_incompatible_plugin_versions_unavailable() {
        let collection = collection();
        let mut context = TeamShareImportContext::default();
        context
            .installed_plugins
            .insert("mysql".into(), "0.0.9".into());

        let plan = plan_team_share_import(&collection, &context);

        assert!(plan.actions.iter().any(|action| {
            action.kind == TeamShareImportActionKind::MarkProfileUnavailable
                && action.reason == Some(TeamShareImportActionReason::IncompatiblePluginVersion)
        }));
        assert!(!serde_json::to_string(&plan)
            .expect("serialize plan")
            .contains("db.internal.example"));
    }

    #[test]
    fn invite_acceptance_records_redacted_import_activity() {
        let collection = collection();
        let invite = invite_for(&collection);
        let acceptance = accept_team_share_invite(
            &invite,
            &collection,
            &TeamShareImportContext::default(),
            actor_for("principal_01JZ8V1E0YH6S5J4M3K2N1P0QB"),
            Utc.with_ymd_and_hms(2026, 7, 4, 18, 30, 0).unwrap(),
        )
        .expect("accept invite");
        let activities = team_share_acceptance_activities(&acceptance);
        let audit_events = activities
            .iter()
            .map(|activity| team_share_activity_audit_event(activity, AuditEventStatus::Succeeded))
            .collect::<Vec<_>>();
        let encoded = serde_json::to_string(&audit_events).expect("serialize activity");

        assert_eq!(acceptance.imported_profile_count, 1);
        assert_eq!(acceptance.unavailable_profile_count, 1);
        assert_eq!(acceptance.credential_reenrollment_count, 1);
        assert_eq!(acceptance.blocked_count, 0);
        assert!(activities.iter().any(|activity| {
            activity.operation == TeamShareActivityOperation::CredentialReenrollmentRequired
        }));
        assert!(
            audit_events
                .iter()
                .any(|event| event.operation == AuditOperation::TeamShareInviteAccepted)
        );
        assert!(
            audit_events
                .iter()
                .any(|event| event.operation == AuditOperation::TeamShareImportPlanned)
        );
        assert!(!encoded.contains("prod-db"));
        assert!(!encoded.contains("mysql"));
        assert!(!encoded.contains("db.internal.example"));
        assert!(!encoded.contains("super-secret"));
    }

    #[test]
    fn expired_invite_is_rejected_without_importing() {
        let collection = collection();
        let invite = invite_for(&collection);
        let error = accept_team_share_invite(
            &invite,
            &collection,
            &TeamShareImportContext::default(),
            actor_for("principal_01JZ8V1E0YH6S5J4M3K2N1P0QB"),
            Utc.with_ymd_and_hms(2026, 7, 4, 20, 30, 0).unwrap(),
        )
        .unwrap_err();

        assert!(matches!(error, TeamShareError::InviteExpired { .. }));
    }

    #[test]
    fn revoked_invite_is_rejected_without_importing() {
        let collection = collection();
        let mut invite = invite_for(&collection);
        invite.status = TeamShareInviteStatus::Revoked;

        let error = accept_team_share_invite(
            &invite,
            &collection,
            &TeamShareImportContext::default(),
            actor_for("principal_01JZ8V1E0YH6S5J4M3K2N1P0QB"),
            Utc.with_ymd_and_hms(2026, 7, 4, 18, 30, 0).unwrap(),
        )
        .unwrap_err();

        assert!(matches!(error, TeamShareError::InviteNotPending));
    }

    #[test]
    fn revoke_requires_authorized_member_and_records_safe_activity() {
        let mut collection = collection();
        let consumer = consumer_member();
        collection.members.push(consumer.clone());

        let unauthorized = revoke_team_share_access(
            &collection,
            TeamShareRevocationInput {
                target: TeamShareRevocationTarget::Invite {
                    invite_id: "share_invite_01JZ8V1E0YH6S5J4M3K2N1P0Q9".into(),
                },
                revoked_by_member_id: consumer.member_id.clone(),
                revoked_by: actor_for(&consumer.principal.opaque_id),
                revoked_at: Utc.with_ymd_and_hms(2026, 7, 4, 18, 35, 0).unwrap(),
                reason: TeamShareRevocationReason::InviteCancelled,
            },
        )
        .unwrap_err();
        assert!(matches!(
            unauthorized,
            TeamShareError::RevokerNotAuthorized
        ));

        let revocation = revoke_team_share_access(
            &collection,
            TeamShareRevocationInput {
                target: TeamShareRevocationTarget::Member {
                    member_id: consumer.member_id.clone(),
                },
                revoked_by_member_id: collection.owner.member_id.clone(),
                revoked_by: actor(),
                revoked_at: Utc.with_ymd_and_hms(2026, 7, 4, 18, 40, 0).unwrap(),
                reason: TeamShareRevocationReason::AccessNoLongerRequired,
            },
        )
        .expect("owner can revoke consumer");
        let activity = team_share_revocation_activity(&revocation);
        let audit_event = team_share_activity_audit_event(&activity, AuditEventStatus::Succeeded);
        let encoded = serde_json::to_string(&audit_event).expect("serialize revocation");

        assert_eq!(activity.operation, TeamShareActivityOperation::AccessRevoked);
        assert_eq!(audit_event.operation, AuditOperation::TeamShareAccessRevoked);
        assert!(encoded.contains(&consumer.member_id));
        assert!(!encoded.contains("prod-db"));
        assert!(!encoded.contains("mysql"));
        assert!(!encoded.contains("db.internal.example"));
        assert!(!encoded.contains("super-secret"));
    }

    #[test]
    fn serialized_collection_does_not_contain_non_shareable_secret_terms() {
        let collection = collection();
        let encoded = serde_json::to_value(&collection).expect("serialize collection");
        let encoded_text = serde_json::to_string(&encoded).expect("collection json");

        assert!(!encoded_text.contains("super-secret"));
        assert!(!encoded_text.contains("mysql://"));
        assert!(!encoded_text.contains("sync_credrec"));
        assert!(!encoded_text.contains("actual-master-password"));
        assert!(!encoded_text.contains("actual-unwrapped-key"));
        assert_eq!(
            encoded["policy"]["schema_version"],
            TEAM_SHARE_SCHEMA_VERSION
        );
        assert!(matches!(encoded, Value::Object(_)));
    }
}
