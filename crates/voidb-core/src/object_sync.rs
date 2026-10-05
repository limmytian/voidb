//! Object-level sync prototype types and safety helpers.
//!
//! The current sync plugin still ships an encrypted full-directory bundle.
//! This module defines the capability-first object boundary that later sync
//! code can use without exposing local files, plaintext secrets, or target
//! system metadata in server-visible fields.

use std::collections::BTreeMap;

use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::prelude::*;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::capability::{
    ActorId, ActorRef, ActorType, ConnectionProfile, ConnectionProfileId, ConnectionProfilePolicy,
    CredentialClass, CredentialRef, CredentialRefId, PluginId, RedactionStatus,
};
use crate::profile_store::{StoredCredentialRecord, StoredCredentialSource};
use crate::redaction::{
    RedactionTarget, collect_redaction_targets, credential_class_for_key,
    is_sensitive_metadata_key, placeholder_for_credential_class, redact_text_with_targets,
};

pub const OBJECT_SYNC_SCHEMA_VERSION: u32 = 1;
pub const OBJECT_SYNC_PAYLOAD_VERSION: u32 = 1;
pub const OBJECT_SYNC_MANIFEST_VERSION: u32 = 1;

pub type SyncObjectId = String;
pub type SyncDeviceId = String;
pub type SyncBatchId = String;
pub type SyncObjectVersion = u64;
pub type SyncServerRevision = u64;

const PROFILE_OBJECT_PREFIX: &str = "sync_profile_";
const CREDENTIAL_REF_OBJECT_PREFIX: &str = "sync_credref_";
const PROFILE_POLICY_OBJECT_PREFIX: &str = "sync_policy_";
const PLUGIN_COMPATIBILITY_OBJECT_PREFIX: &str = "sync_plugin_";
const CREDENTIAL_RECORD_OBJECT_PREFIX: &str = "sync_credrec_";
const APP_PREFERENCE_OBJECT_PREFIX: &str = "sync_pref_";
const LOCAL_IDENTIFIER_PLACEHOLDER: &str = "<redacted:local_identifier>";
const CREDENTIAL_LABEL_PLACEHOLDER: &str = "<redacted:credential_label>";
const CREDENTIAL_RECORD_ALGORITHM: &str = "aes-256-gcm";
const CREDENTIAL_RECORD_KEY_WRAP: &str = "sync-dek.v1";
const CREDENTIAL_RECORD_AAD_CONTEXT: &str = "voidb.object_sync.credential_record.v1";
const SYNC_DEK_LEN: usize = 32;
const AES_GCM_NONCE_LEN: usize = 12;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncObjectKind {
    Profile,
    CredentialRef,
    ProfilePolicy,
    PluginCompatibility,
    CredentialRecord,
    AppPreference,
}

impl SyncObjectKind {
    pub fn object_id_prefix(self) -> &'static str {
        match self {
            Self::Profile => PROFILE_OBJECT_PREFIX,
            Self::CredentialRef => CREDENTIAL_REF_OBJECT_PREFIX,
            Self::ProfilePolicy => PROFILE_POLICY_OBJECT_PREFIX,
            Self::PluginCompatibility => PLUGIN_COMPATIBILITY_OBJECT_PREFIX,
            Self::CredentialRecord => CREDENTIAL_RECORD_OBJECT_PREFIX,
            Self::AppPreference => APP_PREFERENCE_OBJECT_PREFIX,
        }
    }

    pub fn manifest_key(self) -> &'static str {
        match self {
            Self::Profile => "profile",
            Self::CredentialRef => "credential_ref",
            Self::ProfilePolicy => "profile_policy",
            Self::PluginCompatibility => "plugin_compatibility",
            Self::CredentialRecord => "credential_record",
            Self::AppPreference => "app_preference",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ObjectSyncError {
    #[error("sync object id for {kind:?} must start with '{expected_prefix}'")]
    InvalidObjectIdPrefix {
        kind: SyncObjectKind,
        expected_prefix: &'static str,
    },

    #[error("sync object id must contain opaque id characters after its prefix")]
    EmptyObjectIdBody,

    #[error("sync object id contains a non-opaque character: '{0}'")]
    InvalidObjectIdCharacter(char),

    #[error("sync payload hash must use a sha256: prefix")]
    InvalidPayloadHash,

    #[error("sync ciphertext must not be empty")]
    EmptyCiphertext,

    #[error("credential record sync DEK must be 32 bytes, got {actual}")]
    InvalidCredentialRecordDekLength { actual: usize },

    #[error("credential record payload could not be serialized")]
    CredentialRecordPayloadSerialize,

    #[error("credential record payload could not be decoded")]
    CredentialRecordPayloadDeserialize,

    #[error("credential record encryption failed")]
    CredentialRecordEncrypt,

    #[error("credential record decryption failed")]
    CredentialRecordDecrypt,

    #[error("credential record ciphertext or nonce is not valid base64")]
    CredentialRecordInvalidBase64,

    #[error("credential record nonce must decode to 12 bytes")]
    InvalidCredentialRecordNonce,

    #[error("credential record associated data does not match the envelope")]
    CredentialRecordAadMismatch,

    #[error("credential record encrypted payload hash does not match ciphertext")]
    CredentialRecordPayloadHashMismatch,

    #[error("credential record encryption metadata is unsupported")]
    UnsupportedCredentialRecordEncryption,

    #[error("credential record decrypted payload does not match the envelope")]
    CredentialRecordPayloadMismatch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncObjectActor {
    pub actor_type: ActorType,
    pub actor_id: ActorId,
    pub device_id: SyncDeviceId,
}

impl SyncObjectActor {
    pub fn new(actor: ActorRef, device_id: impl Into<SyncDeviceId>) -> Self {
        Self {
            actor_type: actor.actor_type,
            actor_id: actor.id,
            device_id: device_id.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedSyncPayload {
    pub payload_hash: String,
    pub payload_size: u64,
    pub ciphertext: String,
}

impl EncryptedSyncPayload {
    pub fn new(
        payload_hash: impl Into<String>,
        ciphertext: impl Into<String>,
    ) -> Result<Self, ObjectSyncError> {
        let payload_hash = payload_hash.into();
        let ciphertext = ciphertext.into();
        validate_payload_hash(&payload_hash)?;
        if ciphertext.is_empty() {
            return Err(ObjectSyncError::EmptyCiphertext);
        }

        Ok(Self {
            payload_hash,
            payload_size: ciphertext.len() as u64,
            ciphertext,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncObjectEnvelope {
    pub schema_version: u32,
    pub object_id: SyncObjectId,
    pub object_kind: SyncObjectKind,
    pub object_version: SyncObjectVersion,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_server_revision: Option<SyncServerRevision>,

    pub payload_hash: String,
    pub payload_size: u64,
    pub updated_at: DateTime<Utc>,
    pub updated_by: SyncObjectActor,
    pub deleted: bool,
    pub redaction: RedactionStatus,
    pub ciphertext: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncObjectEnvelopeInput {
    pub object_id: SyncObjectId,
    pub object_kind: SyncObjectKind,
    pub object_version: SyncObjectVersion,
    pub base_server_revision: Option<SyncServerRevision>,
    pub encrypted_payload: EncryptedSyncPayload,
    pub updated_at: DateTime<Utc>,
    pub updated_by: SyncObjectActor,
    pub deleted: bool,
    pub redaction: RedactionStatus,
}

pub fn sync_object_envelope(
    input: SyncObjectEnvelopeInput,
) -> Result<SyncObjectEnvelope, ObjectSyncError> {
    validate_sync_object_id(input.object_kind, &input.object_id)?;

    Ok(SyncObjectEnvelope {
        schema_version: OBJECT_SYNC_SCHEMA_VERSION,
        object_id: input.object_id,
        object_kind: input.object_kind,
        object_version: input.object_version,
        base_server_revision: input.base_server_revision,
        payload_hash: input.encrypted_payload.payload_hash,
        payload_size: input.encrypted_payload.payload_size,
        updated_at: input.updated_at,
        updated_by: input.updated_by,
        deleted: input.deleted,
        redaction: input.redaction,
        ciphertext: input.encrypted_payload.ciphertext,
    })
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncObjectManifest {
    pub manifest_version: u32,
    pub batch_id: SyncBatchId,
    pub created_at: DateTime<Utc>,
    pub device_id: SyncDeviceId,
    pub objects: Vec<SyncObjectManifestEntry>,
    pub counts: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncObjectManifestEntry {
    pub object_id: SyncObjectId,
    pub object_kind: SyncObjectKind,
    pub schema_version: u32,
    pub object_version: SyncObjectVersion,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_server_revision: Option<SyncServerRevision>,

    pub deleted: bool,
    pub payload_hash: String,
    pub payload_size: u64,
    pub redaction: RedactionStatus,
}

pub fn sync_object_manifest(
    batch_id: impl Into<SyncBatchId>,
    device_id: impl Into<SyncDeviceId>,
    created_at: DateTime<Utc>,
    objects: &[SyncObjectEnvelope],
) -> SyncObjectManifest {
    let mut counts = BTreeMap::new();
    let entries = objects
        .iter()
        .map(|object| {
            *counts
                .entry(object.object_kind.manifest_key().to_string())
                .or_insert(0) += 1;

            SyncObjectManifestEntry {
                object_id: object.object_id.clone(),
                object_kind: object.object_kind,
                schema_version: object.schema_version,
                object_version: object.object_version,
                base_server_revision: object.base_server_revision,
                deleted: object.deleted,
                payload_hash: object.payload_hash.clone(),
                payload_size: object.payload_size,
                redaction: object.redaction,
            }
        })
        .collect();

    SyncObjectManifest {
        manifest_version: OBJECT_SYNC_MANIFEST_VERSION,
        batch_id: batch_id.into(),
        created_at,
        device_id: device_id.into(),
        objects: entries,
        counts,
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SyncProfilePayload {
    pub payload_version: u32,
    pub profile: SyncProfileRecord,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_ref: Option<SyncObjectId>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compatibility_ref: Option<SyncObjectId>,

    pub redaction: RedactionStatus,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SyncProfileRecord {
    pub id: ConnectionProfileId,
    #[serde(alias = "alias")]
    pub name: String,
    pub plugin_id: PluginId,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,

    #[serde(default)]
    pub metadata: Value,

    #[serde(default)]
    pub default_options: Value,

    #[serde(default)]
    pub credential_ref_ids: Vec<CredentialRefId>,
}

pub fn sync_profile_payload(
    profile: &ConnectionProfile,
    policy_ref: Option<SyncObjectId>,
    compatibility_ref: Option<SyncObjectId>,
) -> SyncProfilePayload {
    let (metadata, metadata_redaction) = redact_sync_value(&profile.metadata);
    let (default_options, options_redaction) = redact_sync_value(&profile.default_options);
    let redaction = combine_redaction(metadata_redaction, options_redaction);

    SyncProfilePayload {
        payload_version: OBJECT_SYNC_PAYLOAD_VERSION,
        profile: SyncProfileRecord {
            id: profile.id.clone(),
            name: profile.name.clone(),
            plugin_id: profile.plugin_id.clone(),
            display_name: profile.display_name.clone(),
            metadata,
            default_options,
            credential_ref_ids: profile
                .credential_refs
                .iter()
                .map(|credential_ref| credential_ref.id.clone())
                .collect(),
        },
        policy_ref,
        compatibility_ref,
        redaction,
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SyncCredentialRefPayload {
    pub payload_version: u32,
    pub profile_object_id: SyncObjectId,
    pub credential_ref: SyncCredentialRefRecord,
    pub redaction: RedactionStatus,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SyncCredentialRefRecord {
    pub id: CredentialRefId,
    pub class: CredentialClass,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
}

pub fn sync_credential_ref_payload(
    profile_object_id: impl Into<SyncObjectId>,
    credential_ref: &CredentialRef,
) -> SyncCredentialRefPayload {
    let (label, redaction) = redact_credential_ref_label(credential_ref.label.as_deref());

    SyncCredentialRefPayload {
        payload_version: OBJECT_SYNC_PAYLOAD_VERSION,
        profile_object_id: profile_object_id.into(),
        credential_ref: SyncCredentialRefRecord {
            id: credential_ref.id.clone(),
            class: credential_ref.class.clone(),
            label,
            fingerprint: None,
        },
        redaction,
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SyncProfilePolicyPayload {
    pub payload_version: u32,
    pub profile_object_id: SyncObjectId,
    pub policy: ConnectionProfilePolicy,
}

pub fn sync_profile_policy_payload(
    profile_object_id: impl Into<SyncObjectId>,
    policy: &ConnectionProfilePolicy,
) -> SyncProfilePolicyPayload {
    SyncProfilePolicyPayload {
        payload_version: OBJECT_SYNC_PAYLOAD_VERSION,
        profile_object_id: profile_object_id.into(),
        policy: policy.clone(),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncPluginCompatibilityPayload {
    pub payload_version: u32,
    pub plugin_id: PluginId,
    pub profile_schema_id: String,
    pub profile_schema_version: u32,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum_plugin_version: Option<String>,

    #[serde(default)]
    pub capability_contracts: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SyncCredentialRecordPayload {
    pub payload_version: u32,
    pub profile_object_id: SyncObjectId,
    pub credential_ref_object_id: SyncObjectId,
    pub credential: SyncCredentialRecord,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub migration: Option<CredentialRecordMigration>,

    pub redaction: RedactionStatus,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SyncCredentialRecord {
    pub profile_id: ConnectionProfileId,
    pub credential_ref_id: CredentialRefId,
    pub plugin_id: PluginId,
    pub class: CredentialClass,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,

    pub created_at: DateTime<Utc>,
    pub material: CredentialRecordSecretMaterial,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CredentialRecordSecretMaterial {
    Utf8 { value: String },
    Json { value: Value },
    Binary { base64: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialRecordAssociatedData {
    pub context: String,
    pub schema_version: u32,
    pub payload_version: u32,
    pub object_kind: SyncObjectKind,
    pub object_id: SyncObjectId,
    pub object_version: SyncObjectVersion,
    pub profile_object_id: SyncObjectId,
    pub credential_ref_object_id: SyncObjectId,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialRecordAssociatedDataInput {
    pub object_id: SyncObjectId,
    pub object_version: SyncObjectVersion,
    pub profile_object_id: SyncObjectId,
    pub credential_ref_object_id: SyncObjectId,
}

#[derive(Debug, Clone)]
pub struct CredentialRecordEncryptionParams<'a> {
    pub object_id: SyncObjectId,
    pub object_version: SyncObjectVersion,
    pub profile_object_id: SyncObjectId,
    pub credential_ref_object_id: SyncObjectId,
    pub sync_dek: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedCredentialRecordEnvelope {
    pub schema_version: u32,
    pub object_id: SyncObjectId,
    pub object_version: SyncObjectVersion,
    pub profile_object_id: SyncObjectId,
    pub credential_ref_object_id: SyncObjectId,
    pub encrypted_payload_hash: String,
    pub encrypted_payload_size: u64,
    pub encryption: CredentialRecordEncryption,
    pub created_at: DateTime<Utc>,
    pub migration: Option<CredentialRecordMigration>,
    pub redaction: RedactionStatus,
    pub ciphertext: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialRecordEnvelopeParams {
    pub object_id: SyncObjectId,
    pub object_version: SyncObjectVersion,
    pub profile_object_id: SyncObjectId,
    pub credential_ref_object_id: SyncObjectId,
    pub encrypted_payload: EncryptedSyncPayload,
    pub encryption: CredentialRecordEncryption,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialRecordEncryption {
    pub algorithm: String,
    pub key_wrap: String,
    pub nonce: String,
    pub aad: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialRecordMigration {
    pub source_kind: CredentialRecordMigrationSourceKind,
    pub local_source_redacted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialRecordMigrationSourceKind {
    LegacyPluginConfig,
}

pub fn sync_credential_record_payload(
    record: &StoredCredentialRecord,
    profile_object_id: impl Into<SyncObjectId>,
    credential_ref_object_id: impl Into<SyncObjectId>,
    material: CredentialRecordSecretMaterial,
) -> Result<SyncCredentialRecordPayload, ObjectSyncError> {
    let profile_object_id = profile_object_id.into();
    let credential_ref_object_id = credential_ref_object_id.into();
    validate_sync_object_id(SyncObjectKind::Profile, &profile_object_id)?;
    validate_sync_object_id(SyncObjectKind::CredentialRef, &credential_ref_object_id)?;

    Ok(SyncCredentialRecordPayload {
        payload_version: OBJECT_SYNC_PAYLOAD_VERSION,
        profile_object_id,
        credential_ref_object_id,
        credential: SyncCredentialRecord {
            profile_id: record.profile_id.clone(),
            credential_ref_id: record.id.clone(),
            plugin_id: record.plugin_id.clone(),
            class: record.class.clone(),
            label: record.label.clone(),
            created_at: record.created_at,
            material,
        },
        migration: credential_record_migration(&record.source),
        redaction: combine_redaction(record.redaction, RedactionStatus::Withheld),
    })
}

pub fn credential_record_associated_data(
    input: CredentialRecordAssociatedDataInput,
) -> Result<CredentialRecordAssociatedData, ObjectSyncError> {
    validate_sync_object_id(SyncObjectKind::CredentialRecord, &input.object_id)?;
    validate_sync_object_id(SyncObjectKind::Profile, &input.profile_object_id)?;
    validate_sync_object_id(
        SyncObjectKind::CredentialRef,
        &input.credential_ref_object_id,
    )?;

    Ok(CredentialRecordAssociatedData {
        context: CREDENTIAL_RECORD_AAD_CONTEXT.to_string(),
        schema_version: OBJECT_SYNC_SCHEMA_VERSION,
        payload_version: OBJECT_SYNC_PAYLOAD_VERSION,
        object_kind: SyncObjectKind::CredentialRecord,
        object_id: input.object_id,
        object_version: input.object_version,
        profile_object_id: input.profile_object_id,
        credential_ref_object_id: input.credential_ref_object_id,
    })
}

pub fn credential_record_associated_data_json(
    input: CredentialRecordAssociatedDataInput,
) -> Result<String, ObjectSyncError> {
    let aad = credential_record_associated_data(input)?;
    serde_json::to_string(&aad).map_err(|_| ObjectSyncError::CredentialRecordPayloadSerialize)
}

pub fn encrypt_credential_record_payload(
    record: &StoredCredentialRecord,
    material: CredentialRecordSecretMaterial,
    params: CredentialRecordEncryptionParams<'_>,
) -> Result<EncryptedCredentialRecordEnvelope, ObjectSyncError> {
    let CredentialRecordEncryptionParams {
        object_id,
        object_version,
        profile_object_id,
        credential_ref_object_id,
        sync_dek,
    } = params;

    validate_sync_dek(sync_dek)?;

    let payload = sync_credential_record_payload(
        record,
        profile_object_id.clone(),
        credential_ref_object_id.clone(),
        material,
    )?;
    let aad = credential_record_associated_data_json(CredentialRecordAssociatedDataInput {
        object_id: object_id.clone(),
        object_version,
        profile_object_id: profile_object_id.clone(),
        credential_ref_object_id: credential_ref_object_id.clone(),
    })?;
    let plaintext = serde_json::to_vec(&payload)
        .map_err(|_| ObjectSyncError::CredentialRecordPayloadSerialize)?;
    let cipher = Aes256Gcm::new_from_slice(sync_dek)
        .map_err(|_| ObjectSyncError::CredentialRecordEncrypt)?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: &plaintext,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| ObjectSyncError::CredentialRecordEncrypt)?;
    let ciphertext_b64 = BASE64_STANDARD.encode(&ciphertext);
    let encrypted_payload =
        EncryptedSyncPayload::new(sha256_payload_hash(&ciphertext), ciphertext_b64)?;

    encrypted_credential_record_envelope(
        record,
        CredentialRecordEnvelopeParams {
            object_id,
            object_version,
            profile_object_id,
            credential_ref_object_id,
            encrypted_payload,
            encryption: CredentialRecordEncryption {
                algorithm: CREDENTIAL_RECORD_ALGORITHM.to_string(),
                key_wrap: CREDENTIAL_RECORD_KEY_WRAP.to_string(),
                nonce: BASE64_STANDARD.encode(nonce.as_slice()),
                aad,
            },
        },
    )
}

pub fn decrypt_credential_record_payload(
    envelope: &EncryptedCredentialRecordEnvelope,
    sync_dek: &[u8],
) -> Result<SyncCredentialRecordPayload, ObjectSyncError> {
    validate_sync_dek(sync_dek)?;
    if envelope.encryption.algorithm != CREDENTIAL_RECORD_ALGORITHM
        || envelope.encryption.key_wrap != CREDENTIAL_RECORD_KEY_WRAP
    {
        return Err(ObjectSyncError::UnsupportedCredentialRecordEncryption);
    }

    let expected_aad =
        credential_record_associated_data_json(CredentialRecordAssociatedDataInput {
            object_id: envelope.object_id.clone(),
            object_version: envelope.object_version,
            profile_object_id: envelope.profile_object_id.clone(),
            credential_ref_object_id: envelope.credential_ref_object_id.clone(),
        })?;
    if envelope.encryption.aad != expected_aad {
        return Err(ObjectSyncError::CredentialRecordAadMismatch);
    }

    let nonce_bytes = BASE64_STANDARD
        .decode(&envelope.encryption.nonce)
        .map_err(|_| ObjectSyncError::CredentialRecordInvalidBase64)?;
    if nonce_bytes.len() != AES_GCM_NONCE_LEN {
        return Err(ObjectSyncError::InvalidCredentialRecordNonce);
    }
    let ciphertext = BASE64_STANDARD
        .decode(&envelope.ciphertext)
        .map_err(|_| ObjectSyncError::CredentialRecordInvalidBase64)?;
    if envelope.encrypted_payload_hash != sha256_payload_hash(&ciphertext) {
        return Err(ObjectSyncError::CredentialRecordPayloadHashMismatch);
    }

    let cipher = Aes256Gcm::new_from_slice(sync_dek)
        .map_err(|_| ObjectSyncError::CredentialRecordDecrypt)?;
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: &ciphertext,
                aad: envelope.encryption.aad.as_bytes(),
            },
        )
        .map_err(|_| ObjectSyncError::CredentialRecordDecrypt)?;
    let payload: SyncCredentialRecordPayload = serde_json::from_slice(&plaintext)
        .map_err(|_| ObjectSyncError::CredentialRecordPayloadDeserialize)?;

    if payload.payload_version != OBJECT_SYNC_PAYLOAD_VERSION
        || payload.profile_object_id != envelope.profile_object_id
        || payload.credential_ref_object_id != envelope.credential_ref_object_id
    {
        return Err(ObjectSyncError::CredentialRecordPayloadMismatch);
    }

    Ok(payload)
}

pub fn encrypted_credential_record_envelope(
    record: &StoredCredentialRecord,
    params: CredentialRecordEnvelopeParams,
) -> Result<EncryptedCredentialRecordEnvelope, ObjectSyncError> {
    validate_sync_object_id(SyncObjectKind::CredentialRecord, &params.object_id)?;
    validate_sync_object_id(SyncObjectKind::Profile, &params.profile_object_id)?;
    validate_sync_object_id(
        SyncObjectKind::CredentialRef,
        &params.credential_ref_object_id,
    )?;

    Ok(EncryptedCredentialRecordEnvelope {
        schema_version: OBJECT_SYNC_SCHEMA_VERSION,
        object_id: params.object_id,
        object_version: params.object_version,
        profile_object_id: params.profile_object_id,
        credential_ref_object_id: params.credential_ref_object_id,
        encrypted_payload_hash: params.encrypted_payload.payload_hash,
        encrypted_payload_size: params.encrypted_payload.payload_size,
        encryption: params.encryption,
        created_at: record.created_at,
        migration: credential_record_migration(&record.source),
        redaction: combine_redaction(record.redaction, RedactionStatus::Withheld),
        ciphertext: params.encrypted_payload.ciphertext,
    })
}

pub fn validate_sync_object_id(
    kind: SyncObjectKind,
    object_id: &str,
) -> Result<(), ObjectSyncError> {
    let expected_prefix = kind.object_id_prefix();
    let Some(body) = object_id.strip_prefix(expected_prefix) else {
        return Err(ObjectSyncError::InvalidObjectIdPrefix {
            kind,
            expected_prefix,
        });
    };
    if body.is_empty() {
        return Err(ObjectSyncError::EmptyObjectIdBody);
    }
    for ch in body.chars() {
        if !ch.is_ascii_alphanumeric() && ch != '_' && ch != '-' {
            return Err(ObjectSyncError::InvalidObjectIdCharacter(ch));
        }
    }
    Ok(())
}

pub fn redact_sync_value(value: &Value) -> (Value, RedactionStatus) {
    let targets = collect_redaction_targets(value);
    let mut changed = false;
    let redacted = redact_sync_value_inner(value, None, &targets, &mut changed);

    if changed {
        (redacted, RedactionStatus::Applied)
    } else {
        (redacted, RedactionStatus::NotRequired)
    }
}

fn redact_sync_value_inner(
    value: &Value,
    inherited_kind: Option<SyncRedactionKind>,
    targets: &[RedactionTarget],
    changed: &mut bool,
) -> Value {
    match value {
        Value::Object(map) => {
            let mut redacted = serde_json::Map::new();
            for (key, child) in map {
                let child_kind = sync_field_kind(key).or_else(|| inherited_kind.clone());
                redacted.insert(
                    key.clone(),
                    redact_sync_value_inner(child, child_kind, targets, changed),
                );
            }
            Value::Object(redacted)
        }
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| redact_sync_value_inner(item, inherited_kind.clone(), targets, changed))
                .collect(),
        ),
        Value::String(text) => {
            if let Some(kind) = inherited_kind {
                *changed = true;
                return Value::String(kind.placeholder().to_string());
            }

            let (redacted, status) = redact_text_with_targets(text, targets);
            if status != RedactionStatus::NotRequired {
                *changed = true;
            }
            Value::String(redacted)
        }
        _ => value.clone(),
    }
}

fn sync_field_kind(key: &str) -> Option<SyncRedactionKind> {
    credential_class_for_key(key)
        .map(SyncRedactionKind::Credential)
        .or_else(|| is_sensitive_metadata_key(key).then_some(SyncRedactionKind::SensitiveMetadata))
        .or_else(|| is_local_identifier_key(key).then_some(SyncRedactionKind::LocalIdentifier))
}

fn validate_payload_hash(payload_hash: &str) -> Result<(), ObjectSyncError> {
    if !payload_hash.starts_with("sha256:") || payload_hash.len() <= "sha256:".len() {
        return Err(ObjectSyncError::InvalidPayloadHash);
    }
    Ok(())
}

fn validate_sync_dek(sync_dek: &[u8]) -> Result<(), ObjectSyncError> {
    if sync_dek.len() != SYNC_DEK_LEN {
        return Err(ObjectSyncError::InvalidCredentialRecordDekLength {
            actual: sync_dek.len(),
        });
    }
    Ok(())
}

fn sha256_payload_hash(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn credential_record_migration(
    source: &StoredCredentialSource,
) -> Option<CredentialRecordMigration> {
    match source {
        StoredCredentialSource::LegacyPluginConfig { .. } => Some(CredentialRecordMigration {
            source_kind: CredentialRecordMigrationSourceKind::LegacyPluginConfig,
            local_source_redacted: true,
        }),
        StoredCredentialSource::LocalEncryptedPluginConfig { .. } => None,
        StoredCredentialSource::SyncedObject { .. } => None,
    }
}

fn redact_credential_ref_label(label: Option<&str>) -> (Option<String>, RedactionStatus) {
    let Some(label) = label else {
        return (None, RedactionStatus::NotRequired);
    };
    if label_needs_redaction(label) {
        return (
            Some(CREDENTIAL_LABEL_PLACEHOLDER.to_string()),
            RedactionStatus::Applied,
        );
    }
    (Some(label.to_string()), RedactionStatus::NotRequired)
}

fn label_needs_redaction(label: &str) -> bool {
    let normalized = label.to_ascii_lowercase().replace(['-', '.', '/'], "_");
    credential_class_for_key(&normalized).is_some()
        || is_sensitive_metadata_key(&normalized)
        || normalized.contains("plugin_config")
        || normalized.contains("legacy")
        || normalized.contains("path")
        || label.contains("::")
}

fn is_local_identifier_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase().replace(['-', '.'], "_");
    key == "legacy_connection_key"
        || key == "connection_key"
        || key == "credential_path"
        || key == "local_path"
        || key == "path"
        || key.ends_with("_path")
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

#[derive(Debug, Clone, PartialEq, Eq)]
enum SyncRedactionKind {
    Credential(CredentialClass),
    SensitiveMetadata,
    LocalIdentifier,
}

impl SyncRedactionKind {
    fn placeholder(&self) -> &'static str {
        match self {
            Self::Credential(class) => placeholder_for_credential_class(class),
            Self::SensitiveMetadata => "<redacted:sensitive_metadata>",
            Self::LocalIdentifier => LOCAL_IDENTIFIER_PLACEHOLDER,
        }
    }
}

#[cfg(test)]
mod tests {
    use chrono::{TimeZone, Utc};
    use serde_json::json;

    use super::*;

    fn actor() -> SyncObjectActor {
        SyncObjectActor::new(
            ActorRef {
                id: "local-user".into(),
                actor_type: ActorType::Human,
            },
            "device_01JZ8N10000000000000000000",
        )
    }

    fn encrypted_payload() -> EncryptedSyncPayload {
        EncryptedSyncPayload::new(
            "sha256:0123456789abcdef",
            "base64-ciphertext-without-plaintext",
        )
        .expect("valid encrypted payload")
    }

    fn credential_record() -> StoredCredentialRecord {
        StoredCredentialRecord {
            id: "credential:encoded-local-key:cGFzc3dvcmQ".into(),
            profile_id: "profile:encoded-local-key".into(),
            plugin_id: "mysql".into(),
            class: CredentialClass::Password,
            label: Some("local credential password".into()),
            source: StoredCredentialSource::LegacyPluginConfig {
                legacy_connection_key: "mysql::prod-db".into(),
                path: "plugin_config.password".into(),
            },
            created_at: Utc.with_ymd_and_hms(2026, 7, 4, 14, 0, 0).unwrap(),
            redaction: RedactionStatus::Withheld,
        }
    }

    fn credential_record_params<'a>(sync_dek: &'a [u8]) -> CredentialRecordEncryptionParams<'a> {
        CredentialRecordEncryptionParams {
            object_id: "sync_credrec_01JZ8N2E9F6Q0Z2P2W3Q4R5T6V".into(),
            object_version: 1,
            profile_object_id: "sync_profile_01JZ8N2E9F6Q0Z2P2W3Q4R5T6V".into(),
            credential_ref_object_id: "sync_credref_01JZ8N2E9F6Q0Z2P2W3Q4R5T6V".into(),
            sync_dek,
        }
    }

    #[test]
    fn rejects_legacy_local_ids_as_server_visible_object_ids() {
        let result = validate_sync_object_id(SyncObjectKind::Profile, "profile:cHJvZDo6ZGI");

        assert!(matches!(
            result,
            Err(ObjectSyncError::InvalidObjectIdPrefix { .. })
        ));
        assert!(
            validate_sync_object_id(
                SyncObjectKind::Profile,
                "sync_profile_01JZ8N2E9F6Q0Z2P2W3Q4R5T6V"
            )
            .is_ok()
        );
    }

    #[test]
    fn profile_payload_redacts_secret_and_target_metadata() {
        let profile = ConnectionProfile {
            id: "profile:encoded-local-key".into(),
            name: "prod-db".into(),
            plugin_id: "mysql".into(),
            display_name: Some("Production DB".into()),
            metadata: json!({
                "legacy_connection_key": "mysql::prod-db",
                "plugin": {
                    "host": "db.internal.example",
                    "username": "app_user",
                    "bucket": "private-bucket",
                    "has_password": true
                }
            }),
            default_options: json!({
                "url": "mysql://app_user:super-secret@db.internal.example/prod",
                "password": "super-secret",
                "query_limit": 100
            }),
            credential_refs: vec![CredentialRef {
                id: "credential:encoded-local-key:cGFzc3dvcmQ".into(),
                class: CredentialClass::Password,
                label: Some("local credential password".into()),
            }],
            policy: ConnectionProfilePolicy::default(),
        };

        let payload = sync_profile_payload(
            &profile,
            Some("sync_policy_01JZ8N2E9F6Q0Z2P2W3Q4R5T6V".into()),
            Some("sync_plugin_mysql_v1".into()),
        );
        let encoded = serde_json::to_string(&payload).expect("serialize profile payload");

        assert_eq!(payload.redaction, RedactionStatus::Applied);
        assert!(encoded.contains("<redacted:local_identifier>"));
        assert!(encoded.contains("<redacted:sensitive_metadata>"));
        assert!(encoded.contains("<redacted:password>"));
        assert!(!encoded.contains("mysql::prod-db"));
        assert!(!encoded.contains("db.internal.example"));
        assert!(!encoded.contains("app_user"));
        assert!(!encoded.contains("private-bucket"));
        assert!(!encoded.contains("super-secret"));
        assert!(!encoded.contains("mysql://"));
    }

    #[test]
    fn credential_ref_payload_redacts_sensitive_generated_labels() {
        let credential_ref = CredentialRef {
            id: "credential:encoded-local-key:cGFzc3dvcmQ".into(),
            class: CredentialClass::Password,
            label: Some("local credential password".into()),
        };

        let payload =
            sync_credential_ref_payload("sync_profile_01JZ8N2E9F6Q0Z2P2W3Q4R5T6V", &credential_ref);
        let encoded = serde_json::to_string(&payload).expect("serialize credential ref");

        assert_eq!(payload.redaction, RedactionStatus::Applied);
        assert!(encoded.contains(CREDENTIAL_LABEL_PLACEHOLDER));
        assert!(!encoded.contains("local credential password"));
    }

    #[test]
    fn credential_record_payload_encrypts_and_decrypts_with_aad() {
        let record = credential_record();
        let sync_dek = [7_u8; 32];
        let secret = "s3-super-secret-token";

        let envelope = encrypt_credential_record_payload(
            &record,
            CredentialRecordSecretMaterial::Utf8 {
                value: secret.into(),
            },
            credential_record_params(&sync_dek),
        )
        .expect("encrypt credential record");
        let encoded = serde_json::to_string(&envelope).expect("serialize credential envelope");

        assert_eq!(envelope.encryption.algorithm, CREDENTIAL_RECORD_ALGORITHM);
        assert_eq!(envelope.encryption.key_wrap, CREDENTIAL_RECORD_KEY_WRAP);
        assert!(
            envelope
                .encryption
                .aad
                .contains(CREDENTIAL_RECORD_AAD_CONTEXT)
        );
        assert!(!encoded.contains(secret));
        assert!(!encoded.contains("credential:encoded-local-key"));
        assert!(!encoded.contains("profile:encoded-local-key"));
        assert!(!encoded.contains("mysql::prod-db"));
        assert!(!encoded.contains("plugin_config.password"));
        assert!(!encoded.contains("local credential password"));
        assert!(!encoded.contains("\"password\""));

        let object = sync_object_envelope(SyncObjectEnvelopeInput {
            object_id: envelope.object_id.clone(),
            object_kind: SyncObjectKind::CredentialRecord,
            object_version: envelope.object_version,
            base_server_revision: None,
            encrypted_payload: EncryptedSyncPayload::new(
                envelope.encrypted_payload_hash.clone(),
                envelope.ciphertext.clone(),
            )
            .expect("encrypted payload"),
            updated_at: envelope.created_at,
            updated_by: actor(),
            deleted: false,
            redaction: envelope.redaction,
        })
        .expect("object envelope");
        let manifest = sync_object_manifest(
            "sync_batch_01JZ8N2E9F6Q0Z2P2W3Q4R5T6V",
            "device_01JZ8N10000000000000000000",
            Utc.with_ymd_and_hms(2026, 7, 4, 15, 0, 0).unwrap(),
            &[object],
        );
        let manifest_encoded = serde_json::to_string(&manifest).expect("serialize manifest");
        assert_eq!(manifest.counts.get("credential_record"), Some(&1));
        assert!(!manifest_encoded.contains(secret));
        assert!(!manifest_encoded.contains(&envelope.ciphertext));
        assert!(!manifest_encoded.contains("plugin_config.password"));
        assert!(!manifest_encoded.contains("local credential password"));

        let decrypted =
            decrypt_credential_record_payload(&envelope, &sync_dek).expect("decrypt credential");
        assert_eq!(decrypted.profile_object_id, envelope.profile_object_id);
        assert_eq!(
            decrypted.credential_ref_object_id,
            envelope.credential_ref_object_id
        );
        assert_eq!(decrypted.credential.plugin_id, "mysql");
        assert_eq!(decrypted.credential.class, CredentialClass::Password);
        assert_eq!(
            decrypted.credential.material,
            CredentialRecordSecretMaterial::Utf8 {
                value: secret.into()
            }
        );
        assert_eq!(
            decrypted.migration.expect("migration").source_kind,
            CredentialRecordMigrationSourceKind::LegacyPluginConfig
        );
    }

    #[test]
    fn credential_record_decrypt_rejects_tampered_aad_without_secret_leak() {
        let record = credential_record();
        let sync_dek = [9_u8; 32];
        let secret = "ssh-private-key-passphrase";
        let mut envelope = encrypt_credential_record_payload(
            &record,
            CredentialRecordSecretMaterial::Utf8 {
                value: secret.into(),
            },
            credential_record_params(&sync_dek),
        )
        .expect("encrypt credential record");

        envelope.object_version += 1;
        let error = decrypt_credential_record_payload(&envelope, &sync_dek).unwrap_err();
        let summary = error.to_string();

        assert!(matches!(
            error,
            ObjectSyncError::CredentialRecordAadMismatch
        ));
        assert!(!summary.contains(secret));
        assert!(!summary.contains("mysql::prod-db"));
        assert!(!summary.contains("plugin_config.password"));
        assert!(!summary.contains("local credential password"));
    }

    #[test]
    fn manifest_excludes_ciphertext_and_profile_labels() {
        let envelope = sync_object_envelope(SyncObjectEnvelopeInput {
            object_id: "sync_profile_01JZ8N2E9F6Q0Z2P2W3Q4R5T6V".into(),
            object_kind: SyncObjectKind::Profile,
            object_version: 8,
            base_server_revision: Some(12),
            encrypted_payload: EncryptedSyncPayload::new(
                "sha256:fedcba9876543210",
                "ciphertext-that-would-contain-prod-db-if-decrypted",
            )
            .expect("encrypted payload"),
            updated_at: Utc.with_ymd_and_hms(2026, 7, 4, 15, 0, 0).unwrap(),
            updated_by: actor(),
            deleted: false,
            redaction: RedactionStatus::Withheld,
        })
        .expect("envelope");

        let manifest = sync_object_manifest(
            "sync_batch_01JZ8N2E9F6Q0Z2P2W3Q4R5T6V",
            "device_01JZ8N10000000000000000000",
            Utc.with_ymd_and_hms(2026, 7, 4, 15, 0, 0).unwrap(),
            &[envelope],
        );
        let encoded = serde_json::to_string(&manifest).expect("serialize manifest");

        assert_eq!(manifest.counts.get("profile"), Some(&1));
        assert!(encoded.contains("sync_profile_01JZ8N2E9F6Q0Z2P2W3Q4R5T6V"));
        assert!(encoded.contains("sha256:fedcba9876543210"));
        assert!(!encoded.contains("ciphertext-that-would-contain"));
        assert!(!encoded.contains("prod-db"));
        assert!(!encoded.contains("db.internal.example"));
        assert!(!encoded.contains("super-secret"));
    }

    #[test]
    fn credential_record_envelope_hides_legacy_source_fields() {
        let record = credential_record();

        let envelope = encrypted_credential_record_envelope(
            &record,
            CredentialRecordEnvelopeParams {
                object_id: "sync_credrec_01JZ8N2E9F6Q0Z2P2W3Q4R5T6V".into(),
                object_version: 1,
                profile_object_id: "sync_profile_01JZ8N2E9F6Q0Z2P2W3Q4R5T6V".into(),
                credential_ref_object_id: "sync_credref_01JZ8N2E9F6Q0Z2P2W3Q4R5T6V".into(),
                encrypted_payload: encrypted_payload(),
                encryption: CredentialRecordEncryption {
                    algorithm: "aes-256-gcm".into(),
                    key_wrap: "sync-dek.v1".into(),
                    nonce: "base64-nonce".into(),
                    aad: "object-sync.credential-record.v1".into(),
                },
            },
        )
        .expect("credential envelope");
        let encoded = serde_json::to_string(&envelope).expect("serialize credential envelope");

        assert_eq!(envelope.redaction, RedactionStatus::Withheld);
        assert!(encoded.contains("legacy_plugin_config"));
        assert!(encoded.contains("local_source_redacted"));
        assert!(!encoded.contains("credential:encoded-local-key"));
        assert!(!encoded.contains("profile:encoded-local-key"));
        assert!(!encoded.contains("mysql::prod-db"));
        assert!(!encoded.contains("plugin_config.password"));
        assert!(!encoded.contains("local credential password"));
        assert!(!encoded.contains("\"password\""));
    }
}
