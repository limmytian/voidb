//! High-level sync operations: register, login, push, pull.
//!
//! Each function is a single async call suitable for
//! `caps.runtime.spawn(..)`. They own their own `SyncClient` and return
//! either a typed success or a [`SyncError`].
//!
//! Author: Limmy

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use voidb_core::{
    ActorRef, ActorType, AppConfig, AuditEvent, AuditEventStatus, AuditEventStore, AuditOperation,
    ConnectionProfile, ConnectionProfilePolicy, ConnectionProfileRef,
    CredentialRecordEncryptionParams, CredentialRecordSecretMaterial, CredentialRef,
    EncryptedCredentialRecordEnvelope, EncryptedSyncPayload, LocalAuditStore, LocalProfileStore,
    OBJECT_SYNC_PAYLOAD_VERSION, RedactionStatus, StoredCredentialEncryption,
    StoredCredentialRecord, StoredCredentialSource, SyncCredentialRefPayload, SyncObjectActor,
    SyncObjectEnvelope, SyncObjectEnvelopeInput, SyncObjectKind, SyncPluginCompatibilityPayload,
    SyncProfilePayload, SyncProfilePolicyPayload, decrypt_credential_record_payload,
    encrypt_credential_record_payload, sync_credential_ref_payload, sync_object_envelope,
    sync_profile_payload, sync_profile_policy_payload,
};

use crate::bundler;
use crate::client::{
    ObjectActor, ObjectResponse, ObjectSummary, PutObjectRequest, PutObjectResponse,
    RecoveryResetRequest, RegisterRequest, SyncClient,
};
use crate::config::{
    PeriodicSyncConfig, SyncConfig, SyncObjectConflict, SyncObjectMapping, voidb_config_dir,
};
use crate::crypto::{self, KdfParams};
use crate::error::{ObjectConflictDetails, SyncError};
use crate::session::Session;

/// Successful login or register. Carries the fresh in-memory session.
#[derive(Debug)]
pub struct LoginOk {
    pub session: Session,
    pub config: SyncConfig,
    pub recovery_code: Option<String>,
}

#[derive(Debug)]
pub struct PushOk {
    pub revision: u64,
    pub bytes: usize,
    pub files: usize,
}

#[derive(Debug)]
pub struct PullOk {
    pub revision: u64,
    pub bytes: usize,
    pub files: usize,
    pub dest: PathBuf,
}

#[derive(Debug)]
pub struct ObjectPushOk {
    pub objects: usize,
    pub bytes: usize,
}

#[derive(Debug)]
pub struct CredentialMappingMigrationOk {
    pub migrated: usize,
    pub skipped: usize,
}

#[derive(Debug)]
pub struct CredentialReenrollInput {
    pub profile_id: String,
    pub credential_ref_id: String,
    pub material: CredentialReenrollMaterial,
}

#[derive(Debug)]
pub enum CredentialReenrollMaterial {
    Provided(CredentialRecordSecretMaterial),
    ExistingLocal,
}

#[derive(Debug)]
pub struct CredentialReenrollOk {
    pub object_id: String,
    pub object_version: u64,
    pub server_revision: u64,
    pub bytes: usize,
}

#[derive(Debug)]
pub struct ObjectPullOk {
    pub objects: usize,
    pub imported_profiles: usize,
    pub imported_credential_refs: usize,
    pub imported_credential_records: usize,
    pub unavailable: usize,
}

#[derive(Debug, Clone)]
pub struct ObjectConflictResolutionInput {
    pub object_kind: String,
    pub object_id: String,
    pub current_server_revision: Option<u64>,
    pub acknowledge_delete: bool,
}

#[derive(Debug, Clone)]
pub struct ObjectConflictResolutionOk {
    pub mode: String,
    pub object_kind: String,
    pub object_id: String,
    pub object_version: u64,
    pub server_revision: u64,
    pub previous_server_revision: u64,
    pub bytes: usize,
    pub local_action: String,
    pub unavailable: bool,
}

#[derive(Debug, Clone)]
pub struct CredentialConflictHandoffOk {
    pub object_id: String,
    pub profile_id: String,
    pub credential_ref_id: String,
    pub unavailable_reason: Option<String>,
    pub command: String,
}

#[derive(Debug, Clone)]
pub struct PeriodicSyncConfigureInput {
    pub enabled: Option<bool>,
    pub interval_minutes: Option<u64>,
    pub mode: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PeriodicSyncStatus {
    pub enabled: bool,
    pub configured: bool,
    pub interval_minutes: u64,
    pub mode: String,
    pub last_run_at: Option<String>,
    pub last_status: Option<String>,
    pub next_run_at: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PeriodicSyncTickOk {
    pub ran: bool,
    pub reason: String,
    pub mode: String,
    pub pushed_objects: usize,
    pub pulled_objects: usize,
    pub unavailable: usize,
}

const PERIODIC_SYNC_MODE_PULL_OBJECTS: &str = "pull-objects";
const PERIODIC_SYNC_MODE_PUSH_PULL_OBJECTS: &str = "push-pull-objects";
const MIN_PERIODIC_SYNC_INTERVAL_MINUTES: u64 = 15;
const SUPPORTED_PROFILE_SCHEMA_VERSION: u32 = 1;
const SUPPORTED_OBJECT_SYNC_PLUGIN_IDS: &[&str] = &[
    "mysql",
    "postgres",
    "sqlite",
    "redis",
    "ssh",
    "docker",
    "kubernetes",
    "webdav",
    "s3",
    "elasticsearch",
    "mongodb",
    "duckdb",
    "email",
    "jenkins",
    "sync",
];

// -----------------------------------------------------------------------------
// Periodic sync
// -----------------------------------------------------------------------------

pub fn configure_periodic_sync(
    mut config: SyncConfig,
    input: PeriodicSyncConfigureInput,
) -> Result<SyncConfig, SyncError> {
    if let Some(interval) = input.interval_minutes {
        validate_periodic_interval(interval)?;
        config.periodic_sync.interval_minutes = interval;
    }
    if let Some(mode) = input.mode {
        validate_periodic_mode(&mode)?;
        config.periodic_sync.mode = mode;
    }
    if let Some(enabled) = input.enabled {
        if enabled {
            validate_periodic_interval(config.periodic_sync.interval_minutes)?;
            validate_periodic_mode(&config.periodic_sync.mode)?;
            config.periodic_sync.last_status = Some("configured".into());
        } else {
            config.periodic_sync.last_status = Some("disabled".into());
        }
        config.periodic_sync.enabled = enabled;
    }
    config.save()?;
    Ok(config)
}

pub fn periodic_sync_status(config: &SyncConfig, now: DateTime<Utc>) -> PeriodicSyncStatus {
    PeriodicSyncStatus {
        enabled: config.periodic_sync.enabled,
        configured: config.periodic_sync.enabled
            && periodic_sync_is_configured(&config.periodic_sync).is_ok(),
        interval_minutes: config.periodic_sync.interval_minutes,
        mode: config.periodic_sync.mode.clone(),
        last_run_at: config.periodic_sync.last_run_at.clone(),
        last_status: config.periodic_sync.last_status.clone(),
        next_run_at: periodic_sync_next_run_at(&config.periodic_sync, now),
    }
}

pub async fn run_periodic_sync_tick(
    session: Session,
    mut config: SyncConfig,
    now: DateTime<Utc>,
    force: bool,
) -> Result<(PeriodicSyncTickOk, SyncConfig), SyncError> {
    if !config.periodic_sync.enabled {
        return Ok((periodic_sync_skipped(&config, "disabled"), config));
    }
    periodic_sync_is_configured(&config.periodic_sync)?;
    if !force && !periodic_sync_is_due(&config.periodic_sync, now) {
        return Ok((periodic_sync_skipped(&config, "not_due"), config));
    }

    let mode = config.periodic_sync.mode.clone();
    let mut pushed_objects = 0usize;
    if mode == PERIODIC_SYNC_MODE_PUSH_PULL_OBJECTS {
        let (push_ok, next_config) = push_objects(session.clone(), config).await?;
        pushed_objects = push_ok.objects;
        config = next_config;
    }
    let (pull_ok, mut next_config) = pull_objects(session, config).await?;
    next_config.periodic_sync.last_run_at = Some(now.to_rfc3339());
    next_config.periodic_sync.last_status = Some("succeeded".into());
    next_config.save()?;

    Ok((
        PeriodicSyncTickOk {
            ran: true,
            reason: "succeeded".into(),
            mode,
            pushed_objects,
            pulled_objects: pull_ok.objects,
            unavailable: pull_ok.unavailable,
        },
        next_config,
    ))
}

fn periodic_sync_skipped(config: &SyncConfig, reason: &str) -> PeriodicSyncTickOk {
    PeriodicSyncTickOk {
        ran: false,
        reason: reason.to_string(),
        mode: config.periodic_sync.mode.clone(),
        pushed_objects: 0,
        pulled_objects: 0,
        unavailable: 0,
    }
}

fn periodic_sync_is_configured(config: &PeriodicSyncConfig) -> Result<(), SyncError> {
    validate_periodic_interval(config.interval_minutes)?;
    validate_periodic_mode(&config.mode)
}

fn periodic_sync_is_due(config: &PeriodicSyncConfig, now: DateTime<Utc>) -> bool {
    let Some(last_run_at) = config
        .last_run_at
        .as_deref()
        .and_then(|raw| DateTime::parse_from_rfc3339(raw).ok())
    else {
        return true;
    };
    let interval = Duration::minutes(config.interval_minutes as i64);
    now.signed_duration_since(last_run_at.with_timezone(&Utc)) >= interval
}

fn periodic_sync_next_run_at(config: &PeriodicSyncConfig, now: DateTime<Utc>) -> Option<String> {
    if !config.enabled || periodic_sync_is_configured(config).is_err() {
        return None;
    }
    let Some(last_run_at) = config
        .last_run_at
        .as_deref()
        .and_then(|raw| DateTime::parse_from_rfc3339(raw).ok())
    else {
        return Some(now.to_rfc3339());
    };
    let interval = Duration::minutes(config.interval_minutes as i64);
    Some((last_run_at.with_timezone(&Utc) + interval).to_rfc3339())
}

fn validate_periodic_interval(interval_minutes: u64) -> Result<(), SyncError> {
    if interval_minutes < MIN_PERIODIC_SYNC_INTERVAL_MINUTES {
        return Err(SyncError::Config(format!(
            "periodic sync interval must be at least {MIN_PERIODIC_SYNC_INTERVAL_MINUTES} minutes"
        )));
    }
    Ok(())
}

fn validate_periodic_mode(mode: &str) -> Result<(), SyncError> {
    match mode {
        PERIODIC_SYNC_MODE_PULL_OBJECTS | PERIODIC_SYNC_MODE_PUSH_PULL_OBJECTS => Ok(()),
        other => Err(SyncError::Config(format!(
            "unsupported periodic sync mode: {other}"
        ))),
    }
}

// -----------------------------------------------------------------------------
// Register
// -----------------------------------------------------------------------------

pub struct RegisterInput {
    pub server_url: String,
    pub email: String,
    pub password: String,
    pub device_name: String,
    pub invite_token: Option<String>,
}

pub struct RecoverInput {
    pub server_url: String,
    pub email: String,
    pub recovery_code: String,
    pub new_password: String,
    pub device_name: String,
}

pub async fn register(input: RegisterInput) -> Result<LoginOk, SyncError> {
    let RegisterInput {
        server_url,
        email,
        password,
        device_name,
        invite_token,
    } = input;

    if server_url.is_empty() {
        return Err(SyncError::Config("server_url empty".into()));
    }
    if !email.contains('@') {
        return Err(SyncError::Config("invalid email".into()));
    }
    if password.len() < 8 {
        return Err(SyncError::Config("password too short (min 8 chars)".into()));
    }

    let params_auth = KdfParams::default_client();
    let params_kek = KdfParams::default_client();
    let params_recovery_auth = KdfParams::default_client();
    let params_recovery_kek = KdfParams::default_client();
    let salt_auth = crypto::random_bytes(16);
    let salt_kek = crypto::random_bytes(16);
    let salt_recovery_auth = crypto::random_bytes(16);
    let salt_recovery_kek = crypto::random_bytes(16);

    let auth_hash_client = crypto::derive(&password, &salt_auth, &params_auth)?;
    let kek = crypto::derive(&password, &salt_kek, &params_kek)?;
    let dek = crypto::random_bytes(32);
    let wrapped_dek = crypto::wrap_dek(&kek, &dek)?;
    let recovery_code = crypto::generate_recovery_code();
    let recovery_hash_client =
        crypto::derive_recovery_code(&recovery_code, &salt_recovery_auth, &params_recovery_auth)?;
    let recovery_wrapped_dek = crypto::wrap_dek_with_recovery_code(
        &recovery_code,
        &salt_recovery_kek,
        &params_recovery_kek,
        &dek,
    )?;

    let req = RegisterRequest {
        email: email.clone(),
        auth_hash_client: B64.encode(&auth_hash_client),
        kdf_salt_auth: B64.encode(&salt_auth),
        kdf_params_auth: params_auth,
        kdf_salt_kek: B64.encode(&salt_kek),
        kdf_params_kek: params_kek,
        wrapped_dek: B64.encode(&wrapped_dek),
        recovery_hash_client: Some(B64.encode(&recovery_hash_client)),
        kdf_salt_recovery_auth: Some(B64.encode(&salt_recovery_auth)),
        kdf_params_recovery_auth: Some(params_recovery_auth),
        kdf_salt_recovery_kek: Some(B64.encode(&salt_recovery_kek)),
        kdf_params_recovery_kek: Some(params_recovery_kek),
        recovery_wrapped_dek: Some(B64.encode(&recovery_wrapped_dek)),
        device_name: device_name.clone(),
        invite_token,
    };

    let client = SyncClient::new(&server_url);
    let resp = client.register(req).await?;

    let session = Session {
        user_id: resp.user_id,
        device_id: resp.device_id.clone(),
        token: resp.token,
        dek,
        email: email.clone(),
        server_url: server_url.clone(),
    };

    let mut cfg = SyncConfig::load().unwrap_or_default();
    cfg.server_url = Some(server_url);
    cfg.email = Some(email);
    cfg.device_id = Some(resp.device_id);
    cfg.device_name = Some(device_name);
    cfg.save()?;

    Ok(LoginOk {
        session,
        config: cfg,
        recovery_code: Some(recovery_code),
    })
}

// -----------------------------------------------------------------------------
// Login
// -----------------------------------------------------------------------------

pub struct LoginInput {
    pub server_url: String,
    pub email: String,
    pub password: String,
    pub device_name: String,
}

pub async fn login(input: LoginInput) -> Result<LoginOk, SyncError> {
    let LoginInput {
        server_url,
        email,
        password,
        device_name,
    } = input;

    let client = SyncClient::new(&server_url);
    let challenge = client.challenge(&email).await?;
    let salt_auth = B64
        .decode(&challenge.kdf_salt_auth)
        .map_err(|e| SyncError::Crypto(format!("base64 salt_auth: {e}")))?;
    let params_auth = challenge.kdf_params_auth;

    let auth_hash_client = crypto::derive(&password, &salt_auth, &params_auth)?;
    let resp = client
        .login(&email, &auth_hash_client, &device_name)
        .await?;

    let salt_kek = B64
        .decode(&resp.kdf_salt_kek)
        .map_err(|e| SyncError::Crypto(format!("base64 salt_kek: {e}")))?;
    let wrapped_dek = B64
        .decode(&resp.wrapped_dek)
        .map_err(|e| SyncError::Crypto(format!("base64 wrapped_dek: {e}")))?;
    let kek = crypto::derive(&password, &salt_kek, &resp.kdf_params_kek)?;
    let dek = crypto::unwrap_dek(&kek, &wrapped_dek)?;

    let session = Session {
        user_id: resp.user_id,
        device_id: resp.device_id.clone(),
        token: resp.token,
        dek,
        email: email.clone(),
        server_url: server_url.clone(),
    };

    let mut cfg = SyncConfig::load().unwrap_or_default();
    cfg.server_url = Some(server_url);
    cfg.email = Some(email);
    cfg.device_id = Some(resp.device_id);
    cfg.device_name = Some(device_name);
    cfg.save()?;

    Ok(LoginOk {
        session,
        config: cfg,
        recovery_code: None,
    })
}

pub async fn recover_password(input: RecoverInput) -> Result<LoginOk, SyncError> {
    let RecoverInput {
        server_url,
        email,
        recovery_code,
        new_password,
        device_name,
    } = input;

    if server_url.is_empty() {
        return Err(SyncError::Config("server_url empty".into()));
    }
    if !email.contains('@') {
        return Err(SyncError::Config("invalid email".into()));
    }
    if new_password.len() < 8 {
        return Err(SyncError::Config(
            "new password too short (min 8 chars)".into(),
        ));
    }

    let client = SyncClient::new(&server_url);
    let challenge = client.recovery_challenge(&email).await?;
    let salt_recovery_auth = B64
        .decode(&challenge.kdf_salt_recovery_auth)
        .map_err(|e| SyncError::Crypto(format!("base64 salt_recovery_auth: {e}")))?;
    let recovery_hash_client = crypto::derive_recovery_code(
        &recovery_code,
        &salt_recovery_auth,
        &challenge.kdf_params_recovery_auth,
    )?;

    let salt_recovery_kek = B64
        .decode(&challenge.kdf_salt_recovery_kek)
        .map_err(|e| SyncError::Crypto(format!("base64 salt_recovery_kek: {e}")))?;
    let recovery_wrapped_dek = B64
        .decode(&challenge.recovery_wrapped_dek)
        .map_err(|e| SyncError::Crypto(format!("base64 recovery_wrapped_dek: {e}")))?;
    let dek = crypto::unwrap_dek_with_recovery_code(
        &recovery_code,
        &salt_recovery_kek,
        &challenge.kdf_params_recovery_kek,
        &recovery_wrapped_dek,
    )?;

    let params_auth = KdfParams::default_client();
    let params_kek = KdfParams::default_client();
    let salt_auth = crypto::random_bytes(16);
    let salt_kek = crypto::random_bytes(16);
    let auth_hash_client = crypto::derive(&new_password, &salt_auth, &params_auth)?;
    let kek = crypto::derive(&new_password, &salt_kek, &params_kek)?;
    let wrapped_dek = crypto::wrap_dek(&kek, &dek)?;

    let resp = client
        .recover(RecoveryResetRequest {
            email: email.clone(),
            recovery_hash_client: B64.encode(&recovery_hash_client),
            auth_hash_client: B64.encode(&auth_hash_client),
            kdf_salt_auth: B64.encode(&salt_auth),
            kdf_params_auth: params_auth,
            kdf_salt_kek: B64.encode(&salt_kek),
            kdf_params_kek: params_kek,
            wrapped_dek: B64.encode(&wrapped_dek),
            device_name: device_name.clone(),
        })
        .await?;

    let session = Session {
        user_id: resp.user_id,
        device_id: resp.device_id.clone(),
        token: resp.token,
        dek,
        email: email.clone(),
        server_url: server_url.clone(),
    };

    let mut cfg = SyncConfig::load().unwrap_or_default();
    cfg.server_url = Some(server_url);
    cfg.email = Some(email);
    cfg.device_id = Some(resp.device_id);
    cfg.device_name = Some(device_name);
    cfg.save()?;

    Ok(LoginOk {
        session,
        config: cfg,
        recovery_code: None,
    })
}

// -----------------------------------------------------------------------------
// Push
// -----------------------------------------------------------------------------

pub async fn push(
    session: Session,
    mut config: SyncConfig,
    kind: &str,
    force_revision: Option<u64>,
) -> Result<(PushOk, SyncConfig), SyncError> {
    let root = voidb_config_dir()?;
    let (manifest, archive) = bundler::build_for_kind(&root, kind)?;
    let ciphertext = crypto::encrypt_bundle(&session.dek, &archive)?;

    let client = SyncClient::new(&session.server_url).with_token(session.token.clone());
    let manifest_json = serde_json::to_value(&manifest)
        .map_err(|e| SyncError::Bundle(format!("manifest json: {e}")))?;

    let expected = force_revision.unwrap_or_else(|| config.revision_for(kind)) as i64;
    let put = client
        .put_blob(kind, expected, &manifest_json, &ciphertext)
        .await?;

    config.set_revision(kind, put.revision as u64);
    config.last_synced_at = Some(chrono::Utc::now().to_rfc3339());
    config.save()?;

    Ok((
        PushOk {
            revision: put.revision as u64,
            bytes: ciphertext.len(),
            files: manifest.files.len(),
        },
        config,
    ))
}

// -----------------------------------------------------------------------------
// Pull
// -----------------------------------------------------------------------------

pub async fn pull(
    session: Session,
    mut config: SyncConfig,
    kind: &str,
) -> Result<(PullOk, SyncConfig), SyncError> {
    let client = SyncClient::new(&session.server_url).with_token(session.token.clone());
    let Some(blob) = client.get_latest(kind).await? else {
        return Err(SyncError::Server {
            status: 404,
            code: "not_found".into(),
            message: "no blob on server yet — try pushing first".into(),
            current_revision: None,
        });
    };

    let ciphertext = B64
        .decode(&blob.ciphertext)
        .map_err(|e| SyncError::Crypto(format!("base64 ciphertext: {e}")))?;
    let archive = crypto::decrypt_bundle(&session.dek, &ciphertext)?;

    let dest = voidb_config_dir()?;
    let preserve = bundler::preserve_on_extract();
    bundler::extract(&dest, &archive, &preserve)?;

    let manifest: serde_json::Value = blob.manifest;
    let files = manifest
        .get("files")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);

    config.set_revision(kind, blob.revision as u64);
    config.last_synced_at = Some(chrono::Utc::now().to_rfc3339());
    config.save()?;

    Ok((
        PullOk {
            revision: blob.revision as u64,
            bytes: archive.len(),
            files,
            dest,
        },
        config,
    ))
}

// -----------------------------------------------------------------------------
// Object push
// -----------------------------------------------------------------------------

pub fn migrate_credential_object_mappings(
    mut config: SyncConfig,
) -> Result<(CredentialMappingMigrationOk, SyncConfig), SyncError> {
    let store = local_profile_store()?;
    let mut profiles = store
        .load_profiles()
        .map_err(|e| SyncError::Config(format!("load profiles: {e}")))?;
    profiles.sort_by(|left, right| left.id.cmp(&right.id));
    let credential_records = store
        .load_credential_records()
        .map_err(|e| SyncError::Config(format!("load credential records: {e}")))?;
    let ok = migrate_credential_object_mappings_for_profiles(
        &mut config,
        &profiles,
        &credential_records,
    );
    config.save()?;
    append_credential_sync_audit(credential_sync_audit_event(
        AuditOperation::CredentialSyncMappingMigrated,
        AuditEventStatus::Succeeded,
        None,
        None,
        json!({
            "migrated": ok.migrated,
            "skipped": ok.skipped,
            "scope": "explicit",
        }),
    ))?;
    Ok((ok, config))
}

pub async fn push_objects(
    session: Session,
    mut config: SyncConfig,
) -> Result<(ObjectPushOk, SyncConfig), SyncError> {
    let root = voidb_config_dir()?;
    let store = local_profile_store()?;
    let mut profiles = store
        .load_profiles()
        .map_err(|e| SyncError::Config(format!("load profiles: {e}")))?;
    profiles.sort_by(|left, right| left.id.cmp(&right.id));
    let credential_records = store
        .load_credential_records()
        .map_err(|e| SyncError::Config(format!("load credential records: {e}")))?;
    let mapping_migration = migrate_credential_object_mappings_for_profiles(
        &mut config,
        &profiles,
        &credential_records,
    );
    if mapping_migration.migrated > 0 {
        append_credential_sync_audit(credential_sync_audit_event(
            AuditOperation::CredentialSyncMappingMigrated,
            AuditEventStatus::Succeeded,
            None,
            None,
            json!({
                "migrated": mapping_migration.migrated,
                "skipped": mapping_migration.skipped,
                "scope": "object_push",
            }),
        ))?;
        config.save()?;
    }
    let app_config = AppConfig::load_from_path(&root.join("config.toml"))
        .map_err(|e| SyncError::Config(format!("load legacy credential material: {e}")))?;

    let client = SyncClient::new(&session.server_url).with_token(session.token.clone());
    let mut pushed_objects = 0usize;
    let mut pushed_bytes = 0usize;

    for pending in build_push_objects(
        &session,
        &mut config,
        &profiles,
        &credential_records,
        &app_config,
    )? {
        let response = put_pending_object(&client, &mut config, &pending).await?;

        record_mapping_revision(
            &mut config,
            MappingRevision {
                local_kind: &pending.local_kind,
                local_id: &pending.local_id,
                object_kind: response.object_kind.as_str(),
                object_id: response.object_id.as_str(),
                object_version: response.object_version,
                server_revision: response.server_revision,
                unavailable: false,
            },
        );
        config.set_revision("objects", response.server_revision);
        config.last_synced_at = Some(chrono::Utc::now().to_rfc3339());
        config.save()?;

        if let Some(audit) = &pending.credential_audit {
            append_credential_sync_audit(credential_sync_audit_event(
                AuditOperation::CredentialSyncPush,
                AuditEventStatus::Succeeded,
                Some(audit),
                None,
                json!({
                    "object_id": response.object_id,
                    "object_version": response.object_version,
                    "server_revision": response.server_revision,
                    "encrypted_bytes": pending.encrypted_bytes,
                }),
            ))?;
        }

        pushed_objects += 1;
        pushed_bytes += pending.encrypted_bytes;
    }

    Ok((
        ObjectPushOk {
            objects: pushed_objects,
            bytes: pushed_bytes,
        },
        config,
    ))
}

pub async fn reenroll_credential_record(
    session: Session,
    mut config: SyncConfig,
    input: CredentialReenrollInput,
) -> Result<(CredentialReenrollOk, SyncConfig), SyncError> {
    let root = voidb_config_dir()?;
    let store = local_profile_store()?;
    let profiles = store
        .load_profiles()
        .map_err(|e| SyncError::Config(format!("load profiles: {e}")))?;
    let profile = profiles
        .iter()
        .find(|profile| profile.id == input.profile_id)
        .ok_or_else(|| SyncError::Config(format!("profile not found: {}", input.profile_id)))?;
    let credential_ref = profile
        .credential_refs
        .iter()
        .find(|credential_ref| credential_ref.id == input.credential_ref_id)
        .ok_or_else(|| {
            SyncError::Config(format!(
                "credential ref not found: {}",
                input.credential_ref_id
            ))
        })?;

    let mut credential_records = store
        .load_credential_records()
        .map_err(|e| SyncError::Config(format!("load credential records: {e}")))?;
    let existing_record = credential_records
        .iter()
        .find(|record| record.profile_id == profile.id && record.id == credential_ref.id)
        .cloned();
    let material = match input.material {
        CredentialReenrollMaterial::Provided(material) => material,
        CredentialReenrollMaterial::ExistingLocal => {
            let app_config = AppConfig::load_from_path(&root.join("config.toml"))
                .map_err(|e| SyncError::Config(format!("load legacy credential material: {e}")))?;
            let record = existing_record.as_ref().ok_or_else(|| {
                SyncError::Config("credential record has no existing local material".into())
            })?;
            credential_material_for_push(record, &app_config).ok_or_else(|| {
                SyncError::Config("credential record local material is unavailable".into())
            })?
        }
    };
    let material_kind_label = material_kind(&material);

    let profile_mapping =
        ensure_mapping(&mut config, "profile", &profile.id, SyncObjectKind::Profile);
    let local_id = credential_ref_local_id(&profile.id, &credential_ref.id);
    let credential_mapping = ensure_mapping(
        &mut config,
        "credential_ref",
        &local_id,
        SyncObjectKind::CredentialRef,
    );
    let record_mapping = ensure_mapping(
        &mut config,
        "credential_record",
        &local_id,
        SyncObjectKind::CredentialRecord,
    );
    if profile_mapping.server_revision == 0 || credential_mapping.server_revision == 0 {
        return Err(SyncError::Config(
            "credential re-enroll requires synced profile and credential_ref objects; run object push or pull first".into(),
        ));
    }

    let object_version = record_mapping.object_version + 1;
    let record_for_payload = existing_record.unwrap_or_else(|| StoredCredentialRecord {
        id: credential_ref.id.clone(),
        profile_id: profile.id.clone(),
        plugin_id: profile.plugin_id.clone(),
        class: credential_ref.class.clone(),
        label: credential_ref.label.clone(),
        source: placeholder_synced_credential_source(
            &record_mapping,
            &profile_mapping.object_id,
            &credential_mapping.object_id,
            object_version,
        ),
        created_at: chrono::Utc::now(),
        redaction: RedactionStatus::Withheld,
    });
    let envelope = encrypt_credential_record_payload(
        &record_for_payload,
        material,
        CredentialRecordEncryptionParams {
            object_id: record_mapping.object_id.clone(),
            object_version,
            profile_object_id: profile_mapping.object_id.clone(),
            credential_ref_object_id: credential_mapping.object_id.clone(),
            sync_dek: &session.dek,
        },
    )
    .map_err(|e| SyncError::Crypto(format!("credential record envelope: {e}")))?;
    let audit =
        PendingCredentialAudit::from_record(&record_for_payload, credential_ref.label.clone());
    let pending = build_pending_object(
        &session,
        record_mapping,
        SyncObjectKind::CredentialRecord,
        &envelope,
        Some(audit.clone()),
    )?;

    let client = SyncClient::new(&session.server_url).with_token(session.token.clone());
    let response = put_pending_object(&client, &mut config, &pending).await?;

    record_mapping_revision(
        &mut config,
        MappingRevision {
            local_kind: &pending.local_kind,
            local_id: &pending.local_id,
            object_kind: response.object_kind.as_str(),
            object_id: response.object_id.as_str(),
            object_version: response.object_version,
            server_revision: response.server_revision,
            unavailable: false,
        },
    );
    config.set_revision("objects", response.server_revision);
    config.last_synced_at = Some(chrono::Utc::now().to_rfc3339());

    let synced_record = stored_credential_record_from_envelope(
        &record_for_payload,
        &envelope,
        response.server_revision,
        false,
        None,
    );
    if let Some(record) = credential_records.iter_mut().find(|record| {
        record.profile_id == synced_record.profile_id && record.id == synced_record.id
    }) {
        *record = synced_record;
    } else {
        credential_records.push(synced_record);
    }
    store
        .save_credential_records(credential_records)
        .map_err(|e| SyncError::Config(format!("write credential records: {e}")))?;
    config.save()?;

    append_credential_sync_audit(credential_sync_audit_event(
        AuditOperation::CredentialSyncReenroll,
        AuditEventStatus::Succeeded,
        Some(&audit),
        None,
        json!({
            "object_id": response.object_id,
            "object_version": response.object_version,
            "server_revision": response.server_revision,
            "encrypted_bytes": pending.encrypted_bytes,
            "material_kind": material_kind_label,
        }),
    ))?;

    Ok((
        CredentialReenrollOk {
            object_id: response.object_id,
            object_version: response.object_version,
            server_revision: response.server_revision,
            bytes: pending.encrypted_bytes,
        },
        config,
    ))
}

pub async fn resolve_keep_local_force(
    session: Session,
    mut config: SyncConfig,
    input: ObjectConflictResolutionInput,
) -> Result<(ObjectConflictResolutionOk, SyncConfig), SyncError> {
    let client = SyncClient::new(&session.server_url).with_token(session.token.clone());
    let remote = latest_object_for_resolution(&client, &input).await?;
    let current_revision = require_current_revision(&input, &remote, "keep-local-force")?;
    let mut mapping = mapping_for_resolution(&config, &input.object_kind, &input.object_id)?;
    if mapping.object_kind == "credential_record" {
        return Err(SyncError::Config(
            "credential_record conflicts require sync credential re-enroll or credential handoff; force push is not allowed".into(),
        ));
    }

    mapping.server_revision = current_revision;
    mapping.object_version = remote.object_version;
    let pending = build_local_pending_object(&session, &config, mapping)?;
    let response = put_pending_object(&client, &mut config, &pending).await?;
    let ok = finish_object_put_resolution(
        &mut config,
        &pending,
        &response,
        ObjectPutResolutionMeta {
            unavailable: false,
            mode: "keep-local-force",
            local_action: "force-pushed local object",
            previous_server_revision: current_revision,
            operation: AuditOperation::SyncObjectForcePush,
        },
    )?;
    Ok((ok, config))
}

pub async fn resolve_keep_remote(
    session: Session,
    mut config: SyncConfig,
    input: ObjectConflictResolutionInput,
) -> Result<(ObjectConflictResolutionOk, SyncConfig), SyncError> {
    let client = SyncClient::new(&session.server_url).with_token(session.token.clone());
    let remote = latest_object_for_resolution(&client, &input).await?;
    if let Some(expected) = input.current_server_revision
        && expected != remote.server_revision
    {
        return Err(SyncError::Config(format!(
            "keep-remote expected server revision {expected}, but latest is {}",
            remote.server_revision
        )));
    }

    let previous_revision = config
        .mapping_by_object_id(&input.object_id)
        .map(|mapping| mapping.server_revision)
        .unwrap_or_default();
    let applied = apply_remote_object(&session, &mut config, remote)?;
    let ok = ObjectConflictResolutionOk {
        mode: "keep-remote".into(),
        object_kind: applied.object_kind,
        object_id: applied.object_id,
        object_version: applied.object_version,
        server_revision: applied.server_revision,
        previous_server_revision: previous_revision,
        bytes: applied.bytes,
        local_action: applied.local_action,
        unavailable: applied.unavailable,
    };
    append_sync_audit(sync_object_resolution_audit_event(
        AuditOperation::SyncObjectKeepRemote,
        &ok,
    ))?;
    Ok((ok, config))
}

pub async fn resolve_merge(
    session: Session,
    mut config: SyncConfig,
    input: ObjectConflictResolutionInput,
) -> Result<(ObjectConflictResolutionOk, SyncConfig), SyncError> {
    let client = SyncClient::new(&session.server_url).with_token(session.token.clone());
    let remote = latest_object_for_resolution(&client, &input).await?;
    let current_revision = require_current_revision(&input, &remote, "merge")?;
    if remote.deleted {
        return Err(SyncError::Config(
            "cannot merge a deleted remote object".into(),
        ));
    }

    let mapping = mapping_for_resolution(&config, &input.object_kind, &input.object_id)?;
    let payload = decrypt_object_payload(&session, &remote)?;
    let mut force_mapping = mapping.clone();
    force_mapping.server_revision = current_revision;
    force_mapping.object_version = remote.object_version;

    let store = local_profile_store()?;
    let mut profiles = store
        .load_profiles()
        .map_err(|e| SyncError::Config(format!("load profiles: {e}")))?;

    let (pending, local_action) = match mapping.object_kind.as_str() {
        "profile_policy" => {
            let remote_policy: SyncProfilePolicyPayload = serde_json::from_value(payload)
                .map_err(|e| SyncError::Bundle(format!("profile policy payload: {e}")))?;
            let profile = profiles
                .iter_mut()
                .find(|profile| profile.id == mapping.local_id)
                .ok_or_else(|| {
                    SyncError::Config(format!("profile not found: {}", mapping.local_id))
                })?;
            let merged = merge_profile_policy(&profile.policy, &remote_policy.policy);
            let profile_mapping =
                config
                    .object_mapping("profile", &profile.id)
                    .ok_or_else(|| {
                        SyncError::Config(format!("profile mapping not found: {}", profile.id))
                    })?;
            let payload = sync_profile_policy_payload(profile_mapping.object_id.clone(), &merged);
            profile.policy = merged;
            (
                build_pending_object(
                    &session,
                    force_mapping,
                    SyncObjectKind::ProfilePolicy,
                    &payload,
                    None,
                )?,
                "merged profile policy",
            )
        }
        "profile" => {
            let remote_profile: SyncProfilePayload = serde_json::from_value(payload)
                .map_err(|e| SyncError::Bundle(format!("profile payload: {e}")))?;
            let profile = profiles
                .iter_mut()
                .find(|profile| profile.id == mapping.local_id)
                .ok_or_else(|| {
                    SyncError::Config(format!("profile not found: {}", mapping.local_id))
                })?;
            merge_profile_payload(profile, &remote_profile)?;
            let policy_ref = config
                .object_mapping("profile_policy", &profile.id)
                .map(|mapping| mapping.object_id.clone());
            let compatibility_ref = config
                .object_mapping("plugin_compatibility", &profile.plugin_id)
                .map(|mapping| mapping.object_id.clone());
            let payload = sync_profile_payload(profile, policy_ref, compatibility_ref);
            (
                build_pending_object(
                    &session,
                    force_mapping,
                    SyncObjectKind::Profile,
                    &payload,
                    None,
                )?,
                "merged profile metadata",
            )
        }
        "app_preference" => {
            let remote_pref: SyncAppPreferencePayload = serde_json::from_value(payload)
                .map_err(|e| SyncError::Bundle(format!("app preference payload: {e}")))?;
            let local_pref = app_preference_payload();
            let merged_preferences = merge_json_without_scalar_conflicts(
                &local_pref.preferences,
                &remote_pref.preferences,
                "app_preference.preferences",
            )?;
            let payload = SyncAppPreferencePayload {
                payload_version: OBJECT_SYNC_PAYLOAD_VERSION,
                preferences: merged_preferences,
            };
            (
                build_pending_object(
                    &session,
                    force_mapping,
                    SyncObjectKind::AppPreference,
                    &payload,
                    None,
                )?,
                "merged app preferences",
            )
        }
        other => {
            return Err(SyncError::Config(format!(
                "merge is not supported for object kind {other}"
            )));
        }
    };

    let response = put_pending_object(&client, &mut config, &pending).await?;
    store
        .save_profiles(profiles)
        .map_err(|e| SyncError::Config(format!("write profiles: {e}")))?;
    let ok = finish_object_put_resolution(
        &mut config,
        &pending,
        &response,
        ObjectPutResolutionMeta {
            unavailable: false,
            mode: "merge",
            local_action,
            previous_server_revision: current_revision,
            operation: AuditOperation::SyncObjectMerge,
        },
    )?;
    Ok((ok, config))
}

pub async fn resolve_delete_tombstone(
    session: Session,
    mut config: SyncConfig,
    input: ObjectConflictResolutionInput,
) -> Result<(ObjectConflictResolutionOk, SyncConfig), SyncError> {
    if !input.acknowledge_delete {
        return Err(SyncError::Config(
            "delete-tombstone requires --acknowledge-delete".into(),
        ));
    }

    let client = SyncClient::new(&session.server_url).with_token(session.token.clone());
    let remote = latest_object_for_resolution(&client, &input).await?;
    let current_revision = require_current_revision(&input, &remote, "delete-tombstone")?;
    let mut mapping = mapping_for_resolution(&config, &input.object_kind, &input.object_id)?;
    mapping.server_revision = current_revision;
    mapping.object_version = remote.object_version;
    let kind = sync_object_kind_from_str(&mapping.object_kind)?;
    let payload = json!({
        "payload_version": OBJECT_SYNC_PAYLOAD_VERSION,
        "object_kind": mapping.object_kind,
        "object_id": mapping.object_id,
        "deleted": true,
    });
    let pending = build_pending_object_with_deleted(&session, mapping, kind, &payload, None, true)?;
    let response = put_pending_object(&client, &mut config, &pending).await?;
    apply_local_tombstone_effect(&pending.local_kind, &pending.local_id)?;
    let ok = finish_object_put_resolution(
        &mut config,
        &pending,
        &response,
        ObjectPutResolutionMeta {
            unavailable: true,
            mode: "delete-tombstone",
            local_action: "wrote tombstone and removed local object",
            previous_server_revision: current_revision,
            operation: AuditOperation::SyncObjectTombstone,
        },
    )?;
    Ok((ok, config))
}

pub fn credential_conflict_handoff(
    config: SyncConfig,
    object_id: &str,
) -> Result<CredentialConflictHandoffOk, SyncError> {
    let conflict = config
        .object_conflicts
        .values()
        .find(|conflict| conflict.object_id == object_id);
    if let Some(conflict) = conflict
        && conflict.object_kind != "credential_record"
    {
        return Err(SyncError::Config(format!(
            "credential handoff only supports credential_record conflicts, got {}",
            conflict.object_kind
        )));
    }
    let mapping = config
        .mapping_by_object_id(object_id)
        .ok_or_else(|| SyncError::Config(format!("object mapping not found: {object_id}")))?;
    if mapping.object_kind != "credential_record" {
        return Err(SyncError::Config(format!(
            "credential handoff only supports credential_record mappings, got {}",
            mapping.object_kind
        )));
    }
    if conflict.is_none() && !mapping.unavailable {
        return Err(SyncError::Config(format!(
            "credential handoff requires a conflict or unavailable credential mapping for object: {object_id}"
        )));
    }
    let store = local_profile_store()?;
    let profiles = store
        .load_profiles()
        .map_err(|e| SyncError::Config(format!("load profiles: {e}")))?;
    let (profile_id, credential_ref_id) = credential_local_parts(&profiles, &mapping.local_id)
        .ok_or_else(|| {
            SyncError::Config(format!(
                "credential mapping local id is not resolvable: {}",
                mapping.local_id
            ))
        })?;
    let command = format!(
        "VOIDB_SYNC_CREDENTIAL_SECRET=<secret> voidb sync credential re-enroll --profile {} --credential {} --secret-env VOIDB_SYNC_CREDENTIAL_SECRET",
        profile_id, credential_ref_id
    );
    let unavailable_reason = conflict
        .and_then(|conflict| conflict.unavailable_reason.clone())
        .or_else(|| mapping.unavailable_reason.clone());
    append_sync_audit(credential_sync_audit_event(
        AuditOperation::CredentialSyncReenrollHandoff,
        AuditEventStatus::Blocked,
        None,
        unavailable_reason.as_deref(),
        json!({
            "object_id": object_id,
            "object_kind": "credential_record",
            "redacted": true,
        }),
    ))?;
    Ok(CredentialConflictHandoffOk {
        object_id: object_id.to_string(),
        profile_id,
        credential_ref_id,
        unavailable_reason,
        command,
    })
}

fn build_push_objects(
    session: &Session,
    config: &mut SyncConfig,
    profiles: &[ConnectionProfile],
    credential_records: &[StoredCredentialRecord],
    app_config: &AppConfig,
) -> Result<Vec<PendingObject>, SyncError> {
    let mut objects = Vec::new();
    let plugin_ids = profiles
        .iter()
        .map(|profile| profile.plugin_id.clone())
        .collect::<BTreeSet<_>>();

    for plugin_id in &plugin_ids {
        let mapping = ensure_mapping(
            config,
            "plugin_compatibility",
            plugin_id,
            SyncObjectKind::PluginCompatibility,
        );
        let payload = SyncPluginCompatibilityPayload {
            payload_version: OBJECT_SYNC_PAYLOAD_VERSION,
            plugin_id: plugin_id.clone(),
            profile_schema_id: format!("{plugin_id}.profile"),
            profile_schema_version: 1,
            minimum_plugin_version: None,
            capability_contracts: Vec::new(),
        };
        objects.push(build_pending_object(
            session,
            mapping,
            SyncObjectKind::PluginCompatibility,
            &payload,
            None,
        )?);
    }

    for profile in profiles {
        let profile_mapping =
            ensure_mapping(config, "profile", &profile.id, SyncObjectKind::Profile);
        let policy_mapping = ensure_mapping(
            config,
            "profile_policy",
            &profile.id,
            SyncObjectKind::ProfilePolicy,
        );
        let plugin_mapping = ensure_mapping(
            config,
            "plugin_compatibility",
            &profile.plugin_id,
            SyncObjectKind::PluginCompatibility,
        );
        let policy_object_id = policy_mapping.object_id.clone();

        let policy_payload =
            sync_profile_policy_payload(profile_mapping.object_id.clone(), &profile.policy);
        objects.push(build_pending_object(
            session,
            policy_mapping,
            SyncObjectKind::ProfilePolicy,
            &policy_payload,
            None,
        )?);

        for credential_ref in &profile.credential_refs {
            let local_id = credential_ref_local_id(&profile.id, &credential_ref.id);
            let credential_mapping = ensure_mapping(
                config,
                "credential_ref",
                &local_id,
                SyncObjectKind::CredentialRef,
            );
            let credential_ref_object_id = credential_mapping.object_id.clone();
            let payload =
                sync_credential_ref_payload(profile_mapping.object_id.clone(), credential_ref);
            objects.push(build_pending_object(
                session,
                credential_mapping,
                SyncObjectKind::CredentialRef,
                &payload,
                None,
            )?);

            if let Some(record) = credential_records
                .iter()
                .find(|record| record.id == credential_ref.id)
                && let Some(material) = credential_material_for_push(record, app_config)
            {
                let record_mapping = ensure_mapping(
                    config,
                    "credential_record",
                    &local_id,
                    SyncObjectKind::CredentialRecord,
                );
                let object_version = record_mapping.object_version + 1;
                let envelope = encrypt_credential_record_payload(
                    record,
                    material,
                    CredentialRecordEncryptionParams {
                        object_id: record_mapping.object_id.clone(),
                        object_version,
                        profile_object_id: profile_mapping.object_id.clone(),
                        credential_ref_object_id: credential_ref_object_id.clone(),
                        sync_dek: &session.dek,
                    },
                )
                .map_err(|e| SyncError::Crypto(format!("credential record envelope: {e}")))?;
                objects.push(build_pending_object(
                    session,
                    record_mapping,
                    SyncObjectKind::CredentialRecord,
                    &envelope,
                    Some(PendingCredentialAudit::from_record(
                        record,
                        credential_ref.label.clone(),
                    )),
                )?);
            }
        }

        let profile_payload = sync_profile_payload(
            profile,
            Some(policy_object_id),
            Some(plugin_mapping.object_id),
        );
        objects.push(build_pending_object(
            session,
            profile_mapping,
            SyncObjectKind::Profile,
            &profile_payload,
            None,
        )?);
    }

    let app_mapping = ensure_mapping(
        config,
        "app_preference",
        "object_sync",
        SyncObjectKind::AppPreference,
    );
    let app_payload = SyncAppPreferencePayload {
        payload_version: OBJECT_SYNC_PAYLOAD_VERSION,
        preferences: json!({
            "object_sync": {
                "safe_kinds": [
                    "profile",
                    "profile_policy",
                    "credential_ref",
                    "credential_record",
                    "plugin_compatibility",
                    "app_preference"
                ],
                "bundle_compatibility": "manual_backup"
            }
        }),
    };
    objects.push(build_pending_object(
        session,
        app_mapping,
        SyncObjectKind::AppPreference,
        &app_payload,
        None,
    )?);

    Ok(objects)
}

fn migrate_credential_object_mappings_for_profiles(
    config: &mut SyncConfig,
    profiles: &[ConnectionProfile],
    credential_records: &[StoredCredentialRecord],
) -> CredentialMappingMigrationOk {
    let mut migrated = 0usize;
    let mut skipped = 0usize;

    for record in credential_records {
        let Some(profile) = profiles
            .iter()
            .find(|profile| profile.id == record.profile_id)
        else {
            skipped += 1;
            continue;
        };
        let Some(credential_ref) = profile
            .credential_refs
            .iter()
            .find(|credential_ref| credential_ref.id == record.id)
        else {
            skipped += 1;
            continue;
        };

        ensure_mapping(config, "profile", &profile.id, SyncObjectKind::Profile);
        ensure_mapping(
            config,
            "credential_ref",
            &credential_ref_local_id(&profile.id, &credential_ref.id),
            SyncObjectKind::CredentialRef,
        );
        let local_id = credential_ref_local_id(&record.profile_id, &record.id);
        if config
            .object_mapping("credential_record", &local_id)
            .is_none()
        {
            migrated += 1;
        }
        ensure_mapping(
            config,
            "credential_record",
            &local_id,
            SyncObjectKind::CredentialRecord,
        );
    }

    CredentialMappingMigrationOk { migrated, skipped }
}

fn credential_material_for_push(
    record: &StoredCredentialRecord,
    app_config: &AppConfig,
) -> Option<CredentialRecordSecretMaterial> {
    let StoredCredentialSource::LegacyPluginConfig {
        legacy_connection_key,
        path,
    } = &record.source
    else {
        return None;
    };

    let connection = app_config
        .connections
        .iter()
        .find(|connection| connection.connection_key() == *legacy_connection_key)?;
    let plugin_config = connection.plugin_config.as_ref()?;
    let value = value_at_credential_path(plugin_config, path)?;

    match value {
        Value::String(secret) => Some(CredentialRecordSecretMaterial::Utf8 {
            value: secret.clone(),
        }),
        Value::Null => None,
        other => Some(CredentialRecordSecretMaterial::Json {
            value: other.clone(),
        }),
    }
}

fn value_at_credential_path<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    let path = path.strip_prefix("plugin_config.").unwrap_or(path);
    let mut current = value;
    for segment in path.split('.') {
        if segment.is_empty() {
            continue;
        }
        current = value_at_path_segment(current, segment)?;
    }
    Some(current)
}

fn value_at_path_segment<'a>(value: &'a Value, segment: &str) -> Option<&'a Value> {
    let mut field_end = segment.find('[').unwrap_or(segment.len());
    if field_end == 0 {
        field_end = segment.len();
    }
    let mut current = value.get(&segment[..field_end])?;
    let mut rest = &segment[field_end..];
    while let Some(after_open) = rest.strip_prefix('[') {
        let close = after_open.find(']')?;
        let index = after_open[..close].parse::<usize>().ok()?;
        current = current.get(index)?;
        rest = &after_open[close + 1..];
    }
    rest.is_empty().then_some(current)
}

fn ensure_mapping(
    config: &mut SyncConfig,
    local_kind: &str,
    local_id: &str,
    object_kind: SyncObjectKind,
) -> SyncObjectMapping {
    config.ensure_object_mapping(local_kind, local_id, object_kind.manifest_key(), || {
        new_object_id(object_kind)
    })
}

fn build_pending_object<T: Serialize>(
    session: &Session,
    mapping: SyncObjectMapping,
    object_kind: SyncObjectKind,
    payload: &T,
    credential_audit: Option<PendingCredentialAudit>,
) -> Result<PendingObject, SyncError> {
    build_pending_object_with_deleted(
        session,
        mapping,
        object_kind,
        payload,
        credential_audit,
        false,
    )
}

fn build_pending_object_with_deleted<T: Serialize>(
    session: &Session,
    mapping: SyncObjectMapping,
    object_kind: SyncObjectKind,
    payload: &T,
    credential_audit: Option<PendingCredentialAudit>,
    deleted: bool,
) -> Result<PendingObject, SyncError> {
    let payload_bytes =
        serde_json::to_vec(payload).map_err(|e| SyncError::Bundle(format!("object json: {e}")))?;
    let encrypted = crypto::encrypt_bundle(&session.dek, &payload_bytes)?;
    let payload_hash = sha256_hash(&encrypted);
    let ciphertext = B64.encode(&encrypted);
    let encrypted_payload = EncryptedSyncPayload::new(payload_hash, ciphertext)
        .map_err(|e| SyncError::Crypto(e.to_string()))?;
    let object_version = mapping.object_version + 1;
    let base_server_revision = (mapping.server_revision > 0).then_some(mapping.server_revision);
    let envelope = sync_object_envelope(SyncObjectEnvelopeInput {
        object_id: mapping.object_id.clone(),
        object_kind,
        object_version,
        base_server_revision,
        encrypted_payload,
        updated_at: chrono::Utc::now(),
        updated_by: SyncObjectActor::new(sync_actor(), session.device_id.clone()),
        deleted,
        redaction: RedactionStatus::Withheld,
    })
    .map_err(|e| SyncError::Config(format!("invalid sync object envelope: {e}")))?;

    Ok(PendingObject {
        local_kind: mapping.local_kind,
        local_id: mapping.local_id,
        encrypted_bytes: encrypted.len(),
        envelope,
        credential_audit,
    })
}

async fn put_pending_object(
    client: &SyncClient,
    config: &mut SyncConfig,
    pending: &PendingObject,
) -> Result<PutObjectResponse, SyncError> {
    let request = put_request_from_envelope(&pending.envelope);
    match client
        .put_object(&pending.envelope.object_id, &request)
        .await
    {
        Ok(response) => Ok(response),
        Err(SyncError::ObjectConflict {
            object_id,
            object_kind,
            details,
        }) => {
            let conflict =
                sync_object_conflict_from_pending(pending, &object_id, &object_kind, &details);
            config.record_object_conflict(conflict.clone());
            config.save()?;
            append_sync_audit(sync_object_conflict_audit_event(&conflict))?;
            Err(SyncError::ObjectConflict {
                object_id,
                object_kind,
                details,
            })
        }
        Err(error) => Err(error),
    }
}

fn sync_object_conflict_from_pending(
    pending: &PendingObject,
    object_id: &str,
    object_kind: &str,
    details: &ObjectConflictDetails,
) -> SyncObjectConflict {
    SyncObjectConflict {
        object_kind: object_kind.to_string(),
        object_id: object_id.to_string(),
        local_kind: Some(pending.local_kind.clone()),
        local_id: Some(pending.local_id.clone()),
        attempted_base_server_revision: details.attempted_base_server_revision,
        current_server_revision: details.current_server_revision,
        attempted_object_version: details.attempted_object_version,
        current_object_version: details.current_object_version,
        detected_at: chrono::Utc::now().to_rfc3339(),
        server_updated_at: details.server_updated_at.clone(),
        redaction: details.redaction.clone(),
        unavailable_reason: Some("object_revision_conflict".to_string()),
    }
}

fn put_request_from_envelope(envelope: &SyncObjectEnvelope) -> PutObjectRequest {
    PutObjectRequest {
        schema_version: envelope.schema_version,
        object_kind: envelope.object_kind.manifest_key().to_string(),
        object_version: envelope.object_version,
        base_server_revision: envelope.base_server_revision,
        payload_hash: envelope.payload_hash.clone(),
        payload_size: envelope.payload_size,
        updated_at: envelope.updated_at.to_rfc3339(),
        updated_by: ObjectActor {
            actor_type: actor_type_label(envelope.updated_by.actor_type).to_string(),
            actor_id: envelope.updated_by.actor_id.clone(),
            device_id: envelope.updated_by.device_id.clone(),
        },
        deleted: envelope.deleted,
        redaction: redaction_label(envelope.redaction).to_string(),
        ciphertext: envelope.ciphertext.clone(),
    }
}

struct PendingObject {
    local_kind: String,
    local_id: String,
    encrypted_bytes: usize,
    envelope: SyncObjectEnvelope,
    credential_audit: Option<PendingCredentialAudit>,
}

#[derive(Debug, Clone)]
struct PendingCredentialAudit {
    profile_id: String,
    plugin_id: String,
    credential_ref: CredentialRef,
}

impl PendingCredentialAudit {
    fn from_record(record: &StoredCredentialRecord, label: Option<String>) -> Self {
        Self {
            profile_id: record.profile_id.clone(),
            plugin_id: record.plugin_id.clone(),
            credential_ref: CredentialRef {
                id: record.id.clone(),
                class: record.class.clone(),
                label,
            },
        }
    }
}

struct AppliedRemoteObject {
    object_kind: String,
    object_id: String,
    object_version: u64,
    server_revision: u64,
    bytes: usize,
    local_action: String,
    unavailable: bool,
}

struct ObjectPutResolutionMeta<'a> {
    unavailable: bool,
    mode: &'a str,
    local_action: &'a str,
    previous_server_revision: u64,
    operation: AuditOperation,
}

async fn latest_object_for_resolution(
    client: &SyncClient,
    input: &ObjectConflictResolutionInput,
) -> Result<ObjectResponse, SyncError> {
    let object = client
        .get_object_latest(&input.object_id)
        .await?
        .ok_or_else(|| SyncError::Config(format!("object not found: {}", input.object_id)))?;
    if object.object_kind != input.object_kind {
        return Err(SyncError::Config(format!(
            "object kind mismatch: expected {}, got {}",
            input.object_kind, object.object_kind
        )));
    }
    Ok(object)
}

fn require_current_revision(
    input: &ObjectConflictResolutionInput,
    remote: &ObjectResponse,
    mode: &str,
) -> Result<u64, SyncError> {
    let expected = input.current_server_revision.ok_or_else(|| {
        SyncError::Config(format!(
            "{mode} requires --current-server-revision {}",
            remote.server_revision
        ))
    })?;
    if expected != remote.server_revision {
        return Err(SyncError::Config(format!(
            "{mode} expected server revision {expected}, but latest is {}",
            remote.server_revision
        )));
    }
    Ok(expected)
}

fn mapping_for_resolution(
    config: &SyncConfig,
    object_kind: &str,
    object_id: &str,
) -> Result<SyncObjectMapping, SyncError> {
    let mapping = config
        .mapping_by_object_id(object_id)
        .cloned()
        .ok_or_else(|| SyncError::Config(format!("object mapping not found: {object_id}")))?;
    if mapping.object_kind != object_kind {
        return Err(SyncError::Config(format!(
            "local mapping kind mismatch: expected {object_kind}, got {}",
            mapping.object_kind
        )));
    }
    Ok(mapping)
}

fn sync_object_kind_from_str(kind: &str) -> Result<SyncObjectKind, SyncError> {
    match kind {
        "profile" => Ok(SyncObjectKind::Profile),
        "credential_ref" => Ok(SyncObjectKind::CredentialRef),
        "profile_policy" => Ok(SyncObjectKind::ProfilePolicy),
        "plugin_compatibility" => Ok(SyncObjectKind::PluginCompatibility),
        "credential_record" => Ok(SyncObjectKind::CredentialRecord),
        "app_preference" => Ok(SyncObjectKind::AppPreference),
        other => Err(SyncError::Config(format!(
            "unsupported object kind: {other}"
        ))),
    }
}

fn build_local_pending_object(
    session: &Session,
    config: &SyncConfig,
    mapping: SyncObjectMapping,
) -> Result<PendingObject, SyncError> {
    let kind = sync_object_kind_from_str(&mapping.object_kind)?;
    match kind {
        SyncObjectKind::Profile => {
            let store = local_profile_store()?;
            let profiles = store
                .load_profiles()
                .map_err(|e| SyncError::Config(format!("load profiles: {e}")))?;
            let profile = profiles
                .iter()
                .find(|profile| profile.id == mapping.local_id)
                .ok_or_else(|| SyncError::Config(format!("profile not found: {}", mapping.local_id)))?;
            let policy_ref = config
                .object_mapping("profile_policy", &profile.id)
                .map(|mapping| mapping.object_id.clone());
            let compatibility_ref = config
                .object_mapping("plugin_compatibility", &profile.plugin_id)
                .map(|mapping| mapping.object_id.clone());
            let payload = sync_profile_payload(profile, policy_ref, compatibility_ref);
            build_pending_object(session, mapping, kind, &payload, None)
        }
        SyncObjectKind::ProfilePolicy => {
            let store = local_profile_store()?;
            let profiles = store
                .load_profiles()
                .map_err(|e| SyncError::Config(format!("load profiles: {e}")))?;
            let profile = profiles
                .iter()
                .find(|profile| profile.id == mapping.local_id)
                .ok_or_else(|| SyncError::Config(format!("profile not found: {}", mapping.local_id)))?;
            let profile_mapping = config
                .object_mapping("profile", &profile.id)
                .ok_or_else(|| SyncError::Config(format!("profile mapping not found: {}", profile.id)))?;
            let payload = sync_profile_policy_payload(profile_mapping.object_id.clone(), &profile.policy);
            build_pending_object(session, mapping, kind, &payload, None)
        }
        SyncObjectKind::CredentialRef => {
            let store = local_profile_store()?;
            let profiles = store
                .load_profiles()
                .map_err(|e| SyncError::Config(format!("load profiles: {e}")))?;
            let (profile_id, credential_ref_id) = credential_local_parts(&profiles, &mapping.local_id)
                .ok_or_else(|| {
                    SyncError::Config(format!(
                        "credential ref mapping local id is not resolvable: {}",
                        mapping.local_id
                    ))
                })?;
            let profile = profiles
                .iter()
                .find(|profile| profile.id == profile_id)
                .ok_or_else(|| SyncError::Config(format!("profile not found: {profile_id}")))?;
            let credential_ref = profile
                .credential_refs
                .iter()
                .find(|credential_ref| credential_ref.id == credential_ref_id)
                .ok_or_else(|| {
                    SyncError::Config(format!("credential ref not found: {credential_ref_id}"))
                })?;
            let profile_mapping = config
                .object_mapping("profile", &profile.id)
                .ok_or_else(|| SyncError::Config(format!("profile mapping not found: {}", profile.id)))?;
            let payload = sync_credential_ref_payload(profile_mapping.object_id.clone(), credential_ref);
            build_pending_object(session, mapping, kind, &payload, None)
        }
        SyncObjectKind::PluginCompatibility => {
            let payload = SyncPluginCompatibilityPayload {
                payload_version: OBJECT_SYNC_PAYLOAD_VERSION,
                plugin_id: mapping.local_id.clone(),
                profile_schema_id: format!("{}.profile", mapping.local_id),
                profile_schema_version: 1,
                minimum_plugin_version: None,
                capability_contracts: Vec::new(),
            };
            build_pending_object(session, mapping, kind, &payload, None)
        }
        SyncObjectKind::AppPreference => {
            let payload = app_preference_payload();
            build_pending_object(session, mapping, kind, &payload, None)
        }
        SyncObjectKind::CredentialRecord => Err(SyncError::Config(
            "credential_record conflicts require sync credential re-enroll; no plaintext diff is available".into(),
        )),
    }
}

fn apply_remote_object(
    session: &Session,
    config: &mut SyncConfig,
    object: ObjectResponse,
) -> Result<AppliedRemoteObject, SyncError> {
    let bytes = object.ciphertext.len();
    if object.deleted {
        if let Some(mapping) = config.mapping_by_object_id(&object.object_id).cloned() {
            apply_local_tombstone_effect(&mapping.local_kind, &mapping.local_id)?;
            record_mapping_revision(
                config,
                MappingRevision {
                    local_kind: &mapping.local_kind,
                    local_id: &mapping.local_id,
                    object_kind: &object.object_kind,
                    object_id: &object.object_id,
                    object_version: object.object_version,
                    server_revision: object.server_revision,
                    unavailable: true,
                },
            );
        }
        config.set_revision("objects", object.server_revision);
        config.last_synced_at = Some(chrono::Utc::now().to_rfc3339());
        config.save()?;
        return Ok(AppliedRemoteObject {
            object_kind: object.object_kind,
            object_id: object.object_id,
            object_version: object.object_version,
            server_revision: object.server_revision,
            bytes,
            local_action: "applied remote tombstone".into(),
            unavailable: true,
        });
    }

    let payload = decrypt_object_payload(session, &object)?;
    let store = local_profile_store()?;
    let mut profiles_by_id = store
        .load_profiles()
        .map_err(|e| SyncError::Config(format!("load profiles: {e}")))?
        .into_iter()
        .map(|profile| (profile.id.clone(), profile))
        .collect::<BTreeMap<_, _>>();
    let mut credential_records_by_id = store
        .load_credential_records()
        .map_err(|e| SyncError::Config(format!("load credential records: {e}")))?
        .into_iter()
        .map(|record| (record.id.clone(), record))
        .collect::<BTreeMap<_, _>>();

    let mut local_kind = object.object_kind.clone();
    let mut local_id = config
        .mapping_by_object_id(&object.object_id)
        .map(|mapping| mapping.local_id.clone())
        .unwrap_or_else(|| object.object_id.clone());
    let mut local_action = "applied remote object".to_string();
    let unavailable = false;

    match object.object_kind.as_str() {
        "profile" => {
            let payload: SyncProfilePayload = serde_json::from_value(payload)
                .map_err(|e| SyncError::Bundle(format!("profile payload: {e}")))?;
            let existing = profiles_by_id.get(&payload.profile.id).cloned();
            let credential_refs = existing
                .as_ref()
                .map(|profile| profile.credential_refs.clone())
                .unwrap_or_default();
            let policy = existing
                .as_ref()
                .map(|profile| profile.policy.clone())
                .unwrap_or_default();
            let profile = connection_profile_from_sync(payload, policy, credential_refs);
            local_kind = "profile".into();
            local_id = profile.id.clone();
            profiles_by_id.insert(profile.id.clone(), profile);
            store
                .save_profiles(profiles_by_id.into_values().collect())
                .map_err(|e| SyncError::Config(format!("write profiles: {e}")))?;
            local_action = "replaced local profile metadata".into();
        }
        "profile_policy" => {
            let payload: SyncProfilePolicyPayload = serde_json::from_value(payload)
                .map_err(|e| SyncError::Bundle(format!("profile policy payload: {e}")))?;
            let profile_id = config
                .mapping_by_object_id(&payload.profile_object_id)
                .map(|mapping| mapping.local_id.clone())
                .or_else(|| {
                    config
                        .mapping_by_object_id(&object.object_id)
                        .map(|mapping| mapping.local_id.clone())
                })
                .ok_or_else(|| SyncError::Config("profile mapping not found for policy".into()))?;
            let profile = profiles_by_id
                .get_mut(&profile_id)
                .ok_or_else(|| SyncError::Config(format!("profile not found: {profile_id}")))?;
            profile.policy = payload.policy;
            local_kind = "profile_policy".into();
            local_id = profile_id;
            store
                .save_profiles(profiles_by_id.into_values().collect())
                .map_err(|e| SyncError::Config(format!("write profiles: {e}")))?;
            local_action = "replaced local profile policy".into();
        }
        "credential_ref" => {
            let payload: SyncCredentialRefPayload = serde_json::from_value(payload)
                .map_err(|e| SyncError::Bundle(format!("credential ref payload: {e}")))?;
            let profile_id = config
                .mapping_by_object_id(&payload.profile_object_id)
                .map(|mapping| mapping.local_id.clone())
                .ok_or_else(|| {
                    SyncError::Config("profile mapping not found for credential_ref".into())
                })?;
            let profile = profiles_by_id
                .get_mut(&profile_id)
                .ok_or_else(|| SyncError::Config(format!("profile not found: {profile_id}")))?;
            let credential_ref = CredentialRef {
                id: payload.credential_ref.id,
                class: payload.credential_ref.class,
                label: payload.credential_ref.label,
            };
            if let Some(existing) = profile
                .credential_refs
                .iter_mut()
                .find(|candidate| candidate.id == credential_ref.id)
            {
                *existing = credential_ref.clone();
            } else {
                profile.credential_refs.push(credential_ref.clone());
            }
            local_kind = "credential_ref".into();
            local_id = credential_ref_local_id(&profile_id, &credential_ref.id);
            store
                .save_profiles(profiles_by_id.into_values().collect())
                .map_err(|e| SyncError::Config(format!("write profiles: {e}")))?;
            local_action = "replaced local credential ref".into();
        }
        "credential_record" => {
            let envelope: EncryptedCredentialRecordEnvelope = serde_json::from_value(payload)
                .map_err(|e| SyncError::Bundle(format!("credential record payload: {e}")))?;
            let pulled = PulledCredentialRecord {
                object: object.clone(),
                envelope,
            };
            match stored_credential_record_from_sync(session, &pulled) {
                Ok(record) => {
                    local_kind = "credential_record".into();
                    local_id = credential_ref_local_id(&record.profile_id, &record.id);
                    let audit = PendingCredentialAudit::from_record(&record, record.label.clone());
                    credential_records_by_id.insert(record.id.clone(), record);
                    store
                        .save_credential_records(credential_records_by_id.into_values().collect())
                        .map_err(|e| SyncError::Config(format!("write credential records: {e}")))?;
                    append_credential_sync_audit(credential_sync_audit_event(
                        AuditOperation::CredentialSyncPull,
                        AuditEventStatus::Succeeded,
                        Some(&audit),
                        None,
                        json!({
                            "object_id": object.object_id,
                            "object_version": object.object_version,
                            "server_revision": object.server_revision,
                            "scope": "keep_remote",
                        }),
                    ))?;
                    local_action = "replaced local credential record".into();
                }
                Err(reason) => {
                    let mapping = config.mapping_by_object_id(&object.object_id).cloned();
                    if let Some(mapping) = mapping {
                        local_kind = mapping.local_kind;
                        local_id = mapping.local_id;
                    }
                    record_unavailable_object_mapping(
                        config,
                        &object,
                        &local_kind,
                        &local_id,
                        &reason,
                    );
                    append_credential_sync_audit(unavailable_credential_sync_audit_event(
                        &reason,
                        &object,
                        Some(&local_id),
                    ))?;
                    config.set_revision("objects", object.server_revision);
                    config.last_synced_at = Some(chrono::Utc::now().to_rfc3339());
                    config.save()?;
                    return Ok(AppliedRemoteObject {
                        object_kind: object.object_kind,
                        object_id: object.object_id,
                        object_version: object.object_version,
                        server_revision: object.server_revision,
                        bytes,
                        local_action: "marked remote credential record unavailable".into(),
                        unavailable: true,
                    });
                }
            }
        }
        "plugin_compatibility" => {
            let payload: SyncPluginCompatibilityPayload = serde_json::from_value(payload)
                .map_err(|e| SyncError::Bundle(format!("plugin compatibility payload: {e}")))?;
            local_kind = "plugin_compatibility".into();
            local_id = payload.plugin_id;
            local_action = "accepted remote plugin compatibility metadata".into();
        }
        "app_preference" => {
            let payload: SyncAppPreferencePayload = serde_json::from_value(payload)
                .map_err(|e| SyncError::Bundle(format!("app preference payload: {e}")))?;
            local_kind = "app_preference".into();
            local_id = payload
                .preferences
                .get("local_id")
                .and_then(Value::as_str)
                .unwrap_or("object_sync")
                .to_string();
            local_action = "accepted remote app preferences".into();
        }
        _ => {}
    }

    record_mapping_revision(
        config,
        MappingRevision {
            local_kind: &local_kind,
            local_id: &local_id,
            object_kind: &object.object_kind,
            object_id: &object.object_id,
            object_version: object.object_version,
            server_revision: object.server_revision,
            unavailable,
        },
    );
    config.set_revision("objects", object.server_revision);
    config.last_synced_at = Some(chrono::Utc::now().to_rfc3339());
    config.save()?;

    Ok(AppliedRemoteObject {
        object_kind: object.object_kind,
        object_id: object.object_id,
        object_version: object.object_version,
        server_revision: object.server_revision,
        bytes,
        local_action,
        unavailable,
    })
}

fn finish_object_put_resolution(
    config: &mut SyncConfig,
    pending: &PendingObject,
    response: &PutObjectResponse,
    meta: ObjectPutResolutionMeta<'_>,
) -> Result<ObjectConflictResolutionOk, SyncError> {
    record_mapping_revision(
        config,
        MappingRevision {
            local_kind: &pending.local_kind,
            local_id: &pending.local_id,
            object_kind: response.object_kind.as_str(),
            object_id: response.object_id.as_str(),
            object_version: response.object_version,
            server_revision: response.server_revision,
            unavailable: meta.unavailable,
        },
    );
    config.set_revision("objects", response.server_revision);
    config.last_synced_at = Some(chrono::Utc::now().to_rfc3339());
    config.save()?;

    let ok = ObjectConflictResolutionOk {
        mode: meta.mode.to_string(),
        object_kind: response.object_kind.clone(),
        object_id: response.object_id.clone(),
        object_version: response.object_version,
        server_revision: response.server_revision,
        previous_server_revision: meta.previous_server_revision,
        bytes: pending.encrypted_bytes,
        local_action: meta.local_action.to_string(),
        unavailable: meta.unavailable,
    };
    append_sync_audit(sync_object_resolution_audit_event(meta.operation, &ok))?;
    Ok(ok)
}

fn merge_profile_policy(
    local: &ConnectionProfilePolicy,
    remote: &ConnectionProfilePolicy,
) -> ConnectionProfilePolicy {
    let mut allowed = local
        .allowed_capabilities
        .iter()
        .filter(|capability| remote.allowed_capabilities.contains(*capability))
        .cloned()
        .collect::<Vec<_>>();
    allowed.sort();
    allowed.dedup();

    let mut denied = local
        .denied_capabilities
        .iter()
        .chain(remote.denied_capabilities.iter())
        .cloned()
        .collect::<Vec<_>>();
    denied.sort();
    denied.dedup();

    ConnectionProfilePolicy {
        allowed_capabilities: allowed,
        denied_capabilities: denied,
        allow_destructive_by_default: local.allow_destructive_by_default
            && remote.allow_destructive_by_default,
    }
}

fn merge_profile_payload(
    local: &mut ConnectionProfile,
    remote: &SyncProfilePayload,
) -> Result<(), SyncError> {
    if local.plugin_id != remote.profile.plugin_id {
        return Err(SyncError::Config(format!(
            "profile merge refused because plugin_id differs: local {}, remote {}",
            local.plugin_id, remote.profile.plugin_id
        )));
    }
    let local_credential_ids = local
        .credential_refs
        .iter()
        .map(|credential_ref| credential_ref.id.as_str())
        .collect::<BTreeSet<_>>();
    let missing_remote_ref = remote
        .profile
        .credential_ref_ids
        .iter()
        .find(|credential_ref_id| !local_credential_ids.contains(credential_ref_id.as_str()));
    if let Some(credential_ref_id) = missing_remote_ref {
        return Err(SyncError::Config(format!(
            "profile merge would drop remote credential reference {credential_ref_id}"
        )));
    }
    local.metadata = merge_json_without_scalar_conflicts(
        &local.metadata,
        &remote.profile.metadata,
        "profile.metadata",
    )?;
    local.default_options = merge_json_without_scalar_conflicts(
        &local.default_options,
        &remote.profile.default_options,
        "profile.default_options",
    )?;
    if local.display_name.is_none() {
        local.display_name = remote.profile.display_name.clone();
    }
    Ok(())
}

fn merge_json_without_scalar_conflicts(
    local: &Value,
    remote: &Value,
    path: &str,
) -> Result<Value, SyncError> {
    if local == remote {
        return Ok(local.clone());
    }
    match (local, remote) {
        (Value::Null, other) => Ok(other.clone()),
        (other, Value::Null) => Ok(other.clone()),
        (Value::Object(local_map), Value::Object(remote_map)) => {
            let mut merged = remote_map.clone();
            for (key, local_value) in local_map {
                let child_path = format!("{path}.{key}");
                let value = match remote_map.get(key) {
                    Some(remote_value) => {
                        merge_json_without_scalar_conflicts(local_value, remote_value, &child_path)?
                    }
                    None => local_value.clone(),
                };
                merged.insert(key.clone(), value);
            }
            Ok(Value::Object(merged))
        }
        _ => Err(SyncError::Config(format!(
            "merge refused at {path}: scalar values differ"
        ))),
    }
}

fn app_preference_payload() -> SyncAppPreferencePayload {
    SyncAppPreferencePayload {
        payload_version: OBJECT_SYNC_PAYLOAD_VERSION,
        preferences: json!({
            "object_sync": {
                "safe_kinds": [
                    "profile",
                    "profile_policy",
                    "credential_ref",
                    "credential_record",
                    "plugin_compatibility",
                    "app_preference"
                ],
                "bundle_compatibility": "manual_backup"
            }
        }),
    }
}

fn credential_local_parts(
    profiles: &[ConnectionProfile],
    local_id: &str,
) -> Option<(String, String)> {
    profiles.iter().find_map(|profile| {
        let prefix = format!("{}:", profile.id);
        local_id
            .strip_prefix(&prefix)
            .map(|credential_ref_id| (profile.id.clone(), credential_ref_id.to_string()))
    })
}

fn apply_local_tombstone_effect(local_kind: &str, local_id: &str) -> Result<(), SyncError> {
    let store = local_profile_store()?;
    match local_kind {
        "profile" => {
            let profiles = store
                .load_profiles()
                .map_err(|e| SyncError::Config(format!("load profiles: {e}")))?
                .into_iter()
                .filter(|profile| profile.id != local_id)
                .collect::<Vec<_>>();
            let credentials = store
                .load_credential_records()
                .map_err(|e| SyncError::Config(format!("load credential records: {e}")))?
                .into_iter()
                .filter(|credential| credential.profile_id != local_id)
                .collect::<Vec<_>>();
            store
                .save_profiles(profiles)
                .map_err(|e| SyncError::Config(format!("write profiles: {e}")))?;
            store
                .save_credential_records(credentials)
                .map_err(|e| SyncError::Config(format!("write credential records: {e}")))?;
        }
        "credential_ref" | "credential_record" => {
            let mut profiles = store
                .load_profiles()
                .map_err(|e| SyncError::Config(format!("load profiles: {e}")))?;
            let Some((profile_id, credential_ref_id)) = credential_local_parts(&profiles, local_id)
            else {
                return Ok(());
            };
            for profile in &mut profiles {
                if profile.id == profile_id {
                    profile
                        .credential_refs
                        .retain(|credential_ref| credential_ref.id != credential_ref_id);
                }
            }
            let credentials = store
                .load_credential_records()
                .map_err(|e| SyncError::Config(format!("load credential records: {e}")))?
                .into_iter()
                .filter(|credential| {
                    !(credential.profile_id == profile_id && credential.id == credential_ref_id)
                })
                .collect::<Vec<_>>();
            store
                .save_profiles(profiles)
                .map_err(|e| SyncError::Config(format!("write profiles: {e}")))?;
            store
                .save_credential_records(credentials)
                .map_err(|e| SyncError::Config(format!("write credential records: {e}")))?;
        }
        _ => {}
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Object pull
// -----------------------------------------------------------------------------

pub async fn pull_objects(
    session: Session,
    mut config: SyncConfig,
) -> Result<(ObjectPullOk, SyncConfig), SyncError> {
    let client = SyncClient::new(&session.server_url).with_token(session.token.clone());
    let objects = client.list_objects(true).await?;
    let mut pulled = PulledObjectSet::default();
    let mut unavailable = 0usize;
    let mut max_revision = 0u64;

    for summary in objects {
        max_revision = max_revision.max(summary.server_revision);
        if summary.deleted {
            if let Some(mapping) = config.mapping_by_object_id(&summary.object_id).cloned() {
                record_pull_conflict_from_summary(
                    &mut config,
                    &mapping,
                    &summary,
                    "remote_tombstone",
                )?;
                unavailable += 1;
            }
            continue;
        }

        let Some(object) = client.get_object_latest(&summary.object_id).await? else {
            continue;
        };
        let payload = match decrypt_object_payload(&session, &object) {
            Ok(payload) => payload,
            Err(_) if summary.object_kind == "credential_record" => {
                let reason = "object_payload_decrypt_failed";
                record_unavailable_object_mapping(
                    &mut config,
                    &object,
                    "credential_record",
                    &summary.object_id,
                    reason,
                );
                append_credential_sync_audit(unavailable_credential_sync_audit_event(
                    reason,
                    &object,
                    Some(&summary.object_id),
                ))?;
                let mapping = config.mapping_by_object_id(&summary.object_id).cloned();
                record_pull_conflict_from_object(
                    &mut config,
                    mapping.as_ref(),
                    &object,
                    "object_payload_decrypt_failed",
                    Some("credential_record"),
                    Some(&summary.object_id),
                )?;
                unavailable += 1;
                continue;
            }
            Err(error) => return Err(error),
        };
        if record_pull_time_conflict_if_needed(&mut config, &object, &payload)? {
            unavailable += 1;
            continue;
        }
        if let Err(error) = pulled.insert(object.clone(), payload) {
            if summary.object_kind == "credential_record" {
                let reason = "credential_record_payload_invalid";
                record_unavailable_object_mapping(
                    &mut config,
                    &object,
                    "credential_record",
                    &summary.object_id,
                    reason,
                );
                append_credential_sync_audit(unavailable_credential_sync_audit_event(
                    reason,
                    &object,
                    Some(&summary.object_id),
                ))?;
                let mapping = config.mapping_by_object_id(&summary.object_id).cloned();
                record_pull_conflict_from_object(
                    &mut config,
                    mapping.as_ref(),
                    &object,
                    "credential_record_payload_invalid",
                    Some("credential_record"),
                    Some(&summary.object_id),
                )?;
                unavailable += 1;
                continue;
            }
            return Err(error);
        }
    }

    let store = local_profile_store()?;
    let mut profiles_by_id = store
        .load_profiles()
        .map_err(|e| SyncError::Config(format!("load profiles: {e}")))?
        .into_iter()
        .map(|profile| (profile.id.clone(), profile))
        .collect::<BTreeMap<_, _>>();
    let mut credential_records_by_id = store
        .load_credential_records()
        .map_err(|e| SyncError::Config(format!("load credential records: {e}")))?
        .into_iter()
        .map(|record| (record.id.clone(), record))
        .collect::<BTreeMap<_, _>>();

    let mut imported_profiles = 0usize;
    let mut imported_credential_refs = 0usize;
    let mut imported_credential_records = 0usize;
    for credential_record in pulled.credential_records {
        match stored_credential_record_from_sync(&session, &credential_record) {
            Ok(record) => {
                let local_id = credential_ref_local_id(&record.profile_id, &record.id);
                let audit = PendingCredentialAudit::from_record(&record, record.label.clone());
                record_mapping_revision(
                    &mut config,
                    MappingRevision {
                        local_kind: "credential_record",
                        local_id: &local_id,
                        object_kind: "credential_record",
                        object_id: &credential_record.object.object_id,
                        object_version: credential_record.object.object_version,
                        server_revision: credential_record.object.server_revision,
                        unavailable: false,
                    },
                );
                credential_records_by_id.insert(record.id.clone(), record);
                append_credential_sync_audit(credential_sync_audit_event(
                    AuditOperation::CredentialSyncPull,
                    AuditEventStatus::Succeeded,
                    Some(&audit),
                    None,
                    json!({
                        "object_id": credential_record.object.object_id,
                        "object_version": credential_record.object.object_version,
                        "server_revision": credential_record.object.server_revision,
                        "encrypted_payload_size": credential_record.envelope.encrypted_payload_size,
                    }),
                ))?;
                imported_credential_records += 1;
            }
            Err(reason) => {
                let local_id =
                    credential_local_id_from_envelope(&config, &credential_record.envelope)
                        .unwrap_or_else(|| credential_record.object.object_id.clone());
                record_unavailable_object_mapping(
                    &mut config,
                    &credential_record.object,
                    "credential_record",
                    &local_id,
                    &reason,
                );
                let mapping = config
                    .mapping_by_object_id(&credential_record.object.object_id)
                    .cloned();
                record_pull_conflict_from_object(
                    &mut config,
                    mapping.as_ref(),
                    &credential_record.object,
                    &reason,
                    Some("credential_record"),
                    Some(&local_id),
                )?;
                append_credential_sync_audit(unavailable_credential_sync_audit_event(
                    &reason,
                    &credential_record.object,
                    Some(&local_id),
                ))?;
                unavailable += 1;
            }
        }
    }

    for (profile_object_id, profile_object) in pulled.profiles {
        let credential_refs = pulled
            .credential_refs
            .remove(&profile_object_id)
            .unwrap_or_default();
        let policy = pulled
            .policies
            .remove(&profile_object_id)
            .unwrap_or_else(ConnectionProfilePolicy::default);

        let compatibility = profile_compatibility_status(
            &profile_object.payload,
            plugin_compatibility_for_profile(&pulled.plugin_compatibility, &profile_object.payload),
        );
        let mut profile =
            connection_profile_from_sync(profile_object.payload, policy, credential_refs);
        let credential_refs_unavailable = profile
            .credential_refs
            .iter()
            .any(|credential_ref| !credential_records_by_id.contains_key(&credential_ref.id));
        profile.metadata = mark_imported_profile_metadata(
            profile.metadata,
            credential_refs_unavailable,
            compatibility,
        );
        imported_credential_refs += profile.credential_refs.len();

        record_mapping_revision_with_reason(
            &mut config,
            MappingRevision {
                local_kind: "profile",
                local_id: &profile.id,
                object_kind: "profile",
                object_id: &profile_object.object.object_id,
                object_version: profile_object.object.object_version,
                server_revision: profile_object.object.server_revision,
                unavailable: compatibility.unavailable,
            },
            compatibility.reason,
        );

        if let Some(policy_object) = pulled.policy_objects.get(&profile_object_id) {
            record_mapping_revision(
                &mut config,
                MappingRevision {
                    local_kind: "profile_policy",
                    local_id: &profile.id,
                    object_kind: "profile_policy",
                    object_id: &policy_object.object_id,
                    object_version: policy_object.object_version,
                    server_revision: policy_object.server_revision,
                    unavailable: false,
                },
            );
        }

        for credential_object in pulled
            .credential_ref_objects
            .remove(&profile_object_id)
            .unwrap_or_default()
        {
            if let Some(credential_ref_id) = credential_object
                .manifest
                .get("credential_ref_id")
                .and_then(Value::as_str)
            {
                let credential_record_available =
                    credential_records_by_id.contains_key(credential_ref_id);
                record_mapping_revision(
                    &mut config,
                    MappingRevision {
                        local_kind: "credential_ref",
                        local_id: &credential_ref_local_id(&profile.id, credential_ref_id),
                        object_kind: "credential_ref",
                        object_id: &credential_object.object_id,
                        object_version: credential_object.object_version,
                        server_revision: credential_object.server_revision,
                        unavailable: !credential_record_available,
                    },
                );
            }
        }

        profiles_by_id.insert(profile.id.clone(), profile);
        imported_profiles += 1;
    }

    for plugin_object in pulled.plugin_compatibility {
        record_mapping_revision(
            &mut config,
            MappingRevision {
                local_kind: "plugin_compatibility",
                local_id: &plugin_object.local_id,
                object_kind: "plugin_compatibility",
                object_id: &plugin_object.object.object_id,
                object_version: plugin_object.object.object_version,
                server_revision: plugin_object.object.server_revision,
                unavailable: false,
            },
        );
    }

    for app_object in pulled.app_preferences {
        record_mapping_revision(
            &mut config,
            MappingRevision {
                local_kind: "app_preference",
                local_id: &app_object.local_id,
                object_kind: "app_preference",
                object_id: &app_object.object.object_id,
                object_version: app_object.object.object_version,
                server_revision: app_object.object.server_revision,
                unavailable: false,
            },
        );
    }

    store
        .save_profiles(profiles_by_id.into_values().collect())
        .map_err(|e| SyncError::Config(format!("write profiles: {e}")))?;
    store
        .save_credential_records(credential_records_by_id.into_values().collect())
        .map_err(|e| SyncError::Config(format!("write credential records: {e}")))?;

    if max_revision > 0 {
        config.set_revision("objects", max_revision);
    }
    config.last_synced_at = Some(chrono::Utc::now().to_rfc3339());
    config.save()?;

    Ok((
        ObjectPullOk {
            objects: pulled.count,
            imported_profiles,
            imported_credential_refs,
            imported_credential_records,
            unavailable,
        },
        config,
    ))
}

fn record_pull_time_conflict_if_needed(
    config: &mut SyncConfig,
    object: &ObjectResponse,
    remote_payload: &Value,
) -> Result<bool, SyncError> {
    let Some(mapping) = config.mapping_by_object_id(&object.object_id).cloned() else {
        return Ok(false);
    };
    if object.server_revision <= mapping.server_revision || mapping.unavailable {
        return Ok(false);
    }
    let Some(local_payload) = local_payload_for_mapping(config, &mapping)? else {
        return Ok(false);
    };
    if local_payload == *remote_payload {
        return Ok(false);
    }

    record_pull_conflict_from_object(
        config,
        Some(&mapping),
        object,
        "pull_time_object_conflict",
        None,
        None,
    )?;
    Ok(true)
}

fn record_pull_conflict_from_summary(
    config: &mut SyncConfig,
    mapping: &SyncObjectMapping,
    summary: &ObjectSummary,
    reason: &str,
) -> Result<(), SyncError> {
    let conflict = SyncObjectConflict {
        object_kind: summary.object_kind.clone(),
        object_id: summary.object_id.clone(),
        local_kind: Some(mapping.local_kind.clone()),
        local_id: Some(mapping.local_id.clone()),
        attempted_base_server_revision: mapping.server_revision,
        current_server_revision: summary.server_revision,
        attempted_object_version: mapping.object_version + 1,
        current_object_version: summary.object_version,
        detected_at: chrono::Utc::now().to_rfc3339(),
        server_updated_at: None,
        redaction: "withheld".into(),
        unavailable_reason: Some(reason.to_string()),
    };
    config.record_object_conflict(conflict.clone());
    append_sync_audit(sync_object_conflict_audit_event(&conflict))?;
    config.save()?;
    Ok(())
}

fn record_pull_conflict_from_object(
    config: &mut SyncConfig,
    mapping: Option<&SyncObjectMapping>,
    object: &ObjectResponse,
    reason: &str,
    local_kind: Option<&str>,
    local_id: Option<&str>,
) -> Result<(), SyncError> {
    let conflict = SyncObjectConflict {
        object_kind: object.object_kind.clone(),
        object_id: object.object_id.clone(),
        local_kind: mapping
            .map(|mapping| mapping.local_kind.clone())
            .or_else(|| local_kind.map(str::to_string)),
        local_id: mapping
            .map(|mapping| mapping.local_id.clone())
            .or_else(|| local_id.map(str::to_string)),
        attempted_base_server_revision: mapping.map(|mapping| mapping.server_revision).unwrap_or(0),
        current_server_revision: object.server_revision,
        attempted_object_version: mapping
            .map(|mapping| mapping.object_version + 1)
            .unwrap_or(0),
        current_object_version: object.object_version,
        detected_at: chrono::Utc::now().to_rfc3339(),
        server_updated_at: None,
        redaction: "withheld".into(),
        unavailable_reason: Some(reason.to_string()),
    };
    config.record_object_conflict(conflict.clone());
    append_sync_audit(sync_object_conflict_audit_event(&conflict))?;
    config.save()?;
    Ok(())
}

fn local_payload_for_mapping(
    config: &SyncConfig,
    mapping: &SyncObjectMapping,
) -> Result<Option<Value>, SyncError> {
    let store = local_profile_store()?;
    let profiles = store
        .load_profiles()
        .map_err(|e| SyncError::Config(format!("load profiles: {e}")))?;

    let value = match mapping.object_kind.as_str() {
        "profile" => {
            let Some(profile) = profiles
                .iter()
                .find(|profile| profile.id == mapping.local_id)
                .cloned()
            else {
                return Ok(None);
            };
            let mut profile = profile;
            remove_sync_import_metadata(&mut profile.metadata);
            let policy_ref = config
                .object_mapping("profile_policy", &profile.id)
                .map(|mapping| mapping.object_id.clone());
            let compatibility_ref = config
                .object_mapping("plugin_compatibility", &profile.plugin_id)
                .map(|mapping| mapping.object_id.clone());
            serde_json::to_value(sync_profile_payload(
                &profile,
                policy_ref,
                compatibility_ref,
            ))
        }
        "profile_policy" => {
            let Some(profile) = profiles
                .iter()
                .find(|profile| profile.id == mapping.local_id)
            else {
                return Ok(None);
            };
            let Some(profile_mapping) = config.object_mapping("profile", &profile.id) else {
                return Ok(None);
            };
            serde_json::to_value(sync_profile_policy_payload(
                profile_mapping.object_id.clone(),
                &profile.policy,
            ))
        }
        "credential_ref" => {
            let Some((profile_id, credential_ref_id)) =
                credential_local_parts(&profiles, &mapping.local_id)
            else {
                return Ok(None);
            };
            let Some(profile) = profiles.iter().find(|profile| profile.id == profile_id) else {
                return Ok(None);
            };
            let Some(profile_mapping) = config.object_mapping("profile", &profile.id) else {
                return Ok(None);
            };
            let Some(credential_ref) = profile
                .credential_refs
                .iter()
                .find(|credential_ref| credential_ref.id == credential_ref_id)
            else {
                return Ok(None);
            };
            serde_json::to_value(sync_credential_ref_payload(
                profile_mapping.object_id.clone(),
                credential_ref,
            ))
        }
        "plugin_compatibility" => {
            let payload = SyncPluginCompatibilityPayload {
                payload_version: OBJECT_SYNC_PAYLOAD_VERSION,
                plugin_id: mapping.local_id.clone(),
                profile_schema_id: format!("{}.profile", mapping.local_id),
                profile_schema_version: 1,
                minimum_plugin_version: None,
                capability_contracts: Vec::new(),
            };
            serde_json::to_value(payload)
        }
        "app_preference" => serde_json::to_value(app_preference_payload()),
        _ => return Ok(None),
    }
    .map_err(|e| SyncError::Bundle(format!("local object payload json: {e}")))?;

    Ok(Some(value))
}

fn remove_sync_import_metadata(metadata: &mut Value) {
    if let Value::Object(map) = metadata {
        map.remove("sync_import");
    }
}

fn credential_local_id_from_envelope(
    config: &SyncConfig,
    envelope: &EncryptedCredentialRecordEnvelope,
) -> Option<String> {
    config
        .mapping_by_object_id(&envelope.credential_ref_object_id)
        .map(|mapping| mapping.local_id.clone())
}

#[derive(Default)]
struct PulledObjectSet {
    count: usize,
    profiles: BTreeMap<String, PulledProfile>,
    policies: BTreeMap<String, ConnectionProfilePolicy>,
    policy_objects: BTreeMap<String, ObjectResponse>,
    credential_refs: BTreeMap<String, Vec<CredentialRef>>,
    credential_ref_objects: BTreeMap<String, Vec<ObjectResponse>>,
    credential_records: Vec<PulledCredentialRecord>,
    plugin_compatibility: Vec<PulledPluginCompatibility>,
    app_preferences: Vec<PulledLocalObject>,
}

impl PulledObjectSet {
    fn insert(&mut self, object: ObjectResponse, payload: Value) -> Result<(), SyncError> {
        self.count += 1;
        match object.object_kind.as_str() {
            "profile" => {
                let payload: SyncProfilePayload = serde_json::from_value(payload)
                    .map_err(|e| SyncError::Bundle(format!("profile payload: {e}")))?;
                self.profiles
                    .insert(object.object_id.clone(), PulledProfile { object, payload });
            }
            "profile_policy" => {
                let payload: SyncProfilePolicyPayload = serde_json::from_value(payload)
                    .map_err(|e| SyncError::Bundle(format!("profile policy payload: {e}")))?;
                self.policy_objects
                    .insert(payload.profile_object_id.clone(), object);
                self.policies
                    .insert(payload.profile_object_id, payload.policy);
            }
            "credential_ref" => {
                let payload: SyncCredentialRefPayload = serde_json::from_value(payload)
                    .map_err(|e| SyncError::Bundle(format!("credential ref payload: {e}")))?;
                let mut object = object;
                object.manifest["credential_ref_id"] =
                    Value::String(payload.credential_ref.id.clone());
                self.credential_ref_objects
                    .entry(payload.profile_object_id.clone())
                    .or_default()
                    .push(object);
                self.credential_refs
                    .entry(payload.profile_object_id)
                    .or_default()
                    .push(CredentialRef {
                        id: payload.credential_ref.id,
                        class: payload.credential_ref.class,
                        label: payload.credential_ref.label,
                    });
            }
            "credential_record" => {
                let envelope: EncryptedCredentialRecordEnvelope = serde_json::from_value(payload)
                    .map_err(|e| {
                    SyncError::Bundle(format!("credential record payload: {e}"))
                })?;
                self.credential_records
                    .push(PulledCredentialRecord { object, envelope });
            }
            "plugin_compatibility" => {
                let payload: SyncPluginCompatibilityPayload = serde_json::from_value(payload)
                    .map_err(|e| SyncError::Bundle(format!("plugin compatibility payload: {e}")))?;
                self.plugin_compatibility.push(PulledPluginCompatibility {
                    local_id: payload.plugin_id.clone(),
                    object,
                    payload,
                });
            }
            "app_preference" => {
                let payload: SyncAppPreferencePayload = serde_json::from_value(payload)
                    .map_err(|e| SyncError::Bundle(format!("app preference payload: {e}")))?;
                let local_id = payload
                    .preferences
                    .get("local_id")
                    .and_then(Value::as_str)
                    .unwrap_or("object_sync")
                    .to_string();
                self.app_preferences
                    .push(PulledLocalObject { local_id, object });
            }
            _ => {}
        }
        Ok(())
    }
}

struct PulledProfile {
    object: ObjectResponse,
    payload: SyncProfilePayload,
}

struct PulledLocalObject {
    local_id: String,
    object: ObjectResponse,
}

struct PulledPluginCompatibility {
    local_id: String,
    object: ObjectResponse,
    payload: SyncPluginCompatibilityPayload,
}

struct PulledCredentialRecord {
    object: ObjectResponse,
    envelope: EncryptedCredentialRecordEnvelope,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProfileCompatibilityStatus {
    unavailable: bool,
    plugin_availability: &'static str,
    reason: Option<&'static str>,
}

fn stored_credential_record_from_sync(
    session: &Session,
    pulled: &PulledCredentialRecord,
) -> Result<StoredCredentialRecord, String> {
    if pulled.object.object_id != pulled.envelope.object_id {
        return Err("credential_record_object_mismatch".to_string());
    }

    let payload = decrypt_credential_record_payload(&pulled.envelope, &session.dek)
        .map_err(|_| "credential_record_decrypt_failed".to_string())?;

    Ok(StoredCredentialRecord {
        id: payload.credential.credential_ref_id,
        profile_id: payload.credential.profile_id,
        plugin_id: payload.credential.plugin_id,
        class: payload.credential.class,
        label: payload.credential.label,
        source: synced_credential_source_from_envelope(
            &pulled.envelope,
            pulled.object.server_revision,
            false,
            None,
        ),
        created_at: payload.credential.created_at,
        redaction: pulled.envelope.redaction,
    })
}

fn stored_credential_record_from_envelope(
    record: &StoredCredentialRecord,
    envelope: &EncryptedCredentialRecordEnvelope,
    server_revision: u64,
    unavailable: bool,
    unavailable_reason: Option<String>,
) -> StoredCredentialRecord {
    StoredCredentialRecord {
        id: record.id.clone(),
        profile_id: record.profile_id.clone(),
        plugin_id: record.plugin_id.clone(),
        class: record.class.clone(),
        label: record.label.clone(),
        source: synced_credential_source_from_envelope(
            envelope,
            server_revision,
            unavailable,
            unavailable_reason,
        ),
        created_at: record.created_at,
        redaction: envelope.redaction,
    }
}

fn synced_credential_source_from_envelope(
    envelope: &EncryptedCredentialRecordEnvelope,
    server_revision: u64,
    unavailable: bool,
    unavailable_reason: Option<String>,
) -> StoredCredentialSource {
    StoredCredentialSource::SyncedObject {
        object_id: envelope.object_id.clone(),
        profile_object_id: envelope.profile_object_id.clone(),
        credential_ref_object_id: envelope.credential_ref_object_id.clone(),
        object_version: envelope.object_version,
        server_revision,
        encrypted_payload_hash: envelope.encrypted_payload_hash.clone(),
        encrypted_payload_size: envelope.encrypted_payload_size,
        encryption: Box::new(StoredCredentialEncryption {
            algorithm: envelope.encryption.algorithm.clone(),
            key_wrap: envelope.encryption.key_wrap.clone(),
            nonce: envelope.encryption.nonce.clone(),
            aad: envelope.encryption.aad.clone(),
        }),
        ciphertext: envelope.ciphertext.clone(),
        unavailable,
        unavailable_reason,
    }
}

fn placeholder_synced_credential_source(
    record_mapping: &SyncObjectMapping,
    profile_object_id: &str,
    credential_ref_object_id: &str,
    object_version: u64,
) -> StoredCredentialSource {
    StoredCredentialSource::SyncedObject {
        object_id: record_mapping.object_id.clone(),
        profile_object_id: profile_object_id.to_string(),
        credential_ref_object_id: credential_ref_object_id.to_string(),
        object_version,
        server_revision: record_mapping.server_revision,
        encrypted_payload_hash: String::new(),
        encrypted_payload_size: 0,
        encryption: Box::new(StoredCredentialEncryption {
            algorithm: String::new(),
            key_wrap: String::new(),
            nonce: String::new(),
            aad: String::new(),
        }),
        ciphertext: String::new(),
        unavailable: false,
        unavailable_reason: None,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SyncAppPreferencePayload {
    payload_version: u32,
    #[serde(default)]
    preferences: Value,
}

fn decrypt_object_payload(session: &Session, object: &ObjectResponse) -> Result<Value, SyncError> {
    let encrypted = B64
        .decode(&object.ciphertext)
        .map_err(|e| SyncError::Crypto(format!("base64 object ciphertext: {e}")))?;
    let plaintext = crypto::decrypt_bundle(&session.dek, &encrypted)?;
    serde_json::from_slice(&plaintext).map_err(|e| SyncError::Bundle(format!("object json: {e}")))
}

fn connection_profile_from_sync(
    payload: SyncProfilePayload,
    policy: ConnectionProfilePolicy,
    credential_refs: Vec<CredentialRef>,
) -> ConnectionProfile {
    ConnectionProfile {
        id: payload.profile.id,
        name: payload.profile.name,
        plugin_id: payload.profile.plugin_id,
        display_name: payload.profile.display_name,
        metadata: payload.profile.metadata,
        default_options: payload.profile.default_options,
        credential_refs,
        policy,
    }
}

fn profile_compatibility_status(
    profile: &SyncProfilePayload,
    compatibility: Option<&SyncPluginCompatibilityPayload>,
) -> ProfileCompatibilityStatus {
    let Some(compatibility) = compatibility else {
        return ProfileCompatibilityStatus {
            unavailable: true,
            plugin_availability: "unavailable",
            reason: Some("missing_plugin_compatibility"),
        };
    };
    if compatibility.plugin_id != profile.profile.plugin_id {
        return ProfileCompatibilityStatus {
            unavailable: true,
            plugin_availability: "unavailable",
            reason: Some("plugin_id_mismatch"),
        };
    }
    if !SUPPORTED_OBJECT_SYNC_PLUGIN_IDS.contains(&compatibility.plugin_id.as_str()) {
        return ProfileCompatibilityStatus {
            unavailable: true,
            plugin_availability: "unavailable",
            reason: Some("plugin_missing"),
        };
    }
    let expected_schema_id = format!("{}.profile", profile.profile.plugin_id);
    if compatibility.profile_schema_id != expected_schema_id {
        return ProfileCompatibilityStatus {
            unavailable: true,
            plugin_availability: "unavailable",
            reason: Some("profile_schema_id_mismatch"),
        };
    }
    if compatibility.profile_schema_version != SUPPORTED_PROFILE_SCHEMA_VERSION {
        return ProfileCompatibilityStatus {
            unavailable: true,
            plugin_availability: "unavailable",
            reason: Some("profile_schema_version_unsupported"),
        };
    }
    if compatibility.minimum_plugin_version.is_some() {
        return ProfileCompatibilityStatus {
            unavailable: true,
            plugin_availability: "unavailable",
            reason: Some("minimum_plugin_version_unverified"),
        };
    }

    ProfileCompatibilityStatus {
        unavailable: false,
        plugin_availability: "available",
        reason: None,
    }
}

fn plugin_compatibility_for_profile<'a>(
    plugin_compatibility: &'a [PulledPluginCompatibility],
    profile: &SyncProfilePayload,
) -> Option<&'a SyncPluginCompatibilityPayload> {
    let compatibility_ref = profile.compatibility_ref.as_deref()?;
    plugin_compatibility
        .iter()
        .find(|object| object.object.object_id == compatibility_ref)
        .map(|object| &object.payload)
}

fn mark_imported_profile_metadata(
    mut metadata: Value,
    credential_refs_unavailable: bool,
    compatibility: ProfileCompatibilityStatus,
) -> Value {
    if !metadata.is_object() {
        metadata = json!({});
    }
    if let Value::Object(map) = &mut metadata {
        let mut sync_import = json!({
            "credential_material": if credential_refs_unavailable {
                "unavailable"
            } else {
                "not_required"
            },
            "plugin_availability": compatibility.plugin_availability,
            "profile_quarantine": compatibility.unavailable,
        });
        if let Some(reason) = compatibility.reason {
            sync_import["plugin_reason"] = Value::String(reason.to_string());
        }
        map.insert("sync_import".to_string(), sync_import);
    }
    metadata
}

fn local_profile_store() -> Result<LocalProfileStore, SyncError> {
    let root = voidb_config_dir()?;
    Ok(LocalProfileStore::new(
        root.join("profiles.json"),
        root.join("credentials.json"),
    ))
}

fn new_object_id(kind: SyncObjectKind) -> String {
    format!(
        "{}{}",
        kind.object_id_prefix(),
        hex::encode(crypto::random_bytes(16))
    )
}

fn sha256_hash(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

fn sync_actor() -> ActorRef {
    ActorRef {
        id: "sync_client".to_string(),
        actor_type: ActorType::System,
    }
}

fn actor_type_label(actor_type: ActorType) -> &'static str {
    match actor_type {
        ActorType::Human => "human",
        ActorType::Agent => "agent",
        ActorType::System => "system",
    }
}

fn redaction_label(redaction: RedactionStatus) -> &'static str {
    match redaction {
        RedactionStatus::NotRequired => "not_required",
        RedactionStatus::Applied => "applied",
        RedactionStatus::Withheld => "withheld",
        RedactionStatus::FailedClosed => "failed_closed",
    }
}

struct MappingRevision<'a> {
    local_kind: &'a str,
    local_id: &'a str,
    object_kind: &'a str,
    object_id: &'a str,
    object_version: u64,
    server_revision: u64,
    unavailable: bool,
}

fn record_mapping_revision(config: &mut SyncConfig, revision: MappingRevision<'_>) {
    record_mapping_revision_with_reason(config, revision, None);
}

fn record_mapping_revision_with_reason(
    config: &mut SyncConfig,
    revision: MappingRevision<'_>,
    unavailable_reason: Option<&str>,
) {
    config.record_object_revision(SyncObjectMapping {
        local_kind: revision.local_kind.to_string(),
        local_id: revision.local_id.to_string(),
        object_kind: revision.object_kind.to_string(),
        object_id: revision.object_id.to_string(),
        object_version: revision.object_version,
        server_revision: revision.server_revision,
        unavailable: revision.unavailable,
        updated_at: None,
        cached_ciphertext: None,
        unavailable_reason: unavailable_reason.map(str::to_string),
    });
}

fn record_unavailable_object_mapping(
    config: &mut SyncConfig,
    object: &ObjectResponse,
    local_kind: &str,
    local_id: &str,
    reason: &str,
) {
    config.record_object_revision(SyncObjectMapping {
        local_kind: local_kind.to_string(),
        local_id: local_id.to_string(),
        object_kind: object.object_kind.clone(),
        object_id: object.object_id.clone(),
        object_version: object.object_version,
        server_revision: object.server_revision,
        unavailable: true,
        updated_at: None,
        cached_ciphertext: Some(object.ciphertext.clone()),
        unavailable_reason: Some(reason.to_string()),
    });
}

fn credential_ref_local_id(profile_id: &str, credential_ref_id: &str) -> String {
    format!("{profile_id}:{credential_ref_id}")
}

fn append_credential_sync_audit(event: AuditEvent) -> Result<(), SyncError> {
    append_sync_audit(event)
}

fn append_sync_audit(event: AuditEvent) -> Result<(), SyncError> {
    let store = LocalAuditStore::default_store()
        .map_err(|e| SyncError::Config(format!("sync audit store: {e}")))?;
    store
        .append(&event)
        .map_err(|e| SyncError::Config(format!("sync audit append: {e}")))
}

fn credential_sync_audit_event(
    operation: AuditOperation,
    status: AuditEventStatus,
    credential: Option<&PendingCredentialAudit>,
    reason: Option<&str>,
    metadata: Value,
) -> AuditEvent {
    let mut event = AuditEvent::new(operation, status);
    if let Some(credential) = credential {
        event.profile = Some(ConnectionProfileRef::Id(credential.profile_id.clone()));
        event.plugin_id = Some(credential.plugin_id.clone());
        event.credential_refs = vec![credential.credential_ref.clone()];
    }
    event.metadata = credential_sync_audit_metadata(metadata, reason);
    event.redaction = RedactionStatus::Withheld;
    event
}

fn unavailable_credential_sync_audit_event(
    reason: &str,
    object: &ObjectResponse,
    local_id: Option<&str>,
) -> AuditEvent {
    credential_sync_audit_event(
        AuditOperation::CredentialSyncUnavailable,
        AuditEventStatus::Blocked,
        None,
        Some(reason),
        json!({
            "object_id": object.object_id,
            "object_kind": object.object_kind,
            "object_version": object.object_version,
            "server_revision": object.server_revision,
            "local_id": local_id,
        }),
    )
}

fn credential_sync_audit_metadata(mut metadata: Value, reason: Option<&str>) -> Value {
    if !metadata.is_object() {
        metadata = json!({ "details": metadata });
    }
    if let Value::Object(map) = &mut metadata {
        map.insert("redacted".to_string(), Value::Bool(true));
        if let Some(reason) = reason {
            map.insert("reason".to_string(), Value::String(reason.to_string()));
        }
    }
    metadata
}

fn sync_object_conflict_audit_event(conflict: &SyncObjectConflict) -> AuditEvent {
    let mut event = AuditEvent::new(
        AuditOperation::SyncObjectConflict,
        AuditEventStatus::Blocked,
    );
    event.metadata = json!({
        "object_kind": conflict.object_kind,
        "object_id": conflict.object_id,
        "local_kind": conflict.local_kind,
        "attempted_base_server_revision": conflict.attempted_base_server_revision,
        "current_server_revision": conflict.current_server_revision,
        "attempted_object_version": conflict.attempted_object_version,
        "current_object_version": conflict.current_object_version,
        "detected_at": conflict.detected_at,
        "server_updated_at": conflict.server_updated_at,
        "redaction": conflict.redaction,
        "unavailable_reason": conflict.unavailable_reason,
        "redacted": true,
    });
    event.redaction = RedactionStatus::Withheld;
    event
}

fn sync_object_resolution_audit_event(
    operation: AuditOperation,
    ok: &ObjectConflictResolutionOk,
) -> AuditEvent {
    let mut event = AuditEvent::new(operation, AuditEventStatus::Succeeded);
    event.metadata = json!({
        "mode": ok.mode,
        "object_kind": ok.object_kind,
        "object_id": ok.object_id,
        "previous_server_revision": ok.previous_server_revision,
        "server_revision": ok.server_revision,
        "object_version": ok.object_version,
        "local_action": ok.local_action,
        "unavailable": ok.unavailable,
        "encrypted_bytes": ok.bytes,
        "redacted": true,
    });
    event.redaction = RedactionStatus::Withheld;
    event
}

fn material_kind(material: &CredentialRecordSecretMaterial) -> &'static str {
    match material {
        CredentialRecordSecretMaterial::Utf8 { .. } => "utf8",
        CredentialRecordSecretMaterial::Json { .. } => "json",
        CredentialRecordSecretMaterial::Binary { .. } => "binary",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_session() -> Session {
        Session {
            user_id: "user".into(),
            device_id: "device".into(),
            token: "token".into(),
            dek: vec![0; 32],
            email: "alice@example.com".into(),
            server_url: "http://127.0.0.1:1".into(),
        }
    }

    fn fixed_now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-07-05T08:00:00Z")
            .expect("fixed timestamp")
            .with_timezone(&Utc)
    }

    #[tokio::test]
    async fn periodic_tick_skips_without_opt_in() {
        let cfg = SyncConfig::default();

        let (ok, next_cfg) = run_periodic_sync_tick(dummy_session(), cfg, fixed_now(), false)
            .await
            .expect("disabled periodic tick skips without network");

        assert!(!ok.ran);
        assert_eq!(ok.reason, "disabled");
        assert!(next_cfg.periodic_sync.last_run_at.is_none());
    }

    #[test]
    fn periodic_config_rejects_too_frequent_interval() {
        let err = configure_periodic_sync(
            SyncConfig::default(),
            PeriodicSyncConfigureInput {
                enabled: Some(true),
                interval_minutes: Some(MIN_PERIODIC_SYNC_INTERVAL_MINUTES - 1),
                mode: Some(PERIODIC_SYNC_MODE_PULL_OBJECTS.into()),
            },
        )
        .expect_err("too frequent periodic sync should fail");

        assert!(err.to_string().contains("at least 15 minutes"));
    }

    #[test]
    fn profile_compatibility_quarantines_unknown_plugins() {
        let profile = SyncProfilePayload {
            payload_version: OBJECT_SYNC_PAYLOAD_VERSION,
            profile: voidb_core::SyncProfileRecord {
                id: "profile-1".into(),
                name: "private".into(),
                plugin_id: "private-plugin".into(),
                display_name: None,
                metadata: json!({ "team": "ops" }),
                default_options: Value::Null,
                credential_ref_ids: Vec::new(),
            },
            policy_ref: None,
            compatibility_ref: Some("sync_plugincompat_private".into()),
            redaction: RedactionStatus::NotRequired,
        };
        let compatibility = SyncPluginCompatibilityPayload {
            payload_version: OBJECT_SYNC_PAYLOAD_VERSION,
            plugin_id: "private-plugin".into(),
            profile_schema_id: "private-plugin.profile".into(),
            profile_schema_version: SUPPORTED_PROFILE_SCHEMA_VERSION,
            minimum_plugin_version: None,
            capability_contracts: Vec::new(),
        };

        let status = profile_compatibility_status(&profile, Some(&compatibility));
        let metadata =
            mark_imported_profile_metadata(profile.profile.metadata.clone(), false, status);

        assert!(status.unavailable);
        assert_eq!(status.reason, Some("plugin_missing"));
        assert_eq!(
            metadata["sync_import"]["plugin_availability"],
            "unavailable"
        );
        assert_eq!(metadata["sync_import"]["plugin_reason"], "plugin_missing");
        assert_eq!(metadata["sync_import"]["profile_quarantine"], true);
    }

    #[test]
    fn unavailable_audit_event_excludes_ciphertext() {
        let object = ObjectResponse {
            object_id: "sync_credrec_0123456789abcdef0123456789abcdef".into(),
            object_kind: "credential_record".into(),
            object_version: 2,
            server_revision: 7,
            deleted: false,
            manifest: json!({ "object_kind": "credential_record" }),
            ciphertext: "super-secret-ciphertext".into(),
        };

        let event = unavailable_credential_sync_audit_event(
            "credential_record_decrypt_failed",
            &object,
            Some("profile:credential"),
        );
        let encoded = serde_json::to_string(&event).expect("serialize audit event");

        assert_eq!(event.operation, AuditOperation::CredentialSyncUnavailable);
        assert_eq!(event.status, AuditEventStatus::Blocked);
        assert_eq!(event.redaction, RedactionStatus::Withheld);
        assert!(encoded.contains("credential_record_decrypt_failed"));
        assert!(!encoded.contains("super-secret-ciphertext"));
    }

    #[test]
    fn profile_policy_merge_preserves_denies_and_keeps_destructive_safe() {
        let local = ConnectionProfilePolicy {
            allowed_capabilities: vec!["query".into(), "export".into()],
            denied_capabilities: vec!["drop_table".into()],
            allow_destructive_by_default: true,
        };
        let remote = ConnectionProfilePolicy {
            allowed_capabilities: vec!["query".into(), "admin".into()],
            denied_capabilities: vec!["truncate".into()],
            allow_destructive_by_default: false,
        };

        let merged = merge_profile_policy(&local, &remote);

        assert_eq!(merged.allowed_capabilities, vec!["query"]);
        assert_eq!(
            merged.denied_capabilities,
            vec!["drop_table".to_string(), "truncate".to_string()]
        );
        assert!(!merged.allow_destructive_by_default);
    }

    #[test]
    fn json_merge_rejects_scalar_conflicts() {
        let err = merge_json_without_scalar_conflicts(
            &json!({ "theme": "light" }),
            &json!({ "theme": "dark" }),
            "app_preference.preferences",
        )
        .expect_err("scalar conflicts are unsafe");

        assert!(err.to_string().contains("scalar values differ"));
    }

    #[test]
    fn json_merge_combines_non_conflicting_objects() {
        let merged = merge_json_without_scalar_conflicts(
            &json!({ "local": { "page_size": 100 } }),
            &json!({ "remote": true, "local": { "theme": "dark" } }),
            "profile.metadata",
        )
        .expect("non-conflicting object merge");

        assert_eq!(merged["remote"], true);
        assert_eq!(merged["local"]["theme"], "dark");
        assert_eq!(merged["local"]["page_size"], 100);
    }
}
