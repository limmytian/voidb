//! End-to-end test: drive the client `ops` module against an in-process
//! `voidb-sync-server`.
//!
//! This test overrides `XDG_CONFIG_HOME` to a `TempDir` so that the sync
//! plugin's reads/writes of `~/.config/voidb/` land in a disposable sandbox.
//!
//! Author: Limmy

use std::net::SocketAddr;
use std::path::Path;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::json;
use tempfile::TempDir;
use tokio::net::TcpListener;

use voidb_core::{
    AppConfig, ConnectionConfig, ConnectionProfile, ConnectionProfilePolicy, CredentialClass,
    CredentialRecordSecretMaterial, CredentialRef, DatabaseType, LocalProfileStore,
    RedactionStatus, StoredCredentialRecord, StoredCredentialSource,
};
use voidb_plugin_sync::client::{ObjectActor, PutObjectRequest, SyncClient};
use voidb_plugin_sync::config::SyncConfig;
use voidb_plugin_sync::crypto;
use voidb_plugin_sync::ops::{
    self, CredentialReenrollInput, CredentialReenrollMaterial, LoginInput,
    ObjectConflictResolutionInput, RecoverInput, RegisterInput,
};
use voidb_sync_server::{AppState, Config, router};

fn server_config(tmp: &TempDir) -> Config {
    toml::from_str::<Config>(&format!(
        r#"
bind = "127.0.0.1:0"
data_dir = "{}"
max_blob_bytes = 1048576
history_keep = 5
registration = "open"
log_level = "error"
"#,
        tmp.path().display()
    ))
    .unwrap()
}

async fn spawn_server(tmp: &TempDir) -> SocketAddr {
    let cfg = server_config(tmp);
    let state = AppState::bootstrap(cfg).await.unwrap();
    let app = router(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    addr
}

fn assert_text_excludes(label: &str, text: &str, forbidden: &[&str]) {
    for needle in forbidden {
        assert!(
            !text.contains(needle),
            "{label} leaked forbidden sample: {needle}"
        );
    }
}

fn assert_error_excludes(label: &str, error: &voidb_plugin_sync::SyncError, forbidden: &[&str]) {
    let text = format!("{error:?}\n{error}");
    assert_text_excludes(label, &text, forbidden);
}

fn assert_bytes_exclude(label: &str, bytes: &[u8], forbidden: &[&str]) {
    for needle in forbidden {
        let needle_bytes = needle.as_bytes();
        assert!(
            !bytes
                .windows(needle_bytes.len())
                .any(|window| window == needle_bytes),
            "{label} leaked forbidden sample: {needle}"
        );
    }
}

fn assert_path_tree_excludes(label: &str, root: &Path, forbidden: &[&str]) {
    fn visit(path: &Path, label: &str, forbidden: &[&str]) {
        if path.is_dir() {
            for entry in std::fs::read_dir(path).expect("read plaintext scan dir") {
                visit(
                    &entry.expect("plaintext scan entry").path(),
                    label,
                    forbidden,
                );
            }
            return;
        }
        let bytes = std::fs::read(path).expect("read plaintext scan file");
        assert_bytes_exclude(&format!("{label}: {}", path.display()), &bytes, forbidden);
    }

    visit(root, label, forbidden);
}

async fn assert_object_api_excludes_plaintext(client: &SyncClient, forbidden: &[&str]) {
    let summaries = client
        .list_objects(true)
        .await
        .expect("list object summaries for plaintext scan");
    assert!(!summaries.is_empty(), "object fixture should push objects");
    for summary in summaries {
        assert_text_excludes(
            &format!("object summary {}", summary.object_id),
            &format!("{summary:?}"),
            forbidden,
        );
        let latest = client
            .get_object_latest(&summary.object_id)
            .await
            .expect("fetch object latest for plaintext scan")
            .expect("object latest exists");
        assert_text_excludes(
            &format!("object latest {}", latest.object_id),
            &format!("{latest:?}"),
            forbidden,
        );
        assert_text_excludes(
            &format!("object latest manifest {}", latest.object_id),
            &latest.manifest.to_string(),
            forbidden,
        );
        assert_text_excludes(
            &format!("object latest ciphertext {}", latest.object_id),
            &latest.ciphertext,
            forbidden,
        );
    }
}

/// Point the plugin at a scratch `VOIDB_CONFIG_DIR` so we don't touch the real
/// user config. Returns a guard that restores the env var on drop.
struct ConfigSandbox {
    _config_tmp: TempDir,
    audit_tmp: TempDir,
    prev_config: Option<String>,
    prev_audit: Option<String>,
}

impl ConfigSandbox {
    fn new() -> Self {
        let config_tmp = TempDir::new().unwrap();
        let audit_tmp = TempDir::new().unwrap();
        let prev_config = std::env::var("VOIDB_CONFIG_DIR").ok();
        let prev_audit = std::env::var("VOIDB_AUDIT_PATH").ok();
        // SAFETY: tests in this binary run serially by default; the unsafe is
        // required because `set_var` is marked unsafe since Rust 1.87.
        unsafe {
            std::env::set_var("VOIDB_CONFIG_DIR", config_tmp.path());
            std::env::set_var("VOIDB_AUDIT_PATH", audit_tmp.path().join("events.jsonl"));
        };
        Self {
            _config_tmp: config_tmp,
            audit_tmp,
            prev_config,
            prev_audit,
        }
    }

    fn audit_path(&self) -> std::path::PathBuf {
        self.audit_tmp.path().join("events.jsonl")
    }
}

impl Drop for ConfigSandbox {
    fn drop(&mut self) {
        unsafe {
            match &self.prev_config {
                Some(v) => std::env::set_var("VOIDB_CONFIG_DIR", v),
                None => std::env::remove_var("VOIDB_CONFIG_DIR"),
            }
            match &self.prev_audit {
                Some(v) => std::env::set_var("VOIDB_AUDIT_PATH", v),
                None => std::env::remove_var("VOIDB_AUDIT_PATH"),
            }
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn register_push_pull() {
    let sandbox = ConfigSandbox::new();
    let server_tmp = TempDir::new().unwrap();
    let addr = spawn_server(&server_tmp).await;
    let base = format!("http://{}", addr);

    // Seed some files in the "local" voidb config dir.
    let voidb_dir = voidb_plugin_sync::config::voidb_config_dir().unwrap();
    std::fs::write(voidb_dir.join("config.toml"), b"connections = []\n").unwrap();
    std::fs::create_dir_all(voidb_dir.join("plugins").join("mysql")).unwrap();
    std::fs::write(
        voidb_dir
            .join("plugins")
            .join("mysql")
            .join("snippets.json"),
        b"{\"snippets\":[\"select 1\"]}",
    )
    .unwrap();

    // Register.
    let reg = ops::register(RegisterInput {
        server_url: base.clone(),
        email: "alice@example.com".into(),
        password: "correcthorsebatterystaple".into(),
        device_name: "e2e-device".into(),
        invite_token: None,
    })
    .await
    .expect("register");

    assert_eq!(reg.config.email.as_deref(), Some("alice@example.com"));
    let recovery_code = reg
        .recovery_code
        .clone()
        .expect("register returns recovery code");
    assert!(recovery_code.starts_with("vbrec-"));
    let secret_plaintext_samples = [
        "super-secret-password",
        "rotated-secret-password",
        "second-secret-password",
        "new-correcthorsebatterystaple",
        recovery_code.as_str(),
    ];
    let server_visible_plaintext_samples = [
        "super-secret-password",
        "rotated-secret-password",
        "second-secret-password",
        "new-correcthorsebatterystaple",
        recovery_code.as_str(),
        "db.internal.example",
        "app_user",
        "prod-db",
        "Production DB",
        "login password",
        "mysql::prod-db",
    ];
    let sync_toml_after_register = std::fs::read_to_string(voidb_dir.join("sync.toml")).unwrap();
    assert_text_excludes(
        "sync.toml after register",
        &sync_toml_after_register,
        &secret_plaintext_samples,
    );

    // Push.
    let (push_ok, cfg) = ops::push(reg.session.clone(), reg.config.clone(), "full", None)
        .await
        .expect("push");
    assert_eq!(push_ok.revision, 1);
    assert!(push_ok.files >= 2, "expected at least 2 bundled files");
    assert_eq!(cfg.revision_for("full"), 1);

    // Nuke the local dir, simulate a fresh machine.
    for entry in std::fs::read_dir(&voidb_dir).unwrap() {
        let entry = entry.unwrap();
        let p = entry.path();
        if p.is_dir() {
            std::fs::remove_dir_all(&p).unwrap();
        } else if p.file_name().and_then(|n| n.to_str()) != Some("sync.toml") {
            std::fs::remove_file(&p).unwrap();
        }
    }
    assert!(!voidb_dir.join("config.toml").exists());

    // Login from "another device" using the same password.
    let login = ops::login(LoginInput {
        server_url: base.clone(),
        email: "alice@example.com".into(),
        password: "correcthorsebatterystaple".into(),
        device_name: "e2e-device-2".into(),
    })
    .await
    .expect("login");

    // Pull and verify files are back.
    let (pull_ok, _cfg) = ops::pull(login.session.clone(), login.config.clone(), "full")
        .await
        .expect("pull");
    assert_eq!(pull_ok.revision, 1);

    assert_eq!(
        std::fs::read(voidb_dir.join("config.toml")).unwrap(),
        b"connections = []\n"
    );
    assert_eq!(
        std::fs::read(
            voidb_dir
                .join("plugins")
                .join("mysql")
                .join("snippets.json")
        )
        .unwrap(),
        b"{\"snippets\":[\"select 1\"]}"
    );

    // Push again — revision should increment to 2.
    std::fs::write(voidb_dir.join("config.toml"), b"connections = [\"x\"]\n").unwrap();
    let (push2, _cfg) = ops::push(login.session.clone(), login.config.clone(), "full", None)
        .await
        .expect("push2");
    assert_eq!(push2.revision, 2);

    // Object sync uses opaque server-visible IDs and keeps sync.toml device-local.
    let profile_store = LocalProfileStore::new(
        voidb_dir.join("profiles.json"),
        voidb_dir.join("credentials.json"),
    );
    let legacy_config = AppConfig {
        connections: vec![ConnectionConfig {
            name: "prod-db".into(),
            db_type: DatabaseType::MySQL,
            plugin_id: None,
            plugin_config: Some(json!({
                "host": "db.internal.example",
                "username": "app_user",
                "password": "super-secret-password"
            })),
        }],
        ..Default::default()
    };
    legacy_config
        .save_to_path_with_password(&voidb_dir.join("config.toml"), None)
        .expect("write legacy config");
    let profile = ConnectionProfile {
        id: "profile-local-1".into(),
        name: "prod-db".into(),
        plugin_id: "mysql".into(),
        display_name: Some("Production DB".into()),
        metadata: json!({ "tier": "prod" }),
        default_options: json!({ "read_only": true }),
        credential_refs: vec![CredentialRef {
            id: "cred-password".into(),
            class: CredentialClass::Password,
            label: Some("login password".into()),
        }],
        policy: ConnectionProfilePolicy::default(),
    };
    profile_store
        .save_profiles(vec![profile.clone()])
        .expect("write profile store");
    profile_store
        .save_credential_records(vec![StoredCredentialRecord {
            id: "cred-password".into(),
            profile_id: profile.id.clone(),
            plugin_id: "mysql".into(),
            class: CredentialClass::Password,
            label: Some("login password".into()),
            source: StoredCredentialSource::LegacyPluginConfig {
                legacy_connection_key: "mysql::prod-db".into(),
                path: "password".into(),
            },
            created_at: chrono::Utc::now(),
            redaction: RedactionStatus::Withheld,
        }])
        .expect("write credential store");

    let (mapping_ok, mapped_cfg) =
        ops::migrate_credential_object_mappings(SyncConfig::load().unwrap())
            .expect("migrate credential object mappings");
    assert_eq!(mapping_ok.migrated, 1);
    assert_eq!(mapping_ok.skipped, 0);
    assert!(
        mapped_cfg
            .object_mapping("credential_record", "profile-local-1:cred-password")
            .is_some()
    );

    let (object_push, object_cfg) = ops::push_objects(login.session.clone(), mapped_cfg)
        .await
        .expect("object push");
    assert!(object_push.objects >= 6);
    let object_client = SyncClient::new(&base).with_token(login.session.token.clone());
    assert_object_api_excludes_plaintext(&object_client, &server_visible_plaintext_samples).await;
    assert_path_tree_excludes(
        "sync server data dir after object push",
        server_tmp.path(),
        &server_visible_plaintext_samples,
    );
    let profile_mapping = object_cfg
        .object_mapping("profile", &profile.id)
        .expect("profile mapping");
    assert!(profile_mapping.object_id.starts_with("sync_profile_"));
    assert!(!profile_mapping.object_id.contains(&profile.id));

    let stale_direct_plaintext = "client-stale-secret";
    let stale_direct_ciphertext = B64.encode(stale_direct_plaintext.as_bytes());
    let stale_base_revision = profile_mapping
        .server_revision
        .checked_sub(1)
        .expect("profile mapping has a server revision");
    let stale_direct_error = object_client
        .put_object(
            &profile_mapping.object_id,
            &PutObjectRequest {
                schema_version: 1,
                object_kind: "profile".into(),
                object_version: profile_mapping.object_version + 1,
                base_server_revision: Some(stale_base_revision),
                payload_hash: format!("sha256:{}", "d".repeat(64)),
                payload_size: stale_direct_plaintext.len() as u64,
                updated_at: "2026-07-05T00:00:00Z".into(),
                updated_by: ObjectActor {
                    actor_type: "human".into(),
                    actor_id: login.session.email.clone(),
                    device_id: login.session.device_id.clone(),
                },
                deleted: false,
                redaction: "withheld".into(),
                ciphertext: stale_direct_ciphertext.clone(),
            },
        )
        .await
        .expect_err("stale direct object write should conflict");
    match &stale_direct_error {
        voidb_plugin_sync::SyncError::ObjectConflict {
            object_id,
            object_kind,
            details,
        } => {
            assert_eq!(object_id, &profile_mapping.object_id);
            assert_eq!(object_kind, "profile");
            assert_eq!(details.attempted_base_server_revision, stale_base_revision);
            assert_eq!(
                details.current_server_revision,
                profile_mapping.server_revision
            );
            assert_eq!(
                details.attempted_object_version,
                profile_mapping.object_version + 1
            );
            assert_eq!(
                details.current_object_version,
                profile_mapping.object_version
            );
            assert_eq!(details.redaction, "withheld");
            assert!(details.server_updated_at.is_some());
        }
        other => panic!("expected direct object conflict, got {other:?}"),
    }
    assert_error_excludes(
        "stale direct object conflict",
        &stale_direct_error,
        &[
            login.session.email.as_str(),
            stale_direct_plaintext,
            stale_direct_ciphertext.as_str(),
        ],
    );
    let latest_after_stale = object_client
        .get_object_latest(&profile_mapping.object_id)
        .await
        .expect("latest after stale direct object write")
        .expect("profile object latest after stale direct write");
    assert_eq!(
        latest_after_stale.server_revision,
        profile_mapping.server_revision
    );
    assert_eq!(
        latest_after_stale.object_version,
        profile_mapping.object_version
    );
    assert_text_excludes(
        "latest after stale direct object write",
        &format!("{latest_after_stale:?}"),
        &[stale_direct_plaintext, stale_direct_ciphertext.as_str()],
    );

    let unauthenticated_error = SyncClient::new(&base)
        .list_objects(true)
        .await
        .expect_err("object list requires a session token");
    assert!(matches!(
        unauthenticated_error,
        voidb_plugin_sync::SyncError::NotLoggedIn
    ));
    assert_error_excludes(
        "unauthenticated object list",
        &unauthenticated_error,
        &server_visible_plaintext_samples,
    );
    let invalid_token = "invalid-token-super-secret-password";
    let invalid_token_error = SyncClient::new(&base)
        .with_token(invalid_token.into())
        .get_object_latest(&profile_mapping.object_id)
        .await
        .expect_err("invalid token cannot fetch objects");
    assert!(matches!(
        invalid_token_error,
        voidb_plugin_sync::SyncError::Unauthorized
    ));
    assert_error_excludes(
        "invalid-token object latest",
        &invalid_token_error,
        &[
            invalid_token,
            "super-secret-password",
            "db.internal.example",
        ],
    );

    let encrypted_profile_payload = B64
        .decode(&latest_after_stale.ciphertext)
        .expect("decode encrypted profile payload");
    let wrong_dek = vec![0xA5; login.session.dek.len()];
    let wrong_key_error = crypto::decrypt_bundle(&wrong_dek, &encrypted_profile_payload)
        .expect_err("wrong DEK cannot decrypt object payload");
    assert_error_excludes(
        "wrong DEK object decrypt",
        &wrong_key_error,
        &server_visible_plaintext_samples,
    );
    assert_error_excludes(
        "wrong DEK object decrypt ciphertext",
        &wrong_key_error,
        &[latest_after_stale.ciphertext.as_str()],
    );

    assert!(voidb_dir.join("sync.toml").exists());
    let sync_toml = std::fs::read_to_string(voidb_dir.join("sync.toml")).unwrap();
    assert_text_excludes(
        "sync.toml after object push",
        &sync_toml,
        &secret_plaintext_samples,
    );

    std::fs::remove_file(profile_store.profiles_path()).unwrap();
    std::fs::remove_file(profile_store.credentials_path()).unwrap();
    assert!(!profile_store.profiles_path().exists());
    assert!(!profile_store.credentials_path().exists());

    let (object_pull, pulled_cfg) = ops::pull_objects(login.session.clone(), object_cfg)
        .await
        .expect("object pull");
    assert!(object_pull.objects >= 6);
    assert_eq!(object_pull.imported_profiles, 1);
    assert_eq!(object_pull.imported_credential_refs, 1);
    assert_eq!(object_pull.imported_credential_records, 1);
    assert!(pulled_cfg.device_id.is_some());
    assert!(voidb_dir.join("sync.toml").exists());

    let imported_profiles = profile_store
        .load_profiles()
        .expect("load imported profiles");
    let imported = imported_profiles
        .iter()
        .find(|candidate| candidate.id == profile.id)
        .expect("imported profile");
    assert_eq!(imported.name, "prod-db");
    assert_eq!(imported.credential_refs.len(), 1);
    assert_eq!(
        imported.metadata["sync_import"]["credential_material"],
        "not_required"
    );
    assert_eq!(
        imported.metadata["sync_import"]["plugin_availability"],
        "available"
    );
    assert_eq!(
        imported.metadata["sync_import"]["profile_quarantine"],
        false
    );
    let imported_credentials = profile_store
        .load_credential_records()
        .expect("load imported credentials");
    let imported_credential = imported_credentials
        .iter()
        .find(|record| record.id == "cred-password")
        .expect("imported credential record");
    match &imported_credential.source {
        StoredCredentialSource::SyncedObject {
            object_id,
            ciphertext,
            unavailable,
            ..
        } => {
            assert!(object_id.starts_with("sync_credrec_"));
            assert!(!ciphertext.contains("super-secret-password"));
            assert!(!unavailable);
        }
        other => panic!("expected synced credential source, got {other:?}"),
    }
    let credentials_json = std::fs::read_to_string(profile_store.credentials_path()).unwrap();
    assert_text_excludes(
        "credential store after object pull",
        &credentials_json,
        &secret_plaintext_samples,
    );
    assert!(!credentials_json.contains("db.internal.example"));

    let stale_reenroll_cfg = pulled_cfg.clone();
    let (reenroll_ok, _reenroll_cfg) = ops::reenroll_credential_record(
        login.session.clone(),
        pulled_cfg,
        CredentialReenrollInput {
            profile_id: profile.id.clone(),
            credential_ref_id: "cred-password".into(),
            material: CredentialReenrollMaterial::Provided(CredentialRecordSecretMaterial::Utf8 {
                value: "rotated-secret-password".into(),
            }),
        },
    )
    .await
    .expect("credential re-enroll");
    assert!(reenroll_ok.object_id.starts_with("sync_credrec_"));
    assert!(reenroll_ok.object_version >= 2);

    let reenrolled_credentials = profile_store
        .load_credential_records()
        .expect("load reenrolled credentials");
    let reenrolled_credential = reenrolled_credentials
        .iter()
        .find(|record| record.id == "cred-password")
        .expect("reenrolled credential record");
    match &reenrolled_credential.source {
        StoredCredentialSource::SyncedObject {
            object_id,
            object_version,
            ciphertext,
            unavailable,
            ..
        } => {
            assert_eq!(object_id, &reenroll_ok.object_id);
            assert_eq!(*object_version, reenroll_ok.object_version);
            assert!(!ciphertext.contains("rotated-secret-password"));
            assert!(!unavailable);
        }
        other => panic!("expected synced credential source after re-enroll, got {other:?}"),
    }

    let conflict = ops::reenroll_credential_record(
        login.session.clone(),
        stale_reenroll_cfg,
        CredentialReenrollInput {
            profile_id: profile.id.clone(),
            credential_ref_id: "cred-password".into(),
            material: CredentialReenrollMaterial::Provided(CredentialRecordSecretMaterial::Utf8 {
                value: "second-secret-password".into(),
            }),
        },
    )
    .await
    .expect_err("stale credential re-enroll should conflict");
    match conflict {
        voidb_plugin_sync::SyncError::ObjectConflict {
            object_id, details, ..
        } => {
            assert_eq!(object_id, reenroll_ok.object_id);
            assert!(details.current_server_revision >= reenroll_ok.server_revision);
            assert_eq!(details.current_object_version, reenroll_ok.object_version);
        }
        other => panic!("expected object conflict, got {other:?}"),
    }
    let conflict_cfg = SyncConfig::load().expect("load conflict config");
    let conflict_marker = conflict_cfg
        .object_conflicts
        .values()
        .find(|conflict| conflict.object_id == reenroll_ok.object_id)
        .expect("credential conflict marker");
    assert_eq!(conflict_marker.object_kind, "credential_record");
    assert_eq!(
        conflict_marker.unavailable_reason.as_deref(),
        Some("object_revision_conflict")
    );
    let credential_conflict_revision = conflict_marker.current_server_revision;

    let handoff = ops::credential_conflict_handoff(conflict_cfg.clone(), &reenroll_ok.object_id)
        .expect("credential handoff");
    assert_eq!(handoff.profile_id, profile.id);
    assert_eq!(handoff.credential_ref_id, "cred-password");
    assert!(handoff.command.contains("credential re-enroll"));
    assert!(handoff.command.contains("--secret-env"));

    let (keep_remote, keep_remote_cfg) = ops::resolve_keep_remote(
        login.session.clone(),
        conflict_cfg,
        ObjectConflictResolutionInput {
            object_kind: "credential_record".into(),
            object_id: reenroll_ok.object_id.clone(),
            current_server_revision: Some(credential_conflict_revision),
            acknowledge_delete: false,
        },
    )
    .await
    .expect("keep remote credential conflict");
    assert_eq!(keep_remote.mode, "keep-remote");
    assert_eq!(keep_remote.object_kind, "credential_record");
    assert!(!keep_remote.unavailable);
    assert!(
        keep_remote_cfg
            .object_conflicts
            .values()
            .all(|conflict| conflict.object_id != reenroll_ok.object_id)
    );

    let stale_profile_cfg = keep_remote_cfg.clone();
    let mut remote_update_profiles = profile_store
        .load_profiles()
        .expect("load profiles for remote update");
    let remote_profile = remote_update_profiles
        .iter_mut()
        .find(|candidate| candidate.id == profile.id)
        .expect("profile for remote update");
    remote_profile.metadata = json!({ "tier": "remote" });
    profile_store
        .save_profiles(remote_update_profiles)
        .expect("write remote-update profile");
    let (_, remote_profile_cfg) = ops::push_objects(login.session.clone(), keep_remote_cfg)
        .await
        .expect("push remote profile update");
    let profile_remote_revision = remote_profile_cfg
        .object_mapping("profile", &profile.id)
        .expect("remote profile mapping")
        .server_revision;
    let profile_object_id = stale_profile_cfg
        .object_mapping("profile", &profile.id)
        .expect("stale profile mapping")
        .object_id
        .clone();

    let mut pull_conflict_profiles = profile_store
        .load_profiles()
        .expect("load profiles for pull conflict");
    let pull_conflict_profile = pull_conflict_profiles
        .iter_mut()
        .find(|candidate| candidate.id == profile.id)
        .expect("profile for pull conflict");
    pull_conflict_profile.metadata = json!({ "tier": "local-conflict" });
    profile_store
        .save_profiles(pull_conflict_profiles)
        .expect("write pull-conflict profile");
    let (pull_conflict_ok, pull_conflict_cfg) =
        ops::pull_objects(login.session.clone(), stale_profile_cfg)
            .await
            .expect("pull records profile conflict");
    assert!(pull_conflict_ok.unavailable >= 1);
    let pull_conflict_marker = pull_conflict_cfg
        .object_conflicts
        .values()
        .find(|conflict| conflict.object_id == profile_object_id)
        .expect("pull-time profile conflict marker");
    assert_eq!(
        pull_conflict_marker.unavailable_reason.as_deref(),
        Some("pull_time_object_conflict")
    );
    let local_after_conflict = profile_store
        .load_profiles()
        .expect("load profiles after pull conflict")
        .into_iter()
        .find(|candidate| candidate.id == profile.id)
        .expect("local profile preserved after pull conflict");
    assert_eq!(local_after_conflict.metadata["tier"], "local-conflict");

    let mut force_profiles = profile_store
        .load_profiles()
        .expect("load profiles for force");
    let force_profile = force_profiles
        .iter_mut()
        .find(|candidate| candidate.id == profile.id)
        .expect("profile for force");
    force_profile.metadata = json!({ "tier": "forced-local" });
    profile_store
        .save_profiles(force_profiles)
        .expect("write force profile");
    let (force_ok, force_cfg) = ops::resolve_keep_local_force(
        login.session.clone(),
        pull_conflict_cfg,
        ObjectConflictResolutionInput {
            object_kind: "profile".into(),
            object_id: profile_object_id.clone(),
            current_server_revision: Some(profile_remote_revision),
            acknowledge_delete: false,
        },
    )
    .await
    .expect("keep local force profile");
    assert_eq!(force_ok.mode, "keep-local-force");
    assert_eq!(force_ok.previous_server_revision, profile_remote_revision);
    let forced_profile_mapping = force_cfg
        .object_mapping("profile", &profile.id)
        .expect("forced profile mapping");
    assert_eq!(
        forced_profile_mapping.server_revision,
        force_ok.server_revision
    );
    assert!(force_ok.server_revision > profile_remote_revision);

    let stale_tombstone_cfg = force_cfg.clone();
    let (tombstone_ok, tombstone_cfg) = ops::resolve_delete_tombstone(
        login.session.clone(),
        force_cfg,
        ObjectConflictResolutionInput {
            object_kind: "profile".into(),
            object_id: profile_object_id.clone(),
            current_server_revision: Some(force_ok.server_revision),
            acknowledge_delete: true,
        },
    )
    .await
    .expect("delete tombstone profile");
    assert_eq!(tombstone_ok.mode, "delete-tombstone");
    assert!(tombstone_ok.unavailable);
    assert!(
        profile_store
            .load_profiles()
            .expect("load profiles after tombstone")
            .iter()
            .all(|candidate| candidate.id != profile.id)
    );
    assert!(
        tombstone_cfg
            .object_mapping("profile", &profile.id)
            .expect("tombstone profile mapping")
            .unavailable
    );

    let mut restored_profiles = profile_store
        .load_profiles()
        .expect("load profiles before remote tombstone pull");
    let mut restored_profile = profile.clone();
    restored_profile.metadata = json!({ "tier": "local-after-remote-delete" });
    restored_profiles.push(restored_profile);
    profile_store
        .save_profiles(restored_profiles)
        .expect("restore local profile before remote tombstone pull");
    let (remote_tombstone_pull, remote_tombstone_cfg) =
        ops::pull_objects(login.session.clone(), stale_tombstone_cfg)
            .await
            .expect("pull records remote tombstone");
    assert!(remote_tombstone_pull.unavailable >= 1);
    let remote_tombstone_marker = remote_tombstone_cfg
        .object_conflicts
        .values()
        .find(|conflict| conflict.object_id == profile_object_id)
        .expect("remote tombstone conflict marker");
    assert_eq!(
        remote_tombstone_marker.unavailable_reason.as_deref(),
        Some("remote_tombstone")
    );
    assert!(
        profile_store
            .load_profiles()
            .expect("load profiles after remote tombstone conflict")
            .iter()
            .any(|candidate| candidate.id == profile.id)
    );
    let (keep_remote_tombstone, _) = ops::resolve_keep_remote(
        login.session.clone(),
        remote_tombstone_cfg,
        ObjectConflictResolutionInput {
            object_kind: "profile".into(),
            object_id: profile_object_id,
            current_server_revision: Some(tombstone_ok.server_revision),
            acknowledge_delete: false,
        },
    )
    .await
    .expect("keep remote tombstone");
    assert_eq!(
        keep_remote_tombstone.local_action,
        "applied remote tombstone"
    );
    assert!(
        profile_store
            .load_profiles()
            .expect("load profiles after keeping remote tombstone")
            .iter()
            .all(|candidate| candidate.id != profile.id)
    );

    let audit_jsonl = std::fs::read_to_string(sandbox.audit_path()).unwrap();
    assert!(audit_jsonl.contains("credential_sync_mapping_migrated"));
    assert!(audit_jsonl.contains("credential_sync_push"));
    assert!(audit_jsonl.contains("credential_sync_pull"));
    assert!(audit_jsonl.contains("credential_sync_reenroll"));
    assert!(audit_jsonl.contains("credential_sync_reenroll_handoff"));
    assert!(audit_jsonl.contains("sync_object_conflict"));
    assert!(audit_jsonl.contains("sync_object_keep_remote"));
    assert!(audit_jsonl.contains("sync_object_force_push"));
    assert!(audit_jsonl.contains("sync_object_tombstone"));
    assert_text_excludes("sync audit log", &audit_jsonl, &secret_plaintext_samples);
    assert!(!audit_jsonl.contains("db.internal.example"));

    // Login with wrong password fails.
    let err = ops::login(LoginInput {
        server_url: base.clone(),
        email: "alice@example.com".into(),
        password: "wrong-password".into(),
        device_name: "nope".into(),
    })
    .await
    .unwrap_err();
    match err {
        voidb_plugin_sync::SyncError::Unauthorized => {}
        other => panic!("expected Unauthorized, got {other:?}"),
    }

    let recovery_err = ops::recover_password(RecoverInput {
        server_url: base.clone(),
        email: "alice@example.com".into(),
        recovery_code: "vbrec-wrong-recovery-code".into(),
        new_password: "new-correcthorsebatterystaple".into(),
        device_name: "bad-recovery".into(),
    })
    .await
    .expect_err("wrong recovery code fails");
    let recovery_err_text = format!("{recovery_err:?}");
    assert!(!recovery_err_text.contains("connections = [\"x\"]"));
    assert_text_excludes(
        "wrong recovery error",
        &recovery_err_text,
        &secret_plaintext_samples,
    );

    let recovered = ops::recover_password(RecoverInput {
        server_url: base.clone(),
        email: "alice@example.com".into(),
        recovery_code: recovery_code.clone(),
        new_password: "new-correcthorsebatterystaple".into(),
        device_name: "recovered-device".into(),
    })
    .await
    .expect("recover with recovery code");
    assert_eq!(recovered.session.dek, reg.session.dek);
    assert_eq!(recovered.config.email.as_deref(), Some("alice@example.com"));
    let sync_toml_after_recovery = std::fs::read_to_string(voidb_dir.join("sync.toml")).unwrap();
    assert_text_excludes(
        "sync.toml after recovery",
        &sync_toml_after_recovery,
        &secret_plaintext_samples,
    );

    let old_password_err = ops::login(LoginInput {
        server_url: base.clone(),
        email: "alice@example.com".into(),
        password: "correcthorsebatterystaple".into(),
        device_name: "old-password".into(),
    })
    .await
    .expect_err("old password rejected after recovery reset");
    match old_password_err {
        voidb_plugin_sync::SyncError::Unauthorized => {}
        other => panic!("expected Unauthorized after recovery reset, got {other:?}"),
    }

    let new_login = ops::login(LoginInput {
        server_url: base.clone(),
        email: "alice@example.com".into(),
        password: "new-correcthorsebatterystaple".into(),
        device_name: "new-password".into(),
    })
    .await
    .expect("login with new password");
    assert_eq!(new_login.session.dek, reg.session.dek);
    let final_object_client = SyncClient::new(&base).with_token(new_login.session.token.clone());
    assert_object_api_excludes_plaintext(&final_object_client, &server_visible_plaintext_samples)
        .await;
    assert_path_tree_excludes(
        "sync server data dir final",
        server_tmp.path(),
        &server_visible_plaintext_samples,
    );

    let (recovered_pull, _) =
        ops::pull(recovered.session.clone(), recovered.config.clone(), "full")
            .await
            .expect("pull after recovery reset");
    assert_eq!(recovered_pull.revision, 2);

    drop(sandbox);
}
