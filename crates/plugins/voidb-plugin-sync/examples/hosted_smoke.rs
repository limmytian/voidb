//! Hosted sync smoke driver.
//!
//! This example is intentionally script-facing. It talks to a real
//! `voidb-sync-server` process over HTTP and uses only disposable local state.

use anyhow::{Context, Result, bail};
use clap::Parser;
use serde_json::json;
use voidb_core::{
    AppConfig, ConnectionConfig, ConnectionProfile, ConnectionProfilePolicy, CredentialClass,
    CredentialRef, DatabaseType, LocalProfileStore, RedactionStatus, StoredCredentialRecord,
    StoredCredentialSource,
};
use voidb_plugin_sync::client::SyncClient;
use voidb_plugin_sync::config::{self, SyncConfig};
use voidb_plugin_sync::ops::{self, LoginInput, RegisterInput};

#[derive(Debug, Parser)]
struct Args {
    #[arg(long)]
    server: String,

    #[arg(long, default_value = "hosted-smoke@example.invalid")]
    email: String,

    #[arg(long, default_value = "hosted-smoke-device")]
    device: String,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let args = Args::parse();
    let password = std::env::var("VOIDB_SYNC_SMOKE_PASSWORD")
        .unwrap_or_else(|_| "hosted-correcthorsebatterystaple".to_string());
    let voidb_dir = config::voidb_config_dir().context("resolve VOIDB_CONFIG_DIR")?;

    std::fs::write(voidb_dir.join("config.toml"), b"connections = []\n")
        .context("seed config.toml")?;

    let reg = ops::register(RegisterInput {
        server_url: args.server.clone(),
        email: args.email.clone(),
        password: password.clone(),
        device_name: args.device.clone(),
        invite_token: None,
    })
    .await
    .context("register hosted smoke account")?;
    let recovery_code = reg
        .recovery_code
        .clone()
        .context("registration should return recovery code")?;

    let login = ops::login(LoginInput {
        server_url: args.server.clone(),
        email: args.email.clone(),
        password: password.clone(),
        device_name: format!("{}-login", args.device),
    })
    .await
    .context("login hosted smoke account")?;

    let secret_samples = [
        "hosted-super-secret-password",
        password.as_str(),
        recovery_code.as_str(),
    ];
    let server_visible_samples = [
        "hosted-super-secret-password",
        password.as_str(),
        recovery_code.as_str(),
        "hosted-db.internal.example",
        "hosted_user",
        "hosted-prod-db",
        "Hosted Production DB",
        "hosted login password",
        "mysql::hosted-prod-db",
    ];

    seed_object_fixture(&voidb_dir).context("seed object-level local fixture")?;
    assert_file_excludes(
        "sync.toml after registration",
        &voidb_dir.join("sync.toml"),
        &secret_samples,
    )?;

    let (mapping_ok, mapped_cfg) = ops::migrate_credential_object_mappings(SyncConfig::load()?)
        .context("migrate credential object mappings")?;
    if mapping_ok.migrated != 1 || mapping_ok.skipped != 0 {
        bail!(
            "unexpected credential mapping counts: migrated={}, skipped={}",
            mapping_ok.migrated,
            mapping_ok.skipped
        );
    }

    let (push_ok, pushed_cfg) = ops::push_objects(login.session.clone(), mapped_cfg)
        .await
        .context("push object-level fixture")?;
    if push_ok.objects < 6 {
        bail!(
            "expected at least 6 object records, got {}",
            push_ok.objects
        );
    }

    let client = SyncClient::new(&args.server).with_token(login.session.token.clone());
    assert_object_api_excludes(&client, &server_visible_samples).await?;
    assert_file_excludes(
        "sync.toml after object push",
        &voidb_dir.join("sync.toml"),
        &secret_samples,
    )?;

    let profile_store = profile_store(&voidb_dir);
    remove_if_exists(profile_store.profiles_path())?;
    remove_if_exists(profile_store.credentials_path())?;

    let (pull_ok, _) = ops::pull_objects(login.session.clone(), pushed_cfg)
        .await
        .context("pull object-level fixture")?;
    if pull_ok.imported_profiles != 1
        || pull_ok.imported_credential_refs != 1
        || pull_ok.imported_credential_records != 1
        || pull_ok.unavailable != 0
    {
        bail!("unexpected object pull result: {pull_ok:?}");
    }

    let profiles = profile_store
        .load_profiles()
        .context("load pulled profiles")?;
    let profile = profiles
        .iter()
        .find(|candidate| candidate.id == "hosted-profile-local-1")
        .context("pulled profile missing")?;
    if profile.name != "hosted-prod-db" || profile.credential_refs.len() != 1 {
        bail!("pulled profile did not round-trip expected public metadata");
    }

    let credentials = profile_store
        .load_credential_records()
        .context("load pulled credential records")?;
    let credential = credentials
        .iter()
        .find(|record| record.id == "hosted-cred-password")
        .context("pulled credential record missing")?;
    match &credential.source {
        StoredCredentialSource::SyncedObject {
            ciphertext,
            unavailable,
            ..
        } => {
            if *unavailable {
                bail!("pulled credential record is unexpectedly unavailable");
            }
            assert_text_excludes(
                "pulled credential ciphertext",
                ciphertext,
                &["hosted-super-secret-password"],
            )?;
        }
        other => bail!("expected synced credential source, got {other:?}"),
    }
    assert_file_excludes(
        "pulled credential store",
        profile_store.credentials_path(),
        &["hosted-super-secret-password", "hosted-db.internal.example"],
    )?;

    println!("hosted sync smoke passed");
    println!("server_url={}", args.server);
    println!("objects_pushed={}", push_ok.objects);
    println!("objects_pulled={}", pull_ok.objects);
    println!("imported_profiles={}", pull_ok.imported_profiles);
    println!(
        "imported_credential_records={}",
        pull_ok.imported_credential_records
    );
    Ok(())
}

fn seed_object_fixture(voidb_dir: &std::path::Path) -> Result<()> {
    let legacy_config = AppConfig {
        connections: vec![ConnectionConfig {
            name: "hosted-prod-db".into(),
            db_type: DatabaseType::MySQL,
            plugin_id: None,
            plugin_config: Some(json!({
                "host": "hosted-db.internal.example",
                "username": "hosted_user",
                "password": "hosted-super-secret-password"
            })),
        }],
        ..Default::default()
    };
    legacy_config
        .save_to_path_with_password(&voidb_dir.join("config.toml"), None)
        .context("write hosted legacy config")?;

    let profile_store = profile_store(voidb_dir);
    let profile = ConnectionProfile {
        id: "hosted-profile-local-1".into(),
        name: "hosted-prod-db".into(),
        plugin_id: "mysql".into(),
        display_name: Some("Hosted Production DB".into()),
        metadata: json!({ "tier": "hosted-smoke" }),
        default_options: json!({ "read_only": true }),
        credential_refs: vec![CredentialRef {
            id: "hosted-cred-password".into(),
            class: CredentialClass::Password,
            label: Some("hosted login password".into()),
        }],
        policy: ConnectionProfilePolicy::default(),
    };
    profile_store
        .save_profiles(vec![profile.clone()])
        .context("write hosted profile store")?;
    profile_store
        .save_credential_records(vec![StoredCredentialRecord {
            id: "hosted-cred-password".into(),
            profile_id: profile.id,
            plugin_id: "mysql".into(),
            class: CredentialClass::Password,
            label: Some("hosted login password".into()),
            source: StoredCredentialSource::LegacyPluginConfig {
                legacy_connection_key: "mysql::hosted-prod-db".into(),
                path: "password".into(),
            },
            created_at: chrono::Utc::now(),
            redaction: RedactionStatus::Withheld,
        }])
        .context("write hosted credential store")?;
    Ok(())
}

async fn assert_object_api_excludes(client: &SyncClient, forbidden: &[&str]) -> Result<()> {
    let summaries = client.list_objects(true).await?;
    if summaries.is_empty() {
        bail!("hosted smoke pushed no object summaries");
    }
    for summary in summaries {
        assert_text_excludes(
            &format!("object summary {}", summary.object_id),
            &format!("{summary:?}"),
            forbidden,
        )?;
        let latest = client
            .get_object_latest(&summary.object_id)
            .await?
            .context("object latest missing")?;
        assert_text_excludes(
            &format!("object latest {}", latest.object_id),
            &format!("{latest:?}"),
            forbidden,
        )?;
        assert_text_excludes(
            &format!("object latest manifest {}", latest.object_id),
            &latest.manifest.to_string(),
            forbidden,
        )?;
        assert_text_excludes(
            &format!("object latest ciphertext {}", latest.object_id),
            &latest.ciphertext,
            forbidden,
        )?;
    }
    Ok(())
}

fn profile_store(voidb_dir: &std::path::Path) -> LocalProfileStore {
    LocalProfileStore::new(
        voidb_dir.join("profiles.json"),
        voidb_dir.join("credentials.json"),
    )
}

fn assert_file_excludes(label: &str, path: &std::path::Path, forbidden: &[&str]) -> Result<()> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("read {} for plaintext scan", path.display()))?;
    assert_text_excludes(label, &text, forbidden)
}

fn assert_text_excludes(label: &str, text: &str, forbidden: &[&str]) -> Result<()> {
    for needle in forbidden {
        if text.contains(needle) {
            bail!("{label} leaked forbidden sample: {needle}");
        }
    }
    Ok(())
}

fn remove_if_exists(path: &std::path::Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("remove {}", path.display())),
    }
}
