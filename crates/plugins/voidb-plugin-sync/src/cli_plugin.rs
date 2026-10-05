//! CLI plugin for `voidb sync` subcommands.
//!
//! Commands:
//!   voidb sync login   --server <url> --email <email> [--device <name>]
//!   voidb sync logout
//!   voidb sync push    [--kind <kind>]
//!   voidb sync pull    [--kind <kind>]
//!   voidb sync status
//!
//! Password is read from VOIDB_SYNC_PASSWORD env var or stdin (via rpassword).
//!
//! Author: Limmy

use std::collections::BTreeMap;

use async_trait::async_trait;
use chrono::Utc;
use clap::{Arg, ArgAction, ArgMatches, Command};
use serde::Serialize;

use voidb_core::plugin::cli::{CliContext, CliPlugin};
use voidb_core::{CredentialRecordSecretMaterial, VoidbError};

use crate::client::SyncClient;
use crate::config::SyncConfig;
use crate::ops::{
    self, CredentialReenrollInput, CredentialReenrollMaterial, LoginInput,
    ObjectConflictResolutionInput, PeriodicSyncConfigureInput, RecoverInput,
};
use crate::token_store::{self, TokenStoreBackend, TokenStoreStatus};

const SYNC_CLI_SCHEMA_VERSION: u32 = 1;

pub struct SyncCliPlugin;

pub fn create_sync_cli_plugin() -> Box<dyn CliPlugin> {
    Box::new(SyncCliPlugin)
}

#[async_trait]
impl CliPlugin for SyncCliPlugin {
    fn plugin_id(&self) -> &str {
        "sync"
    }
    fn name(&self) -> &str {
        "Sync"
    }

    fn commands(&self) -> Vec<Command> {
        vec![
            Command::new("login")
                .about("Authenticate with a sync server and store the token in the local secret store")
                .arg(Arg::new("server").long("server").short('s').required(true).help("Sync server URL"))
                .arg(Arg::new("email").long("email").short('e').required(true).help("Account email"))
                .arg(Arg::new("device").long("device").short('d').help("Device name (defaults to hostname)")),

            Command::new("recover")
                .about("Recover the sync DEK with a recovery code and set a new password")
                .arg(Arg::new("server").long("server").short('s').required(true).help("Sync server URL"))
                .arg(Arg::new("email").long("email").short('e').required(true).help("Account email"))
                .arg(Arg::new("device").long("device").short('d').help("Device name (defaults to hostname)")),

            Command::new("logout")
                .about("Revoke the current device token and clear local credentials"),

            Command::new("push")
                .about("Encrypt and push config to the server")
                .arg(Arg::new("kind").long("kind").short('k').default_value("full")
                    .help("What to push: full | global | plugin:<id> | objects")),

            Command::new("pull")
                .about("Pull and decrypt config from the server")
                .arg(Arg::new("kind").long("kind").short('k').default_value("full")
                    .help("What to pull: full | global | plugin:<id> | objects")),

            Command::new("credential")
                .about("Manage object-sync credential records")
                .subcommand_required(true)
                .arg_required_else_help(true)
                .subcommand(Command::new("migrate-mappings")
                    .about("Create local object mappings for stored credential records"))
                .subcommand(Command::new("re-enroll")
                    .about("Re-encrypt and push one credential_record object")
                    .arg(Arg::new("profile").long("profile").required(true).value_name("PROFILE_ID")
                        .help("Profile id that owns the credential ref"))
                    .arg(Arg::new("credential").long("credential").required(true).value_name("CREDENTIAL_REF_ID")
                        .help("Credential ref id to re-enroll"))
                    .arg(Arg::new("secret-env").long("secret-env").value_name("ENV")
                        .conflicts_with_all(["json-env", "from-legacy"])
                        .required_unless_present_any(["json-env", "from-legacy"])
                        .help("Read UTF-8 credential material from an environment variable"))
                    .arg(Arg::new("json-env").long("json-env").value_name("ENV")
                        .conflicts_with_all(["secret-env", "from-legacy"])
                        .required_unless_present_any(["secret-env", "from-legacy"])
                        .help("Read JSON credential material from an environment variable"))
                    .arg(Arg::new("from-legacy").long("from-legacy").action(ArgAction::SetTrue)
                        .conflicts_with_all(["secret-env", "json-env"])
                        .help("Use the existing local legacy credential material"))),

            Command::new("conflict")
                .about("Inspect and resolve object-sync conflicts")
                .subcommand_required(true)
                .arg_required_else_help(true)
                .subcommand(Command::new("list")
                    .about("List local object conflict markers")
                    .arg(Arg::new("format").long("format").default_value("text").value_parser(["text", "json"])
                        .help("Output format: text | json")))
                .subcommand(Command::new("resolve")
                    .about("Resolve one object conflict")
                    .arg(Arg::new("mode").long("mode").required(true)
                        .value_parser(["keep-remote", "keep-local-force", "merge", "delete-tombstone"])
                        .help("Resolution mode"))
                    .arg(Arg::new("object-kind").long("object-kind").required(true)
                        .value_parser(["profile", "credential_ref", "profile_policy", "plugin_compatibility", "credential_record", "app_preference"])
                        .help("Object kind from sync status JSON"))
                    .arg(Arg::new("object-id").long("object-id").required(true)
                        .help("Opaque object ID from sync status JSON"))
                    .arg(Arg::new("current-server-revision").long("current-server-revision")
                        .value_parser(clap::value_parser!(u64))
                        .help("Latest server revision being resolved; required for force, merge, and tombstone"))
                    .arg(Arg::new("acknowledge-delete").long("acknowledge-delete").action(ArgAction::SetTrue)
                        .help("Required acknowledgement for delete-tombstone")))
                .subcommand(Command::new("credential-handoff")
                    .about("Show the re-enrollment handoff for one credential_record conflict or unavailable record")
                    .arg(Arg::new("object-id").long("object-id").required(true)
                        .help("Opaque credential_record object ID from sync status JSON"))
                    .arg(Arg::new("format").long("format").default_value("text").value_parser(["text", "json"])
                        .help("Output format: text | json"))),

            Command::new("periodic")
                .about("Configure and run explicit opt-in periodic object sync")
                .subcommand_required(true)
                .arg_required_else_help(true)
                .subcommand(Command::new("status")
                    .about("Show periodic sync settings")
                    .arg(Arg::new("format").long("format").default_value("text").value_parser(["text", "json"])
                        .help("Output format: text | json")))
                .subcommand(Command::new("configure")
                    .about("Configure periodic sync without running it")
                    .arg(Arg::new("enable").long("enable").action(ArgAction::SetTrue)
                        .conflicts_with("disable")
                        .help("Enable periodic sync after validating settings"))
                    .arg(Arg::new("disable").long("disable").action(ArgAction::SetTrue)
                        .conflicts_with("enable")
                        .help("Disable periodic sync"))
                    .arg(Arg::new("interval-minutes").long("interval-minutes")
                        .value_parser(clap::value_parser!(u64))
                        .help("Minimum interval in minutes; must be 15 or greater"))
                    .arg(Arg::new("mode").long("mode")
                        .value_parser(["pull-objects", "push-pull-objects"])
                        .help("Periodic object-sync mode")))
                .subcommand(Command::new("run")
                    .about("Run one due periodic sync tick")
                    .arg(Arg::new("force").long("force").action(ArgAction::SetTrue)
                        .help("Run even if the configured interval has not elapsed"))),

            Command::new("status")
                .about("Show local sync state (no network call)")
                .arg(Arg::new("format").long("format").default_value("text").value_parser(["text", "json"])
                    .help("Output format: text | json")),
        ]
    }

    async fn execute(
        &self,
        command: &str,
        matches: &ArgMatches,
        _ctx: &CliContext,
    ) -> Result<(), VoidbError> {
        match command {
            "login" => self.cmd_login(matches).await,
            "recover" => self.cmd_recover(matches).await,
            "logout" => self.cmd_logout().await,
            "push" => self.cmd_push(matches).await,
            "pull" => self.cmd_pull(matches).await,
            "credential" => self.cmd_credential(matches).await,
            "conflict" => self.cmd_conflict(matches).await,
            "periodic" => self.cmd_periodic(matches).await,
            "status" => self.cmd_status(matches),
            _ => Err(VoidbError::Plugin(format!(
                "unknown sync command: {command}"
            ))),
        }
    }
}

impl SyncCliPlugin {
    async fn cmd_login(&self, matches: &ArgMatches) -> Result<(), VoidbError> {
        let server = matches.get_one::<String>("server").unwrap().clone();
        let email = matches.get_one::<String>("email").unwrap().clone();
        let device = matches
            .get_one::<String>("device")
            .cloned()
            .unwrap_or_else(hostname_guess);

        let password = read_password()?;

        let ok = ops::login(LoginInput {
            server_url: server.clone(),
            email: email.clone(),
            password,
            device_name: device.clone(),
        })
        .await
        .map_err(|e| VoidbError::Plugin(format!("login failed: {e}")))?;

        let mut cfg = ok.config;
        let token_status = token_store::save_token(&mut cfg, &ok.session.token)
            .map_err(|e| VoidbError::Plugin(format!("save token: {e}")))?;

        println!(
            "Logged in as {} on device {} (id: {})",
            email,
            device,
            short(&ok.session.device_id)
        );
        print_token_store_status(&token_status);
        if let Some(code) = ok.recovery_code {
            println!("Recovery code: {code}");
            println!("Recovery code is shown once; store it outside VoidB.");
        }
        Ok(())
    }

    async fn cmd_recover(&self, matches: &ArgMatches) -> Result<(), VoidbError> {
        let server = matches.get_one::<String>("server").unwrap().clone();
        let email = matches.get_one::<String>("email").unwrap().clone();
        let device = matches
            .get_one::<String>("device")
            .cloned()
            .unwrap_or_else(hostname_guess);

        let recovery_code = read_recovery_code()?;
        let new_password = read_new_password()?;

        let ok = ops::recover_password(RecoverInput {
            server_url: server,
            email: email.clone(),
            recovery_code,
            new_password,
            device_name: device.clone(),
        })
        .await
        .map_err(|e| VoidbError::Plugin(format!("recovery failed: {e}")))?;

        let mut cfg = ok.config;
        let token_status = token_store::save_token(&mut cfg, &ok.session.token)
            .map_err(|e| VoidbError::Plugin(format!("save token: {e}")))?;

        println!(
            "Recovered {} on device {} (id: {})",
            email,
            device,
            short(&ok.session.device_id)
        );
        print_token_store_status(&token_status);
        Ok(())
    }

    async fn cmd_logout(&self) -> Result<(), VoidbError> {
        let mut cfg =
            SyncConfig::load().map_err(|e| VoidbError::Plugin(format!("load config: {e}")))?;
        let token = token_store::load_token(&cfg)
            .map_err(|e| VoidbError::Plugin(format!("load token: {e}")))?
            .ok_or_else(|| VoidbError::Plugin("not logged in (no local token)".into()))?;
        let server_url = cfg
            .server_url
            .as_ref()
            .ok_or_else(|| VoidbError::Plugin("no server URL in sync.toml".into()))?;

        let client = SyncClient::new(server_url).with_token(token.clone());
        client
            .logout()
            .await
            .map_err(|e| VoidbError::Plugin(format!("logout failed: {e}")))?;

        token_store::clear_token(&mut cfg)
            .map_err(|e| VoidbError::Plugin(format!("clear token: {e}")))?;

        println!("Logged out.");
        Ok(())
    }

    async fn cmd_push(&self, matches: &ArgMatches) -> Result<(), VoidbError> {
        let kind = matches.get_one::<String>("kind").unwrap().clone();
        let session = self.login_session().await?;
        let cfg =
            SyncConfig::load().map_err(|e| VoidbError::Plugin(format!("load config: {e}")))?;

        if kind == "objects" {
            let (ok, _) = ops::push_objects(session, cfg)
                .await
                .map_err(|e| VoidbError::Plugin(format!("object push failed: {e}")))?;
            println!(
                "Pushed {} objects ({} bytes encrypted)",
                ok.objects, ok.bytes
            );
        } else {
            let (ok, _) = ops::push(session, cfg, &kind, None)
                .await
                .map_err(|e| VoidbError::Plugin(format!("push failed: {e}")))?;
            println!(
                "Pushed revision {} ({} files, {} bytes encrypted)",
                ok.revision, ok.files, ok.bytes
            );
        }
        Ok(())
    }

    async fn cmd_pull(&self, matches: &ArgMatches) -> Result<(), VoidbError> {
        let kind = matches.get_one::<String>("kind").unwrap().clone();
        let session = self.login_session().await?;
        let cfg =
            SyncConfig::load().map_err(|e| VoidbError::Plugin(format!("load config: {e}")))?;

        if kind == "objects" {
            let (ok, _) = ops::pull_objects(session, cfg)
                .await
                .map_err(|e| VoidbError::Plugin(format!("object pull failed: {e}")))?;
            println!(
                "Pulled {} objects ({} profiles, {} credential refs, {} credential records imported, {} unavailable)",
                ok.objects,
                ok.imported_profiles,
                ok.imported_credential_refs,
                ok.imported_credential_records,
                ok.unavailable
            );
        } else {
            let (ok, _) = ops::pull(session, cfg, &kind)
                .await
                .map_err(|e| VoidbError::Plugin(format!("pull failed: {e}")))?;
            println!(
                "Pulled revision {} ({} files, {} bytes) → {}",
                ok.revision,
                ok.files,
                ok.bytes,
                ok.dest.display()
            );
        }
        Ok(())
    }

    fn cmd_status(&self, matches: &ArgMatches) -> Result<(), VoidbError> {
        let cfg =
            SyncConfig::load().map_err(|e| VoidbError::Plugin(format!("load config: {e}")))?;
        let token_status = token_store::status(&cfg)
            .map_err(|e| VoidbError::Plugin(format!("load token status: {e}")))?;
        if matches.get_one::<String>("format").map(String::as_str) == Some("json") {
            print_json(&sync_success_envelope(sync_status_json(
                &cfg,
                &token_status,
            )))?;
            return Ok(());
        }

        println!(
            "Server      : {}",
            cfg.server_url.as_deref().unwrap_or("(not set)")
        );
        println!(
            "Account     : {}",
            cfg.email.as_deref().unwrap_or("(not set)")
        );
        println!(
            "Device      : {}",
            cfg.device_name.as_deref().unwrap_or("(not set)")
        );
        println!(
            "Token       : {}",
            if token_status.present {
                "present"
            } else {
                "not set"
            }
        );
        print_token_store_status(&token_status);
        println!(
            "Last synced : {}",
            cfg.last_synced_at.as_deref().unwrap_or("never")
        );

        if cfg.last_revisions.is_empty() && cfg.last_revision == 0 {
            println!("Revisions   : none");
        } else {
            for (kind, rev) in &cfg.last_revisions {
                println!("  {kind} → revision {rev}");
            }
            if cfg.last_revision != 0 && !cfg.last_revisions.contains_key("full") {
                println!("  full → revision {} (legacy)", cfg.last_revision);
            }
        }
        println!("Bundle mode : compatibility backup (--kind full|global|plugin:<id>)");
        print_periodic_status(&ops::periodic_sync_status(&cfg, Utc::now()));
        print_object_status(&cfg);
        print_conflict_status(&cfg);
        Ok(())
    }

    async fn cmd_credential(&self, matches: &ArgMatches) -> Result<(), VoidbError> {
        match matches.subcommand() {
            Some(("migrate-mappings", _)) => {
                let cfg = SyncConfig::load()
                    .map_err(|e| VoidbError::Plugin(format!("load config: {e}")))?;
                let (ok, _) = ops::migrate_credential_object_mappings(cfg).map_err(|e| {
                    VoidbError::Plugin(format!("credential mapping migration failed: {e}"))
                })?;
                println!(
                    "Migrated {} credential object mappings ({} skipped)",
                    ok.migrated, ok.skipped
                );
                Ok(())
            }
            Some(("re-enroll", sub_matches)) => {
                let profile_id = sub_matches
                    .get_one::<String>("profile")
                    .expect("required by clap")
                    .clone();
                let credential_ref_id = sub_matches
                    .get_one::<String>("credential")
                    .expect("required by clap")
                    .clone();
                let material = reenroll_material_from_matches(sub_matches)?;
                let session = self.login_session().await?;
                let cfg = SyncConfig::load()
                    .map_err(|e| VoidbError::Plugin(format!("load config: {e}")))?;
                let (ok, _) = ops::reenroll_credential_record(
                    session,
                    cfg,
                    CredentialReenrollInput {
                        profile_id,
                        credential_ref_id,
                        material,
                    },
                )
                .await
                .map_err(|e| VoidbError::Plugin(format!("credential re-enroll failed: {e}")))?;
                println!(
                    "Re-enrolled credential record {} at version {} (server revision {}, {} bytes encrypted)",
                    short(&ok.object_id),
                    ok.object_version,
                    ok.server_revision,
                    ok.bytes
                );
                Ok(())
            }
            _ => Err(VoidbError::Plugin("unknown sync credential command".into())),
        }
    }

    async fn cmd_conflict(&self, matches: &ArgMatches) -> Result<(), VoidbError> {
        match matches.subcommand() {
            Some(("list", sub_matches)) => {
                let cfg = SyncConfig::load()
                    .map_err(|e| VoidbError::Plugin(format!("load config: {e}")))?;
                if sub_matches.get_one::<String>("format").map(String::as_str) == Some("json") {
                    print_json(&sync_success_envelope(conflict_list_json(&cfg)))?;
                    return Ok(());
                }
                print_conflict_list(&cfg);
                Ok(())
            }
            Some(("resolve", sub_matches)) => {
                let mode = sub_matches
                    .get_one::<String>("mode")
                    .expect("required by clap")
                    .as_str();
                let input = ObjectConflictResolutionInput {
                    object_kind: sub_matches
                        .get_one::<String>("object-kind")
                        .expect("required by clap")
                        .clone(),
                    object_id: sub_matches
                        .get_one::<String>("object-id")
                        .expect("required by clap")
                        .clone(),
                    current_server_revision: sub_matches
                        .get_one::<u64>("current-server-revision")
                        .copied(),
                    acknowledge_delete: sub_matches.get_flag("acknowledge-delete"),
                };
                let session = self.login_session().await?;
                let cfg = SyncConfig::load()
                    .map_err(|e| VoidbError::Plugin(format!("load config: {e}")))?;
                let (ok, _) = match mode {
                    "keep-remote" => ops::resolve_keep_remote(session, cfg, input).await,
                    "keep-local-force" => ops::resolve_keep_local_force(session, cfg, input).await,
                    "merge" => ops::resolve_merge(session, cfg, input).await,
                    "delete-tombstone" => ops::resolve_delete_tombstone(session, cfg, input).await,
                    _ => unreachable!("clap value parser restricts mode"),
                }
                .map_err(|e| VoidbError::Plugin(format!("conflict resolution failed: {e}")))?;
                println!(
                    "Resolved {} {} with {} at object version {} (server revision {}, previous {})",
                    ok.object_kind,
                    short(&ok.object_id),
                    ok.mode,
                    ok.object_version,
                    ok.server_revision,
                    ok.previous_server_revision
                );
                println!("Action      : {}", ok.local_action);
                println!("Unavailable : {}", ok.unavailable);
                Ok(())
            }
            Some(("credential-handoff", sub_matches)) => {
                let cfg = SyncConfig::load()
                    .map_err(|e| VoidbError::Plugin(format!("load config: {e}")))?;
                let object_id = sub_matches
                    .get_one::<String>("object-id")
                    .expect("required by clap");
                let ok = ops::credential_conflict_handoff(cfg, object_id)
                    .map_err(|e| VoidbError::Plugin(format!("credential handoff failed: {e}")))?;
                if sub_matches.get_one::<String>("format").map(String::as_str) == Some("json") {
                    print_json(&sync_success_envelope(serde_json::json!({
                        "object_id": ok.object_id,
                        "profile_id": ok.profile_id,
                        "credential_ref_id": ok.credential_ref_id,
                        "unavailable_reason": ok.unavailable_reason,
                        "command": ok.command,
                    })))?;
                    return Ok(());
                }
                println!("Credential conflict handoff");
                println!("Object      : {}", short(&ok.object_id));
                println!("Profile     : {}", ok.profile_id);
                println!("Credential  : {}", ok.credential_ref_id);
                if let Some(reason) = ok.unavailable_reason {
                    println!("Reason      : {reason}");
                }
                println!("Command     : {}", ok.command);
                Ok(())
            }
            _ => Err(VoidbError::Plugin("unknown sync conflict command".into())),
        }
    }

    async fn cmd_periodic(&self, matches: &ArgMatches) -> Result<(), VoidbError> {
        match matches.subcommand() {
            Some(("status", sub_matches)) => {
                let cfg = SyncConfig::load()
                    .map_err(|e| VoidbError::Plugin(format!("load config: {e}")))?;
                let status = ops::periodic_sync_status(&cfg, Utc::now());
                if sub_matches.get_one::<String>("format").map(String::as_str) == Some("json") {
                    print_json(&sync_success_envelope(periodic_status_json(&status)))?;
                    return Ok(());
                }
                print_periodic_status(&status);
                Ok(())
            }
            Some(("configure", sub_matches)) => {
                let cfg = SyncConfig::load()
                    .map_err(|e| VoidbError::Plugin(format!("load config: {e}")))?;
                let enabled = if sub_matches.get_flag("enable") {
                    Some(true)
                } else if sub_matches.get_flag("disable") {
                    Some(false)
                } else {
                    None
                };
                let input = PeriodicSyncConfigureInput {
                    enabled,
                    interval_minutes: sub_matches.get_one::<u64>("interval-minutes").copied(),
                    mode: sub_matches.get_one::<String>("mode").cloned(),
                };
                let cfg = ops::configure_periodic_sync(cfg, input)
                    .map_err(|e| VoidbError::Plugin(format!("periodic configure failed: {e}")))?;
                print_periodic_status(&ops::periodic_sync_status(&cfg, Utc::now()));
                Ok(())
            }
            Some(("run", sub_matches)) => {
                let session = self.login_session().await?;
                let cfg = SyncConfig::load()
                    .map_err(|e| VoidbError::Plugin(format!("load config: {e}")))?;
                let (ok, _) = ops::run_periodic_sync_tick(
                    session,
                    cfg,
                    Utc::now(),
                    sub_matches.get_flag("force"),
                )
                .await
                .map_err(|e| VoidbError::Plugin(format!("periodic sync failed: {e}")))?;
                if ok.ran {
                    println!(
                        "Periodic sync ran with {} (pushed {}, pulled {}, unavailable {})",
                        ok.mode, ok.pushed_objects, ok.pulled_objects, ok.unavailable
                    );
                } else {
                    println!("Periodic sync skipped: {}", ok.reason);
                }
                Ok(())
            }
            _ => Err(VoidbError::Plugin("unknown sync periodic command".into())),
        }
    }

    /// Re-derive DEK from password and build an in-memory Session.
    /// This always prompts for password because the DEK is never persisted.
    async fn login_session(&self) -> Result<crate::session::Session, VoidbError> {
        let cfg =
            SyncConfig::load().map_err(|e| VoidbError::Plugin(format!("load config: {e}")))?;
        let server_url = cfg.server_url.clone().ok_or_else(|| {
            VoidbError::Plugin("no server URL in sync.toml — run 'voidb sync login' first".into())
        })?;
        let email = cfg.email.clone().ok_or_else(|| {
            VoidbError::Plugin("no email in sync.toml — run 'voidb sync login' first".into())
        })?;
        let device = cfg.device_name.clone().unwrap_or_else(hostname_guess);

        let password = read_password()?;

        let ok = ops::login(LoginInput {
            server_url,
            email,
            password,
            device_name: device,
        })
        .await
        .map_err(|e| VoidbError::Plugin(format!("login failed: {e}")))?;

        Ok(ok.session)
    }
}

fn read_password() -> Result<String, VoidbError> {
    if let Ok(p) = std::env::var("VOIDB_SYNC_PASSWORD") {
        return Ok(p);
    }
    rpassword::prompt_password("Password: ")
        .map_err(|e| VoidbError::Plugin(format!("read password: {e}")))
}

fn read_new_password() -> Result<String, VoidbError> {
    if let Ok(p) = std::env::var("VOIDB_SYNC_NEW_PASSWORD") {
        return Ok(p);
    }
    rpassword::prompt_password("New password: ")
        .map_err(|e| VoidbError::Plugin(format!("read new password: {e}")))
}

fn read_recovery_code() -> Result<String, VoidbError> {
    if let Ok(code) = std::env::var("VOIDB_SYNC_RECOVERY_CODE") {
        return Ok(code);
    }
    rpassword::prompt_password("Recovery code: ")
        .map_err(|e| VoidbError::Plugin(format!("read recovery code: {e}")))
}

fn reenroll_material_from_matches(
    matches: &ArgMatches,
) -> Result<CredentialReenrollMaterial, VoidbError> {
    if matches.get_flag("from-legacy") {
        return Ok(CredentialReenrollMaterial::ExistingLocal);
    }
    if let Some(name) = matches.get_one::<String>("secret-env") {
        let value = std::env::var(name).map_err(|_| {
            VoidbError::Plugin(format!("environment variable '{}' is not set", name))
        })?;
        return Ok(CredentialReenrollMaterial::Provided(
            CredentialRecordSecretMaterial::Utf8 { value },
        ));
    }
    if let Some(name) = matches.get_one::<String>("json-env") {
        let raw = std::env::var(name).map_err(|_| {
            VoidbError::Plugin(format!("environment variable '{}' is not set", name))
        })?;
        let value = serde_json::from_str(&raw)
            .map_err(|e| VoidbError::Plugin(format!("parse JSON credential material: {e}")))?;
        return Ok(CredentialReenrollMaterial::Provided(
            CredentialRecordSecretMaterial::Json { value },
        ));
    }
    Err(VoidbError::Plugin(
        "credential re-enroll requires --secret-env, --json-env, or --from-legacy".into(),
    ))
}

fn hostname_guess() -> String {
    std::env::var("HOST")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "voidb-client".to_string())
}

fn short(id: &str) -> String {
    id.chars().take(8).collect()
}

fn sync_success_envelope(data: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "ok": true,
        "schema_version": SYNC_CLI_SCHEMA_VERSION,
        "command": "sync",
        "data": data,
    })
}

fn print_json(value: &impl Serialize) -> Result<(), VoidbError> {
    let output = serde_json::to_string_pretty(value)
        .map_err(|e| VoidbError::Plugin(format!("serialize sync JSON output: {e}")))?;
    println!("{output}");
    Ok(())
}

fn print_token_store_status(status: &TokenStoreStatus) {
    println!(
        "Token store : {} (mode: {})",
        status.backend.as_str(),
        status.mode
    );
    if status.backend == TokenStoreBackend::FileFallback && status.keyring_error.is_some() {
        println!("Token note  : keyring unavailable; using private file fallback");
    }
}

#[derive(Default)]
struct ObjectStatusSummary {
    count: usize,
    unavailable: usize,
    max_server_revision: u64,
    max_object_version: u64,
}

fn print_object_status(cfg: &SyncConfig) {
    if cfg.object_mappings.is_empty() {
        println!("Object sync : no local object mappings");
        return;
    }

    let mut by_kind = BTreeMap::<String, ObjectStatusSummary>::new();
    for mapping in cfg.object_mappings.values() {
        let entry = by_kind.entry(mapping.object_kind.clone()).or_default();
        entry.count += 1;
        entry.unavailable += usize::from(mapping.unavailable);
        entry.max_server_revision = entry.max_server_revision.max(mapping.server_revision);
        entry.max_object_version = entry.max_object_version.max(mapping.object_version);
    }

    let total = cfg.object_mappings.len();
    let unavailable: usize = by_kind.values().map(|summary| summary.unavailable).sum();
    println!("Object sync : {total} mappings, {unavailable} unavailable");
    for (kind, summary) in by_kind {
        println!(
            "  {kind}: count {}, server rev {}, object version {}, unavailable {}",
            summary.count,
            summary.max_server_revision,
            summary.max_object_version,
            summary.unavailable
        );
    }
}

fn print_conflict_status(cfg: &SyncConfig) {
    if cfg.object_conflicts.is_empty() {
        return;
    }
    let mut by_kind = BTreeMap::<String, usize>::new();
    for conflict in cfg.object_conflicts.values() {
        *by_kind.entry(conflict.object_kind.clone()).or_default() += 1;
    }
    let total = cfg.object_conflicts.len();
    println!("Conflicts   : {total} object conflicts");
    for (kind, count) in by_kind {
        println!("  {kind}: {count}");
    }
}

fn print_conflict_list(cfg: &SyncConfig) {
    if cfg.object_conflicts.is_empty() {
        println!("No object conflicts.");
        return;
    }
    for conflict in sorted_conflicts(cfg) {
        println!(
            "{} {} current rev {} object version {}",
            conflict.object_kind,
            short(&conflict.object_id),
            conflict.current_server_revision,
            conflict.current_object_version
        );
        if let Some(reason) = &conflict.unavailable_reason {
            println!("  reason: {reason}");
        }
    }
}

fn print_periodic_status(status: &ops::PeriodicSyncStatus) {
    println!(
        "Periodic   : {} ({}, every {} minutes)",
        if status.enabled {
            "enabled"
        } else {
            "disabled"
        },
        status.mode,
        status.interval_minutes
    );
    if let Some(next_run_at) = &status.next_run_at {
        println!("  next run : {next_run_at}");
    }
    if let Some(last_run_at) = &status.last_run_at {
        println!("  last run : {last_run_at}");
    }
    if let Some(last_status) = &status.last_status {
        println!("  status   : {last_status}");
    }
}

fn conflict_list_json(cfg: &SyncConfig) -> serde_json::Value {
    serde_json::json!({
        "conflict_count": cfg.object_conflicts.len(),
        "conflicts": conflict_entries_json(cfg),
    })
}

fn periodic_status_json(status: &ops::PeriodicSyncStatus) -> serde_json::Value {
    serde_json::json!({
        "enabled": status.enabled,
        "configured": status.configured,
        "interval_minutes": status.interval_minutes,
        "mode": status.mode.clone(),
        "last_run_at": status.last_run_at.clone(),
        "last_status": status.last_status.clone(),
        "next_run_at": status.next_run_at.clone(),
    })
}

fn sync_status_json(cfg: &SyncConfig, token_status: &TokenStoreStatus) -> serde_json::Value {
    let mut by_kind = BTreeMap::<String, ObjectStatusSummary>::new();
    for mapping in cfg.object_mappings.values() {
        let entry = by_kind.entry(mapping.object_kind.clone()).or_default();
        entry.count += 1;
        entry.unavailable += usize::from(mapping.unavailable);
        entry.max_server_revision = entry.max_server_revision.max(mapping.server_revision);
        entry.max_object_version = entry.max_object_version.max(mapping.object_version);
    }

    let object_kinds = by_kind
        .into_iter()
        .map(|(kind, summary)| {
            serde_json::json!({
                "kind": kind,
                "count": summary.count,
                "unavailable": summary.unavailable,
                "max_server_revision": summary.max_server_revision,
                "max_object_version": summary.max_object_version,
            })
        })
        .collect::<Vec<_>>();

    let conflicts = conflict_entries_json(cfg);

    serde_json::json!({
        "server": cfg.server_url,
        "account": cfg.email,
        "device": cfg.device_name,
        "token": if token_status.present { "present" } else { "not_set" },
        "token_store": {
            "backend": token_status.backend.as_str(),
            "mode": token_status.mode,
            "keyring_error": token_status.keyring_error.as_deref(),
        },
        "last_synced_at": cfg.last_synced_at,
        "revisions": cfg.last_revisions,
        "legacy_full_revision": cfg.last_revision,
        "periodic_sync": periodic_status_json(&ops::periodic_sync_status(cfg, Utc::now())),
        "objects": {
            "mapping_count": cfg.object_mappings.len(),
            "conflict_count": cfg.object_conflicts.len(),
            "kinds": object_kinds,
            "conflicts": conflicts,
        }
    })
}

fn sorted_conflicts(cfg: &SyncConfig) -> Vec<&crate::config::SyncObjectConflict> {
    let mut conflicts = cfg.object_conflicts.values().collect::<Vec<_>>();
    conflicts.sort_by(|left, right| {
        left.object_kind
            .cmp(&right.object_kind)
            .then_with(|| left.object_id.cmp(&right.object_id))
    });
    conflicts
}

fn conflict_entries_json(cfg: &SyncConfig) -> Vec<serde_json::Value> {
    sorted_conflicts(cfg)
        .into_iter()
        .map(|conflict| {
            serde_json::json!({
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
            })
        })
        .collect::<Vec<_>>()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SyncObjectConflict;

    #[test]
    fn status_json_exposes_redacted_object_conflicts() {
        let mut cfg = SyncConfig::default();
        cfg.object_conflicts.insert(
            "credential_record:sync_credrec_abc".into(),
            SyncObjectConflict {
                object_kind: "credential_record".into(),
                object_id: "sync_credrec_abc".into(),
                local_kind: Some("credential_record".into()),
                local_id: Some("profile-local:cred-password".into()),
                attempted_base_server_revision: 3,
                current_server_revision: 4,
                attempted_object_version: 2,
                current_object_version: 3,
                detected_at: "2026-07-04T16:00:00Z".into(),
                server_updated_at: Some("2026-07-04T15:59:00Z".into()),
                redaction: "withheld".into(),
                unavailable_reason: Some("object_revision_conflict".into()),
            },
        );

        let token_status = TokenStoreStatus::not_set("auto", None);
        let status = sync_status_json(&cfg, &token_status);
        let conflict = &status["objects"]["conflicts"][0];
        assert_eq!(status["objects"]["conflict_count"], 1);
        assert_eq!(status["periodic_sync"]["enabled"], false);
        assert_eq!(status["periodic_sync"]["configured"], false);
        assert_eq!(status["periodic_sync"]["mode"], "pull-objects");
        assert_eq!(
            status["periodic_sync"]["next_run_at"],
            serde_json::Value::Null
        );
        assert_eq!(status["token"], "not_set");
        assert_eq!(status["token_store"]["backend"], "none");
        assert_eq!(conflict["object_kind"], "credential_record");
        assert_eq!(conflict["object_id"], "sync_credrec_abc");
        assert_eq!(conflict["current_server_revision"], 4);
        assert_eq!(conflict["redaction"], "withheld");
        assert_eq!(conflict["unavailable_reason"], "object_revision_conflict");
        assert!(conflict.get("local_id").is_none());
    }

    #[test]
    fn sync_json_envelope_is_versioned_for_agents() {
        let mut cfg = SyncConfig::default();
        cfg.object_conflicts.insert(
            "profile:sync_profile_abc".into(),
            SyncObjectConflict {
                object_kind: "profile".into(),
                object_id: "sync_profile_abc".into(),
                local_kind: Some("profile".into()),
                local_id: Some("local-profile-id".into()),
                attempted_base_server_revision: 7,
                current_server_revision: 8,
                attempted_object_version: 3,
                current_object_version: 4,
                detected_at: "2026-07-04T16:30:00Z".into(),
                server_updated_at: Some("2026-07-04T16:29:00Z".into()),
                redaction: "applied".into(),
                unavailable_reason: None,
            },
        );

        let token_status = TokenStoreStatus {
            present: true,
            backend: TokenStoreBackend::FileFallback,
            mode: "file",
            keyring_error: Some("keyring_unavailable".into()),
        };
        let envelope = sync_success_envelope(sync_status_json(&cfg, &token_status));
        let encoded = serde_json::to_string(&envelope).expect("serialize envelope");

        assert_eq!(envelope["ok"], true);
        assert_eq!(envelope["schema_version"], SYNC_CLI_SCHEMA_VERSION);
        assert_eq!(envelope["command"], "sync");
        assert_eq!(envelope["data"]["token"], "present");
        assert_eq!(envelope["data"]["token_store"]["backend"], "file_fallback");
        assert_eq!(envelope["data"]["objects"]["conflict_count"], 1);
        assert_eq!(
            envelope["data"]["objects"]["conflicts"][0]["object_id"],
            "sync_profile_abc"
        );
        assert!(!encoded.contains("local-profile-id"));
    }

    #[test]
    fn conflict_list_json_is_stable_inside_sync_envelope() {
        let mut cfg = SyncConfig::default();
        cfg.object_conflicts.insert(
            "app_preference:sync_pref_abc".into(),
            SyncObjectConflict {
                object_kind: "app_preference".into(),
                object_id: "sync_pref_abc".into(),
                local_kind: Some("app_preference".into()),
                local_id: Some("theme".into()),
                attempted_base_server_revision: 1,
                current_server_revision: 2,
                attempted_object_version: 1,
                current_object_version: 2,
                detected_at: "2026-07-04T17:00:00Z".into(),
                server_updated_at: None,
                redaction: "not_required".into(),
                unavailable_reason: Some("local_version_conflict".into()),
            },
        );

        let envelope = sync_success_envelope(conflict_list_json(&cfg));

        assert_eq!(envelope["ok"], true);
        assert_eq!(envelope["schema_version"], SYNC_CLI_SCHEMA_VERSION);
        assert_eq!(envelope["command"], "sync");
        assert_eq!(envelope["data"]["conflict_count"], 1);
        assert_eq!(
            envelope["data"]["conflicts"][0]["unavailable_reason"],
            "local_version_conflict"
        );
    }
}
