//! Built-in credential management CLI.

use std::io::IsTerminal;

use crate::builtin::json_output::print_json;
use async_trait::async_trait;
use clap::{Arg, ArgAction, ArgMatches, Command};
use serde::Serialize;
use serde_json::json;
use voidb_core::plugin::cli::{CliContext, CliPlugin};
use voidb_core::{
    AppConfig, CapabilityErrorCategory, ConfigReencryptResult, CredentialProtectionMode,
    LocalProfileStore, MasterPasswordSessionState, VOIDB_MASTER_PASSWORD_ENV, VoidbError,
};

pub struct CredentialCliPlugin;

impl CredentialCliPlugin {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl CliPlugin for CredentialCliPlugin {
    fn plugin_id(&self) -> &str {
        "credential"
    }

    fn visible_aliases(&self) -> Vec<&'static str> {
        vec!["cred"]
    }

    fn name(&self) -> &str {
        "Credentials"
    }

    fn commands(&self) -> Vec<Command> {
        vec![
            Command::new("master")
                .about("Manage local credential master password protection")
                .subcommand_required(true)
                .arg_required_else_help(true)
                .subcommand(
                    Command::new("reencrypt")
                        .visible_alias("re-encrypt")
                        .about("Re-encrypt saved credential material with a master password")
                        .arg(format_arg())
                        .arg(
                            Arg::new("new-password-env")
                                .long("new-password-env")
                                .value_name("VAR")
                                .help("Environment variable containing the new master password"),
                        )
                        .arg(
                            Arg::new("current-password-env")
                                .long("current-password-env")
                                .value_name("VAR")
                                .help("Environment variable containing the current master password; omit for legacy default-passphrase configs"),
                        )
                        .arg(
                            Arg::new("dry-run")
                                .long("dry-run")
                                .action(ArgAction::SetTrue)
                                .help("Report credential material that would be re-encrypted without writing files"),
                        )
                        .arg(
                            Arg::new("yes")
                                .long("yes")
                                .action(ArgAction::SetTrue)
                                .help("Confirm writing the re-encrypted config file"),
                        ),
                )
                .subcommand(
                    Command::new("setup")
                        .about("Configure master-password protection on a legacy default-passphrase config")
                        .arg(format_arg())
                        .arg(
                            Arg::new("new-password-env")
                                .long("new-password-env")
                                .value_name("VAR")
                                .help("Environment variable containing the new master password; omit to prompt interactively"),
                        )
                        .arg(
                            Arg::new("dry-run")
                                .long("dry-run")
                                .action(ArgAction::SetTrue)
                                .help("Report the protection state that would be configured without writing files"),
                        )
                        .arg(
                            Arg::new("yes")
                                .long("yes")
                                .action(ArgAction::SetTrue)
                                .help("Confirm writing the protected config file"),
                        ),
                )
                .subcommand(
                    Command::new("unlock")
                        .about("Verify the master password and report the process unlock state")
                        .arg(format_arg())
                        .arg(
                            Arg::new("password-env")
                                .long("password-env")
                                .value_name("VAR")
                                .help("Environment variable containing the master password; omit to prompt or fall back to VOIDB_MASTER_PASSWORD"),
                        ),
                )
                .subcommand(
                    Command::new("forget")
                        .about("Clear in-process master password state (one-shot CLI no-op)")
                        .arg(format_arg()),
                ),
        ]
    }

    async fn execute(
        &self,
        command: &str,
        matches: &ArgMatches,
        ctx: &CliContext,
    ) -> Result<(), VoidbError> {
        match command {
            "master" => handle_master(matches, ctx),
            _ => Err(VoidbError::Plugin(format!("Unknown command: {}", command))),
        }
    }
}

fn handle_master(matches: &ArgMatches, ctx: &CliContext) -> Result<(), VoidbError> {
    match matches.subcommand() {
        Some(("reencrypt", sub_matches)) => handle_reencrypt(sub_matches, ctx),
        Some(("setup", sub_matches)) => handle_setup(sub_matches, ctx),
        Some(("unlock", sub_matches)) => handle_unlock(sub_matches),
        Some(("forget", sub_matches)) => handle_forget(sub_matches),
        _ => Err(VoidbError::Plugin(
            "Unknown credential master command".into(),
        )),
    }
}

/// Configures master-password protection on a legacy default-passphrase
/// config. Refuses to run on an already-protected config (that is a
/// reencrypt); prompts twice unless --new-password-env is supplied.
fn handle_setup(matches: &ArgMatches, ctx: &CliContext) -> Result<(), VoidbError> {
    ensure_json_format(matches)?;

    if ctx.config.credential_protection_mode() == CredentialProtectionMode::UserPassphrase {
        return Err(VoidbError::Config(
            "Master-password protection is already configured; use 'vb credential master reencrypt' to change the password"
                .into(),
        ));
    }
    let interactive = matches.get_one::<String>("new-password-env").is_none();
    if interactive && !std::io::stdin().is_terminal() {
        return Err(VoidbError::Config(
            "Interactive setup requires a terminal; set --new-password-env <VAR> for non-interactive use"
                .into(),
        ));
    }
    let dry_run = matches.get_flag("dry-run");
    if dry_run {
        let state = ctx
            .config
            .credential_protection_state(MasterPasswordSessionState::NotConfigured);
        print_json(&success_envelope(json!({
            "dry_run": true,
            "current_protection_mode": ctx.config.credential_protection_mode(),
            "target_protection_mode": CredentialProtectionMode::UserPassphrase,
            "credential_summary": state.summary,
        })))?;
        return Ok(());
    }
    if !matches.get_flag("yes") {
        return Err(VoidbError::Plugin(
            "Refusing to rewrite config without --yes; use --dry-run to preview".into(),
        ));
    }
    let new_password = if interactive {
        prompt_confirmed_new_password()?
    } else {
        new_master_password(matches)?
    };
    let native_credentials_reencrypted =
        reencrypt_native_credentials(None, new_password.as_str())?;
    let result = AppConfig::reencrypt_config_file(None, new_password.as_str())?;
    print_json(&success_envelope(json!({
        "protection_mode": result.protection_mode,
        "master_password": result.master_password,
        "credential_summary": result.credential_summary,
        "native_credentials_reencrypted": native_credentials_reencrypted,
        "active_password_env": VOIDB_MASTER_PASSWORD_ENV,
    })))
}

/// Verifies the master password and reports the unlock state. One-shot CLI
/// processes do not retain unlock state, so this is verify-and-report.
fn handle_unlock(matches: &ArgMatches) -> Result<(), VoidbError> {
    ensure_json_format(matches)?;

    let password = match password_from_env_arg(matches, "password-env")? {
        Some(password) => password,
        None => match std::env::var(VOIDB_MASTER_PASSWORD_ENV) {
            Ok(password) if !password.is_empty() => password,
            _ if std::io::stdin().is_terminal() => {
                crate::prompt_master_password("VoidB master password: ")?
            }
            _ => {
                return Err(VoidbError::Config(
                    "Master password required; set VOIDB_MASTER_PASSWORD or --password-env for non-interactive unlock"
                        .into(),
                ))
            }
        },
    };
    let unlocked = AppConfig::load_with_password(Some(&password)).is_ok();
    drop(password);
    if !unlocked {
        return Err(VoidbError::Crypto(
            "Invalid master password for credential protection".into(),
        ));
    }
    print_json(&success_envelope(json!({
        "unlocked": true,
        "scope": "process",
        "note": "One-shot CLI commands exit after completion; unlock state is not persisted. Long-lived processes supply the password through VOIDB_MASTER_PASSWORD.",
    })))
}

/// One-shot CLI commands never retain master-password state across processes,
/// so forget is a redacted no-op that reports exactly that.
fn handle_forget(matches: &ArgMatches) -> Result<(), VoidbError> {
    ensure_json_format(matches)?;
    print_json(&success_envelope(json!({
        "forgotten": true,
        "scope": "process",
        "note": "One-shot CLI commands do not retain master-password state between processes; the in-memory password for this process is dropped on exit.",
    })))
}

fn prompt_confirmed_new_password() -> Result<String, VoidbError> {
    let password = crate::prompt_master_password("New master password: ")
        .map_err(|error| VoidbError::Plugin(format!("read master password: {error}")))?;
    let confirmation = crate::prompt_master_password("Confirm master password: ").map_err(
        |error| VoidbError::Plugin(format!("read master password confirmation: {error}")),
    )?;
    if password != confirmation {
        return Err(VoidbError::Plugin(
            "Master password confirmation did not match".into(),
        ));
    }
    Ok(password)
}

fn handle_reencrypt(matches: &ArgMatches, ctx: &CliContext) -> Result<(), VoidbError> {
    ensure_json_format(matches)?;

    let dry_run = matches.get_flag("dry-run");
    if !dry_run && !matches.get_flag("yes") {
        return Err(VoidbError::Plugin(
            "Refusing to rewrite config without --yes; use --dry-run to preview".into(),
        ));
    }

    let current_password = password_from_env_arg(matches, "current-password-env")?;

    if dry_run {
        let state = ctx
            .config
            .credential_protection_state(MasterPasswordSessionState::NotConfigured);
        print_json(&JsonSuccessEnvelope {
            ok: true,
            data: json!({
                "dry_run": true,
                "config_path": AppConfig::config_path()?,
                "current_protection_mode": ctx.config.credential_protection_mode(),
                "target_protection_mode": CredentialProtectionMode::UserPassphrase,
                "credential_summary": state.summary,
            }),
            warnings: Vec::<CredentialWarning>::new(),
        })
    } else {
        let new_password = new_master_password(matches)?;
        let config_current_password = current_password
            .as_deref()
            .or(ctx.credential_master_password()?);
        let native_credentials_reencrypted =
            reencrypt_native_credentials(config_current_password, new_password.as_str())?;
        let result =
            AppConfig::reencrypt_config_file(config_current_password, new_password.as_str())?;
        print_json(&success_envelope(reencrypt_data(
            result,
            native_credentials_reencrypted,
        )))
    }
}

fn reencrypt_native_credentials(
    current_password: Option<&str>,
    new_password: &str,
) -> Result<usize, VoidbError> {
    let store = LocalProfileStore::default_store()?;
    match store.reencrypt_native_credentials(current_password, new_password) {
        Ok(count) => Ok(count),
        Err(current_error) if current_password.is_some() => store
            .reencrypt_native_credentials(None, new_password)
            .map_err(|legacy_error| {
                VoidbError::Config(format!(
                    "Cannot re-encrypt native profile credentials with current or legacy default passphrase: {}; {}",
                    current_error, legacy_error
                ))
            }),
        Err(error) => Err(error),
    }
}

fn reencrypt_data(
    result: ConfigReencryptResult,
    native_credentials_reencrypted: usize,
) -> serde_json::Value {
    json!({
        "config_path": result.config_path,
        "protection_mode": result.protection_mode,
        "master_password": result.master_password,
        "credential_summary": result.credential_summary,
        "native_credentials_reencrypted": native_credentials_reencrypted,
        "active_password_env": VOIDB_MASTER_PASSWORD_ENV,
    })
}

fn password_from_env_arg(
    matches: &ArgMatches,
    arg_name: &'static str,
) -> Result<Option<String>, VoidbError> {
    let Some(var_name) = matches.get_one::<String>(arg_name) else {
        return Ok(None);
    };

    match std::env::var(var_name) {
        Ok(value) if !value.is_empty() => Ok(Some(value)),
        Ok(_) => Err(VoidbError::Plugin(format!("{} is set but empty", var_name))),
        Err(std::env::VarError::NotPresent) => Err(VoidbError::Plugin(format!(
            "{} is not set for --{}",
            var_name, arg_name
        ))),
        Err(error) => Err(VoidbError::Plugin(format!(
            "Cannot read {} for --{}: {}",
            var_name, arg_name, error
        ))),
    }
}

fn new_master_password(matches: &ArgMatches) -> Result<String, VoidbError> {
    if let Some(password) = password_from_env_arg(matches, "new-password-env")? {
        return validate_new_master_password(password);
    }

    let password = crate::prompt_master_password("New master password: ")
        .map_err(|error| VoidbError::Plugin(format!("read master password: {}", error)))?;
    let confirmation =
        crate::prompt_master_password("Confirm master password: ").map_err(|error| {
            VoidbError::Plugin(format!("read master password confirmation: {}", error))
        })?;

    if password != confirmation {
        return Err(VoidbError::Plugin(
            "Master password confirmation did not match".into(),
        ));
    }

    validate_new_master_password(password)
}

fn validate_new_master_password(password: String) -> Result<String, VoidbError> {
    if password.is_empty() {
        return Err(VoidbError::Plugin("Master password cannot be empty".into()));
    }
    Ok(password)
}

fn format_arg() -> Arg {
    Arg::new("format")
        .long("format")
        .value_name("FORMAT")
        .value_parser(["json"])
        .default_value("json")
        .help("Output format; only json is stable for credential commands")
}

fn ensure_json_format(matches: &ArgMatches) -> Result<(), VoidbError> {
    match matches.get_one::<String>("format").map(String::as_str) {
        Some("json") | None => Ok(()),
        Some(format) => Err(credential_error(
            CapabilityErrorCategory::Validation,
            "credential.format_unsupported",
            "Only JSON output is supported for credential commands.",
            json!({ "format": format }),
            false,
        )),
    }
}

fn credential_error(
    category: CapabilityErrorCategory,
    code: &'static str,
    message: &'static str,
    details: serde_json::Value,
    retryable: bool,
) -> VoidbError {
    VoidbError::Plugin(
        json!({
            "category": category,
            "code": code,
            "message": message,
            "details": details,
            "retryable": retryable,
        })
        .to_string(),
    )
}

fn success_envelope<T: Serialize>(data: T) -> JsonSuccessEnvelope<T> {
    JsonSuccessEnvelope {
        ok: true,
        data,
        warnings: Vec::new(),
    }
}

#[derive(Debug, Serialize)]
struct JsonSuccessEnvelope<T> {
    ok: bool,
    data: T,
    warnings: Vec<CredentialWarning>,
}

#[derive(Debug, Serialize)]
struct CredentialWarning {
    code: String,
    message: String,
    details: serde_json::Value,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn master_reencrypt_command_exposes_safe_password_sources() {
        let plugin = CredentialCliPlugin::new();
        let commands = plugin.commands();
        let master = commands
            .iter()
            .find(|command| command.get_name() == "master")
            .expect("master command");
        let reencrypt = master
            .get_subcommands()
            .find(|command| command.get_name() == "reencrypt")
            .expect("reencrypt command");

        assert!(
            reencrypt
                .get_arguments()
                .any(|arg| arg.get_id() == "new-password-env")
        );
        assert!(
            reencrypt
                .get_arguments()
                .any(|arg| arg.get_id() == "current-password-env")
        );
        assert!(reencrypt.get_arguments().any(|arg| arg.get_id() == "yes"));
        assert!(
            reencrypt
                .get_arguments()
                .any(|arg| arg.get_id() == "dry-run")
        );
    }

    fn master_subcommand(name: &str) -> Command {
        let plugin = CredentialCliPlugin::new();
        let commands = plugin.commands();
        let master = commands
            .iter()
            .find(|command| command.get_name() == "master")
            .expect("master command");
        master
            .get_subcommands()
            .find(|command| command.get_name() == name)
            .unwrap_or_else(|| panic!("{name} subcommand"))
            .clone()
    }

    #[test]
    fn master_setup_and_unlock_expose_documented_surface() {
        let setup = master_subcommand("setup");
        assert!(setup.get_arguments().any(|arg| arg.get_id() == "new-password-env"));
        assert!(setup.get_arguments().any(|arg| arg.get_id() == "yes"));
        assert!(setup.get_arguments().any(|arg| arg.get_id() == "dry-run"));

        let unlock = master_subcommand("unlock");
        assert!(unlock.get_arguments().any(|arg| arg.get_id() == "password-env"));

        let forget = master_subcommand("forget");
        assert!(forget.get_arguments().all(|arg| arg.get_id() != "yes"));
    }

    #[test]
    fn setup_parses_non_interactive_and_interactive_forms() {
        let command = master_subcommand("setup");
        let matches = command
            .clone()
            .try_get_matches_from(["setup", "--new-password-env", "VOIDB_TEST_PW", "--yes"])
            .expect("non-interactive setup parses");
        assert!(matches.get_flag("yes"));

        let matches = command
            .try_get_matches_from(["setup", "--dry-run"])
            .expect("interactive dry-run setup parses");
        assert!(matches.get_flag("dry-run"));
    }

    #[test]
    fn unlock_reports_error_without_tty_or_password_source() {
        let command = master_subcommand("unlock");
        let matches = command
            .try_get_matches_from(["unlock"])
            .expect("unlock parses");
        // Non-TTY test processes have neither --password-env nor a usable
        // VOIDB_MASTER_PASSWORD, so the handler must fail closed with the
        // structured guidance error instead of prompting.
        if std::env::var_os(VOIDB_MASTER_PASSWORD_ENV).is_some_and(|value| !value.is_empty()) {
            return; // environment provides a password; skip the fail-closed assert
        }
        assert!(handle_unlock(&matches).is_err());
    }

    #[test]
    fn forget_is_a_reported_no_op() {
        let command = master_subcommand("forget");
        let matches = command.try_get_matches_from(["forget"]).expect("parses");
        handle_forget(&matches).expect("forget never fails");
    }
}
