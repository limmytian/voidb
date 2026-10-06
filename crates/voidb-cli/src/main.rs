mod agent_broker;
mod agent_session_host;
mod builtin;
mod jit_authorization;

use clap::{ArgMatches, Command};
use voidb_core::config::AppConfig;
use voidb_core::plugin::cli::{CliContext, CliPluginManager};
use voidb_core::{VOIDB_MASTER_PASSWORD_ENV, VoidbError};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .init();

    if let Some(exit_code) = agent_broker::handle_early(std::env::args().collect()).await? {
        std::process::exit(exit_code);
    }

    // Broker children receive the password through an anonymous pipe, never
    // through argv, grant files, socket messages, or their environment.
    let broker_password = agent_broker::take_broker_child_password().await?;
    let cli_manager = build_cli_manager();
    let app = build_cli_app(&cli_manager);

    let matches = app.get_matches();
    let (config, active_master_password) = load_config_for_command(broker_password, &matches)?;

    // Create context and dispatch
    let ctx = CliContext::new(config).with_master_password(active_master_password);
    let (plugin_id, sub_matches) = matches.subcommand().expect("subcommand_required");

    if let Err(error) = cli_manager.dispatch(plugin_id, sub_matches, &ctx).await {
        match error {
            VoidbError::CliExit { code } => std::process::exit(i32::from(code)),
            error => return Err(anyhow::anyhow!("{}", error)),
        }
    }

    Ok(())
}

fn build_cli_manager() -> CliPluginManager {
    let mut cli_manager = CliPluginManager::new();

    // Built-in
    cli_manager.register(Box::new(builtin::audit::AuditCliPlugin::new()));
    cli_manager.register(Box::new(builtin::connections::ConnectionsCliPlugin::new()));
    cli_manager.register(Box::new(builtin::context::ContextCliPlugin::new()));
    cli_manager.register(Box::new(builtin::credential::CredentialCliPlugin::new()));
    cli_manager.register(Box::new(builtin::invoke::InvokeCliPlugin::new()));
    cli_manager.register(Box::new(builtin::plugin::PluginCliPlugin::new()));
    cli_manager.register(Box::new(builtin::profile::ProfileCliPlugin::new()));

    // Database plugins
    #[cfg(feature = "mysql")]
    cli_manager.register(voidb_plugin_mysql::create_mysql_cli_plugin());
    #[cfg(feature = "postgres")]
    cli_manager.register(voidb_plugin_postgres::create_postgres_cli_plugin());
    #[cfg(feature = "sqlite")]
    cli_manager.register(voidb_plugin_sqlite::create_sqlite_cli_plugin());

    // Other plugins
    #[cfg(feature = "email")]
    cli_manager.register(voidb_plugin_email::create_email_cli_plugin());
    #[cfg(feature = "redis")]
    cli_manager.register(voidb_plugin_redis::create_redis_cli_plugin());
    #[cfg(feature = "ssh")]
    cli_manager.register(voidb_plugin_ssh::create_ssh_cli_plugin());
    #[cfg(feature = "docker")]
    cli_manager.register(voidb_plugin_docker::create_docker_cli_plugin());
    #[cfg(feature = "kubernetes")]
    cli_manager.register(voidb_plugin_kubernetes::create_k8s_cli_plugin());
    #[cfg(feature = "s3")]
    cli_manager.register(voidb_plugin_s3::create_s3_cli_plugin());
    #[cfg(feature = "elasticsearch")]
    cli_manager.register(voidb_plugin_elasticsearch::create_es_cli_plugin());
    #[cfg(feature = "mongodb")]
    cli_manager.register(voidb_plugin_mongodb::create_mongo_cli_plugin());
    #[cfg(feature = "duckdb")]
    cli_manager.register(voidb_plugin_duckdb::create_duckdb_cli_plugin());
    #[cfg(feature = "sync")]
    cli_manager.register(voidb_plugin_sync::create_sync_cli_plugin());

    cli_manager
}

fn build_cli_app(cli_manager: &CliPluginManager) -> Command {
    let mut app = Command::new("voidb")
        .about("VoidB - Terminal Database Management Tool")
        .version(env!("CARGO_PKG_VERSION"))
        .subcommand_required(true)
        .arg_required_else_help(true);

    for cmd in cli_manager.build_commands() {
        app = app.subcommand(cmd);
    }

    app
}

fn load_config_for_command(
    broker_password: Option<String>,
    matches: &ArgMatches,
) -> Result<(AppConfig, Option<String>), VoidbError> {
    let config_path = AppConfig::config_path()?;
    load_config_for_command_at_path(broker_password, matches, &config_path)
}

fn load_config_for_command_at_path(
    broker_password: Option<String>,
    matches: &ArgMatches,
    config_path: &std::path::Path,
) -> Result<(AppConfig, Option<String>), VoidbError> {
    if command_can_use_raw_config(matches) {
        return Ok((AppConfig::load_raw_from_path(config_path)?, None));
    }

    if let Some(password) = broker_password {
        let config = AppConfig::load_from_path_with_password(config_path, Some(&password))?;
        return Ok((config, Some(password)));
    }

    let raw_config = AppConfig::load_raw_from_path(config_path)?;
    if !raw_config.requires_master_password() {
        return Ok((
            AppConfig::load_from_path_with_password(config_path, None)?,
            None,
        ));
    }

    let password = match master_password_from_env()? {
        Some(password) => password,
        None if command_allows_interactive_master_password(matches) => {
            prompt_master_password_for_tui()?
        }
        None => return Err(master_password_required_error()),
    };

    let config = AppConfig::load_from_path_with_password(config_path, Some(&password))?;
    Ok((config, Some(password)))
}

fn master_password_from_env() -> Result<Option<String>, VoidbError> {
    match std::env::var(VOIDB_MASTER_PASSWORD_ENV) {
        Ok(value) if !value.is_empty() => Ok(Some(value)),
        Ok(_) => Err(VoidbError::Config(format!(
            "{} is set but empty",
            VOIDB_MASTER_PASSWORD_ENV
        ))),
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(error) => Err(VoidbError::Config(format!(
            "Cannot read {}: {}",
            VOIDB_MASTER_PASSWORD_ENV, error
        ))),
    }
}

fn prompt_master_password_for_tui() -> Result<String, VoidbError> {
    let password = rpassword::prompt_password("VoidB master password: ")
        .map_err(|error| VoidbError::Config(format!("read master password: {}", error)))?;
    if password.is_empty() {
        return Err(VoidbError::Config(
            "Master password cannot be empty".to_string(),
        ));
    }
    Ok(password)
}

fn master_password_required_error() -> VoidbError {
    VoidbError::Config(format!(
        "Master password required; set {} for this process",
        VOIDB_MASTER_PASSWORD_ENV
    ))
}

fn command_allows_interactive_master_password(matches: &ArgMatches) -> bool {
    let Some((plugin_id, command, command_matches)) = selected_cli_command(matches) else {
        return false;
    };

    command == "tui"
        && plugin_id != "connections"
        && tui_target_requested(command_matches)
        && !tui_machine_output_requested(command_matches)
        && !tui_fixture_without_target(command_matches)
}

fn command_can_use_raw_config(matches: &ArgMatches) -> bool {
    let Some((plugin_id, command, command_matches)) = selected_cli_command(matches) else {
        return false;
    };

    (plugin_id == "connections" && matches!(command, "list" | "show" | "tui"))
        || (plugin_id == "profile" && matches!(command, "list" | "show"))
        || (plugin_id == "plugin" && matches!(command, "list" | "describe"))
        || (plugin_id == "invoke" && matches!(command, "list" | "describe" | "matrix"))
        || plugin_id == "context"
        || (plugin_id == "ssh" && matches!(command, "session" | "assist"))
        || (command == "tui" && tui_fixture_without_target(command_matches))
}

fn selected_cli_command(matches: &ArgMatches) -> Option<(&str, &str, &ArgMatches)> {
    let (plugin_id, plugin_matches) = matches.subcommand()?;
    let (command, command_matches) = plugin_matches.subcommand()?;
    Some((plugin_id, command, command_matches))
}

fn tui_machine_output_requested(matches: &ArgMatches) -> bool {
    arg_present(matches, "format")
        || arg_present(matches, "evidence")
        || arg_present(matches, "print-command")
}

fn tui_fixture_without_target(matches: &ArgMatches) -> bool {
    arg_present(matches, "fixture")
        && !arg_present(matches, "profile")
        && !arg_present(matches, "connection")
}

fn tui_target_requested(matches: &ArgMatches) -> bool {
    arg_present(matches, "profile") || arg_present(matches, "connection")
}

fn arg_present(matches: &ArgMatches, id: &str) -> bool {
    matches.try_contains_id(id).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_cli(args: &[&str]) -> ArgMatches {
        let cli_manager = build_cli_manager();
        let mut argv = vec!["voidb"];
        argv.extend_from_slice(args);
        build_cli_app(&cli_manager)
            .try_get_matches_from(argv)
            .expect("valid CLI args")
    }

    #[test]
    fn standalone_tui_profile_launch_allows_interactive_master_password() {
        let matches = parse_cli(&["ssh", "tui", "--profile", "id:profile:abc"]);

        assert!(command_allows_interactive_master_password(&matches));
        assert!(!command_can_use_raw_config(&matches));
    }

    #[test]
    fn machine_tui_outputs_do_not_prompt_for_master_password() {
        let preflight = parse_cli(&[
            "ssh",
            "tui",
            "--profile",
            "id:profile:abc",
            "--format",
            "json",
        ]);
        let evidence = parse_cli(&[
            "ssh",
            "tui",
            "--profile",
            "id:profile:abc",
            "--evidence",
            "target/tmp/evidence.json",
        ]);

        assert!(!command_allows_interactive_master_password(&preflight));
        assert!(!command_allows_interactive_master_password(&evidence));
        assert!(!command_can_use_raw_config(&preflight));
        assert!(!command_can_use_raw_config(&evidence));
    }

    #[test]
    fn fixture_tui_without_target_uses_raw_config() {
        let matches = parse_cli(&[
            "ssh",
            "tui",
            "--fixture",
            "crates/plugins/voidb-plugin-ssh/fixtures/ssh_tui_terminal_core.json",
        ]);

        assert!(!command_allows_interactive_master_password(&matches));
        assert!(command_can_use_raw_config(&matches));
    }

    #[test]
    fn connection_manager_tui_uses_raw_config() {
        let matches = parse_cli(&["connections", "tui"]);

        assert!(!command_allows_interactive_master_password(&matches));
        assert!(command_can_use_raw_config(&matches));
    }

    #[test]
    fn static_discovery_and_profile_metadata_use_raw_config() {
        for args in [
            vec!["invoke", "list"],
            vec!["invoke", "describe", "ssh.exec"],
            vec!["invoke", "matrix"],
            vec!["plugin", "list"],
            vec!["plugin", "describe", "example"],
            vec!["profile", "list"],
            vec!["profile", "show", "id:profile:abc"],
            vec!["connections", "list"],
            vec!["connections", "show", "legacy"],
            vec![
                "context",
                "list",
                "--client-id",
                "agent-cli",
                "--task-id",
                "task-1",
            ],
            vec![
                "context",
                "status",
                "--client-id",
                "agent-cli",
                "--task-id",
                "task-1",
                "--plugin",
                "docker",
                "--generation",
                "1",
                "context:docker:1:1",
            ],
        ] {
            let matches = parse_cli(&args);
            assert!(
                command_can_use_raw_config(&matches),
                "{args:?} should not require credential decryption"
            );
        }
    }

    #[test]
    fn protected_config_static_discovery_never_requires_or_exposes_password() {
        let root = std::env::temp_dir().join(format!(
            "voidb-cli-static-discovery-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).expect("create test config root");
        let path = root.join("config.toml");
        let mut protected = AppConfig {
            connections: vec![voidb_core::ConnectionConfig {
                name: "protected".into(),
                db_type: voidb_core::DatabaseType::Plugin,
                plugin_id: Some("redis".into()),
                plugin_config: Some(serde_json::json!({
                    "host": "cache.internal",
                    "password": "static-discovery-secret"
                })),
            }],
            ..Default::default()
        };
        protected
            .set_user_passphrase_protection("correct horse battery staple")
            .expect("configure protection");
        protected
            .save_to_path_with_password(&path, Some("correct horse battery staple"))
            .expect("save protected config");

        for args in [
            vec!["invoke", "list"],
            vec!["invoke", "describe", "ssh.exec"],
            vec!["plugin", "list"],
            vec!["profile", "list"],
            vec![
                "context",
                "status",
                "--client-id",
                "agent-cli",
                "--task-id",
                "task-1",
                "--plugin",
                "docker",
                "--generation",
                "1",
                "context:docker:1:1",
            ],
        ] {
            let matches = parse_cli(&args);
            for broker_password in [None, Some("deliberately-wrong".to_string())] {
                let (raw, active_password) =
                    load_config_for_command_at_path(broker_password, &matches, &path)
                        .unwrap_or_else(|error| panic!("{args:?} should load statically: {error}"));
                let encoded = serde_json::to_string(&raw).expect("serialize raw config");
                assert!(raw.requires_master_password());
                assert!(active_password.is_none());
                assert!(!encoded.contains("static-discovery-secret"));
                assert!(!encoded.contains("correct horse battery staple"));
            }
        }

        std::fs::remove_dir_all(&root).expect("remove test config root");
    }

    #[test]
    fn legacy_unprotected_config_static_discovery_ignores_password_context() {
        let root = std::env::temp_dir().join(format!(
            "voidb-cli-legacy-static-discovery-{}",
            uuid::Uuid::new_v4()
        ));
        std::fs::create_dir_all(&root).expect("create test config root");
        let path = root.join("config.toml");
        let config = AppConfig {
            connections: vec![voidb_core::ConnectionConfig {
                name: "legacy".into(),
                db_type: voidb_core::DatabaseType::Plugin,
                plugin_id: Some("redis".into()),
                plugin_config: Some(serde_json::json!({
                    "host": "cache.internal",
                    "password": "legacy-static-discovery-secret"
                })),
            }],
            ..Default::default()
        };
        config
            .save_to_path_with_password(&path, None)
            .expect("save legacy config");

        for args in [
            vec!["invoke", "list", "--execution-mode", "stateless"],
            vec!["invoke", "describe", "ssh.terminal_read"],
            vec!["plugin", "list"],
            vec!["profile", "list"],
            vec![
                "context",
                "status",
                "--client-id",
                "agent-cli",
                "--task-id",
                "task-1",
                "--plugin",
                "docker",
                "--generation",
                "1",
                "context:docker:1:1",
            ],
        ] {
            let matches = parse_cli(&args);
            let (raw, active_password) = load_config_for_command_at_path(
                Some("irrelevant-broker-password".to_string()),
                &matches,
                &path,
            )
            .unwrap_or_else(|error| panic!("{args:?} should load statically: {error}"));
            let encoded = serde_json::to_string(&raw).expect("serialize raw config");
            assert!(!raw.requires_master_password());
            assert!(active_password.is_none());
            assert!(!encoded.contains("legacy-static-discovery-secret"));
            assert!(!encoded.contains("irrelevant-broker-password"));
        }

        std::fs::remove_dir_all(&root).expect("remove test config root");
    }

    #[test]
    fn shared_ssh_session_commands_use_password_free_raw_config() {
        let canonical = parse_cli(&["ssh", "session", "list"]);
        let compatibility_alias = parse_cli(&["ssh", "assist", "list"]);

        assert!(command_can_use_raw_config(&canonical));
        assert!(command_can_use_raw_config(&compatibility_alias));
    }

    #[test]
    fn non_tui_commands_keep_non_interactive_master_password_policy() {
        let matches = parse_cli(&["ssh", "test", "--connection", "prod"]);

        assert!(!command_allows_interactive_master_password(&matches));
        assert!(!command_can_use_raw_config(&matches));
    }

    #[test]
    fn incomplete_tui_command_does_not_prompt_before_plugin_validation() {
        let matches = parse_cli(&["ssh", "tui"]);

        assert!(!command_allows_interactive_master_password(&matches));
        assert!(!command_can_use_raw_config(&matches));
    }
}
