//! Built-in `connections` CLI plugin.
//!
//! Provides `list`, `show`, and `test` subcommands for managing VoidB
//! connection configurations. Connection testing uses each plugin's service
//! layer directly — no `PluginManager` or `NativePlugin` indirection.

use async_trait::async_trait;
use clap::{Arg, ArgAction, ArgMatches, Command};
use std::process::Stdio;
use voidb_core::VoidbError;
use voidb_core::plugin::cli::{CliContext, CliPlugin};

pub struct ConnectionsCliPlugin;

impl ConnectionsCliPlugin {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl CliPlugin for ConnectionsCliPlugin {
    fn plugin_id(&self) -> &str {
        "connections"
    }

    fn name(&self) -> &str {
        "Connection Management"
    }

    fn commands(&self) -> Vec<Command> {
        vec![
            Command::new("list").about("List all configured connections"),
            Command::new("test")
                .about("Test a connection")
                .arg(Arg::new("name").required(true).help("Connection name")),
            Command::new("show")
                .about("Show connection details")
                .arg(Arg::new("name").required(true).help("Connection name")),
            Command::new("tui")
                .about("Open the standalone Connection Manager TUI")
                .arg(
                    Arg::new("print-command")
                        .long("print-command")
                        .help("Print the resolved TUI command instead of launching it")
                        .action(ArgAction::SetTrue),
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
            "list" => self.handle_list(ctx),
            "test" => {
                let name = matches.get_one::<String>("name").unwrap();
                self.handle_test(name, ctx).await
            }
            "show" => {
                let name = matches.get_one::<String>("name").unwrap();
                self.handle_show(name, ctx)
            }
            "tui" => self.handle_tui(matches),
            _ => Err(VoidbError::Plugin(format!("Unknown command: {}", command))),
        }
    }
}

impl ConnectionsCliPlugin {
    fn handle_tui(&self, matches: &ArgMatches) -> Result<(), VoidbError> {
        let tui_bin = resolve_voidb_tui_binary();
        if matches.get_flag("print-command") {
            println!("{} --connection-manager", tui_bin.display());
            return Ok(());
        }

        let status = std::process::Command::new(&tui_bin)
            .arg("--connection-manager")
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
            .map_err(|error| {
                VoidbError::Plugin(format!(
                    "Failed to launch Connection Manager TUI '{}': {}",
                    tui_bin.display(),
                    error
                ))
            })?;

        if status.success() {
            Ok(())
        } else {
            Err(VoidbError::Plugin(format!(
                "Connection Manager TUI exited with status {}",
                status
                    .code()
                    .map(|code| code.to_string())
                    .unwrap_or_else(|| "signal".to_string())
            )))
        }
    }

    fn handle_list(&self, ctx: &CliContext) -> Result<(), VoidbError> {
        let mut any_found = false;
        if !ctx.config.connections.is_empty() {
            println!("{:<20} {:<15} {:<10}", "NAME", "PLUGIN", "TYPE");
            println!("{}", "-".repeat(45));
            for conn in &ctx.config.connections {
                println!(
                    "{:<20} {:<15} {:<10}",
                    conn.name,
                    conn.effective_plugin_id(),
                    conn.db_type.as_str(),
                );
            }
            any_found = true;
        }

        if let Ok(profiles) = ctx.profiles()
            && !profiles.is_empty()
        {
            if !any_found {
                println!("{:<20} {:<15} {:<10}", "NAME", "PLUGIN", "TYPE");
                println!("{}", "-".repeat(45));
            }
            for profile in &profiles {
                if ctx
                    .config
                    .connections
                    .iter()
                    .any(|c| c.name == profile.name)
                {
                    continue;
                }
                println!(
                    "{:<20} {:<15} {:<10}",
                    profile.name,
                    profile.plugin_id,
                    profile
                        .metadata
                        .get("database_type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("plugin"),
                );
            }
            any_found = true;
        }

        if !any_found {
            println!("No connections configured.");
        }
        Ok(())
    }

    async fn handle_test(&self, name: &str, ctx: &CliContext) -> Result<(), VoidbError> {
        let conn_config = if let Some(conn) = ctx.find_connection(name) {
            conn.clone()
        } else {
            let (_profile, conn) = ctx.resolve_profile_connection(name, None)?;
            conn
        };

        let plugin_id = conn_config.effective_plugin_id().to_string();

        print!("Testing connection '{}'... ", name);

        let result = test_connection_by_plugin(&plugin_id, &conn_config).await;

        match result {
            Ok(msg) => {
                println!("OK ({})", msg);
                Ok(())
            }
            Err(e) => {
                println!("FAILED");
                Err(VoidbError::Connection(e))
            }
        }
    }

    fn handle_show(&self, name: &str, ctx: &CliContext) -> Result<(), VoidbError> {
        let conn_config = if let Some(conn) = ctx.find_connection(name) {
            conn.clone()
        } else {
            let (_profile, conn) = ctx.resolve_profile_connection(name, None)?;
            conn
        };

        println!("Name:      {}", conn_config.name);
        println!("Type:      {}", conn_config.db_type.as_str());
        println!("Plugin:    {}", conn_config.effective_plugin_id());

        if let Some(ref pc) = conn_config.plugin_config {
            println!("Config:");
            if let Some(obj) = pc.as_object() {
                for (key, value) in obj {
                    // Mask sensitive fields
                    let display_value = if key.contains("password") || key.contains("secret") {
                        "********".to_string()
                    } else {
                        value.to_string()
                    };
                    println!("  {}: {}", key, display_value);
                }
            }
        }

        Ok(())
    }
}

fn resolve_voidb_tui_binary() -> std::path::PathBuf {
    if let Ok(path) = std::env::var("VOIDB_TUI_BIN") {
        return path.into();
    }

    if let Ok(current_exe) = std::env::current_exe()
        && let Some(dir) = current_exe.parent()
    {
        let sibling = dir.join("voidb");
        if sibling.exists() {
            return sibling;
        }
    }

    "voidb".into()
}

/// Deserialize plugin config from a `ConnectionConfig` into a typed struct.
///
/// Returns an error string if `plugin_config` is missing or cannot be
/// deserialized into `T`.
#[allow(dead_code)]
fn parse_plugin_config<T: serde::de::DeserializeOwned>(
    conn: &voidb_core::connection::ConnectionConfig,
) -> Result<T, String> {
    let raw = conn
        .plugin_config
        .as_ref()
        .ok_or_else(|| "Missing plugin_config".to_string())?;
    serde_json::from_value(raw.clone()).map_err(|e| format!("Invalid plugin config: {}", e))
}

/// Test a connection by dispatching to the plugin's `test` subcommand.
///
/// Returns a short status string on success, or an error message on failure.
pub(crate) async fn test_connection_by_plugin(
    plugin_id: &str,
    conn: &voidb_core::connection::ConnectionConfig,
) -> Result<String, String> {
    let discovery = voidb_core::process_plugin::discover_process_plugins();
    test_connection_with_discovery(plugin_id, conn, &discovery).await
}

async fn test_connection_with_discovery(
    plugin_id: &str,
    conn: &voidb_core::connection::ConnectionConfig,
    discovery: &voidb_core::ProcessPluginDiscovery,
) -> Result<String, String> {
    if let Some(candidate) = discovery.effective_candidate(plugin_id)
        && let Some(binary) = &candidate.resolved_runtime_command
    {
        if let Err(integrity_err) =
            voidb_core::process_plugin::verify_plugin_binary_integrity(candidate)
        {
            return Err(format!(
                "Plugin security gate check failed: {}",
                integrity_err
            ));
        }

        // Try testing with --stdin-config first (transfers decrypted config via secure anonymous pipe,
        // avoiding CLI argument leakage and eliminating dependency on child process disk configuration).
        let config_bytes = serde_json::to_vec(conn).unwrap_or_default();
        let stdin_run = (|| -> Result<std::process::Output, std::io::Error> {
            use std::io::Write;
            let mut child = std::process::Command::new(binary)
                .arg("test")
                .arg("--stdin-config")
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()?;

            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(&config_bytes);
            }
            child.wait_with_output()
        })();

        let output = match stdin_run {
            Ok(out) if out.status.success() => out,
            Ok(out) => {
                let err_str = String::from_utf8_lossy(&out.stderr);
                if err_str.contains("unexpected argument '--stdin-config'")
                    || err_str.contains("unrecognized option '--stdin-config'")
                {
                    // Fall back to legacy --connection argument for older plugin binaries
                    std::process::Command::new(binary)
                        .arg("test")
                        .arg("--connection")
                        .arg(&conn.name)
                        .output()
                        .map_err(|e| format!("Failed to execute '{}': {}", binary.display(), e))?
                } else {
                    out
                }
            }
            Err(_) => {
                // Fall back to legacy --connection argument
                std::process::Command::new(binary)
                    .arg("test")
                    .arg("--connection")
                    .arg(&conn.name)
                    .output()
                    .map_err(|e| format!("Failed to execute '{}': {}", binary.display(), e))?
            }
        };

        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

        if output.status.success() {
            if !stdout.is_empty() {
                return Ok(stdout);
            } else {
                return Ok("Connection test succeeded".to_string());
            }
        } else {
            let msg = if !stderr.is_empty() {
                stderr
            } else if !stdout.is_empty() {
                stdout
            } else {
                format!("Test exited with status {}", output.status)
            };
            return Err(msg);
        }
    }

    Err(format!(
        "Connection testing is not supported for plugin '{}' (plugin not installed or missing binary)",
        plugin_id
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use voidb_core::{ConnectionConfig, DatabaseType, ProcessPluginDiscovery};

    fn connection() -> ConnectionConfig {
        ConnectionConfig {
            name: "transport-fixture".into(),
            db_type: DatabaseType::Plugin,
            plugin_id: Some("fixture".into()),
            plugin_config: Some(serde_json::json!({"password":"pipe-only-secret"})),
        }
    }

    #[tokio::test]
    async fn missing_plugin_reports_unavailable_without_target_access() {
        let discovery = ProcessPluginDiscovery {
            roots: vec![],
            candidates: vec![],
        };
        let error = test_connection_with_discovery("fixture", &connection(), &discovery)
            .await
            .expect_err("no installed runtime");
        assert!(error.contains("plugin not installed or missing binary"));
        assert!(!error.contains("pipe-only-secret"));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn subprocess_receives_credentials_only_through_stdin() {
        use std::os::unix::fs::PermissionsExt;
        use voidb_core::{
            ProcessPluginRoot, ProcessPluginRootKind, discover_process_plugins_from_roots,
        };
        let root = std::env::temp_dir().join(format!("voidb-transport-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(root.join("fixture/bin")).unwrap();
        std::fs::create_dir_all(root.join("fixture/schemas")).unwrap();
        let received = root.join("fixture/received.json");
        let binary = root.join("fixture/bin/fixture-runtime");
        std::fs::write(
            &binary,
            r#"#!/bin/sh
[ "$#" = 2 ] && [ "$1" = test ] && [ "$2" = --stdin-config ] || exit 21
cd "$(dirname "$0")/.." || exit 22
cat > received.json
printf 'connection fixture accepted'
"#,
        )
        .unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::write(
            root.join("fixture/plugin.toml"),
            r#"id = "fixture"
name = "Transport fixture"
version = "0.3.3"
protocol_version = "1"
[runtime]
command = "fixture-runtime"
args = ["serve"]
transport = "stdio-jsonrpc"
[connections]
profile_schema = "schemas/profile.schema.json"
secret_classes = ["password"]
[[capabilities]]
id = "test"
description = "Transport fixture"
input_schema = "schemas/profile.schema.json"
output_schema = "schemas/profile.schema.json"
permissions = ["connection.test"]
destructive = false
streaming = false
"#,
        )
        .unwrap();
        std::fs::write(
            root.join("fixture/schemas/profile.schema.json"),
            r#"{"type":"object"}"#,
        )
        .unwrap();
        let discovery = discover_process_plugins_from_roots(vec![ProcessPluginRoot::new(
            &root,
            ProcessPluginRootKind::EnvPath,
            0,
        )]);
        assert!(
            discovery
                .effective_candidate("fixture")
                .is_some_and(|c| c.resolved_runtime_command.is_some()),
            "{discovery:?}"
        );
        let result = test_connection_with_discovery("fixture", &connection(), &discovery).await;
        let payload = std::fs::read(&received);
        std::fs::remove_dir_all(&root).unwrap();
        assert_eq!(result.unwrap(), "connection fixture accepted");
        assert_eq!(payload.unwrap(), serde_json::to_vec(&connection()).unwrap());
    }
}
