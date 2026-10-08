//! Built-in `connections` CLI plugin.
//!
//! Provides `list`, `show`, and `test` subcommands for managing VoidB
//! connection configurations. Connection testing uses each plugin's service
//! layer directly — no `PluginManager` or `NativePlugin` indirection.

use async_trait::async_trait;
use clap::{Arg, ArgAction, ArgMatches, Command};
use std::process::Stdio;
use voidb_core::plugin::cli::{CliContext, CliPlugin};
use voidb_core::VoidbError;

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
        if ctx.config.connections.is_empty() {
            println!("No connections configured.");
            return Ok(());
        }

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
        Ok(())
    }

    async fn handle_test(&self, name: &str, ctx: &CliContext) -> Result<(), VoidbError> {
        let conn_config = ctx.find_connection(name).ok_or_else(|| {
            VoidbError::Plugin(format!("Connection '{}' not found", name))
        })?;

        let plugin_id = conn_config.effective_plugin_id();

        print!("Testing connection '{}'... ", name);

        let result = test_connection_by_plugin(plugin_id, conn_config).await;

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
        let conn_config = ctx.find_connection(name).ok_or_else(|| {
            VoidbError::Plugin(format!("Connection '{}' not found", name))
        })?;

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
    if let Some(candidate) = discovery.effective_candidate(plugin_id)
        && let Some(binary) = &candidate.resolved_runtime_command
    {
            let output = std::process::Command::new(binary)
                .arg("test")
                .arg("--connection")
                .arg(&conn.name)
                .output()
                .map_err(|e| format!("Failed to execute '{}': {}", binary.display(), e))?;

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
