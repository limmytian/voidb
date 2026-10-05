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
fn parse_plugin_config<T: serde::de::DeserializeOwned>(
    conn: &voidb_core::connection::ConnectionConfig,
) -> Result<T, String> {
    let raw = conn
        .plugin_config
        .as_ref()
        .ok_or_else(|| "Missing plugin_config".to_string())?;
    serde_json::from_value(raw.clone()).map_err(|e| format!("Invalid plugin config: {}", e))
}

/// Test a connection using the appropriate service's `new_direct()` constructor
/// or a dedicated `test_connection()` helper, dispatched by `plugin_id`.
///
/// Returns a short status string on success, or an error message on failure.
pub(crate) async fn test_connection_by_plugin(
    plugin_id: &str,
    conn: &voidb_core::connection::ConnectionConfig,
) -> Result<String, String> {
    match plugin_id {
        // === MySQL ===
        "mysql" => {
            let config: voidb_plugin_mysql::MySqlConfig = parse_plugin_config(conn)?;
            voidb_plugin_mysql::service::MySqlService::new_direct(&config)
                .await?;
            Ok(format!("connected to {}:{}", config.host, config.port))
        }

        // === PostgreSQL ===
        "postgres" | "postgresql" => {
            let config: voidb_plugin_postgres::PostgresConfig = parse_plugin_config(conn)?;
            voidb_plugin_postgres::service::PostgresService::new_direct(&config)
                .await?;
            Ok(format!("connected to {}:{}", config.host, config.port))
        }

        // === SQLite ===
        "sqlite" => {
            let config: voidb_plugin_sqlite::SqliteConfig = parse_plugin_config(conn)?;
            voidb_plugin_sqlite::service::SqliteService::new_direct(&config)?;
            Ok(format!("opened '{}'", config.path))
        }

        // === DuckDB ===
        "duckdb" => {
            let config: voidb_plugin_duckdb::DuckDbConfig = parse_plugin_config(conn)?;
            voidb_plugin_duckdb::test_connection(&config)
        }

        // === Redis — uses dedicated test_connection helper for a real PING ===
        "redis" => {
            voidb_plugin_redis::test_connection(conn)
                .await
                .map_err(|e| e.to_string())
        }

        // === Kubernetes ===
        "kubernetes" => {
            voidb_plugin_kubernetes::test_connection(conn)
                .await
                .map_err(|e| e.to_string())
        }

        // === S3 ===
        "s3" => {
            voidb_plugin_s3::test_connection(conn)
                .await
                .map_err(|e| e.to_string())
        }

        // === WebDAV ===
        "webdav" => {
            voidb_plugin_webdav::test_connection(conn)
                .await
                .map_err(|e| e.to_string())
        }

        // === Elasticsearch ===
        "elasticsearch" => {
            voidb_plugin_elasticsearch::test_connection(conn)
                .await
                .map_err(|e| e.to_string())
        }

        // === MongoDB ===
        "mongodb" => {
            voidb_plugin_mongodb::test_connection(conn)
                .await
                .map_err(|e| e.to_string())
        }

        // === SSH ===
        "ssh" => {
            voidb_plugin_ssh::test_connection(conn)
                .await
                .map_err(|e| e.to_string())
        }

        // === Email — new_direct() then connect_direct() ===
        "email" => {
            let config: voidb_plugin_email::EmailConfig = parse_plugin_config(conn)?;
            let mut svc = voidb_plugin_email::EmailService::new_direct()
                .map_err(|e| e.to_string())?;
            svc.connect_direct(config)
                .await
                .map_err(|e| e.to_string())?;
            Ok("connected".to_string())
        }

        // === Jenkins ===
        "jenkins" => voidb_plugin_jenkins::test_connection(conn)
            .await
            .map_err(|e| e.to_string()),

        // === Unsupported ===
        other => Err(format!(
            "Connection testing is not supported for plugin '{}'",
            other
        )),
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use voidb_core::{ConnectionConfig, DatabaseType};

    use super::test_connection_by_plugin;

    #[tokio::test]
    async fn dispatches_jenkins_connection_test() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind Jenkins fixture server");
        let address = listener.local_addr().expect("fixture server address");

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept Jenkins request");
            let mut request = Vec::new();
            loop {
                let mut chunk = [0; 512];
                let bytes_read = stream
                    .read(&mut chunk)
                    .await
                    .expect("read Jenkins request");
                assert!(bytes_read > 0, "Jenkins request ended before its headers");
                request.extend_from_slice(&chunk[..bytes_read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let request = String::from_utf8_lossy(&request);
            assert!(
                request.starts_with("GET /api/json?tree=nodeName,nodeDescription,url HTTP/1.1")
            );

            let body =
                r#"{"nodeName":"fixture-controller","nodeDescription":"","url":"http://fixture/"}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .write_all(response.as_bytes())
                .await
                .expect("write Jenkins response");
        });

        let connection = ConnectionConfig {
            name: "fixture-jenkins".into(),
            db_type: DatabaseType::Plugin,
            plugin_id: Some("jenkins".into()),
            plugin_config: Some(json!({
                "url": format!("http://{address}"),
                "auth": { "type": "None" },
                "timeout": 5,
                "verify_ssl": true
            })),
        };

        let result = test_connection_by_plugin("jenkins", &connection)
            .await
            .expect("Jenkins test is dispatched");

        assert_eq!(
            result,
            format!("Jenkins node 'fixture-controller' at http://{address}")
        );
        server.await.expect("Jenkins fixture server completes");
    }
}
