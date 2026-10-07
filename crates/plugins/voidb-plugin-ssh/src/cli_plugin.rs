//! SSH CLI plugin -- implements `CliPlugin` using `SshService` for all operations.
//!
//! # Service layer usage
//!
//! All operations except port forwarding go through `SshService::new_direct()` and
//! the service's direct async methods (`exec`, `sftp_ls`, `sftp_get`, etc.).
//!
//! # Port forwarding compromise
//!
//! Local, remote, and SOCKS5 forwarding require a persistent accept loop, which
//! cannot be expressed as a single awaitable call. For these commands the service
//! is consumed via `SshService::into_direct_handle()`, exposing the underlying
//! russh session. The forwarding loop then runs directly against that handle.
//! This is the only place in the CLI that retains direct russh usage; it is
//! documented here to make the constraint explicit.

use std::fs;
use std::io::{self, Read};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use clap::{Arg, ArgMatches, Command};
use russh::ChannelMsg;
use serde::Serialize;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use voidb_core::plugin::cli::{CliContext, CliPlugin};
use voidb_core::{
    AgentOperationRequest, AgentPrincipal, AssistAction, AssistActionRisk, AssistActionTarget,
    AssistPermission, AssistRequestStatus, AssistResponse, ConnectionProfileRef,
    PluginSessionHealth, RedactionStatus, TuiLaunchRequest, VoidbError, build_tui_launch_plan,
};

use crate::assist_broker::{SshAssistStore, SshAssistSubmitInput, SshAssistTerminalState};
use crate::config::{SshAuthMethod, SshConfig};
use crate::service::SshService;
use crate::tui::{
    SshTuiLaunch, SshTuiSource, build_ssh_tui_evidence, run_ssh_tui, write_ssh_tui_preflight,
};

pub struct SshCliPlugin;

pub fn create_ssh_cli_plugin() -> Box<dyn CliPlugin> {
    Box::new(SshCliPlugin)
}

fn session_command() -> Command {
    Command::new("session")
        .alias("assist")
        .about("Observe and operate a shared live SSH TUI session")
        .arg(
            Arg::new("store")
                .long("store")
                .value_name("DIR")
                .global(true)
                .help("Override the local SSH session-share store directory"),
        )
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("submit")
                .hide(true)
                .about("Submit a compatibility shared-session JSON payload")
                .arg(
                    Arg::new("input")
                        .short('i')
                        .long("input")
                        .required(true)
                        .value_name("PATH|-")
                        .help("JSON containing request, context, and optional terminal_state"),
                ),
        )
        .subcommand(
            Command::new("list")
                .about("List locally shared SSH TUI sessions")
                .arg(
                    Arg::new("status")
                        .long("status")
                        .help(
                            "Filter by context-share status: draft, pending, operation_pending, cancelled, expired, or closed",
                        ),
                ),
        )
        .subcommand(
            Command::new("show")
                .about("Show one shared session with bounded redacted context")
                .arg(Arg::new("request").required(true).value_name("REQUEST_ID")),
        )
        .subcommand(
            Command::new("wait")
                .about("Wait for an operation request or terminal session status")
                .arg(Arg::new("request").required(true).value_name("REQUEST_ID"))
                .arg(
                    Arg::new("timeout-ms")
                        .long("timeout-ms")
                        .default_value("30000")
                        .value_parser(clap::value_parser!(u64))
                        .help("Maximum wait time in milliseconds"),
                )
                .arg(
                    Arg::new("interval-ms")
                        .long("interval-ms")
                        .default_value("250")
                        .value_parser(clap::value_parser!(u64))
                        .help("Polling interval in milliseconds"),
                ),
        )
        .subcommand(
            Command::new("operation")
                .alias("respond")
                .about("Post a structured external-agent operation request")
                .arg(Arg::new("request").required(true).value_name("REQUEST_ID"))
                .arg(
                    Arg::new("operation-json")
                        .long("operation-json")
                        .alias("response-json")
                        .value_name("PATH|-")
                        .help("Full operation-request JSON; otherwise summary fields are used"),
                )
                .arg(
                    Arg::new("summary")
                        .long("summary")
                        .value_name("TEXT")
                        .required_unless_present("operation-json")
                        .help("Operation summary"),
                )
                .arg(
                    Arg::new("note")
                        .long("note")
                        .alias("diagnosis")
                        .value_name("TEXT")
                        .help("Optional bounded operation note"),
                )
                .arg(
                    Arg::new("permission")
                        .long("permission")
                        .value_parser([
                            "suggest_only",
                            "agent_side_inspect",
                            "propose_commands",
                            "take_control",
                        ])
                        .action(clap::ArgAction::Append)
                        .help("Permission requested by the operation"),
                )
                .arg(
                    Arg::new("agent-client")
                        .long("agent-client")
                        .default_value("external-agent")
                        .help("External agent client ID"),
                )
                .arg(
                    Arg::new("agent-task")
                        .long("agent-task")
                        .default_value("ssh-session")
                        .help("External agent task ID"),
                )
                .arg(
                    Arg::new("agent-instance")
                        .long("agent-instance")
                        .help("Optional external agent instance ID"),
                ),
        )
        .subcommand(
            Command::new("input")
                .about("Request one command on the shared live SSH PTY")
                .arg(Arg::new("request").required(true).value_name("SESSION_ID"))
                .arg(
                    Arg::new("command")
                        .long("command")
                        .required(true)
                        .allow_hyphen_values(true)
                        .value_name("COMMAND")
                        .help("Single-line command to show for local approval"),
                )
                .arg(
                    Arg::new("reason")
                        .long("reason")
                        .default_value("Operate the shared SSH session")
                        .value_name("TEXT")
                        .help("Short reason shown to the local operator"),
                )
                .arg(
                    Arg::new("agent-client")
                        .long("agent-client")
                        .default_value("external-agent")
                        .help("External agent client ID"),
                )
                .arg(
                    Arg::new("agent-task")
                        .long("agent-task")
                        .default_value("ssh-session")
                        .help("External agent task ID"),
                )
                .arg(
                    Arg::new("agent-instance")
                        .long("agent-instance")
                        .help("Optional external agent instance ID"),
                ),
        )
        .subcommand(
            Command::new("cancel")
                .about("Stop sharing a pending SSH TUI session")
                .arg(Arg::new("request").required(true).value_name("REQUEST_ID")),
        )
        .subcommand(
            Command::new("close")
                .about("Close a shared SSH TUI session after local review")
                .arg(Arg::new("request").required(true).value_name("REQUEST_ID")),
        )
        .subcommand(
            Command::new("state")
                .about("Report frontend-safe state for a shared SSH TUI session")
                .arg(Arg::new("request").required(true).value_name("REQUEST_ID"))
                .arg(Arg::new("mode").long("mode").required(true))
                .arg(
                    Arg::new("health")
                        .long("health")
                        .required(true)
                        .value_parser([
                            "ready", "starting", "degraded", "failed", "stale", "closed",
                        ]),
                )
                .arg(
                    Arg::new("status")
                        .long("status")
                        .default_value("")
                        .help("Redacted one-line terminal status"),
                ),
        )
}

#[async_trait]
impl CliPlugin for SshCliPlugin {
    fn plugin_id(&self) -> &str {
        "ssh"
    }

    fn name(&self) -> &str {
        "SSH"
    }

    fn commands(&self) -> Vec<Command> {
        let conn_arg = Arg::new("connection")
            .short('c')
            .long("connection")
            .required(true)
            .help("Connection name");

        vec![
            Command::new("test")
                .about("Test SSH connection")
                .arg(conn_arg.clone()),
            Command::new("exec")
                .about("Execute a remote command")
                .arg(conn_arg.clone())
                .arg(
                    Arg::new("command")
                        .required(true)
                        .trailing_var_arg(true)
                        .num_args(1..)
                        .help("Command to execute"),
                ),
            Command::new("sftp-ls")
                .about("List remote directory")
                .arg(conn_arg.clone())
                .arg(
                    Arg::new("path")
                        .default_value("/")
                        .help("Remote directory path"),
                ),
            Command::new("sftp-get")
                .about("Download a file")
                .arg(conn_arg.clone())
                .arg(Arg::new("remote").required(true).help("Remote file path"))
                .arg(Arg::new("local").required(true).help("Local file path")),
            Command::new("sftp-put")
                .about("Upload a file")
                .arg(conn_arg.clone())
                .arg(Arg::new("local").required(true).help("Local file path"))
                .arg(Arg::new("remote").required(true).help("Remote file path")),
            Command::new("sftp-rm")
                .about("Delete a remote file")
                .arg(conn_arg.clone())
                .arg(Arg::new("path").required(true).help("Remote file path")),
            Command::new("sftp-mkdir")
                .about("Create a remote directory")
                .arg(conn_arg.clone())
                .arg(
                    Arg::new("path")
                        .required(true)
                        .help("Remote directory path"),
                ),
            Command::new("forward-local")
                .about("Local port forwarding (-L), Ctrl+C to stop")
                .arg(conn_arg.clone())
                .arg(
                    Arg::new("spec")
                        .short('L')
                        .required(true)
                        .help("[bind_addr:]port:remote_host:remote_port"),
                ),
            Command::new("forward-remote")
                .about("Remote port forwarding (-R), Ctrl+C to stop")
                .arg(conn_arg.clone())
                .arg(
                    Arg::new("spec")
                        .short('R')
                        .required(true)
                        .help("[remote_addr:]port:local_host:local_port"),
                ),
            Command::new("forward-socks")
                .about("Dynamic SOCKS5 proxy (-D), Ctrl+C to stop")
                .arg(conn_arg.clone())
                .arg(
                    Arg::new("spec")
                        .short('D')
                        .required(true)
                        .help("[bind_addr:]port"),
                ),
            session_command(),
            Command::new("tui")
                .about("Launch the standalone SSH TUI")
                .arg(
                    Arg::new("profile")
                        .long("profile")
                        .value_name("PROFILE")
                        .conflicts_with("connection")
                        .help("Profile name, id:<id>, or name:<name>"),
                )
                .arg(
                    Arg::new("connection")
                        .short('c')
                        .long("connection")
                        .value_name("CONNECTION")
                        .conflicts_with("profile")
                        .help("Legacy connection name"),
                )
                .arg(
                    Arg::new("fixture").long("fixture").value_name("PATH").help(
                        "Load deterministic SSH TUI fixture JSON instead of opening a target",
                    ),
                )
                .arg(
                    Arg::new("purpose")
                        .long("purpose")
                        .value_name("PURPOSE")
                        .default_value("terminal")
                        .help("Launch purpose, for example terminal or sftp"),
                )
                .arg(
                    Arg::new("readonly")
                        .long("readonly")
                        .action(clap::ArgAction::SetTrue)
                        .help("Request read-only behavior where the TUI can enforce it"),
                )
                .arg(
                    Arg::new("no-restore")
                        .long("no-restore")
                        .action(clap::ArgAction::SetTrue)
                        .help("Start without restoring plugin-owned UI state"),
                )
                .arg(
                    Arg::new("format")
                        .long("format")
                        .value_parser(["json"])
                        .help("Emit secret-free preflight JSON and exit"),
                )
                .arg(
                    Arg::new("evidence")
                        .long("evidence")
                        .value_name("PATH")
                        .help("Write fixture-backed standalone SSH TUI evidence JSON and exit"),
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
            "test" => self.handle_test(matches, ctx).await,
            "exec" => self.handle_exec(matches, ctx).await,
            "sftp-ls" => self.handle_sftp_ls(matches, ctx).await,
            "sftp-get" => self.handle_sftp_get(matches, ctx).await,
            "sftp-put" => self.handle_sftp_put(matches, ctx).await,
            "sftp-rm" => self.handle_sftp_rm(matches, ctx).await,
            "sftp-mkdir" => self.handle_sftp_mkdir(matches, ctx).await,
            "forward-local" => self.handle_forward_local(matches, ctx).await,
            "forward-remote" => self.handle_forward_remote(matches, ctx).await,
            "forward-socks" => self.handle_forward_socks(matches, ctx).await,
            "session" | "assist" => self.handle_session(matches).await,
            "tui" => self.handle_tui(matches, ctx).await,
            _ => Err(VoidbError::Plugin(format!("Unknown command: {}", command))),
        }
    }
}

impl SshCliPlugin {
    /// Parse and validate the SSH config for a named connection from the CLI context.
    fn parse_config(conn_name: &str, ctx: &CliContext) -> Result<SshConfig, VoidbError> {
        let config = ctx
            .find_connection(conn_name)
            .ok_or_else(|| VoidbError::Plugin(format!("Connection '{}' not found", conn_name)))?;

        if config.effective_plugin_id() != "ssh" {
            return Err(VoidbError::Plugin(format!(
                "Connection '{}' is not an SSH connection (plugin: {})",
                conn_name,
                config.effective_plugin_id()
            )));
        }

        config
            .plugin_config
            .as_ref()
            .ok_or_else(|| VoidbError::Connection("Missing plugin_config".to_string()))
            .and_then(|pc| {
                serde_json::from_value(pc.clone())
                    .map_err(|e| VoidbError::Connection(format!("Invalid SSH config: {}", e)))
            })
    }

    fn parse_tui_launch(
        matches: &ArgMatches,
        ctx: &CliContext,
    ) -> Result<SshTuiLaunch, VoidbError> {
        let fixture_path = matches.get_one::<String>("fixture").cloned();
        let purpose = matches
            .get_one::<String>("purpose")
            .cloned()
            .unwrap_or_else(|| "terminal".to_string());
        let readonly = matches.get_flag("readonly");
        let restore = !matches.get_flag("no-restore");

        if let Some(profile_ref) = matches.get_one::<String>("profile") {
            let (profile, connection) = ctx.resolve_profile_connection(profile_ref, Some("ssh"))?;
            let config = connection
                .plugin_config
                .as_ref()
                .ok_or_else(|| VoidbError::Connection("Missing plugin_config".to_string()))
                .and_then(|pc| {
                    serde_json::from_value(pc.clone())
                        .map_err(|e| VoidbError::Connection(format!("Invalid SSH config: {}", e)))
                })?;
            let profile_arg = profile_ref_arg(profile_ref, &profile.id);
            let request = TuiLaunchRequest::new("ssh", profile_arg, purpose.clone())
                .readonly(readonly)
                .restore(restore)
                .raw_input(true);
            let launch_plan = build_tui_launch_plan(&profile, request, "voidb-cli", Utc::now())?;

            return Ok(SshTuiLaunch {
                profile_label: profile.name,
                config: Some(config),
                source: SshTuiSource::Profile,
                fixture_path,
                purpose,
                readonly,
                restore,
                launch_plan: Some(launch_plan),
            });
        }

        if let Some(conn_name) = matches.get_one::<String>("connection") {
            return Ok(SshTuiLaunch {
                profile_label: conn_name.clone(),
                config: Some(Self::parse_config(conn_name, ctx)?),
                source: SshTuiSource::Connection,
                fixture_path,
                purpose,
                readonly,
                restore,
                launch_plan: None,
            });
        }

        if fixture_path.is_some() {
            return Ok(SshTuiLaunch {
                profile_label: "fixture".to_string(),
                config: None,
                source: SshTuiSource::Fixture,
                fixture_path,
                purpose,
                readonly,
                restore,
                launch_plan: None,
            });
        }

        Err(VoidbError::Plugin(
            "ssh tui requires --profile, --connection, or --fixture".to_string(),
        ))
    }

    async fn handle_tui(&self, matches: &ArgMatches, ctx: &CliContext) -> Result<(), VoidbError> {
        let launch = Self::parse_tui_launch(matches, ctx)?;
        if let Some(path) = matches.get_one::<String>("evidence") {
            let evidence = build_ssh_tui_evidence(&launch)
                .map_err(|e| VoidbError::Plugin(format!("SSH TUI evidence failed: {}", e)))?;
            let rendered = serde_json::to_string_pretty(&evidence).map_err(|e| {
                VoidbError::Plugin(format!("SSH TUI evidence serialization failed: {}", e))
            })?;
            if let Some(parent) = std::path::Path::new(path).parent()
                && !parent.as_os_str().is_empty()
            {
                fs::create_dir_all(parent).map_err(|e| {
                    VoidbError::Plugin(format!(
                        "Failed to create SSH TUI evidence directory '{}': {}",
                        parent.display(),
                        e
                    ))
                })?;
            }
            fs::write(path, rendered).map_err(|e| {
                VoidbError::Plugin(format!(
                    "Failed to write SSH TUI evidence '{}': {}",
                    path, e
                ))
            })?;
            println!("Wrote SSH TUI evidence to {path}");
            return Ok(());
        }

        if matches
            .get_one::<String>("format")
            .is_some_and(|format| format == "json")
        {
            write_ssh_tui_preflight(&launch)
                .map_err(|e| VoidbError::Plugin(format!("SSH TUI preflight failed: {}", e)))?;
            return Ok(());
        }

        run_ssh_tui(launch)
            .await
            .map_err(|e| VoidbError::Plugin(format!("SSH TUI failed: {}", e)))
    }

    /// Create an `SshService` in Direct mode for the named connection.
    async fn open_service(conn_name: &str, ctx: &CliContext) -> Result<SshService, VoidbError> {
        let ssh_config = Self::parse_config(conn_name, ctx)?;
        SshService::new_direct(ssh_config).await
    }

    async fn handle_session(&self, matches: &ArgMatches) -> Result<(), VoidbError> {
        let result = (|| -> anyhow::Result<serde_json::Value> {
            let store = assist_store_from_matches(matches)?;
            match matches.subcommand() {
                Some(("submit", sub)) => {
                    let input_path = sub.get_one::<String>("input").unwrap();
                    let input: SshAssistSubmitInput = parse_json_input(input_path)?;
                    let record = store.share(input.request, input.context, input.terminal_state)?;
                    Ok(serde_json::to_value(store.detail(&record.request.id)?)?)
                }
                Some(("list", sub)) => {
                    let status = sub
                        .get_one::<String>("status")
                        .map(|value| parse_context_share_status(value))
                        .transpose()?;
                    Ok(serde_json::to_value(store.list(status)?)?)
                }
                Some(("show", sub)) => {
                    let request_id = sub.get_one::<String>("request").unwrap();
                    Ok(serde_json::to_value(store.detail(request_id)?)?)
                }
                Some(("wait", sub)) => {
                    let request_id = sub.get_one::<String>("request").unwrap();
                    let timeout_ms = *sub.get_one::<u64>("timeout-ms").unwrap();
                    let interval_ms = *sub.get_one::<u64>("interval-ms").unwrap();
                    Ok(serde_json::to_value(store.wait_for_operation_request(
                        request_id,
                        Duration::from_millis(timeout_ms),
                        Duration::from_millis(interval_ms.max(1)),
                    )?)?)
                }
                Some(("operation", sub)) => {
                    let request_id = sub.get_one::<String>("request").unwrap();
                    let response = if let Some(path) = sub.get_one::<String>("operation-json") {
                        parse_json_input::<AgentOperationRequest>(path)?
                    } else {
                        operation_request_from_matches(request_id, sub)?
                    };
                    Ok(serde_json::to_value(
                        store.post_operation_request(request_id, response)?,
                    )?)
                }
                Some(("input", sub)) => {
                    let request_id = sub.get_one::<String>("request").unwrap();
                    let detail = store.detail(request_id)?;
                    if detail.record.request.status.is_terminal() {
                        anyhow::bail!("shared SSH session is no longer available");
                    }
                    let response = session_input_operation_from_matches(
                        request_id,
                        detail.record.request.binding.clone(),
                        sub,
                    )?;
                    Ok(serde_json::to_value(
                        store.post_operation_request(request_id, response)?,
                    )?)
                }
                Some(("cancel", sub)) => {
                    let request_id = sub.get_one::<String>("request").unwrap();
                    Ok(serde_json::to_value(store.cancel(request_id)?)?)
                }
                Some(("close", sub)) => {
                    let request_id = sub.get_one::<String>("request").unwrap();
                    Ok(serde_json::to_value(store.close(request_id)?)?)
                }
                Some(("state", sub)) => {
                    let request_id = sub.get_one::<String>("request").unwrap();
                    let state = SshAssistTerminalState {
                        mode: sub.get_one::<String>("mode").unwrap().clone(),
                        health: parse_session_health(sub.get_one::<String>("health").unwrap())?,
                        status: sub.get_one::<String>("status").unwrap().clone(),
                        updated_at: Utc::now(),
                        redaction: RedactionStatus::Applied,
                    };
                    Ok(serde_json::to_value(
                        store.update_terminal_state(request_id, state)?,
                    )?)
                }
                _ => Err(anyhow::anyhow!("Unknown ssh session command")),
            }
        })();

        match result {
            Ok(data) => print_session_json(data),
            Err(error) => print_session_error(error),
        }
    }

    // -----------------------------------------------------------------------
    // Command handlers
    // -----------------------------------------------------------------------

    async fn handle_test(&self, matches: &ArgMatches, ctx: &CliContext) -> Result<(), VoidbError> {
        let conn_name = matches.get_one::<String>("connection").unwrap();
        let ssh_config = Self::parse_config(conn_name, ctx)?;

        print!("Testing connection '{}'... ", conn_name);
        // new_direct() connects and authenticates; success means the connection works.
        let svc = SshService::new_direct(ssh_config.clone()).await?;
        svc.disconnect().await;
        println!(
            "OK ({}@{}:{})",
            ssh_config.username, ssh_config.host, ssh_config.port
        );
        Ok(())
    }

    async fn handle_exec(&self, matches: &ArgMatches, ctx: &CliContext) -> Result<(), VoidbError> {
        let conn_name = matches.get_one::<String>("connection").unwrap();
        let parts: Vec<&String> = matches.get_many::<String>("command").unwrap().collect();
        let command_str = parts
            .iter()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join(" ");

        let mut svc = Self::open_service(conn_name, ctx).await?;
        let (stdout, exit_code) = svc.exec(&command_str).await?;
        svc.disconnect().await;

        print!("{}", stdout);

        if let Some(code) = exit_code
            && code != 0
        {
            return Err(VoidbError::Plugin(format!(
                "Command exited with code {}",
                code
            )));
        }

        Ok(())
    }

    async fn handle_sftp_ls(
        &self,
        matches: &ArgMatches,
        ctx: &CliContext,
    ) -> Result<(), VoidbError> {
        let conn_name = matches.get_one::<String>("connection").unwrap();
        let path = matches.get_one::<String>("path").unwrap();

        let mut svc = Self::open_service(conn_name, ctx).await?;
        let entries = svc.sftp_ls(path).await?;
        svc.disconnect().await;

        println!("{:<10} {:>12} NAME", "TYPE", "SIZE");
        println!("{}", "-".repeat(50));
        for (name, is_dir, size) in entries {
            let type_str = if is_dir { "dir" } else { "file" };
            println!("{:<10} {:>12} {}", type_str, size, name);
        }

        Ok(())
    }

    async fn handle_sftp_get(
        &self,
        matches: &ArgMatches,
        ctx: &CliContext,
    ) -> Result<(), VoidbError> {
        let conn_name = matches.get_one::<String>("connection").unwrap();
        let remote = matches.get_one::<String>("remote").unwrap();
        let local = matches.get_one::<String>("local").unwrap();

        let mut svc = Self::open_service(conn_name, ctx).await?;
        let bytes = svc.sftp_get(remote, local).await?;
        svc.disconnect().await;

        println!("Downloaded {} -> {} ({} bytes)", remote, local, bytes);
        Ok(())
    }

    async fn handle_sftp_put(
        &self,
        matches: &ArgMatches,
        ctx: &CliContext,
    ) -> Result<(), VoidbError> {
        let conn_name = matches.get_one::<String>("connection").unwrap();
        let local = matches.get_one::<String>("local").unwrap();
        let remote = matches.get_one::<String>("remote").unwrap();

        let mut svc = Self::open_service(conn_name, ctx).await?;
        let bytes = svc.sftp_put(local, remote).await?;
        svc.disconnect().await;

        println!("Uploaded {} -> {} ({} bytes)", local, remote, bytes);
        Ok(())
    }

    async fn handle_sftp_rm(
        &self,
        matches: &ArgMatches,
        ctx: &CliContext,
    ) -> Result<(), VoidbError> {
        let conn_name = matches.get_one::<String>("connection").unwrap();
        let path = matches.get_one::<String>("path").unwrap();

        let mut svc = Self::open_service(conn_name, ctx).await?;
        svc.sftp_rm(path).await?;
        svc.disconnect().await;

        println!("Deleted {}", path);
        Ok(())
    }

    async fn handle_sftp_mkdir(
        &self,
        matches: &ArgMatches,
        ctx: &CliContext,
    ) -> Result<(), VoidbError> {
        let conn_name = matches.get_one::<String>("connection").unwrap();
        let path = matches.get_one::<String>("path").unwrap();

        let mut svc = Self::open_service(conn_name, ctx).await?;
        svc.sftp_mkdir(path).await?;
        svc.disconnect().await;

        println!("Created directory {}", path);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Port forwarding handlers
    //
    // NOTE: These consume the service via `into_direct_handle()` to obtain
    // the raw russh session handle. This is necessary because forwarding
    // requires a persistent accept loop that cannot be expressed as a single
    // awaitable service call. See module-level doc for the full rationale.
    // -----------------------------------------------------------------------

    async fn handle_forward_local(
        &self,
        matches: &ArgMatches,
        ctx: &CliContext,
    ) -> Result<(), VoidbError> {
        let conn_name = matches.get_one::<String>("connection").unwrap();
        let spec = matches.get_one::<String>("spec").unwrap();
        let (bind_addr, bind_port, remote_host, remote_port) = parse_local_forward_spec(spec)?;

        let ssh_config = Self::parse_config(conn_name, ctx)?;
        let svc = SshService::new_direct(ssh_config.clone()).await?;
        // Consume service into raw handle for the forwarding loop.
        let handle = svc
            .into_direct_handle()
            .expect("new_direct always produces Direct mode");
        let session = Arc::new(handle.inner);

        let listener = TcpListener::bind(format!("{}:{}", bind_addr, bind_port))
            .await
            .map_err(|e| {
                VoidbError::Plugin(format!("Failed to bind {}:{}: {}", bind_addr, bind_port, e))
            })?;

        eprintln!(
            "Forwarding {}:{} -> {}:{} via {}@{}:{}",
            bind_addr,
            bind_port,
            remote_host,
            remote_port,
            ssh_config.username,
            ssh_config.host,
            ssh_config.port,
        );
        eprintln!("Press Ctrl+C to stop");

        let stats = Arc::new(ForwardStats::default());

        loop {
            tokio::select! {
                accept = listener.accept() => {
                    let (stream, peer) = accept
                        .map_err(|e| VoidbError::Plugin(format!("Accept error: {}", e)))?;
                    let session = session.clone();
                    let rh = remote_host.clone();
                    let stats = stats.clone();
                    tokio::spawn(async move {
                        stats.connections.fetch_add(1, Ordering::Relaxed);
                        if let Err(e) = handle_local_forward_conn(
                            stream, &session, &rh, remote_port,
                            &peer.ip().to_string(), peer.port(),
                            &stats,
                        ).await {
                            eprintln!("Connection error: {}", e);
                        }
                        stats.connections.fetch_sub(1, Ordering::Relaxed);
                    });
                }
                _ = tokio::signal::ctrl_c() => {
                    eprintln!("\nStopping... (sent {} bytes, received {} bytes)",
                        stats.bytes_sent.load(Ordering::Relaxed),
                        stats.bytes_recv.load(Ordering::Relaxed),
                    );
                    break;
                }
            }
        }

        let _ = session
            .disconnect(russh::Disconnect::ByApplication, "", "en")
            .await;
        Ok(())
    }

    async fn handle_forward_remote(
        &self,
        matches: &ArgMatches,
        ctx: &CliContext,
    ) -> Result<(), VoidbError> {
        let conn_name = matches.get_one::<String>("connection").unwrap();
        let spec = matches.get_one::<String>("spec").unwrap();
        let (remote_addr, remote_port, local_host, local_port) = parse_local_forward_spec(spec)?;

        let ssh_config = Self::parse_config(conn_name, ctx)?;

        // Remote forwarding needs a handler that accepts forwarded-tcpip channels.
        // We use a dedicated handler+connect path here since the DirectCliHandler
        // does not forward-tcpip callbacks.
        let (fwd_tx, mut fwd_rx) = tokio::sync::mpsc::unbounded_channel::<ForwardedTcpip>();
        let mut session = connect_and_auth_forwarding(&ssh_config, fwd_tx).await?;

        let allocated_port = session
            .tcpip_forward(&remote_addr, remote_port as u32)
            .await
            .map_err(|e| VoidbError::Plugin(format!("tcpip-forward failed: {}", e)))?;

        let effective_port = if allocated_port == 0 {
            remote_port
        } else {
            allocated_port as u16
        };

        eprintln!(
            "Remote forwarding {}:{} -> {}:{} via {}@{}:{}",
            remote_addr,
            effective_port,
            local_host,
            local_port,
            ssh_config.username,
            ssh_config.host,
            ssh_config.port,
        );
        eprintln!("Press Ctrl+C to stop");

        let stats = Arc::new(ForwardStats::default());

        loop {
            tokio::select! {
                fwd = fwd_rx.recv() => {
                    let Some(fwd) = fwd else { break };
                    let lh = local_host.clone();
                    let stats = stats.clone();
                    tokio::spawn(async move {
                        stats.connections.fetch_add(1, Ordering::Relaxed);
                        if let Err(e) =
                            handle_remote_forward_conn(fwd.channel, &lh, local_port, &stats).await
                        {
                            eprintln!("Remote forward connection error: {}", e);
                        }
                        stats.connections.fetch_sub(1, Ordering::Relaxed);
                    });
                }
                _ = tokio::signal::ctrl_c() => {
                    eprintln!("\nStopping... (sent {} bytes, received {} bytes)",
                        stats.bytes_sent.load(Ordering::Relaxed),
                        stats.bytes_recv.load(Ordering::Relaxed),
                    );
                    break;
                }
            }
        }

        let _ = session
            .cancel_tcpip_forward(&remote_addr, effective_port as u32)
            .await;
        let _ = session
            .disconnect(russh::Disconnect::ByApplication, "", "en")
            .await;
        Ok(())
    }

    async fn handle_forward_socks(
        &self,
        matches: &ArgMatches,
        ctx: &CliContext,
    ) -> Result<(), VoidbError> {
        let conn_name = matches.get_one::<String>("connection").unwrap();
        let spec = matches.get_one::<String>("spec").unwrap();
        let (bind_addr, bind_port) = parse_socks_spec(spec)?;

        let ssh_config = Self::parse_config(conn_name, ctx)?;
        let svc = SshService::new_direct(ssh_config.clone()).await?;
        let handle = svc
            .into_direct_handle()
            .expect("new_direct always produces Direct mode");
        let session = Arc::new(handle.inner);

        let listener = TcpListener::bind(format!("{}:{}", bind_addr, bind_port))
            .await
            .map_err(|e| {
                VoidbError::Plugin(format!("Failed to bind {}:{}: {}", bind_addr, bind_port, e))
            })?;

        eprintln!(
            "SOCKS5 proxy listening on {}:{} via {}@{}:{}",
            bind_addr, bind_port, ssh_config.username, ssh_config.host, ssh_config.port,
        );
        eprintln!("Press Ctrl+C to stop");

        let stats = Arc::new(ForwardStats::default());

        loop {
            tokio::select! {
                accept = listener.accept() => {
                    let (stream, peer) = accept
                        .map_err(|e| VoidbError::Plugin(format!("Accept error: {}", e)))?;
                    let session = session.clone();
                    let stats = stats.clone();
                    tokio::spawn(async move {
                        stats.connections.fetch_add(1, Ordering::Relaxed);
                        if let Err(e) = handle_socks5_conn(
                            stream, &session,
                            &peer.ip().to_string(), peer.port(),
                            &stats,
                        ).await {
                            eprintln!("SOCKS5 error: {}", e);
                        }
                        stats.connections.fetch_sub(1, Ordering::Relaxed);
                    });
                }
                _ = tokio::signal::ctrl_c() => {
                    eprintln!("\nStopping... (sent {} bytes, received {} bytes)",
                        stats.bytes_sent.load(Ordering::Relaxed),
                        stats.bytes_recv.load(Ordering::Relaxed),
                    );
                    break;
                }
            }
        }

        let _ = session
            .disconnect(russh::Disconnect::ByApplication, "", "en")
            .await;
        Ok(())
    }
}

fn assist_store_from_matches(matches: &ArgMatches) -> anyhow::Result<SshAssistStore> {
    if let Some(path) = matches.get_one::<String>("store") {
        SshAssistStore::new(PathBuf::from(path))
    } else {
        SshAssistStore::default_store()
    }
}

fn parse_json_input<T: serde::de::DeserializeOwned>(path: &str) -> anyhow::Result<T> {
    let mut text = String::new();
    if path == "-" {
        io::stdin().read_to_string(&mut text)?;
    } else {
        text = fs::read_to_string(path)?;
    }
    Ok(serde_json::from_str(&text)?)
}

fn print_session_json<T: Serialize>(data: T) -> Result<(), VoidbError> {
    let output = json!({
        "ok": true,
        "data": data,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&output).map_err(|error| {
            VoidbError::Plugin(format!("Failed to serialize session output: {error}"))
        })?
    );
    Ok(())
}

fn print_session_error(error: anyhow::Error) -> Result<(), VoidbError> {
    let message = error.to_string();
    let output = json!({
        "ok": false,
        "error": message,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&output).map_err(|error| {
            VoidbError::Plugin(format!(
                "Failed to serialize session operation error: {error}"
            ))
        })?
    );
    Err(VoidbError::Plugin(message))
}

fn operation_request_from_matches(
    request_id: &str,
    matches: &ArgMatches,
) -> anyhow::Result<AgentOperationRequest> {
    let permissions = matches
        .get_many::<String>("permission")
        .map(|values| {
            values
                .map(|value| parse_assist_permission(value))
                .collect::<anyhow::Result<Vec<_>>>()
        })
        .transpose()?
        .unwrap_or_default();
    let actions = permissions
        .iter()
        .filter(|permission| **permission != AssistPermission::SuggestOnly)
        .map(|permission| AssistAction::RequestPermission {
            permission: *permission,
            reason: permission_reason(*permission).to_string(),
            ttl_seconds: 300,
        })
        .collect::<Vec<_>>();
    let response = AssistResponse {
        id: format!("agent:operation:{}", uuid::Uuid::new_v4()),
        request_id: request_id.to_string(),
        agent: AgentPrincipal {
            client_id: matches.get_one::<String>("agent-client").unwrap().clone(),
            task_id: matches.get_one::<String>("agent-task").unwrap().clone(),
            instance_id: matches.get_one::<String>("agent-instance").cloned(),
        },
        created_at: Utc::now(),
        summary: matches.get_one::<String>("summary").unwrap().clone(),
        diagnosis: matches.get_one::<String>("note").cloned(),
        actions,
        requested_permissions: permissions,
        redaction: RedactionStatus::NotRequired,
    };
    response
        .validate()
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    Ok(response)
}

fn session_input_operation_from_matches(
    request_id: &str,
    binding: voidb_core::AssistSessionBinding,
    matches: &ArgMatches,
) -> anyhow::Result<AgentOperationRequest> {
    let command = matches.get_one::<String>("command").unwrap().trim();
    if command.is_empty() {
        anyhow::bail!("shared session input command is required");
    }
    if command.len() > 4096 {
        anyhow::bail!("shared session input command exceeds 4096 bytes");
    }
    if command.contains('\r') || command.contains('\n') {
        anyhow::bail!("shared session input must be a single-line command");
    }
    let agent = AgentPrincipal {
        client_id: matches.get_one::<String>("agent-client").unwrap().clone(),
        task_id: matches.get_one::<String>("agent-task").unwrap().clone(),
        instance_id: matches.get_one::<String>("agent-instance").cloned(),
    };
    agent.validate()?;

    Ok(AssistResponse {
        id: format!("agent:operation:{}", uuid::Uuid::new_v4()),
        request_id: request_id.to_string(),
        agent,
        created_at: Utc::now(),
        summary: "Agent requests input on the shared live SSH session.".to_string(),
        diagnosis: None,
        actions: vec![AssistAction::ProposedCommand {
            command: command.to_string(),
            rationale: matches.get_one::<String>("reason").unwrap().clone(),
            risk: AssistActionRisk::Destructive,
            target: AssistActionTarget::CurrentPty { binding },
        }],
        requested_permissions: vec![AssistPermission::TakeControl],
        redaction: RedactionStatus::NotRequired,
    })
}

fn parse_context_share_status(value: &str) -> anyhow::Result<AssistRequestStatus> {
    match value {
        "draft" => Ok(AssistRequestStatus::Draft),
        "pending" => Ok(AssistRequestStatus::Pending),
        "operation_pending" | "responded" => Ok(AssistRequestStatus::Responded),
        "cancelled" => Ok(AssistRequestStatus::Cancelled),
        "expired" => Ok(AssistRequestStatus::Expired),
        "closed" => Ok(AssistRequestStatus::Closed),
        _ => Err(anyhow::anyhow!("Unsupported context-share status: {value}")),
    }
}

fn parse_assist_permission(value: &str) -> anyhow::Result<AssistPermission> {
    match value {
        "suggest_only" => Ok(AssistPermission::SuggestOnly),
        "agent_side_inspect" => Ok(AssistPermission::AgentSideInspect),
        "propose_commands" => Ok(AssistPermission::ProposeCommands),
        "take_control" => Ok(AssistPermission::TakeControl),
        _ => Err(anyhow::anyhow!("Unsupported session permission: {value}")),
    }
}

fn parse_session_health(value: &str) -> anyhow::Result<PluginSessionHealth> {
    match value {
        "ready" => Ok(PluginSessionHealth::Ready),
        "starting" => Ok(PluginSessionHealth::Starting),
        "degraded" => Ok(PluginSessionHealth::Degraded),
        "failed" => Ok(PluginSessionHealth::Failed),
        "stale" => Ok(PluginSessionHealth::Stale),
        "closed" => Ok(PluginSessionHealth::Closed),
        _ => Err(anyhow::anyhow!("Unsupported session health: {value}")),
    }
}

fn permission_reason(permission: AssistPermission) -> &'static str {
    match permission {
        AssistPermission::SuggestOnly => "Provide guidance without additional authority.",
        AssistPermission::AgentSideInspect => {
            "Open a separate authorized agent-side SSH session for diagnostics."
        }
        AssistPermission::ProposeCommands => {
            "Return proposed commands for explicit human review before execution."
        }
        AssistPermission::TakeControl => {
            "Request short-lived current PTY control; requires separate explicit approval."
        }
    }
}

// ── Forwarding helpers ──────────────────────────────────────────────

/// Per-forwarding-session statistics (atomic counters for thread-safe updates).
struct ForwardStats {
    bytes_sent: AtomicU64,
    bytes_recv: AtomicU64,
    connections: AtomicU64,
}

impl Default for ForwardStats {
    fn default() -> Self {
        Self {
            bytes_sent: AtomicU64::new(0),
            bytes_recv: AtomicU64::new(0),
            connections: AtomicU64::new(0),
        }
    }
}

/// Parse `-L [bind_addr:]bind_port:remote_host:remote_port`
fn parse_local_forward_spec(spec: &str) -> Result<(String, u16, String, u16), VoidbError> {
    let parts: Vec<&str> = spec.split(':').collect();
    match parts.len() {
        3 => {
            // port:host:port
            let bind_port: u16 = parts[0]
                .parse()
                .map_err(|_| VoidbError::Plugin("Invalid bind port".into()))?;
            let remote_port: u16 = parts[2]
                .parse()
                .map_err(|_| VoidbError::Plugin("Invalid remote port".into()))?;
            Ok(("127.0.0.1".into(), bind_port, parts[1].into(), remote_port))
        }
        4 => {
            // addr:port:host:port
            let bind_port: u16 = parts[1]
                .parse()
                .map_err(|_| VoidbError::Plugin("Invalid bind port".into()))?;
            let remote_port: u16 = parts[3]
                .parse()
                .map_err(|_| VoidbError::Plugin("Invalid remote port".into()))?;
            Ok((parts[0].into(), bind_port, parts[2].into(), remote_port))
        }
        _ => Err(VoidbError::Plugin(
            "Invalid spec. Use [bind_addr:]port:remote_host:remote_port".into(),
        )),
    }
}

/// Parse `-D [bind_addr:]port`
fn parse_socks_spec(spec: &str) -> Result<(String, u16), VoidbError> {
    let parts: Vec<&str> = spec.split(':').collect();
    match parts.len() {
        1 => {
            let port: u16 = parts[0]
                .parse()
                .map_err(|_| VoidbError::Plugin("Invalid port".into()))?;
            Ok(("127.0.0.1".into(), port))
        }
        2 => {
            let port: u16 = parts[1]
                .parse()
                .map_err(|_| VoidbError::Plugin("Invalid port".into()))?;
            Ok((parts[0].into(), port))
        }
        _ => Err(VoidbError::Plugin(
            "Invalid spec. Use [bind_addr:]port".into(),
        )),
    }
}

/// Handle a single local-forward connection: open direct-tcpip and bridge.
async fn handle_local_forward_conn(
    mut tcp: TcpStream,
    session: &russh::client::Handle<crate::service::DirectCliHandler>,
    remote_host: &str,
    remote_port: u16,
    originator_addr: &str,
    originator_port: u16,
    stats: &ForwardStats,
) -> anyhow::Result<()> {
    let mut channel = session
        .channel_open_direct_tcpip(
            remote_host,
            remote_port as u32,
            originator_addr,
            originator_port as u32,
        )
        .await?;

    bridge_tcp_ssh(&mut tcp, &mut channel, stats).await
}

/// Handle a SOCKS5 connection: handshake, resolve target, open direct-tcpip, bridge.
async fn handle_socks5_conn(
    mut tcp: TcpStream,
    session: &russh::client::Handle<crate::service::DirectCliHandler>,
    originator_addr: &str,
    originator_port: u16,
    stats: &ForwardStats,
) -> anyhow::Result<()> {
    // SOCKS5 greeting
    let mut buf = [0u8; 258];
    let n = tcp.read(&mut buf).await?;
    if n < 2 || buf[0] != 0x05 {
        return Err(anyhow::anyhow!("Invalid SOCKS5 greeting"));
    }

    // No auth required
    tcp.write_all(&[0x05, 0x00]).await?;

    // SOCKS5 connect request
    let n = tcp.read(&mut buf).await?;
    if n < 4 || buf[0] != 0x05 || buf[1] != 0x01 {
        tcp.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        return Err(anyhow::anyhow!("Unsupported SOCKS5 command"));
    }

    let (target_host, target_port) = match buf[3] {
        0x01 => {
            // IPv4
            if n < 10 {
                return Err(anyhow::anyhow!("SOCKS5 request too short"));
            }
            let host = format!("{}.{}.{}.{}", buf[4], buf[5], buf[6], buf[7]);
            let port = u16::from_be_bytes([buf[8], buf[9]]);
            (host, port)
        }
        0x03 => {
            // Domain
            let len = buf[4] as usize;
            if n < 5 + len + 2 {
                return Err(anyhow::anyhow!("SOCKS5 request too short"));
            }
            let host = String::from_utf8_lossy(&buf[5..5 + len]).to_string();
            let port = u16::from_be_bytes([buf[5 + len], buf[5 + len + 1]]);
            (host, port)
        }
        0x04 => {
            // IPv6
            if n < 22 {
                return Err(anyhow::anyhow!("SOCKS5 request too short"));
            }
            let mut segs = [0u16; 8];
            for i in 0..8 {
                segs[i] = u16::from_be_bytes([buf[4 + i * 2], buf[5 + i * 2]]);
            }
            let host = format!(
                "{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}:{:x}",
                segs[0], segs[1], segs[2], segs[3], segs[4], segs[5], segs[6], segs[7],
            );
            let port = u16::from_be_bytes([buf[20], buf[21]]);
            (host, port)
        }
        _ => {
            tcp.write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            return Err(anyhow::anyhow!("Unsupported SOCKS5 address type"));
        }
    };

    // Open direct-tcpip through SSH
    match session
        .channel_open_direct_tcpip(
            &target_host,
            target_port as u32,
            originator_addr,
            originator_port as u32,
        )
        .await
    {
        Ok(mut channel) => {
            tcp.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            bridge_tcp_ssh(&mut tcp, &mut channel, stats).await
        }
        Err(e) => {
            tcp.write_all(&[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            Err(anyhow::anyhow!("direct-tcpip failed: {}", e))
        }
    }
}

fn profile_ref_arg(profile_ref: &str, resolved_id: &str) -> ConnectionProfileRef {
    if let Some(id) = profile_ref.strip_prefix("id:") {
        ConnectionProfileRef::Id(id.to_string())
    } else if let Some(name) = profile_ref
        .strip_prefix("name:")
        .or_else(|| profile_ref.strip_prefix("alias:"))
    {
        ConnectionProfileRef::Name(name.to_string())
    } else if profile_ref == resolved_id {
        ConnectionProfileRef::Id(profile_ref.to_string())
    } else {
        ConnectionProfileRef::Name(profile_ref.to_string())
    }
}

/// Bidirectional bridge between a TCP stream and an SSH channel.
async fn bridge_tcp_ssh(
    tcp: &mut TcpStream,
    channel: &mut russh::Channel<russh::client::Msg>,
    stats: &ForwardStats,
) -> anyhow::Result<()> {
    let (mut tcp_r, mut tcp_w) = tcp.split();
    let mut buf = vec![0u8; 32768];

    loop {
        tokio::select! {
            n = tcp_r.read(&mut buf) => {
                match n {
                    Ok(0) => break,
                    Ok(n) => {
                        channel.data(&buf[..n]).await?;
                        stats.bytes_sent.fetch_add(n as u64, Ordering::Relaxed);
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            msg = channel.wait() => {
                match msg {
                    Some(ChannelMsg::Data { data }) => {
                        tcp_w.write_all(&data).await?;
                        stats.bytes_recv.fetch_add(data.len() as u64, Ordering::Relaxed);
                    }
                    Some(ChannelMsg::Eof) | None => break,
                    _ => {}
                }
            }
        }
    }

    Ok(())
}

/// Handle an incoming remote-forwarded connection: connect to local target and bridge.
async fn handle_remote_forward_conn(
    mut channel: russh::Channel<russh::client::Msg>,
    local_host: &str,
    local_port: u16,
    stats: &ForwardStats,
) -> anyhow::Result<()> {
    let mut tcp = TcpStream::connect(format!("{}:{}", local_host, local_port)).await?;
    bridge_tcp_ssh(&mut tcp, &mut channel, stats).await
}

// ── Remote forwarding handler (needs forwarded-tcpip callbacks) ─────

/// Incoming forwarded-tcpip channel from the server (for -R forwarding).
struct ForwardedTcpip {
    channel: russh::Channel<russh::client::Msg>,
}

/// SSH handler that accepts forwarded-tcpip channels for remote port forwarding.
///
/// This is kept separate from `DirectCliHandler` because `forward-remote` is the
/// only command that needs to receive server-initiated forwarded-tcpip channels.
/// Using a specialised handler avoids adding callback state to the general CLI handler.
struct ForwardingCliHandler {
    fwd_tx: tokio::sync::mpsc::UnboundedSender<ForwardedTcpip>,
    host: String,
    port: u16,
    host_key_failure: crate::service::HostKeyFailureSlot,
}

#[async_trait]
impl russh::client::Handler for ForwardingCliHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        crate::service::strict_host_key_check(
            &self.host,
            self.port,
            server_public_key,
            &self.host_key_failure,
        )
    }

    async fn server_channel_open_forwarded_tcpip(
        &mut self,
        channel: russh::Channel<russh::client::Msg>,
        _connected_address: &str,
        _connected_port: u32,
        _originator_address: &str,
        _originator_port: u32,
        _session: &mut russh::client::Session,
    ) -> Result<(), Self::Error> {
        let _ = self.fwd_tx.send(ForwardedTcpip { channel });
        Ok(())
    }
}

/// Connect and authenticate using `ForwardingCliHandler` (for remote port forwarding).
///
/// This is the only remaining direct russh call in the CLI. It is required because
/// `forward-remote` needs a handler that implements `server_channel_open_forwarded_tcpip`,
/// and russh does not support swapping handlers after connection.
async fn connect_and_auth_forwarding(
    ssh_config: &SshConfig,
    fwd_tx: tokio::sync::mpsc::UnboundedSender<ForwardedTcpip>,
) -> Result<russh::client::Handle<ForwardingCliHandler>, VoidbError> {
    let client_config = russh::client::Config {
        keepalive_interval: None,
        ..Default::default()
    };

    let host_key_failure = crate::service::new_host_key_failure_slot();
    let handler = ForwardingCliHandler {
        fwd_tx,
        host: ssh_config.host.clone(),
        port: ssh_config.port,
        host_key_failure: host_key_failure.clone(),
    };
    let addr = (ssh_config.host.as_str(), ssh_config.port);
    let timeout = std::time::Duration::from_secs(ssh_config.options.connect_timeout);

    let mut session = tokio::time::timeout(
        timeout,
        russh::client::connect(Arc::new(client_config), addr, handler),
    )
    .await
    .map_err(|_| {
        VoidbError::Connection(format!(
            "Connection timed out after {}s",
            ssh_config.options.connect_timeout
        ))
    })?
    .map_err(|e| crate::service::host_key_connection_error(&host_key_failure, e))?;

    // Authenticate (same logic as service connect_and_auth_direct)
    match &ssh_config.auth {
        SshAuthMethod::Password { password } => {
            let ok = session
                .authenticate_password(&ssh_config.username, password)
                .await
                .map_err(|e| VoidbError::Connection(format!("Auth error: {}", e)))?;
            if !ok {
                return Err(VoidbError::Connection(
                    "Authentication failed: invalid username or password".to_string(),
                ));
            }
        }
        SshAuthMethod::PublicKey {
            private_key_path,
            passphrase,
        } => {
            let key = russh_keys::load_secret_key(private_key_path, passphrase.as_deref())
                .map_err(|e| VoidbError::Connection(format!("Failed to load key: {}", e)))?;
            let ok = session
                .authenticate_publickey(&ssh_config.username, Arc::new(key))
                .await
                .map_err(|e| VoidbError::Connection(format!("Auth error: {}", e)))?;
            if !ok {
                return Err(VoidbError::Connection(
                    "Public key authentication failed".to_string(),
                ));
            }
        }
        SshAuthMethod::Agent => {
            #[cfg(unix)]
            {
                let mut agent = russh_keys::agent::client::AgentClient::connect_env()
                    .await
                    .map_err(|e| VoidbError::Connection(format!("SSH agent not available: {}", e)))?;
                let identities = agent
                    .request_identities()
                    .await
                    .map_err(|e| VoidbError::Connection(format!("Agent list failed: {}", e)))?;
                if identities.is_empty() {
                    return Err(VoidbError::Connection("SSH agent has no keys".to_string()));
                }
                let mut ok = false;
                for key in &identities {
                    if let Ok(true) = session
                        .authenticate_publickey_with(&ssh_config.username, key.clone(), &mut agent)
                        .await
                    {
                        ok = true;
                        break;
                    }
                }
                if !ok {
                    return Err(VoidbError::Connection(
                        "SSH agent authentication failed".to_string(),
                    ));
                }
            }
            #[cfg(not(unix))]
            {
                return Err(VoidbError::Connection(
                    "SSH agent authentication is not supported on Windows yet".to_string(),
                ));
            }
        }
    }

    Ok(session)
}

#[cfg(test)]
mod tests {
    use super::*;
    use voidb_core::{AssistSessionBinding, PluginSessionPurpose};

    fn binding() -> AssistSessionBinding {
        AssistSessionBinding {
            plugin_id: "ssh".to_string(),
            session_id: "ssh-session-1".to_string(),
            generation: 3,
            owner_id: "ssh-tui-owner-1".to_string(),
            purpose: PluginSessionPurpose::InteractiveTerminal,
            profile_ref: None,
        }
    }

    #[test]
    fn session_input_builds_a_current_pty_operation_request() {
        let matches = session_command()
            .try_get_matches_from([
                "session",
                "input",
                "assist:session:test",
                "--command",
                "pwd",
                "--agent-client",
                "agent",
                "--agent-task",
                "task-1",
            ])
            .unwrap();
        let (_, input) = matches.subcommand().unwrap();

        let response =
            session_input_operation_from_matches("assist:session:test", binding(), input).unwrap();

        assert_eq!(response.agent.client_id, "agent");
        assert_eq!(
            response.requested_permissions,
            vec![AssistPermission::TakeControl]
        );
        assert!(matches!(
            &response.actions[0],
            AssistAction::ProposedCommand {
                command,
                risk: AssistActionRisk::Destructive,
                target: AssistActionTarget::CurrentPty { binding },
                ..
            } if command == "pwd" && binding.generation == 3
        ));
    }

    #[test]
    fn session_input_rejects_multiline_commands() {
        let matches = session_command()
            .try_get_matches_from([
                "session",
                "input",
                "assist:session:test",
                "--command",
                "pwd\nwhoami",
            ])
            .unwrap();
        let (_, input) = matches.subcommand().unwrap();

        let error = session_input_operation_from_matches("assist:session:test", binding(), input)
            .unwrap_err();

        assert!(error.to_string().contains("single-line"));
    }

    #[test]
    fn session_help_uses_external_first_operation_vocabulary() {
        let help = session_command().render_long_help().to_string();

        assert!(help.contains("operation"));
        assert!(!help.contains("respond"));
        assert!(!help.contains("response-json"));
        assert!(!help.contains("diagnosis"));
        assert!(!help.contains("question"));
        assert!(!help.contains("assist"));
    }

    #[test]
    fn legacy_respond_alias_builds_a_canonical_operation_request() {
        let matches = session_command()
            .try_get_matches_from([
                "session",
                "respond",
                "assist:session:test",
                "--summary",
                "Review one operation",
            ])
            .unwrap();
        let (name, operation) = matches.subcommand().unwrap();

        assert_eq!(name, "operation");
        let request = operation_request_from_matches("assist:session:test", operation).unwrap();
        let json = serde_json::to_value(request).unwrap();
        assert!(json.get("operations").is_some());
        assert!(json.get("actions").is_none());
    }
}
