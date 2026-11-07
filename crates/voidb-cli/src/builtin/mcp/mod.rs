//! `vb mcp serve` — Model Context Protocol stdio server (MVP).
//!
//! Exposes the installed capability catalog as MCP tools with every safety
//! property intact: tools/call is routed through the agent authorization
//! broker (grant-scoped, destructive-gated, redacted, audited), the server
//! process never holds the master password, and output stays inside the
//! broker's bounded child envelope. See docs/mcp-server.md and
//! docs/adr-mcp-agent-gateway.md.

pub(crate) mod handlers;
pub(crate) mod wire;

#[cfg(test)]
mod tests;

use clap::{Arg, ArgAction, ArgMatches, Command};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use voidb_core::agent_authorization::AgentPrincipal;
use voidb_core::plugin::cli::{CliContext, CliPlugin};
use voidb_core::{VoidbError, discover_process_plugins};

use crate::agent_broker::{AGENT_CLIENT_ID_ENV, AGENT_INSTANCE_ID_ENV, AGENT_TASK_ID_ENV};
use handlers::McpServer;
use wire::MAX_FRAME_BYTES;

pub struct McpCliPlugin;

impl McpCliPlugin {
    pub fn new() -> Self {
        Self
    }
}

impl Default for McpCliPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl CliPlugin for McpCliPlugin {
    fn plugin_id(&self) -> &str {
        "mcp"
    }

    fn name(&self) -> &str {
        "Model Context Protocol Gateway"
    }

    fn commands(&self) -> Vec<Command> {
        vec![
            Command::new("serve")
                .about(
                    "Serve the capability catalog as MCP tools over stdio \
                 (JSON-RPC; tools/call requires an active agent grant)",
                )
                .arg(
                    Arg::new("client-id")
                        .long("client-id")
                        .value_name("CLIENT_ID")
                        .help(
                            "Agent principal client id for grant matching (default: env or none)",
                        ),
                )
                .arg(
                    Arg::new("task-id")
                        .long("task-id")
                        .value_name("TASK_ID")
                        .requires("client-id")
                        .help("Agent principal task id; required together with --client-id"),
                )
                .arg(
                    Arg::new("instance-id")
                        .long("instance-id")
                        .value_name("INSTANCE_ID")
                        .help("Optional agent principal instance id"),
                )
                .arg(
                    Arg::new("quiet")
                        .long("quiet")
                        .action(ArgAction::SetTrue)
                        .help("Suppress the stderr startup banner"),
                ),
        ]
    }

    async fn execute(
        &self,
        command: &str,
        matches: &ArgMatches,
        _ctx: &CliContext,
    ) -> Result<(), VoidbError> {
        match command {
            "serve" => handle_serve(matches).await,
            other => Err(VoidbError::Plugin(format!("Unknown command: {other}"))),
        }
    }
}

async fn handle_serve(matches: &ArgMatches) -> Result<(), VoidbError> {
    let principal = mcp_principal(matches)?;
    let discovery = discover_process_plugins();
    if !matches.get_flag("quiet") {
        // stderr only: stdout carries MCP frames exclusively.
        eprintln!(
            "voidb mcp serve: protocol {} | tools from installed capability catalog | tools/call requires an agent grant",
            wire::MCP_PROTOCOL_VERSION
        );
    }

    let mut server = McpServer::new(principal, discovery);
    let mut reader = BufReader::new(tokio::io::stdin());
    let mut writer = BufWriter::new(tokio::io::stdout());
    let mut buffer = Vec::new();
    loop {
        buffer.clear();
        let read = reader.read_until(b'\n', &mut buffer).await?;
        if read == 0 {
            // stdin closed: graceful shutdown per the MCP stdio transport.
            break;
        }
        let responses = if read > MAX_FRAME_BYTES {
            vec![wire::failure(
                &serde_json::Value::Null,
                wire::PARSE_ERROR,
                "frame exceeds the MCP maximum size",
            )]
        } else {
            server.handle_frame(&buffer[..read]).await
        };
        for response in responses {
            writer.write_all(response.as_bytes()).await?;
            writer.write_all(b"\n").await?;
        }
        writer.flush().await?;
    }
    Ok(())
}

/// Builds the agent principal for grant matching, mirroring `vb agent exec`:
/// explicit flags first, then the agent environment variables, then none (a
/// server without a principal only matches principal-less grants).
fn mcp_principal(matches: &ArgMatches) -> Result<Option<AgentPrincipal>, VoidbError> {
    let explicit_client = matches.get_one::<String>("client-id").cloned();
    let explicit_task = matches.get_one::<String>("task-id").cloned();
    let explicit_instance = matches.get_one::<String>("instance-id").cloned();
    let (client_id, task_id, instance_id) =
        if explicit_client.is_some() || explicit_task.is_some() || explicit_instance.is_some() {
            (explicit_client, explicit_task, explicit_instance)
        } else {
            (
                nonempty_env(AGENT_CLIENT_ID_ENV),
                nonempty_env(AGENT_TASK_ID_ENV),
                nonempty_env(AGENT_INSTANCE_ID_ENV),
            )
        };

    let Some(client_id) = client_id else {
        if task_id.is_some() || instance_id.is_some() {
            return Err(VoidbError::InvalidConfig(
                "--client-id and --task-id must be provided together".into(),
            ));
        }
        return Ok(None);
    };
    let Some(task_id) = task_id else {
        return Err(VoidbError::InvalidConfig(
            "--client-id and --task-id must be provided together".into(),
        ));
    };
    let principal = AgentPrincipal {
        client_id,
        task_id,
        instance_id,
    };
    principal
        .validate()
        .map_err(|error| VoidbError::InvalidConfig(error.to_string()))?;
    Ok(Some(principal))
}

fn nonempty_env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}
