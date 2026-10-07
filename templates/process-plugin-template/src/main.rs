//! Entrypoint for voidb-plugin-{{plugin_name}}.

use anyhow::Result;
use clap::{Parser, Subcommand};
use voidb_core::{CapabilityInvocationResult, InvocationStatus};
use voidb_process_plugin_sdk::{CapabilityRouter, serve_stdio};

#[derive(Parser, Debug)]
#[command(name = "voidb-plugin-{{plugin_name}}")]
#[command(about = "{{plugin_description}}", version)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Run as a stdio-jsonrpc server (default when launched by VoidB)
    Serve,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Serve) | None => run_server(),
    }
}

fn run_server() -> Result<()> {
    let router = CapabilityRouter::new("{{plugin_name}}")
        .capability("ping", |invocation, _grants| {
            let message = invocation
                .input
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("pong");

            Ok(CapabilityInvocationResult {
                invocation_id: invocation.id,
                status: InvocationStatus::Succeeded,
                output: serde_json::json!({ "reply": message, "ok": true }),
                output_summary: serde_json::json!({ "reply": message }),
                page: None,
            })
        });

    serve_stdio(router)?;
    Ok(())
}
