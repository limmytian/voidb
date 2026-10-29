//! Built-in generic capability invocation CLI.
//!
//! This command is the first agent-facing path that invokes capability handlers
//! by `<plugin>.<capability>` instead of through plugin-specific CLI commands.

use async_trait::async_trait;
use clap::{Arg, ArgAction, ArgMatches, Command};
use voidb_core::VoidbError;
use voidb_core::plugin::cli::{CliContext, CliPlugin};

use command_tree::{capability_arg, execution_mode_arg, format_arg, run_format_arg};
use handlers::{handle_describe, handle_list, handle_matrix, handle_run};

mod audit;
mod command_tree;
mod discovery;
mod execution;
mod handlers;
mod output;
mod profiles;

#[cfg(all(test, feature = "full"))]
mod tests;

#[cfg(feature = "full")]
pub(crate) use discovery::builtin_capabilities;
pub(crate) use discovery::{resolved_authorization_capabilities, resolved_capability_risk};
pub(crate) use execution::session_handoff_guidance;
pub(crate) use output::session_purpose_cli_name;

const SUPPORTED_INVOKE_PLUGINS: &[&str] = &[
    #[cfg(feature = "sync")]
    "sync",
];
const INVOKE_CLI_SCHEMA_VERSION: u32 = 1;
const INVOCATION_STREAM_CHANNEL_CAPACITY: usize = 32;
const INVOCATION_CANCEL_GRACE_MS: u64 = 2_000;
const MAX_PUBLIC_CONTROL_ID_BYTES: usize = 128;

pub struct InvokeCliPlugin;

impl InvokeCliPlugin {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl CliPlugin for InvokeCliPlugin {
    fn plugin_id(&self) -> &str {
        "invoke"
    }

    fn name(&self) -> &str {
        "Generic Capability Invocation"
    }

    fn commands(&self) -> Vec<Command> {
        vec![
            Command::new("list")
                .about("List generic capability metadata")
                .arg(format_arg())
                .arg(execution_mode_arg())
                .arg(
                    Arg::new("plugin")
                        .value_name("PLUGIN_ID")
                        .help("Only list capabilities for one plugin"),
                ),
            Command::new("describe")
                .about("Describe one generic capability as JSON")
                .arg(capability_arg())
                .arg(format_arg()),
            Command::new("matrix")
                .about("Generate the canonical built-in Agent capability and experience matrix")
                .arg(
                    Arg::new("format")
                        .long("format")
                        .value_name("FORMAT")
                        .value_parser(["json", "markdown"])
                        .default_value("markdown")
                        .help("Output stable JSON or the canonical generated Markdown document"),
                ),
            Command::new("run")
                .about("Invoke one generic capability as JSON")
                .arg(capability_arg())
                .arg(
                    Arg::new("profile")
                        .long("profile")
                        .short('p')
                        .required(true)
                        .value_name("PROFILE_REF")
                        .help("Profile ref: <name>, id:<profile-id>, or name:<name>"),
                )
                .arg(
                    Arg::new("input-json")
                        .long("input-json")
                        .value_name("JSON")
                        .conflicts_with("input-file")
                        .help("Inline JSON object for capability input"),
                )
                .arg(
                    Arg::new("input-file")
                        .long("input-file")
                        .value_name("PATH")
                        .help("Path to a JSON input file"),
                )
                .arg(
                    Arg::new("timeout-ms")
                        .long("timeout-ms")
                        .value_name("MILLISECONDS")
                        .conflicts_with("timeout")
                        .help("Execution timeout in milliseconds (legacy-compatible)"),
                )
                .arg(
                    Arg::new("timeout")
                        .long("timeout")
                        .value_name("DURATION")
                        .conflicts_with("timeout-ms")
                        .help("Execution timeout such as 250ms, 10s, 2m, or 1h"),
                )
                .arg(
                    Arg::new("dry-run")
                        .long("dry-run")
                        .action(ArgAction::SetTrue)
                        .help("Request dry-run behavior when the capability supports it"),
                )
                .arg(
                    Arg::new("yes")
                        .long("yes")
                        .action(ArgAction::SetTrue)
                        .help("Explicitly acknowledge a destructive invocation"),
                )
                .arg(
                    Arg::new("page-limit")
                        .long("page-limit")
                        .value_name("LIMIT")
                        .value_parser(clap::value_parser!(u32))
                        .help("Optional result page limit for paginated capabilities"),
                )
                .arg(
                    Arg::new("page-cursor")
                        .long("page-cursor")
                        .value_name("CURSOR")
                        .help("Optional result page cursor for paginated capabilities"),
                )
                .arg(
                    Arg::new("call-id")
                        .long("call-id")
                        .value_name("ID")
                        .help("Caller-owned public invocation ID; generated when omitted"),
                )
                .arg(
                    Arg::new("cancellation-token")
                        .long("cancellation-token")
                        .value_name("TOKEN")
                        .help("Opaque caller-owned cancellation token; never emitted or audited"),
                )
                .arg(
                    Arg::new("max-output-bytes")
                        .long("max-output-bytes")
                        .value_name("BYTES")
                        .value_parser(clap::value_parser!(u64))
                        .help("Maximum serialized invocation result size"),
                )
                .arg(run_format_arg()),
        ]
    }

    async fn execute(
        &self,
        command: &str,
        matches: &ArgMatches,
        ctx: &CliContext,
    ) -> Result<(), VoidbError> {
        match command {
            "list" => handle_list(matches),
            "describe" => handle_describe(matches),
            "matrix" => handle_matrix(matches),
            "run" => handle_run(matches, ctx).await,
            _ => Err(VoidbError::Plugin(format!("Unknown command: {}", command))),
        }
    }
}
