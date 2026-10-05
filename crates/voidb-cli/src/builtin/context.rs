//! Generic, password-free external context discovery CLI.

use std::time::Duration;

use async_trait::async_trait;
use clap::{Arg, ArgMatches, Command};
use serde::Serialize;
use voidb_core::plugin::cli::{CliContext, CliPlugin};
use voidb_core::{
    AGENT_CONTEXT_CLIENT_ID_ENV, AGENT_CONTEXT_INSTANCE_ID_ENV, AGENT_CONTEXT_TASK_ID_ENV,
    AgentContextCommand, AgentContextEnvelope, AgentContextErrorCode, AgentContextListData,
    AgentContextOperationInput, AgentContextProtocolError, AgentContextRef,
    AgentContextStoreCatalog, AgentContextStoreSource, AgentOperation, AgentPrincipal,
    DEFAULT_AGENT_CONTEXT_WAIT_POLL_MS, MAX_AGENT_CONTEXT_OPERATION_INPUT_BYTES,
    MAX_AGENT_CONTEXT_WAIT_MS, VoidbError,
};

pub struct ContextCliPlugin;

impl ContextCliPlugin {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl CliPlugin for ContextCliPlugin {
    fn plugin_id(&self) -> &str {
        "context"
    }

    fn name(&self) -> &str {
        "External Context Handoff"
    }

    fn commands(&self) -> Vec<Command> {
        vec![
            Command::new("list")
                .about("List bounded external-agent context shares as JSON")
                .arg(principal_client_arg())
                .arg(principal_task_arg())
                .arg(principal_instance_arg())
                .arg(
                    Arg::new("plugin")
                        .long("plugin")
                        .value_name("PLUGIN_ID")
                        .value_parser(["ssh", "docker", "kubernetes", "jenkins"])
                        .help("Only discover contexts owned by one supported plugin"),
                ),
            context_reference_command(
                Command::new("show").about("Inspect one bounded context share as JSON"),
            ),
            context_reference_command(
                Command::new("operation")
                    .about("Submit one structured operation for local review as JSON")
                    .arg(
                        Arg::new("operation-request-id")
                            .long("operation-request-id")
                            .required(true)
                            .value_name("OPERATION_REQUEST_ID")
                            .help("Caller-unique idempotency key for this operation request"),
                    )
                    .arg(
                        Arg::new("summary")
                            .long("summary")
                            .required(true)
                            .value_name("SUMMARY")
                            .help("Bounded human-readable review summary"),
                    )
                    .arg(
                        Arg::new("note")
                            .long("note")
                            .value_name("NOTE")
                            .help("Optional bounded diagnostic note"),
                    )
                    .arg(
                        Arg::new("operations-json")
                            .long("operations-json")
                            .required(true)
                            .value_name("JSON_ARRAY")
                            .help("JSON array containing exactly one structured operation"),
                    ),
            ),
            context_reference_command(
                Command::new("deny")
                    .about("Withdraw one pending operation index as JSON")
                    .arg(
                        Arg::new("operation-request-id")
                            .long("operation-request-id")
                            .required(true)
                            .value_name("OPERATION_REQUEST_ID"),
                    )
                    .arg(
                        Arg::new("operation-index")
                            .long("operation-index")
                            .required(true)
                            .value_name("INDEX")
                            .value_parser(clap::value_parser!(usize)),
                    )
                    .arg(
                        Arg::new("reason")
                            .long("reason")
                            .required(true)
                            .value_name("REASON")
                            .help("Bounded reason for withdrawing the operation"),
                    ),
            ),
            context_reference_command(
                Command::new("status").about("Inspect indexed operation review status as JSON"),
            ),
            context_reference_command(
                Command::new("wait")
                    .about("Wait boundedly for operation review completion as JSON")
                    .arg(
                        Arg::new("timeout-ms")
                            .long("timeout-ms")
                            .value_name("MILLISECONDS")
                            .default_value("30000")
                            .value_parser(
                                clap::value_parser!(u64).range(1..=MAX_AGENT_CONTEXT_WAIT_MS),
                            ),
                    )
                    .arg(
                        Arg::new("poll-interval-ms")
                            .long("poll-interval-ms")
                            .value_name("MILLISECONDS")
                            .default_value("100")
                            .value_parser(clap::value_parser!(u64).range(1..=1000)),
                    ),
            ),
        ]
    }

    async fn execute(
        &self,
        command: &str,
        matches: &ArgMatches,
        _ctx: &CliContext,
    ) -> Result<(), VoidbError> {
        let command = match command {
            "list" => AgentContextCommand::List,
            "show" => AgentContextCommand::Show,
            "operation" => AgentContextCommand::Operation,
            "deny" => AgentContextCommand::Deny,
            "status" => AgentContextCommand::Status,
            "wait" => AgentContextCommand::Wait,
            other => {
                return Err(VoidbError::Plugin(format!(
                    "Unknown context command: {other}"
                )));
            }
        };
        let principal = match principal_from_matches(matches) {
            Ok(principal) => principal,
            Err(error) => return print_protocol_error(command, error),
        };
        let catalog = match default_catalog() {
            Ok(catalog) => catalog,
            Err(error) => return print_protocol_error(command, error),
        };

        match command {
            AgentContextCommand::List => {
                let plugin = matches.get_one::<String>("plugin").map(String::as_str);
                match catalog.list(&principal, plugin) {
                    Ok(data) => print_json(&AgentContextEnvelope::success(command, data)),
                    Err(error) => print_protocol_error(command, error),
                }
            }
            AgentContextCommand::Show => {
                let reference = match reference_from_matches(matches) {
                    Ok(reference) => reference,
                    Err(error) => return print_protocol_error(command, error),
                };
                match catalog.show(&principal, &reference) {
                    Ok(data) => print_json(&AgentContextEnvelope::success(command, data)),
                    Err(error) => print_protocol_error(command, error),
                }
            }
            AgentContextCommand::Operation => {
                let reference = match reference_from_matches(matches) {
                    Ok(reference) => reference,
                    Err(error) => return print_protocol_error(command, error),
                };
                let operations_json = matches
                    .get_one::<String>("operations-json")
                    .expect("required by clap");
                if operations_json.len() > MAX_AGENT_CONTEXT_OPERATION_INPUT_BYTES {
                    return print_protocol_error(
                        command,
                        AgentContextProtocolError::invalid_request(format!(
                            "operations JSON exceeds {MAX_AGENT_CONTEXT_OPERATION_INPUT_BYTES} bytes"
                        )),
                    );
                }
                let operations = match serde_json::from_str::<Vec<AgentOperation>>(operations_json)
                {
                    Ok(operations) => operations,
                    Err(_) => {
                        return print_protocol_error(
                            command,
                            AgentContextProtocolError::invalid_request(
                                "--operations-json must be a valid structured operation array",
                            ),
                        );
                    }
                };
                let input = AgentContextOperationInput {
                    operation_request_id: matches
                        .get_one::<String>("operation-request-id")
                        .expect("required by clap")
                        .clone(),
                    summary: matches
                        .get_one::<String>("summary")
                        .expect("required by clap")
                        .clone(),
                    note: matches.get_one::<String>("note").cloned(),
                    operations,
                };
                match catalog.operation(&principal, &reference, input) {
                    Ok(data) => print_json(&AgentContextEnvelope::success(command, data)),
                    Err(error) => print_protocol_error(command, error),
                }
            }
            AgentContextCommand::Deny => {
                let reference = match reference_from_matches(matches) {
                    Ok(reference) => reference,
                    Err(error) => return print_protocol_error(command, error),
                };
                let operation_request_id = matches
                    .get_one::<String>("operation-request-id")
                    .expect("required by clap");
                let operation_index = *matches
                    .get_one::<usize>("operation-index")
                    .expect("required by clap");
                let reason = matches
                    .get_one::<String>("reason")
                    .expect("required by clap");
                match catalog.deny(
                    &principal,
                    &reference,
                    operation_request_id,
                    operation_index,
                    reason,
                ) {
                    Ok(data) => print_json(&AgentContextEnvelope::success(command, data)),
                    Err(error) => print_protocol_error(command, error),
                }
            }
            AgentContextCommand::Status => {
                let reference = match reference_from_matches(matches) {
                    Ok(reference) => reference,
                    Err(error) => return print_protocol_error(command, error),
                };
                match catalog.status(&principal, &reference) {
                    Ok(data) => print_json(&AgentContextEnvelope::success(command, data)),
                    Err(error) => print_protocol_error(command, error),
                }
            }
            AgentContextCommand::Wait => {
                let reference = match reference_from_matches(matches) {
                    Ok(reference) => reference,
                    Err(error) => return print_protocol_error(command, error),
                };
                let timeout = Duration::from_millis(
                    *matches
                        .get_one::<u64>("timeout-ms")
                        .expect("defaulted by clap"),
                );
                let interval = Duration::from_millis(
                    *matches
                        .get_one::<u64>("poll-interval-ms")
                        .unwrap_or(&DEFAULT_AGENT_CONTEXT_WAIT_POLL_MS),
                );
                match catalog.wait(&principal, &reference, timeout, interval) {
                    Ok(data) => print_json(&AgentContextEnvelope::success(command, data)),
                    Err(error) => print_protocol_error(command, error),
                }
            }
        }
    }
}

fn context_reference_command(command: Command) -> Command {
    command
        .arg(principal_client_arg())
        .arg(principal_task_arg())
        .arg(principal_instance_arg())
        .arg(
            Arg::new("plugin")
                .long("plugin")
                .required(true)
                .value_name("PLUGIN_ID")
                .value_parser(["ssh", "docker", "kubernetes", "jenkins"])
                .help("Owning plugin ID"),
        )
        .arg(
            Arg::new("generation")
                .long("generation")
                .required(true)
                .value_name("GENERATION")
                .value_parser(clap::value_parser!(u64))
                .help("Exact owner-session generation from context list"),
        )
        .arg(
            Arg::new("context-id")
                .required(true)
                .value_name("CONTEXT_ID")
                .help("Opaque context ID from context list"),
        )
}

fn reference_from_matches(
    matches: &ArgMatches,
) -> Result<AgentContextRef, AgentContextProtocolError> {
    AgentContextRef::new(
        matches
            .get_one::<String>("plugin")
            .expect("required by clap"),
        matches
            .get_one::<String>("context-id")
            .expect("required by clap"),
        *matches
            .get_one::<u64>("generation")
            .expect("required by clap"),
    )
}

fn principal_client_arg() -> Arg {
    Arg::new("client-id")
        .long("client-id")
        .value_name("CLIENT_ID")
        .help(format!(
            "External client ID; falls back to {AGENT_CONTEXT_CLIENT_ID_ENV}"
        ))
}

fn principal_task_arg() -> Arg {
    Arg::new("task-id")
        .long("task-id")
        .value_name("TASK_ID")
        .help(format!(
            "External task ID; falls back to {AGENT_CONTEXT_TASK_ID_ENV}"
        ))
}

fn principal_instance_arg() -> Arg {
    Arg::new("instance-id")
        .long("instance-id")
        .value_name("INSTANCE_ID")
        .help(format!(
            "Optional process instance ID; falls back to {AGENT_CONTEXT_INSTANCE_ID_ENV}"
        ))
}

fn principal_from_matches(
    matches: &ArgMatches,
) -> Result<AgentPrincipal, AgentContextProtocolError> {
    let client_id = principal_component(matches, "client-id", AGENT_CONTEXT_CLIENT_ID_ENV, true)?
        .expect("required component");
    let task_id = principal_component(matches, "task-id", AGENT_CONTEXT_TASK_ID_ENV, true)?
        .expect("required component");
    let instance_id =
        principal_component(matches, "instance-id", AGENT_CONTEXT_INSTANCE_ID_ENV, false)?;
    let principal = AgentPrincipal {
        client_id,
        task_id,
        instance_id,
    };
    principal.validate().map_err(|_| {
        AgentContextProtocolError::invalid_request(
            "external principal components must contain 1 to 255 characters",
        )
    })?;
    Ok(principal)
}

fn principal_component(
    matches: &ArgMatches,
    argument: &str,
    environment: &str,
    required: bool,
) -> Result<Option<String>, AgentContextProtocolError> {
    if let Some(value) = matches.get_one::<String>(argument) {
        return Ok(Some(value.clone()));
    }
    match std::env::var(environment) {
        Ok(value) if !value.is_empty() => Ok(Some(value)),
        Ok(_) => Err(AgentContextProtocolError::invalid_request(format!(
            "{environment} is set but empty"
        ))),
        Err(std::env::VarError::NotPresent) if !required => Ok(None),
        Err(std::env::VarError::NotPresent) => Err(AgentContextProtocolError::invalid_request(
            format!("--{argument} or {environment} is required"),
        )),
        Err(_) => Err(AgentContextProtocolError::invalid_request(format!(
            "cannot read {environment}"
        ))),
    }
}

fn default_catalog() -> Result<AgentContextStoreCatalog, AgentContextProtocolError> {
    let mut roots = Vec::new();
    #[cfg(feature = "ssh")]
    roots.push(("ssh", voidb_plugin_ssh::ssh_agent_context_store_root()));
    #[cfg(feature = "docker")]
    roots.push((
        "docker",
        voidb_plugin_docker::docker_agent_context_store_root(),
    ));
    #[cfg(feature = "kubernetes")]
    roots.push((
        "kubernetes",
        voidb_plugin_kubernetes::kubernetes_agent_context_store_root(),
    ));
    #[cfg(feature = "jenkins")]
    roots.push((
        "jenkins",
        voidb_plugin_jenkins::jenkins_agent_context_store_root(),
    ));

    let mut sources = Vec::with_capacity(roots.len());
    for (plugin_id, root) in roots {
        let root = root.map_err(|_| {
            AgentContextProtocolError::new(
                AgentContextErrorCode::StoreUnavailable,
                "cannot resolve the local context-store root",
            )
        })?;
        sources.push(AgentContextStoreSource::new(plugin_id, root));
    }
    Ok(AgentContextStoreCatalog::new(sources))
}

fn print_protocol_error(
    command: AgentContextCommand,
    error: AgentContextProtocolError,
) -> Result<(), VoidbError> {
    let code = error.exit_code;
    print_json(&AgentContextEnvelope::<AgentContextListData>::failure(
        command, error,
    ))?;
    Err(VoidbError::CliExit { code })
}

fn print_json(value: &impl Serialize) -> Result<(), VoidbError> {
    let output = serde_json::to_string_pretty(value).map_err(|error| {
        VoidbError::Plugin(format!("Failed to serialize context output: {error}"))
    })?;
    println!("{output}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matches(args: &[&str]) -> ArgMatches {
        let plugin = ContextCliPlugin::new();
        let mut root = Command::new("context");
        for command in plugin.commands() {
            root = root.subcommand(command);
        }
        let parsed = root.try_get_matches_from(args).unwrap();
        parsed.subcommand().unwrap().1.clone()
    }

    #[test]
    fn explicit_principal_is_non_interactive_and_stable() {
        let matches = matches(&[
            "context",
            "list",
            "--client-id",
            "agent-cli",
            "--task-id",
            "task-1",
            "--instance-id",
            "process-1",
        ]);
        let principal = principal_from_matches(&matches).unwrap();
        assert_eq!(principal.client_id, "agent-cli");
        assert_eq!(principal.task_id, "task-1");
        assert_eq!(principal.instance_id.as_deref(), Some("process-1"));
    }

    #[test]
    fn show_requires_plugin_generation_and_opaque_id() {
        let plugin = ContextCliPlugin::new();
        let show = plugin
            .commands()
            .into_iter()
            .find(|command| command.get_name() == "show")
            .unwrap();
        let parsed = show
            .try_get_matches_from([
                "show",
                "--client-id",
                "agent-cli",
                "--task-id",
                "task-1",
                "--plugin",
                "docker",
                "--generation",
                "4",
                "context:docker:1:1",
            ])
            .unwrap();
        let reference = AgentContextRef::new(
            parsed.get_one::<String>("plugin").unwrap(),
            parsed.get_one::<String>("context-id").unwrap(),
            *parsed.get_one::<u64>("generation").unwrap(),
        )
        .unwrap();
        assert_eq!(reference.plugin_id, "docker");
        assert_eq!(reference.generation, 4);
    }

    #[test]
    fn operation_and_wait_commands_are_non_interactive_and_exactly_bound() {
        let operation = matches(&[
            "context",
            "operation",
            "--client-id",
            "agent-cli",
            "--task-id",
            "task-1",
            "--plugin",
            "docker",
            "--generation",
            "4",
            "--operation-request-id",
            "operation:docker:1",
            "--summary",
            "Review stop",
            "--operations-json",
            r#"[{"kind":"capability_call","capability_id":"docker.container_action","input_summary":{"action":"stop"},"rationale":"review","risk":"destructive","target":{"kind":"capability","capability_id":"docker.container_action"}}]"#,
            "context:docker:1:1",
        ]);
        assert_eq!(
            reference_from_matches(&operation).unwrap(),
            AgentContextRef::new("docker", "context:docker:1:1", 4).unwrap()
        );
        let operations = serde_json::from_str::<Vec<AgentOperation>>(
            operation
                .get_one::<String>("operations-json")
                .expect("required operation JSON"),
        )
        .unwrap();
        assert_eq!(operations.len(), 1);

        let wait = matches(&[
            "context",
            "wait",
            "--client-id",
            "agent-cli",
            "--task-id",
            "task-1",
            "--plugin",
            "jenkins",
            "--generation",
            "2",
            "--timeout-ms",
            "250",
            "context:jenkins:1:1",
        ]);
        assert_eq!(*wait.get_one::<u64>("timeout-ms").unwrap(), 250);
        assert_eq!(
            *wait.get_one::<u64>("poll-interval-ms").unwrap(),
            DEFAULT_AGENT_CONTEXT_WAIT_POLL_MS
        );
    }
}
