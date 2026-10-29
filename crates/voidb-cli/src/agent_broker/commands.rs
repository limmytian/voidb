#![cfg_attr(not(unix), allow(unused_imports))]

use crate::builtin::invoke::{
    resolved_authorization_capabilities, resolved_capability_risk, session_handoff_guidance,
};
use crate::jit_authorization::{CreateAuthorizationRequest, JitAuthorizationStore};
use anyhow::{Context, anyhow, bail};
use chrono::{DateTime, Utc};
use clap::{Arg, ArgAction, ArgMatches, Command, error::ErrorKind};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{IsTerminal, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use uuid::Uuid;
use voidb_core::{
    AgentAuthorizationCapability, AgentAuthorizationPluginCatalog,
    AgentAuthorizationPresetDefinition, AgentAuthorizationPresetKind,
    AgentAuthorizationProfileSummary, AgentAuthorizationScope, AgentAuthorizationSupportStatus,
    AgentAuthorizationSupportSummary, AgentBrokerHealth, AgentPrincipal, AppConfig, AuditOperation,
    CapabilityDefinition, CapabilityExecutionMode, ConnectionProfile,
    DEFAULT_AGENT_GRANT_TTL_MINUTES, DEFAULT_AGENT_GRANT_USES, FrontendAgentGrant,
    LocalProfileStore, MAX_AGENT_GRANT_TTL_MINUTES, MAX_AGENT_GRANT_USES, PluginSessionPurpose,
    VOIDB_MASTER_PASSWORD_ENV, normalize_agent_operation, profile_names_equal,
};

use super::audit::append_agent_audit;
use super::jit::{
    JIT_EXIT_BROKER_OFFLINE, JIT_EXIT_CANCELLED, JIT_EXIT_DENIED, JIT_EXIT_EXPIRED,
    JIT_EXIT_INVALID, JIT_EXIT_PENDING, JIT_EXIT_SUPERSEDED, jit_request_command, print_jit_error,
    print_jit_store_error, prompt_tty_line, run_jit_request_command, sanitize_terminal_text,
    validate_declared_jit_scope, with_hidden_optional_principal_args, with_optional_principal_args,
};
use super::ledger::{
    AgentGrantFile, BatchAuthorizationSpec, GrantInspection, MAX_BATCH_AUTHORIZATION_GRANTS,
    MAX_BATCH_AUTHORIZATION_SPEC_BYTES, PreparedBatchGrant,
};
use super::runtime::{
    ensure_unix, grant_directory, grant_path_for_id, load_grants, read_grant,
    remove_grant_artifacts, run_broker, send_request, shutdown_grant, wait_for_socket, write_grant,
    write_password_and_close,
};
use super::session::{
    command_allowed, ensure_grant_principal, run_session_command, session_command,
};
use super::wire::BrokerRequest;
use super::{
    AGENT_CLIENT_ID_ENV, AGENT_INSTANCE_ID_ENV, AGENT_TASK_ID_ENV, AGENT_THREAD_ID_ENV,
    BROKER_CHILD_ENV, BROKER_PROBE_TIMEOUT, GRANT_VERSION,
};

pub async fn handle_early(args: Vec<String>) -> anyhow::Result<Option<i32>> {
    let Some(command) = args.get(1).map(String::as_str) else {
        return Ok(None);
    };
    if command == "__agent-broker" {
        let grant_file = args
            .get(2)
            .ok_or_else(|| anyhow!("internal broker grant file is required"))?;
        run_broker(Path::new(grant_file)).await?;
        return Ok(Some(0));
    }
    if command != "agent" {
        return Ok(None);
    }

    let matches = match agent_command().try_get_matches_from(args) {
        Ok(matches) => matches,
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) =>
        {
            error.print()?;
            return Ok(Some(0));
        }
        Err(error) => return Err(error.into()),
    };
    let (_, matches) = matches
        .subcommand()
        .expect("agent command requires a subcommand");
    let exit_code = match matches.subcommand() {
        Some(("authorize", sub_matches)) => authorize(sub_matches).await?,
        Some(("authorize-batch", sub_matches)) => authorize_batch(sub_matches).await?,
        Some(("catalog", sub_matches)) => list_authorization_catalog(sub_matches)?,
        Some(("list", sub_matches)) => list_grants(sub_matches).await?,
        Some(("renew", sub_matches)) => renew_grant(sub_matches).await?,
        Some(("revoke", sub_matches)) => revoke(sub_matches).await?,
        Some(("exec", sub_matches)) => exec_capability(sub_matches).await?,
        Some(("run", sub_matches)) => run_granted(sub_matches).await?,
        Some(("session", sub_matches)) => run_session_command(sub_matches).await?,
        Some(("request", sub_matches)) => run_jit_request_command(sub_matches).await?,
        _ => unreachable!("clap enforces agent subcommands"),
    };
    Ok(Some(exit_code))
}

pub async fn take_broker_child_password() -> anyhow::Result<Option<String>> {
    if std::env::var(BROKER_CHILD_ENV).as_deref() != Ok("1") {
        return Ok(None);
    }
    let mut password = String::new();
    tokio::io::stdin().read_to_string(&mut password).await?;
    if password.is_empty() {
        bail!("broker child did not receive a master password");
    }
    Ok(Some(password))
}

pub(super) fn agent_command() -> Command {
    Command::new("voidb-cli")
        .subcommand_required(true)
        .subcommand(
            Command::new("agent")
                .about("Manage short-lived, scoped agent access")
                .subcommand_required(true)
                .subcommand(with_hidden_optional_principal_args(
                    Command::new("exec")
                        .about("Run one capability through matching access or request exact approval")
                        .arg(
                            Arg::new("capability")
                                .required(true)
                                .value_name("PLUGIN.CAPABILITY")
                                .help("Qualified capability, for example docker.list_containers"),
                        )
                        .arg(
                            Arg::new("profile")
                                .long("profile")
                                .short('p')
                                .required(true)
                                .value_name("PROFILE")
                                .help("Friendly profile name, name:<name>, or id:<profile-id>"),
                        )
                        .arg(
                            Arg::new("input-json")
                                .long("input-json")
                                .default_value("{}")
                                .value_name("JSON")
                                .help("Inline capability input JSON"),
                        )
                        .arg(
                            Arg::new("purpose")
                                .long("purpose")
                                .visible_alias("reason")
                                .value_name("TEXT")
                                .help(
                                    "Specific intended use shown to the user if authorization is required",
                                ),
                        )
                        .arg(
                            Arg::new("wait-timeout-ms")
                                .long("wait-timeout-ms")
                                .default_value("30000")
                                .value_name("MILLISECONDS")
                                .value_parser(clap::value_parser!(u64))
                                .help("How long to wait for an automatic JIT decision"),
                        )
                        .arg(
                            Arg::new("request-ttl-seconds")
                                .long("request-ttl-seconds")
                                .default_value("300")
                                .value_name("SECONDS")
                                .value_parser(clap::value_parser!(u64))
                                .help("Lifetime of an automatic JIT request"),
                        )
                        .arg(
                            Arg::new("timeout-ms")
                                .long("timeout-ms")
                                .value_name("MILLISECONDS")
                                .value_parser(clap::value_parser!(u64)),
                        )
                        .arg(
                            Arg::new("page-limit")
                                .long("page-limit")
                                .value_name("LIMIT")
                                .value_parser(clap::value_parser!(u32)),
                        )
                        .arg(
                            Arg::new("page-cursor")
                                .long("page-cursor")
                                .value_name("CURSOR"),
                        )
                        .arg(
                            Arg::new("dry-run")
                                .long("dry-run")
                                .action(ArgAction::SetTrue),
                        )
                        .arg(
                            Arg::new("yes")
                                .long("yes")
                                .action(ArgAction::SetTrue),
                        )
                        .arg(
                            Arg::new("no-request")
                                .long("no-request")
                                .action(ArgAction::SetTrue)
                                .help("Fail with authorization_required instead of creating a JIT request"),
                        ),
                ))
                .subcommand(
                    Command::new("authorize")
                        .about("Authorize time-bounded agent access to one profile")
                        .arg(Arg::new("profile").long("profile").required(true))
                        .arg(Arg::new("plugin").long("plugin").required(true))
                        .arg(
                            Arg::new("execution-mode")
                                .long("execution-mode")
                                .default_value("stateless")
                                .value_parser(["stateless", "session_only", "both"])
                                .help("Grant one-shot, persistent-session, or explicitly combined transport access"),
                        )
                        .arg(
                            Arg::new("preset")
                                .long("preset")
                                .value_parser([
                                    "read_only",
                                    "interactive_execute",
                                    "full_access",
                                    "custom",
                                ])
                                .help("Resolve and record a shared preset; explicit capabilities without this flag infer Custom"),
                        )
                        .arg(
                            Arg::new("capability")
                                .long("capability")
                                .action(ArgAction::Append)
                                .help("Exact qualified capability; without --preset explicit values infer Custom"),
                        )
                        .arg(
                            Arg::new("ttl-minutes")
                                .long("ttl-minutes")
                                .default_value("15")
                                .value_parser(clap::value_parser!(u64)),
                        )
                        .arg(
                            Arg::new("uses")
                                .long("uses")
                                .value_parser(clap::value_parser!(u32))
                                .help("Optional accepted-command limit; omit for time-only access"),
                        )
                        .arg(
                            Arg::new("allow-destructive")
                                .long("allow-destructive")
                                .action(ArgAction::SetTrue)
                                .requires("yes"),
                        )
                        .arg(
                            Arg::new("yes")
                                .long("yes")
                                .action(ArgAction::SetTrue)
                                .help("Confirm an authorization that permits --yes operations"),
                        )
                        .arg(
                            Arg::new("password-stdin")
                                .long("password-stdin")
                                .action(ArgAction::SetTrue)
                                .hide(true),
                        )
                        .arg(
                            Arg::new("replace")
                                .long("replace")
                                .action(ArgAction::SetTrue)
                                .help("Replace existing grants for the same immutable profile and plugin"),
                        ),
                )
                .subcommand(
                    Command::new("authorize-batch")
                        .about("Review and authorize multiple profile-scoped grants at once")
                        .arg(
                            Arg::new("spec")
                                .long("spec")
                                .required(true)
                                .value_name("PATH")
                                .help("Local JSON file containing a grants array"),
                        )
                        .arg(
                            Arg::new("ttl-minutes")
                                .long("ttl-minutes")
                                .default_value("15")
                                .value_parser(clap::value_parser!(u64)),
                        )
                        .arg(
                            Arg::new("uses")
                                .long("uses")
                                .value_parser(clap::value_parser!(u32))
                                .help("Optional accepted-command limit per grant; omit for time-only access"),
                        )
                        .arg(
                            Arg::new("allow-destructive")
                                .long("allow-destructive")
                                .action(ArgAction::SetTrue)
                                .help("Permit reviewed grants containing non-read-only capabilities"),
                        )
                        .arg(
                            Arg::new("yes")
                                .long("yes")
                                .action(ArgAction::SetTrue)
                                .help("Accept the rendered batch review non-interactively"),
                        )
                        .arg(
                            Arg::new("replace")
                                .long("replace")
                                .action(ArgAction::SetTrue)
                                .help("Replace existing grants for matching immutable profile scopes"),
                        ),
                )
                .subcommand(
                    Command::new("catalog")
                        .about("List the password-free central authorization capability catalog")
                        .arg(Arg::new("plugin").long("plugin"))
                        .arg(
                            Arg::new("execution-mode")
                                .long("execution-mode")
                                .value_parser(["stateless", "session_only", "both"])
                                .action(ArgAction::Append)
                                .help("Filter capabilities by supported execution mode and presets by grant mode; repeat to select multiple modes"),
                        )
                        .arg(
                            Arg::new("format")
                                .long("format")
                                .default_value("json")
                                .value_parser(["json", "table"])
                                .help("Output format; json is stable for agents, table is human-readable"),
                        ),
                )
                .subcommand(jit_request_command())
                .subcommand(
                    Command::new("list")
                        .about("List frontend-safe agent grant and broker summaries")
                        .arg(Arg::new("profile").long("profile"))
                        .arg(Arg::new("plugin").long("plugin")),
                )
                .subcommand(
                    Command::new("renew")
                        .about("Renew one grant without changing its profile, plugin, or capability scope")
                        .arg(Arg::new("grant").value_name("GRANT_ID").required(true))
                        .arg(
                            Arg::new("ttl-minutes")
                                .long("ttl-minutes")
                                .default_value("15")
                                .value_parser(clap::value_parser!(u64)),
                        )
                        .arg(
                            Arg::new("uses")
                                .long("uses")
                                .value_parser(clap::value_parser!(u32))
                                .help("Optional renewed use limit; omit for time-only access"),
                        ),
                )
                .subcommand(
                    Command::new("revoke")
                        .about("Revoke one grant, one immutable profile scope, or all grants")
                        .arg(Arg::new("grant").value_name("GRANT_ID"))
                        .arg(
                            Arg::new("profile")
                                .long("profile")
                                .requires("plugin")
                                .conflicts_with_all(["grant", "all"]),
                        )
                        .arg(
                            Arg::new("plugin")
                                .long("plugin")
                                .requires("profile")
                                .conflicts_with_all(["grant", "all"]),
                        )
                        .arg(
                            Arg::new("all")
                                .long("all")
                                .action(ArgAction::SetTrue)
                                .conflicts_with_all(["grant", "profile", "plugin"]),
                        ),
                )
                .subcommand(with_optional_principal_args(
                    Command::new("run")
                        .about("Run a scoped VoidB command through an active grant")
                        .arg(Arg::new("grant").long("grant"))
                        .arg(
                            Arg::new("command")
                                .required(true)
                                .trailing_var_arg(true)
                                .num_args(1..),
                        ),
                ))
                .subcommand(with_optional_principal_args(session_command())),
        )
}

pub(super) async fn spawn_agent_broker(
    grant_path: &Path,
    grant: &AgentGrantFile,
    password: &str,
) -> anyhow::Result<()> {
    let mut command = tokio::process::Command::new(std::env::current_exe()?);
    command
        .arg("__agent-broker")
        .arg(grant_path)
        .env_remove(VOIDB_MASTER_PASSWORD_ENV)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(false);
    #[cfg(unix)]
    command.process_group(0);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            remove_grant_artifacts(grant)?;
            return Err(error).context("start agent broker");
        }
    };
    let Some(stdin) = child.stdin.take() else {
        let _ = child.kill().await;
        let _ = child.wait().await;
        remove_grant_artifacts(grant)?;
        bail!("open broker password pipe");
    };
    if let Err(error) = write_password_and_close(stdin, password.as_bytes()).await {
        let _ = child.kill().await;
        let _ = child.wait().await;
        remove_grant_artifacts(grant)?;
        return Err(error).context("write broker password pipe");
    }
    if let Err(error) = wait_for_socket(&grant.socket_path).await {
        let _ = child.kill().await;
        let detail = child
            .wait_with_output()
            .await
            .ok()
            .map(|output| String::from_utf8_lossy(&output.stderr).trim().to_string())
            .filter(|detail| !detail.is_empty());
        remove_grant_artifacts(grant)?;
        return Err(match detail {
            Some(detail) => anyhow!("{error}: {detail}"),
            None => error,
        });
    }
    drop(child);
    Ok(())
}

fn list_authorization_catalog(matches: &ArgMatches) -> anyhow::Result<i32> {
    let plugin_filter = matches.get_one::<String>("plugin").map(String::as_str);
    let definitions =
        resolved_authorization_capabilities(plugin_filter).map_err(|error| anyhow!(error))?;
    let execution_modes = matches
        .get_many::<String>("execution-mode")
        .into_iter()
        .flatten()
        .map(|mode| parse_execution_mode(mode))
        .collect::<Vec<_>>();
    let filtered_definitions = definitions
        .iter()
        .filter(|capability| capability_matches_execution_modes(capability, &execution_modes))
        .collect::<Vec<_>>();
    let mut plugins = build_authorization_plugin_catalogs(&definitions, plugin_filter);
    if !execution_modes.is_empty() {
        for plugin in &mut plugins {
            plugin.capabilities.retain(|capability| {
                execution_modes.iter().any(|filter| match filter {
                    CapabilityExecutionMode::Stateless => {
                        capability.execution_mode.supports_stateless()
                    }
                    CapabilityExecutionMode::SessionOnly => {
                        capability.execution_mode.supports_session()
                    }
                    CapabilityExecutionMode::Both => true,
                })
            });
            plugin
                .presets
                .retain(|preset| execution_modes.contains(&preset.execution_mode));
        }
    }
    if matches.get_one::<String>("format").map(String::as_str) == Some("table") {
        println!("{}", authorization_catalog_table(&filtered_definitions));
        return Ok(0);
    }
    let capabilities = filtered_definitions
        .into_iter()
        .map(|capability| {
            let mut value = serde_json::to_value(capability)?;
            if let Some(object) = value.as_object_mut() {
                object.insert("qualified_id".into(), json!(capability.qualified_id()));
            }
            Ok::<_, serde_json::Error>(value)
        })
        .collect::<serde_json::Result<Vec<_>>>()?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "ok": true,
            "data": {
                "capabilities": capabilities,
                "count": capabilities.len(),
                "plugins": plugins,
            }
        }))?
    );
    Ok(0)
}

pub(super) fn authorization_catalog_table(definitions: &[&CapabilityDefinition]) -> String {
    let mut lines = vec!["Capability\tMode\tRisk\tStream\tSession purpose".to_string()];
    for definition in definitions {
        let purpose = definition
            .session_handoff
            .as_ref()
            .map(|handoff| crate::builtin::invoke::session_purpose_cli_name(&handoff.purpose))
            .unwrap_or_else(|| "-".into());
        lines.push(format!(
            "{}\t{}\t{}\t{}\t{}",
            sanitize_table_cell(&definition.qualified_id()),
            execution_mode_name(definition.execution_mode),
            capability_risk_name(definition.effective_risk()),
            definition.streaming,
            sanitize_table_cell(&purpose),
        ));
    }
    lines.join("\n")
}

fn sanitize_table_cell(value: &str) -> String {
    value.replace(['\t', '\n', '\r'], " ")
}

fn capability_risk_name(risk: voidb_core::CapabilityRiskLevel) -> &'static str {
    match risk {
        voidb_core::CapabilityRiskLevel::ReadOnly => "read_only",
        voidb_core::CapabilityRiskLevel::Mutating => "mutating",
        voidb_core::CapabilityRiskLevel::Destructive => "destructive",
        voidb_core::CapabilityRiskLevel::ExternalSideEffect => "external_side_effect",
    }
}

pub(super) fn build_authorization_plugin_catalogs(
    definitions: &[CapabilityDefinition],
    _plugin_filter: Option<&str>,
) -> Vec<AgentAuthorizationPluginCatalog> {
    let mut grouped = BTreeMap::<String, Vec<&CapabilityDefinition>>::new();
    for definition in definitions {
        grouped
            .entry(definition.plugin_id.clone())
            .or_default()
            .push(definition);
    }

    let mut catalogs = grouped
        .into_iter()
        .map(|(plugin_id, mut definitions)| {
            definitions.sort_by_key(|definition| definition.qualified_id());
            let metadata_complete = definitions
                .iter()
                .all(|definition| definition.authorization.declared);
            let capabilities = definitions
                .iter()
                .map(|definition| AgentAuthorizationCapability {
                    id: definition.qualified_id(),
                    risk: definition.effective_risk(),
                    streaming: definition.streaming,
                    execution_mode: definition.execution_mode,
                    session_handoff: definition.session_handoff.clone(),
                    session_purposes: definition.authorization.session_purposes.clone(),
                })
                .collect::<Vec<_>>();
            let presets = [
                CapabilityExecutionMode::Stateless,
                CapabilityExecutionMode::SessionOnly,
                CapabilityExecutionMode::Both,
            ]
            .into_iter()
            .flat_map(|execution_mode| {
                authorization_presets_for_mode(&definitions, metadata_complete, execution_mode)
            })
            .collect();
            AgentAuthorizationPluginCatalog {
                plugin_id,
                support: AgentAuthorizationSupportSummary {
                    status: AgentAuthorizationSupportStatus::Supported,
                    reason: if metadata_complete {
                        "Capability authorization metadata is centrally normalized.".into()
                    } else {
                        "Authorization metadata is incomplete; only explicit Custom scopes are available."
                            .into()
                    },
                },
                capabilities,
                presets,
            }
        })
        .collect::<Vec<_>>();

    catalogs.sort_by(|left, right| left.plugin_id.cmp(&right.plugin_id));
    catalogs
}

fn authorization_presets_for_mode(
    definitions: &[&CapabilityDefinition],
    metadata_complete: bool,
    execution_mode: CapabilityExecutionMode,
) -> Vec<AgentAuthorizationPresetDefinition> {
    if execution_mode == CapabilityExecutionMode::Both
        && (!definitions
            .iter()
            .any(|definition| definition.supports_stateless_execution())
            || !definitions
                .iter()
                .any(|definition| definition.supports_session_execution()))
    {
        return Vec::new();
    }
    let matching = definitions
        .iter()
        .copied()
        .filter(|definition| capability_supports_grant_mode(definition, execution_mode))
        .collect::<Vec<_>>();
    if matching.is_empty() {
        return Vec::new();
    }

    let read_only_definitions = matching
        .iter()
        .copied()
        .filter(|definition| {
            definition.authorization.declared
                && definition.effective_risk() == voidb_core::CapabilityRiskLevel::ReadOnly
        })
        .collect::<Vec<_>>();
    let read_only = read_only_definitions
        .iter()
        .map(|definition| definition.qualified_id())
        .collect::<Vec<_>>();
    let interactive_definitions = matching
        .iter()
        .copied()
        .filter(|definition| {
            definition.authorization.declared && definition.authorization.interactive_execute
        })
        .collect::<Vec<_>>();
    let interactive = interactive_definitions
        .iter()
        .map(|definition| definition.qualified_id())
        .collect::<Vec<_>>();
    let interactive_purposes = if execution_mode.supports_session() {
        unique_session_purposes(&interactive_definitions)
    } else {
        Vec::new()
    };
    let read_only_purposes = if execution_mode.supports_session() {
        unique_session_purposes(&read_only_definitions)
    } else {
        Vec::new()
    };
    let full_access_purposes = if execution_mode.supports_session() {
        unique_session_purposes(&matching)
    } else {
        Vec::new()
    };
    let interactive_requires_ack = interactive_definitions
        .iter()
        .any(|definition| definition.requires_acknowledgement());
    let full_access = matching
        .iter()
        .map(|definition| definition.qualified_id())
        .collect::<Vec<_>>();
    let full_access_requires_ack = matching
        .iter()
        .any(|definition| definition.requires_acknowledgement());
    let suffix = match execution_mode {
        CapabilityExecutionMode::Stateless => "",
        CapabilityExecutionMode::SessionOnly => " (session)",
        CapabilityExecutionMode::Both => " (combined)",
    };
    let mut presets = Vec::new();
    if metadata_complete && !read_only.is_empty() {
        presets.push(AgentAuthorizationPresetDefinition {
            kind: AgentAuthorizationPresetKind::ReadOnly,
            label: format!("Read-only{suffix}"),
            description: format!(
                "Policy-reviewed operations without target side effects for {} execution.",
                execution_mode_name(execution_mode)
            ),
            execution_mode,
            recommended: execution_mode == CapabilityExecutionMode::Stateless,
            capabilities: read_only,
            session_purposes: read_only_purposes,
            requires_destructive_acknowledgement: false,
        });
    }
    if metadata_complete && !interactive.is_empty() {
        presets.push(AgentAuthorizationPresetDefinition {
            kind: AgentAuthorizationPresetKind::InteractiveExecute,
            label: format!("Interactive/Execute{suffix}"),
            description: format!(
                "The plugin's narrow, reviewed interactive scope for {} execution.",
                execution_mode_name(execution_mode)
            ),
            execution_mode,
            recommended: false,
            capabilities: interactive,
            session_purposes: interactive_purposes,
            requires_destructive_acknowledgement: interactive_requires_ack,
        });
    }
    if metadata_complete && !full_access.is_empty() {
        presets.push(AgentAuthorizationPresetDefinition {
            kind: AgentAuthorizationPresetKind::FullAccess,
            label: format!("Full access{suffix}"),
            description: format!(
                "Every {} capability in the current catalog, captured as an exact snapshot.",
                execution_mode_name(execution_mode)
            ),
            execution_mode,
            recommended: false,
            capabilities: full_access.clone(),
            session_purposes: full_access_purposes.clone(),
            requires_destructive_acknowledgement: full_access_requires_ack,
        });
    }
    presets.push(AgentAuthorizationPresetDefinition {
        kind: AgentAuthorizationPresetKind::Custom,
        label: format!("Custom{suffix}"),
        description: format!(
            "Explicit exact capability selection for {} execution.",
            execution_mode_name(execution_mode)
        ),
        execution_mode,
        recommended: false,
        capabilities: full_access,
        session_purposes: full_access_purposes,
        requires_destructive_acknowledgement: false,
    });
    presets
}

fn unique_session_purposes(definitions: &[&CapabilityDefinition]) -> Vec<PluginSessionPurpose> {
    definitions
        .iter()
        .flat_map(|definition| definition.authorization.session_purposes.clone())
        .fold(Vec::new(), |mut purposes, purpose| {
            if !purposes.contains(&purpose) {
                purposes.push(purpose);
            }
            purposes
        })
}

pub(super) async fn authorize(matches: &ArgMatches) -> anyhow::Result<i32> {
    ensure_unix()?;
    let ttl_minutes = *matches
        .get_one::<u64>("ttl-minutes")
        .expect("defaulted by clap");
    if !(1..=MAX_AGENT_GRANT_TTL_MINUTES).contains(&ttl_minutes) {
        bail!("TTL must be between 1 and {MAX_AGENT_GRANT_TTL_MINUTES} minutes");
    }
    let max_uses = matches.get_one::<u32>("uses").copied();
    if max_uses.is_some_and(|uses| !(1..=MAX_AGENT_GRANT_USES).contains(&uses)) {
        bail!("Uses must be between 1 and {MAX_AGENT_GRANT_USES} when specified");
    }

    let raw_config = AppConfig::load_raw_from_path(&AppConfig::config_path()?)?;
    if !raw_config.requires_master_password() {
        bail!(
            "agent authorization requires user-passphrase protection; set a master password first"
        );
    }

    let password = if matches.get_flag("password-stdin") {
        let mut password = String::new();
        tokio::io::stdin().read_to_string(&mut password).await?;
        if password.is_empty() {
            bail!("master password was not provided on standard input");
        }
        password
    } else {
        match std::env::var(VOIDB_MASTER_PASSWORD_ENV) {
            Ok(password) if !password.is_empty() => password,
            _ => rpassword::prompt_password("VoidB master password: ")?,
        }
    };
    AppConfig::load_with_password(Some(&password))
        .context("master password verification failed")?;

    let profile_ref = matches
        .get_one::<String>("profile")
        .expect("required by clap");
    let plugin_id = matches
        .get_one::<String>("plugin")
        .expect("required by clap");
    let store = LocalProfileStore::default_store()?;
    let profile = resolve_profile(&store.load_profiles()?, profile_ref, plugin_id)?;
    verify_profile_credentials(&store, &profile, &password)
        .context("profile credential verification failed")?;

    let requested_capabilities = matches
        .get_many::<String>("capability")
        .map(|values| values.cloned().collect::<Vec<_>>());
    let requested_preset = matches.get_one::<String>("preset").map(String::as_str);
    let execution_mode = parse_execution_mode(
        matches
            .get_one::<String>("execution-mode")
            .expect("defaulted by clap"),
    );
    let (preset, capabilities) = resolve_authorization_scope(
        plugin_id,
        execution_mode,
        requested_preset,
        requested_capabilities,
    )?;
    validate_grant_capabilities(
        plugin_id,
        &capabilities,
        execution_mode,
        matches.get_flag("allow-destructive"),
    )?;
    let allow_destructive = matches.get_flag("allow-destructive");
    let existing = grants_for_profile(&load_grants(false)?, &profile.id, plugin_id);
    if !existing.is_empty() && !matches.get_flag("replace") {
        bail!(
            "profile already has an agent grant; inspect it or pass --replace to close its sessions and replace it"
        );
    }
    let now = Utc::now();
    let id = format!("agent-grant:{}", Uuid::new_v4());
    let file_stem = id.trim_start_matches("agent-grant:");
    let directory = grant_directory()?;
    let grant_path = directory.join(format!("{file_stem}.json"));
    let socket_path = PathBuf::from("/tmp").join(format!(
        "voidb-agent-{}.sock",
        file_stem.chars().take(16).collect::<String>()
    ));
    let grant = AgentGrantFile {
        version: GRANT_VERSION,
        id: id.clone(),
        token: Uuid::new_v4().to_string(),
        profile_id: profile.id,
        profile_name: profile.name,
        plugin_id: plugin_id.clone(),
        capabilities,
        execution_mode,
        preset: Some(preset),
        allow_destructive,
        issued_at: now,
        expires_at: now + chrono::Duration::minutes(ttl_minutes as i64),
        remaining_uses: max_uses,
        socket_path,
        authorization_scopes: Vec::new(),
        principal_fingerprint: None,
        grant_revision: None,
    };
    write_grant(&grant_path, &grant)?;

    let mut command = tokio::process::Command::new(std::env::current_exe()?);
    command
        .arg("__agent-broker")
        .arg(&grant_path)
        .env_remove(VOIDB_MASTER_PASSWORD_ENV)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(false);
    #[cfg(unix)]
    command.process_group(0);
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            remove_grant_artifacts(&grant)?;
            return Err(error).context("start agent broker");
        }
    };
    let stdin = child.stdin.take().context("open broker password pipe")?;
    write_password_and_close(stdin, password.as_bytes()).await?;
    drop(password);
    if let Err(error) = wait_for_socket(&grant.socket_path).await {
        let _ = child.kill().await;
        let detail = child
            .wait_with_output()
            .await
            .ok()
            .map(|output| String::from_utf8_lossy(&output.stderr).trim().to_string())
            .filter(|detail| !detail.is_empty());
        remove_grant_artifacts(&grant)?;
        return Err(match detail {
            Some(detail) => anyhow!("{error}: {detail}"),
            None => error,
        });
    }
    drop(child);
    let mut replaced = Vec::new();
    for displaced in existing {
        shutdown_grant(&displaced, "replaced").await?;
        replaced.push(displaced.id);
    }
    append_agent_audit(
        &grant,
        AuditOperation::CredentialGrantIssued,
        json!({
            "expires_at": grant.expires_at,
            "max_uses": max_uses,
            "capabilities": grant.capabilities,
            "execution_mode": grant.execution_mode,
            "allow_destructive": grant.allow_destructive,
            "replaced": replaced,
        }),
    );
    let inspection = inspect_grant(&grant).await;
    let public_grant = grant.public(inspection.broker_health, inspection.active_session_count);
    let status = public_grant.status_at(Utc::now());
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "ok": true,
            "data": {
                "grant": public_grant,
                "status": status,
                "replaced": replaced,
                "defaults": {
                    "ttl_minutes": DEFAULT_AGENT_GRANT_TTL_MINUTES,
                    "max_uses": DEFAULT_AGENT_GRANT_USES,
                    "destructive_denied": !grant.allow_destructive,
                    "execution_mode": grant.execution_mode,
                },
                "usage_args": [
                    "voidb-cli", "agent", "exec", "<plugin.capability>",
                    "--profile", grant.profile_name, "--input-json", "{}"
                ],
                "advanced_usage": format!("voidb-cli agent run --grant {} -- invoke run <plugin.capability> --profile id:{} --input-json '{{}}' --format json", grant.id, grant.profile_id),
            }
        }))?
    );
    Ok(0)
}

async fn authorize_batch(matches: &ArgMatches) -> anyhow::Result<i32> {
    ensure_unix()?;
    let ttl_minutes = *matches
        .get_one::<u64>("ttl-minutes")
        .expect("defaulted by clap");
    if !(1..=MAX_AGENT_GRANT_TTL_MINUTES).contains(&ttl_minutes) {
        bail!("TTL must be between 1 and {MAX_AGENT_GRANT_TTL_MINUTES} minutes");
    }
    let max_uses = matches.get_one::<u32>("uses").copied();
    if max_uses.is_some_and(|uses| !(1..=MAX_AGENT_GRANT_USES).contains(&uses)) {
        bail!("Uses must be between 1 and {MAX_AGENT_GRANT_USES} when specified");
    }

    let raw_config = AppConfig::load_raw_from_path(&AppConfig::config_path()?)?;
    if !raw_config.requires_master_password() {
        bail!(
            "agent authorization requires user-passphrase protection; set a master password first"
        );
    }

    let spec_path = PathBuf::from(matches.get_one::<String>("spec").expect("required by clap"));
    let spec = load_batch_authorization_spec(&spec_path)?;
    if spec.grants.is_empty() {
        bail!("batch authorization spec must contain at least one grant");
    }
    if spec.grants.len() > MAX_BATCH_AUTHORIZATION_GRANTS {
        bail!("batch authorization spec exceeds the {MAX_BATCH_AUTHORIZATION_GRANTS}-grant limit");
    }

    let profile_store = LocalProfileStore::default_store()?;
    let profiles = profile_store.load_profiles()?;
    let current_grants = load_grants(false)?;
    let mut scopes = BTreeSet::new();
    let mut prepared = Vec::with_capacity(spec.grants.len());
    for entry in spec.grants {
        validate_review_purpose(&entry.purpose)?;
        let execution_mode = parse_batch_execution_mode(entry.execution_mode.as_deref())?;
        let requested_capabilities = (!entry.capabilities.is_empty()).then_some(entry.capabilities);
        let (preset, capabilities) = resolve_authorization_scope(
            &entry.plugin,
            execution_mode,
            entry.preset.as_deref(),
            requested_capabilities,
        )?;
        let requires_destructive = grant_scope_requires_destructive(&capabilities)?;
        validate_grant_capabilities(
            &entry.plugin,
            &capabilities,
            execution_mode,
            matches.get_flag("allow-destructive"),
        )?;
        let profile = resolve_profile(&profiles, &entry.profile, &entry.plugin)?;
        if !scopes.insert((profile.id.clone(), entry.plugin.clone())) {
            bail!(
                "batch authorization contains duplicate scope for profile '{}' and plugin '{}'",
                profile.name,
                entry.plugin
            );
        }
        let existing = grants_for_profile(&current_grants, &profile.id, &entry.plugin);
        if !existing.is_empty() && !matches.get_flag("replace") {
            bail!(
                "profile '{}' already has an agent grant; pass --replace to review its replacement",
                profile.name
            );
        }
        prepared.push(PreparedBatchGrant {
            profile,
            plugin_id: entry.plugin,
            purpose: entry.purpose,
            execution_mode,
            preset,
            capabilities,
            allow_destructive: requires_destructive,
            existing,
        });
    }

    render_batch_authorization_review(&prepared, ttl_minutes, max_uses)?;
    if !matches.get_flag("yes") {
        if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
            bail!(
                "batch authorization review requires an interactive TTY; rerun locally or pass --yes after reviewing the spec"
            );
        }
        let confirmation = prompt_tty_line("Type AUTHORIZE to create these grants: ")?;
        if confirmation != "AUTHORIZE" {
            bail!("batch authorization was not confirmed");
        }
    }

    let mut password = rpassword::prompt_password("VoidB master password: ")?;
    if password.is_empty() {
        bail!("master password is required");
    }
    if AppConfig::load_with_password(Some(&password)).is_err() {
        password.clear();
        bail!("master password verification failed");
    }
    for plan in &prepared {
        if let Err(error) = verify_profile_credentials(&profile_store, &plan.profile, &password) {
            password.clear();
            return Err(error).with_context(|| {
                format!(
                    "profile credential verification failed for '{}' ({})",
                    plan.profile.name, plan.plugin_id
                )
            });
        }
    }

    let now = Utc::now();
    let mut started = Vec::<AgentGrantFile>::with_capacity(prepared.len());
    let mut replacements = BTreeMap::<String, Vec<String>>::new();
    for plan in &prepared {
        let (grant_path, grant) = build_proactive_grant(plan, now, ttl_minutes, max_uses)?;
        if let Err(error) = write_grant(&grant_path, &grant) {
            rollback_batch_grants(&started).await;
            password.clear();
            return Err(error).context("write batch agent grant");
        }
        if let Err(error) = spawn_agent_broker(&grant_path, &grant, &password).await {
            rollback_batch_grants(&started).await;
            password.clear();
            return Err(error).with_context(|| {
                format!(
                    "start batch agent broker for '{}' ({})",
                    plan.profile.name, plan.plugin_id
                )
            });
        }
        replacements.insert(
            grant.id.clone(),
            plan.existing
                .iter()
                .map(|existing| existing.id.clone())
                .collect(),
        );
        started.push(grant);
    }
    password.clear();

    for plan in &prepared {
        for existing in &plan.existing {
            if let Err(error) = shutdown_grant(existing, "batch_replaced").await {
                rollback_batch_grants(&started).await;
                return Err(error).with_context(|| {
                    format!(
                        "replace existing grant '{}' for '{}' ({})",
                        existing.id, plan.profile.name, plan.plugin_id
                    )
                });
            }
        }
    }

    let mut results = Vec::with_capacity(started.len());
    for grant in &started {
        let replaced = replacements.get(&grant.id).cloned().unwrap_or_default();
        append_agent_audit(
            grant,
            AuditOperation::CredentialGrantIssued,
            json!({
                "lifecycle": "batch",
                "expires_at": grant.expires_at,
                "max_uses": grant.remaining_uses,
                "capabilities": grant.capabilities,
                "execution_mode": grant.execution_mode,
                "allow_destructive": grant.allow_destructive,
                "replaced": replaced,
            }),
        );
        let inspection = inspect_grant(grant).await;
        let public = grant.public(inspection.broker_health, inspection.active_session_count);
        let status = public.status_at(Utc::now());
        results.push(json!({
            "grant": public,
            "status": status,
            "replaced": replaced,
        }));
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "ok": true,
            "data": {
                "grants": results,
                "count": results.len(),
                "defaults": {
                    "ttl_minutes": DEFAULT_AGENT_GRANT_TTL_MINUTES,
                    "max_uses": DEFAULT_AGENT_GRANT_USES,
                }
            }
        }))?
    );
    Ok(0)
}

pub(super) fn load_batch_authorization_spec(path: &Path) -> anyhow::Result<BatchAuthorizationSpec> {
    let path_metadata = fs::symlink_metadata(path)
        .with_context(|| format!("inspect batch authorization spec '{}'", path.display()))?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        bail!("batch authorization spec must be a regular, non-symlink file");
    }
    if path_metadata.len() > MAX_BATCH_AUTHORIZATION_SPEC_BYTES {
        bail!(
            "batch authorization spec exceeds the {}-byte limit",
            MAX_BATCH_AUTHORIZATION_SPEC_BYTES
        );
    }

    let file = OpenOptions::new()
        .read(true)
        .open(path)
        .with_context(|| format!("open batch authorization spec '{}'", path.display()))?;
    let opened_metadata = file.metadata().with_context(|| {
        format!(
            "inspect opened batch authorization spec '{}'",
            path.display()
        )
    })?;
    #[cfg(unix)]
    if path_metadata.dev() != opened_metadata.dev()
        || path_metadata.ino() != opened_metadata.ino()
        || !opened_metadata.is_file()
    {
        bail!("batch authorization spec changed while it was being opened");
    }
    if opened_metadata.len() > MAX_BATCH_AUTHORIZATION_SPEC_BYTES {
        bail!(
            "batch authorization spec exceeds the {}-byte limit",
            MAX_BATCH_AUTHORIZATION_SPEC_BYTES
        );
    }

    let mut bytes = Vec::with_capacity(opened_metadata.len() as usize);
    file.take(MAX_BATCH_AUTHORIZATION_SPEC_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_BATCH_AUTHORIZATION_SPEC_BYTES {
        bail!(
            "batch authorization spec exceeds the {}-byte limit",
            MAX_BATCH_AUTHORIZATION_SPEC_BYTES
        );
    }
    serde_json::from_slice(&bytes)
        .with_context(|| format!("parse batch authorization spec '{}'", path.display()))
}

fn parse_batch_execution_mode(value: Option<&str>) -> anyhow::Result<CapabilityExecutionMode> {
    match value.unwrap_or("stateless") {
        "stateless" => Ok(CapabilityExecutionMode::Stateless),
        "session_only" => Ok(CapabilityExecutionMode::SessionOnly),
        "both" => Ok(CapabilityExecutionMode::Both),
        value => bail!("unsupported batch grant execution mode '{value}'"),
    }
}

pub(super) fn grant_scope_requires_destructive(capabilities: &[String]) -> anyhow::Result<bool> {
    capabilities.iter().try_fold(false, |required, capability| {
        let risk = resolved_capability_risk(capability).map_err(|error| anyhow!(error))?;
        Ok(required || risk != voidb_core::CapabilityRiskLevel::ReadOnly)
    })
}

fn render_batch_authorization_review(
    prepared: &[PreparedBatchGrant],
    ttl_minutes: u64,
    max_uses: Option<u32>,
) -> anyhow::Result<()> {
    println!("VoidB batch agent authorization review");
    println!("Duration: {ttl_minutes} minutes");
    println!(
        "Use limit: {}",
        max_uses.map_or_else(|| "unlimited".to_string(), |uses| uses.to_string())
    );
    for (index, plan) in prepared.iter().enumerate() {
        let preset = serde_json::to_value(plan.preset)?
            .as_str()
            .unwrap_or("custom")
            .to_string();
        println!(
            "{}. {} ({}) preset={} mode={} destructive={}{}",
            index + 1,
            sanitize_terminal_text(&plan.profile.name),
            sanitize_terminal_text(&plan.plugin_id),
            preset,
            execution_mode_name(plan.execution_mode),
            plan.allow_destructive,
            if plan.existing.is_empty() {
                ""
            } else {
                " replacing-existing-grant"
            }
        );
        println!(
            "   purpose: {}",
            sanitize_terminal_text(plan.purpose.trim())
        );
        println!("   capabilities: {}", plan.capabilities.join(", "));
    }
    Ok(())
}

pub(super) fn validate_review_purpose(purpose: &str) -> anyhow::Result<()> {
    if purpose.trim().is_empty() || purpose.len() > 1000 {
        bail!("authorization purpose must contain 1 to 1000 bytes");
    }
    Ok(())
}

fn build_proactive_grant(
    plan: &PreparedBatchGrant,
    issued_at: DateTime<Utc>,
    ttl_minutes: u64,
    max_uses: Option<u32>,
) -> anyhow::Result<(PathBuf, AgentGrantFile)> {
    let id = format!("agent-grant:{}", Uuid::new_v4());
    let file_stem = id.trim_start_matches("agent-grant:");
    let grant_path = grant_directory()?.join(format!("{file_stem}.json"));
    let socket_path = PathBuf::from("/tmp").join(format!(
        "voidb-agent-{}.sock",
        file_stem.chars().take(16).collect::<String>()
    ));
    Ok((
        grant_path,
        AgentGrantFile {
            version: GRANT_VERSION,
            id,
            token: Uuid::new_v4().to_string(),
            profile_id: plan.profile.id.clone(),
            profile_name: plan.profile.name.clone(),
            plugin_id: plan.plugin_id.clone(),
            capabilities: plan.capabilities.clone(),
            execution_mode: plan.execution_mode,
            preset: Some(plan.preset),
            allow_destructive: plan.allow_destructive,
            issued_at,
            expires_at: issued_at + chrono::Duration::minutes(ttl_minutes as i64),
            remaining_uses: max_uses,
            socket_path,
            authorization_scopes: Vec::new(),
            principal_fingerprint: None,
            grant_revision: None,
        },
    ))
}

async fn rollback_batch_grants(grants: &[AgentGrantFile]) {
    for grant in grants.iter().rev() {
        let _ = shutdown_grant(grant, "batch_rollback").await;
    }
}

pub(super) fn resolve_authorization_scope(
    plugin_id: &str,
    execution_mode: CapabilityExecutionMode,
    requested_preset: Option<&str>,
    requested_capabilities: Option<Vec<String>>,
) -> anyhow::Result<(AgentAuthorizationPresetKind, Vec<String>)> {
    let preset = match requested_preset {
        Some("read_only") => AgentAuthorizationPresetKind::ReadOnly,
        Some("interactive_execute") => AgentAuthorizationPresetKind::InteractiveExecute,
        Some("full_access") => AgentAuthorizationPresetKind::FullAccess,
        Some("custom") => AgentAuthorizationPresetKind::Custom,
        Some(value) => bail!("unsupported authorization preset '{value}'"),
        None if requested_capabilities.is_some() => AgentAuthorizationPresetKind::Custom,
        None => AgentAuthorizationPresetKind::ReadOnly,
    };
    let mut capabilities = match requested_capabilities {
        Some(capabilities) => capabilities,
        None => match preset {
            AgentAuthorizationPresetKind::ReadOnly => read_only_scope(plugin_id, execution_mode)?,
            AgentAuthorizationPresetKind::InteractiveExecute => {
                interactive_execute_scope(plugin_id, execution_mode)?
            }
            AgentAuthorizationPresetKind::FullAccess => {
                full_access_scope(plugin_id, execution_mode)?
            }
            AgentAuthorizationPresetKind::Custom => {
                bail!("the Custom preset requires at least one explicit --capability")
            }
        },
    };
    capabilities.sort();
    capabilities.dedup();
    match preset {
        AgentAuthorizationPresetKind::ReadOnly => {
            for capability in &capabilities {
                if resolved_capability_risk(capability).map_err(|error| anyhow!(error))?
                    != voidb_core::CapabilityRiskLevel::ReadOnly
                {
                    bail!("the Read-only preset cannot include '{capability}'");
                }
            }
            let expected = read_only_scope(plugin_id, execution_mode)?;
            if capabilities != expected {
                bail!(
                    "the Read-only preset must use its exact central {} capability scope",
                    execution_mode_name(execution_mode)
                );
            }
        }
        AgentAuthorizationPresetKind::InteractiveExecute => {
            let expected = interactive_execute_scope(plugin_id, execution_mode)?;
            if capabilities != expected {
                bail!(
                    "the Interactive/Execute preset must use its exact central {} capability scope",
                    execution_mode_name(execution_mode)
                );
            }
        }
        AgentAuthorizationPresetKind::FullAccess => {
            let expected = full_access_scope(plugin_id, execution_mode)?;
            if capabilities != expected {
                bail!(
                    "the Full access preset must use its exact central {} capability scope",
                    execution_mode_name(execution_mode)
                );
            }
        }
        AgentAuthorizationPresetKind::Custom => {}
    }
    if capabilities.is_empty() {
        bail!("authorization capability scope is empty");
    }
    Ok((preset, capabilities))
}

pub(super) fn read_only_scope(
    plugin_id: &str,
    execution_mode: CapabilityExecutionMode,
) -> anyhow::Result<Vec<String>> {
    let mut capabilities = resolved_authorization_capabilities(Some(plugin_id))
        .map_err(|error| anyhow!(error))?
        .into_iter()
        .filter(|definition| {
            definition.authorization.declared
                && definition.effective_risk() == voidb_core::CapabilityRiskLevel::ReadOnly
                && capability_supports_grant_mode(definition, execution_mode)
        })
        .map(|definition| definition.qualified_id())
        .collect::<Vec<_>>();
    capabilities.sort();
    capabilities.dedup();
    if capabilities.is_empty() {
        bail!(
            "plugin '{plugin_id}' has no agent-ready read-only capabilities for {} execution",
            execution_mode_name(execution_mode)
        );
    }
    Ok(capabilities)
}

fn interactive_execute_scope(
    plugin_id: &str,
    execution_mode: CapabilityExecutionMode,
) -> anyhow::Result<Vec<String>> {
    let mut capabilities = resolved_authorization_capabilities(Some(plugin_id))
        .map_err(|error| anyhow!(error))?
        .into_iter()
        .filter(|definition| {
            definition.authorization.declared
                && definition.authorization.interactive_execute
                && capability_supports_grant_mode(definition, execution_mode)
        })
        .map(|definition| definition.qualified_id())
        .collect::<Vec<_>>();
    capabilities.sort();
    capabilities.dedup();
    if capabilities.is_empty() {
        bail!(
            "plugin '{plugin_id}' has no Interactive/Execute preset for {} execution",
            execution_mode_name(execution_mode)
        );
    }
    Ok(capabilities)
}

fn full_access_scope(
    plugin_id: &str,
    execution_mode: CapabilityExecutionMode,
) -> anyhow::Result<Vec<String>> {
    let definitions =
        resolved_authorization_capabilities(Some(plugin_id)).map_err(|error| anyhow!(error))?;
    if definitions
        .iter()
        .any(|definition| !definition.authorization.declared)
    {
        bail!(
            "plugin '{plugin_id}' has incomplete authorization metadata; use an explicit Custom scope"
        );
    }
    let mut capabilities = definitions
        .into_iter()
        .filter(|definition| capability_supports_grant_mode(definition, execution_mode))
        .map(|definition| definition.qualified_id())
        .collect::<Vec<_>>();
    capabilities.sort();
    capabilities.dedup();
    if capabilities.is_empty() {
        bail!(
            "plugin '{plugin_id}' has no capabilities for the {} Full access preset",
            execution_mode_name(execution_mode)
        );
    }
    Ok(capabilities)
}

fn parse_execution_mode(value: &str) -> CapabilityExecutionMode {
    match value {
        "stateless" => CapabilityExecutionMode::Stateless,
        "session_only" => CapabilityExecutionMode::SessionOnly,
        "both" => CapabilityExecutionMode::Both,
        _ => unreachable!("clap validates execution modes"),
    }
}

pub(super) fn execution_mode_name(mode: CapabilityExecutionMode) -> &'static str {
    match mode {
        CapabilityExecutionMode::Stateless => "stateless",
        CapabilityExecutionMode::SessionOnly => "session_only",
        CapabilityExecutionMode::Both => "both",
    }
}

fn capability_supports_grant_mode(
    definition: &CapabilityDefinition,
    execution_mode: CapabilityExecutionMode,
) -> bool {
    match execution_mode {
        CapabilityExecutionMode::Stateless => definition.supports_stateless_execution(),
        CapabilityExecutionMode::SessionOnly => definition.supports_session_execution(),
        CapabilityExecutionMode::Both => {
            definition.supports_stateless_execution() || definition.supports_session_execution()
        }
    }
}

pub(super) fn capability_matches_execution_modes(
    definition: &CapabilityDefinition,
    filters: &[CapabilityExecutionMode],
) -> bool {
    filters.is_empty()
        || filters
            .iter()
            .any(|filter| capability_supports_grant_mode(definition, *filter))
}

pub(super) fn resolve_profile(
    profiles: &[ConnectionProfile],
    profile_ref: &str,
    plugin_id: &str,
) -> anyhow::Result<ConnectionProfile> {
    if plugin_id == "sync" {
        let profile = sync_system_profile();
        let requested_id = profile_ref.strip_prefix("id:");
        let requested_name = profile_ref.strip_prefix("name:").unwrap_or(profile_ref);
        if requested_id.is_some_and(|id| id == profile.id)
            || requested_id.is_none()
                && (profile_ref == profile.id || profile_names_equal(&profile.name, requested_name))
        {
            return Ok(profile);
        }
        bail!(
            "connection-independent Sync capabilities use '--profile local' or '--profile id:system:sync'"
        );
    }
    let requested_id = profile_ref.strip_prefix("id:");
    let requested_name = profile_ref.strip_prefix("name:").unwrap_or(profile_ref);
    let matches = profiles
        .iter()
        .filter(|profile| profile.plugin_id == plugin_id)
        .filter(|profile| {
            requested_id.is_some_and(|id| profile.id == id)
                || requested_id.is_none()
                    && (profile.id == profile_ref
                        || profile_names_equal(&profile.name, requested_name))
        })
        .cloned()
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [profile] => Ok(profile.clone()),
        [] => bail!("profile '{profile_ref}' was not found for plugin '{plugin_id}'"),
        _ => bail!("profile '{profile_ref}' is ambiguous; use id:<profile-id>"),
    }
}

fn sync_system_profile() -> ConnectionProfile {
    ConnectionProfile {
        id: "system:sync".into(),
        name: "local".into(),
        plugin_id: "sync".into(),
        display_name: Some("Local Sync control surface".into()),
        metadata: json!({
            "scope": "local_system",
            "connection_required": false
        }),
        default_options: Value::Null,
        credential_refs: Vec::new(),
        policy: Default::default(),
    }
}

pub(super) fn verify_profile_credentials(
    store: &LocalProfileStore,
    profile: &ConnectionProfile,
    password: &str,
) -> anyhow::Result<()> {
    if profile.metadata.get("scope").and_then(Value::as_str) == Some("local_system") {
        return Ok(());
    }
    store
        .native_connection(profile, Some(password))
        .map(|_| ())
        .map_err(anyhow::Error::from)
}

pub(super) fn validate_grant_capabilities(
    plugin_id: &str,
    capabilities: &[String],
    execution_mode: CapabilityExecutionMode,
    allow_destructive: bool,
) -> anyhow::Result<()> {
    if capabilities.is_empty() {
        bail!("agent grant capability scope cannot be empty");
    }
    let definitions = resolved_authorization_capabilities(Some(plugin_id))
        .map_err(|error| anyhow!("capability catalog could not be verified: {error}"))?;
    for capability in capabilities {
        if capability == "*" {
            bail!("wildcard agent grant scopes are not allowed; select exact capabilities");
        }
        let Some((plugin, _)) = capability.split_once('.') else {
            bail!("agent grant capabilities must be qualified as <plugin>.<capability>");
        };
        if plugin != plugin_id {
            bail!("capability '{capability}' is outside plugin '{plugin_id}'");
        }
        let definition = definitions
            .iter()
            .find(|definition| definition.qualified_id() == *capability)
            .ok_or_else(|| anyhow!("capability '{capability}' is not in the current catalog"))?;
        if !capability_supports_grant_mode(definition, execution_mode) {
            bail!(
                "capability '{capability}' does not support {} grant execution",
                execution_mode_name(execution_mode)
            );
        }
        let risk = definition.effective_risk();
        if risk != voidb_core::CapabilityRiskLevel::ReadOnly && !allow_destructive {
            bail!(
                "capability '{capability}' has risk '{risk:?}'; pass --allow-destructive and complete the required CLI confirmation"
            );
        }
    }
    Ok(())
}

pub(super) fn grants_for_profile(
    grants: &[AgentGrantFile],
    profile_id: &str,
    plugin_id: &str,
) -> Vec<AgentGrantFile> {
    grants
        .iter()
        .filter(|grant| grant.profile_id == profile_id && grant.plugin_id == plugin_id)
        .cloned()
        .collect()
}

fn grant_matches_profile(grant: &AgentGrantFile, profile: &str) -> bool {
    profile
        .strip_prefix("id:")
        .is_some_and(|id| grant.profile_id == id)
        || profile
            .strip_prefix("name:")
            .is_some_and(|name| profile_names_equal(&grant.profile_name, name))
        || !profile.contains(':') && profile_names_equal(&grant.profile_name, profile)
}

pub(super) async fn inspect_grant(grant: &AgentGrantFile) -> GrantInspection {
    if !grant.socket_path.exists() {
        return GrantInspection {
            broker_health: AgentBrokerHealth::Offline,
            active_session_count: 0,
        };
    }
    let response = tokio::time::timeout(
        BROKER_PROBE_TIMEOUT,
        send_request(
            grant,
            BrokerRequest::Inspect {
                token: grant.token.clone(),
            },
        ),
    )
    .await;
    let Ok(Ok(response)) = response else {
        return GrantInspection {
            broker_health: AgentBrokerHealth::StaleSocket,
            active_session_count: 0,
        };
    };
    if !response.ok {
        return GrantInspection {
            broker_health: AgentBrokerHealth::StaleSocket,
            active_session_count: 0,
        };
    }
    GrantInspection {
        broker_health: AgentBrokerHealth::Online,
        active_session_count: response
            .data
            .as_ref()
            .and_then(|data| data.get("active_session_count"))
            .and_then(Value::as_u64)
            .and_then(|count| usize::try_from(count).ok())
            .unwrap_or(0),
    }
}

pub(super) fn frontend_grant_value(
    grant: &FrontendAgentGrant,
    now: DateTime<Utc>,
) -> anyhow::Result<Value> {
    let status = grant.status_at(now);
    let mut value = serde_json::to_value(grant)?;
    if let Some(object) = value.as_object_mut() {
        object.insert("status".into(), serde_json::to_value(status)?);
        object.insert(
            "active".into(),
            Value::Bool(matches!(
                status,
                voidb_core::AgentGrantStatus::Active | voidb_core::AgentGrantStatus::Expiring
            )),
        );
    }
    Ok(value)
}

async fn list_grants(matches: &ArgMatches) -> anyhow::Result<i32> {
    ensure_unix()?;
    let profile_filter = matches.get_one::<String>("profile");
    let plugin_filter = matches.get_one::<String>("plugin");
    let grants = load_grants(false)?
        .into_iter()
        .filter(|grant| {
            plugin_filter.is_none_or(|plugin| grant.plugin_id == *plugin)
                && profile_filter.is_none_or(|profile| grant_matches_profile(grant, profile))
        })
        .collect::<Vec<_>>();
    let mut public_grants = Vec::with_capacity(grants.len());
    let mut grouped = BTreeMap::<(String, String), Vec<FrontendAgentGrant>>::new();
    for grant in &grants {
        let inspection = inspect_grant(grant).await;
        let public = grant.public(inspection.broker_health, inspection.active_session_count);
        public_grants.push(frontend_grant_value(&public, Utc::now())?);
        grouped
            .entry((grant.profile_id.clone(), grant.plugin_id.clone()))
            .or_default()
            .push(grant.public(inspection.broker_health, inspection.active_session_count));
    }
    let mut profiles = Vec::with_capacity(grouped.len());
    for ((_profile_id, _plugin_id), mut grants) in grouped {
        grants.sort_by_key(|grant| grant.issued_at);
        let grant = grants.pop().expect("group contains one grant");
        profiles.push(AgentAuthorizationProfileSummary {
            profile_id: grant.profile_id.clone(),
            profile_name: grant.profile_name.clone(),
            plugin_id: grant.plugin_id.clone(),
            support: AgentAuthorizationSupportSummary {
                status: AgentAuthorizationSupportStatus::Supported,
                reason: "A central agent capability grant exists for this profile.".into(),
            },
            broker_health: grant.broker_health,
            active_session_count: grant.active_session_count,
            grant_status: Some(grant.status_at(Utc::now())),
            grant: Some(grant),
            refreshed_at: Utc::now(),
        });
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "ok": true,
            "data": {
                "profiles": profiles,
                "grants": public_grants,
                "count": public_grants.len(),
            }
        }))?
    );
    Ok(0)
}

pub(super) async fn renew_grant(matches: &ArgMatches) -> anyhow::Result<i32> {
    ensure_unix()?;
    let ttl_minutes = *matches
        .get_one::<u64>("ttl-minutes")
        .expect("defaulted by clap");
    if !(1..=MAX_AGENT_GRANT_TTL_MINUTES).contains(&ttl_minutes) {
        bail!("TTL must be between 1 and {MAX_AGENT_GRANT_TTL_MINUTES} minutes");
    }
    let remaining_uses = matches.get_one::<u32>("uses").copied();
    if remaining_uses.is_some_and(|uses| !(1..=MAX_AGENT_GRANT_USES).contains(&uses)) {
        bail!("Uses must be between 1 and {MAX_AGENT_GRANT_USES} when specified");
    }
    let requested = matches
        .get_one::<String>("grant")
        .expect("required by clap");
    let grant = load_grants(false)?
        .into_iter()
        .find(|grant| grant.id == *requested)
        .ok_or_else(|| anyhow!("agent grant was not found"))?;
    let inspection = inspect_grant(&grant).await;
    if inspection.broker_health != AgentBrokerHealth::Online {
        bail!("agent broker is not online; revoke or replace the stale grant instead");
    }
    let expires_at = Utc::now() + chrono::Duration::minutes(ttl_minutes as i64);
    let response = send_request(
        &grant,
        BrokerRequest::RenewGrant {
            token: grant.token.clone(),
            expires_at,
            remaining_uses,
        },
    )
    .await?;
    if !response.ok {
        bail!(
            "agent grant renewal failed: {}",
            response
                .error
                .unwrap_or_else(|| "broker rejected renewal".into())
        );
    }
    let refreshed = read_grant(&grant_path_for_id(&grant.id)?)?;
    let inspection = inspect_grant(&refreshed).await;
    let public = refreshed.public(inspection.broker_health, inspection.active_session_count);
    let status = public.status_at(Utc::now());
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "ok": true,
            "data": {
                "grant": public,
                "status": status,
                "renewed": true,
            }
        }))?
    );
    Ok(0)
}

pub(super) async fn revoke(matches: &ArgMatches) -> anyhow::Result<i32> {
    ensure_unix()?;
    let all = matches.get_flag("all");
    let requested = matches.get_one::<String>("grant");
    let profile = matches.get_one::<String>("profile");
    let plugin = matches.get_one::<String>("plugin");
    if !all && requested.is_none() && profile.is_none() {
        bail!("pass a grant ID, --profile with --plugin, or --all");
    }
    let grants = load_grants(false)?;
    let selected = select_grants_for_revoke(&grants, all, requested, profile, plugin);
    if selected.is_empty() && !all {
        bail!("agent grant was not found");
    }
    let mut revoked = Vec::new();
    for grant in selected {
        shutdown_grant(&grant, "scoped_revoke").await?;
        if grant.grant_revision.is_some() {
            JitAuthorizationStore::default_store()
                .context("open JIT authorization ledger for revoke")?
                .revoke_grant(&grant.id, Utc::now())
                .context("record JIT logical grant revoke")?;
        }
        revoked.push(grant.id);
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "ok": true,
            "data": { "revoked": revoked, "count": revoked.len() }
        }))?
    );
    Ok(0)
}

pub(super) fn select_grants_for_revoke(
    grants: &[AgentGrantFile],
    all: bool,
    requested: Option<&String>,
    profile: Option<&String>,
    plugin: Option<&String>,
) -> Vec<AgentGrantFile> {
    grants
        .iter()
        .filter(|grant| {
            all || requested.is_some_and(|id| grant.id == *id)
                || profile.is_some_and(|profile| {
                    plugin.is_some_and(|plugin| grant.plugin_id == *plugin)
                        && grant_matches_profile(grant, profile)
                })
        })
        .cloned()
        .collect()
}

async fn exec_capability(matches: &ArgMatches) -> anyhow::Result<i32> {
    ensure_unix()?;
    let capability = matches
        .get_one::<String>("capability")
        .expect("required by clap");
    let plugin_id = capability
        .split_once('.')
        .map(|(plugin_id, _)| plugin_id)
        .filter(|plugin_id| !plugin_id.is_empty())
        .ok_or_else(|| anyhow!("capability must be qualified as <plugin>.<capability>"))?;
    let profile_ref = matches
        .get_one::<String>("profile")
        .expect("required by clap");
    let definitions =
        resolved_authorization_capabilities(Some(plugin_id)).map_err(|error| anyhow!(error))?;
    if let Some(definition) = definitions
        .iter()
        .find(|definition| definition.qualified_id() == *capability)
        && !definition.supports_stateless_execution()
    {
        let discovery = voidb_core::discover_process_plugins();
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": false,
                "data": session_handoff_guidance(definition, profile_ref, &discovery),
                "error": {
                    "code": "execution_mode_mismatch",
                    "message": "Capability is session-only; agent exec creates stateless JIT requests. Follow data.authorize_args and data.session_open_args instead."
                }
            }))?
        );
        return Ok(JIT_EXIT_INVALID);
    }
    let profile_store = LocalProfileStore::default_store()?;
    let profile = resolve_profile(&profile_store.load_profiles()?, profile_ref, plugin_id)?;
    let input = parse_agent_exec_input(matches)?;
    let argv = agent_exec_argv(matches, capability, &profile.id, &input);
    let principal = agent_exec_principal(matches)?;

    if let Some(grant) = find_agent_exec_grant(&argv, principal.as_ref()).await? {
        return execute_granted_command(grant, argv).await;
    }

    if matches.get_flag("no-request") || principal.is_none() {
        return print_agent_exec_authorization_required(
            &profile.name,
            plugin_id,
            capability,
            principal.is_none(),
        );
    }

    let principal = principal.expect("checked above");
    let request_ttl_seconds = *matches
        .get_one::<u64>("request-ttl-seconds")
        .expect("defaulted by clap");
    if !(1..=voidb_core::MAX_AUTHORIZATION_REQUEST_TTL_SECONDS as u64)
        .contains(&request_ttl_seconds)
    {
        return print_jit_error(
            JIT_EXIT_INVALID,
            "invalid_request_ttl",
            &format!(
                "request TTL must be between 1 and {} seconds",
                voidb_core::MAX_AUTHORIZATION_REQUEST_TTL_SECONDS
            ),
            None,
        );
    }
    let Some(purpose) = matches.get_one::<String>("purpose").cloned() else {
        return print_jit_error(
            JIT_EXIT_INVALID,
            "purpose_required",
            "authorization requests require --purpose with the specific intended use for user review",
            None,
        );
    };
    let (scope, risk) = exact_agent_exec_scope(plugin_id, capability, input)?;
    let now = Utc::now();
    let store = match JitAuthorizationStore::default_store() {
        Ok(store) => store,
        Err(error) => return print_jit_store_error(error),
    };
    let created = match store.create(
        CreateAuthorizationRequest {
            principal: principal.clone(),
            profile_id: profile.id,
            plugin_id: plugin_id.to_string(),
            scope,
            risk,
            purpose,
            expires_at: now + chrono::Duration::seconds(request_ttl_seconds as i64),
        },
        now,
    ) {
        Ok(created) => created,
        Err(error) => return print_jit_store_error(error),
    };

    eprintln!(
        "{}",
        agent_exec_review_prompt(plugin_id, &profile.name, &created.review_command)
    );
    let wait_timeout = Duration::from_millis(
        *matches
            .get_one::<u64>("wait-timeout-ms")
            .expect("defaulted by clap"),
    );
    let waited = match store
        .wait_for_principal(&created.request.id, &principal, wait_timeout)
        .await
    {
        Ok(waited) => waited,
        Err(error) => return print_jit_store_error(error),
    };
    if waited.request.status != voidb_core::AgentAuthorizationRequestStatus::Approved {
        return print_agent_exec_request_status(
            waited.request,
            &created.review_command,
            created.deduplicated,
            waited.timed_out,
        );
    }

    let Some(grant_id) = waited.request.grant_id.as_deref() else {
        return print_jit_error(
            JIT_EXIT_BROKER_OFFLINE,
            "broker_offline",
            "authorization was approved without an active grant binding",
            Some(1_000),
        );
    };
    let Some(grant) = load_grants(true)?
        .into_iter()
        .find(|grant| grant.id == grant_id)
    else {
        return print_jit_error(
            JIT_EXIT_BROKER_OFFLINE,
            "broker_offline",
            "authorization was approved but its broker is unavailable",
            Some(1_000),
        );
    };
    if !grant_matches_agent_exec_principal(&grant, Some(&principal))?
        || command_allowed(&grant, &argv).is_err()
        || inspect_grant(&grant).await.broker_health != AgentBrokerHealth::Online
    {
        return print_jit_error(
            JIT_EXIT_BROKER_OFFLINE,
            "broker_offline",
            "the approved grant could not safely execute this request",
            Some(1_000),
        );
    }
    execute_granted_command(grant, argv).await
}

pub(super) fn parse_agent_exec_input(matches: &ArgMatches) -> anyhow::Result<Value> {
    let raw = matches
        .get_one::<String>("input-json")
        .expect("defaulted by clap");
    serde_json::from_str(raw).context("parse --input-json JSON")
}

pub(super) fn agent_exec_argv(
    matches: &ArgMatches,
    capability: &str,
    profile_id: &str,
    input: &Value,
) -> Vec<String> {
    let mut argv = vec![
        "invoke".into(),
        "run".into(),
        capability.into(),
        "--profile".into(),
        format!("id:{profile_id}"),
        "--input-json".into(),
        input.to_string(),
        "--format".into(),
        "json".into(),
    ];
    if let Some(timeout_ms) = matches.get_one::<u64>("timeout-ms") {
        argv.extend(["--timeout-ms".into(), timeout_ms.to_string()]);
    }
    if let Some(page_limit) = matches.get_one::<u32>("page-limit") {
        argv.extend(["--page-limit".into(), page_limit.to_string()]);
    }
    if let Some(page_cursor) = matches.get_one::<String>("page-cursor") {
        argv.extend(["--page-cursor".into(), page_cursor.clone()]);
    }
    if matches.get_flag("dry-run") {
        argv.push("--dry-run".into());
    }
    if matches.get_flag("yes") {
        argv.push("--yes".into());
    }
    argv
}

pub(super) fn agent_exec_principal(matches: &ArgMatches) -> anyhow::Result<Option<AgentPrincipal>> {
    let explicit_client = matches.get_one::<String>("client-id").cloned();
    let explicit_task = matches.get_one::<String>("task-id").cloned();
    let explicit_instance = matches.get_one::<String>("instance-id").cloned();
    if explicit_client.is_some() || explicit_task.is_some() || explicit_instance.is_some() {
        let principal = AgentPrincipal {
            client_id: explicit_client
                .ok_or_else(|| anyhow!("--client-id and --task-id must be provided together"))?,
            task_id: explicit_task
                .ok_or_else(|| anyhow!("--client-id and --task-id must be provided together"))?,
            instance_id: explicit_instance,
        };
        principal.validate().map_err(|error| anyhow!(error))?;
        return Ok(Some(principal));
    }

    let environment_client = nonempty_env(AGENT_CLIENT_ID_ENV);
    let environment_task = nonempty_env(AGENT_TASK_ID_ENV);
    let environment_instance = nonempty_env(AGENT_INSTANCE_ID_ENV);
    if environment_client.is_some() || environment_task.is_some() || environment_instance.is_some()
    {
        let principal = AgentPrincipal {
            client_id: environment_client.ok_or_else(|| {
                anyhow!("{AGENT_CLIENT_ID_ENV} and {AGENT_TASK_ID_ENV} must be set together")
            })?,
            task_id: environment_task.ok_or_else(|| {
                anyhow!("{AGENT_CLIENT_ID_ENV} and {AGENT_TASK_ID_ENV} must be set together")
            })?,
            instance_id: environment_instance,
        };
        principal.validate().map_err(|error| anyhow!(error))?;
        return Ok(Some(principal));
    }

    if let Some(thread_id) = nonempty_env(AGENT_THREAD_ID_ENV) {
        let principal = AgentPrincipal {
            client_id: "agent".into(),
            task_id: thread_id,
            instance_id: None,
        };
        principal.validate().map_err(|error| anyhow!(error))?;
        return Ok(Some(principal));
    }
    Ok(None)
}

fn nonempty_env(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
}

pub(super) fn exact_agent_exec_scope(
    plugin_id: &str,
    capability: &str,
    input: Value,
) -> anyhow::Result<(AgentAuthorizationScope, voidb_core::CapabilityRiskLevel)> {
    let definitions =
        resolved_authorization_capabilities(Some(plugin_id)).map_err(|error| anyhow!(error))?;
    let definition = definitions
        .iter()
        .find(|definition| definition.qualified_id() == capability)
        .ok_or_else(|| anyhow!("capability has no current authorization declaration"))?;
    if !matches!(
        definition.authorization.jit_support(),
        voidb_core::CapabilityJitSupport::Supported
    ) {
        bail!("capability does not support JIT authorization");
    }
    if voidb_core::collect_redaction_targets(&input)
        .iter()
        .any(|target| matches!(target.kind, voidb_core::RedactionTargetKind::Credential(_)))
    {
        bail!("authorization requests cannot persist credential-bearing input fields");
    }
    let operation = normalize_agent_operation(capability, input)?;
    let scope = AgentAuthorizationScope::ExactInvocation {
        capability_id: operation.capability_id,
        normalized_input: operation.input,
        invocation_fingerprint: operation.fingerprint,
    };
    validate_declared_jit_scope(definition, &scope)?;
    Ok((scope, definition.effective_risk()))
}

async fn find_agent_exec_grant(
    argv: &[String],
    principal: Option<&AgentPrincipal>,
) -> anyhow::Result<Option<AgentGrantFile>> {
    let mut candidates = Vec::new();
    for grant in load_grants(true)? {
        if command_allowed(&grant, argv).is_err()
            || !grant_matches_agent_exec_principal(&grant, principal)?
            || inspect_grant(&grant).await.broker_health != AgentBrokerHealth::Online
        {
            continue;
        }
        candidates.push(grant);
    }
    candidates.sort_by_key(|grant| {
        (
            grant.principal_fingerprint.is_none(),
            grant.authorization_scopes.is_empty(),
            grant.expires_at,
        )
    });
    Ok(candidates.into_iter().next())
}

pub(super) fn grant_matches_agent_exec_principal(
    grant: &AgentGrantFile,
    principal: Option<&AgentPrincipal>,
) -> anyhow::Result<bool> {
    match grant.principal_fingerprint.as_deref() {
        None => Ok(true),
        Some(expected) => Ok(principal
            .map(AgentPrincipal::fingerprint)
            .transpose()?
            .as_deref()
            == Some(expected)),
    }
}

fn print_agent_exec_authorization_required(
    profile_name: &str,
    plugin_id: &str,
    capability: &str,
    identity_missing: bool,
) -> anyhow::Result<i32> {
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "ok": false,
            "data": {
                "profile": profile_name,
                "plugin": plugin_id,
                "capability": capability,
                "quick_authorize": {
                    "tui": "Select this profile in the Connection Manager, press a, then confirm read-only access.",
                    "cli_args": [
                        "voidb-cli", "agent", "authorize", "--profile", profile_name,
                        "--plugin", plugin_id
                    ]
                }
            },
            "error": {
                "code": if identity_missing { "agent_identity_required" } else { "authorization_required" },
                "message": if identity_missing {
                    "No active grant permits this operation, and no stable agent identity is available for automatic JIT approval."
                } else {
                    "No active grant permits this operation."
                }
            }
        }))?
    );
    Ok(JIT_EXIT_PENDING)
}

pub(super) fn agent_exec_review_prompt(
    plugin_id: &str,
    profile_name: &str,
    review_command: &str,
) -> String {
    format!(
        "Authorization required for {}/{}.\nApprove from a local terminal (the password prompt hides input):\n  {}\nOr open the Connection Manager approval inbox (p).",
        sanitize_terminal_text(plugin_id),
        sanitize_terminal_text(profile_name),
        sanitize_terminal_text(review_command),
    )
}

fn print_agent_exec_request_status(
    request: voidb_core::FrontendAuthorizationRequest,
    review_command: &str,
    deduplicated: bool,
    timed_out: bool,
) -> anyhow::Result<i32> {
    use voidb_core::AgentAuthorizationRequestStatus as Status;
    let (exit_code, code, message) = match request.status {
        Status::Pending => (
            JIT_EXIT_PENDING,
            "authorization_required",
            if timed_out {
                "Authorization is still pending. Run data.review_command in a local terminal for an interactive hidden password prompt, or use the Connection Manager approval inbox."
            } else {
                "Authorization is required. Run data.review_command in a local terminal for an interactive hidden password prompt, or use the Connection Manager approval inbox."
            },
        ),
        Status::Denied if request.timed_out => (
            JIT_EXIT_DENIED,
            "timed_out",
            "Authorization request timed out and was automatically denied.",
        ),
        Status::Denied => (JIT_EXIT_DENIED, "denied", "Authorization was denied."),
        Status::Expired => (
            JIT_EXIT_EXPIRED,
            "expired",
            "Authorization request expired.",
        ),
        Status::Cancelled => (
            JIT_EXIT_CANCELLED,
            "cancelled",
            "Authorization request was cancelled.",
        ),
        Status::Superseded => (
            JIT_EXIT_SUPERSEDED,
            "superseded",
            "Authorization request was superseded.",
        ),
        Status::Approved => (
            JIT_EXIT_BROKER_OFFLINE,
            "broker_offline",
            "Authorization was approved but execution could not start.",
        ),
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "ok": false,
            "data": {
                "request": request,
                "review_command": review_command,
                "deduplicated": deduplicated,
                "timed_out": timed_out,
            },
            "error": { "code": code, "message": message }
        }))?
    );
    Ok(exit_code)
}

async fn run_granted(matches: &ArgMatches) -> anyhow::Result<i32> {
    ensure_unix()?;
    let argv = matches
        .get_many::<String>("command")
        .expect("required by clap")
        .cloned()
        .collect::<Vec<_>>();
    let grants = load_grants(true)?;
    let grant = if let Some(id) = matches.get_one::<String>("grant") {
        grants
            .into_iter()
            .find(|grant| grant.id == *id)
            .ok_or_else(|| anyhow!("active agent grant '{id}' was not found"))?
    } else {
        let matches = grants
            .into_iter()
            .filter(|grant| command_allowed(grant, &argv).is_ok())
            .collect::<Vec<_>>();
        match matches.as_slice() {
            [grant] => grant.clone(),
            [] => bail!("no active agent grant permits this command"),
            _ => bail!("multiple grants permit this command; pass --grant <grant-id>"),
        }
    };
    ensure_grant_principal(&grant, matches)?;
    command_allowed(&grant, &argv)?;
    execute_granted_command(grant, argv).await
}

async fn execute_granted_command(grant: AgentGrantFile, argv: Vec<String>) -> anyhow::Result<i32> {
    let response = send_request(
        &grant,
        BrokerRequest::Run {
            token: grant.token.clone(),
            argv,
        },
    )
    .await?;
    print!("{}", response.stdout);
    std::io::stdout().flush()?;
    eprint!("{}", response.stderr);
    if let Some(error) = response.error {
        eprintln!("Agent broker rejected command: {error}");
    }
    Ok(response.exit_code)
}
