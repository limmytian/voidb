#![cfg_attr(not(unix), allow(unused_imports))]

use crate::builtin::invoke::resolved_authorization_capabilities;
use crate::jit_authorization::{
    CreateAuthorizationRequest, JitAuthorizationStore, JitAuthorizationStoreError,
};
use anyhow::{Context, anyhow, bail};
use chrono::{DateTime, Utc};
use clap::{Arg, ArgAction, ArgMatches, Command};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::{BufRead, IsTerminal, Write};
use std::path::PathBuf;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use uuid::Uuid;
use voidb_core::{
    AgentAuthorizationPresetKind, AgentAuthorizationRequest, AgentAuthorizationScope,
    AgentGrantAmendment, AgentGrantRevision, AgentPrincipal, AppConfig, AuditOperation,
    CapabilityDefinition, CapabilityExecutionMode, ConnectionProfile, FrontendAgentGrant,
    LocalProfileStore, authorize_normalized_operation, normalize_agent_operation,
};

use super::GRANT_VERSION;
use super::audit::append_agent_audit;
use super::commands::{
    inspect_grant, resolve_profile, spawn_agent_broker, verify_profile_credentials,
};
use super::ledger::AgentGrantFile;
use super::runtime::{ensure_unix, grant_path_for_id, load_grants, shutdown_grant, write_grant};

pub(super) fn jit_request_command() -> Command {
    Command::new("request")
        .about("Request, inspect, wait for, cancel, or locally review JIT authorization")
        .subcommand_required(true)
        .subcommand(with_principal_args(
            Command::new("create")
                .about("Create a short-lived authorization request (JSON output)")
                .arg(Arg::new("profile").long("profile").short('p').required(true))
                .arg(Arg::new("plugin").long("plugin").required(true))
                .arg(Arg::new("capability").long("capability").short('c').required(true))
                .arg(
                    Arg::new("scope")
                        .long("scope")
                        .required(true)
                        .value_parser(["capability", "constrained", "exact"]),
                )
                .arg(
                    Arg::new("input-json")
                        .long("input-json")
                        .required_if_eq("scope", "exact")
                        .conflicts_with("constraints-json"),
                )
                .arg(
                    Arg::new("constraints-json")
                        .long("constraints-json")
                        .required_if_eq("scope", "constrained")
                        .conflicts_with("input-json"),
                )
                .arg(
                    Arg::new("purpose")
                        .long("purpose")
                        .visible_alias("reason")
                        .required(true)
                        .help("Specific intended use shown to the user during review"),
                )
                .arg(
                    Arg::new("ttl-seconds")
                        .long("ttl-seconds")
                        .short('t')
                        .default_value("300")
                        .value_parser(clap::value_parser!(u64)),
                ),
        ))
        .subcommand(with_principal_args(
            Command::new("get")
                .about("Get the safe canonical status of one request")
                .arg(Arg::new("request-id").required(true)),
        ))
        .subcommand(with_principal_args(Command::new("list").about(
            "List safe requests belonging to the authenticated principal",
        )))
        .subcommand(with_principal_args(
            Command::new("wait")
                .about("Wait for a terminal decision with a bounded timeout")
                .arg(Arg::new("request-id").required(true))
                .arg(
                    Arg::new("timeout-ms")
                        .long("timeout-ms")
                        .default_value("30000")
                        .value_parser(clap::value_parser!(u64)),
                ),
        ))
        .subcommand(with_principal_args(
            Command::new("cancel")
                .about("Cancel the principal's own pending request")
                .arg(Arg::new("request-id").required(true)),
        ))
        .subcommand(
            Command::new("inbox")
                .alias("in")
                .about("List the canonical secret-free local approval inbox and grant revisions")
                .arg(
                    Arg::new("format")
                        .long("format")
                        .short('f')
                        .default_value("json")
                        .value_parser(["json", "table"])
                        .help("Output format; json is stable for agents, table is human-readable"),
                ),
        )
        .subcommand(
            Command::new("decide")
                .about(
                    "Apply one local frontend approval decision; prompts for the hidden master password on a TTY, or reads --password-stdin for automation",
                )
                .arg(Arg::new("request-id").required(true))
                .arg(
                    Arg::new("decision")
                        .long("decision")
                        .required(true)
                        .value_parser(["deny", "once", "bounded", "add_to_grant"]),
                )
                .arg(Arg::new("reason").long("reason"))
                .arg(
                    Arg::new("ttl-seconds")
                        .long("ttl-seconds")
                        .short('t')
                        .default_value("900")
                        .value_parser(clap::value_parser!(u64)),
                )
                .arg(
                    Arg::new("uses")
                        .long("uses")
                        .value_parser(clap::value_parser!(u32))
                        .help("Optional accepted-command limit; omit for time-only access"),
                )
                .arg(Arg::new("grant").long("grant"))
                .arg(
                    Arg::new("ttl-delta-seconds")
                        .long("ttl-delta-seconds")
                        .default_value("0")
                        .value_parser(clap::value_parser!(u64)),
                )
                .arg(
                    Arg::new("uses-delta")
                        .long("uses-delta")
                        .default_value("0")
                        .value_parser(clap::value_parser!(u32)),
                )
                .arg(
                    Arg::new("constraints-json")
                        .long("constraints-json")
                        .help("Non-secret declarative narrowing constraints"),
                )
                .arg(
                    Arg::new("password-stdin")
                        .long("password-stdin")
                        .action(ArgAction::SetTrue)
                        .hide(true),
                ),
        )
        .subcommand(
            Command::new("review")
                .about("Review canonical details and decide locally through a TTY")
                .arg(Arg::new("request-id").required(true)),
        )
}

fn with_principal_args(command: Command) -> Command {
    command
        .arg(Arg::new("client-id").long("client-id").required(true))
        .arg(Arg::new("task-id").long("task-id").required(true))
        .arg(Arg::new("instance-id").long("instance-id"))
}

pub(super) fn with_optional_principal_args(command: Command) -> Command {
    command
        .arg(Arg::new("client-id").long("client-id").global(true))
        .arg(Arg::new("task-id").long("task-id").global(true))
        .arg(Arg::new("instance-id").long("instance-id").global(true))
}

pub(super) fn with_hidden_optional_principal_args(command: Command) -> Command {
    command
        .arg(
            Arg::new("client-id")
                .long("client-id")
                .global(true)
                .hide(true),
        )
        .arg(Arg::new("task-id").long("task-id").global(true).hide(true))
        .arg(
            Arg::new("instance-id")
                .long("instance-id")
                .global(true)
                .hide(true),
        )
}

pub(super) const JIT_EXIT_PENDING: i32 = 10;
pub(super) const JIT_EXIT_DENIED: i32 = 11;
pub(super) const JIT_EXIT_EXPIRED: i32 = 12;
pub(super) const JIT_EXIT_CANCELLED: i32 = 13;
pub(super) const JIT_EXIT_SUPERSEDED: i32 = 14;
pub(super) const JIT_EXIT_BROKER_OFFLINE: i32 = 15;
const JIT_EXIT_RATE_LIMITED: i32 = 16;
pub(super) const JIT_EXIT_INVALID: i32 = 17;
const JIT_EXIT_CONFLICT: i32 = 18;

pub(super) async fn run_jit_request_command(matches: &ArgMatches) -> anyhow::Result<i32> {
    let (operation, matches) = matches
        .subcommand()
        .expect("request command requires an operation");
    if operation == "review" {
        return review_jit_request(
            matches
                .get_one::<String>("request-id")
                .expect("required by clap"),
        )
        .await;
    }
    let store = match JitAuthorizationStore::default_store() {
        Ok(store) => store,
        Err(error) => return print_jit_store_error(error),
    };
    if operation == "inbox" {
        return print_jit_review_inbox(&store, matches);
    }
    if operation == "decide" {
        return decide_jit_request(&store, matches).await;
    }
    let principal = principal_from_matches(matches);
    let principal = match principal.and_then(|principal| {
        principal
            .validate()
            .map(|_| principal)
            .map_err(|error| anyhow!(error))
    }) {
        Ok(principal) => principal,
        Err(error) => {
            return print_jit_error(
                JIT_EXIT_INVALID,
                "invalid_principal",
                &error.to_string(),
                None,
            );
        }
    };

    match operation {
        "create" => create_jit_request(&store, matches, principal),
        "get" => {
            let id = matches
                .get_one::<String>("request-id")
                .expect("required by clap");
            match store.get_for_principal(id, &principal, Utc::now()) {
                Ok(request) => print_jit_request_status(request, false),
                Err(error) => print_jit_store_error(error),
            }
        }
        "list" => match store.list_for_principal(&principal, Utc::now()) {
            Ok(requests) => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "ok": true,
                        "data": { "requests": requests, "count": requests.len() }
                    }))?
                );
                Ok(0)
            }
            Err(error) => print_jit_store_error(error),
        },
        "wait" => {
            let id = matches
                .get_one::<String>("request-id")
                .expect("required by clap");
            let timeout = Duration::from_millis(
                *matches
                    .get_one::<u64>("timeout-ms")
                    .expect("defaulted by clap"),
            );
            match store.wait_for_principal(id, &principal, timeout).await {
                Ok(result) => print_jit_request_status(result.request, result.timed_out),
                Err(error) => print_jit_store_error(error),
            }
        }
        "cancel" => {
            let id = matches
                .get_one::<String>("request-id")
                .expect("required by clap");
            match store.cancel(id, &principal, Utc::now()) {
                Ok(request) => print_jit_request_status(request, false),
                Err(error) => print_jit_store_error(error),
            }
        }
        _ => unreachable!("clap enforces request operations"),
    }
}

/// Human-readable request table for `agent request inbox --format table`.
fn jit_inbox_table(
    requests: &[voidb_core::FrontendAuthorizationRequest],
    now: DateTime<Utc>,
) -> String {
    let mut lines = vec!["ID\tSTATUS\tRISK\tPLUGIN\tPROFILE\tPURPOSE\tEXPIRES".to_string()];
    for request in requests {
        lines.push(format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}",
            short_request_id(&request.id),
            request_status_label(&request.status),
            crate::agent_broker::commands::capability_risk_name(request.risk),
            crate::agent_broker::commands::sanitize_table_cell(&request.plugin_id),
            crate::agent_broker::commands::sanitize_table_cell(&request.profile_id),
            truncate_cell(&request.purpose, 48),
            crate::agent_broker::commands::relative_expiry(request.expires_at, now),
        ));
    }
    lines.join("\n")
}

/// Short request id for humans: the segment after the prefix, truncated.
pub(super) fn short_request_id(id: &str) -> String {
    let tail = id.rsplit(':').next().unwrap_or(id);
    let mut tail = tail.to_string();
    if tail.len() > 13 {
        tail.truncate(13);
        tail.push('\u{2026}');
    }
    tail
}

fn truncate_cell(value: &str, max: usize) -> String {
    let mut value: String = value.chars().take(max).collect();
    if value.chars().count() >= max {
        value.push('\u{2026}');
    }
    crate::agent_broker::commands::sanitize_table_cell(&value)
}

fn request_status_label(status: &voidb_core::AgentAuthorizationRequestStatus) -> &'static str {
    use voidb_core::AgentAuthorizationRequestStatus as Status;
    match status {
        Status::Pending => "PENDING",
        Status::Approved => "APPROVED",
        Status::Denied => "DENIED",
        Status::Expired => "EXPIRED",
        Status::Cancelled => "CANCELLED",
        Status::Superseded => "SUPERSEDED",
    }
}

fn print_jit_review_inbox(
    store: &JitAuthorizationStore,
    matches: &ArgMatches,
) -> anyhow::Result<i32> {
    let requests = match store.list_for_review(Utc::now()) {
        Ok(requests) => requests,
        Err(error) => return print_jit_store_error(error),
    };
    let revisions = match store.list_revisions() {
        Ok(revisions) => revisions,
        Err(error) => return print_jit_store_error(error),
    };
    let pending_count = requests
        .iter()
        .filter(|request| request.status == voidb_core::AgentAuthorizationRequestStatus::Pending)
        .count();
    if matches.get_one::<String>("format").map(String::as_str) == Some("table") {
        println!("{}", jit_inbox_table(&requests, Utc::now()));
        return Ok(0);
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "ok": true,
            "data": {
                "requests": requests,
                "revisions": revisions,
                "pending_count": pending_count,
                "observed_at": Utc::now(),
            }
        }))?
    );
    Ok(0)
}

async fn decide_jit_request(
    store: &JitAuthorizationStore,
    matches: &ArgMatches,
) -> anyhow::Result<i32> {
    let request_id = matches
        .get_one::<String>("request-id")
        .expect("required by clap");
    let request = match store.get_for_review(request_id, Utc::now()) {
        Ok(request) => request,
        Err(error) => return print_jit_store_error(error),
    };
    if request.status != voidb_core::AgentAuthorizationRequestStatus::Pending {
        return print_jit_request_status(
            voidb_core::FrontendAuthorizationRequest::try_from(&request)?,
            false,
        );
    }
    let decision = matches
        .get_one::<String>("decision")
        .expect("required by clap")
        .as_str();
    // One-command approvals: an interactive terminal prompts for the hidden
    // master password in place; automation keeps the --password-stdin path.
    let mut password = if matches.get_flag("password-stdin") {
        let mut password = String::new();
        tokio::io::stdin().read_to_string(&mut password).await?;
        password
    } else if std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
        rpassword::prompt_password("VoidB master password: ")?
    } else {
        return print_jit_error(
            JIT_EXIT_INVALID,
            "authentication_required",
            &format!(
                "frontend decisions need the master password on standard input (--password-stdin) or an interactive terminal; run 'vb agent request decide {request_id} ...' in a local terminal, or 'vb agent request review {request_id}' for the guided flow"
            ),
            None,
        );
    };
    if password.is_empty() {
        return print_jit_error(
            JIT_EXIT_INVALID,
            "authentication_failed",
            "master password is required",
            None,
        );
    }
    if AppConfig::load_with_password(Some(&password)).is_err() {
        password.clear();
        return print_jit_error(
            JIT_EXIT_INVALID,
            "authentication_failed",
            "master password verification failed",
            None,
        );
    }
    if decision == "deny" {
        let reason = matches
            .get_one::<String>("reason")
            .cloned()
            .unwrap_or_else(|| "Denied from Connection Manager".into());
        let denied = match store.deny(request_id, reason, Utc::now()) {
            Ok(request) => request,
            Err(error) => {
                password.clear();
                return print_jit_store_error(error);
            }
        };
        password.clear();
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({
                "ok": true,
                "data": { "request": denied }
            }))?
        );
        return Ok(0);
    }

    let mut approved_scope = request.scope.clone();
    if let Some(raw) = matches.get_one::<String>("constraints-json") {
        let additional: BTreeMap<String, Value> = match serde_json::from_str(raw) {
            Ok(value) => value,
            Err(error) => {
                return print_jit_error(
                    JIT_EXIT_INVALID,
                    "invalid_constraints",
                    &format!("constraints must be a JSON object: {error}"),
                    None,
                );
            }
        };
        let capability_id = request.scope.capability_id().to_string();
        approved_scope = match &request.scope {
            AgentAuthorizationScope::Capability { .. } => AgentAuthorizationScope::Constrained {
                capability_id,
                constraints: additional,
            },
            AgentAuthorizationScope::Constrained { constraints, .. } => {
                let mut narrowed = constraints.clone();
                for (path, value) in additional {
                    if narrowed.insert(path.clone(), value).is_some() {
                        return print_jit_error(
                            JIT_EXIT_INVALID,
                            "scope_widening",
                            &format!("requested constraint '{path}' cannot be replaced"),
                            None,
                        );
                    }
                }
                AgentAuthorizationScope::Constrained {
                    capability_id,
                    constraints: narrowed,
                }
            }
            AgentAuthorizationScope::ExactInvocation { .. } if additional.is_empty() => {
                request.scope.clone()
            }
            AgentAuthorizationScope::ExactInvocation { .. } => {
                return print_jit_error(
                    JIT_EXIT_INVALID,
                    "scope_widening",
                    "exact invocations cannot be changed during approval",
                    None,
                );
            }
        };
    }
    if !request.scope.can_narrow_to(&approved_scope) {
        return print_jit_error(
            JIT_EXIT_INVALID,
            "scope_widening",
            "approved scope must be equal to or narrower than the request",
            None,
        );
    }
    let definitions = match resolved_authorization_capabilities(Some(&request.plugin_id)) {
        Ok(definitions) => definitions,
        Err(error) => return print_jit_error(JIT_EXIT_INVALID, "invalid_scope", &error, None),
    };
    let Some(definition) = definitions
        .iter()
        .find(|definition| definition.qualified_id() == request.scope.capability_id())
    else {
        return print_jit_error(
            JIT_EXIT_INVALID,
            "invalid_scope",
            "capability authorization declaration is no longer available",
            None,
        );
    };
    if let Err(error) = validate_declared_jit_scope(definition, &approved_scope) {
        return print_jit_error(JIT_EXIT_INVALID, "invalid_scope", &error.to_string(), None);
    }

    let amendment = match decision {
        "once" => AgentGrantAmendment::Once,
        "bounded" => AgentGrantAmendment::Bounded {
            ttl_seconds: *matches
                .get_one::<u64>("ttl-seconds")
                .expect("defaulted by clap"),
            uses: matches.get_one::<u32>("uses").copied(),
        },
        "add_to_grant" => {
            let Some(grant_id) = matches.get_one::<String>("grant") else {
                return print_jit_error(
                    JIT_EXIT_INVALID,
                    "invalid_amendment",
                    "add_to_grant requires --grant",
                    None,
                );
            };
            AgentGrantAmendment::AddToGrant {
                grant_id: grant_id.clone(),
                ttl_delta_seconds: *matches
                    .get_one::<u64>("ttl-delta-seconds")
                    .expect("defaulted by clap"),
                uses_delta: *matches
                    .get_one::<u32>("uses-delta")
                    .expect("defaulted by clap"),
            }
        }
        _ => unreachable!("clap validates decisions"),
    };

    let profile_store = LocalProfileStore::default_store()?;
    let profile = resolve_profile(
        &profile_store.load_profiles()?,
        &request.profile_id,
        &request.plugin_id,
    );
    if profile
        .and_then(|profile| verify_profile_credentials(&profile_store, &profile, &password))
        .is_err()
    {
        password.clear();
        return print_jit_error(
            JIT_EXIT_INVALID,
            "authentication_failed",
            "master password or target profile credential verification failed",
            None,
        );
    }

    let revision = match store.approve(request_id, approved_scope, amendment, Utc::now()) {
        Ok(revision) => revision,
        Err(error) => {
            password.clear();
            return print_jit_store_error(error);
        }
    };
    let scopes = store.effective_scopes(&revision.grant_id)?;
    let activation = activate_jit_revision(&request, &revision, scopes, &password).await;
    password.clear();
    let grant = match activation {
        Ok(grant) => grant,
        Err(error) => {
            return print_jit_error(
                JIT_EXIT_BROKER_OFFLINE,
                "broker_offline",
                &format!("approval was recorded but broker activation failed: {error}"),
                Some(1_000),
            );
        }
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "ok": true,
            "data": { "revision": revision, "grant": grant }
        }))?
    );
    Ok(0)
}

fn principal_from_matches(matches: &ArgMatches) -> anyhow::Result<AgentPrincipal> {
    Ok(AgentPrincipal {
        client_id: matches
            .get_one::<String>("client-id")
            .expect("required by clap")
            .clone(),
        task_id: matches
            .get_one::<String>("task-id")
            .expect("required by clap")
            .clone(),
        instance_id: matches.get_one::<String>("instance-id").cloned(),
    })
}

fn create_jit_request(
    store: &JitAuthorizationStore,
    matches: &ArgMatches,
    principal: AgentPrincipal,
) -> anyhow::Result<i32> {
    let plugin_id = matches
        .get_one::<String>("plugin")
        .expect("required by clap");
    let capability_id = matches
        .get_one::<String>("capability")
        .expect("required by clap");
    if capability_id.split_once('.').map(|(plugin, _)| plugin) != Some(plugin_id.as_str()) {
        return print_jit_error(
            JIT_EXIT_INVALID,
            "binding_mismatch",
            "qualified capability does not belong to --plugin",
            None,
        );
    }
    let definitions = match resolved_authorization_capabilities(Some(plugin_id)) {
        Ok(definitions) => definitions,
        Err(error) => {
            return print_jit_error(JIT_EXIT_INVALID, "unsupported_capability", &error, None);
        }
    };
    let Some(definition) = definitions
        .iter()
        .find(|definition| definition.qualified_id() == *capability_id)
    else {
        return print_jit_error(
            JIT_EXIT_INVALID,
            "unsupported_capability",
            "capability has no current authorization declaration",
            None,
        );
    };
    if !matches!(
        definition.authorization.jit_support(),
        voidb_core::CapabilityJitSupport::Supported
    ) {
        return print_jit_error(
            JIT_EXIT_INVALID,
            "unsupported_capability",
            "capability does not support JIT authorization",
            None,
        );
    }
    let scope = match matches
        .get_one::<String>("scope")
        .expect("required by clap")
        .as_str()
    {
        "capability" => AgentAuthorizationScope::Capability {
            capability_id: capability_id.clone(),
        },
        "constrained" => {
            let raw = matches
                .get_one::<String>("constraints-json")
                .expect("required by clap");
            let constraints: BTreeMap<String, Value> = match serde_json::from_str(raw) {
                Ok(constraints) => constraints,
                Err(error) => {
                    return print_jit_error(
                        JIT_EXIT_INVALID,
                        "invalid_constraints",
                        &format!("constraints must be a JSON object: {error}"),
                        None,
                    );
                }
            };
            AgentAuthorizationScope::Constrained {
                capability_id: capability_id.clone(),
                constraints,
            }
        }
        "exact" => {
            let raw = matches
                .get_one::<String>("input-json")
                .expect("required by clap");
            let input: Value = match serde_json::from_str(raw) {
                Ok(input) => input,
                Err(error) => {
                    return print_jit_error(
                        JIT_EXIT_INVALID,
                        "invalid_input",
                        &format!("input must be valid JSON: {error}"),
                        None,
                    );
                }
            };
            if voidb_core::collect_redaction_targets(&input)
                .iter()
                .any(|target| matches!(target.kind, voidb_core::RedactionTargetKind::Credential(_)))
            {
                return print_jit_error(
                    JIT_EXIT_INVALID,
                    "secret_input_forbidden",
                    "authorization requests cannot persist credential-bearing input fields",
                    None,
                );
            }
            let operation = match normalize_agent_operation(capability_id, input) {
                Ok(operation) => operation,
                Err(error) => {
                    return print_jit_error(
                        JIT_EXIT_INVALID,
                        "invalid_input",
                        &error.to_string(),
                        None,
                    );
                }
            };
            AgentAuthorizationScope::ExactInvocation {
                capability_id: operation.capability_id,
                normalized_input: operation.input,
                invocation_fingerprint: operation.fingerprint,
            }
        }
        _ => unreachable!("clap validates scope"),
    };
    if let Err(error) = validate_declared_jit_scope(definition, &scope) {
        return print_jit_error(JIT_EXIT_INVALID, "invalid_scope", &error.to_string(), None);
    }
    let ttl_seconds = *matches
        .get_one::<u64>("ttl-seconds")
        .expect("defaulted by clap");
    let profile_id = matches
        .get_one::<String>("profile")
        .expect("required by clap")
        .strip_prefix("id:")
        .unwrap_or_else(|| matches.get_one::<String>("profile").unwrap())
        .to_string();
    let now = Utc::now();
    match store.create(
        CreateAuthorizationRequest {
            principal,
            profile_id,
            plugin_id: plugin_id.clone(),
            scope,
            risk: definition.effective_risk(),
            purpose: matches
                .get_one::<String>("purpose")
                .expect("required by clap")
                .clone(),
            expires_at: now + chrono::Duration::seconds(ttl_seconds as i64),
        },
        now,
    ) {
        Ok(result) => {
            println!(
                "{}",
                serde_json::to_string_pretty(&json!({ "ok": true, "data": result }))?
            );
            Ok(JIT_EXIT_PENDING)
        }
        Err(error) => print_jit_store_error(error),
    }
}

pub(super) fn validate_declared_jit_scope(
    definition: &CapabilityDefinition,
    scope: &AgentAuthorizationScope,
) -> anyhow::Result<()> {
    if !definition.supports_stateless_execution() {
        bail!(
            "capability '{}' is session-only; JIT agent exec grants are stateless. Use an explicit --execution-mode session_only proactive grant and the declared session handoff",
            definition.qualified_id()
        );
    }
    match scope {
        AgentAuthorizationScope::Capability { .. } => {
            if !definition.authorization.capability_wide_allowed {
                bail!("capability-wide approval is disabled by the plugin declaration");
            }
        }
        AgentAuthorizationScope::Constrained { constraints, .. } => {
            let schema = definition
                .authorization
                .approval_schema
                .as_ref()
                .ok_or_else(|| anyhow!("capability has no structured approval schema"))?;
            schema.validate().map_err(|error| anyhow!(error))?;
            for path in constraints.keys() {
                if !schema.fields.iter().any(|field| field.path == *path) {
                    bail!("constraint path '{path}' is not declared by the plugin");
                }
            }
            for field in schema.fields.iter().filter(|field| field.required) {
                if !constraints.contains_key(&field.path) {
                    bail!("required constraint '{}' is missing", field.path);
                }
            }
        }
        AgentAuthorizationScope::ExactInvocation {
            capability_id,
            normalized_input,
            invocation_fingerprint,
        } => {
            let operation = normalize_agent_operation(capability_id, normalized_input.clone())?;
            if operation.fingerprint != *invocation_fingerprint {
                bail!("exact invocation fingerprint does not match normalized input");
            }
            authorize_normalized_operation(&definition.authorization, scope, &operation)?;
        }
    }
    Ok(())
}

fn print_jit_request_status(
    request: voidb_core::FrontendAuthorizationRequest,
    timed_out: bool,
) -> anyhow::Result<i32> {
    use voidb_core::AgentAuthorizationRequestStatus as Status;
    let request_timed_out = request.timed_out;
    let broker_offline = request.status == Status::Approved
        && request.grant_id.as_ref().is_some_and(|grant_id| {
            load_grants(false)
                .map(|grants| {
                    !grants
                        .iter()
                        .any(|grant| grant.id == *grant_id && grant.socket_path.exists())
                })
                .unwrap_or(true)
        });
    let (exit_code, error_code) = match request.status {
        Status::Pending => (JIT_EXIT_PENDING, timed_out.then_some("pending")),
        Status::Approved if broker_offline => (JIT_EXIT_BROKER_OFFLINE, Some("broker_offline")),
        Status::Approved => (0, None),
        Status::Denied if request_timed_out => (JIT_EXIT_DENIED, Some("timed_out")),
        Status::Denied => (JIT_EXIT_DENIED, Some("denied")),
        Status::Expired => (JIT_EXIT_EXPIRED, Some("expired")),
        Status::Cancelled => (JIT_EXIT_CANCELLED, Some("cancelled")),
        Status::Superseded => (JIT_EXIT_SUPERSEDED, Some("superseded")),
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "ok": error_code.is_none() || request.status == Status::Pending,
            "data": { "request": request, "timed_out": timed_out },
            "error": error_code.map(|code| json!({
                "code": code,
                "message": if request_timed_out {
                    "authorization request timed out and was automatically denied"
                } else if timed_out {
                    "authorization decision is still pending"
                } else {
                    "authorization request reached a terminal non-approved state"
                }
            }))
        }))?
    );
    Ok(exit_code)
}

pub(super) fn print_jit_store_error(error: JitAuthorizationStoreError) -> anyhow::Result<i32> {
    match error {
        JitAuthorizationStoreError::RateLimited { retry_after_ms }
        | JitAuthorizationStoreError::QueueFull { retry_after_ms }
        | JitAuthorizationStoreError::DenialCooldown { retry_after_ms } => {
            eprintln!(
                "throttled: try again in {}s (retry_after_ms={retry_after_ms})",
                (retry_after_ms / 1000).max(1)
            );
            print_jit_error(
                JIT_EXIT_RATE_LIMITED,
                "rate_limited",
                "authorization request is temporarily throttled",
                Some(retry_after_ms),
            )
        }
        JitAuthorizationStoreError::Io(_) | JitAuthorizationStoreError::Corrupt(_) => {
            print_jit_error(
                JIT_EXIT_BROKER_OFFLINE,
                "broker_offline",
                "local authorization broker state is unavailable",
                Some(1_000),
            )
        }
        JitAuthorizationStoreError::Contract(
            voidb_core::AgentAuthorizationError::AlreadyDecided,
        )
        | JitAuthorizationStoreError::Busy => print_jit_error(
            JIT_EXIT_CONFLICT,
            "decision_conflict",
            "authorization request was already decided or is being decided",
            Some(250),
        ),
        other => print_jit_error(
            JIT_EXIT_INVALID,
            "invalid_request",
            &other.to_string(),
            None,
        ),
    }
}

pub(super) fn print_jit_error(
    exit_code: i32,
    code: &str,
    message: &str,
    retry_after_ms: Option<u64>,
) -> anyhow::Result<i32> {
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "ok": false,
            "data": null,
            "error": {
                "code": code,
                "message": message,
                "retry_after_ms": retry_after_ms,
            }
        }))?
    );
    Ok(exit_code)
}

/// Interactive add-to-grant target selection: list the principal's grants on
/// the same profile and plugin numbered 1..n (Enter picks the first /
/// soonest-expiring), accept a number or a full grant id, and fall back to
/// manual entry when nothing is compatible.
fn prompt_existing_grant(request: &AgentAuthorizationRequest) -> anyhow::Result<String> {
    let fingerprint = request.principal.fingerprint()?;
    let compatible: Vec<AgentGrantFile> = load_grants(false)?
        .into_iter()
        .filter(|grant| {
            grant.profile_id == request.profile_id
                && grant.plugin_id == request.plugin_id
                && grant
                    .principal_fingerprint
                    .as_deref()
                    .is_none_or(|principal| principal == fingerprint)
        })
        .collect();
    if compatible.is_empty() {
        println!("No existing grants on this profile/principal; enter a grant id manually.");
        return prompt_tty_line("Existing logical grant ID: ");
    }
    println!("Existing grants on this profile:");
    for (index, grant) in compatible.iter().enumerate() {
        println!(
            "  {}. {} · expires {}",
            index + 1,
            grant.id,
            grant.expires_at.to_rfc3339()
        );
    }
    let entered = prompt_tty_line("Grant number (Enter for 1, or a full grant id): ")?;
    let entered = entered.trim();
    if entered.is_empty() {
        return Ok(compatible[0].id.clone());
    }
    if let Ok(index) = entered.parse::<usize>() {
        return compatible
            .get(index.wrapping_sub(1))
            .map(|grant| grant.id.clone())
            .ok_or_else(|| anyhow!("grant number {index} is not in the list"));
    }
    Ok(entered.to_string())
}

pub(super) async fn review_jit_request(request_id: &str) -> anyhow::Result<i32> {
    if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
        return print_jit_error(
            JIT_EXIT_INVALID,
            "tty_required",
            "local review requires an interactive controlling TTY",
            None,
        );
    }
    let store = match JitAuthorizationStore::default_store() {
        Ok(store) => store,
        Err(error) => return print_jit_store_error(error),
    };
    let request = match store.get_for_review(request_id, Utc::now()) {
        Ok(request) => request,
        Err(error) => return print_jit_store_error(error),
    };
    if request.status != voidb_core::AgentAuthorizationRequestStatus::Pending {
        return print_jit_request_status(
            voidb_core::FrontendAuthorizationRequest::try_from(&request)?,
            false,
        );
    }

    let profile_label = format_review_profile(&request.profile_id, &request.plugin_id);
    let principal_label = format_review_principal(&request.principal);
    let risk_label = format_review_risk(request.risk);
    let scope_summary = format_review_scope_summary(&request.scope);

    println!("==================================================");
    println!("          VoidB JIT Authorization Review          ");
    println!("==================================================");
    println!("Request:  {}", request.id);
    println!("Agent:    {}", principal_label);
    println!("Profile:  {}", profile_label);
    println!("Plugin:   {}", sanitize_terminal_text(&request.plugin_id));
    println!("Risk:     {}", risk_label);
    println!("Purpose:  {}", sanitize_terminal_text(&request.purpose));
    println!("Scope:    {}", scope_summary);
    println!("Expires:  {}", request.expires_at.to_rfc3339());
    println!("--------------------------------------------------");

    // Verify the master password before any decision is collected: a wrong
    // password must not throw away the whole decision flow.
    let mut password = rpassword::prompt_password("VoidB master password: ")?;
    if password.is_empty() {
        return print_jit_error(
            JIT_EXIT_INVALID,
            "authentication_failed",
            "master password is required",
            None,
        );
    }
    let verified = AppConfig::load_with_password(Some(&password));
    if verified.is_err() {
        password.clear();
        return print_jit_error(
            JIT_EXIT_INVALID,
            "authentication_failed",
            "master password verification failed",
            None,
        );
    }
    let profile_store = LocalProfileStore::default_store()?;
    let profile = resolve_profile(
        &profile_store.load_profiles()?,
        &request.profile_id,
        &request.plugin_id,
    );
    let credentials_verified =
        profile.and_then(|profile| verify_profile_credentials(&profile_store, &profile, &password));
    if credentials_verified.is_err() {
        password.clear();
        return print_jit_error(
            JIT_EXIT_INVALID,
            "authentication_failed",
            "master password or target profile credential verification failed",
            None,
        );
    }

    let action_str = prompt_tty_line(
        "Decision [b=time-bounded (recommended, Enter), o=once, a=add-to-grant, d=deny]: ",
    )?;
    let action = match parse_review_decision(&action_str) {
        Some(action) => action,
        None => {
            return print_jit_error(
                JIT_EXIT_INVALID,
                "invalid_decision",
                &format!("review decision '{action_str}' was not recognized; choose b, o, a, or d"),
                None,
            );
        }
    };
    if action == "d" {
        let reason = prompt_tty_line("Denial reason: ")?;
        let denied = match store.deny(request_id, reason, Utc::now()) {
            Ok(request) => request,
            Err(error) => return print_jit_store_error(error),
        };
        println!("Request {} denied.", denied.id);
        return Ok(0);
    }
    let amendment = match action {
        "o" => AgentGrantAmendment::Once,
        "b" => AgentGrantAmendment::Bounded {
            ttl_seconds: prompt_tty_number_with_default(
                "Grant TTL seconds (1-3600, Enter for default 300): ",
                300,
            )?,
            uses: prompt_tty_optional_number("Optional use limit (1-100, Enter for unlimited): ")?,
        },
        "a" => AgentGrantAmendment::AddToGrant {
            grant_id: prompt_existing_grant(&request)?,
            ttl_delta_seconds: prompt_tty_number_with_default(
                "TTL extension seconds (0 allowed, Enter for default 300): ",
                300,
            )?,
            uses_delta: prompt_tty_number_with_default(
                "Additional uses (0 allowed, Enter for default 0): ",
                0,
            )?,
        },
        _ => unreachable!(),
    };
    let approved_scope = prompt_narrowed_scope(&request.scope)?;
    if !request.scope.can_narrow_to(&approved_scope) {
        return print_jit_error(
            JIT_EXIT_INVALID,
            "scope_widening",
            "approved scope must be equal to or narrower than the request",
            None,
        );
    }
    let definitions = resolved_authorization_capabilities(Some(&request.plugin_id))
        .map_err(|error| anyhow!(error))?;
    let definition = definitions
        .iter()
        .find(|definition| definition.qualified_id() == request.scope.capability_id())
        .ok_or_else(|| anyhow!("capability authorization declaration is no longer available"))?;
    if let Err(error) = validate_declared_jit_scope(definition, &approved_scope) {
        return print_jit_error(JIT_EXIT_INVALID, "invalid_scope", &error.to_string(), None);
    }

    let revision = match store.approve(request_id, approved_scope, amendment, Utc::now()) {
        Ok(revision) => revision,
        Err(error) => {
            password.clear();
            return print_jit_store_error(error);
        }
    };
    let scopes = store.effective_scopes(&revision.grant_id)?;
    let activation = activate_jit_revision(&request, &revision, scopes, &password).await;
    password.clear();
    let public = match activation {
        Ok(public) => public,
        Err(error) => {
            eprintln!("JIT approval was recorded but broker activation failed: {error}");
            return Ok(JIT_EXIT_BROKER_OFFLINE);
        }
    };
    let use_limit = public.remaining_uses.map_or_else(
        || "unlimited uses".to_string(),
        |uses| format!("{uses} uses"),
    );
    println!(
        "Approved request {} as grant {} revision {} (expires {}, {}).",
        request.id,
        public.id,
        revision.revision,
        public.expires_at.to_rfc3339(),
        use_limit
    );
    println!("--------------------------------------------------");
    println!("✓ JIT authorization approved successfully.");
    println!("  Target Profile: {}", profile_label);
    println!("  Active Grant:   {}", public.id);
    println!("  Capabilities:   {}", request.scope.capability_id());
    println!(
        "  Valid Until:    {} ({})",
        public.expires_at.to_rfc3339(),
        use_limit
    );
    println!("==================================================");
    Ok(0)
}

fn prompt_narrowed_scope(
    requested: &AgentAuthorizationScope,
) -> anyhow::Result<AgentAuthorizationScope> {
    if matches!(requested, AgentAuthorizationScope::ExactInvocation { .. }) {
        return Ok(requested.clone());
    }
    let choice = prompt_tty_line("Scope [r=requested, n=add non-secret constraints]: ")?;
    if choice.eq_ignore_ascii_case("r") || choice.is_empty() {
        return Ok(requested.clone());
    }
    if !choice.eq_ignore_ascii_case("n") {
        bail!("scope choice was not recognized");
    }
    let raw = prompt_tty_line("Additional constraints JSON object: ")?;
    let additional: BTreeMap<String, Value> =
        serde_json::from_str(&raw).context("constraints must be a JSON object")?;
    let mut constraints = match requested {
        AgentAuthorizationScope::Capability { .. } => BTreeMap::new(),
        AgentAuthorizationScope::Constrained { constraints, .. } => constraints.clone(),
        AgentAuthorizationScope::ExactInvocation { .. } => unreachable!(),
    };
    for (path, value) in additional {
        if constraints.contains_key(&path) {
            bail!("existing requested constraints cannot be replaced during narrowing");
        }
        constraints.insert(path, value);
    }
    Ok(AgentAuthorizationScope::Constrained {
        capability_id: requested.capability_id().to_string(),
        constraints,
    })
}

pub(super) fn prompt_tty_line(prompt: &str) -> anyhow::Result<String> {
    eprint!("{prompt}");
    std::io::stderr().flush()?;
    let mut value = String::new();
    std::io::stdin().lock().read_line(&mut value)?;
    Ok(value.trim().to_string())
}

fn prompt_tty_optional_number<T>(prompt: &str) -> anyhow::Result<Option<T>>
where
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    let value = prompt_tty_line(prompt)?;
    if value.is_empty() {
        return Ok(None);
    }
    value
        .parse()
        .map(Some)
        .map_err(|error| anyhow!("invalid numeric value: {error}"))
}

fn prompt_tty_number_with_default<T>(prompt: &str, default: T) -> anyhow::Result<T>
where
    T: std::str::FromStr + Copy,
    T::Err: std::fmt::Display,
{
    let value = prompt_tty_line(prompt)?;
    if value.is_empty() {
        return Ok(default);
    }
    value
        .parse()
        .map_err(|error| anyhow!("invalid numeric value: {error}"))
}

pub(super) fn parse_review_decision(input: &str) -> Option<&'static str> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Some("b"); // Default to recommended (time-bounded)
    }
    let lower = trimmed.to_ascii_lowercase();
    match lower.as_str() {
        "b" | "bounded" | "time-bounded" => Some("b"),
        "o" | "once" | "single" => Some("o"),
        "a" | "add" | "add-to-grant" => Some("a"),
        "d" | "deny" | "reject" => Some("d"),
        _ => None,
    }
}

fn format_review_profile(profile_id: &str, plugin_id: &str) -> String {
    let store = match LocalProfileStore::default_store() {
        Ok(store) => store,
        Err(_) => return sanitize_terminal_text(profile_id),
    };
    let profiles = match store.load_profiles() {
        Ok(profiles) => profiles,
        Err(_) => return sanitize_terminal_text(profile_id),
    };
    let format_one = |profile: &ConnectionProfile| match &profile.display_name {
        Some(dn) if !dn.trim().is_empty() && dn != &profile.name => {
            format!("{} [{}] ({})", profile.name, dn, profile.id)
        }
        _ => format!("{} ({})", profile.name, profile.id),
    };
    if let Ok(profile) = resolve_profile(&profiles, profile_id, plugin_id) {
        format_one(&profile)
    } else if let Some(profile) = profiles.into_iter().find(|p| p.id == profile_id) {
        format_one(&profile)
    } else {
        sanitize_terminal_text(profile_id)
    }
}

pub(super) fn format_review_principal(principal: &AgentPrincipal) -> String {
    let fingerprint = principal
        .fingerprint()
        .unwrap_or_else(|_| "unknown-fingerprint".to_string());
    if let Some(instance_id) = &principal.instance_id {
        format!(
            "client={} task={} instance={} ({})",
            principal.client_id, principal.task_id, instance_id, fingerprint
        )
    } else {
        format!(
            "client={} task={} ({})",
            principal.client_id, principal.task_id, fingerprint
        )
    }
}

pub(super) fn format_review_risk(risk: voidb_core::CapabilityRiskLevel) -> &'static str {
    use voidb_core::CapabilityRiskLevel;
    match risk {
        CapabilityRiskLevel::ReadOnly => "read_only (safe)",
        CapabilityRiskLevel::Mutating => "mutating (state change)",
        CapabilityRiskLevel::Destructive => "destructive (high risk)",
        CapabilityRiskLevel::ExternalSideEffect => "external_side_effect",
    }
}

pub(super) fn format_review_scope_summary(scope: &AgentAuthorizationScope) -> String {
    match scope {
        AgentAuthorizationScope::Capability { capability_id } => {
            format!("Capability '{}' (all invocations allowed)", capability_id)
        }
        AgentAuthorizationScope::Constrained {
            capability_id,
            constraints,
        } => {
            format!(
                "Capability '{}' with constraints: {}",
                capability_id,
                serde_json::to_string(constraints).unwrap_or_else(|_| "{}".to_string())
            )
        }
        AgentAuthorizationScope::ExactInvocation {
            capability_id,
            normalized_input,
            ..
        } => {
            if normalized_input.as_object().is_none_or(|o| o.is_empty()) {
                format!("Exact invocation: '{}' (no arguments)", capability_id)
            } else {
                format!(
                    "Exact invocation: '{}' with input: {}",
                    capability_id,
                    serde_json::to_string(normalized_input).unwrap_or_else(|_| "{}".to_string())
                )
            }
        }
    }
}

pub(super) fn sanitize_terminal_text(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_control() {
                '�'
            } else {
                character
            }
        })
        .take(1_000)
        .collect()
}

async fn activate_jit_revision(
    request: &voidb_core::AgentAuthorizationRequest,
    revision: &AgentGrantRevision,
    scopes: Vec<AgentAuthorizationScope>,
    password: &str,
) -> anyhow::Result<FrontendAgentGrant> {
    ensure_unix()?;
    if scopes.is_empty() {
        bail!("approved grant revision has no effective scopes");
    }
    let profile_store = LocalProfileStore::default_store()?;
    let profile = resolve_profile(
        &profile_store.load_profiles()?,
        &request.profile_id,
        &request.plugin_id,
    )?;
    verify_profile_credentials(&profile_store, &profile, password)
        .context("profile credential verification failed")?;

    if let Some(existing) = load_grants(false)?
        .into_iter()
        .find(|grant| grant.id == revision.grant_id)
    {
        shutdown_grant(&existing, "jit_revision_replaced").await?;
    }
    let file_stem = revision.grant_id.trim_start_matches("agent-grant:");
    let grant_path = grant_path_for_id(&revision.grant_id)?;
    let socket_path = PathBuf::from("/tmp").join(format!(
        "voidb-agent-{}.sock",
        file_stem.chars().take(16).collect::<String>()
    ));
    let mut capabilities = scopes
        .iter()
        .map(|scope| scope.capability_id().to_string())
        .collect::<Vec<_>>();
    capabilities.sort();
    capabilities.dedup();
    let grant = AgentGrantFile {
        version: GRANT_VERSION,
        id: revision.grant_id.clone(),
        token: Uuid::new_v4().to_string(),
        profile_id: request.profile_id.clone(),
        profile_name: profile.name,
        plugin_id: request.plugin_id.clone(),
        capabilities,
        execution_mode: CapabilityExecutionMode::Stateless,
        preset: Some(AgentAuthorizationPresetKind::Custom),
        allow_destructive: request.risk != voidb_core::CapabilityRiskLevel::ReadOnly,
        issued_at: revision.issued_at,
        expires_at: revision.expires_at,
        remaining_uses: revision.remaining_uses,
        socket_path,
        authorization_scopes: scopes,
        principal_fingerprint: Some(revision.principal_fingerprint.clone()),
        grant_revision: Some(revision.revision),
    };
    write_grant(&grant_path, &grant)?;
    spawn_agent_broker(&grant_path, &grant, password).await?;
    append_agent_audit(
        &grant,
        AuditOperation::CredentialGrantIssued,
        json!({
            "lifecycle": "jit_revision",
            "revision": revision.revision,
            "request_id": revision.source_request_id,
            "principal_fingerprint": revision.principal_fingerprint,
            "scope_fingerprints": grant.authorization_scopes.iter().map(AgentAuthorizationScope::canonical_fingerprint).collect::<Vec<_>>(),
            "execution_mode": grant.execution_mode,
        }),
    );
    let inspection = inspect_grant(&grant).await;
    Ok(grant.public(inspection.broker_health, inspection.active_session_count))
}
