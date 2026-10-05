//! Built-in `audit` CLI for local audit event queries.

use std::collections::BTreeMap;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use clap::{Arg, ArgMatches, Command};
use serde::Serialize;
use serde_json::Value;
use voidb_core::plugin::cli::{CliContext, CliPlugin};
use voidb_core::{
    ActorType, AuditEvent, AuditQuery, AuditQueryPage, AuditQueryResult, AuditSourceFile,
    CapabilityErrorCategory, LocalAuditStore, PolicyDecisionOutcome, RedactionStatus, VoidbError,
};

const AUDIT_CLI_SCHEMA_VERSION: u32 = 1;

pub struct AuditCliPlugin;

impl AuditCliPlugin {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl CliPlugin for AuditCliPlugin {
    fn plugin_id(&self) -> &str {
        "audit"
    }

    fn name(&self) -> &str {
        "Local Audit Events"
    }

    fn commands(&self) -> Vec<Command> {
        vec![
            audit_query_command(
                Command::new("list").about("List recent local audit events"),
                true,
            ),
            audit_query_command(
                Command::new("export").about("Export local audit events as JSON"),
                false,
            ),
            audit_query_command(
                Command::new("summary").about("Summarize local audit events"),
                false,
            ),
            audit_query_command(
                Command::new("bundle").about("Generate a redacted audit support bundle"),
                true,
            ),
        ]
    }

    async fn execute(
        &self,
        command: &str,
        matches: &ArgMatches,
        _ctx: &CliContext,
    ) -> Result<(), VoidbError> {
        ensure_json_format(matches)?;

        match command {
            "list" => handle_query(matches, Some(50)),
            "export" => handle_query(matches, None),
            "summary" => handle_summary(matches),
            "bundle" => handle_bundle(matches),
            _ => Err(VoidbError::Plugin(format!("Unknown command: {}", command))),
        }
    }
}

fn audit_query_command(command: Command, include_default_limit: bool) -> Command {
    let command = command
        .arg(format_arg())
        .arg(
            Arg::new("operation")
                .long("operation")
                .value_name("OPERATION")
                .help("Filter by operation: profile_list, profile_show, profile_test, profile_migrate, capability_invoke, credential_grant_issued, credential_grant_used, credential_grant_released"),
        )
        .arg(
            Arg::new("status")
                .long("status")
                .value_name("STATUS")
                .help("Filter by status: succeeded, failed, blocked, timed_out, cancelled"),
        )
        .arg(
            Arg::new("actor")
                .long("actor")
                .value_name("ACTOR_ID")
                .help("Filter by actor id"),
        )
        .arg(
            Arg::new("actor-type")
                .long("actor-type")
                .value_name("TYPE")
                .help("Filter by actor type: human, agent, system"),
        )
        .arg(
            Arg::new("invocation")
                .long("invocation")
                .value_name("INVOCATION_ID")
                .help("Filter by invocation id"),
        )
        .arg(
            Arg::new("grant")
                .long("grant")
                .value_name("GRANT_ID")
                .help("Filter by credential grant id"),
        )
        .arg(
            Arg::new("credential-ref")
                .long("credential-ref")
                .value_name("CREDENTIAL_REF_ID")
                .help("Filter by credential reference id"),
        )
        .arg(
            Arg::new("profile")
                .long("profile")
                .value_name("PROFILE_REF")
                .help("Filter by profile id:<id>, name:<name>, or bare ID/name"),
        )
        .arg(
            Arg::new("plugin")
                .long("plugin")
                .value_name("PLUGIN_ID")
                .help("Filter by plugin id"),
        )
        .arg(
            Arg::new("capability")
                .long("capability")
                .value_name("CAPABILITY_ID")
                .help("Filter by local capability id"),
        )
        .arg(
            Arg::new("policy-outcome")
                .long("policy-outcome")
                .value_name("OUTCOME")
                .help("Filter by policy outcome: allow, deny, requires_approval, requires_acknowledgement, dry_run_only"),
        )
        .arg(
            Arg::new("policy-reason-code")
                .long("policy-reason-code")
                .value_name("CODE")
                .help("Filter by policy reason code"),
        )
        .arg(
            Arg::new("error-category")
                .long("error-category")
                .value_name("CATEGORY")
                .help("Filter by error category"),
        )
        .arg(
            Arg::new("error-code")
                .long("error-code")
                .value_name("CODE")
                .help("Filter by structured error code"),
        )
        .arg(
            Arg::new("redaction")
                .long("redaction")
                .value_name("STATUS")
                .help("Filter by redaction status: not_required, applied, withheld, failed_closed"),
        )
        .arg(
            Arg::new("since")
                .long("since")
                .value_name("RFC3339")
                .help("Only include events at or after this timestamp"),
        )
        .arg(
            Arg::new("until")
                .long("until")
                .value_name("RFC3339")
                .help("Only include events at or before this timestamp"),
        )
        .arg(
            Arg::new("page-token")
                .long("page-token")
                .value_name("TOKEN")
                .help("Continue a previous paginated audit query"),
        );

    if include_default_limit {
        command.arg(
            Arg::new("limit")
                .long("limit")
                .value_name("COUNT")
                .value_parser(clap::value_parser!(usize))
                .default_value("50")
                .help("Maximum events to return"),
        )
    } else {
        command.arg(
            Arg::new("limit")
                .long("limit")
                .value_name("COUNT")
                .value_parser(clap::value_parser!(usize))
                .help("Maximum events to export"),
        )
    }
}

fn format_arg() -> Arg {
    Arg::new("format")
        .long("format")
        .value_name("FORMAT")
        .value_parser(["json"])
        .default_value("json")
        .help("Output format; only json is stable for audit commands")
}

fn ensure_json_format(matches: &ArgMatches) -> Result<(), VoidbError> {
    match matches.get_one::<String>("format").map(String::as_str) {
        Some("json") | None => Ok(()),
        Some(other) => Err(VoidbError::Plugin(format!(
            "Unsupported audit output format '{}'; use --format json",
            other
        ))),
    }
}

fn handle_query(matches: &ArgMatches, default_limit: Option<usize>) -> Result<(), VoidbError> {
    let query = audit_query_from_matches(matches, default_limit)?;
    let store = LocalAuditStore::default_store()?;
    let result = store.query_page(&query)?;
    let event_count = result.events.len();

    print_json(&success_envelope(AuditListData {
        events: result.events,
        page: result.page,
        export: AuditExportMetadata {
            generated_at: Utc::now(),
            source_files: result.source_files,
            event_count,
            filters: query,
        },
    }))
}

fn handle_summary(matches: &ArgMatches) -> Result<(), VoidbError> {
    let query = audit_query_from_matches(matches, None)?;
    let store = LocalAuditStore::default_store()?;
    let result = store.query_page(&query)?;
    let event_count = result.events.len();
    let summary = summarize_events(&result.events);

    print_json(&success_envelope(AuditSummaryData {
        summary,
        export: AuditExportMetadata {
            generated_at: Utc::now(),
            source_files: result.source_files,
            event_count,
            filters: query,
        },
    }))
}

fn handle_bundle(matches: &ArgMatches) -> Result<(), VoidbError> {
    let query = audit_query_from_matches(matches, Some(50))?;
    let store = LocalAuditStore::default_store()?;
    let result = store.query_page(&query)?;

    print_json(&success_envelope(support_bundle_data(query, result)))
}

fn audit_query_from_matches(
    matches: &ArgMatches,
    default_limit: Option<usize>,
) -> Result<AuditQuery, VoidbError> {
    Ok(AuditQuery {
        operation: parse_optional(matches, "operation")?,
        status: parse_optional(matches, "status")?,
        actor_id: matches.get_one::<String>("actor").cloned(),
        actor_type: parse_optional_actor_type(matches, "actor-type")?,
        invocation_id: matches.get_one::<String>("invocation").cloned(),
        grant_id: matches.get_one::<String>("grant").cloned(),
        credential_ref_id: matches.get_one::<String>("credential-ref").cloned(),
        profile: matches.get_one::<String>("profile").cloned(),
        plugin_id: matches.get_one::<String>("plugin").cloned(),
        capability_id: matches.get_one::<String>("capability").cloned(),
        policy_outcome: parse_optional_policy_outcome(matches, "policy-outcome")?,
        policy_reason_code: matches.get_one::<String>("policy-reason-code").cloned(),
        error_category: parse_optional_error_category(matches, "error-category")?,
        error_code: matches.get_one::<String>("error-code").cloned(),
        redaction: parse_optional_redaction(matches, "redaction")?,
        since: parse_optional_time(matches, "since")?,
        until: parse_optional_time(matches, "until")?,
        limit: matches.get_one::<usize>("limit").copied().or(default_limit),
        page_token: matches.get_one::<String>("page-token").cloned(),
    })
}

fn parse_optional<T>(matches: &ArgMatches, name: &str) -> Result<Option<T>, VoidbError>
where
    T: std::str::FromStr<Err = String>,
{
    matches
        .get_one::<String>(name)
        .map(|value| {
            value
                .parse::<T>()
                .map_err(|error| VoidbError::Plugin(error.to_string()))
        })
        .transpose()
}

fn parse_optional_actor_type(
    matches: &ArgMatches,
    name: &str,
) -> Result<Option<ActorType>, VoidbError> {
    matches
        .get_one::<String>(name)
        .map(|value| match value.as_str() {
            "human" => Ok(ActorType::Human),
            "agent" => Ok(ActorType::Agent),
            "system" => Ok(ActorType::System),
            other => Err(VoidbError::Plugin(format!(
                "Unsupported audit actor type: {other}"
            ))),
        })
        .transpose()
}

fn parse_optional_policy_outcome(
    matches: &ArgMatches,
    name: &str,
) -> Result<Option<PolicyDecisionOutcome>, VoidbError> {
    matches
        .get_one::<String>(name)
        .map(|value| match value.as_str() {
            "allow" => Ok(PolicyDecisionOutcome::Allow),
            "deny" => Ok(PolicyDecisionOutcome::Deny),
            "requires_approval" => Ok(PolicyDecisionOutcome::RequiresApproval),
            "requires_acknowledgement" => Ok(PolicyDecisionOutcome::RequiresAcknowledgement),
            "dry_run_only" => Ok(PolicyDecisionOutcome::DryRunOnly),
            other => Err(VoidbError::Plugin(format!(
                "Unsupported audit policy outcome: {other}"
            ))),
        })
        .transpose()
}

fn parse_optional_error_category(
    matches: &ArgMatches,
    name: &str,
) -> Result<Option<CapabilityErrorCategory>, VoidbError> {
    matches
        .get_one::<String>(name)
        .map(|value| match value.as_str() {
            "validation" => Ok(CapabilityErrorCategory::Validation),
            "auth" => Ok(CapabilityErrorCategory::Auth),
            "permission" => Ok(CapabilityErrorCategory::Permission),
            "credential" => Ok(CapabilityErrorCategory::Credential),
            "policy" => Ok(CapabilityErrorCategory::Policy),
            "transport" => Ok(CapabilityErrorCategory::Transport),
            "timeout" => Ok(CapabilityErrorCategory::Timeout),
            "cancellation" => Ok(CapabilityErrorCategory::Cancellation),
            "plugin" => Ok(CapabilityErrorCategory::Plugin),
            "target_system" => Ok(CapabilityErrorCategory::TargetSystem),
            "conflict" => Ok(CapabilityErrorCategory::Conflict),
            "unavailable" => Ok(CapabilityErrorCategory::Unavailable),
            "internal" => Ok(CapabilityErrorCategory::Internal),
            other => Err(VoidbError::Plugin(format!(
                "Unsupported audit error category: {other}"
            ))),
        })
        .transpose()
}

fn parse_optional_redaction(
    matches: &ArgMatches,
    name: &str,
) -> Result<Option<RedactionStatus>, VoidbError> {
    matches
        .get_one::<String>(name)
        .map(|value| match value.as_str() {
            "not_required" => Ok(RedactionStatus::NotRequired),
            "applied" => Ok(RedactionStatus::Applied),
            "withheld" => Ok(RedactionStatus::Withheld),
            "failed_closed" => Ok(RedactionStatus::FailedClosed),
            other => Err(VoidbError::Plugin(format!(
                "Unsupported audit redaction status: {other}"
            ))),
        })
        .transpose()
}

fn parse_optional_time(
    matches: &ArgMatches,
    name: &str,
) -> Result<Option<DateTime<Utc>>, VoidbError> {
    matches
        .get_one::<String>(name)
        .map(|value| {
            DateTime::parse_from_rfc3339(value)
                .map(|time| time.with_timezone(&Utc))
                .map_err(|error| {
                    VoidbError::Plugin(format!("Invalid RFC3339 timestamp for --{name}: {error}"))
                })
        })
        .transpose()
}

fn success_envelope<T: Serialize>(data: T) -> JsonSuccessEnvelope<T> {
    JsonSuccessEnvelope {
        ok: true,
        schema_version: AUDIT_CLI_SCHEMA_VERSION,
        command: "audit",
        data,
        warnings: Vec::new(),
    }
}

fn print_json(value: &impl Serialize) -> Result<(), VoidbError> {
    let output = serde_json::to_string_pretty(value)
        .map_err(|e| VoidbError::Plugin(format!("Failed to serialize JSON output: {}", e)))?;
    println!("{}", output);
    Ok(())
}

#[derive(Debug, Serialize)]
struct JsonSuccessEnvelope<T> {
    ok: bool,
    schema_version: u32,
    command: &'static str,
    data: T,
    warnings: Vec<AuditWarning>,
}

#[derive(Debug, Serialize)]
struct AuditWarning {
    code: String,
    message: String,
    details: Value,
}

#[derive(Debug, Serialize)]
struct AuditListData {
    events: Vec<AuditEvent>,
    page: AuditQueryPage,
    export: AuditExportMetadata,
}

#[derive(Debug, Serialize)]
struct AuditSummaryData {
    summary: AuditSummary,
    export: AuditExportMetadata,
}

#[derive(Debug, Serialize)]
struct AuditSupportBundleData {
    bundle: AuditSupportBundle,
}

#[derive(Debug, Serialize)]
struct AuditSupportBundle {
    schema_version: u32,
    generated_at: DateTime<Utc>,
    voidb: AuditBundleVersionInfo,
    audit: AuditBundleAudit,
    redaction: AuditBundleRedaction,
}

#[derive(Debug, Serialize)]
struct AuditBundleVersionInfo {
    cli_package_version: &'static str,
    target_os: &'static str,
    target_arch: &'static str,
}

#[derive(Debug, Serialize)]
struct AuditBundleAudit {
    events: Vec<AuditEvent>,
    summary: AuditSummary,
    page: AuditQueryPage,
    export: AuditExportMetadata,
}

#[derive(Debug, Serialize)]
struct AuditBundleRedaction {
    status: &'static str,
    guarantees: Vec<&'static str>,
    excluded: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
struct AuditSummary {
    event_count: usize,
    status_counts: Vec<AuditCount>,
    operation_counts: Vec<AuditCount>,
    plugin_counts: Vec<AuditCount>,
    capability_counts: Vec<AuditCount>,
    error_category_counts: Vec<AuditCount>,
    error_code_counts: Vec<AuditCount>,
    policy_outcome_counts: Vec<AuditCount>,
    latency: AuditLatencySummary,
    security_signals: Vec<AuditSecuritySignal>,
}

#[derive(Debug, Serialize)]
struct AuditCount {
    key: String,
    count: usize,
}

#[derive(Debug, Serialize)]
struct AuditLatencySummary {
    event_count: usize,
    min_duration_ms: Option<u64>,
    max_duration_ms: Option<u64>,
    average_duration_ms: Option<u64>,
}

#[derive(Debug, Serialize)]
struct AuditSecuritySignal {
    category: String,
    count: usize,
    sample_event_ids: Vec<String>,
}

#[derive(Debug, Serialize)]
struct AuditExportMetadata {
    generated_at: DateTime<Utc>,
    source_files: Vec<AuditSourceFile>,
    event_count: usize,
    filters: AuditQuery,
}

fn summarize_events(events: &[AuditEvent]) -> AuditSummary {
    let mut status_counts = BTreeMap::new();
    let mut operation_counts = BTreeMap::new();
    let mut plugin_counts = BTreeMap::new();
    let mut capability_counts = BTreeMap::new();
    let mut error_category_counts = BTreeMap::new();
    let mut error_code_counts = BTreeMap::new();
    let mut policy_outcome_counts = BTreeMap::new();
    let mut security_signals = BTreeMap::<String, SecuritySignalAccumulator>::new();
    let mut durations = Vec::new();

    for event in events {
        increment(&mut status_counts, stable_json_label(event.status));
        increment(&mut operation_counts, stable_json_label(event.operation));
        if let Some(plugin_id) = &event.plugin_id {
            increment(&mut plugin_counts, plugin_id.clone());
        }
        if let Some(capability_id) = &event.capability_id {
            increment(&mut capability_counts, capability_id.clone());
        }
        if let Some(duration_ms) = event.duration_ms {
            durations.push(duration_ms);
        }
        if let Some(error) = &event.error {
            increment(&mut error_category_counts, stable_json_label(error.category));
            increment(&mut error_code_counts, error.code.clone());
        }
        if let Some(outcome) = audit_policy_outcome(event) {
            increment(&mut policy_outcome_counts, outcome.to_string());
        }
        for category in security_signal_categories(event) {
            let entry = security_signals
                .entry(category.to_string())
                .or_default();
            entry.count += 1;
            if entry.sample_event_ids.len() < 5 {
                entry.sample_event_ids.push(event.id.clone());
            }
        }
    }

    AuditSummary {
        event_count: events.len(),
        status_counts: counts_from_map(status_counts),
        operation_counts: counts_from_map(operation_counts),
        plugin_counts: counts_from_map(plugin_counts),
        capability_counts: counts_from_map(capability_counts),
        error_category_counts: counts_from_map(error_category_counts),
        error_code_counts: counts_from_map(error_code_counts),
        policy_outcome_counts: counts_from_map(policy_outcome_counts),
        latency: latency_summary(&durations),
        security_signals: security_signals_from_map(security_signals),
    }
}

fn support_bundle_data(query: AuditQuery, result: AuditQueryResult) -> AuditSupportBundleData {
    let event_count = result.events.len();
    let summary = summarize_events(&result.events);
    AuditSupportBundleData {
        bundle: AuditSupportBundle {
            schema_version: 1,
            generated_at: Utc::now(),
            voidb: AuditBundleVersionInfo {
                cli_package_version: env!("CARGO_PKG_VERSION"),
                target_os: std::env::consts::OS,
                target_arch: std::env::consts::ARCH,
            },
            audit: AuditBundleAudit {
                events: result.events,
                summary,
                page: result.page,
                export: AuditExportMetadata {
                    generated_at: Utc::now(),
                    source_files: result.source_files,
                    event_count,
                    filters: query,
                },
            },
            redaction: AuditBundleRedaction {
                status: "applied",
                guarantees: vec![
                    "Audit records contain redacted metadata supplied by callers.",
                    "Raw invocation input and decrypted plugin_config are not included.",
                    "Support bundles include bounded audit excerpts and aggregate summaries only.",
                ],
                excluded: vec![
                    "plaintext credentials",
                    "decrypted connection configuration",
                    "authorization headers",
                    "cookies",
                    "unredacted target-system diagnostics",
                ],
            },
        },
    }
}

fn increment(counts: &mut BTreeMap<String, usize>, key: String) {
    *counts.entry(key).or_default() += 1;
}

fn counts_from_map(counts: BTreeMap<String, usize>) -> Vec<AuditCount> {
    counts
        .into_iter()
        .map(|(key, count)| AuditCount { key, count })
        .collect()
}

fn latency_summary(durations: &[u64]) -> AuditLatencySummary {
    let event_count = durations.len();
    let total = durations.iter().sum::<u64>();
    AuditLatencySummary {
        event_count,
        min_duration_ms: durations.iter().min().copied(),
        max_duration_ms: durations.iter().max().copied(),
        average_duration_ms: (event_count > 0).then(|| total / event_count as u64),
    }
}

fn security_signals_from_map(
    signals: BTreeMap<String, SecuritySignalAccumulator>,
) -> Vec<AuditSecuritySignal> {
    signals
        .into_iter()
        .map(|(category, signal)| AuditSecuritySignal {
            category,
            count: signal.count,
            sample_event_ids: signal.sample_event_ids,
        })
        .collect()
}

#[derive(Default)]
struct SecuritySignalAccumulator {
    count: usize,
    sample_event_ids: Vec<String>,
}

fn security_signal_categories(event: &AuditEvent) -> Vec<&'static str> {
    let mut categories = Vec::new();
    let error_category = event.error.as_ref().map(|error| error.category);
    let error_code = event.error.as_ref().map(|error| error.code.as_str());
    let policy_outcome = audit_policy_outcome(event);
    let policy_reason_code = audit_policy_reason_code(event);

    if event.status == voidb_core::AuditEventStatus::Blocked
        || matches!(
            error_category,
            Some(CapabilityErrorCategory::Permission | CapabilityErrorCategory::Policy)
        )
        || matches!(
            policy_outcome,
            Some("deny" | "requires_approval" | "requires_acknowledgement")
        )
    {
        categories.push("policy_block");
    }

    if policy_reason_code.is_some_and(|code| code.contains("approval"))
        || matches!(policy_outcome, Some("requires_approval"))
    {
        categories.push("approval_attention");
    }

    if matches!(error_category, Some(CapabilityErrorCategory::Credential))
        || matches!(
            event.operation,
            voidb_core::AuditOperation::CredentialSyncUnavailable
                | voidb_core::AuditOperation::CredentialSyncReenrollHandoff
                | voidb_core::AuditOperation::TeamShareCredentialReenrollmentRequired
        )
        || error_code.is_some_and(|code| code.contains("credential"))
    {
        categories.push("credential_attention");
    }

    if event.redaction == RedactionStatus::FailedClosed
        || event
            .error
            .as_ref()
            .is_some_and(|error| error.redaction == RedactionStatus::FailedClosed)
    {
        categories.push("redaction_failure");
    }

    categories
}

fn audit_policy_outcome(event: &AuditEvent) -> Option<&str> {
    event
        .metadata
        .get("policy_decision")
        .and_then(|decision| decision.get("outcome"))
        .and_then(Value::as_str)
}

fn audit_policy_reason_code(event: &AuditEvent) -> Option<&str> {
    event
        .metadata
        .get("policy_decision")
        .and_then(|decision| decision.get("reason"))
        .and_then(|reason| reason.get("code"))
        .and_then(Value::as_str)
}

fn stable_json_label(value: impl Serialize) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_else(|| "unknown".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use voidb_core::{
        AuditEventStatus, AuditOperation, CapabilityError, CapabilityErrorCategory,
        RedactionStatus,
    };

    #[test]
    fn parses_operation_and_status_filters() {
        let matches = audit_query_command(Command::new("list"), true)
            .try_get_matches_from([
                "list",
                "--operation",
                "capability_invoke",
                "--status",
                "blocked",
                "--actor",
                "agent:test",
                "--actor-type",
                "agent",
                "--plugin",
                "redis",
                "--capability",
                "set",
                "--policy-outcome",
                "requires_acknowledgement",
                "--policy-reason-code",
                "policy.destructive_denied_by_default",
                "--invocation",
                "invoke-1",
                "--grant",
                "grant-1",
                "--credential-ref",
                "credential-ref-1",
                "--error-category",
                "target_system",
                "--error-code",
                "redis.command_failed",
                "--redaction",
                "applied",
                "--page-token",
                "offset:50",
                "--limit",
                "10",
            ])
            .expect("parse matches");

        let query = audit_query_from_matches(&matches, Some(50)).expect("query");
        assert_eq!(query.operation, Some(AuditOperation::CapabilityInvoke));
        assert_eq!(query.status, Some(AuditEventStatus::Blocked));
        assert_eq!(query.actor_id.as_deref(), Some("agent:test"));
        assert_eq!(query.actor_type, Some(ActorType::Agent));
        assert_eq!(query.plugin_id.as_deref(), Some("redis"));
        assert_eq!(query.capability_id.as_deref(), Some("set"));
        assert_eq!(
            query.policy_outcome,
            Some(PolicyDecisionOutcome::RequiresAcknowledgement)
        );
        assert_eq!(
            query.policy_reason_code.as_deref(),
            Some("policy.destructive_denied_by_default")
        );
        assert_eq!(query.invocation_id.as_deref(), Some("invoke-1"));
        assert_eq!(query.grant_id.as_deref(), Some("grant-1"));
        assert_eq!(query.credential_ref_id.as_deref(), Some("credential-ref-1"));
        assert_eq!(
            query.error_category,
            Some(CapabilityErrorCategory::TargetSystem)
        );
        assert_eq!(query.error_code.as_deref(), Some("redis.command_failed"));
        assert_eq!(query.redaction, Some(RedactionStatus::Applied));
        assert_eq!(query.page_token.as_deref(), Some("offset:50"));
        assert_eq!(query.limit, Some(10));

        let matches = audit_query_command(Command::new("list"), true)
            .try_get_matches_from(["list", "--operation", "credential_grant_used"])
            .expect("parse profile migrate operation");
        let query = audit_query_from_matches(&matches, Some(50)).expect("query");
        assert_eq!(query.operation, Some(AuditOperation::CredentialGrantUsed));
    }

    #[test]
    fn success_envelope_is_versioned_for_agents() {
        let value = serde_json::to_value(success_envelope(AuditListData {
            events: Vec::new(),
            page: AuditQueryPage::default(),
            export: AuditExportMetadata {
                generated_at: Utc::now(),
                source_files: Vec::new(),
                event_count: 0,
                filters: AuditQuery::default(),
            },
        }))
        .expect("serialize envelope");

        assert_eq!(value["ok"], true);
        assert_eq!(value["schema_version"], AUDIT_CLI_SCHEMA_VERSION);
        assert_eq!(value["command"], "audit");
        assert_eq!(value["warnings"], serde_json::json!([]));
        assert!(value["data"]["events"].as_array().is_some());
        assert_eq!(value["data"]["export"]["event_count"], 0);
    }

    #[test]
    fn bundle_query_defaults_to_bounded_event_excerpt() {
        let matches = audit_query_command(Command::new("bundle"), true)
            .try_get_matches_from(["bundle"])
            .expect("parse matches");

        let query = audit_query_from_matches(&matches, Some(50)).expect("query");

        assert_eq!(query.limit, Some(50));
    }

    #[test]
    fn support_bundle_includes_redacted_contract_and_summary() {
        let mut event =
            AuditEvent::new(AuditOperation::CapabilityInvoke, AuditEventStatus::Failed);
        event.id = "audit-support-1".into();
        event.plugin_id = Some("postgres".into());
        event.capability_id = Some("query".into());
        event.duration_ms = Some(25);
        event.redaction = RedactionStatus::Applied;
        event.metadata = json!({
            "input_summary": {
                "schema": "query-input",
                "fields": ["sql"],
                "redacted_fields": ["sql"]
            }
        });
        event.error = Some(CapabilityError {
            category: CapabilityErrorCategory::TargetSystem,
            code: "postgres.syntax_error".into(),
            message: "Target system rejected the query.".into(),
            details: json!({ "statement": "[redacted]" }),
            target: None,
            retryable: false,
            redaction: RedactionStatus::Applied,
        });

        let bundle = support_bundle_data(
            AuditQuery {
                operation: Some(AuditOperation::CapabilityInvoke),
                limit: Some(50),
                ..AuditQuery::default()
            },
            AuditQueryResult {
                events: vec![event],
                page: AuditQueryPage::default(),
                source_files: vec![AuditSourceFile {
                    path: std::path::PathBuf::from("events.jsonl"),
                    bytes: 512,
                }],
            },
        );
        let value = serde_json::to_value(&bundle).expect("serialize bundle");
        let serialized = serde_json::to_string(&bundle).expect("serialize bundle string");

        assert_eq!(value["bundle"]["schema_version"], 1);
        assert_eq!(
            value["bundle"]["voidb"]["cli_package_version"],
            env!("CARGO_PKG_VERSION")
        );
        assert_eq!(value["bundle"]["audit"]["summary"]["event_count"], 1);
        assert_eq!(value["bundle"]["audit"]["export"]["event_count"], 1);
        assert_eq!(
            value["bundle"]["audit"]["export"]["filters"]["operation"],
            "capability_invoke"
        );
        assert_eq!(value["bundle"]["redaction"]["status"], "applied");
        assert!(value["bundle"]["redaction"]["excluded"]
            .as_array()
            .expect("excluded list")
            .iter()
            .any(|entry| entry == "plaintext credentials"));
        assert!(!serialized.contains("super-secret"));
    }

    #[test]
    fn summary_counts_latency_errors_policy_and_security_signals() {
        let mut success =
            AuditEvent::new(AuditOperation::CapabilityInvoke, AuditEventStatus::Succeeded);
        success.id = "audit-success".into();
        success.plugin_id = Some("sqlite".into());
        success.capability_id = Some("query".into());
        success.duration_ms = Some(10);

        let mut blocked =
            AuditEvent::new(AuditOperation::CapabilityInvoke, AuditEventStatus::Blocked);
        blocked.id = "audit-blocked".into();
        blocked.plugin_id = Some("redis".into());
        blocked.capability_id = Some("del".into());
        blocked.duration_ms = Some(30);
        blocked.metadata = json!({
            "policy_decision": {
                "outcome": "requires_acknowledgement",
                "reason": {
                    "code": "policy.destructive_denied_by_default"
                }
            }
        });
        blocked.error = Some(CapabilityError {
            category: CapabilityErrorCategory::Policy,
            code: "policy.destructive_denied_by_default".into(),
            message: "Profile policy blocks destructive capability execution by default.".into(),
            details: json!({ "capability_id": "del" }),
            target: None,
            retryable: false,
            redaction: RedactionStatus::NotRequired,
        });

        let mut redaction_failure =
            AuditEvent::new(AuditOperation::CredentialSyncUnavailable, AuditEventStatus::Failed);
        redaction_failure.id = "audit-redaction".into();
        redaction_failure.redaction = RedactionStatus::FailedClosed;
        redaction_failure.error = Some(CapabilityError {
            category: CapabilityErrorCategory::Credential,
            code: "credential.decrypt_failed".into(),
            message: "Credential could not be decrypted.".into(),
            details: json!({ "reason": "withheld" }),
            target: None,
            retryable: false,
            redaction: RedactionStatus::FailedClosed,
        });

        let summary = summarize_events(&[success, blocked, redaction_failure]);

        assert_eq!(summary.event_count, 3);
        assert_eq!(summary.latency.event_count, 2);
        assert_eq!(summary.latency.min_duration_ms, Some(10));
        assert_eq!(summary.latency.max_duration_ms, Some(30));
        assert_eq!(summary.latency.average_duration_ms, Some(20));
        assert_eq!(
            count_for(&summary.error_category_counts, "policy"),
            Some(1)
        );
        assert_eq!(
            count_for(&summary.error_category_counts, "credential"),
            Some(1)
        );
        assert_eq!(
            count_for(
                &summary.policy_outcome_counts,
                "requires_acknowledgement"
            ),
            Some(1)
        );
        assert_eq!(
            signal_count(&summary.security_signals, "policy_block"),
            Some(1)
        );
        assert_eq!(
            signal_count(&summary.security_signals, "credential_attention"),
            Some(1)
        );
        assert_eq!(
            signal_count(&summary.security_signals, "redaction_failure"),
            Some(1)
        );
    }

    #[test]
    fn rejects_invalid_timestamp() {
        let matches = audit_query_command(Command::new("list"), true)
            .try_get_matches_from(["list", "--since", "not-a-time"])
            .expect("parse matches");

        let error = audit_query_from_matches(&matches, Some(50)).expect_err("invalid timestamp");
        assert!(error.to_string().contains("Invalid RFC3339 timestamp"));
    }

    fn count_for(counts: &[AuditCount], key: &str) -> Option<usize> {
        counts
            .iter()
            .find(|count| count.key == key)
            .map(|count| count.count)
    }

    fn signal_count(signals: &[AuditSecuritySignal], category: &str) -> Option<usize> {
        signals
            .iter()
            .find(|signal| signal.category == category)
            .map(|signal| signal.count)
    }
}
