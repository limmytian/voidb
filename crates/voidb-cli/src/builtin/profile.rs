//! Built-in `profile` CLI plugin.
//!
//! Exposes capability-first, agent-safe profile views over writable local
//! native profile records backed by encrypted local connection configuration.

use async_trait::async_trait;
use clap::{Arg, ArgMatches, Command};
use serde::Serialize;
use serde_json::{Value, json};
use std::io::Read;
use std::time::Instant;
use voidb_core::capability::{
    ConnectionProfile, ConnectionProfilePolicy, ConnectionProfileRef, CredentialClass,
    CredentialRef, RedactionStatus,
};
use voidb_core::plugin::cli::{CliContext, CliPlugin};
use voidb_core::profile_schema::{ProfileFormFieldKind, ProfileFormSchema};
use voidb_core::{
    AppConfig, AuditEvent, AuditEventStatus, AuditEventStore, AuditOperation, CapabilityError,
    CapabilityErrorCategory, ConnectionConfig, DEFAULT_PASSPHRASE_WARNING_CODE, LocalAuditStore,
    LocalProfileStore, MasterPasswordSessionState, NativeProfileDocument, RedactionTargetKind,
    VoidbError, collect_redaction_targets, credential_class_for_key, database_type_for_plugin,
    derive_native_profile, new_native_profile_id, profile_names_equal, profile_plugin_id,
    redact_text_with_json,
};

use crate::builtin::connections::test_connection_by_plugin;
use crate::builtin::json_output::print_json;

const SUPPORTED_LEGACY_PROFILE_PLUGINS: &[&str] = &[
    "mysql",
    "postgres",
    "sqlite",
    "redis",
    "ssh",
    "docker",
    "kubernetes",
    "webdav",
    "s3",
    "elasticsearch",
    "mongodb",
    "duckdb",
    "email",
    "jenkins",
    "sync",
];
const PROFILE_CLI_SCHEMA_VERSION: u32 = 1;

pub struct ProfileCliPlugin;

impl ProfileCliPlugin {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl CliPlugin for ProfileCliPlugin {
    fn plugin_id(&self) -> &str {
        "profile"
    }

    fn visible_aliases(&self) -> Vec<&'static str> {
        vec!["profiles"]
    }

    fn name(&self) -> &str {
        "Connection Profiles"
    }

    fn commands(&self) -> Vec<Command> {
        vec![
            Command::new("list")
                .about("List saved connection profiles as agent-safe JSON")
                .arg(format_arg())
                .arg(plugin_arg("Only include profiles owned by one plugin")),
            Command::new("show")
                .visible_alias("inspect")
                .about("Show one saved connection profile as agent-safe JSON")
                .arg(
                    Arg::new("profile")
                        .required(true)
                        .help("Profile ref: <name>, id:<profile-id>, or name:<name>"),
                )
                .arg(format_arg())
                .arg(plugin_arg("Resolve a name shared by different plugins")),
            Command::new("test")
                .about("Test whether a saved profile can reach its target")
                .arg(
                    Arg::new("profile")
                        .required(true)
                        .help("Profile ref: <name>, id:<profile-id>, or name:<name>"),
                )
                .arg(format_arg())
                .arg(plugin_arg("Resolve a name shared by different plugins")),
            Command::new("create")
                .about("Create one saved connection profile from a schema-validated document")
                .arg(plugin_required_arg())
                .arg(name_required_arg())
                .arg(
                    Arg::new("display-name")
                        .long("display-name")
                        .value_name("NAME")
                        .help("Optional human display name"),
                )
                .arg(
                    Arg::new("input")
                        .long("input")
                        .value_name("PATH")
                        .required(true)
                        .help("Profile JSON document containing metadata, defaults, and policy; '-' reads stdin"),
                )
                .arg(credential_arg())
                .arg(dry_run_arg())
                .arg(format_arg()),
            Command::new("update")
                .about("Update one saved connection profile with optimistic concurrency")
                .arg(
                    Arg::new("profile")
                        .required(true)
                        .help("Profile ref: <name>, id:<profile-id>, or name:<name>"),
                )
                .arg(plugin_arg("Resolve a name shared by different plugins"))
                .arg(input_arg())
                .arg(
                    Arg::new("set")
                        .long("set")
                        .value_name("PATH=VALUE")
                        .action(clap::ArgAction::Append)
                        .num_args(1)
                        .help("Scalar patch: name, display_name, or metadata.<key> (repeatable)"),
                )
                .arg(
                    Arg::new("unset")
                        .long("unset")
                        .value_name("PATH")
                        .action(clap::ArgAction::Append)
                        .num_args(1)
                        .help("Remove display_name or metadata.<key> (repeatable)"),
                )
                .arg(credential_arg())
                .arg(expected_version_arg())
                .arg(dry_run_arg())
                .arg(format_arg()),
            Command::new("validate")
                .about("Validate a profile document against a plugin schema without saving it")
                .arg(plugin_required_arg())
                .arg(
                    Arg::new("input")
                        .long("input")
                        .value_name("PATH")
                        .required(true)
                        .help("Profile JSON document; '-' reads stdin"),
                )
                .arg(format_arg()),
            Command::new("migrate")
                .about("Preview or apply migration from legacy connections to local profiles")
                .subcommand_required(true)
                .arg_required_else_help(true)
                .subcommand(
                    Command::new("preview")
                        .about("Preview profile migration without writing files")
                        .arg(format_arg())
                        .arg(plugin_arg("Only preview legacy connections for one plugin")),
                )
                .subcommand(
                    Command::new("apply")
                        .about("Persist migrated profile and credential-reference records")
                        .arg(format_arg())
                        .arg(plugin_arg("Only migrate legacy connections for one plugin")),
                ),
        ]
    }

    async fn execute(
        &self,
        command: &str,
        matches: &ArgMatches,
        ctx: &CliContext,
    ) -> Result<(), VoidbError> {
        if command != "migrate" {
            ensure_json_format(matches)?;
        }

        match command {
            "list" => handle_list(matches, ctx),
            "show" | "inspect" => handle_show(matches, ctx),
            "test" => handle_test(matches, ctx).await,
            "migrate" => handle_migrate(matches, ctx),
            "create" => handle_create(matches, ctx),
            "update" => handle_update(matches, ctx),
            "validate" => handle_validate(matches, ctx),
            _ => Err(VoidbError::Plugin(format!("Unknown command: {}", command))),
        }
    }
}

fn format_arg() -> Arg {
    Arg::new("format")
        .long("format")
        .value_name("FORMAT")
        .value_parser(["json"])
        .default_value("json")
        .help("Output format; only json is stable for profile commands")
}

fn plugin_arg(help: &'static str) -> Arg {
    Arg::new("plugin")
        .long("plugin")
        .value_name("PLUGIN_ID")
        .help(help)
}

fn plugin_required_arg() -> Arg {
    Arg::new("plugin")
        .long("plugin")
        .value_name("PLUGIN_ID")
        .required(true)
        .help("Plugin that owns the profile")
}

fn name_required_arg() -> Arg {
    Arg::new("name")
        .long("name")
        .value_name("NAME")
        .required(true)
        .help("Stable profile name, unique within the plugin (case-insensitive)")
}

fn input_arg() -> Arg {
    Arg::new("input")
        .long("input")
        .value_name("PATH")
        .help("Profile JSON document; '-' reads stdin")
}

fn credential_arg() -> Arg {
    Arg::new("credential")
        .long("credential")
        .value_name("CLASS:SOURCE")
        .action(clap::ArgAction::Append)
        .num_args(1)
        .help("Secret source converted into a credential reference, e.g. password:env=VAR or token:file=PATH (repeatable)")
}

fn dry_run_arg() -> Arg {
    Arg::new("dry-run")
        .long("dry-run")
        .action(clap::ArgAction::SetTrue)
        .help("Validate and show the planned mutation without storing it")
}

fn expected_version_arg() -> Arg {
    Arg::new("expected-version")
        .long("expected-version")
        .value_name("N")
        .value_parser(clap::value_parser!(u64))
        .help("Optimistic concurrency guard; required for non-interactive updates")
}

fn ensure_json_format(matches: &ArgMatches) -> Result<(), VoidbError> {
    match matches.get_one::<String>("format").map(String::as_str) {
        Some("json") | None => Ok(()),
        Some(other) => Err(VoidbError::Plugin(format!(
            "Unsupported profile output format '{}'; use --format json",
            other
        ))),
    }
}

fn handle_list(matches: &ArgMatches, ctx: &CliContext) -> Result<(), VoidbError> {
    let plugin_filter = matches.get_one::<String>("plugin").map(String::as_str);
    let profiles = profiles_from_context(ctx)?;
    let data = profile_list_data(&profiles, plugin_filter);
    let warnings = security_warnings_for_config(&ctx.config);
    let mut event = AuditEvent::new(AuditOperation::ProfileList, AuditEventStatus::Succeeded);
    event.plugin_id = plugin_filter.map(str::to_string);
    event.metadata = json!({
        "plugin_filter": plugin_filter,
        "profile_count": data.profiles.len(),
    });
    append_audit_event(event)?;
    print_json(&success_envelope_with_warnings(data, warnings))
}

fn handle_show(matches: &ArgMatches, ctx: &CliContext) -> Result<(), VoidbError> {
    let profile_ref = matches
        .get_one::<String>("profile")
        .expect("required by clap");
    let plugin_filter = matches.get_one::<String>("plugin").map(String::as_str);
    let profiles = profiles_from_context(ctx)?;

    match resolve_profile(&profiles, profile_ref, plugin_filter) {
        Ok(profile) => {
            let mut event =
                AuditEvent::new(AuditOperation::ProfileMigrate, AuditEventStatus::Succeeded);
            event.profile = Some(ConnectionProfileRef::Id(profile.id.clone()));
            event.plugin_id = Some(profile.plugin_id.clone());
            event.metadata = profile_audit_metadata(profile_ref, plugin_filter);
            append_audit_event(event)?;
            print_json(&success_envelope_with_warnings(
                ProfileShowData {
                    schema_status: ProfileSchemaStatus::for_profile(&profile),
                    profile,
                },
                security_warnings_for_config(&ctx.config),
            ))
        }
        Err(error) => {
            let mut event = AuditEvent::new(AuditOperation::ProfileShow, AuditEventStatus::Failed);
            event.metadata = profile_audit_metadata(profile_ref, plugin_filter);
            event.error = Some(profile_error_to_capability_error(&error));
            event.redaction = error.redaction;
            append_audit_event(event)?;
            print_json(&JsonErrorEnvelope {
                ok: false,
                schema_version: PROFILE_CLI_SCHEMA_VERSION,
                command: "profile",
                error: *error,
            })
        }
    }
}

async fn handle_test(matches: &ArgMatches, ctx: &CliContext) -> Result<(), VoidbError> {
    let profile_ref = matches
        .get_one::<String>("profile")
        .expect("required by clap");
    let plugin_filter = matches.get_one::<String>("plugin").map(String::as_str);
    let profiles = profiles_from_context(ctx)?;

    let (profile, connection) =
        match resolve_native_profile_connection(ctx, &profiles, profile_ref, plugin_filter) {
            Ok(resolved) => resolved,
            Err(error) => {
                let mut event =
                    AuditEvent::new(AuditOperation::ProfileTest, AuditEventStatus::Failed);
                event.metadata = profile_audit_metadata(profile_ref, plugin_filter);
                event.error = Some(profile_error_to_capability_error(&error));
                event.redaction = error.redaction;
                append_audit_event(event)?;
                return print_json(&JsonErrorEnvelope {
                    ok: false,
                    schema_version: PROFILE_CLI_SCHEMA_VERSION,
                    command: "profile",
                    error: *error,
                });
            }
        };

    let started = Instant::now();
    let plugin_id = connection.effective_plugin_id().to_string();
    let result = test_connection_by_plugin(&plugin_id, &connection).await;
    let duration_ms = started.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;

    match result {
        Ok(message) => {
            let mut event =
                AuditEvent::new(AuditOperation::ProfileTest, AuditEventStatus::Succeeded);
            event.profile = Some(ConnectionProfileRef::Id(profile.id.clone()));
            event.plugin_id = Some(plugin_id);
            event.duration_ms = Some(duration_ms);
            event.metadata = json!({
                "profile_ref": profile_ref,
                "plugin_filter": plugin_filter,
            });
            append_audit_event(event)?;
            print_json(&success_envelope_with_warnings(
                profile_test_data(&profile, &message, duration_ms),
                security_warnings_for_config(&ctx.config),
            ))
        }
        Err(diagnostic) => {
            let error = profile_test_failed(&profile, &connection, &diagnostic, duration_ms);
            let mut event = AuditEvent::new(AuditOperation::ProfileTest, AuditEventStatus::Failed);
            event.profile = Some(ConnectionProfileRef::Id(profile.id.clone()));
            event.plugin_id = Some(profile.plugin_id.clone());
            event.duration_ms = Some(duration_ms);
            event.metadata = json!({
                "profile_ref": profile_ref,
                "plugin_filter": plugin_filter,
            });
            event.error = Some(profile_error_to_capability_error(&error));
            event.redaction = error.redaction;
            append_audit_event(event)?;
            print_json(&JsonErrorEnvelope {
                ok: false,
                schema_version: PROFILE_CLI_SCHEMA_VERSION,
                command: "profile",
                error,
            })
        }
    }
}

fn handle_migrate(matches: &ArgMatches, ctx: &CliContext) -> Result<(), VoidbError> {
    let (subcommand, sub_matches) = matches.subcommand().ok_or_else(|| {
        VoidbError::Plugin("No migration action specified; use preview or apply.".into())
    })?;
    ensure_json_format(sub_matches)?;

    let plugin_filter = sub_matches.get_one::<String>("plugin").map(String::as_str);
    let connections = migration_connections(&ctx.config.connections, plugin_filter);
    let store = LocalProfileStore::default_store()?;

    match subcommand {
        "preview" => {
            let plan = store.migration_plan(&connections)?;
            let mut event =
                AuditEvent::new(AuditOperation::ProfileMigrate, AuditEventStatus::Succeeded);
            event.metadata = json!({
                "operation": "profile.migrate.preview",
                "plugin_filter": plugin_filter,
                "profile_count": plan.items.len(),
                "profile_store_path": plan.profile_store_path,
                "credential_store_path": plan.credential_store_path,
            });
            append_audit_event(event)?;
            print_json(&success_envelope_with_warnings(
                plan,
                security_warnings_for_config(&ctx.config),
            ))
        }
        "apply" => {
            let master_password = ctx.credential_master_password()?;
            let result = store.apply_native_migration(&connections, master_password)?;
            let mut event =
                AuditEvent::new(AuditOperation::ProfileShow, AuditEventStatus::Succeeded);
            event.metadata = json!({
                "operation": "profile.migrate.apply",
                "plugin_filter": plugin_filter,
                "profile_count": result.plan.items.len(),
                "profiles_written": result.profiles_written,
                "credentials_written": result.credentials_written,
                "legacy_configs_preserved": result.legacy_configs_preserved,
                "profile_store_path": result.plan.profile_store_path,
                "credential_store_path": result.plan.credential_store_path,
            });
            append_audit_event(event)?;
            print_json(&success_envelope_with_warnings(
                result,
                security_warnings_for_config(&ctx.config),
            ))
        }
        other => Err(VoidbError::Plugin(format!(
            "Unknown migration action: {}",
            other
        ))),
    }
}

fn append_audit_event(event: AuditEvent) -> Result<(), VoidbError> {
    LocalAuditStore::default_store()?.append(&event)
}

fn profile_audit_metadata(profile_ref: &str, plugin_filter: Option<&str>) -> Value {
    json!({
        "profile_ref": profile_ref,
        "plugin_filter": plugin_filter,
    })
}

fn profile_error_to_capability_error(error: &ProfileError) -> CapabilityError {
    CapabilityError {
        category: error.category,
        code: error.code.into(),
        message: error.message.into(),
        details: error.details.clone(),
        target: None,
        retryable: error.retryable,
        redaction: error.redaction,
    }
}

#[cfg(test)]
fn profiles_from_connections(connections: &[ConnectionConfig]) -> Vec<ConnectionProfile> {
    voidb_core::connection_configs_to_profiles(connections)
}

fn profiles_from_context(_ctx: &CliContext) -> Result<Vec<ConnectionProfile>, VoidbError> {
    let store = LocalProfileStore::default_store()?;
    store.load_profiles()
}

fn resolve_native_profile_connection(
    ctx: &CliContext,
    profiles: &[ConnectionProfile],
    profile_ref: &str,
    plugin_filter: Option<&str>,
) -> Result<(ConnectionProfile, ConnectionConfig), Box<ProfileError>> {
    let profile = resolve_profile(profiles, profile_ref, plugin_filter)?;
    let master_password = ctx.credential_master_password().map_err(|error| {
        Box::new(profile_error(
            CapabilityErrorCategory::Credential,
            "credential.master_password_required",
            "The native profile store is locked.",
            json!({ "message": error.to_string() }),
            false,
        ))
    })?;
    let connection = LocalProfileStore::default_store()
        .and_then(|store| store.native_connection(&profile, master_password))
        .map_err(|error| {
            Box::new(profile_error(
                CapabilityErrorCategory::Credential,
                "credential.native_profile_unavailable",
                "Native profile configuration could not be unlocked.",
                json!({ "profile_id": profile.id, "message": error.to_string() }),
                false,
            ))
        })?;
    Ok((profile, connection))
}

fn migration_connections(
    connections: &[ConnectionConfig],
    plugin_filter: Option<&str>,
) -> Vec<ConnectionConfig> {
    connections
        .iter()
        .filter(|connection| {
            let Some(plugin_filter) = plugin_filter else {
                return true;
            };

            profile_plugin_id(connection) == plugin_filter
                || connection.effective_plugin_id() == plugin_filter
        })
        .cloned()
        .collect()
}

fn profile_list_data(
    profiles: &[ConnectionProfile],
    plugin_filter: Option<&str>,
) -> ProfileListData {
    let profiles = profiles
        .iter()
        .filter(|profile| profile_matches_plugin(profile, plugin_filter))
        .map(ProfileListItem::from_profile)
        .collect();

    ProfileListData {
        profiles,
        page: ProfilePage {
            next_page_token: None,
        },
    }
}

fn resolve_profile(
    profiles: &[ConnectionProfile],
    profile_ref: &str,
    plugin_filter: Option<&str>,
) -> Result<ConnectionProfile, Box<ProfileError>> {
    let matches: Vec<_> = profiles
        .iter()
        .filter(|profile| profile_matches_plugin(profile, plugin_filter))
        .filter(|profile| profile_matches_ref(profile, profile_ref))
        .cloned()
        .collect();

    match matches.len() {
        0 => Err(Box::new(profile_not_found(profile_ref, plugin_filter))),
        1 => Ok(matches[0].clone()),
        _ => Err(Box::new(profile_ref_ambiguous(profile_ref, matches))),
    }
}

#[cfg(test)]
fn resolve_profile_connection<'a>(
    profiles: &[ConnectionProfile],
    connections: &'a [ConnectionConfig],
    profile_ref: &str,
    plugin_filter: Option<&str>,
) -> Result<(ConnectionProfile, &'a ConnectionConfig), Box<ProfileError>> {
    let profile = resolve_profile(profiles, profile_ref, plugin_filter)?;
    let Some(legacy_connection_key) = profile.metadata["legacy_connection_key"].as_str() else {
        return Err(Box::new(profile_error(
            CapabilityErrorCategory::Internal,
            "internal.profile_missing_legacy_connection_key",
            "Legacy profile metadata did not include a connection key.",
            json!({ "profile_id": profile.id }),
            false,
        )));
    };

    let connection = connections
        .iter()
        .find(|connection| connection.connection_key() == legacy_connection_key)
        .ok_or_else(|| {
            Box::new(profile_error(
                CapabilityErrorCategory::Internal,
                "internal.profile_connection_not_found",
                "Legacy profile resolved but its source connection was not available.",
                json!({
                    "profile_id": profile.id,
                    "legacy_connection_key": legacy_connection_key,
                }),
                false,
            ))
        })?;

    Ok((profile, connection))
}

fn profile_matches_ref(profile: &ConnectionProfile, profile_ref: &str) -> bool {
    if let Some(id) = profile_ref.strip_prefix("id:") {
        return profile.id == id;
    }
    if profile.id == profile_ref {
        return true;
    }

    let name = profile_ref
        .strip_prefix("name:")
        .or_else(|| profile_ref.strip_prefix("alias:"))
        .unwrap_or(profile_ref);
    profile_names_equal(&profile.name, name)
}

fn profile_matches_plugin(profile: &ConnectionProfile, plugin_filter: Option<&str>) -> bool {
    let Some(plugin_filter) = plugin_filter else {
        return true;
    };

    profile.plugin_id == plugin_filter
        || profile.metadata["legacy_plugin_id"]
            .as_str()
            .is_some_and(|legacy_plugin_id| legacy_plugin_id == plugin_filter)
}

fn profile_not_found(profile_ref: &str, plugin_filter: Option<&str>) -> ProfileError {
    profile_error(
        CapabilityErrorCategory::Validation,
        "validation.profile_ref_not_found",
        "Profile reference did not match any saved profile.",
        json!({
            "profile_ref": profile_ref,
            "plugin": plugin_filter,
        }),
        false,
    )
}

fn profile_ref_ambiguous(profile_ref: &str, matches: Vec<ConnectionProfile>) -> ProfileError {
    let candidates: Vec<Value> = matches
        .into_iter()
        .map(|profile| {
            json!({
                "id": profile.id,
                "name": profile.name,
                "plugin_id": profile.plugin_id,
                "source": profile.metadata["source"],
            })
        })
        .collect();

    profile_error(
        CapabilityErrorCategory::Conflict,
        "conflict.profile_ref_ambiguous",
        "Profile reference matched multiple profiles; pass id:<profile-id> or --plugin.",
        json!({
            "profile_ref": profile_ref,
            "candidates": candidates,
        }),
        false,
    )
}

fn profile_test_data(
    profile: &ConnectionProfile,
    message: &str,
    duration_ms: u64,
) -> ProfileTestData {
    ProfileTestData {
        profile: ConnectionProfileRef::id(profile.id.clone()),
        profile_id: profile.id.clone(),
        name: profile.name.clone(),
        plugin_id: profile.plugin_id.clone(),
        storage: "native_profile_store",
        capability_id: "connection.test",
        status: "succeeded",
        message: message.to_string(),
        timing: ProfileTestTiming {
            duration_ms,
            timeout_ms: None,
        },
        redaction: RedactionStatus::NotRequired,
    }
}

fn profile_test_failed(
    profile: &ConnectionProfile,
    connection: &ConnectionConfig,
    diagnostic: &str,
    duration_ms: u64,
) -> ProfileError {
    let mut error = profile_error(
        CapabilityErrorCategory::TargetSystem,
        "target_system.profile_test_failed",
        "Profile test failed.",
        json!({
            "profile_id": profile.id,
            "name": profile.name,
            "plugin_id": profile.plugin_id,
            "storage": "native_profile_store",
            "capability_id": "connection.test",
            "diagnostic": redact_diagnostic(diagnostic, connection),
            "timing": {
                "duration_ms": duration_ms,
                "timeout_ms": null,
            },
        }),
        false,
    );
    error.redaction = RedactionStatus::Applied;
    error
}

fn redact_diagnostic(diagnostic: &str, connection: &ConnectionConfig) -> String {
    if let Some(plugin_config) = &connection.plugin_config {
        return redact_text_with_json(diagnostic, plugin_config).0;
    }

    diagnostic.to_string()
}

fn profile_error(
    category: CapabilityErrorCategory,
    code: &'static str,
    message: &'static str,
    details: Value,
    retryable: bool,
) -> ProfileError {
    ProfileError {
        category,
        code,
        message,
        details,
        target: None,
        retryable,
        redaction: RedactionStatus::NotRequired,
    }
}

// ---------------------------------------------------------------------------
// Profile document lifecycle: create / update / validate
// ---------------------------------------------------------------------------

fn print_profile_error(error: Box<ProfileError>) -> Result<(), VoidbError> {
    print_json(&JsonErrorEnvelope {
        ok: false,
        schema_version: PROFILE_CLI_SCHEMA_VERSION,
        command: "profile",
        error: *error,
    })
}

fn audit_profile_failure(
    operation: AuditOperation,
    error: &ProfileError,
    metadata: Value,
) -> Result<(), VoidbError> {
    let mut event = AuditEvent::new(operation, AuditEventStatus::Failed);
    event.metadata = metadata;
    event.error = Some(profile_error_to_capability_error(error));
    event.redaction = error.redaction;
    append_audit_event(event)
}

fn audit_profile_success(
    operation: AuditOperation,
    profile: &ConnectionProfile,
    metadata: Value,
) -> Result<(), VoidbError> {
    let mut event = AuditEvent::new(operation, AuditEventStatus::Succeeded);
    event.profile = Some(ConnectionProfileRef::Id(profile.id.clone()));
    event.plugin_id = Some(profile.plugin_id.clone());
    event.metadata = metadata;
    append_audit_event(event)
}

#[derive(Debug, Serialize)]
struct ProfileMutationData {
    profile: ConnectionProfile,
    dry_run: bool,
}

#[derive(Debug, Serialize)]
struct ProfileValidateData {
    plugin_id: String,
    valid: bool,
    violations: Vec<Value>,
    schema_known: bool,
}

const SECRET_IN_PAYLOAD_CODE: &str = "validation.secret_in_profile_payload";

fn secret_in_payload_error(offenders: Vec<Value>) -> Box<ProfileError> {
    Box::new(profile_error(
        CapabilityErrorCategory::Validation,
        SECRET_IN_PAYLOAD_CODE,
        "Profile input contained plaintext credential material; pass secrets with --credential sources instead.",
        json!({ "paths": offenders }),
        false,
    ))
}

/// Flag every credential-shaped value in a document that is about to be
/// stored from CLI input. Schema-declared secret fields are authoritative
/// even when the key name alone would not be classified as a credential.
fn secret_payload_offenders(metadata: &Value, schema: Option<&ProfileFormSchema>) -> Vec<Value> {
    let mut offenders: Vec<Value> = collect_redaction_targets(metadata)
        .into_iter()
        .filter_map(|target| {
            let RedactionTargetKind::Credential(class) = target.kind else {
                return None;
            };
            Some(json!({
                "path": dot_path_to_pointer(&target.path),
                "class": serde_json::to_value(class).unwrap_or(Value::Null),
            }))
        })
        .collect();

    let Some(schema) = schema else {
        return offenders;
    };
    for field in &schema.fields {
        if !matches!(field.kind, ProfileFormFieldKind::Secret) {
            continue;
        }
        let Some(value) = metadata.pointer(&field.path) else {
            continue;
        };
        let present = match value {
            Value::Null => false,
            Value::String(text) => !text.trim().is_empty(),
            _ => true,
        };
        if !present {
            continue;
        }
        let path = json!(field.path);
        if !offenders.iter().any(|item| item["path"] == path) {
            offenders.push(json!({ "path": path, "class": { "kind": "schema_secret" } }));
        }
    }
    offenders
}

fn reject_secret_payload(
    metadata: &Value,
    schema: Option<&ProfileFormSchema>,
) -> Result<(), Box<ProfileError>> {
    let offenders = secret_payload_offenders(metadata, schema);
    if offenders.is_empty() {
        return Ok(());
    }
    Err(secret_in_payload_error(offenders))
}

/// Reject a `--set PATH=VALUE` patch that would write plaintext credential
/// material. `pointer` is relative to the metadata document.
fn reject_set_target(
    pointer: &str,
    value: &Value,
    schema: &ProfileFormSchema,
) -> Result<(), Box<ProfileError>> {
    let offenders = secret_payload_offenders(value, None);
    if !offenders.is_empty() {
        let prefixed: Vec<Value> = offenders
            .into_iter()
            .map(|mut item| {
                let path = item["path"].as_str().unwrap_or_default().to_string();
                let joined = if path == "/" {
                    pointer.to_string()
                } else {
                    format!("{pointer}{path}")
                };
                item["path"] = json!(joined);
                item
            })
            .collect();
        return Err(secret_in_payload_error(prefixed));
    }

    if let Value::String(text) = value {
        if !text.trim().is_empty() {
            let last_key = pointer.rsplit('/').next().unwrap_or_default();
            let schema_secret = schema.fields.iter().any(|field| {
                field.path == pointer && matches!(field.kind, ProfileFormFieldKind::Secret)
            });
            if credential_class_for_key(last_key).is_some() || schema_secret {
                return Err(secret_in_payload_error(vec![json!({
                    "path": pointer,
                    "class": { "kind": "schema_secret" },
                })]));
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone)]
enum SecretSourceKind {
    Env(String),
    File(String),
}

#[derive(Debug, Clone)]
struct SecretSource {
    class: CredentialClass,
    class_token: String,
    source: SecretSourceKind,
}

fn credential_class_from_token(token: &str) -> CredentialClass {
    match token {
        "password" => CredentialClass::Password,
        "token" => CredentialClass::Token,
        "api_key" => CredentialClass::ApiKey,
        "private_key" => CredentialClass::PrivateKey,
        "client_certificate" | "client_cert" => CredentialClass::ClientCertificate,
        "cloud_access_key" | "access_key" => CredentialClass::CloudAccessKey,
        "cloud_secret_key" | "secret_key" => CredentialClass::CloudSecretKey,
        other => CredentialClass::Other(other.to_string()),
    }
}

/// Parse `<class>:env=<VAR>` or `<class>:file=<PATH>`. Source values are
/// operational input: names may be echoed, resolved values may not.
fn parse_secret_source(raw: &str) -> Result<SecretSource, Box<ProfileError>> {
    const CODE: &str = "validation.credential_source_invalid";
    let Some((class_token, source)) = raw.split_once(':') else {
        return Err(Box::new(profile_error(
            CapabilityErrorCategory::Validation,
            CODE,
            "Credential sources must look like <class>:env=VAR or <class>:file=PATH.",
            json!({}),
            false,
        )));
    };
    let (kind, value) = source.split_once('=').ok_or_else(|| {
        Box::new(profile_error(
            CapabilityErrorCategory::Validation,
            CODE,
            "Credential sources must look like <class>:env=VAR or <class>:file=PATH.",
            json!({}),
            false,
        ))
    })?;
    if class_token.is_empty() || value.is_empty() {
        return Err(Box::new(profile_error(
            CapabilityErrorCategory::Validation,
            CODE,
            "Credential source class and value must not be empty.",
            json!({}),
            false,
        )));
    }
    let source = match kind {
        "env" => {
            let valid_name = value
                .chars()
                .next()
                .is_some_and(|first| first.is_ascii_uppercase() || first == '_')
                && value
                    .chars()
                    .all(|rest| rest.is_ascii_alphanumeric() || rest == '_');
            if !valid_name {
                return Err(Box::new(profile_error(
                    CapabilityErrorCategory::Validation,
                    CODE,
                    "Environment variable names must match [A-Z_][A-Za-z0-9_]*.",
                    json!({ "variable": value }),
                    false,
                )));
            }
            SecretSourceKind::Env(value.to_string())
        }
        "file" => SecretSourceKind::File(value.to_string()),
        _ => {
            return Err(Box::new(profile_error(
                CapabilityErrorCategory::Validation,
                CODE,
                "Unsupported credential source kind; use env or file.",
                json!({ "kind": kind }),
                false,
            )));
        }
    };
    Ok(SecretSource {
        class: credential_class_from_token(class_token),
        class_token: class_token.to_string(),
        source,
    })
}

/// Resolve a secret source to its plaintext value. The value is operational
/// input and is never echoed into errors, logs, or output.
fn resolve_secret_source(source: &SecretSource) -> Result<String, Box<ProfileError>> {
    const CODE: &str = "credential.secret_source_unavailable";
    match &source.source {
        SecretSourceKind::Env(name) => std::env::var(name).map_err(|_| {
            Box::new(profile_error(
                CapabilityErrorCategory::Credential,
                CODE,
                "The environment variable for the credential source was not set.",
                json!({ "source": "env", "variable": name }),
                false,
            ))
        }),
        SecretSourceKind::File(path) => {
            let content = std::fs::read_to_string(path).map_err(|_| {
                Box::new(profile_error(
                    CapabilityErrorCategory::Credential,
                    CODE,
                    "The credential source file could not be read.",
                    json!({ "source": "file", "path": path }),
                    false,
                ))
            })?;
            // A single trailing newline from `echo value > file` is not part
            // of the secret.
            let trimmed = content
                .strip_suffix("\r\n")
                .or_else(|| content.strip_suffix('\n'))
                .unwrap_or(&content);
            if trimmed.is_empty() {
                return Err(Box::new(profile_error(
                    CapabilityErrorCategory::Credential,
                    CODE,
                    "The credential source file was empty.",
                    json!({ "source": "file", "path": path }),
                    false,
                )));
            }
            Ok(trimmed.to_string())
        }
    }
}

fn field_key_class(path: &str) -> Option<CredentialClass> {
    path.rsplit('/').next().and_then(credential_class_for_key)
}

/// Resolve where a `--credential <class>:<source>` value belongs in the
/// metadata document: a schema secret field first, then an existing
/// credential-shaped path, then a top-level key named after the class.
fn secret_pointer_for_class(
    schema: &ProfileFormSchema,
    metadata: &Value,
    source: &SecretSource,
) -> Result<String, Box<ProfileError>> {
    const CODE: &str = "validation.credential_class_unknown";
    let schema_matches: Vec<&str> = schema
        .fields
        .iter()
        .filter(|field| matches!(field.kind, ProfileFormFieldKind::Secret))
        .filter(|field| field_key_class(&field.path).as_ref() == Some(&source.class))
        .map(|field| field.path.as_str())
        .collect();
    match schema_matches.as_slice() {
        [path] => return Ok((*path).to_string()),
        [] => {}
        [_, ..] => {
            return Err(Box::new(profile_error(
                CapabilityErrorCategory::Validation,
                "validation.credential_class_ambiguous",
                "The credential class matched multiple schema secret fields.",
                json!({ "class": source.class_token }),
                false,
            )));
        }
    }

    let existing: Vec<String> = collect_redaction_targets(metadata)
        .into_iter()
        .filter_map(|target| {
            let RedactionTargetKind::Credential(class) = target.kind else {
                return None;
            };
            (class == source.class).then(|| dot_path_to_pointer(&target.path))
        })
        .collect();
    match existing.as_slice() {
        [path] => return Ok(path.clone()),
        [] => {}
        [_, ..] => {
            return Err(Box::new(profile_error(
                CapabilityErrorCategory::Validation,
                "validation.credential_class_ambiguous",
                "The credential class matched multiple credential-shaped fields.",
                json!({ "class": source.class_token }),
                false,
            )));
        }
    }

    Ok(format!("/{}", source.class_token))
}

fn collect_secret_sources(matches: &ArgMatches) -> Result<Vec<SecretSource>, Box<ProfileError>> {
    let Some(raw_sources) = matches.get_many::<String>("credential") else {
        return Ok(Vec::new());
    };
    raw_sources.map(|raw| parse_secret_source(raw)).collect()
}

/// Resolve and inject `--credential` values into the metadata document. The
/// resolved values never appear in returned errors.
fn apply_secret_sources(
    metadata: &mut Value,
    schema: &ProfileFormSchema,
    sources: &[SecretSource],
) -> Result<(), Box<ProfileError>> {
    for source in sources {
        let value = resolve_secret_source(source)?;
        let pointer = secret_pointer_for_class(schema, metadata, source)?;
        set_at_pointer(metadata, &pointer, Value::String(value))?;
    }
    Ok(())
}

// -- JSON pointer helpers ---------------------------------------------------

fn pointer_segments(pointer: &str) -> Result<Vec<String>, Box<ProfileError>> {
    const CODE: &str = "validation.profile_input_invalid";
    if pointer.is_empty() {
        return Ok(Vec::new());
    }
    let body = pointer.strip_prefix('/').ok_or_else(|| {
        Box::new(profile_error(
            CapabilityErrorCategory::Validation,
            CODE,
            "Credential paths must be JSON-pointer style (start with '/').",
            json!({ "pointer": pointer }),
            false,
        ))
    })?;
    Ok(body
        .split('/')
        .map(|segment| segment.replace("~1", "/").replace("~0", "~"))
        .collect())
}

fn pointer_conflict_error(pointer: &str) -> Box<ProfileError> {
    Box::new(profile_error(
        CapabilityErrorCategory::Validation,
        "validation.profile_input_invalid",
        "The credential path does not address a storable location.",
        json!({ "pointer": pointer }),
        false,
    ))
}

fn set_at_pointer(target: &mut Value, pointer: &str, value: Value) -> Result<(), Box<ProfileError>> {
    let segments = pointer_segments(pointer)?;
    set_at_segments(target, &segments, pointer, value)
}

fn set_at_segments(
    target: &mut Value,
    segments: &[String],
    pointer: &str,
    value: Value,
) -> Result<(), Box<ProfileError>> {
    let Some((head, rest)) = segments.split_first() else {
        *target = value;
        return Ok(());
    };
    if rest.is_empty() {
        return assign_at_segments(target, head, pointer, value);
    }
    if !target.is_object() && !target.is_array() {
        *target = Value::Object(Default::default());
    }
    match target {
        Value::Object(map) => {
            let entry = map
                .entry(head.clone())
                .or_insert_with(|| Value::Object(Default::default()));
            if !entry.is_object() && !entry.is_array() {
                *entry = Value::Object(Default::default());
            }
            set_at_segments(entry, rest, pointer, value)
        }
        Value::Array(items) => {
            let index: usize = head.parse().map_err(|_| pointer_conflict_error(pointer))?;
            let slot = items.get_mut(index).ok_or_else(|| pointer_conflict_error(pointer))?;
            if !slot.is_object() && !slot.is_array() {
                *slot = Value::Object(Default::default());
            }
            set_at_segments(slot, rest, pointer, value)
        }
        _ => Err(pointer_conflict_error(pointer)),
    }
}

fn assign_at_segments(
    target: &mut Value,
    head: &str,
    pointer: &str,
    value: Value,
) -> Result<(), Box<ProfileError>> {
    match target {
        Value::Object(map) => {
            map.insert(head.to_string(), value);
            Ok(())
        }
        Value::Array(items) => {
            let index: usize = head.parse().map_err(|_| pointer_conflict_error(pointer))?;
            if index < items.len() {
                items[index] = value;
                Ok(())
            } else if index == items.len() {
                items.push(value);
                Ok(())
            } else {
                Err(pointer_conflict_error(pointer))
            }
        }
        _ => {
            *target = value;
            Ok(())
        }
    }
}

fn remove_at_pointer(target: &mut Value, pointer: &str) -> bool {
    let segments = match pointer_segments(pointer) {
        Ok(segments) => segments,
        Err(_) => return false,
    };
    remove_at_segments(target, &segments)
}

fn remove_at_segments(target: &mut Value, segments: &[String]) -> bool {
    let Some((head, rest)) = segments.split_first() else {
        return false;
    };
    if rest.is_empty() {
        return match target {
            Value::Object(map) => map.remove(head).is_some(),
            Value::Array(items) => head
                .parse::<usize>()
                .ok()
                .filter(|index| *index < items.len())
                .map(|index| {
                    items.remove(index);
                })
                .is_some(),
            _ => false,
        };
    }
    match target {
        Value::Object(map) => map
            .get_mut(head)
            .map(|child| remove_at_segments(child, rest))
            .unwrap_or(false),
        Value::Array(items) => head
            .parse::<usize>()
            .ok()
            .and_then(|index| items.get_mut(index))
            .map(|child| remove_at_segments(child, rest))
            .unwrap_or(false),
        _ => false,
    }
}

/// Convert a redaction dot path (`auth.password`, `items[0].token`) into a
/// JSON pointer (`/auth/password`, `/items/0/token`).
fn dot_path_to_pointer(path: &str) -> String {
    let mut pointer = String::from("/");
    let mut first = true;
    for segment in path.split('.') {
        let (key, indexes) = split_array_indexes(segment);
        if !first {
            pointer.push('/');
        }
        first = false;
        pointer.push_str(&escape_pointer_token(key));
        for index in indexes {
            pointer.push('/');
            pointer.push_str(&index);
        }
    }
    pointer
}

fn escape_pointer_token(token: &str) -> String {
    token.replace('~', "~0").replace('/', "~1")
}

fn split_array_indexes(segment: &str) -> (&str, Vec<String>) {
    let Some(open) = segment.find('[') else {
        return (segment, Vec::new());
    };
    let key = &segment[..open];
    let mut indexes = Vec::new();
    let mut rest = &segment[open + 1..];
    while let Some(end) = rest.find(']') {
        indexes.push(rest[..end].to_string());
        rest = &rest[end + 1..];
        if rest.starts_with('[') {
            rest = &rest[1..];
        } else {
            break;
        }
    }
    (key, indexes)
}

/// Apply RFC 7386 JSON Merge Patch. `null` values delete keys.
fn json_merge_patch(target: &mut Value, patch: &Value) {
    let Value::Object(patch_map) = patch else {
        *target = patch.clone();
        return;
    };
    if !target.is_object() {
        *target = Value::Object(Default::default());
    }
    let Value::Object(target_map) = target else {
        unreachable!("target normalized above");
    };
    for (key, value) in patch_map {
        if value.is_null() {
            target_map.remove(key);
        } else if let Some(existing) = target_map.get_mut(key) {
            json_merge_patch(existing, value);
        } else {
            let mut fresh = Value::Null;
            json_merge_patch(&mut fresh, value);
            target_map.insert(key.clone(), fresh);
        }
    }
}

// -- shared document plumbing ------------------------------------------------

fn read_input_document(path: &str) -> Result<Value, Box<ProfileError>> {
    const CODE: &str = "validation.profile_input_unreadable";
    let raw = if path == "-" {
        let mut buffer = String::new();
        std::io::stdin()
            .read_to_string(&mut buffer)
            .map_err(|_| {
                Box::new(profile_error(
                    CapabilityErrorCategory::Validation,
                    CODE,
                    "The profile document on stdin could not be read.",
                    json!({ "input": "-" }),
                    false,
                ))
            })?;
        buffer
    } else {
        std::fs::read_to_string(path).map_err(|_| {
            Box::new(profile_error(
                CapabilityErrorCategory::Validation,
                CODE,
                "The profile document file could not be read.",
                json!({ "input": path }),
                false,
            ))
        })?
    };
    serde_json::from_str(&raw).map_err(|error| {
        Box::new(profile_error(
            CapabilityErrorCategory::Validation,
            "validation.profile_input_invalid",
            "The profile document is not valid JSON.",
            json!({ "message": error.to_string() }),
            false,
        ))
    })
}

/// Reserved keys that CLI input documents must never set: identity, plugin
/// ownership, name (create), and version come from flags and Core, and
/// credential references are derived from the encrypted configuration.
fn reject_reserved_fields(
    document: &Value,
    reserved: &[&str],
) -> Result<(), Box<ProfileError>> {
    let Some(map) = document.as_object() else {
        return Err(Box::new(profile_error(
            CapabilityErrorCategory::Validation,
            "validation.profile_input_invalid",
            "The profile document must be a JSON object.",
            json!({}),
            false,
        )));
    };
    let offenders: Vec<&str> = reserved
        .iter()
        .filter(|key| map.contains_key(**key))
        .copied()
        .collect();
    if offenders.is_empty() {
        return Ok(());
    }
    Err(Box::new(profile_error(
        CapabilityErrorCategory::Validation,
        "validation.profile_input_reserved_field",
        "The profile document set fields that are owned by Core or flags.",
        json!({ "fields": offenders }),
        false,
    )))
}

fn document_metadata(document: &Value) -> Result<Value, Box<ProfileError>> {
    let metadata = document
        .as_object()
        .and_then(|map| map.get("metadata"))
        .cloned()
        .unwrap_or_else(|| json!({}));
    if !metadata.is_object() {
        return Err(Box::new(profile_error(
            CapabilityErrorCategory::Validation,
            "validation.profile_input_invalid",
            "Profile metadata must be a JSON object.",
            json!({}),
            false,
        )));
    }
    Ok(metadata)
}

fn document_default_options(document: &Value) -> Value {
    document
        .as_object()
        .and_then(|map| map.get("default_options"))
        .cloned()
        .unwrap_or(Value::Null)
}

fn document_policy(document: &Value) -> Result<Option<ConnectionProfilePolicy>, Box<ProfileError>> {
    let Some(raw) = document.as_object().and_then(|map| map.get("policy")) else {
        return Ok(None);
    };
    if raw.is_null() {
        return Ok(None);
    }
    serde_json::from_value(raw.clone()).map(Some).map_err(|error| {
        Box::new(profile_error(
            CapabilityErrorCategory::Validation,
            "validation.profile_input_invalid",
            "The profile policy did not match the documented policy shape.",
            json!({ "message": error.to_string() }),
            false,
        ))
    })
}

fn schema_violations_error(violations: Vec<Value>) -> Box<ProfileError> {
    Box::new(profile_error(
        CapabilityErrorCategory::Validation,
        "validation.profile_schema_mismatch",
        "Profile metadata did not match the plugin profile schema.",
        json!({ "violations": violations }),
        false,
    ))
}

fn schema_violation_values(violations: &[voidb_core::ProfileFormViolation]) -> Vec<Value> {
    violations
        .iter()
        .map(|violation| {
            json!({
                "path": violation.path,
                "message": violation.message,
            })
        })
        .collect()
}

fn validate_metadata_against_schema(
    metadata: &Value,
    schema: &ProfileFormSchema,
) -> Result<(), Box<ProfileError>> {
    let violations = schema.validate(metadata);
    if violations.is_empty() {
        return Ok(());
    }
    Err(schema_violations_error(schema_violation_values(&violations)))
}

fn profile_schema_for(plugin_id: &str) -> ProfileFormSchema {
    voidb_core::profile_form_schema(plugin_id)
}

fn require_plugin_id<'a>(matches: &'a ArgMatches) -> Result<&'a str, Box<ProfileError>> {
    matches
        .get_one::<String>("plugin")
        .map(String::as_str)
        .ok_or_else(|| {
            Box::new(profile_error(
                CapabilityErrorCategory::Validation,
                "validation.profile_plugin_required",
                "The plugin that owns the profile is required.",
                json!({}),
                false,
            ))
        })
}

fn profile_name_conflict_error(plugin_id: &str, name: &str) -> Box<ProfileError> {
    Box::new(profile_error(
        CapabilityErrorCategory::Conflict,
        "conflict.profile_name_conflict",
        "A profile with this name already exists for the plugin (names are case-insensitive).",
        json!({ "plugin_id": plugin_id, "name": name }),
        false,
    ))
}

fn ensure_name_available(
    profiles: &[ConnectionProfile],
    plugin_id: &str,
    name: &str,
    ignore_profile_id: Option<&str>,
) -> Result<(), Box<ProfileError>> {
    let taken = profiles
        .iter()
        .any(|profile| {
            profile.plugin_id == plugin_id
                && profile.id != ignore_profile_id.unwrap_or_default()
                && profile_names_equal(&profile.name, name)
        });
    if taken {
        return Err(profile_name_conflict_error(plugin_id, name));
    }
    Ok(())
}

fn native_profile_error(profile: &ConnectionProfile) -> Box<ProfileError> {
    Box::new(profile_error(
        CapabilityErrorCategory::Validation,
        "validation.profile_not_native",
        "Only native profile store entries can be mutated; migrate legacy connections first.",
        json!({
            "profile_id": profile.id,
            "source": profile.metadata["source"],
        }),
        false,
    ))
}

fn version_mismatch_error(expected: u64, actual: u64) -> Box<ProfileError> {
    Box::new(profile_error(
        CapabilityErrorCategory::Conflict,
        "conflict.profile_version_mismatch",
        "The stored profile version differs from --expected-version; re-read the profile and retry.",
        json!({ "expected": expected, "actual": actual }),
        false,
    ))
}

fn mutation_envelope(profile: ConnectionProfile, dry_run: bool) -> ProfileMutationData {
    ProfileMutationData { profile, dry_run }
}

/// Shared update guards: the profile must be a native store entry,
/// non-interactive writes need `--expected-version`, and a provided version
/// must match the stored one (optimistic concurrency).
fn ensure_update_guards(
    profile: &ConnectionProfile,
    expected_version: Option<u64>,
    dry_run: bool,
) -> Result<(), Box<ProfileError>> {
    if profile.metadata["source"].as_str() != Some("native_profile_store") {
        return Err(native_profile_error(profile));
    }
    if !dry_run && expected_version.is_none() {
        return Err(Box::new(profile_error(
            CapabilityErrorCategory::Validation,
            "validation.expected_version_required",
            "Non-interactive updates require --expected-version to guard against concurrent edits.",
            json!({ "profile_id": profile.id, "version": profile.version }),
            false,
        )));
    }
    if let Some(expected) = expected_version {
        if expected != profile.version {
            return Err(version_mismatch_error(expected, profile.version));
        }
    }
    Ok(())
}

fn handle_create(matches: &ArgMatches, ctx: &CliContext) -> Result<(), VoidbError> {
    let plugin_id = match require_plugin_id(matches) {
        Ok(plugin_id) => plugin_id.to_string(),
        Err(error) => {
            audit_profile_failure(AuditOperation::ProfileCreate, &error, json!({}))?;
            return print_profile_error(error);
        }
    };
    let name = matches
        .get_one::<String>("name")
        .expect("required by clap")
        .trim()
        .to_string();
    let display_name = matches
        .get_one::<String>("display-name")
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let input_path = matches
        .get_one::<String>("input")
        .expect("required by clap");
    let dry_run = matches.get_flag("dry-run");

    let raw = match read_input_document(input_path) {
        Ok(raw) => raw,
        Err(error) => {
            audit_profile_failure(AuditOperation::ProfileCreate, &error, json!({ "plugin_id": plugin_id }))?;
            return print_profile_error(error);
        }
    };
    let parse = (|| -> Result<Value, Box<ProfileError>> {
        reject_reserved_fields(&raw, &["id", "plugin_id", "name", "version", "credential_refs"])?;
        document_metadata(&raw)
    })();
    let metadata = match parse {
        Ok(metadata) => metadata,
        Err(error) => {
            audit_profile_failure(AuditOperation::ProfileCreate, &error, json!({ "plugin_id": plugin_id }))?;
            return print_profile_error(error);
        }
    };

    let schema = profile_schema_for(&plugin_id);
    let sources = match collect_secret_sources(matches).and_then(|sources| {
        reject_secret_payload(&metadata, Some(&schema))?;
        Ok(sources)
    }) {
        Ok(sources) => sources,
        Err(error) => {
            audit_profile_failure(AuditOperation::ProfileCreate, &error, json!({ "plugin_id": plugin_id }))?;
            return print_profile_error(error);
        }
    };

    let mut metadata = metadata;
    if let Err(error) = apply_secret_sources(&mut metadata, &schema, &sources) {
        audit_profile_failure(AuditOperation::ProfileCreate, &error, json!({ "plugin_id": plugin_id }))?;
        return print_profile_error(error);
    }
    if let Err(error) = validate_metadata_against_schema(&metadata, &schema) {
        audit_profile_failure(AuditOperation::ProfileCreate, &error, json!({ "plugin_id": plugin_id }))?;
        return print_profile_error(error);
    }

    let profiles = profiles_from_context(ctx)?;
    if let Err(error) = ensure_name_available(&profiles, &plugin_id, &name, None) {
        audit_profile_failure(AuditOperation::ProfileCreate, &error, json!({ "plugin_id": plugin_id, "name": name }))?;
        return print_profile_error(error);
    }

    let default_options = document_default_options(&raw);
    let policy = match document_policy(&raw) {
        Ok(policy) => policy,
        Err(error) => {
            audit_profile_failure(AuditOperation::ProfileCreate, &error, json!({ "plugin_id": plugin_id }))?;
            return print_profile_error(error);
        }
    };
    let config = ConnectionConfig {
        name: name.clone(),
        db_type: database_type_for_plugin(&plugin_id),
        plugin_id: Some(plugin_id.clone()),
        plugin_config: Some(metadata),
    };
    let document = NativeProfileDocument {
        default_options: Some(default_options),
        policy,
    };

    if dry_run {
        let plan = derive_native_profile(
            &new_native_profile_id(),
            None,
            &config,
            display_name,
            &document,
        );
        audit_profile_success(
            AuditOperation::ProfileCreate,
            &plan,
            json!({ "plugin_id": plugin_id, "name": name, "dry_run": true }),
        )?;
        return print_json(&success_envelope_with_warnings(
            mutation_envelope(plan, true),
            security_warnings_for_config(&ctx.config),
        ));
    }

    let master_password = ctx.credential_master_password()?;
    let store = LocalProfileStore::default_store()?;
    let profile = match store.upsert_native_connection_document(
        None,
        &config,
        display_name,
        master_password,
        document,
    ) {
        Ok(profile) => profile,
        Err(error) => {
            let error = Box::new(profile_error(
                CapabilityErrorCategory::Validation,
                "validation.profile_store_rejected",
                "The profile store rejected the new profile.",
                json!({ "plugin_id": plugin_id, "message": error.to_string() }),
                false,
            ));
            audit_profile_failure(AuditOperation::ProfileCreate, &error, json!({ "plugin_id": plugin_id, "name": name }))?;
            return print_profile_error(error);
        }
    };

    audit_profile_success(
        AuditOperation::ProfileCreate,
        &profile,
        json!({ "plugin_id": plugin_id, "name": name, "dry_run": false }),
    )?;
    print_json(&success_envelope_with_warnings(
        mutation_envelope(profile, false),
        security_warnings_for_config(&ctx.config),
    ))
}

fn handle_update(matches: &ArgMatches, ctx: &CliContext) -> Result<(), VoidbError> {
    let profile_ref = matches
        .get_one::<String>("profile")
        .expect("required by clap");
    let plugin_filter = matches.get_one::<String>("plugin").map(String::as_str);
    let dry_run = matches.get_flag("dry-run");
    let expected_version = matches.get_one::<u64>("expected-version").copied();

    let profiles = profiles_from_context(ctx)?;
    let profile = match resolve_profile(&profiles, profile_ref, plugin_filter) {
        Ok(profile) => profile,
        Err(error) => {
            audit_profile_failure(
                AuditOperation::ProfileUpdate,
                &error,
                profile_audit_metadata(profile_ref, plugin_filter),
            )?;
            return print_profile_error(error);
        }
    };
    let audit_metadata = json!({
        "profile_ref": profile_ref,
        "plugin_filter": plugin_filter,
        "profile_id": profile.id,
        "dry_run": dry_run,
    });

    let error_and_exit = |error: Box<ProfileError>| -> Result<(), VoidbError> {
        audit_profile_failure(AuditOperation::ProfileUpdate, &error, audit_metadata.clone())?;
        print_profile_error(error)
    };

    if let Err(error) = ensure_update_guards(&profile, expected_version, dry_run) {
        return error_and_exit(error);
    }

    let master_password = ctx.credential_master_password()?;
    let store = LocalProfileStore::default_store()?;
    let connection = match store.native_connection(&profile, master_password) {
        Ok(connection) => connection,
        Err(error) => {
            return error_and_exit(Box::new(profile_error(
                CapabilityErrorCategory::Credential,
                "credential.native_profile_unavailable",
                "Native profile configuration could not be unlocked.",
                json!({ "profile_id": profile.id, "message": error.to_string() }),
                false,
            )));
        }
    };

    let mut doc = json!({
        "name": profile.name,
        "metadata": connection.plugin_config.clone().unwrap_or_else(|| json!({})),
        "default_options": profile.default_options,
        "policy": serde_json::to_value(&profile.policy).unwrap_or_else(|_| json!({})),
    });
    if let Some(display_name) = &profile.display_name {
        doc["display_name"] = json!(display_name);
    }

    let schema = profile_schema_for(&profile.plugin_id);

    // Validate the incoming patch before mutating the working document.
    if let Some(raw_path) = matches.get_one::<String>("input") {
        let raw = match read_input_document(raw_path) {
            Ok(raw) => raw,
            Err(error) => return error_and_exit(error),
        };
        if let Err(error) = reject_reserved_fields(
            &raw,
            &["id", "plugin_id", "version", "credential_refs"],
        ) {
            return error_and_exit(error);
        }
        if let Ok(patch_metadata) = document_metadata(&raw) {
            if let Err(error) = reject_secret_payload(&patch_metadata, Some(&schema)) {
                return error_and_exit(error);
            }
        }
        json_merge_patch(&mut doc, &raw);
    }

    for pair in matches.get_many::<String>("set").unwrap_or_default() {
        let Some((path, raw_value)) = pair.split_once('=') else {
            return error_and_exit(Box::new(profile_error(
                CapabilityErrorCategory::Validation,
                "validation.profile_set_invalid",
                "--set values must look like PATH=VALUE.",
                json!({ "value": pair }),
                false,
            )));
        };
        let value: Value = serde_json::from_str(raw_value)
            .unwrap_or_else(|_| Value::String(raw_value.to_string()));
        let (pointer_target, metadata_pointer) = if let Some(rest) = path.strip_prefix("metadata.") {
            (None, format!("/{}", rest.trim_start_matches('/')))
        } else {
            match path {
                "name" | "display_name" => (Some(path), String::new()),
                other => {
                    return error_and_exit(Box::new(profile_error(
                        CapabilityErrorCategory::Validation,
                        "validation.profile_set_invalid",
                        "--set paths must be name, display_name, or metadata.<key>.",
                        json!({ "path": other }),
                        false,
                    )));
                }
            }
        };
        if let Some(field) = pointer_target {
            if field == "name" {
                let Value::String(name) = &value else {
                    return error_and_exit(Box::new(profile_error(
                        CapabilityErrorCategory::Validation,
                        "validation.profile_set_invalid",
                        "--set name requires a string value.",
                        json!({}),
                        false,
                    )));
                };
                doc["name"] = json!(name.trim());
            } else {
                doc["display_name"] = value;
            }
            continue;
        }
        if let Err(error) = reject_set_target(&metadata_pointer, &value, &schema) {
            return error_and_exit(error);
        }
        let metadata = doc
            .get_mut("metadata")
            .expect("metadata object normalized above");
        if let Err(error) = set_at_pointer(metadata, &metadata_pointer, value) {
            return error_and_exit(error);
        }
    }

    for path in matches.get_many::<String>("unset").unwrap_or_default() {
        match path.as_str() {
            "display_name" => {
                doc
                    .as_object_mut()
                    .expect("doc is an object")
                    .remove("display_name");
            }
            other => {
                let Some(rest) = other.strip_prefix("metadata.") else {
                    return error_and_exit(Box::new(profile_error(
                        CapabilityErrorCategory::Validation,
                        "validation.profile_set_invalid",
                        "--unset paths must be display_name or metadata.<key>.",
                        json!({ "path": other }),
                        false,
                    )));
                };
                let pointer = format!("/{}", rest.trim_start_matches('/'));
                let metadata = doc
                    .get_mut("metadata")
                    .expect("metadata object normalized above");
                remove_at_pointer(metadata, &pointer);
            }
        }
    }

    let sources = match collect_secret_sources(matches) {
        Ok(sources) => sources,
        Err(error) => return error_and_exit(error),
    };
    let metadata = doc
        .get_mut("metadata")
        .expect("metadata object normalized above");
    if let Err(error) = apply_secret_sources(metadata, &schema, &sources) {
        return error_and_exit(error);
    }
    let metadata = metadata.clone();

    if let Err(error) = validate_metadata_against_schema(&metadata, &schema) {
        return error_and_exit(error);
    }

    let final_name = doc["name"].as_str().unwrap_or_default().trim().to_string();
    if final_name.is_empty() {
        return error_and_exit(Box::new(profile_error(
            CapabilityErrorCategory::Validation,
            "validation.profile_input_invalid",
            "Profile name must not be empty.",
            json!({}),
            false,
        )));
    }
    if !profile_names_equal(&final_name, &profile.name) {
        if let Err(error) =
            ensure_name_available(&profiles, &profile.plugin_id, &final_name, Some(&profile.id))
        {
            return error_and_exit(error);
        }
    }
    let display_name = doc
        .get("display_name")
        .and_then(Value::as_str)
        .map(str::to_string);
    let policy: ConnectionProfilePolicy = match serde_json::from_value(doc["policy"].clone()) {
        Ok(policy) => policy,
        Err(error) => {
            return error_and_exit(Box::new(profile_error(
                CapabilityErrorCategory::Validation,
                "validation.profile_input_invalid",
                "The profile policy did not match the documented policy shape.",
                json!({ "message": error.to_string() }),
                false,
            )));
        }
    };

    let config = ConnectionConfig {
        name: final_name,
        db_type: database_type_for_plugin(&profile.plugin_id),
        plugin_id: Some(profile.plugin_id.clone()),
        plugin_config: Some(metadata),
    };
    let document = NativeProfileDocument {
        default_options: Some(doc["default_options"].clone()),
        policy: Some(policy),
    };

    if dry_run {
        let plan =
            derive_native_profile(&profile.id, Some(&profile), &config, display_name, &document);
        audit_profile_success(
            AuditOperation::ProfileUpdate,
            &plan,
            audit_metadata,
        )?;
        return print_json(&success_envelope_with_warnings(
            mutation_envelope(plan, true),
            security_warnings_for_config(&ctx.config),
        ));
    }

    let updated = match store.upsert_native_connection_document(
        Some(&profile.id),
        &config,
        display_name,
        master_password,
        document,
    ) {
        Ok(profile) => profile,
        Err(error) => {
            return error_and_exit(Box::new(profile_error(
                CapabilityErrorCategory::Validation,
                "validation.profile_store_rejected",
                "The profile store rejected the profile update.",
                json!({ "profile_id": profile.id, "message": error.to_string() }),
                false,
            )));
        }
    };

    audit_profile_success(AuditOperation::ProfileUpdate, &updated, audit_metadata)?;
    print_json(&success_envelope_with_warnings(
        mutation_envelope(updated, false),
        security_warnings_for_config(&ctx.config),
    ))
}

fn handle_validate(matches: &ArgMatches, ctx: &CliContext) -> Result<(), VoidbError> {
    let plugin_id = match require_plugin_id(matches) {
        Ok(plugin_id) => plugin_id.to_string(),
        Err(error) => {
            audit_profile_failure(AuditOperation::ProfileValidate, &error, json!({}))?;
            return print_profile_error(error);
        }
    };
    let audit_metadata = json!({ "plugin_id": plugin_id });
    let input_path = matches
        .get_one::<String>("input")
        .expect("required by clap");

    let raw = match read_input_document(input_path) {
        Ok(raw) => raw,
        Err(error) => {
            audit_profile_failure(AuditOperation::ProfileValidate, &error, audit_metadata.clone())?;
            return print_profile_error(error);
        }
    };

    let data = (|| -> Result<ProfileValidateData, Box<ProfileError>> {
        reject_reserved_fields(&raw, &["id", "plugin_id", "version", "credential_refs"])?;
        let metadata = document_metadata(&raw)?;
        let policy = document_policy(&raw)?;
        if policy.is_none() && raw.as_object().is_some_and(|map| map.contains_key("policy")) {
            return Err(Box::new(profile_error(
                CapabilityErrorCategory::Validation,
                "validation.profile_input_invalid",
                "The profile policy did not match the documented policy shape.",
                json!({}),
                false,
            )));
        }
        let schema = profile_schema_for(&plugin_id);
        reject_secret_payload(&metadata, Some(&schema))?;
        let violations = schema.validate(&metadata);
        let valid = violations.is_empty();
        Ok(ProfileValidateData {
            plugin_id: plugin_id.clone(),
            valid,
            violations: schema_violation_values(&violations),
            schema_known: !schema.fields.is_empty(),
        })
    })();

    match data {
        Ok(data) => {
            let mut event =
                AuditEvent::new(AuditOperation::ProfileValidate, AuditEventStatus::Succeeded);
            event.plugin_id = Some(plugin_id.clone());
            event.metadata = json!({ "plugin_id": plugin_id, "valid": data.valid });
            append_audit_event(event)?;
            return print_json(&success_envelope_with_warnings(
                data,
                security_warnings_for_config(&ctx.config),
            ));
        }
        Err(error) => {
            audit_profile_failure(AuditOperation::ProfileValidate, &error, audit_metadata)?;
            print_profile_error(error)
        }
    }
}

#[cfg(test)]
fn success_envelope<T: Serialize>(data: T) -> JsonSuccessEnvelope<T> {
    success_envelope_with_warnings(data, Vec::new())
}

fn success_envelope_with_warnings<T: Serialize>(
    data: T,
    warnings: Vec<ProfileWarning>,
) -> JsonSuccessEnvelope<T> {
    JsonSuccessEnvelope {
        ok: true,
        schema_version: PROFILE_CLI_SCHEMA_VERSION,
        command: "profile",
        data,
        warnings,
    }
}

fn security_warnings_for_config(config: &AppConfig) -> Vec<ProfileWarning> {
    let master_password = if config.requires_master_password() {
        MasterPasswordSessionState::Unlocked
    } else {
        MasterPasswordSessionState::NotConfigured
    };
    let state = config.credential_protection_state(master_password);

    if !state.requires_reencryption() {
        return Vec::new();
    }

    vec![ProfileWarning {
        code: DEFAULT_PASSPHRASE_WARNING_CODE.into(),
        message:
            "Credentials saved without a user-controlled master password are weakly protected."
                .into(),
        details: json!({
            "credential_connection_count": state.summary.credential_owner_count,
            "credential_item_count": state.summary.credential_item_count,
            "plugins": state.summary.plugins,
            "storage": "legacy_connection_config",
            "protection_mode": state.mode,
            "migration": state.migration,
            "recommendation": "Set a master password and re-encrypt saved credentials before broad release.",
        }),
    }]
}

#[derive(Debug, Serialize)]
struct JsonSuccessEnvelope<T> {
    ok: bool,
    schema_version: u32,
    command: &'static str,
    data: T,
    warnings: Vec<ProfileWarning>,
}

#[derive(Debug, Serialize)]
struct JsonErrorEnvelope {
    ok: bool,
    schema_version: u32,
    command: &'static str,
    error: ProfileError,
}

#[derive(Debug, Serialize)]
struct ProfileWarning {
    code: String,
    message: String,
    details: Value,
}

#[derive(Debug, Clone, Serialize)]
struct ProfileError {
    category: CapabilityErrorCategory,
    code: &'static str,
    message: &'static str,
    details: Value,
    target: Option<Value>,
    retryable: bool,
    redaction: RedactionStatus,
}

#[derive(Debug, Serialize)]
struct ProfileListData {
    profiles: Vec<ProfileListItem>,
    page: ProfilePage,
}

#[derive(Debug, Serialize)]
struct ProfilePage {
    next_page_token: Option<String>,
}

#[derive(Debug, Serialize)]
struct ProfileListItem {
    id: String,
    name: String,
    plugin_id: String,
    display_name: Option<String>,
    credential_refs: Vec<CredentialRef>,
    policy: ConnectionProfilePolicy,
    availability: ProfileAvailability,
}

impl ProfileListItem {
    fn from_profile(profile: &ConnectionProfile) -> Self {
        Self {
            id: profile.id.clone(),
            name: profile.name.clone(),
            plugin_id: profile.plugin_id.clone(),
            display_name: profile.display_name.clone(),
            credential_refs: profile.credential_refs.clone(),
            policy: profile.policy.clone(),
            availability: ProfileAvailability::for_profile(profile),
        }
    }
}

#[derive(Debug, Serialize)]
struct ProfileAvailability {
    status: ProfileAvailabilityStatus,
    reason: Option<String>,
}

impl ProfileAvailability {
    fn for_profile(profile: &ConnectionProfile) -> Self {
        if SUPPORTED_LEGACY_PROFILE_PLUGINS.contains(&profile.plugin_id.as_str()) {
            Self {
                status: ProfileAvailabilityStatus::Available,
                reason: None,
            }
        } else {
            Self {
                status: ProfileAvailabilityStatus::Unsupported,
                reason: Some(format!(
                    "No built-in profile CLI support is registered for plugin '{}'.",
                    profile.plugin_id
                )),
            }
        }
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
enum ProfileAvailabilityStatus {
    Available,
    Unsupported,
}

#[derive(Debug, Serialize)]
struct ProfileShowData {
    profile: ConnectionProfile,
    schema_status: ProfileSchemaStatus,
}

#[derive(Debug, Serialize)]
struct ProfileTestData {
    profile: ConnectionProfileRef,
    profile_id: String,
    name: String,
    plugin_id: String,
    storage: &'static str,
    capability_id: &'static str,
    status: &'static str,
    message: String,
    timing: ProfileTestTiming,
    redaction: RedactionStatus,
}

#[derive(Debug, Serialize)]
struct ProfileTestTiming {
    duration_ms: u64,
    timeout_ms: Option<u64>,
}

#[derive(Debug, Serialize)]
struct ProfileSchemaStatus {
    status: &'static str,
    reason: &'static str,
}

impl ProfileSchemaStatus {
    fn for_profile(profile: &ConnectionProfile) -> Self {
        match profile.metadata["source"].as_str() {
            Some("native_profile_store") => Self {
                status: "stored",
                reason: "Native profile metadata and encrypted plugin configuration are stored separately.",
            },
            Some("local_profile_store") => Self {
                status: "migration_required",
                reason: "Migrated local profile metadata is stored separately from credential references.",
            },
            _ => Self::legacy_adapter(),
        }
    }

    fn legacy_adapter() -> Self {
        Self {
            status: "not_checked",
            reason: "Legacy ConnectionConfig profiles are not schema-validated in the adapter phase.",
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use voidb_core::{
        ConnectionConfig, DatabaseType, config::AppConfig, migrated_profile_from_connection,
    };

    use super::*;

    const LEGACY_PROFILE_FIXTURE: &str = include_str!("../../tests/fixtures/legacy_profiles.toml");

    fn connection(name: &str, db_type: DatabaseType, plugin_id: Option<&str>) -> ConnectionConfig {
        ConnectionConfig {
            name: name.to_string(),
            db_type,
            plugin_id: plugin_id.map(str::to_string),
            plugin_config: None,
        }
    }

    fn fixture_config() -> AppConfig {
        toml::from_str(LEGACY_PROFILE_FIXTURE).expect("legacy profile fixture parses")
    }

    #[test]
    fn list_output_omits_legacy_plugin_config_values() {
        let mut config = connection("assets", DatabaseType::Plugin, Some("s3"));
        config.plugin_config = Some(json!({
            "endpoint": "https://internal.example",
            "secret_key": "super-secret",
            "bucket": "private-bucket"
        }));
        let profiles = profiles_from_connections(&[config]);

        let envelope = success_envelope(profile_list_data(&profiles, None));
        let value = serde_json::to_value(&envelope).expect("serialize profile list value");
        let output = serde_json::to_string(&envelope).expect("serialize profile list");

        assert_eq!(value["ok"], true);
        assert_eq!(value["schema_version"], PROFILE_CLI_SCHEMA_VERSION);
        assert_eq!(value["command"], "profile");
        assert_eq!(value["warnings"], json!([]));
        assert_eq!(value["data"]["profiles"][0]["name"], "assets");
        assert_eq!(value["data"]["page"]["next_page_token"], Value::Null);
        assert!(!output.contains("internal.example"));
        assert!(!output.contains("super-secret"));
        assert!(!output.contains("private-bucket"));
    }

    #[test]
    fn default_passphrase_warning_is_redacted_and_machine_readable() {
        let mut config = connection("assets", DatabaseType::Plugin, Some("s3"));
        config.plugin_config = Some(json!({
            "endpoint": "https://internal.example",
            "access_key": "AKIA_TEST_VALUE",
            "secret_key": "super-secret",
            "bucket": "private-bucket"
        }));

        let app_config = AppConfig {
            connections: vec![config],
            ..Default::default()
        };
        let warnings = security_warnings_for_config(&app_config);
        let output = serde_json::to_string(&warnings).expect("serialize warnings");

        assert_eq!(warnings.len(), 1);
        assert_eq!(
            warnings[0].code,
            "security.default_passphrase_credential_risk"
        );
        assert_eq!(warnings[0].details["credential_connection_count"], 1);
        assert_eq!(warnings[0].details["plugins"][0], "s3");
        assert!(!output.contains("internal.example"));
        assert!(!output.contains("AKIA_TEST_VALUE"));
        assert!(!output.contains("super-secret"));
        assert!(!output.contains("private-bucket"));
    }

    #[test]
    fn user_passphrase_protection_suppresses_default_passphrase_warning() {
        let mut connection = connection("assets", DatabaseType::Plugin, Some("s3"));
        connection.plugin_config = Some(json!({
            "endpoint": "https://internal.example",
            "secret_key": "super-secret",
        }));
        let mut config = AppConfig {
            connections: vec![connection],
            ..Default::default()
        };
        config
            .set_user_passphrase_protection("correct horse battery staple")
            .expect("set protection");

        let warnings = security_warnings_for_config(&config);

        assert!(warnings.is_empty());
    }

    #[test]
    fn legacy_profile_fixture_defaults_to_default_passphrase_protection() {
        let config = fixture_config();

        assert_eq!(
            config.credential_protection_mode(),
            voidb_core::CredentialProtectionMode::DefaultPassphrase
        );
    }

    #[test]
    fn list_marks_unknown_legacy_plugin_as_unsupported() {
        let config = connection("legacy", DatabaseType::Plugin, Some("custom"));
        let profiles = profiles_from_connections(&[config]);
        let data = serde_json::to_value(profile_list_data(&profiles, None)).expect("list data");

        assert_eq!(data["profiles"][0]["plugin_id"], "custom");
        assert_eq!(data["profiles"][0]["availability"]["status"], "unsupported");
    }

    #[test]
    fn migrate_command_exposes_preview_and_apply() {
        let plugin = ProfileCliPlugin::new();
        let commands = plugin.commands();
        let migrate = commands
            .iter()
            .find(|command| command.get_name() == "migrate")
            .expect("migrate command");
        let subcommands = migrate
            .get_subcommands()
            .map(|command| command.get_name().to_string())
            .collect::<Vec<_>>();

        assert!(subcommands.contains(&"preview".to_string()));
        assert!(subcommands.contains(&"apply".to_string()));
    }

    #[test]
    fn migrated_profile_show_status_requires_native_migration() {
        let profile =
            migrated_profile_from_connection(&connection("local", DatabaseType::SQLite, None));
        let data = serde_json::to_value(ProfileShowData {
            schema_status: ProfileSchemaStatus::for_profile(&profile),
            profile,
        })
        .expect("serialize show data");

        assert_eq!(data["schema_status"]["status"], "migration_required");
        assert_eq!(data["profile"]["metadata"]["source"], "local_profile_store");
    }

    #[test]
    fn native_profile_show_status_is_stored() {
        let mut profile =
            migrated_profile_from_connection(&connection("local", DatabaseType::SQLite, None));
        profile.metadata = json!({ "source": "native_profile_store" });

        let data = serde_json::to_value(ProfileShowData {
            schema_status: ProfileSchemaStatus::for_profile(&profile),
            profile,
        })
        .expect("serialize show data");

        assert_eq!(data["schema_status"]["status"], "stored");
        assert_eq!(
            data["profile"]["metadata"]["source"],
            "native_profile_store"
        );
    }

    #[test]
    fn migration_connection_filter_accepts_normalized_and_legacy_plugin_ids() {
        let postgres = connection("warehouse", DatabaseType::PostgreSQL, None);

        assert_eq!(
            migration_connections(std::slice::from_ref(&postgres), Some("postgres")).len(),
            1
        );
        assert_eq!(
            migration_connections(&[postgres], Some("postgresql")).len(),
            1
        );
    }

    #[test]
    fn show_resolves_bare_name_case_insensitively_when_unique() {
        let profiles =
            profiles_from_connections(&[connection("local", DatabaseType::SQLite, None)]);

        let profile = resolve_profile(&profiles, "LOCAL", None).expect("resolve profile");

        assert_eq!(profile.name, "local");
        assert_eq!(profile.plugin_id, "sqlite");
    }

    #[test]
    fn show_reports_name_shared_across_plugins_as_ambiguous() {
        let profiles = profiles_from_connections(&[
            connection("prod", DatabaseType::MySQL, None),
            connection("prod", DatabaseType::Plugin, Some("redis")),
        ]);

        let error = resolve_profile(&profiles, "prod", None).expect_err("ambiguous profile");

        assert_eq!(error.category, CapabilityErrorCategory::Conflict);
        assert_eq!(error.code, "conflict.profile_ref_ambiguous");
        assert_eq!(error.details["candidates"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn show_resolves_cross_plugin_name_with_plugin_filter() {
        let profiles = profiles_from_connections(&[
            connection("prod", DatabaseType::MySQL, None),
            connection("prod", DatabaseType::Plugin, Some("redis")),
        ]);

        let profile =
            resolve_profile(&profiles, "name:PROD", Some("redis")).expect("resolve profile");

        assert_eq!(profile.name, "prod");
        assert_eq!(profile.plugin_id, "redis");
    }

    #[test]
    fn show_resolves_postgresql_name_filter() {
        let profiles =
            profiles_from_connections(&[connection("warehouse", DatabaseType::PostgreSQL, None)]);

        let profile =
            resolve_profile(&profiles, "warehouse", Some("postgresql")).expect("resolve profile");

        assert_eq!(profile.plugin_id, "postgres");
    }

    #[test]
    fn show_resolves_profile_id_ref() {
        let profiles = profiles_from_connections(&[connection("prod", DatabaseType::MySQL, None)]);
        let profile_id = profiles[0].id.clone();

        let profile = resolve_profile(&profiles, &format!("id:{}", profile_id), None)
            .expect("resolve by profile id");
        let bare_profile =
            resolve_profile(&profiles, &profile_id, None).expect("resolve by bare profile id");

        assert_eq!(profile.id, profile_id);
        assert_eq!(bare_profile.id, profile_id);
    }

    #[test]
    fn test_resolves_profile_to_legacy_connection() {
        let connections = vec![connection("local", DatabaseType::SQLite, None)];
        let profiles = profiles_from_connections(&connections);

        let (profile, connection) =
            resolve_profile_connection(&profiles, &connections, "local", None)
                .expect("resolve connection");

        assert_eq!(profile.plugin_id, "sqlite");
        assert_eq!(connection.connection_key(), "sqlite::local");
    }

    #[test]
    fn test_success_output_is_agent_parseable() {
        let profile = profiles_from_connections(&[connection("local", DatabaseType::SQLite, None)])
            .pop()
            .expect("profile");

        let output = serde_json::to_value(profile_test_data(&profile, "opened ':memory:'", 42))
            .expect("test data");

        assert_eq!(output["profile"]["kind"], "id");
        assert_eq!(output["plugin_id"], "sqlite");
        assert_eq!(output["capability_id"], "connection.test");
        assert_eq!(output["status"], "succeeded");
        assert_eq!(output["timing"]["duration_ms"], 42);
    }

    #[test]
    fn test_failure_output_redacts_secret_values() {
        let mut connection = connection("assets", DatabaseType::Plugin, Some("s3"));
        connection.plugin_config = Some(json!({
            "access_key": "AKIA_TEST_VALUE",
            "secret_key": "super-secret",
            "nested": {
                "refresh_token": "token-value"
            }
        }));
        let profile = profiles_from_connections(&[connection.clone()])
            .pop()
            .expect("profile");

        let error = profile_test_failed(
            &profile,
            &connection,
            "failed with AKIA_TEST_VALUE / super-secret / token-value",
            7,
        );
        let output = serde_json::to_string(&JsonErrorEnvelope {
            ok: false,
            schema_version: PROFILE_CLI_SCHEMA_VERSION,
            command: "profile",
            error,
        })
        .expect("serialize error");

        assert!(output.contains("<redacted:credential>"));
        assert!(!output.contains("AKIA_TEST_VALUE"));
        assert!(!output.contains("super-secret"));
        assert!(!output.contains("token-value"));
    }

    #[test]
    fn show_error_envelope_is_agent_parseable() {
        let profiles: Vec<ConnectionProfile> = Vec::new();
        let error = resolve_profile(&profiles, "missing", None).expect_err("not found");
        let output = serde_json::to_value(JsonErrorEnvelope {
            ok: false,
            schema_version: PROFILE_CLI_SCHEMA_VERSION,
            command: "profile",
            error: *error,
        })
        .unwrap();

        assert_eq!(output["ok"], false);
        assert_eq!(output["schema_version"], PROFILE_CLI_SCHEMA_VERSION);
        assert_eq!(output["command"], "profile");
        assert_eq!(
            output["error"]["code"],
            Value::String("validation.profile_ref_not_found".into())
        );
    }

    #[test]
    fn legacy_config_fixture_loads_into_profile_views_without_rewrite() {
        let config = fixture_config();
        let before = serde_json::to_value(&config).expect("serialize config before");

        let profiles = profiles_from_connections(&config.connections);
        let after = serde_json::to_value(&config).expect("serialize config after");

        assert_eq!(profiles.len(), 4);
        assert_eq!(before, after);
        assert_eq!(config.connections[0].connection_key(), "mysql::prod");
        assert_eq!(config.connections[1].connection_key(), "redis::prod");
        assert_eq!(
            config.connections[2].connection_key(),
            "postgresql::warehouse"
        );
    }

    #[test]
    fn legacy_config_fixture_redacts_profile_list_and_show_output() {
        let config = fixture_config();
        let profiles = profiles_from_connections(&config.connections);
        let list_output =
            serde_json::to_string(&success_envelope(profile_list_data(&profiles, None)))
                .expect("serialize profile list");
        let warehouse = resolve_profile(&profiles, "warehouse", None).expect("warehouse profile");
        let show_output = serde_json::to_string(&success_envelope(ProfileShowData {
            profile: warehouse,
            schema_status: ProfileSchemaStatus::legacy_adapter(),
        }))
        .expect("serialize profile show");

        for output in [list_output, show_output] {
            assert!(!output.contains("mysql-secret"));
            assert!(!output.contains("redis-secret"));
            assert!(!output.contains("postgres-secret"));
            assert!(!output.contains("custom-secret"));
            assert!(!output.contains("mysql.internal.example"));
            assert!(!output.contains("redis.internal.example"));
            assert!(!output.contains("postgres.internal.example"));
            assert!(!output.contains("custom.internal.example"));
        }
    }

    #[test]
    fn legacy_config_fixture_exposes_refs_not_credential_values() {
        let config = fixture_config();
        let profiles = profiles_from_connections(&config.connections);
        let mysql = resolve_profile(&profiles, "prod", Some("mysql")).expect("mysql prod");
        let redis = resolve_profile(&profiles, "prod", Some("redis")).expect("redis prod");
        let custom =
            resolve_profile(&profiles, "legacy", Some("custom-protocol")).expect("custom legacy");
        let output = serde_json::to_string(&success_envelope(profile_list_data(&profiles, None)))
            .expect("serialize profile list");

        assert_eq!(mysql.credential_refs.len(), 1);
        assert_eq!(
            mysql.credential_refs[0].class,
            voidb_core::CredentialClass::Password
        );
        assert_eq!(redis.credential_refs.len(), 1);
        assert_eq!(custom.credential_refs.len(), 1);
        assert!(output.contains("\"credential_refs\""));
        assert!(!output.contains("mysql-secret"));
        assert!(!output.contains("redis-secret"));
        assert!(!output.contains("custom-secret"));
    }

    #[test]
    fn legacy_config_fixture_preserves_name_and_cross_plugin_duplicates() {
        let config = fixture_config();
        let profiles = profiles_from_connections(&config.connections);

        let ambiguous = resolve_profile(&profiles, "prod", None).expect_err("prod is ambiguous");
        assert_eq!(ambiguous.code, "conflict.profile_ref_ambiguous");

        let redis = resolve_profile(&profiles, "prod", Some("redis")).expect("redis prod");
        assert_eq!(redis.plugin_id, "redis");
        assert_eq!(redis.metadata["legacy_connection_key"], "redis::prod");

        let postgres =
            resolve_profile(&profiles, "warehouse", Some("postgresql")).expect("postgres name");
        assert_eq!(postgres.plugin_id, "postgres");
        assert_eq!(postgres.metadata["legacy_plugin_id"], "postgresql");
        assert_eq!(
            postgres.metadata["legacy_connection_key"],
            "postgresql::warehouse"
        );
    }

    #[test]
    fn legacy_config_fixture_marks_missing_plugin_without_leaking_config() {
        let config = fixture_config();
        let profiles = profiles_from_connections(&config.connections);
        let data = serde_json::to_value(profile_list_data(&profiles, Some("custom-protocol")))
            .expect("serialize list data");
        let output = data.to_string();

        assert_eq!(data["profiles"][0]["name"], "legacy");
        assert_eq!(data["profiles"][0]["plugin_id"], "custom-protocol");
        assert_eq!(data["profiles"][0]["availability"]["status"], "unsupported");
        assert!(!output.contains("custom-secret"));
        assert!(!output.contains("custom.internal.example"));
    }

    #[test]
    fn legacy_config_fixture_redacts_profile_test_failure_diagnostics() {
        let config = fixture_config();
        let profiles = profiles_from_connections(&config.connections);
        let profile = resolve_profile(&profiles, "prod", Some("mysql")).expect("mysql prod");
        let connection = config
            .connections
            .iter()
            .find(|connection| connection.connection_key() == "mysql::prod")
            .expect("mysql connection");

        let error = profile_test_failed(
            &profile,
            connection,
            "target echoed mysql-secret from mysql.internal.example",
            9,
        );
        let output = serde_json::to_string(&JsonErrorEnvelope {
            ok: false,
            schema_version: PROFILE_CLI_SCHEMA_VERSION,
            command: "profile",
            error,
        })
        .expect("serialize");

        assert!(output.contains("<redacted:password>"));
        assert!(output.contains("<redacted:sensitive_metadata>"));
        assert!(!output.contains("mysql-secret"));
        assert!(!output.contains("mysql.internal.example"));
    }

    // -- profile lifecycle (create / update / validate) ----------------------

    struct TempDir {
        path: std::path::PathBuf,
    }

    impl TempDir {
        fn new(label: &str) -> Self {
            static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "voidb-profile-cli-{label}-{}-{id}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path).expect("create temp dir");
            Self { path }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    fn native_profile_fixture(name: &str, version: u64) -> ConnectionProfile {
        let mut profile =
            migrated_profile_from_connection(&connection(name, DatabaseType::Plugin, Some("mysql")));
        profile.metadata = json!({
            "source": "native_profile_store",
            "host": "db.internal.example",
        });
        profile.version = version;
        profile
    }

    #[test]
    fn create_rejects_secret_shaped_payload() {
        let schema = profile_schema_for("mysql");
        let metadata = json!({ "host": "db.internal.example", "password": "plain-secret" });

        let error = reject_secret_payload(&metadata, Some(&schema)).expect_err("secret rejected");

        assert_eq!(error.code, "validation.secret_in_profile_payload");
        assert_eq!(error.category, CapabilityErrorCategory::Validation);
        assert_eq!(error.details["paths"][0]["path"], "/password");
        let output = serde_json::to_string(&JsonErrorEnvelope {
            ok: false,
            schema_version: PROFILE_CLI_SCHEMA_VERSION,
            command: "profile",
            error: *error,
        })
        .expect("serialize error");
        assert!(!output.contains("plain-secret"));
        assert!(output.contains("/password"));
    }

    #[test]
    fn create_accepts_empty_secret_placeholder_and_injects_credential_source() {
        static GUARD: std::sync::Once = std::sync::Once::new();
        GUARD.call_once(|| unsafe {
            std::env::set_var("VOIDB_PROFILE_TEST_PASSWORD", "resolved-secret");
        });

        let schema = profile_schema_for("mysql");
        let mut metadata = json!({
            "host": "db.internal.example",
            "port": 3306,
            "username": "root",
            "password": "",
        });
        reject_secret_payload(&metadata, Some(&schema)).expect("empty placeholder allowed");

        let sources = vec![parse_secret_source("password:env=VOIDB_PROFILE_TEST_PASSWORD").unwrap()];
        apply_secret_sources(&mut metadata, &schema, &sources).expect("inject credential source");

        assert_eq!(metadata["password"], "resolved-secret");
        validate_metadata_against_schema(&metadata, &schema).expect("schema valid after injection");
        // The resolved value is operational input: it never appears in errors.
        let source_error = parse_secret_source("password:env=VOIDB_PROFILE_MISSING_VAR")
            .and_then(|source| apply_secret_sources(&mut json!({}), &schema, &[source]))
            .expect_err("missing env var");
        let output = serde_json::to_string(&JsonErrorEnvelope {
            ok: false,
            schema_version: PROFILE_CLI_SCHEMA_VERSION,
            command: "profile",
            error: *source_error,
        })
        .expect("serialize error");
        assert!(!output.contains("resolved-secret"));
        assert!(output.contains("credential.secret_source_unavailable"));
    }

    #[test]
    fn credential_source_grammar_is_validated() {
        assert_eq!(
            parse_secret_source("password").unwrap_err().code,
            "validation.credential_source_invalid"
        );
        assert_eq!(
            parse_secret_source("password:pipe=x").unwrap_err().code,
            "validation.credential_source_invalid"
        );
        assert_eq!(
            parse_secret_source("password:env=lower_case").unwrap_err().code,
            "validation.credential_source_invalid"
        );
        assert_eq!(
            parse_secret_source("password:env=").unwrap_err().code,
            "validation.credential_source_invalid"
        );

        let env_source = parse_secret_source("cloud_secret_key:env=AWS_SECRET").unwrap();
        assert_eq!(env_source.class, CredentialClass::CloudSecretKey);
        assert!(matches!(
            parse_secret_source("token:file=/tmp/voidb-token").unwrap().source,
            SecretSourceKind::File(path) if path == "/tmp/voidb-token"
        ));
    }

    #[test]
    fn secret_pointer_for_class_prefers_schema_field_then_existing_path() {
        let schema = profile_schema_for("mysql");
        let source = parse_secret_source("password:env=VOIDB_X").unwrap();
        assert_eq!(
            secret_pointer_for_class(&schema, &json!({}), &source).unwrap(),
            "/password"
        );

        // Unknown class with no schema field falls back to a top-level key.
        let custom = parse_secret_source("webhook_secret:env=VOIDB_X").unwrap();
        assert_eq!(
            secret_pointer_for_class(&schema, &json!({}), &custom).unwrap(),
            "/webhook_secret"
        );

        // An existing credential-shaped path in the document is preferred.
        let existing = parse_secret_source("api_key:env=VOIDB_X").unwrap();
        assert_eq!(
            secret_pointer_for_class(&schema, &json!({ "api_key": "old" }), &existing).unwrap(),
            "/api_key"
        );
    }

    #[test]
    fn update_rejects_set_on_secret_paths() {
        let schema = profile_schema_for("mysql");

        let error = reject_set_target("/password", &json!("new-secret"), &schema)
            .expect_err("secret set rejected");
        assert_eq!(error.code, "validation.secret_in_profile_payload");

        reject_set_target("/host", &json!("db2.internal.example"), &schema)
            .expect("non-secret set allowed");

        // An object value carrying secrets is rejected with prefixed paths.
        let error = reject_set_target("/auth", &json!({ "password": "x" }), &schema)
            .expect_err("nested secret rejected");
        assert_eq!(error.details["paths"][0]["path"], "/auth/password");
    }

    #[test]
    fn merge_patch_follows_rfc_7386() {
        let mut doc = json!({
            "name": "prod",
            "display_name": "Production",
            "metadata": { "host": "h", "port": 1 },
        });
        json_merge_patch(
            &mut doc,
            &json!({
                "metadata": { "port": 2, "database": "app" },
                "display_name": null,
            }),
        );

        assert_eq!(
            doc,
            json!({
                "name": "prod",
                "metadata": { "host": "h", "port": 2, "database": "app" },
            })
        );
    }

    #[test]
    fn update_guards_enforce_native_source_and_optimistic_concurrency() {
        let profile = native_profile_fixture("prod", 3);

        ensure_update_guards(&profile, Some(3), false).expect("matching version");
        let error = ensure_update_guards(&profile, Some(2), false).expect_err("stale version");
        assert_eq!(error.code, "conflict.profile_version_mismatch");
        assert_eq!(error.category, CapabilityErrorCategory::Conflict);
        assert_eq!(error.details["expected"], 2);
        assert_eq!(error.details["actual"], 3);

        let error = ensure_update_guards(&profile, None, false).expect_err("version required");
        assert_eq!(error.code, "validation.expected_version_required");
        ensure_update_guards(&profile, None, true).expect("dry-run exempt");

        let mut legacy = native_profile_fixture("legacy", 1);
        legacy.metadata = json!({ "source": "local_profile_store" });
        let error = ensure_update_guards(&legacy, Some(1), false).expect_err("not native");
        assert_eq!(error.code, "validation.profile_not_native");
    }

    #[test]
    fn name_uniqueness_is_case_insensitive_within_plugin() {
        let profiles = profiles_from_connections(&[
            connection("prod", DatabaseType::MySQL, None),
            connection("prod", DatabaseType::Plugin, Some("redis")),
        ]);
        let mysql_id = profiles[0].id.clone();

        let error = ensure_name_available(&profiles, "mysql", "PROD", None)
            .expect_err("case-insensitive conflict");
        assert_eq!(error.code, "conflict.profile_name_conflict");

        ensure_name_available(&profiles, "duckdb", "PROD", None)
            .expect("same name under a different plugin is fine");
        ensure_name_available(&profiles, "mysql", "PROD", Some(&mysql_id))
            .expect("self is ignored");
    }

    #[test]
    fn mutation_envelope_shape_is_agent_parseable() {
        let profile = native_profile_fixture("prod", 7);
        let value = serde_json::to_value(success_envelope(mutation_envelope(profile, true)))
            .expect("serialize mutation envelope");

        assert_eq!(value["ok"], true);
        assert_eq!(value["schema_version"], PROFILE_CLI_SCHEMA_VERSION);
        assert_eq!(value["command"], "profile");
        assert_eq!(value["data"]["dry_run"], true);
        assert_eq!(value["data"]["profile"]["version"], 7);
        assert!(value["data"]["profile"]["metadata"]["host"].is_string());
    }

    #[test]
    fn json_pointer_helpers_build_nested_paths() {
        let mut doc = json!({ "auth": { "type": "Password" } });
        set_at_pointer(&mut doc, "/auth/password", json!("x")).expect("set nested");
        assert_eq!(doc["auth"]["password"], "x");

        let mut doc = json!({});
        set_at_pointer(&mut doc, "/a/b", json!(1)).expect("create intermediates");
        assert_eq!(doc, json!({ "a": { "b": 1 } }));
        assert!(remove_at_pointer(&mut doc, "/a/b"));
        assert_eq!(doc, json!({ "a": {} }));
        assert!(!remove_at_pointer(&mut doc, "/missing/path"));

        let mut doc = json!({ "items": [json!({ "token": "t" })] });
        assert_eq!(dot_path_to_pointer("items[0].token"), "/items/0/token");
        set_at_pointer(&mut doc, "/items/0/token", json!("t2")).expect("set into array");
        assert_eq!(doc["items"][0]["token"], "t2");
    }

    #[test]
    fn validate_flow_uses_stable_codes_for_reserved_fields_and_schema_mismatch() {
        let reserved = json!({ "id": "profile:x", "metadata": {} });
        let error = reject_reserved_fields(
            &reserved,
            &["id", "plugin_id", "name", "version", "credential_refs"],
        )
        .expect_err("reserved field");
        assert_eq!(error.code, "validation.profile_input_reserved_field");
        assert_eq!(error.details["fields"][0], "id");

        let bad_metadata = json!({ "metadata": [] });
        assert_eq!(
            document_metadata(&bad_metadata).unwrap_err().code,
            "validation.profile_input_invalid"
        );

        let schema = profile_schema_for("mysql");
        let error = validate_metadata_against_schema(&json!({}), &schema)
            .expect_err("required fields missing");
        assert_eq!(error.code, "validation.profile_schema_mismatch");
        assert!(error.details["violations"]
            .as_array()
            .unwrap()
            .iter()
            .any(|violation| violation["path"] == "/host"));
    }

    #[test]
    fn profile_lifecycle_end_to_end_through_the_store_uses_versions() {
        let temp = TempDir::new("profile-cli-lifecycle");
        let store = LocalProfileStore::new(
            temp.path.join("profiles.json"),
            temp.path.join("credentials.json"),
        );

        let mut config = connection("prod", DatabaseType::Plugin, Some("mysql"));
        config.plugin_config = Some(json!({
            "host": "db.internal.example",
            "port": 3306,
            "username": "root",
            "password": "",
        }));
        let created = store
            .upsert_native_connection_document(
                None,
                &config,
                Some("Production".into()),
                None,
                NativeProfileDocument::default(),
            )
            .expect("create");
        assert_eq!(created.version, 1);
        assert_eq!(created.metadata["host"], "db.internal.example");
        assert!(created.metadata["password"].is_null());

        let mut updated_config = config.clone();
        updated_config.plugin_config = Some(json!({
            "host": "db2.internal.example",
            "port": 3306,
            "username": "root",
            "password": "injected-via-credential",
        }));
        let updated = store
            .upsert_native_connection_document(
                Some(&created.id),
                &updated_config,
                Some("Production".into()),
                None,
                NativeProfileDocument {
                    default_options: Some(json!({ "readonly": true })),
                    policy: None,
                },
            )
            .expect("update");
        assert_eq!(updated.version, 2);
        assert_eq!(updated.metadata["host"], "db2.internal.example");
        assert!(updated.metadata["password"].is_null());
        assert_eq!(updated.default_options, json!({ "readonly": true }));

        // The decrypted connection still carries the real configuration.
        let resolved = store.native_connection(&updated, None).expect("resolve");
        assert_eq!(
            resolved.plugin_config.as_ref().unwrap()["password"],
            "injected-via-credential"
        );
    }
}
