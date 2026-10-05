//! Built-in `profile` CLI plugin.
//!
//! Exposes capability-first, agent-safe profile views over writable local
//! native profile records backed by encrypted local connection configuration.

use async_trait::async_trait;
use clap::{Arg, ArgMatches, Command};
use serde::Serialize;
use serde_json::{Value, json};
use std::time::Instant;
use voidb_core::capability::{
    ConnectionProfile, ConnectionProfilePolicy, ConnectionProfileRef, CredentialRef,
    RedactionStatus,
};
use voidb_core::plugin::cli::{CliContext, CliPlugin};
use voidb_core::{
    AppConfig, AuditEvent, AuditEventStatus, AuditEventStore, AuditOperation, CapabilityError,
    CapabilityErrorCategory, ConnectionConfig, DEFAULT_PASSPHRASE_WARNING_CODE, LocalAuditStore,
    LocalProfileStore, MasterPasswordSessionState, VoidbError, profile_names_equal,
    profile_plugin_id, redact_text_with_json,
};

use crate::builtin::connections::test_connection_by_plugin;

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
}
