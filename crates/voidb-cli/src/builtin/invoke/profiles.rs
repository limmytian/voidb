use serde_json::{Value, json};
use voidb_core::capability::{
    CapabilityDefinition, CapabilityError, CapabilityErrorCategory, CapabilityInvocationResult,
    ConnectionProfile, RedactionStatus, TargetSystemFailure,
};
use voidb_core::plugin::cli::CliContext;
use voidb_core::{
    ConnectionConfig, LocalProfileStore, VoidbError, profile_names_equal, redact_text_with_json,
};

use super::output::capability_error;

pub(super) fn resolve_native_profile_connection(
    ctx: &CliContext,
    profiles: &[ConnectionProfile],
    profile_ref: &str,
    capability: &CapabilityDefinition,
) -> Result<(ConnectionProfile, ConnectionConfig), Box<CapabilityError>> {
    let plugin_id = capability.plugin_id.as_str();
    if !capability.connection_required {
        let profile = connectionless_profile(plugin_id);
        if !profile_matches_ref(&profile, profile_ref) {
            return Err(Box::new(capability_error(
                CapabilityErrorCategory::Validation,
                "validation.system_profile_ref_invalid",
                "Connection-independent capabilities use the local system authorization scope.",
                json!({
                    "profile_ref": profile_ref,
                    "expected": ["local", "name:local", format!("id:{}", profile.id)],
                    "plugin_id": plugin_id
                }),
                None,
                false,
            )));
        }
        return Ok((
            profile,
            ConnectionConfig {
                name: "local".into(),
                db_type: voidb_core::DatabaseType::Plugin,
                plugin_id: Some(plugin_id.into()),
                plugin_config: None,
            },
        ));
    }
    let matches = profiles
        .iter()
        .filter(|profile| profile_matches_plugin(profile, plugin_id))
        .filter(|profile| profile_matches_ref(profile, profile_ref))
        .cloned()
        .collect::<Vec<_>>();
    let profile = match matches.len() {
        0 => {
            return Err(Box::new(capability_error(
                CapabilityErrorCategory::Validation,
                "validation.profile_ref_not_found",
                "Profile reference did not match a saved native profile for this capability.",
                json!({ "profile_ref": profile_ref, "plugin_id": plugin_id }),
                None,
                false,
            )));
        }
        1 => matches[0].clone(),
        _ => {
            return Err(Box::new(capability_error(
                CapabilityErrorCategory::Conflict,
                "conflict.profile_ref_ambiguous",
                "Profile reference matched multiple profiles; pass id:<profile-id>.",
                json!({ "profile_ref": profile_ref, "plugin_id": plugin_id }),
                None,
                false,
            )));
        }
    };
    let master_password = ctx
        .credential_master_password()
        .map_err(profile_store_error)?;
    let connection = match LocalProfileStore::default_store()
        .and_then(|store| store.native_connection(&profile, master_password))
    {
        Ok(connection) => connection,
        Err(native_error) => {
            let legacy_key = profile
                .metadata
                .get("legacy_connection_key")
                .and_then(Value::as_str);
            match legacy_key.and_then(|key| {
                ctx.config
                    .connections
                    .iter()
                    .find(|connection| connection.connection_key() == key)
            }) {
                Some(connection) => connection.clone(),
                None => return Err(profile_store_error(native_error)),
            }
        }
    };
    Ok((profile, connection))
}

fn connectionless_profile(plugin_id: &str) -> ConnectionProfile {
    ConnectionProfile {
        id: format!("system:{plugin_id}"),
        name: "local".into(),
        plugin_id: plugin_id.into(),
        display_name: Some(format!("Local {plugin_id} control surface")),
        metadata: json!({
            "scope": "local_system",
            "connection_required": false
        }),
        default_options: Value::Null,
        credential_refs: Vec::new(),
        policy: Default::default(),
    }
}

pub(super) fn profiles_from_context(
    ctx: &CliContext,
) -> Result<Vec<ConnectionProfile>, Box<CapabilityError>> {
    #[cfg(not(test))]
    let _ = ctx;
    let store = LocalProfileStore::default_store().map_err(profile_store_error)?;
    let profiles = store.load_profiles().map_err(profile_store_error)?;
    #[cfg(test)]
    if !ctx.config.connections.is_empty() {
        return Ok(voidb_core::connection_configs_to_profiles(
            &ctx.config.connections,
        ));
    }
    Ok(profiles)
}

fn profile_store_error(error: VoidbError) -> Box<CapabilityError> {
    Box::new(capability_error(
        CapabilityErrorCategory::Internal,
        "internal.profile_store_unavailable",
        "Local profile store could not be loaded.",
        json!({ "message": error.to_string() }),
        None,
        false,
    ))
}

pub(super) fn profile_matches_ref(profile: &ConnectionProfile, profile_ref: &str) -> bool {
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

fn profile_matches_plugin(profile: &ConnectionProfile, plugin_id: &str) -> bool {
    profile.plugin_id == plugin_id
        || profile.metadata["legacy_plugin_id"]
            .as_str()
            .is_some_and(|legacy_plugin_id| legacy_plugin_id == plugin_id)
}

pub(super) fn redact_result(
    mut result: CapabilityInvocationResult,
    connection: &ConnectionConfig,
) -> (CapabilityInvocationResult, RedactionStatus) {
    let Some(plugin_config) = &connection.plugin_config else {
        return (result, RedactionStatus::NotRequired);
    };

    let (output, output_status) = redact_value_with_config(&result.output, plugin_config);
    let (output_summary, summary_status) =
        redact_value_with_config(&result.output_summary, plugin_config);
    result.output = output;
    result.output_summary = output_summary;

    let status = if output_status == RedactionStatus::Applied
        || summary_status == RedactionStatus::Applied
    {
        RedactionStatus::Applied
    } else {
        RedactionStatus::NotRequired
    };

    (result, status)
}

pub(super) fn redact_error(
    mut error: CapabilityError,
    connection: &ConnectionConfig,
) -> CapabilityError {
    let Some(plugin_config) = &connection.plugin_config else {
        return error;
    };

    let (message, message_status) = redact_text_with_json(&error.message, plugin_config);
    let (details, details_status) = redact_value_with_config(&error.details, plugin_config);
    let (target, target_status) = redact_target_failure(error.target, plugin_config);
    error.message = message;
    error.details = details;
    error.target = target;

    if error.redaction == RedactionStatus::Applied
        || message_status == RedactionStatus::Applied
        || details_status == RedactionStatus::Applied
        || target_status == RedactionStatus::Applied
    {
        error.redaction = RedactionStatus::Applied;
    }

    error
}

fn redact_target_failure(
    target: Option<TargetSystemFailure>,
    plugin_config: &Value,
) -> (Option<TargetSystemFailure>, RedactionStatus) {
    let Some(mut target) = target else {
        return (None, RedactionStatus::NotRequired);
    };

    let mut status = RedactionStatus::NotRequired;
    if let Some(message) = target.message {
        let (message, message_status) = redact_text_with_json(&message, plugin_config);
        if message_status == RedactionStatus::Applied {
            status = RedactionStatus::Applied;
        }
        target.message = Some(message);
    }

    (Some(target), status)
}

fn redact_value_with_config(value: &Value, plugin_config: &Value) -> (Value, RedactionStatus) {
    match value {
        Value::String(text) => {
            let (redacted, status) = redact_text_with_json(text, plugin_config);
            (Value::String(redacted), status)
        }
        Value::Array(items) => {
            let mut status = RedactionStatus::NotRequired;
            let items = items
                .iter()
                .map(|item| {
                    let (item, item_status) = redact_value_with_config(item, plugin_config);
                    if item_status == RedactionStatus::Applied {
                        status = RedactionStatus::Applied;
                    }
                    item
                })
                .collect();
            (Value::Array(items), status)
        }
        Value::Object(map) => {
            let mut status = RedactionStatus::NotRequired;
            let map = map
                .iter()
                .map(|(key, value)| {
                    let (value, value_status) = redact_value_with_config(value, plugin_config);
                    if value_status == RedactionStatus::Applied {
                        status = RedactionStatus::Applied;
                    }
                    (key.clone(), value)
                })
                .collect();
            (Value::Object(map), status)
        }
        _ => (value.clone(), RedactionStatus::NotRequired),
    }
}
