//! Adapters from legacy connection storage into capability-first profiles.
//!
//! The current config file persists `ConnectionConfig` records. Capability-first
//! CLI and invocation work should expose `ConnectionProfile` values instead, but
//! the adapter must not rewrite config files or publish decrypted plugin config.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};

use crate::capability::{ConnectionProfile, ConnectionProfileId, CredentialRef, PluginId};
use crate::connection::ConnectionConfig;
use crate::redaction::{RedactionTargetKind, collect_redaction_targets};

const LEGACY_PROFILE_ID_PREFIX: &str = "legacy:";
const LEGACY_PROFILE_SOURCE: &str = "connection_config";

/// Build a stable profile ID from the legacy composite connection key.
///
/// The source key remains available in profile metadata for diagnostics. The ID
/// is encoded so connection names with spaces, separators, or shell-sensitive
/// characters still produce a single safe identifier.
pub fn legacy_profile_id(connection_key: &str) -> ConnectionProfileId {
    format!(
        "{}{}",
        LEGACY_PROFILE_ID_PREFIX,
        URL_SAFE_NO_PAD.encode(connection_key.as_bytes())
    )
}

/// Resolve the plugin ID used by capability-first profile surfaces.
///
/// This intentionally does not mutate the stored `ConnectionConfig`. It only
/// normalizes aliases at the public profile boundary.
pub fn profile_plugin_id(config: &ConnectionConfig) -> PluginId {
    match config.effective_plugin_id() {
        "postgresql" => "postgres".to_string(),
        plugin_id => plugin_id.to_string(),
    }
}

/// Convert one legacy `ConnectionConfig` into a capability-first profile view.
///
/// Plugin-specific config is storage-internal during the adapter phase. The
/// returned profile therefore contains only legacy identity/routing metadata and
/// an empty credential reference list until credential brokering lands.
pub fn connection_config_to_profile(config: &ConnectionConfig) -> ConnectionProfile {
    let connection_key = config.connection_key();
    let legacy_plugin_id = config.effective_plugin_id().to_string();
    let plugin_id = profile_plugin_id(config);

    ConnectionProfile {
        id: legacy_profile_id(&connection_key),
        name: config.name.clone(),
        plugin_id: plugin_id.clone(),
        display_name: Some(config.display_name()),
        metadata: legacy_profile_metadata(config, &connection_key, &legacy_plugin_id, &plugin_id),
        default_options: Value::Null,
        credential_refs: legacy_credential_refs(config, &connection_key),
        policy: Default::default(),
    }
}

/// Convert multiple legacy configs while preserving their input order.
pub fn connection_configs_to_profiles<'a>(
    configs: impl IntoIterator<Item = &'a ConnectionConfig>,
) -> Vec<ConnectionProfile> {
    configs
        .into_iter()
        .map(connection_config_to_profile)
        .collect()
}

fn legacy_profile_metadata(
    config: &ConnectionConfig,
    connection_key: &str,
    legacy_plugin_id: &str,
    plugin_id: &str,
) -> Value {
    let mut metadata = json!({
        "source": LEGACY_PROFILE_SOURCE,
        "legacy_connection_key": connection_key,
        "legacy_plugin_id": legacy_plugin_id,
        "legacy_database_type": config.db_type.protocol_name(),
        "legacy_database_type_label": config.db_type.as_str(),
        "plugin_id_alias_applied": legacy_plugin_id != plugin_id,
        "has_legacy_plugin_config": config.plugin_config.is_some(),
    });
    if let Some(plugin_metadata) = safe_plugin_profile_metadata(config) {
        metadata["plugin"] = plugin_metadata;
    }
    metadata
}

pub(crate) fn safe_plugin_profile_metadata(config: &ConnectionConfig) -> Option<Value> {
    match profile_plugin_id(config).as_str() {
        "ssh" => ssh_profile_metadata(config),
        _ => None,
    }
}

fn ssh_profile_metadata(config: &ConnectionConfig) -> Option<Value> {
    let plugin_config = config.plugin_config.as_ref()?;
    let auth = plugin_config.get("auth")?;
    let auth_type = auth.get("type").and_then(Value::as_str).unwrap_or("unknown");
    let auth_method = match auth_type {
        "Password" | "password" => "password",
        "PublicKey" | "public_key" | "public-key" => "public_key",
        "Agent" | "agent" => "agent",
        _ => "unknown",
    };

    Some(json!({
        "kind": "ssh",
        "auth_method": auth_method,
        "uses_password": auth_method == "password",
        "uses_public_key": auth_method == "public_key",
        "uses_agent": auth_method == "agent",
        "has_private_key_path": auth.get("private_key_path").is_some(),
        "has_passphrase": auth
            .get("passphrase")
            .and_then(Value::as_str)
            .is_some_and(|value| !value.is_empty()),
        "agent_paths_host_key_policy": "known_hosts_strict",
    }))
}

fn legacy_credential_refs(config: &ConnectionConfig, connection_key: &str) -> Vec<CredentialRef> {
    let Some(plugin_config) = &config.plugin_config else {
        return Vec::new();
    };

    collect_redaction_targets(plugin_config)
        .into_iter()
        .filter_map(|target| {
            let RedactionTargetKind::Credential(class) = target.kind else {
                return None;
            };

            Some(CredentialRef {
                id: legacy_credential_ref_id(connection_key, &target.path),
                class,
                label: Some(format!("legacy plugin_config {}", target.path)),
            })
        })
        .collect()
}

fn legacy_credential_ref_id(connection_key: &str, path: &str) -> String {
    format!(
        "{}credential:{}:{}",
        LEGACY_PROFILE_ID_PREFIX,
        URL_SAFE_NO_PAD.encode(connection_key.as_bytes()),
        URL_SAFE_NO_PAD.encode(path.as_bytes())
    )
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::capability::CredentialClass;
    use crate::connection::DatabaseType;

    fn connection(name: &str, db_type: DatabaseType, plugin_id: Option<&str>) -> ConnectionConfig {
        ConnectionConfig {
            name: name.to_string(),
            db_type,
            plugin_id: plugin_id.map(str::to_string),
            plugin_config: None,
        }
    }

    #[test]
    fn adapter_preserves_legacy_composite_identity() {
        let config = connection("prod", DatabaseType::MySQL, None);

        let profile = connection_config_to_profile(&config);

        assert_eq!(profile.id, legacy_profile_id("mysql::prod"));
        assert_eq!(profile.name, "prod");
        assert_eq!(profile.display_name.as_deref(), Some("prod"));
        assert_eq!(profile.plugin_id, "mysql");
        assert_eq!(profile.metadata["legacy_connection_key"], "mysql::prod");
        assert_eq!(profile.metadata["legacy_plugin_id"], "mysql");
    }

    #[test]
    fn adapter_keeps_duplicate_display_names_distinct_by_legacy_key() {
        let mysql = connection("prod", DatabaseType::MySQL, None);
        let redis = connection("prod", DatabaseType::Plugin, Some("redis"));

        let mysql_profile = connection_config_to_profile(&mysql);
        let redis_profile = connection_config_to_profile(&redis);

        assert_eq!(mysql_profile.name, "prod");
        assert_eq!(redis_profile.name, "prod");
        assert_ne!(mysql_profile.id, redis_profile.id);
        assert_eq!(
            mysql_profile.metadata["legacy_connection_key"],
            "mysql::prod"
        );
        assert_eq!(
            redis_profile.metadata["legacy_connection_key"],
            "redis::prod"
        );
    }

    #[test]
    fn adapter_maps_postgresql_legacy_alias_without_rewriting_identity() {
        let config = connection("warehouse", DatabaseType::PostgreSQL, None);

        let profile = connection_config_to_profile(&config);

        assert_eq!(profile.plugin_id, "postgres");
        assert_eq!(profile.id, legacy_profile_id("postgresql::warehouse"));
        assert_eq!(profile.metadata["legacy_plugin_id"], "postgresql");
        assert_eq!(
            profile.metadata["legacy_connection_key"],
            "postgresql::warehouse"
        );
        assert_eq!(profile.metadata["plugin_id_alias_applied"], true);
    }

    #[test]
    fn adapter_preserves_explicit_postgres_plugin_identity() {
        let config = connection("warehouse", DatabaseType::PostgreSQL, Some("postgres"));

        let profile = connection_config_to_profile(&config);

        assert_eq!(profile.plugin_id, "postgres");
        assert_eq!(profile.id, legacy_profile_id("postgres::warehouse"));
        assert_eq!(profile.metadata["legacy_plugin_id"], "postgres");
        assert_eq!(
            profile.metadata["legacy_connection_key"],
            "postgres::warehouse"
        );
        assert_eq!(profile.metadata["plugin_id_alias_applied"], false);
    }

    #[test]
    fn adapter_uses_effective_plugin_id_fallback_for_builtin_configs() {
        let config = connection("local", DatabaseType::SQLite, None);

        let profile = connection_config_to_profile(&config);

        assert_eq!(config.effective_plugin_id(), "sqlite");
        assert_eq!(config.connection_key(), "sqlite::local");
        assert_eq!(profile.plugin_id, "sqlite");
        assert_eq!(profile.id, legacy_profile_id("sqlite::local"));
        assert_eq!(profile.metadata["legacy_connection_key"], "sqlite::local");
    }

    #[test]
    fn adapter_keeps_profile_id_distinct_from_legacy_connection_key() {
        let config = connection("prod db", DatabaseType::MySQL, None);

        let profile = connection_config_to_profile(&config);

        assert_ne!(profile.id, config.connection_key());
        assert_eq!(profile.metadata["legacy_connection_key"], "mysql::prod db");
        assert!(profile.id.starts_with("legacy:"));
        assert!(!profile.id.contains("prod db"));
    }

    #[test]
    fn adapter_exposes_credential_refs_without_plugin_config_values() {
        let mut config = connection("private", DatabaseType::Plugin, Some("s3"));
        config.plugin_config = Some(json!({
            "endpoint": "https://internal.example",
            "access_key": "AKIA_TEST_VALUE",
            "secret_key": "super-secret",
            "bucket": "private-bucket"
        }));

        let profile = connection_config_to_profile(&config);
        let encoded = serde_json::to_string(&profile).expect("serialize profile");

        assert_eq!(profile.metadata["has_legacy_plugin_config"], true);
        assert!(!encoded.contains("internal.example"));
        assert!(!encoded.contains("AKIA_TEST_VALUE"));
        assert!(!encoded.contains("super-secret"));
        assert!(!encoded.contains("private-bucket"));
        assert_eq!(profile.credential_refs.len(), 2);
        assert!(profile.credential_refs.iter().any(|credential_ref| {
            credential_ref.class == CredentialClass::CloudAccessKey
                && credential_ref
                    .label
                    .as_deref()
                    .is_some_and(|label| label.ends_with("access_key"))
        }));
        assert!(profile.credential_refs.iter().any(|credential_ref| {
            credential_ref.class == CredentialClass::CloudSecretKey
                && credential_ref
                    .label
                    .as_deref()
                    .is_some_and(|label| label.ends_with("secret_key"))
        }));
        assert!(
            profile
                .credential_refs
                .iter()
                .all(|credential_ref| credential_ref.id.starts_with("legacy:credential:"))
        );
    }

    #[test]
    fn adapter_maps_nested_legacy_secret_fields_to_stable_credential_refs() {
        let mut config = connection("private", DatabaseType::Plugin, Some("ssh"));
        config.plugin_config = Some(json!({
            "host": "bastion.internal.example",
            "auth": {
                "private_key": "PRIVATE KEY MATERIAL",
                "passphrase": "key-passphrase"
            }
        }));

        let first = connection_config_to_profile(&config);
        let second = connection_config_to_profile(&config);
        let encoded = serde_json::to_string(&first).expect("serialize profile");

        assert_eq!(first.credential_refs.len(), 2);
        assert_eq!(first.credential_refs, second.credential_refs);
        assert!(
            first
                .credential_refs
                .iter()
                .any(|credential_ref| credential_ref.class == CredentialClass::PrivateKey)
        );
        assert!(
            first
                .credential_refs
                .iter()
                .any(|credential_ref| credential_ref.class == CredentialClass::Password)
        );
        assert!(!encoded.contains("PRIVATE KEY MATERIAL"));
        assert!(!encoded.contains("key-passphrase"));
        assert!(!encoded.contains("bastion.internal.example"));
    }

    #[test]
    fn adapter_adds_safe_ssh_auth_metadata_without_values() {
        let mut config = connection("bastion", DatabaseType::Plugin, Some("ssh"));
        config.plugin_config = Some(json!({
            "host": "bastion.internal.example",
            "username": "deploy",
            "auth": {
                "type": "PublicKey",
                "private_key_path": "/home/deploy/.ssh/id_ed25519",
                "passphrase": "key-passphrase"
            }
        }));

        let profile = connection_config_to_profile(&config);
        let encoded = serde_json::to_string(&profile).expect("serialize profile");

        assert_eq!(profile.metadata["plugin"]["kind"], "ssh");
        assert_eq!(profile.metadata["plugin"]["auth_method"], "public_key");
        assert_eq!(profile.metadata["plugin"]["uses_public_key"], true);
        assert_eq!(profile.metadata["plugin"]["has_private_key_path"], true);
        assert_eq!(profile.metadata["plugin"]["has_passphrase"], true);
        assert!(
            profile
                .credential_refs
                .iter()
                .any(|credential_ref| credential_ref.class == CredentialClass::PrivateKey)
        );
        assert!(
            profile
                .credential_refs
                .iter()
                .any(|credential_ref| credential_ref.class == CredentialClass::Password)
        );
        assert_eq!(
            profile.metadata["plugin"]["agent_paths_host_key_policy"],
            "known_hosts_strict"
        );
        assert!(!encoded.contains("bastion.internal.example"));
        assert!(!encoded.contains("deploy"));
        assert!(!encoded.contains("/home/deploy/.ssh/id_ed25519"));
        assert!(!encoded.contains("key-passphrase"));
    }

    #[test]
    fn adapter_preserves_input_order_for_profile_lists() {
        let configs = vec![
            connection("one", DatabaseType::MySQL, None),
            connection("two", DatabaseType::SQLite, Some("sqlite")),
        ];

        let profiles = connection_configs_to_profiles(&configs);

        assert_eq!(profiles[0].name, "one");
        assert_eq!(profiles[1].name, "two");
    }
}
