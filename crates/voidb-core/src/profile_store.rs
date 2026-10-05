//! Local writable profile and credential-reference storage.
//!
//! The first migration step keeps legacy `ConnectionConfig` records as the
//! source of live connection details, while persisting agent-safe profile
//! metadata and credential references in separate local files.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::capability::{
    ConnectionProfile, ConnectionProfileId, ConnectionProfilePolicy, CredentialClass,
    CredentialRef, RedactionStatus,
};
use crate::config::{AppConfig, write_private_file};
use crate::connection::ConnectionConfig;
use crate::error::VoidbError;
use crate::profile_adapter::{profile_plugin_id, safe_plugin_profile_metadata};
use crate::redaction::{RedactionTargetKind, collect_redaction_targets};

const PROFILE_STORE_VERSION: u32 = 1;
const CREDENTIAL_STORE_VERSION: u32 = 1;
const MIGRATED_PROFILE_ID_PREFIX: &str = "profile:";
const MIGRATED_CREDENTIAL_ID_PREFIX: &str = "credential:";
const MIGRATED_PROFILE_SOURCE: &str = "local_profile_store";
const NATIVE_PROFILE_SOURCE: &str = "native_profile_store";
const NATIVE_CONNECTION_CONFIG_KIND: &str = "encrypted_plugin_config";

#[derive(Debug, Clone)]
pub struct LocalProfileStore {
    profiles_path: PathBuf,
    credentials_path: PathBuf,
}

impl LocalProfileStore {
    pub fn default_store() -> Result<Self, VoidbError> {
        let dir = AppConfig::config_dir()?;
        Ok(Self::new(
            dir.join("profiles.json"),
            dir.join("credentials.json"),
        ))
    }

    pub fn new(profiles_path: impl Into<PathBuf>, credentials_path: impl Into<PathBuf>) -> Self {
        Self {
            profiles_path: profiles_path.into(),
            credentials_path: credentials_path.into(),
        }
    }

    pub fn profiles_path(&self) -> &Path {
        &self.profiles_path
    }

    pub fn credentials_path(&self) -> &Path {
        &self.credentials_path
    }

    pub fn load_profiles(&self) -> Result<Vec<ConnectionProfile>, VoidbError> {
        Ok(self.load_profile_file()?.profiles)
    }

    pub fn load_credential_records(&self) -> Result<Vec<StoredCredentialRecord>, VoidbError> {
        Ok(self.load_credential_file()?.credentials)
    }

    pub fn save_credential_records(
        &self,
        mut credentials: Vec<StoredCredentialRecord>,
    ) -> Result<usize, VoidbError> {
        credentials.sort_by(|left, right| left.id.cmp(&right.id));
        let count = credentials.len();
        self.write_credential_file(&StoredCredentialFile {
            version: CREDENTIAL_STORE_VERSION,
            credentials,
        })?;
        Ok(count)
    }

    pub fn save_profiles(&self, mut profiles: Vec<ConnectionProfile>) -> Result<usize, VoidbError> {
        validate_profile_identities(&profiles)?;
        profiles.sort_by(|left, right| left.id.cmp(&right.id));
        let count = profiles.len();
        self.write_profile_file(&StoredProfileFile {
            version: PROFILE_STORE_VERSION,
            profiles,
        })?;
        Ok(count)
    }

    /// Create or update a native profile and its encrypted plugin configuration.
    ///
    /// Native profiles are self-contained in the profile and credential stores;
    /// they never require an `AppConfig.connections` fallback at runtime.
    pub fn upsert_native_connection(
        &self,
        existing_profile_id: Option<&str>,
        config: &ConnectionConfig,
        display_name: Option<String>,
        master_password: Option<&str>,
    ) -> Result<ConnectionProfile, VoidbError> {
        let plugin_id = profile_plugin_id(config);
        let profile_name = config.name.trim();
        if profile_name.is_empty() {
            return Err(VoidbError::Config("Profile name is required".to_string()));
        }
        let mut profile_file = self.load_profile_file()?;
        let mut credential_file = self.load_credential_file()?;
        let profile_id = existing_profile_id
            .map(str::to_string)
            .unwrap_or_else(new_native_profile_id);
        let existing = profile_file
            .profiles
            .iter()
            .find(|profile| profile.id == profile_id)
            .cloned();
        if existing_profile_id.is_some() && existing.is_none() {
            return Err(VoidbError::Config(format!(
                "Cannot update unknown profile ID '{}'",
                profile_id
            )));
        }

        if profile_file.profiles.iter().any(|profile| {
            profile.id != profile_id
                && profile.plugin_id == plugin_id
                && profile_names_equal(&profile.name, profile_name)
        }) {
            return Err(VoidbError::Config(format!(
                "A {} profile named '{}' already exists (names are case-insensitive)",
                plugin_id, profile_name
            )));
        }

        let encrypted_config_ref = CredentialRef {
            id: native_connection_credential_id(&profile_id),
            class: CredentialClass::Other("plugin_config".to_string()),
            label: Some("Encrypted local plugin configuration".to_string()),
        };
        let mut credential_refs = vec![encrypted_config_ref.clone()];
        if let Some(plugin_config) = &config.plugin_config {
            credential_refs.extend(
                collect_redaction_targets(plugin_config)
                    .into_iter()
                    .filter_map(|target| {
                        let RedactionTargetKind::Credential(class) = target.kind else {
                            return None;
                        };
                        Some(CredentialRef {
                            id: native_target_credential_id(&profile_id, &target.path),
                            class,
                            label: Some(format!("Local credential {}", target.path)),
                        })
                    }),
            );
        }
        let profile = ConnectionProfile {
            id: profile_id.clone(),
            name: profile_name.to_string(),
            plugin_id: plugin_id.clone(),
            display_name,
            metadata: native_profile_metadata(config),
            default_options: existing
                .as_ref()
                .map(|profile| profile.default_options.clone())
                .unwrap_or(Value::Null),
            credential_refs,
            policy: existing.map(|profile| profile.policy).unwrap_or_default(),
        };

        let plugin_config = serde_json::to_string(
            config.plugin_config.as_ref().unwrap_or(&Value::Null),
        )
        .map_err(|error| {
            VoidbError::Config(format!("Cannot serialize native plugin config: {error}"))
        })?;
        let ciphertext = crate::crypto::encrypt(&plugin_config, master_password)?;
        let created_at = credential_file
            .credentials
            .iter()
            .find(|record| record.id == encrypted_config_ref.id)
            .map(|record| record.created_at)
            .unwrap_or_else(Utc::now);
        let record = StoredCredentialRecord {
            id: encrypted_config_ref.id,
            profile_id: profile_id.clone(),
            plugin_id,
            class: CredentialClass::Other("plugin_config".to_string()),
            label: Some("Encrypted local plugin configuration".to_string()),
            source: StoredCredentialSource::LocalEncryptedPluginConfig { ciphertext },
            created_at,
            redaction: RedactionStatus::Applied,
        };

        profile_file.profiles.retain(|item| item.id != profile_id);
        profile_file.profiles.push(profile.clone());
        validate_profile_identities(&profile_file.profiles)?;
        profile_file
            .profiles
            .sort_by(|left, right| left.id.cmp(&right.id));
        credential_file
            .credentials
            .retain(|item| item.profile_id != profile_id);
        credential_file.credentials.push(record);
        credential_file
            .credentials
            .sort_by(|left, right| left.id.cmp(&right.id));

        self.write_credential_file(&credential_file)?;
        self.write_profile_file(&profile_file)?;
        Ok(profile)
    }

    /// Remove a native profile and all credential records owned by it.
    pub fn delete_profile(&self, profile_id: &str) -> Result<bool, VoidbError> {
        let mut profile_file = self.load_profile_file()?;
        let mut credential_file = self.load_credential_file()?;
        let before = profile_file.profiles.len();
        profile_file
            .profiles
            .retain(|profile| profile.id != profile_id);
        credential_file
            .credentials
            .retain(|record| record.profile_id != profile_id);
        if profile_file.profiles.len() == before {
            return Ok(false);
        }
        self.write_credential_file(&credential_file)?;
        self.write_profile_file(&profile_file)?;
        Ok(true)
    }

    /// Resolve a native profile into the existing in-repo service input type.
    ///
    /// `ConnectionConfig` remains an internal service DTO here; persistence and
    /// identity are fully profile-native.
    pub fn native_connection(
        &self,
        profile: &ConnectionProfile,
        master_password: Option<&str>,
    ) -> Result<ConnectionConfig, VoidbError> {
        if profile.metadata.get("source").and_then(Value::as_str) != Some(NATIVE_PROFILE_SOURCE) {
            return Err(VoidbError::Config(format!(
                "Profile '{}' is not a native profile",
                profile.id
            )));
        }
        let record = self
            .load_credential_file()?
            .credentials
            .into_iter()
            .find(|record| {
                record.profile_id == profile.id
                    && matches!(
                        record.source,
                        StoredCredentialSource::LocalEncryptedPluginConfig { .. }
                    )
            })
            .ok_or_else(|| {
                VoidbError::Config(format!(
                    "Native profile '{}' has no encrypted plugin configuration",
                    profile.id
                ))
            })?;
        let StoredCredentialSource::LocalEncryptedPluginConfig { ciphertext } = record.source
        else {
            unreachable!("source checked above")
        };
        let plaintext = crate::crypto::decrypt(&ciphertext, master_password)?;
        let plugin_config = serde_json::from_str(&plaintext).map_err(|error| {
            VoidbError::Config(format!("Cannot decode native plugin config: {error}"))
        })?;
        Ok(ConnectionConfig {
            name: profile.name.clone(),
            db_type: database_type_for_plugin(&profile.plugin_id),
            plugin_id: Some(profile.plugin_id.clone()),
            plugin_config: Some(plugin_config),
        })
    }

    /// Re-encrypt every native local plugin configuration with a new password.
    pub fn reencrypt_native_credentials(
        &self,
        current_master_password: Option<&str>,
        new_master_password: &str,
    ) -> Result<usize, VoidbError> {
        let mut file = self.load_credential_file()?;
        let mut count = 0;
        for record in &mut file.credentials {
            let StoredCredentialSource::LocalEncryptedPluginConfig { ciphertext } =
                &mut record.source
            else {
                continue;
            };
            let plaintext = crate::crypto::decrypt(ciphertext, current_master_password)?;
            *ciphertext = crate::crypto::encrypt(&plaintext, Some(new_master_password))?;
            count += 1;
        }
        self.write_credential_file(&file)?;
        Ok(count)
    }

    pub fn connection_manager_catalog(
        &self,
        legacy_connections: &[ConnectionConfig],
    ) -> Result<ConnectionManagerProfileCatalog, VoidbError> {
        Ok(ConnectionManagerProfileCatalog::from_profiles(
            profiles_with_migrated_first(self.load_profiles()?, legacy_connections),
        ))
    }

    pub fn migration_plan(
        &self,
        connections: &[ConnectionConfig],
    ) -> Result<ProfileMigrationPlan, VoidbError> {
        let existing_profiles = self.load_profiles()?;
        let existing_by_id = existing_profiles
            .iter()
            .map(|profile| (profile.id.as_str(), profile))
            .collect::<BTreeMap<_, _>>();

        let items = connections
            .iter()
            .map(|connection| {
                let profile = migrated_profile_from_connection(connection);
                let action = match existing_by_id.get(profile.id.as_str()) {
                    None => ProfileMigrationAction::Create,
                    Some(existing) if *existing == &profile => ProfileMigrationAction::Unchanged,
                    Some(_) => ProfileMigrationAction::Update,
                };

                ProfileMigrationItem {
                    action,
                    legacy_connection_key: connection.connection_key(),
                    profile,
                }
            })
            .collect();

        Ok(ProfileMigrationPlan {
            profile_store_path: self.profiles_path.clone(),
            credential_store_path: self.credentials_path.clone(),
            items,
        })
    }

    pub fn apply_migration(
        &self,
        connections: &[ConnectionConfig],
    ) -> Result<ProfileMigrationApplyResult, VoidbError> {
        let plan = self.migration_plan(connections)?;
        let mut profiles_by_id = self
            .load_profiles()?
            .into_iter()
            .map(|profile| (profile.id.clone(), profile))
            .collect::<BTreeMap<_, _>>();

        for item in &plan.items {
            profiles_by_id.insert(item.profile.id.clone(), item.profile.clone());
        }

        let existing_credentials = self.load_credential_records()?;
        let created_at_by_id = existing_credentials
            .iter()
            .map(|record| (record.id.clone(), record.created_at))
            .collect::<BTreeMap<_, _>>();
        let now = Utc::now();
        let mut migrated_record_ids = BTreeSet::new();
        let mut credential_records = Vec::new();

        for connection in connections {
            for record in credential_records_from_connection(connection, &created_at_by_id, now) {
                migrated_record_ids.insert(record.id.clone());
                credential_records.push(record);
            }
        }

        for record in existing_credentials {
            if !migrated_record_ids.contains(&record.id) {
                credential_records.push(record);
            }
        }

        credential_records.sort_by(|a, b| a.id.cmp(&b.id));

        let profiles = profiles_by_id.into_values().collect::<Vec<_>>();
        self.write_profile_file(&StoredProfileFile {
            version: PROFILE_STORE_VERSION,
            profiles: profiles.clone(),
        })?;
        self.write_credential_file(&StoredCredentialFile {
            version: CREDENTIAL_STORE_VERSION,
            credentials: credential_records.clone(),
        })?;

        Ok(ProfileMigrationApplyResult {
            plan,
            profiles_written: profiles.len(),
            credentials_written: credential_records.len(),
            legacy_configs_preserved: true,
        })
    }

    /// Import legacy connections into self-contained native profiles.
    ///
    /// The source config file is left untouched as a rollback backup, but all
    /// active profile reads and connection resolution use the native stores.
    pub fn apply_native_migration(
        &self,
        connections: &[ConnectionConfig],
        master_password: Option<&str>,
    ) -> Result<ProfileMigrationApplyResult, VoidbError> {
        let mut imported_names = BTreeSet::new();
        for connection in connections {
            let plugin_id = profile_plugin_id(connection);
            let key = (plugin_id.clone(), normalize_profile_name(&connection.name));
            if key.1.is_empty() {
                return Err(VoidbError::Config("Profile name is required".to_string()));
            }
            if !imported_names.insert(key) {
                return Err(VoidbError::Config(format!(
                    "Migration contains more than one {} profile named '{}' (names are case-insensitive)",
                    plugin_id, connection.name
                )));
            }
        }

        let mut plan = self.migration_plan(connections)?;
        for connection in connections {
            let plugin_id = profile_plugin_id(connection);
            let existing_profile_id = self
                .load_profiles()?
                .into_iter()
                .find(|profile| {
                    profile.plugin_id == plugin_id
                        && profile_names_equal(&profile.name, &connection.name)
                })
                .map(|profile| profile.id);
            let profile = self.upsert_native_connection(
                existing_profile_id.as_deref(),
                connection,
                None,
                master_password,
            )?;
            if let Some(item) = plan
                .items
                .iter_mut()
                .find(|item| item.legacy_connection_key == connection.connection_key())
            {
                // The migration plan describes the source connection, but its
                // result must reflect the native profile that is actually
                // persisted and used at runtime.
                item.profile = profile;
            }
        }
        Ok(ProfileMigrationApplyResult {
            plan,
            profiles_written: self.load_profiles()?.len(),
            credentials_written: self.load_credential_records()?.len(),
            legacy_configs_preserved: true,
        })
    }

    fn load_profile_file(&self) -> Result<StoredProfileFile, VoidbError> {
        if !self.profiles_path.exists() {
            return Ok(StoredProfileFile::default());
        }

        let content = std::fs::read_to_string(&self.profiles_path).map_err(|error| {
            VoidbError::Config(format!("Cannot read profile store file: {}", error))
        })?;
        serde_json::from_str(&content).map_err(|error| {
            VoidbError::Config(format!("Cannot parse profile store file: {}", error))
        })
    }

    fn load_credential_file(&self) -> Result<StoredCredentialFile, VoidbError> {
        if !self.credentials_path.exists() {
            return Ok(StoredCredentialFile::default());
        }

        let content = std::fs::read_to_string(&self.credentials_path).map_err(|error| {
            VoidbError::Config(format!("Cannot read credential store file: {}", error))
        })?;
        serde_json::from_str(&content).map_err(|error| {
            VoidbError::Config(format!("Cannot parse credential store file: {}", error))
        })
    }

    fn write_profile_file(&self, file: &StoredProfileFile) -> Result<(), VoidbError> {
        let content = serde_json::to_vec_pretty(file)
            .map_err(|error| VoidbError::Config(format!("Cannot serialize profiles: {}", error)))?;
        write_private_file(&self.profiles_path, content)
            .map_err(|error| VoidbError::Config(format!("Cannot write profile store: {}", error)))
    }

    fn write_credential_file(&self, file: &StoredCredentialFile) -> Result<(), VoidbError> {
        let content = serde_json::to_vec_pretty(file).map_err(|error| {
            VoidbError::Config(format!("Cannot serialize credential records: {}", error))
        })?;
        write_private_file(&self.credentials_path, content).map_err(|error| {
            VoidbError::Config(format!("Cannot write credential store: {}", error))
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredProfileFile {
    pub version: u32,

    #[serde(default)]
    pub profiles: Vec<ConnectionProfile>,
}

impl Default for StoredProfileFile {
    fn default() -> Self {
        Self {
            version: PROFILE_STORE_VERSION,
            profiles: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCredentialFile {
    pub version: u32,

    #[serde(default)]
    pub credentials: Vec<StoredCredentialRecord>,
}

impl Default for StoredCredentialFile {
    fn default() -> Self {
        Self {
            version: CREDENTIAL_STORE_VERSION,
            credentials: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StoredCredentialRecord {
    pub id: String,
    pub profile_id: ConnectionProfileId,
    pub plugin_id: String,
    pub class: CredentialClass,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,

    pub source: StoredCredentialSource,
    pub created_at: DateTime<Utc>,

    #[serde(default)]
    pub redaction: RedactionStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StoredCredentialSource {
    LocalEncryptedPluginConfig {
        ciphertext: String,
    },
    LegacyPluginConfig {
        legacy_connection_key: String,
        path: String,
    },
    SyncedObject {
        object_id: String,
        profile_object_id: String,
        credential_ref_object_id: String,
        object_version: u64,
        server_revision: u64,
        encrypted_payload_hash: String,
        encrypted_payload_size: u64,
        encryption: Box<StoredCredentialEncryption>,
        ciphertext: String,
        unavailable: bool,

        #[serde(default, skip_serializing_if = "Option::is_none")]
        unavailable_reason: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredCredentialEncryption {
    pub algorithm: String,
    pub key_wrap: String,
    pub nonce: String,
    pub aad: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileMigrationAction {
    Create,
    Update,
    Unchanged,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProfileMigrationPlan {
    pub profile_store_path: PathBuf,
    pub credential_store_path: PathBuf,
    pub items: Vec<ProfileMigrationItem>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProfileMigrationItem {
    pub action: ProfileMigrationAction,
    pub legacy_connection_key: String,
    pub profile: ConnectionProfile,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProfileMigrationApplyResult {
    pub plan: ProfileMigrationPlan,
    pub profiles_written: usize,
    pub credentials_written: usize,
    pub legacy_configs_preserved: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConnectionManagerProfileCatalog {
    pub entries: Vec<ConnectionManagerProfileEntry>,
}

impl ConnectionManagerProfileCatalog {
    pub fn from_profiles(profiles: Vec<ConnectionProfile>) -> Self {
        Self {
            entries: profiles
                .into_iter()
                .map(ConnectionManagerProfileEntry::from_profile)
                .collect(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConnectionManagerProfileEntry {
    pub profile_id: ConnectionProfileId,
    pub name: String,
    pub plugin_id: String,
    pub display_name: Option<String>,
    pub source: ConnectionManagerProfileSource,
    pub legacy_connection_key: Option<String>,
    pub credential_ref_count: usize,
    pub supports_legacy_crud_route: bool,
    pub supports_test_route: bool,
    pub supports_open_route: bool,
}

impl ConnectionManagerProfileEntry {
    fn from_profile(profile: ConnectionProfile) -> Self {
        let legacy_connection_key = profile
            .metadata
            .get("legacy_connection_key")
            .and_then(Value::as_str)
            .map(str::to_string);
        let supports_legacy_route = legacy_connection_key.is_some();

        Self {
            source: if profile.id.starts_with("legacy:") {
                ConnectionManagerProfileSource::LegacyConfigFallback
            } else {
                ConnectionManagerProfileSource::StoredProfile
            },
            profile_id: profile.id,
            name: profile.name,
            plugin_id: profile.plugin_id,
            display_name: profile.display_name,
            legacy_connection_key,
            credential_ref_count: profile.credential_refs.len(),
            supports_legacy_crud_route: supports_legacy_route,
            supports_test_route: supports_legacy_route,
            supports_open_route: supports_legacy_route,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionManagerProfileSource {
    StoredProfile,
    LegacyConfigFallback,
}

pub fn migrated_profile_id(connection_key: &str) -> ConnectionProfileId {
    format!(
        "{}{}",
        MIGRATED_PROFILE_ID_PREFIX,
        URL_SAFE_NO_PAD.encode(connection_key.as_bytes())
    )
}

pub fn new_native_profile_id() -> ConnectionProfileId {
    format!("{}{}", MIGRATED_PROFILE_ID_PREFIX, Uuid::new_v4())
}

pub fn normalize_profile_name(name: &str) -> String {
    name.trim().to_lowercase()
}

pub fn profile_names_equal(left: &str, right: &str) -> bool {
    normalize_profile_name(left) == normalize_profile_name(right)
}

fn validate_profile_identities(profiles: &[ConnectionProfile]) -> Result<(), VoidbError> {
    let mut ids = BTreeSet::new();
    let mut names = BTreeSet::new();
    for profile in profiles {
        if profile.id.trim().is_empty() || !ids.insert(profile.id.clone()) {
            return Err(VoidbError::Config(format!(
                "Profile ID '{}' is empty or duplicated",
                profile.id
            )));
        }
        let normalized_name = normalize_profile_name(&profile.name);
        if normalized_name.is_empty() {
            return Err(VoidbError::Config(format!(
                "Profile '{}' has an empty name",
                profile.id
            )));
        }
        if !names.insert((profile.plugin_id.clone(), normalized_name)) {
            return Err(VoidbError::Config(format!(
                "Plugin '{}' contains duplicate profile name '{}' (names are case-insensitive)",
                profile.plugin_id, profile.name
            )));
        }
    }
    Ok(())
}

pub fn native_connection_credential_id(profile_id: &str) -> String {
    format!(
        "{}{}:{}",
        MIGRATED_CREDENTIAL_ID_PREFIX,
        URL_SAFE_NO_PAD.encode(profile_id.as_bytes()),
        NATIVE_CONNECTION_CONFIG_KIND
    )
}

fn native_target_credential_id(profile_id: &str, path: &str) -> String {
    format!(
        "{}{}:{}",
        MIGRATED_CREDENTIAL_ID_PREFIX,
        URL_SAFE_NO_PAD.encode(profile_id.as_bytes()),
        URL_SAFE_NO_PAD.encode(path.as_bytes())
    )
}

fn native_profile_metadata(config: &ConnectionConfig) -> Value {
    json!({
        "source": NATIVE_PROFILE_SOURCE,
        "connection_config_version": 1,
        "database_type": config.db_type.protocol_name(),
    })
}

fn database_type_for_plugin(plugin_id: &str) -> crate::connection::DatabaseType {
    match plugin_id {
        "mysql" => crate::connection::DatabaseType::MySQL,
        "postgres" | "postgresql" => crate::connection::DatabaseType::PostgreSQL,
        "sqlite" => crate::connection::DatabaseType::SQLite,
        _ => crate::connection::DatabaseType::Plugin,
    }
}

pub fn migrated_credential_ref_id(connection_key: &str, path: &str) -> String {
    format!(
        "{}{}:{}",
        MIGRATED_CREDENTIAL_ID_PREFIX,
        URL_SAFE_NO_PAD.encode(connection_key.as_bytes()),
        URL_SAFE_NO_PAD.encode(path.as_bytes())
    )
}

pub fn migrated_profile_from_connection(config: &ConnectionConfig) -> ConnectionProfile {
    let connection_key = config.connection_key();
    let legacy_plugin_id = config.effective_plugin_id().to_string();
    let plugin_id = profile_plugin_id(config);

    ConnectionProfile {
        id: migrated_profile_id(&connection_key),
        name: config.name.clone(),
        plugin_id: plugin_id.clone(),
        display_name: Some(config.display_name()),
        metadata: migrated_profile_metadata(config, &connection_key, &legacy_plugin_id, &plugin_id),
        default_options: Value::Null,
        credential_refs: migrated_credential_refs(config, &connection_key),
        policy: ConnectionProfilePolicy::default(),
    }
}

pub fn profiles_with_migrated_first(
    stored_profiles: Vec<ConnectionProfile>,
    legacy_connections: &[ConnectionConfig],
) -> Vec<ConnectionProfile> {
    let migrated_legacy_keys = stored_profiles
        .iter()
        .filter_map(|profile| {
            profile
                .metadata
                .get("legacy_connection_key")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .collect::<BTreeSet<_>>();

    let mut profiles = stored_profiles;
    profiles.extend(
        legacy_connections
            .iter()
            .filter(|connection| !migrated_legacy_keys.contains(&connection.connection_key()))
            .map(crate::profile_adapter::connection_config_to_profile),
    );
    profiles
}

fn migrated_profile_metadata(
    config: &ConnectionConfig,
    connection_key: &str,
    legacy_plugin_id: &str,
    plugin_id: &str,
) -> Value {
    let mut metadata = json!({
        "source": MIGRATED_PROFILE_SOURCE,
        "legacy_connection_key": connection_key,
        "legacy_plugin_id": legacy_plugin_id,
        "legacy_database_type": config.db_type.protocol_name(),
        "legacy_database_type_label": config.db_type.as_str(),
        "plugin_id_alias_applied": legacy_plugin_id != plugin_id,
        "has_legacy_plugin_config": config.plugin_config.is_some(),
        "credential_store": "local",
        "migration_version": PROFILE_STORE_VERSION,
    });
    if let Some(plugin_metadata) = safe_plugin_profile_metadata(config) {
        metadata["plugin"] = plugin_metadata;
    }
    metadata
}

fn migrated_credential_refs(config: &ConnectionConfig, connection_key: &str) -> Vec<CredentialRef> {
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
                id: migrated_credential_ref_id(connection_key, &target.path),
                class,
                label: Some(format!("local credential {}", target.path)),
            })
        })
        .collect()
}

fn credential_records_from_connection(
    config: &ConnectionConfig,
    created_at_by_id: &BTreeMap<String, DateTime<Utc>>,
    fallback_created_at: DateTime<Utc>,
) -> Vec<StoredCredentialRecord> {
    let Some(plugin_config) = &config.plugin_config else {
        return Vec::new();
    };

    let connection_key = config.connection_key();
    let profile_id = migrated_profile_id(&connection_key);
    let plugin_id = profile_plugin_id(config);

    collect_redaction_targets(plugin_config)
        .into_iter()
        .filter_map(|target| {
            let RedactionTargetKind::Credential(class) = target.kind else {
                return None;
            };

            let id = migrated_credential_ref_id(&connection_key, &target.path);
            let created_at = created_at_by_id
                .get(&id)
                .copied()
                .unwrap_or(fallback_created_at);

            Some(StoredCredentialRecord {
                id,
                profile_id: profile_id.clone(),
                plugin_id: plugin_id.clone(),
                class,
                label: Some(format!("local credential {}", target.path)),
                source: StoredCredentialSource::LegacyPluginConfig {
                    legacy_connection_key: connection_key.clone(),
                    path: target.path,
                },
                created_at,
                redaction: RedactionStatus::Withheld,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
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
    fn migrated_profile_is_distinct_from_legacy_profile_and_redacted() {
        let mut config = connection("assets", DatabaseType::Plugin, Some("s3"));
        config.plugin_config = Some(json!({
            "endpoint": "https://internal.example",
            "access_key": "AKIA_TEST_VALUE",
            "secret_key": "super-secret",
            "bucket": "private-bucket"
        }));

        let profile = migrated_profile_from_connection(&config);
        let encoded = serde_json::to_string(&profile).expect("serialize profile");

        assert!(profile.id.starts_with("profile:"));
        assert_ne!(
            profile.id,
            crate::profile_adapter::legacy_profile_id("s3::assets")
        );
        assert_eq!(profile.metadata["source"], "local_profile_store");
        assert_eq!(profile.metadata["legacy_connection_key"], "s3::assets");
        assert_eq!(profile.credential_refs.len(), 2);
        assert!(!encoded.contains("internal.example"));
        assert!(!encoded.contains("AKIA_TEST_VALUE"));
        assert!(!encoded.contains("super-secret"));
        assert!(!encoded.contains("private-bucket"));
    }

    #[test]
    fn migrated_profiles_shadow_matching_legacy_fallback() {
        let mysql = connection("prod", DatabaseType::MySQL, None);
        let redis = connection("prod", DatabaseType::Plugin, Some("redis"));
        let stored = vec![migrated_profile_from_connection(&mysql)];

        let profiles = profiles_with_migrated_first(stored, &[mysql, redis]);

        assert_eq!(profiles.len(), 2);
        assert!(
            profiles
                .iter()
                .any(|profile| profile.id.starts_with("profile:"))
        );
        assert!(
            profiles
                .iter()
                .any(|profile| profile.id.starts_with("legacy:"))
        );
    }

    #[test]
    fn migrated_profile_adds_safe_ssh_auth_metadata_without_values() {
        let mut config = connection("bastion", DatabaseType::Plugin, Some("ssh"));
        config.plugin_config = Some(json!({
            "host": "bastion.internal.example",
            "username": "deploy",
            "auth": {
                "type": "Agent"
            }
        }));

        let profile = migrated_profile_from_connection(&config);
        let encoded = serde_json::to_string(&profile).expect("serialize profile");

        assert_eq!(profile.metadata["plugin"]["kind"], "ssh");
        assert_eq!(profile.metadata["plugin"]["auth_method"], "agent");
        assert_eq!(profile.metadata["plugin"]["uses_agent"], true);
        assert_eq!(profile.metadata["plugin"]["has_private_key_path"], false);
        assert_eq!(profile.metadata["plugin"]["has_passphrase"], false);
        assert!(!encoded.contains("bastion.internal.example"));
        assert!(!encoded.contains("deploy"));
    }

    #[test]
    fn migration_preview_and_apply_do_not_persist_secret_values() {
        let temp = TempDir::new("profile-store");
        let store = LocalProfileStore::new(
            temp.path.join("profiles.json"),
            temp.path.join("credentials.json"),
        );
        let mut config = connection("assets", DatabaseType::Plugin, Some("s3"));
        config.plugin_config = Some(json!({
            "endpoint": "https://internal.example",
            "access_key": "AKIA_TEST_VALUE",
            "secret_key": "super-secret",
            "bucket": "private-bucket"
        }));

        let plan = store.migration_plan(&[config.clone()]).expect("preview");
        let preview = serde_json::to_string(&plan).expect("serialize plan");
        assert_eq!(plan.items[0].action, ProfileMigrationAction::Create);
        assert!(!preview.contains("AKIA_TEST_VALUE"));
        assert!(!preview.contains("super-secret"));
        assert!(!preview.contains("private-bucket"));

        let result = store.apply_migration(&[config]).expect("apply migration");
        assert!(result.legacy_configs_preserved);
        assert_eq!(result.profiles_written, 1);
        assert_eq!(result.credentials_written, 2);

        let profiles = std::fs::read_to_string(store.profiles_path()).expect("profiles file");
        let credentials =
            std::fs::read_to_string(store.credentials_path()).expect("credentials file");
        for output in [profiles, credentials] {
            assert!(!output.contains("AKIA_TEST_VALUE"));
            assert!(!output.contains("super-secret"));
            assert!(!output.contains("private-bucket"));
            assert!(!output.contains("internal.example"));
        }
    }

    #[test]
    fn connection_manager_catalog_prefers_stored_profiles_and_keeps_legacy_fallbacks() {
        let temp = TempDir::new("profile-catalog");
        let store = LocalProfileStore::new(
            temp.path.join("profiles.json"),
            temp.path.join("credentials.json"),
        );
        let mysql = connection("prod", DatabaseType::MySQL, None);
        let redis = connection("prod", DatabaseType::Plugin, Some("redis"));

        store
            .apply_migration(std::slice::from_ref(&mysql))
            .expect("apply migration");

        let catalog = store
            .connection_manager_catalog(&[mysql.clone(), redis.clone()])
            .expect("catalog");

        assert_eq!(catalog.entries.len(), 2);
        let mysql_entry = catalog
            .entries
            .iter()
            .find(|entry| entry.plugin_id == "mysql")
            .expect("mysql entry");
        let redis_entry = catalog
            .entries
            .iter()
            .find(|entry| entry.plugin_id == "redis")
            .expect("redis entry");

        assert_eq!(
            mysql_entry.source,
            ConnectionManagerProfileSource::StoredProfile
        );
        assert_eq!(
            mysql_entry.legacy_connection_key.as_deref(),
            Some("mysql::prod")
        );
        assert!(mysql_entry.supports_legacy_crud_route);
        assert_eq!(
            redis_entry.source,
            ConnectionManagerProfileSource::LegacyConfigFallback
        );
        assert_eq!(
            redis_entry.legacy_connection_key.as_deref(),
            Some("redis::prod")
        );
        assert!(redis_entry.supports_open_route);
        assert_ne!(mysql_entry.profile_id, redis_entry.profile_id);
    }

    #[test]
    fn connection_manager_catalog_is_redacted_and_reports_credential_refs() {
        let temp = TempDir::new("profile-catalog-redacted");
        let store = LocalProfileStore::new(
            temp.path.join("profiles.json"),
            temp.path.join("credentials.json"),
        );
        let mut config = connection("assets", DatabaseType::Plugin, Some("s3"));
        config.plugin_config = Some(json!({
            "endpoint": "https://internal.example",
            "access_key": "AKIA_TEST_VALUE",
            "secret_key": "super-secret",
            "bucket": "private-bucket"
        }));

        store
            .apply_migration(std::slice::from_ref(&config))
            .expect("apply migration");

        let catalog = store
            .connection_manager_catalog(&[config])
            .expect("catalog");
        let encoded = serde_json::to_string(&catalog).expect("serialize catalog");

        assert_eq!(catalog.entries.len(), 1);
        assert_eq!(catalog.entries[0].credential_ref_count, 2);
        assert_eq!(
            catalog.entries[0].legacy_connection_key.as_deref(),
            Some("s3::assets")
        );
        assert!(!encoded.contains("internal.example"));
        assert!(!encoded.contains("AKIA_TEST_VALUE"));
        assert!(!encoded.contains("super-secret"));
        assert!(!encoded.contains("private-bucket"));
    }

    #[test]
    fn migration_apply_preserves_existing_legacy_config_file() {
        let temp = TempDir::new("profile-store-preserve-config");
        let store = LocalProfileStore::new(
            temp.path.join("profiles.json"),
            temp.path.join("credentials.json"),
        );
        let config_path = temp.path.join("config.toml");
        let mut config = connection("assets", DatabaseType::Plugin, Some("s3"));
        config.plugin_config = Some(json!({
            "access_key": "AKIA_TEST_VALUE",
            "secret_key": "super-secret"
        }));
        let app_config = AppConfig {
            connections: vec![config.clone()],
            ..Default::default()
        };
        app_config
            .save_to_path_with_password(&config_path, None)
            .expect("save legacy config");
        let before = std::fs::read_to_string(&config_path).expect("read config before");

        let result = store.apply_migration(&[config]).expect("apply migration");
        let after = std::fs::read_to_string(&config_path).expect("read config after");

        assert!(result.legacy_configs_preserved);
        assert_eq!(before, after);
    }

    #[test]
    fn native_profile_roundtrip_is_self_contained_and_encrypted() {
        let temp = TempDir::new("native-profile-roundtrip");
        let store = LocalProfileStore::new(
            temp.path.join("profiles.json"),
            temp.path.join("credentials.json"),
        );
        let mut config = connection("production", DatabaseType::MySQL, Some("mysql"));
        config.plugin_config = Some(json!({
            "host": "db.internal.example",
            "port": 3306,
            "username": "admin",
            "password": "native-secret"
        }));

        let profile = store
            .upsert_native_connection(None, &config, Some("Production DB".into()), None)
            .expect("save native profile");
        let resolved = store
            .native_connection(&profile, None)
            .expect("resolve native connection");

        assert_eq!(profile.metadata["source"], NATIVE_PROFILE_SOURCE);
        assert!(profile.metadata.get("legacy_connection_key").is_none());
        assert_eq!(profile.credential_refs.len(), 2);
        assert!(
            profile
                .credential_refs
                .iter()
                .any(|credential| credential.class == CredentialClass::Password)
        );
        assert_eq!(resolved.name, "production");
        assert_eq!(resolved.plugin_config, config.plugin_config);

        let profiles = std::fs::read_to_string(store.profiles_path()).expect("profiles file");
        let credentials =
            std::fs::read_to_string(store.credentials_path()).expect("credentials file");
        assert!(!profiles.contains("db.internal.example"));
        assert!(!profiles.contains("native-secret"));
        assert!(!credentials.contains("db.internal.example"));
        assert!(!credentials.contains("native-secret"));
        assert!(credentials.contains("local_encrypted_plugin_config"));
    }

    #[test]
    fn native_profile_identity_is_global_and_names_are_plugin_scoped() {
        let temp = TempDir::new("native-profile-identity");
        let store = LocalProfileStore::new(
            temp.path.join("profiles.json"),
            temp.path.join("credentials.json"),
        );
        let ssh = connection("Prod", DatabaseType::Plugin, Some("ssh"));
        let redis = connection("prod", DatabaseType::Plugin, Some("redis"));

        let ssh_profile = store
            .upsert_native_connection(None, &ssh, Some("Production".into()), None)
            .expect("save ssh profile");
        let redis_profile = store
            .upsert_native_connection(None, &redis, Some("Production".into()), None)
            .expect("same name in another plugin");

        assert_ne!(ssh_profile.id, redis_profile.id);
        assert!(ssh_profile.id.starts_with("profile:"));
        Uuid::parse_str(ssh_profile.id.trim_start_matches("profile:"))
            .expect("profile id contains UUID v4");
        assert_eq!(ssh_profile.display_name, redis_profile.display_name);

        let duplicate = connection("  prod  ", DatabaseType::Plugin, Some("ssh"));
        let error = store
            .upsert_native_connection(None, &duplicate, None, None)
            .expect_err("same plugin name is unique ignoring case");
        assert!(error.to_string().contains("case-insensitive"));

        let mut imported_duplicate = ssh_profile.clone();
        imported_duplicate.id = new_native_profile_id();
        imported_duplicate.name = "prod".into();
        let error = store
            .save_profiles(vec![ssh_profile, redis_profile, imported_duplicate])
            .expect_err("bulk profile imports enforce the same invariant");
        assert!(error.to_string().contains("duplicate profile name"));
    }

    #[test]
    fn editing_native_profile_preserves_id_when_name_changes() {
        let temp = TempDir::new("native-profile-stable-id");
        let store = LocalProfileStore::new(
            temp.path.join("profiles.json"),
            temp.path.join("credentials.json"),
        );
        let original = connection("prod", DatabaseType::Plugin, Some("ssh"));
        let saved = store
            .upsert_native_connection(None, &original, None, None)
            .expect("save profile");
        let renamed = connection("bastion", DatabaseType::Plugin, Some("ssh"));
        let updated = store
            .upsert_native_connection(Some(&saved.id), &renamed, None, None)
            .expect("rename profile");

        assert_eq!(updated.id, saved.id);
        assert_eq!(updated.name, "bastion");
        assert_eq!(store.load_profiles().expect("profiles").len(), 1);
    }

    #[test]
    fn native_profile_credentials_can_be_reencrypted_and_deleted() {
        let temp = TempDir::new("native-profile-lifecycle");
        let store = LocalProfileStore::new(
            temp.path.join("profiles.json"),
            temp.path.join("credentials.json"),
        );
        let mut config = connection("cache", DatabaseType::Plugin, Some("redis"));
        config.plugin_config = Some(json!({
            "host": "localhost",
            "port": 6379,
            "password": "redis-secret"
        }));
        let profile = store
            .upsert_native_connection(None, &config, None, None)
            .expect("save native profile");

        assert_eq!(
            store
                .reencrypt_native_credentials(None, "correct horse battery staple")
                .expect("reencrypt"),
            1
        );
        assert!(store.native_connection(&profile, None).is_err());
        assert_eq!(
            store
                .native_connection(&profile, Some("correct horse battery staple"))
                .expect("resolve with new password")
                .plugin_config,
            config.plugin_config
        );

        assert!(store.delete_profile(&profile.id).expect("delete profile"));
        assert!(store.load_profiles().expect("profiles").is_empty());
        assert!(
            store
                .load_credential_records()
                .expect("credentials")
                .is_empty()
        );
    }

    #[test]
    fn native_migration_imports_without_runtime_legacy_metadata() {
        let temp = TempDir::new("native-profile-migration");
        let store = LocalProfileStore::new(
            temp.path.join("profiles.json"),
            temp.path.join("credentials.json"),
        );
        let mut config = connection("local", DatabaseType::SQLite, Some("sqlite"));
        config.plugin_config = Some(json!({ "path": "/tmp/native.db" }));

        let result = store
            .apply_native_migration(std::slice::from_ref(&config), None)
            .expect("native migration");
        let repeated = store
            .apply_native_migration(std::slice::from_ref(&config), None)
            .expect("repeated native migration");
        let profiles = store.load_profiles().expect("profiles");

        assert!(result.legacy_configs_preserved);
        assert_eq!(
            result.plan.items[0].profile.metadata["source"],
            NATIVE_PROFILE_SOURCE
        );
        assert_eq!(repeated.profiles_written, 1);
        assert_eq!(profiles.len(), 1);
        assert_eq!(result.plan.items[0].profile.id, profiles[0].id);
        assert_eq!(repeated.plan.items[0].profile.id, profiles[0].id);
        assert_eq!(profiles[0].metadata["source"], NATIVE_PROFILE_SOURCE);
        assert!(profiles[0].metadata.get("legacy_connection_key").is_none());
        assert_eq!(
            store
                .native_connection(&profiles[0], None)
                .expect("native connection")
                .plugin_config,
            config.plugin_config
        );
    }

    #[cfg(unix)]
    #[test]
    fn migration_apply_writes_private_files() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new("profile-store-private");
        let store = LocalProfileStore::new(
            temp.path.join("profiles.json"),
            temp.path.join("credentials.json"),
        );
        let config = connection("local", DatabaseType::SQLite, None);

        store.apply_migration(&[config]).expect("apply migration");

        for path in [store.profiles_path(), store.credentials_path()] {
            let mode = std::fs::metadata(path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(label: &str) -> Self {
            static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

            let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let path =
                std::env::temp_dir().join(format!("voidb-{label}-{}-{id}", std::process::id()));
            std::fs::create_dir_all(&path).expect("create temp dir");
            Self { path }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }
}
