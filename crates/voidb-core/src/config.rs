use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::connection::ConnectionConfig;
use crate::credential_protection::{
    CredentialMaterialSummary, CredentialProtectionMode, MasterPasswordSessionState,
    credential_material_summary_for_connections, legacy_config_protection_state,
};
use crate::crypto;
use crate::error::VoidbError;

pub const VOIDB_MASTER_PASSWORD_ENV: &str = "VOIDB_MASTER_PASSWORD";
const CREDENTIAL_PROTECTION_VERSION: u32 = 1;
const MASTER_PASSWORD_VERIFIER: &str = "voidb-master-password-verifier-v1";

/// Application configuration.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppConfig {
    pub connections: Vec<ConnectionConfig>,
    #[serde(default)]
    pub settings: Settings,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_protection: Option<ConfigCredentialProtection>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    #[serde(default = "default_page_size")]
    pub page_size: u64,
    #[serde(default = "default_max_connections")]
    pub max_connections: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            page_size: default_page_size(),
            max_connections: default_max_connections(),
        }
    }
}

fn default_page_size() -> u64 {
    100
}

fn default_max_connections() -> u32 {
    5
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConfigCredentialProtection {
    pub version: u32,
    pub mode: CredentialProtectionMode,
    pub verifier: String,
}

impl ConfigCredentialProtection {
    pub fn user_passphrase(master_password: &str) -> Result<Self, VoidbError> {
        validate_master_password(master_password)?;
        Ok(Self {
            version: CREDENTIAL_PROTECTION_VERSION,
            mode: CredentialProtectionMode::UserPassphrase,
            verifier: crypto::encrypt(MASTER_PASSWORD_VERIFIER, Some(master_password))?,
        })
    }

    pub fn verify_master_password(&self, master_password: &str) -> Result<(), VoidbError> {
        validate_master_password(master_password)?;
        let verifier = crypto::decrypt(&self.verifier, Some(master_password)).map_err(|_| {
            VoidbError::Crypto("Invalid master password for credential protection".into())
        })?;
        if verifier != MASTER_PASSWORD_VERIFIER {
            return Err(VoidbError::Crypto(
                "Invalid master password for credential protection".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ConfigReencryptResult {
    pub config_path: PathBuf,
    pub protection_mode: CredentialProtectionMode,
    pub master_password: MasterPasswordSessionState,
    pub credential_summary: CredentialMaterialSummary,
}

impl AppConfig {
    /// Get the VoidB config directory, creating it if needed.
    pub fn config_dir() -> Result<PathBuf, VoidbError> {
        let config_dir = dirs::config_dir()
            .ok_or_else(|| VoidbError::Config("Cannot determine config directory".to_string()))?;

        let voidb_dir = config_dir.join("voidb");
        std::fs::create_dir_all(&voidb_dir)
            .map_err(|e| VoidbError::Config(format!("Cannot create config directory: {}", e)))?;

        Ok(voidb_dir)
    }

    /// Get the config file path.
    pub fn config_path() -> Result<PathBuf, VoidbError> {
        Ok(Self::config_dir()?.join("config.toml"))
    }

    /// Load configuration from file with automatic decryption of sensitive fields.
    pub fn load() -> Result<Self, VoidbError> {
        Self::load_from_path(&Self::config_path()?)
    }

    /// Load configuration from file with an explicit master password.
    pub fn load_with_password(master_password: Option<&str>) -> Result<Self, VoidbError> {
        Self::load_from_path_with_password(&Self::config_path()?, master_password)
    }

    pub fn load_from_path(path: &Path) -> Result<Self, VoidbError> {
        let mut config = Self::load_raw_from_path(path)?;
        let env_master_password = if config.requires_master_password() {
            Some(active_master_password_from_env()?)
        } else {
            None
        };
        config.ensure_master_password(env_master_password.as_deref())?;
        config.decrypt_connections(env_master_password.as_deref())?;
        Ok(config)
    }

    pub fn load_from_path_with_password(
        path: &Path,
        master_password: Option<&str>,
    ) -> Result<Self, VoidbError> {
        let mut config = Self::load_raw_from_path(path)?;
        config.ensure_master_password(master_password)?;
        config.decrypt_connections(master_password)?;
        Ok(config)
    }

    pub fn load_raw_from_path(path: &Path) -> Result<Self, VoidbError> {
        if !path.exists() {
            return Ok(Self::default());
        }

        let content = std::fs::read_to_string(path)
            .map_err(|e| VoidbError::Config(format!("Cannot read config file: {}", e)))?;

        toml::from_str(&content)
            .map_err(|e| VoidbError::Config(format!("Cannot parse config file: {}", e)))
    }

    /// Save configuration to file with automatic encryption of sensitive fields.
    pub fn save(&self) -> Result<(), VoidbError> {
        self.save_to_path(&Self::config_path()?)
    }

    /// Save configuration to file with an explicit master password.
    pub fn save_with_password(&self, master_password: Option<&str>) -> Result<(), VoidbError> {
        self.save_to_path_with_password(&Self::config_path()?, master_password)
    }

    pub fn save_to_path(&self, path: &Path) -> Result<(), VoidbError> {
        let env_master_password = if self.requires_master_password() {
            Some(active_master_password_from_env()?)
        } else {
            None
        };
        self.save_to_path_with_password(path, env_master_password.as_deref())
    }

    pub fn save_to_path_with_password(
        &self,
        path: &Path,
        master_password: Option<&str>,
    ) -> Result<(), VoidbError> {
        self.ensure_master_password(master_password)?;
        // Clone and encrypt sensitive fields before writing
        let mut config = self.clone();
        for conn in &mut config.connections {
            encrypt_connection(conn, master_password)?;
        }

        let content = toml::to_string_pretty(&config)
            .map_err(|e| VoidbError::Config(format!("Cannot serialize config: {}", e)))?;

        write_private_file(path, content)
            .map_err(|e| VoidbError::Config(format!("Cannot write config file: {}", e)))?;

        Ok(())
    }

    pub fn set_user_passphrase_protection(
        &mut self,
        master_password: &str,
    ) -> Result<(), VoidbError> {
        self.credential_protection = Some(ConfigCredentialProtection::user_passphrase(
            master_password,
        )?);
        Ok(())
    }

    pub fn credential_protection_mode(&self) -> CredentialProtectionMode {
        self.credential_protection
            .as_ref()
            .map(|protection| protection.mode)
            .unwrap_or(CredentialProtectionMode::DefaultPassphrase)
    }

    pub fn requires_master_password(&self) -> bool {
        self.credential_protection_mode() == CredentialProtectionMode::UserPassphrase
    }

    pub fn reencrypt_config_file(
        current_master_password: Option<&str>,
        new_master_password: &str,
    ) -> Result<ConfigReencryptResult, VoidbError> {
        Self::reencrypt_config_file_at_path(
            &Self::config_path()?,
            current_master_password,
            new_master_password,
        )
    }

    pub fn reencrypt_config_file_at_path(
        path: &Path,
        current_master_password: Option<&str>,
        new_master_password: &str,
    ) -> Result<ConfigReencryptResult, VoidbError> {
        validate_master_password(new_master_password)?;
        let mut config = Self::load_from_path_with_password(path, current_master_password)?;
        let credential_summary = credential_material_summary_for_connections(&config.connections);
        config.set_user_passphrase_protection(new_master_password)?;
        config.save_to_path_with_password(path, Some(new_master_password))?;

        Ok(ConfigReencryptResult {
            config_path: path.to_path_buf(),
            protection_mode: CredentialProtectionMode::UserPassphrase,
            master_password: MasterPasswordSessionState::Locked,
            credential_summary,
        })
    }

    pub fn credential_protection_state(
        &self,
        master_password: MasterPasswordSessionState,
    ) -> crate::CredentialProtectionState {
        legacy_config_protection_state(
            &self.connections,
            self.credential_protection_mode(),
            master_password,
        )
    }

    fn decrypt_connections(&mut self, master_password: Option<&str>) -> Result<(), VoidbError> {
        for conn in &mut self.connections {
            decrypt_connection(conn, master_password)?;
        }
        Ok(())
    }

    fn ensure_master_password(&self, master_password: Option<&str>) -> Result<(), VoidbError> {
        if !self.requires_master_password() {
            return Ok(());
        }

        let Some(master_password) = master_password else {
            return Err(master_password_required_error());
        };

        let Some(protection) = &self.credential_protection else {
            return Err(master_password_required_error());
        };

        protection.verify_master_password(master_password)
    }

    /// Add or update a connection (matched by composite key: plugin_id + name).
    pub fn upsert_connection(&mut self, config: ConnectionConfig) {
        let key = config.connection_key();
        if let Some(existing) = self
            .connections
            .iter_mut()
            .find(|c| c.connection_key() == key)
        {
            *existing = config;
        } else {
            self.connections.push(config);
        }
    }

    /// Replace a connection: remove old key entry, insert new config.
    ///
    /// Used when editing a connection whose name may have changed.
    pub fn replace_connection(&mut self, old_key: &str, config: ConnectionConfig) {
        self.connections.retain(|c| c.connection_key() != old_key);
        self.connections.push(config);
    }

    /// Remove a connection by composite key (plugin_id::name).
    pub fn remove_connection(&mut self, key: &str) {
        self.connections.retain(|c| c.connection_key() != key);
    }

    /// Find a connection by the current composite key or the legacy display name.
    ///
    /// The composite key is the stable TUI/capability identifier. The name
    /// fallback keeps legacy TUI factories compatible with older contexts that
    /// passed only the user-visible connection name.
    pub fn connection_by_key_or_name(&self, id: &str) -> Option<&ConnectionConfig> {
        self.connections
            .iter()
            .find(|connection| connection.connection_key() == id || connection.name == id)
    }
}

pub fn active_master_password_from_env() -> Result<String, VoidbError> {
    match std::env::var(VOIDB_MASTER_PASSWORD_ENV) {
        Ok(value) if !value.is_empty() => Ok(value),
        Ok(_) => Err(VoidbError::Config(format!(
            "{} is set but empty",
            VOIDB_MASTER_PASSWORD_ENV
        ))),
        Err(std::env::VarError::NotPresent) => Err(master_password_required_error()),
        Err(error) => Err(VoidbError::Config(format!(
            "Cannot read {}: {}",
            VOIDB_MASTER_PASSWORD_ENV, error
        ))),
    }
}

fn validate_master_password(master_password: &str) -> Result<(), VoidbError> {
    if master_password.is_empty() {
        return Err(VoidbError::Config(
            "Master password cannot be empty".to_string(),
        ));
    }
    Ok(())
}

fn master_password_required_error() -> VoidbError {
    VoidbError::Config(format!(
        "Master password required; set {} for this process",
        VOIDB_MASTER_PASSWORD_ENV
    ))
}

#[cfg(unix)]
pub(crate) fn write_private_file(path: &Path, content: impl AsRef<[u8]>) -> std::io::Result<()> {
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(content.as_ref())?;
    file.sync_all()?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
pub(crate) fn write_private_file(path: &Path, content: impl AsRef<[u8]>) -> std::io::Result<()> {
    std::fs::write(path, content)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_lookup_accepts_composite_key_and_legacy_name() {
        let config = AppConfig {
            connections: vec![ConnectionConfig {
                name: "local".into(),
                db_type: crate::connection::DatabaseType::SQLite,
                plugin_id: None,
                plugin_config: None,
            }],
            ..Default::default()
        };

        assert_eq!(
            config
                .connection_by_key_or_name("sqlite::local")
                .expect("lookup by key")
                .name,
            "local"
        );
        assert_eq!(
            config
                .connection_by_key_or_name("local")
                .expect("lookup by legacy name")
                .connection_key(),
            "sqlite::local"
        );
        assert!(config.connection_by_key_or_name("mysql::local").is_none());
    }

    #[cfg(unix)]
    #[test]
    fn write_private_file_sets_0600_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let path = std::env::temp_dir().join(format!(
            "voidb-private-config-{}.toml",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time")
                .as_nanos()
        ));

        write_private_file(&path, b"connections = []\n").expect("write private config");

        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(
            std::fs::read_to_string(&path).expect("read private config"),
            "connections = []\n"
        );

        std::fs::remove_file(path).expect("remove private config");
    }

    #[cfg(unix)]
    #[test]
    fn security_sensitive_local_files_are_private() {
        use std::os::unix::fs::PermissionsExt;

        use crate::{
            AuditEvent, AuditEventStatus, AuditEventStore, AuditOperation, DatabaseType,
            LocalAuditStore, LocalProfileStore,
        };

        let root = std::env::temp_dir().join(format!(
            "voidb-security-files-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time")
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).expect("create temp root");

        let config_path = root.join("config.toml");
        write_private_file(&config_path, b"connections = []\n").expect("write config");

        let profile_store =
            LocalProfileStore::new(root.join("profiles.json"), root.join("credentials.json"));
        let connection = ConnectionConfig {
            name: "assets".into(),
            db_type: DatabaseType::Plugin,
            plugin_id: Some("s3".into()),
            plugin_config: Some(serde_json::json!({
                "access_key": "AKIA_TEST_VALUE",
                "secret_key": "super-secret",
            })),
        };
        profile_store
            .apply_migration(&[connection])
            .expect("apply profile migration");

        let audit_store = LocalAuditStore::new(root.join("audit").join("events.jsonl"));
        audit_store
            .append(&AuditEvent::new(
                AuditOperation::ProfileList,
                AuditEventStatus::Succeeded,
            ))
            .expect("append audit event");

        for path in [
            config_path.as_path(),
            profile_store.profiles_path(),
            profile_store.credentials_path(),
            audit_store.path(),
        ] {
            let mode = std::fs::metadata(path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "{} should be private", path.display());
        }

        std::fs::remove_dir_all(root).expect("remove temp root");
    }

    #[test]
    fn reencrypt_config_file_sets_user_passphrase_metadata() {
        let root = temp_config_root("reencrypt");
        std::fs::create_dir_all(&root).expect("create temp root");
        let path = root.join("config.toml");
        let config = AppConfig {
            connections: vec![ConnectionConfig {
                name: "assets".into(),
                db_type: crate::DatabaseType::Plugin,
                plugin_id: Some("s3".into()),
                plugin_config: Some(serde_json::json!({
                    "endpoint": "https://internal.example",
                    "access_key": "AKIA_TEST_VALUE",
                    "secret_key": "super-secret",
                })),
            }],
            ..Default::default()
        };
        config
            .save_to_path_with_password(&path, None)
            .expect("save legacy config");

        let before = AppConfig::load_from_path_with_password(&path, None).expect("load legacy");
        assert_eq!(before.connections.len(), 1);

        let result =
            AppConfig::reencrypt_config_file_at_path(&path, None, "correct horse battery staple")
                .expect("reencrypt config");
        assert_eq!(
            result.protection_mode,
            CredentialProtectionMode::UserPassphrase
        );
        assert_eq!(result.credential_summary.credential_owner_count, 1);
        assert_eq!(result.credential_summary.credential_item_count, 2);

        let content = std::fs::read_to_string(&path).expect("read config");
        assert!(content.contains("credential_protection"));
        assert!(content.contains("user_passphrase"));
        assert!(!content.contains("AKIA_TEST_VALUE"));
        assert!(!content.contains("super-secret"));
        assert!(!content.contains("internal.example"));

        let missing_password = AppConfig::load_from_path_with_password(&path, None)
            .expect_err("master password should be required");
        assert!(
            missing_password
                .to_string()
                .contains("Master password required")
        );

        let wrong_password = AppConfig::load_from_path_with_password(&path, Some("wrong-password"))
            .expect_err("wrong master password should fail");
        assert!(
            wrong_password
                .to_string()
                .contains("Invalid master password")
        );

        let loaded =
            AppConfig::load_from_path_with_password(&path, Some("correct horse battery staple"))
                .expect("load with master password");
        assert_eq!(
            loaded.connections[0]
                .plugin_config
                .as_ref()
                .expect("plugin config")["secret_key"],
            "super-secret"
        );

        std::fs::remove_dir_all(root).expect("remove temp root");
    }

    #[test]
    fn configured_user_passphrase_save_requires_active_password() {
        let root = temp_config_root("protected-save");
        std::fs::create_dir_all(&root).expect("create temp root");
        let path = root.join("config.toml");
        let mut config = AppConfig::default();
        config
            .set_user_passphrase_protection("correct horse battery staple")
            .expect("set protection");

        let error = config
            .save_to_path_with_password(&path, None)
            .expect_err("missing password");
        assert!(error.to_string().contains("Master password required"));

        config
            .save_to_path_with_password(&path, Some("correct horse battery staple"))
            .expect("save with password");
        assert!(path.exists());

        std::fs::remove_dir_all(root).expect("remove temp root");
    }

    fn temp_config_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "voidb-config-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system time")
                .as_nanos()
        ))
    }
}

// ============================================================================
// Connection encryption helpers
// ============================================================================

/// Encrypt the entire plugin_config as a blob before saving to disk.
fn encrypt_connection(
    conn: &mut ConnectionConfig,
    master_password: Option<&str>,
) -> Result<(), VoidbError> {
    // Encrypt the entire plugin_config as a JSON string
    if let Some(ref pc) = conn.plugin_config {
        let json_str = serde_json::to_string(pc)
            .map_err(|e| VoidbError::Config(format!("Failed to serialize plugin_config: {}", e)))?;

        if !crypto::is_encrypted(&json_str) {
            let encrypted = crypto::encrypt(&json_str, master_password)?;
            // Store the encrypted string as a JSON string value
            conn.plugin_config = Some(serde_json::Value::String(encrypted));
        }
    }

    Ok(())
}

/// Decrypt the entire plugin_config blob after loading from disk.
fn decrypt_connection(
    conn: &mut ConnectionConfig,
    master_password: Option<&str>,
) -> Result<(), VoidbError> {
    // Decrypt the entire plugin_config from encrypted string
    if let Some(serde_json::Value::String(ref encrypted_str)) = conn.plugin_config
        && crypto::is_encrypted(encrypted_str)
    {
        let decrypted = crypto::decrypt(encrypted_str, master_password)?;
        conn.plugin_config = Some(serde_json::from_str(&decrypted).map_err(|e| {
            VoidbError::Config(format!("Failed to deserialize plugin_config: {}", e))
        })?);
    }

    Ok(())
}

// ============================================================================
// Saved queries (bookmarks / favorites)
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedQuery {
    pub id: String,
    pub title: String,
    pub sql: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub connection: Option<String>,
    pub created_at: String,
    #[serde(default)]
    pub last_used_at: Option<String>,
}

pub struct SavedQueries {
    entries: Vec<SavedQuery>,
}

impl SavedQueries {
    fn file_path() -> Result<PathBuf, VoidbError> {
        let config_dir = dirs::config_dir()
            .ok_or_else(|| VoidbError::Config("Cannot determine config directory".to_string()))?;
        let voidb_dir = config_dir.join("voidb");
        std::fs::create_dir_all(&voidb_dir)
            .map_err(|e| VoidbError::Config(format!("Cannot create config directory: {}", e)))?;
        Ok(voidb_dir.join("saved_queries.json"))
    }

    pub fn load() -> Self {
        let mut sq = Self {
            entries: Vec::new(),
        };
        if let Ok(path) = Self::file_path()
            && let Ok(content) = std::fs::read_to_string(path)
            && let Ok(entries) = serde_json::from_str::<Vec<SavedQuery>>(&content)
        {
            sq.entries = entries;
        }
        sq
    }

    pub fn save(&self) {
        if let Ok(path) = Self::file_path()
            && let Ok(json) = serde_json::to_string_pretty(&self.entries)
        {
            let _ = std::fs::write(path, json);
        }
    }

    pub fn add(
        &mut self,
        title: String,
        sql: String,
        tags: Vec<String>,
        connection: Option<String>,
    ) -> &SavedQuery {
        let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        let id = format!("{:08x}", rand_id());
        self.entries.push(SavedQuery {
            id,
            title,
            sql,
            tags,
            connection,
            created_at: now,
            last_used_at: None,
        });
        self.save();
        self.entries.last().unwrap()
    }

    pub fn remove(&mut self, id: &str) -> bool {
        let before = self.entries.len();
        self.entries.retain(|e| e.id != id);
        if self.entries.len() != before {
            self.save();
            true
        } else {
            false
        }
    }

    pub fn touch(&mut self, id: &str) {
        let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        if let Some(entry) = self.entries.iter_mut().find(|e| e.id == id) {
            entry.last_used_at = Some(now);
            self.save();
        }
    }

    pub fn search(&self, query: &str) -> Vec<&SavedQuery> {
        if query.is_empty() {
            return self.entries.iter().rev().collect();
        }
        let lower = query.to_lowercase();
        self.entries
            .iter()
            .filter(|e| {
                e.title.to_lowercase().contains(&lower)
                    || e.sql.to_lowercase().contains(&lower)
                    || e.tags.iter().any(|t| t.to_lowercase().contains(&lower))
            })
            .rev()
            .collect()
    }

    pub fn entries(&self) -> &[SavedQuery] {
        &self.entries
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

fn rand_id() -> u32 {
    use std::time::SystemTime;
    let d = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    (d.as_nanos() & 0xFFFF_FFFF) as u32
}

// ============================================================================
// Query history
// ============================================================================

/// Persistent query history stored as a plain text file (one query per line).
pub struct QueryHistory {
    entries: Vec<String>,
    max_entries: usize,
}

impl Default for QueryHistory {
    fn default() -> Self {
        Self {
            entries: Vec::new(),
            max_entries: Self::MAX_ENTRIES,
        }
    }
}

impl QueryHistory {
    const MAX_ENTRIES: usize = 500;

    pub fn new() -> Self {
        Self::default()
    }

    /// Get the history file path.
    fn history_path() -> Result<PathBuf, VoidbError> {
        let config_dir = dirs::config_dir()
            .ok_or_else(|| VoidbError::Config("Cannot determine config directory".to_string()))?;
        let voidb_dir = config_dir.join("voidb");
        std::fs::create_dir_all(&voidb_dir)
            .map_err(|e| VoidbError::Config(format!("Cannot create config directory: {}", e)))?;
        Ok(voidb_dir.join("query_history.txt"))
    }

    /// Load history from file.
    pub fn load() -> Self {
        let mut history = Self::new();
        if let Ok(path) = Self::history_path()
            && let Ok(content) = std::fs::read_to_string(path)
        {
            history.entries = content
                .lines()
                .filter(|l| !l.is_empty())
                .map(|l| l.replace("\\n", "\n"))
                .collect();
            let max = history.max_entries;
            if history.entries.len() > max {
                history.entries = history.entries.split_off(history.entries.len() - max);
            }
        }
        history
    }

    /// Save history to file.
    pub fn save(&self) {
        if let Ok(path) = Self::history_path() {
            let content: String = self
                .entries
                .iter()
                .map(|e| e.replace('\n', "\\n"))
                .collect::<Vec<_>>()
                .join("\n");
            let _ = std::fs::write(path, content);
        }
    }

    /// Add a query to history (deduplicates consecutive duplicates).
    pub fn push(&mut self, sql: String) {
        let trimmed = sql.trim().to_string();
        if trimmed.is_empty() {
            return;
        }
        // Remove duplicate if it's the last entry
        if self.entries.last().map(|s| s.as_str()) == Some(trimmed.as_str()) {
            return;
        }
        self.entries.push(trimmed);
        if self.entries.len() > self.max_entries {
            self.entries.remove(0);
        }
    }

    /// Get entry count.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if history is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get entry at index (0 = oldest).
    pub fn get(&self, index: usize) -> Option<&str> {
        self.entries.get(index).map(|s| s.as_str())
    }

    /// Get all entries (oldest first).
    pub fn entries(&self) -> &[String] {
        &self.entries
    }
}
