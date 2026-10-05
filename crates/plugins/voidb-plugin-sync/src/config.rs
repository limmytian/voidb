//! On-disk sync plugin configuration.
//!
//! Lives at `~/.config/voidb/sync.toml`. Contains non-secret state that the
//! plugin needs across restarts: the server URL, the user's email, the
//! device_id, and bookkeeping for the most recent successful sync.
//!
//! Secrets (bearer token, DEK) are *never* written to this file — they live
//! only in process memory after login. This keeps the "losing the config
//! file is not a breach" property.
//!
//! Author: Limmy

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::Context;
use serde::{Deserialize, Serialize};

use crate::error::SyncError;

/// Non-secret persistent state for the sync plugin.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct SyncConfig {
    /// Base URL of the sync server (e.g. `https://sync.example.com`).
    #[serde(default)]
    pub server_url: Option<String>,

    /// Registered account email.
    #[serde(default)]
    pub email: Option<String>,

    /// Device id returned by the server on register/login.
    #[serde(default)]
    pub device_id: Option<String>,

    /// Friendly device name (shown in `/v1/devices`).
    #[serde(default)]
    pub device_name: Option<String>,

    /// Deprecated: single global revision field kept for backward compatibility.
    /// Superseded by `last_revisions`. Only used if `last_revisions` has no
    /// entry for `"full"`.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub last_revision: u64,

    /// Per-kind last-known server revision.
    #[serde(default)]
    pub last_revisions: HashMap<String, u64>,

    /// RFC-3339 timestamp of the last successful push or pull.
    #[serde(default)]
    pub last_synced_at: Option<String>,

    /// Deprecated file-fallback bearer token for CLI use (never the DEK).
    /// New logins prefer the OS keyring and use this only when keyring storage
    /// is unavailable or `VOIDB_SYNC_TOKEN_STORE=file` is set.
    #[serde(default)]
    pub token: Option<String>,

    /// Device-local mapping from local records to opaque server-visible object
    /// IDs. This file is excluded from bundle sync, so legacy local IDs never
    /// become server-visible metadata.
    #[serde(default)]
    pub object_mappings: HashMap<String, SyncObjectMapping>,

    /// Device-local redacted object conflict markers. They are keyed by
    /// object kind and opaque object ID and are not part of object payloads.
    #[serde(default)]
    pub object_conflicts: HashMap<String, SyncObjectConflict>,

    /// Explicit opt-in periodic object sync settings. Defaults are disabled so
    /// periodic sync cannot run until the user configures it.
    #[serde(default)]
    pub periodic_sync: PeriodicSyncConfig,

    /// Device-local replay ledger for completed Agent mutations. Keys are
    /// caller-provided idempotency keys; values contain redacted fingerprints
    /// and result summaries only. This file is excluded from Sync payloads.
    #[serde(default)]
    pub agent_replays: HashMap<String, SyncAgentReplay>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SyncAgentReplay {
    pub capability_id: String,
    pub fingerprint: String,
    pub completed_at: String,
    pub result: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeriodicSyncConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default = "default_periodic_sync_interval_minutes")]
    pub interval_minutes: u64,

    #[serde(default = "default_periodic_sync_mode")]
    pub mode: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_run_at: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_status: Option<String>,
}

impl Default for PeriodicSyncConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_minutes: default_periodic_sync_interval_minutes(),
            mode: default_periodic_sync_mode(),
            last_run_at: None,
            last_status: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncObjectMapping {
    pub local_kind: String,
    pub local_id: String,
    pub object_kind: String,
    pub object_id: String,

    #[serde(default)]
    pub object_version: u64,

    #[serde(default)]
    pub server_revision: u64,

    #[serde(default)]
    pub unavailable: bool,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cached_ciphertext: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unavailable_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncObjectConflict {
    pub object_kind: String,
    pub object_id: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_kind: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_id: Option<String>,

    #[serde(default)]
    pub attempted_base_server_revision: u64,

    #[serde(default)]
    pub current_server_revision: u64,

    #[serde(default)]
    pub attempted_object_version: u64,

    #[serde(default)]
    pub current_object_version: u64,

    pub detected_at: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_updated_at: Option<String>,

    #[serde(default)]
    pub redaction: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unavailable_reason: Option<String>,
}

fn is_zero(v: &u64) -> bool {
    *v == 0
}

fn default_periodic_sync_interval_minutes() -> u64 {
    60
}

fn default_periodic_sync_mode() -> String {
    "pull-objects".to_string()
}

impl SyncConfig {
    pub fn file_path() -> Result<PathBuf, SyncError> {
        let dir = voidb_config_dir()?;
        Ok(dir.join("sync.toml"))
    }

    pub fn load() -> Result<Self, SyncError> {
        let path = Self::file_path()?;
        if !path.exists() {
            return Ok(Self::default());
        }
        let s = std::fs::read_to_string(&path)
            .with_context(|| format!("read {}", path.display()))
            .map_err(SyncError::from)?;
        let cfg: Self = toml::from_str(&s).map_err(SyncError::from)?;
        Ok(cfg)
    }

    pub fn save(&self) -> Result<(), SyncError> {
        let path = Self::file_path()?;
        let s = toml::to_string_pretty(self).map_err(SyncError::from)?;
        write_private_file(&path, s)
            .with_context(|| format!("write {}", path.display()))
            .map_err(SyncError::from)?;
        Ok(())
    }

    /// Last known revision for the given kind.
    pub fn revision_for(&self, kind: &str) -> u64 {
        self.last_revisions
            .get(kind)
            .copied()
            .or_else(|| {
                if kind == "full" {
                    Some(self.last_revision)
                } else {
                    None
                }
            })
            .unwrap_or(0)
    }

    /// Record a new server revision for the given kind.
    pub fn set_revision(&mut self, kind: &str, rev: u64) {
        self.last_revisions.insert(kind.to_string(), rev);
    }

    pub fn object_mapping_key(local_kind: &str, local_id: &str) -> String {
        format!("{local_kind}:{local_id}")
    }

    pub fn object_conflict_key(object_kind: &str, object_id: &str) -> String {
        format!("{object_kind}:{object_id}")
    }

    pub fn object_mapping(&self, local_kind: &str, local_id: &str) -> Option<&SyncObjectMapping> {
        self.object_mappings
            .get(&Self::object_mapping_key(local_kind, local_id))
    }

    pub fn ensure_object_mapping(
        &mut self,
        local_kind: &str,
        local_id: &str,
        object_kind: &str,
        object_id: impl FnOnce() -> String,
    ) -> SyncObjectMapping {
        let key = Self::object_mapping_key(local_kind, local_id);
        self.object_mappings
            .entry(key)
            .or_insert_with(|| SyncObjectMapping {
                local_kind: local_kind.to_string(),
                local_id: local_id.to_string(),
                object_kind: object_kind.to_string(),
                object_id: object_id(),
                object_version: 0,
                server_revision: 0,
                unavailable: false,
                updated_at: None,
                cached_ciphertext: None,
                unavailable_reason: None,
            })
            .clone()
    }

    pub fn record_object_revision(&mut self, mut mapping: SyncObjectMapping) {
        mapping.updated_at = Some(chrono::Utc::now().to_rfc3339());
        let key = Self::object_mapping_key(&mapping.local_kind, &mapping.local_id);
        self.object_conflicts.remove(&Self::object_conflict_key(
            &mapping.object_kind,
            &mapping.object_id,
        ));
        self.object_mappings.insert(key, mapping);
    }

    pub fn record_object_conflict(&mut self, conflict: SyncObjectConflict) {
        let key = Self::object_conflict_key(&conflict.object_kind, &conflict.object_id);
        self.object_conflicts.insert(key, conflict);
    }

    pub fn mapping_by_object_id(&self, object_id: &str) -> Option<&SyncObjectMapping> {
        self.object_mappings
            .values()
            .find(|mapping| mapping.object_id == object_id)
    }

    /// Whether at least a server URL and email are on file.
    pub fn is_configured(&self) -> bool {
        self.server_url.as_deref().is_some_and(|s| !s.is_empty())
            && self.email.as_deref().is_some_and(|s| !s.is_empty())
    }
}

/// Directory holding all user-scoped VoidB configuration.
///
/// Resolution order:
///   1. `$VOIDB_CONFIG_DIR` (explicit override — useful for CI, multi-profile,
///      or pointing at a cloud-synced folder like `~/Dropbox/voidb`).
///   2. `dirs::config_dir()/voidb` (platform default).
///
/// The sync plugin snapshots **this entire directory** (minus its own
/// `sync.toml`) during a push.
pub fn voidb_config_dir() -> Result<PathBuf, SyncError> {
    let dir = if let Some(custom) = std::env::var_os("VOIDB_CONFIG_DIR") {
        PathBuf::from(custom)
    } else {
        let base = dirs::config_dir()
            .ok_or_else(|| SyncError::Config("cannot determine config dir".into()))?;
        base.join("voidb")
    };
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("create {}", dir.display()))
        .map_err(SyncError::from)?;
    Ok(dir)
}

/// Path inside `~/.config/voidb/` that we never sync (it contains the current
/// device's bookkeeping and is device-specific).
pub fn sync_config_filename() -> &'static Path {
    Path::new("sync.toml")
}

#[cfg(unix)]
fn write_private_file(path: &Path, content: impl AsRef<[u8]>) -> std::io::Result<()> {
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
fn write_private_file(path: &Path, content: impl AsRef<[u8]>) -> std::io::Result<()> {
    std::fs::write(path, content)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn write_private_file_sets_0600_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("sync.toml");

        write_private_file(&path, b"email = 'user@example.com'\n").expect("write sync config");

        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        assert_eq!(
            std::fs::read_to_string(&path).expect("read sync config"),
            "email = 'user@example.com'\n"
        );
    }
}
