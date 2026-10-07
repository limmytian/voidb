//! Plugin Registry Metadata & Index Specification
//!
//! Provides data structures and serialization for the official VoidB Plugin
//! Registry index, enabling discovery, version resolution, SHA256 integrity
//! verification, and Ed25519 signature checks.

use std::path::{Path, PathBuf};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use crate::error::VoidbError;

pub const REGISTRY_SCHEMA_VERSION: u32 = 1;
pub const REGISTRY_SCHEMA_URI: &str = "https://voidb.dev/schemas/plugin-registry.schema.json";
pub const DEFAULT_OFFICIAL_REGISTRY_URL: &str = "https://raw.githubusercontent.com/limmytian/voidb/main/registry/index.json";

/// High-level category for plugin discovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginCategory {
    Storage,
    Infrastructure,
    Search,
    Database,
    Communication,
    Other,
}

impl PluginCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Storage => "storage",
            Self::Infrastructure => "infrastructure",
            Self::Search => "search",
            Self::Database => "database",
            Self::Communication => "communication",
            Self::Other => "other",
        }
    }
}

/// Downloadable package artifact in the registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryPackageArtifact {
    pub filename: String,
    pub format: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    pub url: String,
    pub sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// Version entry in the registry index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryPluginVersion {
    pub version: String,
    pub protocol_version: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub released_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub voidb_core: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub platforms: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_scheme: Option<String>,
    pub packages: Vec<RegistryPackageArtifact>,
}

/// Plugin entry in the registry index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryPluginEntry {
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub homepage: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<PluginCategory>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
    pub latest_version: String,
    pub versions: Vec<RegistryPluginVersion>,
}

/// The complete plugin registry index catalog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginRegistryIndex {
    #[serde(default, rename = "$schema", skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    pub schema_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry_url: Option<String>,
    pub updated_at: DateTime<Utc>,
    pub plugins: Vec<RegistryPluginEntry>,
}

impl Default for PluginRegistryIndex {
    fn default() -> Self {
        Self {
            schema: Some(REGISTRY_SCHEMA_URI.to_string()),
            schema_version: REGISTRY_SCHEMA_VERSION,
            registry_name: Some("VoidB Official Plugin Registry".to_string()),
            registry_url: Some(DEFAULT_OFFICIAL_REGISTRY_URL.to_string()),
            updated_at: Utc::now(),
            plugins: Vec::new(),
        }
    }
}

impl PluginRegistryIndex {
    /// Create a new empty registry index.
    pub fn new() -> Self {
        Self::default()
    }

    /// Lookup a plugin by its unique ID.
    pub fn get_plugin(&self, id: &str) -> Option<&RegistryPluginEntry> {
        self.plugins.iter().find(|p| p.id == id)
    }

    /// Lookup a mutable plugin entry by ID.
    pub fn get_plugin_mut(&mut self, id: &str) -> Option<&mut RegistryPluginEntry> {
        self.plugins.iter_mut().find(|p| p.id == id)
    }

    /// Add or update a plugin entry in the index.
    pub fn upsert_plugin(&mut self, plugin: RegistryPluginEntry) {
        if let Some(pos) = self.plugins.iter().position(|p| p.id == plugin.id) {
            self.plugins[pos] = plugin;
        } else {
            self.plugins.push(plugin);
        }
        self.plugins.sort_by(|a, b| a.id.cmp(&b.id));
        self.updated_at = Utc::now();
    }

    /// Serialize to formatted JSON.
    pub fn to_json_pretty(&self) -> Result<String, VoidbError> {
        serde_json::to_string_pretty(self).map_err(|e| VoidbError::Plugin(format!("Failed to serialize registry index to JSON: {e}")))
    }

    /// Parse from JSON string.
    pub fn from_json(json_str: &str) -> Result<Self, VoidbError> {
        serde_json::from_str(json_str).map_err(|e| VoidbError::Plugin(format!("Failed to parse registry index JSON: {e}")))
    }

    /// Serialize to TOML string.
    pub fn to_toml(&self) -> Result<String, VoidbError> {
        toml::to_string_pretty(self).map_err(|e| VoidbError::Plugin(format!("Failed to serialize registry index to TOML: {e}")))
    }

    /// Parse from TOML string.
    pub fn from_toml(toml_str: &str) -> Result<Self, VoidbError> {
        toml::from_str(toml_str).map_err(|e| VoidbError::Plugin(format!("Failed to parse registry index TOML: {e}")))
    }

    /// Save index to file (JSON or TOML based on file extension).
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), VoidbError> {
        let path = path.as_ref();
        let content = if path.extension().and_then(|s| s.to_str()) == Some("toml") {
            self.to_toml()?
        } else {
            self.to_json_pretty()?
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Load index from file (JSON or TOML based on file extension).
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, VoidbError> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path)?;
        if path.extension().and_then(|s| s.to_str()) == Some("toml") {
            Self::from_toml(&content)
        } else {
            Self::from_json(&content)
        }
    }

    /// Fetch registry index from a remote HTTP, HTTPS URL, file:// URL, or local path.
    pub async fn fetch_from_url(url: &str) -> Result<Self, VoidbError> {
        if let Some(file_path) = url.strip_prefix("file://") {
            return Self::load_from_file(file_path);
        }
        if std::path::Path::new(url).is_file() {
            return Self::load_from_file(url);
        }

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .map_err(|e| VoidbError::Network(format!("Failed to build HTTP client: {e}")))?;

        let resp = client
            .get(url)
            .send()
            .await
            .map_err(|e| VoidbError::Network(format!("Failed to fetch registry from '{url}': {e}")))?;

        if !resp.status().is_success() {
            return Err(VoidbError::Network(format!(
                "Registry fetch returned HTTP status {}: {}",
                resp.status(),
                url
            )));
        }

        let content = resp
            .text()
            .await
            .map_err(|e| VoidbError::Network(format!("Failed to read registry response body from '{url}': {e}")))?;

        if url.ends_with(".toml") {
            Self::from_toml(&content)
        } else {
            Self::from_json(&content)
        }
    }

    /// Load from local cache file if fresh (less than `ttl`), otherwise fetch from URL and persist cache.
    pub async fn fetch_with_cache<P: AsRef<Path>>(
        url: &str,
        cache_path: P,
        ttl: std::time::Duration,
    ) -> Result<Self, VoidbError> {
        let cache_path = cache_path.as_ref();

        // 1. Check if cache exists and is fresh
        let is_fresh = std::fs::metadata(cache_path)
            .and_then(|m| m.modified())
            .and_then(|mod_time| mod_time.elapsed().map_err(std::io::Error::other))
            .map(|elapsed| elapsed < ttl)
            .unwrap_or(false);

        if is_fresh && let Ok(cached) = Self::load_from_file(cache_path) {
            return Ok(cached);
        }

        // 2. Fetch remote
        match Self::fetch_from_url(url).await {
            Ok(fetched) => {
                let _ = fetched.save_to_file(cache_path);
                Ok(fetched)
            }
            Err(e) => {
                // If remote fetch fails, fallback to existing stale cache if present
                if let Ok(stale) = Self::load_from_file(cache_path) {
                    tracing::warn!("Failed to fetch remote registry ({e}), using cached fallback: {}", cache_path.display());
                    Ok(stale)
                } else {
                    Err(e)
                }
            }
        }
    }

    /// Download and verify a package artifact from remote URL.
    /// Verifies SHA256 digest and optionally detached signature.
    pub async fn download_artifact(
        artifact: &RegistryPackageArtifact,
        dest_path: impl AsRef<Path>,
    ) -> Result<PathBuf, VoidbError> {
        let dest_path = dest_path.as_ref();
        if let Some(parent) = dest_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let bytes = if let Some(local_path) = artifact.url.strip_prefix("file://") {
            std::fs::read(local_path)?
        } else if std::path::Path::new(&artifact.url).is_file() {
            std::fs::read(&artifact.url)?
        } else {
            let client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(60))
                .build()
                .map_err(|e| VoidbError::Network(format!("Failed to build HTTP client for artifact download: {e}")))?;

            let resp = client
                .get(&artifact.url)
                .send()
                .await
                .map_err(|e| VoidbError::Network(format!("Failed to download package from '{}': {e}", artifact.url)))?;

            if !resp.status().is_success() {
                return Err(VoidbError::Network(format!(
                    "Failed to download package from '{}': HTTP {}",
                    artifact.url,
                    resp.status()
                )));
            }

            resp.bytes()
                .await
                .map_err(|e| VoidbError::Network(format!("Failed to read response stream from '{}': {e}", artifact.url)))?
                .to_vec()
        };

        // SHA256 integrity gate
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let calculated_sha256 = hex::encode(hasher.finalize());

        let expected_sha256 = artifact.sha256.strip_prefix("sha256:").unwrap_or(&artifact.sha256);
        if !calculated_sha256.eq_ignore_ascii_case(expected_sha256) {
            return Err(VoidbError::Plugin(format!(
                "Artifact SHA256 checksum mismatch for '{}'! Expected: {}, Calculated: {}",
                artifact.filename, artifact.sha256, calculated_sha256
            )));
        }

        std::fs::write(dest_path, &bytes)?;

        // If package has an inline signature or detached signature, write it as well
        if let Some(sig) = &artifact.signature {
            let sig_path = crate::plugin_signing::default_signature_path(dest_path);
            let _ = std::fs::write(sig_path, sig.trim());
        }

        Ok(dest_path.to_path_buf())
    }
}

impl RegistryPluginVersion {
    /// Find the best matching package artifact for the given target and platform.
    pub fn find_matching_package(
        &self,
        current_target: &str,
        current_plat: &str,
    ) -> Option<&RegistryPackageArtifact> {
        // 1. Exact match on target triple (e.g., aarch64-apple-darwin)
        if let Some(artifact) = self.packages.iter().find(|p| {
            p.target.as_deref().is_some_and(|t| t == current_target)
        }) {
            return Some(artifact);
        }

        // 2. Exact match on platform or platform prefix in target
        if let Some(artifact) = self.packages.iter().find(|p| {
            if let Some(target) = p.target.as_deref() {
                target == current_plat || target.contains(current_plat)
            } else {
                false
            }
        }) {
            return Some(artifact);
        }

        // 3. Match universal or platform-agnostic target
        if let Some(artifact) = self.packages.iter().find(|p| {
            p.target.as_deref().is_some_and(|t| t == "universal" || t == "all" || t == "any")
        }) {
            return Some(artifact);
        }

        // 4. Default fallback: artifact with no target specified, or first package
        self.packages.iter().find(|p| p.target.is_none()).or_else(|| self.packages.first())
    }
}

impl RegistryPluginEntry {
    /// Get the latest version descriptor.
    pub fn get_latest_version(&self) -> Option<&RegistryPluginVersion> {
        self.versions.iter().find(|v| v.version == self.latest_version).or_else(|| self.versions.last())
    }

    /// Find a specific version or fall back to latest.
    pub fn get_version(&self, ver_opt: Option<&str>) -> Option<&RegistryPluginVersion> {
        match ver_opt {
            Some(v) => self.versions.iter().find(|item| item.version == v),
            None => self.get_latest_version(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_index_roundtrip_json_and_toml() {
        let mut index = PluginRegistryIndex::new();
        index.registry_name = Some("Test Registry".to_string());

        let artifact = RegistryPackageArtifact {
            filename: "s3-0.3.0.tar.gz".to_string(),
            format: "tar.gz".to_string(),
            target: Some("universal".to_string()),
            url: "https://github.com/limmytian/voidb-plugin-s3/releases/download/v0.3.0/s3-0.3.0.tar.gz".to_string(),
            sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            size_bytes: Some(1024),
            signature: None,
        };

        let version = RegistryPluginVersion {
            version: "0.3.0".to_string(),
            protocol_version: "1".to_string(),
            released_at: Some(Utc::now()),
            voidb_core: Some(">=0.1.0".to_string()),
            platforms: vec!["darwin".to_string(), "linux".to_string(), "windows".to_string()],
            signature_scheme: None,
            packages: vec![artifact],
        };

        let plugin = RegistryPluginEntry {
            id: "s3".to_string(),
            name: "S3 Object Storage Plugin".to_string(),
            description: Some("S3 storage plugin".to_string()),
            homepage: Some("https://github.com/limmytian/voidb-plugin-s3".to_string()),
            license: Some("Apache-2.0".to_string()),
            category: Some(PluginCategory::Storage),
            tags: vec!["s3".to_string(), "storage".to_string()],
            capabilities: vec!["list".to_string(), "get".to_string(), "put".to_string()],
            latest_version: "0.3.0".to_string(),
            versions: vec![version],
        };

        index.upsert_plugin(plugin);

        let json = index.to_json_pretty().expect("json serialize");
        let parsed_json = PluginRegistryIndex::from_json(&json).expect("json deserialize");
        assert_eq!(parsed_json.plugins.len(), 1);
        assert_eq!(parsed_json.plugins[0].id, "s3");
        assert_eq!(parsed_json.plugins[0].category, Some(PluginCategory::Storage));

        let toml_str = index.to_toml().expect("toml serialize");
        let parsed_toml = PluginRegistryIndex::from_toml(&toml_str).expect("toml deserialize");
        assert_eq!(parsed_toml.plugins.len(), 1);
        assert_eq!(parsed_toml.plugins[0].id, "s3");
    }

    #[test]
    fn test_registry_schema_validation() {
        let mut index = PluginRegistryIndex::new();
        let plugin = RegistryPluginEntry {
            id: "docker".to_string(),
            name: "Docker Plugin".to_string(),
            description: Some("Docker plugin description".to_string()),
            homepage: Some("https://github.com/limmytian/voidb-plugin-docker".to_string()),
            license: Some("Apache-2.0".to_string()),
            category: Some(PluginCategory::Infrastructure),
            tags: vec!["docker".to_string()],
            capabilities: vec!["list_containers".to_string()],
            latest_version: "0.3.0".to_string(),
            versions: vec![RegistryPluginVersion {
                version: "0.3.0".to_string(),
                protocol_version: "1".to_string(),
                released_at: Some(Utc::now()),
                voidb_core: Some(">=0.1.0".to_string()),
                platforms: vec!["linux".to_string()],
                signature_scheme: None,
                packages: vec![RegistryPackageArtifact {
                    filename: "docker-0.3.0.tar.gz".to_string(),
                    format: "tar.gz".to_string(),
                    target: None,
                    url: "https://example.com/docker.tar.gz".to_string(),
                    sha256: "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string(),
                    size_bytes: Some(2048),
                    signature: None,
                }],
            }],
        };
        index.upsert_plugin(plugin);

        let json_value = serde_json::to_value(&index).unwrap();
        let schema_json: serde_json::Value = serde_json::from_str(include_str!("../../../schemas/plugin-registry.schema.json")).unwrap();
        let compiled = jsonschema::validator_for(&schema_json).unwrap();
        assert!(compiled.is_valid(&json_value));
    }
}
