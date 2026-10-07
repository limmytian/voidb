//! Runtime process-plugin discovery.
//!
//! This module implements the read-only discovery MVP for `plugin.toml`
//! manifests. It does not execute plugin binaries; it only parses manifests,
//! validates metadata, resolves referenced files, and reports deterministic
//! candidate states for CLI and future runtime code.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};

use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use semver::{Op, Prerelease, Version, VersionReq};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::capability::{
    CapabilityAuthorizationMetadata, CapabilityExecutionMode, CapabilityRiskLevel,
    CapabilitySessionHandoff,
};
use crate::process_plugin_contract::{
    PROCESS_PLUGIN_BUNDLED_ROOT_ENV, PROCESS_PLUGIN_DEVELOPMENT_PATH_ENV,
    PROCESS_PLUGIN_MANIFEST_SCHEMA_URI, PROCESS_PLUGIN_PROTOCOL_VERSION,
    PROCESS_PLUGIN_SUPPORTED_PROTOCOL_VERSIONS, PROCESS_PLUGIN_SUPPORTED_TRANSPORTS,
    PROCESS_PLUGIN_TRANSPORT_STDIO_JSONRPC, is_supported_process_plugin_protocol_version,
};

const MANIFEST_FILE_NAME: &str = "plugin.toml";
pub const PROCESS_PLUGIN_INSTALL_METADATA_DIR: &str = ".voidb-install";
pub const PROCESS_PLUGIN_INSTALL_RECORD_FILE: &str = "install.toml";
pub const PROCESS_PLUGIN_INSTALL_RECORD_SCHEMA_VERSION: u32 = 1;

static PLUGIN_MANIFEST_SCHEMA: Lazy<Value> = Lazy::new(|| {
    serde_json::from_str(include_str!("../../../schemas/plugin-manifest.schema.json"))
        .expect("plugin manifest schema is valid JSON")
});

/// Parsed `plugin.toml` manifest for a process plugin.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProcessPluginManifest {
    #[serde(default, rename = "$schema")]
    pub schema: Option<String>,
    pub id: String,
    pub name: String,
    pub version: String,
    pub protocol_version: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub license: Option<String>,
    #[serde(default)]
    pub homepage: Option<String>,
    pub runtime: ProcessPluginRuntime,
    pub connections: ProcessPluginConnections,
    pub capabilities: Vec<ProcessPluginCapability>,
    #[serde(default)]
    pub ui: Option<ProcessPluginUi>,
    #[serde(default)]
    pub requirements: Option<ProcessPluginRequirements>,
}

/// Runtime launch declaration from a process-plugin manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessPluginRuntime {
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    pub transport: String,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

/// Connection profile declaration from a process-plugin manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessPluginConnections {
    pub profile_schema: String,
    pub secret_classes: Vec<String>,
}

/// Capability declaration from a process-plugin manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessPluginCapability {
    pub id: String,
    pub description: String,
    pub input_schema: String,
    pub output_schema: String,
    pub permissions: Vec<String>,
    #[serde(default)]
    pub authorization: CapabilityAuthorizationMetadata,
    #[serde(default)]
    pub risk: Option<CapabilityRiskLevel>,
    pub destructive: bool,
    pub streaming: bool,
    #[serde(default)]
    pub execution_mode: CapabilityExecutionMode,
    #[serde(default)]
    pub session_handoff: Option<CapabilitySessionHandoff>,
    #[serde(default = "default_connection_required")]
    pub connection_required: bool,
    #[serde(default)]
    pub required_secret_classes: Vec<String>,
    #[serde(default)]
    pub supports_dry_run: bool,
    #[serde(default)]
    pub default_timeout_ms: Option<u64>,
}

/// Optional TUI declaration from a process-plugin manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessPluginUi {
    pub tui: bool,
    #[serde(default)]
    pub entrypoint_capability: Option<String>,
    #[serde(default)]
    pub raw_input: bool,
}

/// Compatibility requirements from a process-plugin manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessPluginRequirements {
    #[serde(default)]
    pub voidb_core: Option<String>,
    #[serde(default)]
    pub platforms: Option<Vec<String>>,
}

/// Ordered plugin root kind.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ProcessPluginRootKind {
    EnvPath,
    User,
    System,
    Bundled,
}

impl ProcessPluginRootKind {
    pub fn trust_level(self) -> ProcessPluginTrustLevel {
        match self {
            Self::EnvPath => ProcessPluginTrustLevel::ExplicitDevelopment,
            Self::User => ProcessPluginTrustLevel::UserInstalled,
            Self::System => ProcessPluginTrustLevel::AdministratorManaged,
            Self::Bundled => ProcessPluginTrustLevel::Bundled,
        }
    }
}

/// Local execution trust boundary for a process-plugin root or candidate.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProcessPluginTrustLevel {
    ExplicitDevelopment,
    UserInstalled,
    AdministratorManaged,
    Bundled,
}

/// One root directory that may contain process-plugin directories.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessPluginRoot {
    pub path: PathBuf,
    pub kind: ProcessPluginRootKind,
    pub precedence: usize,
    pub explicit_development: bool,
}

impl ProcessPluginRoot {
    pub fn new(path: impl Into<PathBuf>, kind: ProcessPluginRootKind, precedence: usize) -> Self {
        Self {
            path: path.into(),
            kind,
            precedence,
            explicit_development: kind == ProcessPluginRootKind::EnvPath,
        }
    }

    pub fn trust_level(&self) -> ProcessPluginTrustLevel {
        if self.explicit_development {
            ProcessPluginTrustLevel::ExplicitDevelopment
        } else {
            self.kind.trust_level()
        }
    }
}

/// Candidate source metadata.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessPluginSource {
    pub root: PathBuf,
    pub plugin_dir: PathBuf,
    pub kind: ProcessPluginRootKind,
    pub trust_level: ProcessPluginTrustLevel,
    pub precedence: usize,
}

/// Discovery state for one process-plugin candidate.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum ProcessPluginCandidateState {
    Available,
    Invalid,
    Incompatible,
    Shadowed,
    Disabled,
    Failed,
}

impl ProcessPluginCandidateState {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::Invalid => "invalid",
            Self::Incompatible => "incompatible",
            Self::Shadowed => "shadowed",
            Self::Disabled => "disabled",
            Self::Failed => "failed",
        }
    }
}

impl std::str::FromStr for ProcessPluginCandidateState {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "available" => Ok(Self::Available),
            "invalid" => Ok(Self::Invalid),
            "incompatible" => Ok(Self::Incompatible),
            "shadowed" => Ok(Self::Shadowed),
            "disabled" => Ok(Self::Disabled),
            "failed" => Ok(Self::Failed),
            other => Err(format!("Unsupported process plugin state: {}", other)),
        }
    }
}

/// Severity for a process-plugin discovery diagnostic.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProcessPluginDiagnosticSeverity {
    Error,
    Warning,
}

/// Agent-safe diagnostic for process-plugin discovery.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProcessPluginDiagnostic {
    pub severity: ProcessPluginDiagnosticSeverity,
    pub code: String,
    pub message: String,
    pub details: Box<Value>,
}

impl ProcessPluginDiagnostic {
    fn error(code: &str, message: &str, details: Value) -> Self {
        Self {
            severity: ProcessPluginDiagnosticSeverity::Error,
            code: code.into(),
            message: message.into(),
            details: Box::new(details),
        }
    }

    fn warning(code: &str, message: &str, details: Value) -> Self {
        Self {
            severity: ProcessPluginDiagnosticSeverity::Warning,
            code: code.into(),
            message: message.into(),
            details: Box::new(details),
        }
    }
}

/// One discovered process-plugin candidate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProcessPluginCandidate {
    pub id: String,
    pub name: Option<String>,
    pub version: Option<String>,
    pub protocol_version: Option<String>,
    pub manifest_path: PathBuf,
    pub source: ProcessPluginSource,
    pub state: ProcessPluginCandidateState,
    pub transport: Option<String>,
    pub capability_count: usize,
    pub tui: bool,
    pub diagnostics: Vec<ProcessPluginDiagnostic>,
    pub manifest: Option<ProcessPluginManifest>,
    pub resolved_runtime_command: Option<PathBuf>,
    pub resolved_schema_paths: BTreeMap<String, PathBuf>,
}

impl ProcessPluginCandidate {
    pub fn is_effective_available(&self) -> bool {
        self.state == ProcessPluginCandidateState::Available
    }
}

/// Read-only process-plugin discovery result.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProcessPluginDiscovery {
    pub roots: Vec<ProcessPluginRoot>,
    pub candidates: Vec<ProcessPluginCandidate>,
}

impl ProcessPluginDiscovery {
    pub fn candidates_for_id(&self, plugin_id: &str) -> Vec<&ProcessPluginCandidate> {
        self.candidates
            .iter()
            .filter(|candidate| candidate.id == plugin_id)
            .collect()
    }

    pub fn effective_candidate(&self, plugin_id: &str) -> Option<&ProcessPluginCandidate> {
        self.candidates
            .iter()
            .find(|candidate| candidate.id == plugin_id && candidate.is_effective_available())
            .or_else(|| {
                self.candidates
                    .iter()
                    .find(|candidate| candidate.id == plugin_id)
            })
    }
}

/// Local package source kind for process-plugin installation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProcessPluginPackageSourceKind {
    LocalDirectory,
    LocalArchive,
}

/// Local package input for process-plugin validation or installation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessPluginPackageSource {
    pub kind: ProcessPluginPackageSourceKind,
    pub path: PathBuf,
}

impl ProcessPluginPackageSource {
    pub fn local_directory(path: impl Into<PathBuf>) -> Self {
        Self {
            kind: ProcessPluginPackageSourceKind::LocalDirectory,
            path: path.into(),
        }
    }

    pub fn local_archive(path: impl Into<PathBuf>) -> Self {
        Self {
            kind: ProcessPluginPackageSourceKind::LocalArchive,
            path: path.into(),
        }
    }

    pub fn from_path(
        path: impl Into<PathBuf>,
    ) -> Result<Self, ProcessPluginPackageValidationError> {
        let path = path.into();
        if path.is_dir() {
            Ok(Self::local_directory(path))
        } else if path.is_file() {
            Ok(Self::local_archive(path))
        } else {
            Err(ProcessPluginPackageValidationError::new(
                "package.source_missing",
                "Plugin package source must be an existing local directory or archive.",
                json!({ "path": redact_source_locator(&path) }),
            ))
        }
    }
}

/// Agent-safe source metadata stored in install records and JSON output.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessPluginPackageSourceSummary {
    pub kind: ProcessPluginPackageSourceKind,
    pub locator: String,
    pub redacted_locator: String,
}

/// Previous active package metadata retained for rollback.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessPluginPreviousVersionRecord {
    pub version: String,
    pub path: PathBuf,
    pub manifest_digest: Option<String>,
    pub package_digest: Option<String>,
    pub recorded_at: DateTime<Utc>,
}

/// Last compatibility status captured during package validation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProcessPluginInstallCompatibilityRecord {
    pub state: ProcessPluginCandidateState,
    pub core_version: String,
    pub protocol_version: Option<String>,
    pub diagnostics: Vec<ProcessPluginDiagnostic>,
}

/// Source metadata persisted in `.voidb-install/<plugin-id>/install.toml`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessPluginInstallSourceRecord {
    pub kind: ProcessPluginPackageSourceKind,
    pub locator: String,
    pub redacted_locator: String,
}

/// Install record persisted under `.voidb-install/<plugin-id>/install.toml`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProcessPluginInstallRecord {
    pub schema_version: u32,
    pub plugin_id: String,
    pub installed_version: String,
    pub manifest_digest: String,
    pub package_digest: String,
    pub source: ProcessPluginInstallSourceRecord,
    pub install_root: PathBuf,
    pub installed_at: DateTime<Utc>,
    pub installed_by: String,
    pub enabled: bool,
    pub previous_version: Option<ProcessPluginPreviousVersionRecord>,
    pub compatibility: ProcessPluginInstallCompatibilityRecord,
}

/// Successful package validation result. The caller owns `staging_root`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProcessPluginPackageValidation {
    pub source: ProcessPluginPackageSourceSummary,
    pub install_root: PathBuf,
    pub staging_root: PathBuf,
    pub staged_plugin_dir: PathBuf,
    pub manifest_path: PathBuf,
    pub plugin_id: String,
    pub version: String,
    pub manifest_digest: String,
    pub package_digest: String,
    pub candidate: ProcessPluginCandidate,
    pub install_record: ProcessPluginInstallRecord,
    pub warnings: Vec<ProcessPluginDiagnostic>,
}

/// Archive format for packaging offline process plugins.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProcessPluginPackageFormat {
    TarZst,
    Tar,
}

impl ProcessPluginPackageFormat {
    pub fn extension(&self) -> &'static str {
        match self {
            Self::TarZst => "tar.zst",
            Self::Tar => "tar",
        }
    }
}

/// Metadata of an entry included in a packaged process-plugin archive.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessPluginPackagedFile {
    pub path: String,
    pub size: u64,
}

/// Metadata output from packaging a process plugin.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessPluginPackageResult {
    pub plugin_id: String,
    pub version: String,
    pub archive_path: PathBuf,
    pub format: ProcessPluginPackageFormat,
    pub package_digest: String,
    pub total_size: u64,
    pub files: Vec<ProcessPluginPackagedFile>,
}

/// Structured package validation failure for stable CLI JSON output.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProcessPluginPackageValidationError {
    pub code: String,
    pub message: String,
    pub details: Box<Value>,
    pub diagnostics: Box<[ProcessPluginDiagnostic]>,
}

impl ProcessPluginPackageValidationError {
    fn new(code: &str, message: &str, details: Value) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            details: Box::new(details),
            diagnostics: Vec::new().into_boxed_slice(),
        }
    }

    fn with_diagnostics(
        code: &str,
        message: &str,
        details: Value,
        diagnostics: Vec<ProcessPluginDiagnostic>,
    ) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            details: Box::new(details),
            diagnostics: diagnostics.into_boxed_slice(),
        }
    }

    fn io(action: &str, path: &Path, error: io::Error) -> Self {
        Self::new(
            "package.io_failed",
            "Plugin package filesystem operation failed.",
            json!({
                "action": action,
                "path": redact_source_locator(path),
                "message": error.to_string(),
            }),
        )
    }
}

impl std::fmt::Display for ProcessPluginPackageValidationError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for ProcessPluginPackageValidationError {}

/// Resolve the normal writable per-user process-plugin install root.
pub fn default_user_process_plugin_install_root() -> Option<PathBuf> {
    default_user_plugin_root()
}

pub fn process_plugin_install_metadata_root(install_root: &Path) -> PathBuf {
    install_root.join(PROCESS_PLUGIN_INSTALL_METADATA_DIR)
}

pub fn process_plugin_install_record_path(install_root: &Path, plugin_id: &str) -> PathBuf {
    process_plugin_install_metadata_root(install_root)
        .join(plugin_id)
        .join(PROCESS_PLUGIN_INSTALL_RECORD_FILE)
}

pub fn read_process_plugin_install_record(
    path: &Path,
) -> Result<ProcessPluginInstallRecord, ProcessPluginPackageValidationError> {
    let content = fs::read_to_string(path).map_err(|error| {
        ProcessPluginPackageValidationError::io("read install record", path, error)
    })?;
    toml::from_str(&content).map_err(|error| {
        ProcessPluginPackageValidationError::new(
            "install_record.toml_invalid",
            "Process-plugin install record is not valid TOML.",
            json!({
                "path": redact_source_locator(path),
                "message": error.to_string(),
            }),
        )
    })
}

pub fn write_process_plugin_install_record(
    record: &ProcessPluginInstallRecord,
) -> Result<PathBuf, ProcessPluginPackageValidationError> {
    let path = process_plugin_install_record_path(&record.install_root, &record.plugin_id);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            ProcessPluginPackageValidationError::io(
                "create install record directory",
                parent,
                error,
            )
        })?;
    }
    let content = toml::to_string_pretty(record).map_err(|error| {
        ProcessPluginPackageValidationError::new(
            "install_record.encode_failed",
            "Process-plugin install record could not be encoded as TOML.",
            json!({ "message": error.to_string() }),
        )
    })?;
    fs::write(&path, content).map_err(|error| {
        ProcessPluginPackageValidationError::io("write install record", &path, error)
    })?;
    Ok(path)
}

pub fn cleanup_process_plugin_package_staging(
    staging_root: &Path,
) -> Result<(), ProcessPluginPackageValidationError> {
    if staging_root.exists() {
        fs::remove_dir_all(staging_root).map_err(|error| {
            ProcessPluginPackageValidationError::io(
                "remove package staging directory",
                staging_root,
                error,
            )
        })?;
    }
    Ok(())
}

/// Validate a local directory or archive package without replacing an active plugin.
pub fn validate_process_plugin_package(
    source: ProcessPluginPackageSource,
    install_root: impl AsRef<Path>,
) -> Result<ProcessPluginPackageValidation, ProcessPluginPackageValidationError> {
    let install_root = install_root.as_ref().to_path_buf();
    let source_summary = summarize_package_source(&source);
    let staging_root = create_process_plugin_staging_root(&install_root)?;

    let result = match source.kind {
        ProcessPluginPackageSourceKind::LocalDirectory => {
            validate_directory_package(&source.path, &install_root, &staging_root, source_summary)
        }
        ProcessPluginPackageSourceKind::LocalArchive => {
            validate_archive_package(&source.path, &install_root, &staging_root, source_summary)
        }
    };

    if result.is_err() {
        let _ = cleanup_process_plugin_package_staging(&staging_root);
    }

    result
}

pub fn validate_process_plugin_package_from_path(
    source_path: impl Into<PathBuf>,
    install_root: impl AsRef<Path>,
) -> Result<ProcessPluginPackageValidation, ProcessPluginPackageValidationError> {
    validate_process_plugin_package(
        ProcessPluginPackageSource::from_path(source_path)?,
        install_root,
    )
}

/// Discover process plugins from default roots.
pub fn discover_process_plugins() -> ProcessPluginDiscovery {
    discover_process_plugins_from_roots(default_process_plugin_roots())
}

/// Discover process plugins from explicit roots.
pub fn discover_process_plugins_from_roots(
    mut roots: Vec<ProcessPluginRoot>,
) -> ProcessPluginDiscovery {
    roots.sort_by_key(|root| root.precedence);

    let mut candidates = Vec::new();
    for root in &roots {
        candidates.extend(discover_root(root));
    }

    apply_shadowing(&mut candidates);
    candidates.sort_by(|left, right| {
        left.id
            .cmp(&right.id)
            .then_with(|| left.source.precedence.cmp(&right.source.precedence))
            .then_with(|| left.manifest_path.cmp(&right.manifest_path))
    });

    ProcessPluginDiscovery { roots, candidates }
}

/// Collect process-plugin roots using VoidB's documented precedence order.
pub fn default_process_plugin_roots() -> Vec<ProcessPluginRoot> {
    let mut user_roots = default_user_plugin_roots();
    let primary_user_root = if !user_roots.is_empty() {
        Some(user_roots.remove(0))
    } else {
        None
    };

    let mut roots = process_plugin_roots_from_parts(
        std::env::var_os(PROCESS_PLUGIN_DEVELOPMENT_PATH_ENV).as_deref(),
        primary_user_root,
        default_system_plugin_roots(),
        default_bundled_plugin_roots(),
    );

    // If additional user roots exist (e.g. ~/.config/voidb/plugins), add them under User kind
    for additional_root in user_roots {
        let precedence = roots.len();
        roots.push(ProcessPluginRoot::new(
            additional_root,
            ProcessPluginRootKind::User,
            precedence,
        ));
    }

    roots
}

/// Build ordered process-plugin roots from explicit parts.
///
/// Tests and future configuration callers use this to avoid mutating process
/// environment variables.
pub fn process_plugin_roots_from_parts(
    env_plugin_path: Option<&OsStr>,
    user_root: Option<PathBuf>,
    system_roots: Vec<PathBuf>,
    bundled_roots: Vec<PathBuf>,
) -> Vec<ProcessPluginRoot> {
    let mut roots = Vec::new();

    if let Some(env_plugin_path) = env_plugin_path {
        for path in
            std::env::split_paths(env_plugin_path).filter(|path| !path.as_os_str().is_empty())
        {
            push_root(&mut roots, path, ProcessPluginRootKind::EnvPath);
        }
    }

    if let Some(user_root) = user_root {
        push_root(&mut roots, user_root, ProcessPluginRootKind::User);
    }

    for system_root in system_roots {
        push_root(&mut roots, system_root, ProcessPluginRootKind::System);
    }

    for bundled_root in bundled_roots {
        push_root(&mut roots, bundled_root, ProcessPluginRootKind::Bundled);
    }

    roots
}

fn push_root(roots: &mut Vec<ProcessPluginRoot>, path: PathBuf, kind: ProcessPluginRootKind) {
    let precedence = roots.len();
    roots.push(ProcessPluginRoot::new(path, kind, precedence));
}

fn default_connection_required() -> bool {
    true
}

fn default_user_plugin_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    // 1. User configuration directory: ~/.config/voidb/plugins
    if let Some(config_dir) = dirs::config_dir() {
        let path = config_dir.join("voidb").join("plugins");
        if !roots.contains(&path) {
            roots.push(path);
        }
    }
    // 2. User data directory: ~/.local/share/voidb/plugins or platform equivalent
    if let Some(data_dir) = dirs::data_dir() {
        let path = data_dir.join("voidb").join("plugins");
        if !roots.contains(&path) {
            roots.push(path);
        }
    }
    roots
}

fn default_user_plugin_root() -> Option<PathBuf> {
    default_user_plugin_roots().into_iter().next()
}

fn default_bundled_plugin_roots() -> Vec<PathBuf> {
    std::env::var_os(PROCESS_PLUGIN_BUNDLED_ROOT_ENV)
        .map(|roots| std::env::split_paths(&roots).collect())
        .unwrap_or_default()
}

#[cfg(target_os = "macos")]
fn default_system_plugin_roots() -> Vec<PathBuf> {
    vec![PathBuf::from("/Library/Application Support/voidb/plugins")]
}

#[cfg(target_os = "linux")]
fn default_system_plugin_roots() -> Vec<PathBuf> {
    vec![
        PathBuf::from("/usr/local/share/voidb/plugins"),
        PathBuf::from("/usr/share/voidb/plugins"),
    ]
}

#[cfg(windows)]
fn default_system_plugin_roots() -> Vec<PathBuf> {
    std::env::var_os("ProgramData")
        .map(|dir| vec![PathBuf::from(dir).join("voidb").join("plugins")])
        .unwrap_or_default()
}

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
fn default_system_plugin_roots() -> Vec<PathBuf> {
    Vec::new()
}

fn summarize_package_source(
    source: &ProcessPluginPackageSource,
) -> ProcessPluginPackageSourceSummary {
    let redacted_locator = redact_source_locator(&source.path);
    ProcessPluginPackageSourceSummary {
        kind: source.kind,
        locator: redacted_locator.clone(),
        redacted_locator,
    }
}

fn redact_source_locator(path: &Path) -> String {
    let mut value = path.to_string_lossy().to_string();
    if let Some(home_dir) = dirs::home_dir() {
        let home = home_dir.to_string_lossy();
        if value == home {
            value = "~".into();
        } else if let Some(rest) = value.strip_prefix(&format!("{home}/")) {
            value = format!("~/{rest}");
        }
    }
    redact_locator_secrets(&value)
}

fn redact_locator_secrets(value: &str) -> String {
    if let Some((scheme, rest)) = value.split_once("://")
        && let Some((userinfo, host_and_path)) = rest.split_once('@')
        && (userinfo.contains(':') || userinfo.to_ascii_lowercase().contains("token"))
    {
        return format!("{scheme}://<redacted>@{host_and_path}");
    }

    value
        .split('/')
        .map(|segment| {
            let lower = segment.to_ascii_lowercase();
            if lower.contains("password")
                || lower.contains("passwd")
                || lower.contains("secret")
                || lower.contains("token")
                || lower.contains("apikey")
                || lower.contains("api_key")
            {
                "<redacted>"
            } else {
                segment
            }
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn create_process_plugin_staging_root(
    install_root: &Path,
) -> Result<PathBuf, ProcessPluginPackageValidationError> {
    let staging_parent = process_plugin_install_metadata_root(install_root).join(".staging");
    fs::create_dir_all(&staging_parent).map_err(|error| {
        ProcessPluginPackageValidationError::io(
            "create package staging parent",
            &staging_parent,
            error,
        )
    })?;

    let mut attempt = 0_u32;
    loop {
        let nonce = Utc::now()
            .timestamp_nanos_opt()
            .unwrap_or_else(|| Utc::now().timestamp_micros());
        let staging_root = staging_parent.join(format!(
            "package-{}-{}-{}",
            std::process::id(),
            nonce,
            attempt
        ));
        match fs::create_dir(&staging_root) {
            Ok(()) => return Ok(staging_root),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                attempt += 1;
                continue;
            }
            Err(error) => {
                return Err(ProcessPluginPackageValidationError::io(
                    "create package staging directory",
                    &staging_root,
                    error,
                ));
            }
        }
    }
}

fn validate_directory_package(
    source_path: &Path,
    install_root: &Path,
    staging_root: &Path,
    source_summary: ProcessPluginPackageSourceSummary,
) -> Result<ProcessPluginPackageValidation, ProcessPluginPackageValidationError> {
    let source_root = fs::canonicalize(source_path).map_err(|error| {
        ProcessPluginPackageValidationError::io(
            "canonicalize package directory",
            source_path,
            error,
        )
    })?;
    if !source_root.is_dir() {
        return Err(ProcessPluginPackageValidationError::new(
            "package.source_not_directory",
            "Plugin package source is not a directory.",
            json!({ "path": redact_source_locator(source_path) }),
        ));
    }

    ensure_package_tree_safe(&source_root)?;
    let package_root = locate_single_package_root(&source_root)?;
    let package_digest = digest_directory(&package_root)?;
    validate_staged_package_root(
        &package_root,
        install_root,
        staging_root,
        source_summary,
        package_digest,
    )
}

fn validate_archive_package(
    source_path: &Path,
    install_root: &Path,
    staging_root: &Path,
    source_summary: ProcessPluginPackageSourceSummary,
) -> Result<ProcessPluginPackageValidation, ProcessPluginPackageValidationError> {
    if !source_path.is_file() {
        return Err(ProcessPluginPackageValidationError::new(
            "package.source_not_archive",
            "Plugin package source is not a local archive file.",
            json!({ "path": redact_source_locator(source_path) }),
        ));
    }

    let package_digest = digest_file(source_path)?;
    let unpack_root = staging_root.join(".unpacked");
    fs::create_dir_all(&unpack_root).map_err(|error| {
        ProcessPluginPackageValidationError::io(
            "create archive unpack directory",
            &unpack_root,
            error,
        )
    })?;
    extract_process_plugin_archive(source_path, &unpack_root)?;
    ensure_package_tree_safe(&unpack_root)?;

    let package_root = locate_single_package_root(&unpack_root)?;
    validate_staged_package_root(
        &package_root,
        install_root,
        staging_root,
        source_summary,
        package_digest,
    )
}

fn validate_staged_package_root(
    package_root: &Path,
    install_root: &Path,
    staging_root: &Path,
    source_summary: ProcessPluginPackageSourceSummary,
    package_digest: String,
) -> Result<ProcessPluginPackageValidation, ProcessPluginPackageValidationError> {
    let manifest_id =
        read_package_manifest_id(package_root).unwrap_or_else(|| plugin_dir_name(package_root));
    let staged_plugin_dir = staging_root.join(&manifest_id);
    if staged_plugin_dir.exists() {
        fs::remove_dir_all(&staged_plugin_dir).map_err(|error| {
            ProcessPluginPackageValidationError::io(
                "clear package staging plugin directory",
                &staged_plugin_dir,
                error,
            )
        })?;
    }
    copy_directory_contents(package_root, &staged_plugin_dir)?;
    ensure_package_tree_safe(&staged_plugin_dir)?;

    let discovery = discover_process_plugins_from_roots(vec![ProcessPluginRoot::new(
        staging_root,
        ProcessPluginRootKind::User,
        0,
    )]);
    let Some(candidate) = discovery
        .candidates
        .into_iter()
        .find(|candidate| candidate.source.plugin_dir == staged_plugin_dir)
    else {
        return Err(ProcessPluginPackageValidationError::new(
            "package.candidate_missing",
            "Validated package staging did not produce a process-plugin candidate.",
            json!({
                "staging_root": staging_root,
                "staged_plugin_dir": staged_plugin_dir,
            }),
        ));
    };

    if candidate.state != ProcessPluginCandidateState::Available {
        let code = if candidate.state == ProcessPluginCandidateState::Incompatible {
            "package.compatibility_failed"
        } else {
            "package.validation_failed"
        };
        return Err(ProcessPluginPackageValidationError::with_diagnostics(
            code,
            "Plugin package failed process-plugin validation.",
            json!({
                "plugin_id": candidate.id,
                "candidate_state": candidate.state,
                "manifest_path": candidate.manifest_path,
            }),
            candidate.diagnostics,
        ));
    }

    let manifest = candidate.manifest.as_ref().ok_or_else(|| {
        ProcessPluginPackageValidationError::new(
            "package.manifest_missing",
            "Available process-plugin candidate is missing decoded manifest metadata.",
            json!({ "plugin_id": candidate.id }),
        )
    })?;
    let manifest_digest = digest_file(&candidate.manifest_path)?;
    let warnings = candidate
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.severity == ProcessPluginDiagnosticSeverity::Warning)
        .cloned()
        .collect::<Vec<_>>();
    let compatibility = ProcessPluginInstallCompatibilityRecord {
        state: candidate.state,
        core_version: env!("CARGO_PKG_VERSION").into(),
        protocol_version: candidate.protocol_version.clone(),
        diagnostics: candidate.diagnostics.clone(),
    };
    let install_record = ProcessPluginInstallRecord {
        schema_version: PROCESS_PLUGIN_INSTALL_RECORD_SCHEMA_VERSION,
        plugin_id: candidate.id.clone(),
        installed_version: manifest.version.clone(),
        manifest_digest: manifest_digest.clone(),
        package_digest: package_digest.clone(),
        source: ProcessPluginInstallSourceRecord {
            kind: source_summary.kind,
            locator: source_summary.locator.clone(),
            redacted_locator: source_summary.redacted_locator.clone(),
        },
        install_root: install_root.to_path_buf(),
        installed_at: Utc::now(),
        installed_by: default_install_actor(),
        enabled: true,
        previous_version: None,
        compatibility,
    };

    Ok(ProcessPluginPackageValidation {
        source: source_summary,
        install_root: install_root.to_path_buf(),
        staging_root: staging_root.to_path_buf(),
        staged_plugin_dir,
        manifest_path: candidate.manifest_path.clone(),
        plugin_id: candidate.id.clone(),
        version: manifest.version.clone(),
        manifest_digest,
        package_digest,
        candidate,
        install_record,
        warnings,
    })
}

fn default_install_actor() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .map(|user| format!("local:{user}"))
        .unwrap_or_else(|_| "local:unknown".into())
}

fn install_record_disables_candidate(root: &Path, plugin_id: &str) -> bool {
    read_process_plugin_install_record(&process_plugin_install_record_path(root, plugin_id))
        .is_ok_and(|record| !record.enabled)
}

fn locate_single_package_root(root: &Path) -> Result<PathBuf, ProcessPluginPackageValidationError> {
    let root_manifest = root.join(MANIFEST_FILE_NAME).is_file();
    let mut plugin_dirs = fs::read_dir(root)
        .map_err(|error| ProcessPluginPackageValidationError::io("read package root", root, error))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .filter(|path| !is_dot_prefixed(path))
        .filter(|path| path.join(MANIFEST_FILE_NAME).is_file())
        .collect::<Vec<_>>();
    plugin_dirs.sort();

    match (root_manifest, plugin_dirs.as_slice()) {
        (true, []) => Ok(root.to_path_buf()),
        (false, [plugin_dir]) => Ok(plugin_dir.clone()),
        (true, _) => Err(ProcessPluginPackageValidationError::new(
            "package.multiple_plugin_roots",
            "Plugin package must contain exactly one plugin root.",
            json!({
                "root_manifest": root.join(MANIFEST_FILE_NAME),
                "plugin_dirs": plugin_dirs,
            }),
        )),
        (false, []) => Err(ProcessPluginPackageValidationError::new(
            "package.manifest_not_found",
            "Plugin package must contain a plugin.toml at its root or inside one plugin directory.",
            json!({ "root": root }),
        )),
        (false, _) => Err(ProcessPluginPackageValidationError::new(
            "package.multiple_plugin_roots",
            "Plugin package must contain exactly one plugin root.",
            json!({ "plugin_dirs": plugin_dirs }),
        )),
    }
}

fn read_package_manifest_id(plugin_root: &Path) -> Option<String> {
    let content = fs::read_to_string(plugin_root.join(MANIFEST_FILE_NAME)).ok()?;
    let value = content.parse::<toml::Value>().ok()?;
    manifest_id_from_value(&value)
}

fn extract_process_plugin_archive(
    archive_path: &Path,
    destination: &Path,
) -> Result<(), ProcessPluginPackageValidationError> {
    let archive_name = archive_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default();
    let file = File::open(archive_path).map_err(|error| {
        ProcessPluginPackageValidationError::io("open plugin package archive", archive_path, error)
    })?;

    if archive_name.ends_with(".tar.zst") {
        let decoder = zstd::stream::read::Decoder::new(file).map_err(|error| {
            ProcessPluginPackageValidationError::new(
                "package.archive_decode_failed",
                "Plugin package archive could not be decoded as zstd.",
                json!({
                    "path": redact_source_locator(archive_path),
                    "message": error.to_string(),
                }),
            )
        })?;
        extract_tar_stream(decoder, destination)
    } else if archive_name.ends_with(".tar.gz") || archive_name.ends_with(".tgz") {
        let decoder = flate2::read::GzDecoder::new(file);
        extract_tar_stream(decoder, destination)
    } else if archive_name.ends_with(".tar") {
        extract_tar_stream(file, destination)
    } else {
        Err(ProcessPluginPackageValidationError::new(
            "package.archive_unsupported",
            "Plugin package archive must be a .tar, .tar.gz, or .tar.zst file.",
            json!({ "path": redact_source_locator(archive_path) }),
        ))
    }
}

fn extract_tar_stream<R: Read>(
    reader: R,
    destination: &Path,
) -> Result<(), ProcessPluginPackageValidationError> {
    let mut archive = tar::Archive::new(reader);
    let entries = archive.entries().map_err(|error| {
        ProcessPluginPackageValidationError::new(
            "package.archive_read_failed",
            "Plugin package archive entries could not be read.",
            json!({ "message": error.to_string() }),
        )
    })?;

    for entry in entries {
        let mut entry = entry.map_err(|error| {
            ProcessPluginPackageValidationError::new(
                "package.archive_read_failed",
                "Plugin package archive entry could not be read.",
                json!({ "message": error.to_string() }),
            )
        })?;
        let archive_path = entry.path().map_err(|error| {
            ProcessPluginPackageValidationError::new(
                "package.archive_path_invalid",
                "Plugin package archive contains an unreadable path.",
                json!({ "message": error.to_string() }),
            )
        })?;
        let relative_path = normalize_package_relative_path(&archive_path)?;
        if relative_path.as_os_str().is_empty() {
            continue;
        }
        let target_path = destination.join(&relative_path);
        let entry_type = entry.header().entry_type();

        if entry_type.is_dir() {
            fs::create_dir_all(&target_path).map_err(|error| {
                ProcessPluginPackageValidationError::io(
                    "create archive directory",
                    &target_path,
                    error,
                )
            })?;
        } else if entry_type.is_file() {
            if let Some(parent) = target_path.parent() {
                fs::create_dir_all(parent).map_err(|error| {
                    ProcessPluginPackageValidationError::io(
                        "create archive file parent directory",
                        parent,
                        error,
                    )
                })?;
            }
            let mut output = File::create(&target_path).map_err(|error| {
                ProcessPluginPackageValidationError::io("create archive file", &target_path, error)
            })?;
            io::copy(&mut entry, &mut output).map_err(|error| {
                ProcessPluginPackageValidationError::io("write archive file", &target_path, error)
            })?;
            set_archive_file_permissions(&target_path, entry.header().mode().ok());
        } else if entry_type.is_symlink() {
            let link_target = entry.link_name().map_err(|error| {
                ProcessPluginPackageValidationError::new(
                    "package.archive_symlink_invalid",
                    "Plugin package archive contains an unreadable symlink target.",
                    json!({
                        "path": relative_path,
                        "message": error.to_string(),
                    }),
                )
            })?;
            let Some(link_target) = link_target else {
                return Err(ProcessPluginPackageValidationError::new(
                    "package.archive_symlink_invalid",
                    "Plugin package archive contains a symlink without a target.",
                    json!({ "path": relative_path }),
                ));
            };
            validate_package_symlink_target(Path::new(""), &relative_path, &link_target)?;
            if let Some(parent) = target_path.parent() {
                fs::create_dir_all(parent).map_err(|error| {
                    ProcessPluginPackageValidationError::io(
                        "create archive symlink parent directory",
                        parent,
                        error,
                    )
                })?;
            }
            create_package_symlink(&link_target, &target_path)?;
        } else {
            return Err(ProcessPluginPackageValidationError::new(
                "package.archive_entry_unsupported",
                "Plugin package archive contains an unsupported entry type.",
                json!({
                    "path": relative_path,
                    "entry_type": format!("{:?}", entry_type),
                }),
            ));
        }
    }

    Ok(())
}

#[cfg(unix)]
fn set_archive_file_permissions(path: &Path, mode: Option<u32>) {
    use std::os::unix::fs::PermissionsExt;

    let Some(mode) = mode else {
        return;
    };
    if let Ok(metadata) = fs::metadata(path) {
        let mut permissions = metadata.permissions();
        permissions.set_mode(mode & 0o777);
        let _ = fs::set_permissions(path, permissions);
    }
}

#[cfg(not(unix))]
fn set_archive_file_permissions(_path: &Path, _mode: Option<u32>) {}

fn normalize_package_relative_path(
    path: &Path,
) -> Result<PathBuf, ProcessPluginPackageValidationError> {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => normalized.push(part),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(ProcessPluginPackageValidationError::new(
                    "package.archive_path_unsafe",
                    "Plugin package archive contains an unsafe path.",
                    json!({ "path": path }),
                ));
            }
        }
    }
    Ok(normalized)
}

fn copy_directory_contents(
    source: &Path,
    destination: &Path,
) -> Result<(), ProcessPluginPackageValidationError> {
    copy_directory_contents_with_root(source, source, destination)
}

fn copy_directory_contents_with_root(
    root: &Path,
    source: &Path,
    destination: &Path,
) -> Result<(), ProcessPluginPackageValidationError> {
    fs::create_dir_all(destination).map_err(|error| {
        ProcessPluginPackageValidationError::io(
            "create staged package directory",
            destination,
            error,
        )
    })?;
    let mut entries = fs::read_dir(source)
        .map_err(|error| {
            ProcessPluginPackageValidationError::io("read package directory", source, error)
        })?
        .filter_map(Result::ok)
        .collect::<Vec<_>>();
    entries.sort_by_key(|entry| entry.path());

    for entry in entries {
        let entry_path = entry.path();
        let target_path = destination.join(entry.file_name());
        let metadata = fs::symlink_metadata(&entry_path).map_err(|error| {
            ProcessPluginPackageValidationError::io(
                "read package entry metadata",
                &entry_path,
                error,
            )
        })?;
        let file_type = metadata.file_type();
        if file_type.is_dir() {
            copy_directory_contents_with_root(root, &entry_path, &target_path)?;
        } else if file_type.is_file() {
            fs::copy(&entry_path, &target_path).map_err(|error| {
                ProcessPluginPackageValidationError::io("copy package file", &entry_path, error)
            })?;
            fs::set_permissions(&target_path, metadata.permissions()).map_err(|error| {
                ProcessPluginPackageValidationError::io(
                    "copy package file permissions",
                    &target_path,
                    error,
                )
            })?;
        } else if file_type.is_symlink() {
            let link_target = fs::read_link(&entry_path).map_err(|error| {
                ProcessPluginPackageValidationError::io("read package symlink", &entry_path, error)
            })?;
            validate_package_symlink_target(root, &entry_path, &link_target)?;
            create_package_symlink(&link_target, &target_path)?;
        } else {
            return Err(ProcessPluginPackageValidationError::new(
                "package.entry_unsupported",
                "Plugin package contains an unsupported filesystem entry.",
                json!({ "path": entry_path }),
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn create_package_symlink(
    link_target: &Path,
    path: &Path,
) -> Result<(), ProcessPluginPackageValidationError> {
    std::os::unix::fs::symlink(link_target, path).map_err(|error| {
        ProcessPluginPackageValidationError::io("create package symlink", path, error)
    })
}

#[cfg(not(unix))]
fn create_package_symlink(
    _link_target: &Path,
    path: &Path,
) -> Result<(), ProcessPluginPackageValidationError> {
    Err(ProcessPluginPackageValidationError::new(
        "package.symlink_unsupported",
        "Plugin package symlinks are not supported on this platform.",
        json!({ "path": path }),
    ))
}

fn ensure_package_tree_safe(root: &Path) -> Result<(), ProcessPluginPackageValidationError> {
    visit_package_tree(root, root, &mut |entry_path, metadata| {
        if metadata.file_type().is_symlink() {
            let link_target = fs::read_link(entry_path).map_err(|error| {
                ProcessPluginPackageValidationError::io("read package symlink", entry_path, error)
            })?;
            validate_package_symlink_target(root, entry_path, &link_target)?;
        }
        reject_world_writable_executable(entry_path, metadata)
    })
}

fn visit_package_tree(
    root: &Path,
    current: &Path,
    visitor: &mut impl FnMut(&Path, &fs::Metadata) -> Result<(), ProcessPluginPackageValidationError>,
) -> Result<(), ProcessPluginPackageValidationError> {
    let metadata = fs::symlink_metadata(current).map_err(|error| {
        ProcessPluginPackageValidationError::io("read package entry metadata", current, error)
    })?;
    visitor(current, &metadata)?;
    if !metadata.file_type().is_dir() {
        return Ok(());
    }

    let mut entries = fs::read_dir(current)
        .map_err(|error| {
            ProcessPluginPackageValidationError::io("read package directory", current, error)
        })?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    entries.sort();
    for entry in entries {
        if !entry.starts_with(root) {
            return Err(ProcessPluginPackageValidationError::new(
                "package.path_escape",
                "Plugin package traversal escaped the package root.",
                json!({
                    "root": root,
                    "path": entry,
                }),
            ));
        }
        visit_package_tree(root, &entry, visitor)?;
    }
    Ok(())
}

fn validate_package_symlink_target(
    root: &Path,
    link_path: &Path,
    link_target: &Path,
) -> Result<(), ProcessPluginPackageValidationError> {
    if link_target.is_absolute() {
        return Err(ProcessPluginPackageValidationError::new(
            "package.symlink_escape",
            "Plugin package contains a symlink that escapes the package root.",
            json!({
                "path": link_path,
                "target": link_target,
            }),
        ));
    }

    let link_relative = if root.as_os_str().is_empty() {
        link_path.to_path_buf()
    } else {
        link_path
            .strip_prefix(root)
            .map(Path::to_path_buf)
            .unwrap_or_else(|_| link_path.to_path_buf())
    };
    let parent = link_relative.parent().unwrap_or_else(|| Path::new(""));
    let combined = parent.join(link_target);
    normalize_package_relative_path(&combined).map_err(|_| {
        ProcessPluginPackageValidationError::new(
            "package.symlink_escape",
            "Plugin package contains a symlink that escapes the package root.",
            json!({
                "path": link_path,
                "target": link_target,
            }),
        )
    })?;
    Ok(())
}

#[cfg(unix)]
fn reject_world_writable_executable(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), ProcessPluginPackageValidationError> {
    use std::os::unix::fs::PermissionsExt;

    let mode = metadata.permissions().mode();
    if metadata.file_type().is_file() && mode & 0o111 != 0 && mode & 0o002 != 0 {
        return Err(ProcessPluginPackageValidationError::new(
            "package.executable_world_writable",
            "Plugin package contains a world-writable executable file.",
            json!({
                "path": path,
                "mode": format!("{mode:o}"),
            }),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn reject_world_writable_executable(
    _path: &Path,
    _metadata: &fs::Metadata,
) -> Result<(), ProcessPluginPackageValidationError> {
    Ok(())
}

fn digest_file(path: &Path) -> Result<String, ProcessPluginPackageValidationError> {
    let mut file = File::open(path).map_err(|error| {
        ProcessPluginPackageValidationError::io("open digest input", path, error)
    })?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let bytes_read = file.read(&mut buffer).map_err(|error| {
            ProcessPluginPackageValidationError::io("read digest input", path, error)
        })?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }
    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

fn digest_directory(root: &Path) -> Result<String, ProcessPluginPackageValidationError> {
    let mut entries = Vec::new();
    collect_digest_paths(root, root, &mut entries)?;
    entries.sort();

    let mut hasher = Sha256::new();
    for path in entries {
        let relative = path.strip_prefix(root).unwrap_or(&path);
        let relative = digest_relative_path(relative);
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            ProcessPluginPackageValidationError::io("read digest entry metadata", &path, error)
        })?;
        if metadata.file_type().is_dir() {
            hasher.update(b"dir\0");
            hasher.update(relative.as_bytes());
            hasher.update(b"\0");
        } else if metadata.file_type().is_symlink() {
            let target = fs::read_link(&path).map_err(|error| {
                ProcessPluginPackageValidationError::io("read digest symlink", &path, error)
            })?;
            hasher.update(b"symlink\0");
            hasher.update(relative.as_bytes());
            hasher.update(b"\0");
            hasher.update(target.to_string_lossy().as_bytes());
            hasher.update(b"\0");
        } else if metadata.file_type().is_file() {
            hasher.update(b"file\0");
            hasher.update(relative.as_bytes());
            hasher.update(b"\0");
            let mut file = File::open(&path).map_err(|error| {
                ProcessPluginPackageValidationError::io("open digest file", &path, error)
            })?;
            let mut buffer = [0_u8; 8192];
            loop {
                let bytes_read = file.read(&mut buffer).map_err(|error| {
                    ProcessPluginPackageValidationError::io("read digest file", &path, error)
                })?;
                if bytes_read == 0 {
                    break;
                }
                hasher.update(&buffer[..bytes_read]);
            }
            hasher.update(b"\0");
        }
    }

    Ok(format!("sha256:{}", hex::encode(hasher.finalize())))
}

fn collect_digest_paths(
    root: &Path,
    current: &Path,
    entries: &mut Vec<PathBuf>,
) -> Result<(), ProcessPluginPackageValidationError> {
    let metadata = fs::symlink_metadata(current).map_err(|error| {
        ProcessPluginPackageValidationError::io("read digest entry metadata", current, error)
    })?;
    if current != root {
        entries.push(current.to_path_buf());
    }
    if !metadata.file_type().is_dir() {
        return Ok(());
    }

    let mut children = fs::read_dir(current)
        .map_err(|error| {
            ProcessPluginPackageValidationError::io("read digest directory", current, error)
        })?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .collect::<Vec<_>>();
    children.sort();
    for child in children {
        collect_digest_paths(root, &child, entries)?;
    }
    Ok(())
}

fn digest_relative_path(path: &Path) -> String {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(part) => Some(part.to_string_lossy().to_string()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

/// Package a validated plugin directory into a standalone offline distribution archive (.tar or .tar.zst).
pub fn package_process_plugin(
    source_dir: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
    format: ProcessPluginPackageFormat,
) -> Result<ProcessPluginPackageResult, ProcessPluginPackageValidationError> {
    let source_dir = source_dir.as_ref();
    let output_path = output_path.as_ref();

    let source_root = fs::canonicalize(source_dir).map_err(|error| {
        ProcessPluginPackageValidationError::io(
            "canonicalize package source directory",
            source_dir,
            error,
        )
    })?;
    if !source_root.is_dir() {
        return Err(ProcessPluginPackageValidationError::new(
            "package.source_not_directory",
            "Plugin package source is not a directory.",
            json!({ "path": redact_source_locator(source_dir) }),
        ));
    }

    ensure_package_tree_safe(&source_root)?;
    let package_root = locate_single_package_root(&source_root)?;

    // Read manifest to get plugin id and version
    let manifest_content = fs::read_to_string(package_root.join(MANIFEST_FILE_NAME)).map_err(|error| {
        ProcessPluginPackageValidationError::io(
            "read package manifest",
            &package_root.join(MANIFEST_FILE_NAME),
            error,
        )
    })?;
    let toml_value = manifest_content.parse::<toml::Value>().map_err(|error| {
        ProcessPluginPackageValidationError::new(
            "manifest.toml_invalid",
            "Plugin manifest is not valid TOML.",
            json!({ "message": error.to_string() }),
        )
    })?;
    let plugin_id = manifest_id_from_value(&toml_value).ok_or_else(|| {
        ProcessPluginPackageValidationError::new(
            "manifest.id_missing",
            "Plugin manifest must declare an id field.",
            json!({ "manifest_path": package_root.join(MANIFEST_FILE_NAME) }),
        )
    })?;
    let version = toml_value
        .get("version")
        .and_then(|v| v.as_str())
        .map(String::from)
        .unwrap_or_else(|| "0.1.0".into());

    if let Some(parent) = output_path.parent()
        && !parent.as_os_str().is_empty()
    {
        fs::create_dir_all(parent).map_err(|error| {
            ProcessPluginPackageValidationError::io(
                "create package output directory",
                parent,
                error,
            )
        })?;
    }

    // Collect all files to include in archive
    let mut file_entries = Vec::new();
    collect_package_files(&package_root, &package_root, &mut file_entries)?;
    file_entries.sort_by(|a, b| a.0.cmp(&b.0));

    let output_file = File::create(output_path).map_err(|error| {
        ProcessPluginPackageValidationError::io("create output archive file", output_path, error)
    })?;

    let mut packaged_files = Vec::new();
    let mut total_size = 0_u64;

    match format {
        ProcessPluginPackageFormat::TarZst => {
            let zstd_encoder = zstd::stream::write::Encoder::new(output_file, 10).map_err(|error| {
                ProcessPluginPackageValidationError::new(
                    "package.zstd_init_failed",
                    "Failed to initialize zstd compression encoder.",
                    json!({ "message": error.to_string() }),
                )
            })?;
            let mut tar_builder = tar::Builder::new(zstd_encoder);
            tar_builder.mode(tar::HeaderMode::Deterministic);

            for (rel_path, abs_path, is_exec) in &file_entries {
                let mut f = File::open(abs_path).map_err(|error| {
                    ProcessPluginPackageValidationError::io("read file for packaging", abs_path, error)
                })?;
                let mut bytes = Vec::new();
                f.read_to_end(&mut bytes).map_err(|error| {
                    ProcessPluginPackageValidationError::io("read file content for packaging", abs_path, error)
                })?;

                let size = bytes.len() as u64;
                total_size += size;
                packaged_files.push(ProcessPluginPackagedFile {
                    path: rel_path.clone(),
                    size,
                });

                let mut header = tar::Header::new_gnu();
                header.set_size(size);
                header.set_mode(if *is_exec { 0o755 } else { 0o644 });
                header.set_mtime(0);
                header.set_cksum();
                tar_builder
                    .append_data(&mut header, rel_path, &bytes[..])
                    .map_err(|error| {
                        ProcessPluginPackageValidationError::new(
                            "package.tar_append_failed",
                            "Failed to append file entry to tar archive.",
                            json!({ "path": rel_path, "message": error.to_string() }),
                        )
                    })?;
            }

            let zstd_encoder = tar_builder.into_inner().map_err(|error| {
                ProcessPluginPackageValidationError::new(
                    "package.tar_finish_failed",
                    "Failed to finalize tar archive stream.",
                    json!({ "message": error.to_string() }),
                )
            })?;
            zstd_encoder.finish().map_err(|error| {
                ProcessPluginPackageValidationError::new(
                    "package.zstd_finish_failed",
                    "Failed to finish zstd compressed archive.",
                    json!({ "message": error.to_string() }),
                )
            })?;
        }
        ProcessPluginPackageFormat::Tar => {
            let mut tar_builder = tar::Builder::new(output_file);
            tar_builder.mode(tar::HeaderMode::Deterministic);

            for (rel_path, abs_path, is_exec) in &file_entries {
                let mut f = File::open(abs_path).map_err(|error| {
                    ProcessPluginPackageValidationError::io("read file for packaging", abs_path, error)
                })?;
                let mut bytes = Vec::new();
                f.read_to_end(&mut bytes).map_err(|error| {
                    ProcessPluginPackageValidationError::io("read file content for packaging", abs_path, error)
                })?;

                let size = bytes.len() as u64;
                total_size += size;
                packaged_files.push(ProcessPluginPackagedFile {
                    path: rel_path.clone(),
                    size,
                });

                let mut header = tar::Header::new_gnu();
                header.set_size(size);
                header.set_mode(if *is_exec { 0o755 } else { 0o644 });
                header.set_mtime(0);
                header.set_cksum();
                tar_builder
                    .append_data(&mut header, rel_path, &bytes[..])
                    .map_err(|error| {
                        ProcessPluginPackageValidationError::new(
                            "package.tar_append_failed",
                            "Failed to append file entry to tar archive.",
                            json!({ "path": rel_path, "message": error.to_string() }),
                        )
                    })?;
            }

            tar_builder.finish().map_err(|error| {
                ProcessPluginPackageValidationError::new(
                    "package.tar_finish_failed",
                    "Failed to finalize tar archive stream.",
                    json!({ "message": error.to_string() }),
                )
            })?;
        }
    }

    let package_digest = digest_file(output_path)?;

    Ok(ProcessPluginPackageResult {
        plugin_id,
        version,
        archive_path: output_path.to_path_buf(),
        format,
        package_digest,
        total_size,
        files: packaged_files,
    })
}

fn collect_package_files(
    root: &Path,
    current: &Path,
    entries: &mut Vec<(String, PathBuf, bool)>,
) -> Result<(), ProcessPluginPackageValidationError> {
    let read_entries = fs::read_dir(current).map_err(|error| {
        ProcessPluginPackageValidationError::io("read package directory entries", current, error)
    })?;

    for entry in read_entries.filter_map(Result::ok) {
        let entry_path = entry.path();
        let metadata = fs::symlink_metadata(&entry_path).map_err(|error| {
            ProcessPluginPackageValidationError::io("read file metadata", &entry_path, error)
        })?;

        if metadata.file_type().is_dir() {
            // Ignore hidden/dot directories like .git or .voidb-install
            if !is_dot_prefixed(&entry_path) {
                let name = entry_path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                // When packaging from a workspace/repo root, ignore heavy build/output dirs
                if name != "target" && name != "dist" {
                    collect_package_files(root, &entry_path, entries)?;
                }
            }
        } else if metadata.file_type().is_file() {
            let relative = entry_path.strip_prefix(root).unwrap_or(&entry_path);
            let rel_str = digest_relative_path(relative);
            let is_exec = is_executable_metadata(&metadata);
            entries.push((rel_str, entry_path, is_exec));
        }
    }

    Ok(())
}

#[cfg(unix)]
fn is_executable_metadata(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable_metadata(_metadata: &fs::Metadata) -> bool {
    false
}

fn discover_root(root: &ProcessPluginRoot) -> Vec<ProcessPluginCandidate> {
    let entries = match fs::read_dir(&root.path) {
        Ok(entries) => entries,
        Err(_) => return Vec::new(),
    };

    let mut plugin_dirs = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .filter(|path| !is_dot_prefixed(path))
        .filter(|path| path.join(MANIFEST_FILE_NAME).is_file())
        .collect::<Vec<_>>();
    plugin_dirs.sort();

    plugin_dirs
        .into_iter()
        .map(|plugin_dir| discover_candidate(root, plugin_dir))
        .collect()
}

fn discover_candidate(root: &ProcessPluginRoot, plugin_dir: PathBuf) -> ProcessPluginCandidate {
    let manifest_path = plugin_dir.join(MANIFEST_FILE_NAME);
    let source = ProcessPluginSource {
        root: root.path.clone(),
        plugin_dir: plugin_dir.clone(),
        kind: root.kind,
        trust_level: root.trust_level(),
        precedence: root.precedence,
    };
    let fallback_id = plugin_dir_name(&plugin_dir);

    let content = match fs::read_to_string(&manifest_path) {
        Ok(content) => content,
        Err(error) => {
            return invalid_candidate(
                fallback_id,
                manifest_path,
                source,
                ProcessPluginDiagnostic::error(
                    "manifest.unreadable",
                    "Plugin manifest could not be read.",
                    json!({ "message": error.to_string() }),
                ),
            );
        }
    };

    let toml_value = match content.parse::<toml::Value>() {
        Ok(value) => value,
        Err(error) => {
            return invalid_candidate(
                fallback_id,
                manifest_path,
                source,
                ProcessPluginDiagnostic::error(
                    "manifest.toml_invalid",
                    "Plugin manifest is not valid TOML.",
                    json!({ "message": error.to_string() }),
                ),
            );
        }
    };

    let manifest_json = match serde_json::to_value(&toml_value) {
        Ok(value) => value,
        Err(error) => {
            return invalid_candidate(
                manifest_id_from_value(&toml_value).unwrap_or(fallback_id),
                manifest_path,
                source,
                ProcessPluginDiagnostic::error(
                    "manifest.json_conversion_failed",
                    "Plugin manifest could not be converted to JSON-compatible data.",
                    json!({ "message": error.to_string() }),
                ),
            );
        }
    };

    if let Err(error) = jsonschema::validate(&PLUGIN_MANIFEST_SCHEMA, &manifest_json) {
        return invalid_candidate(
            manifest_json_id(&manifest_json).unwrap_or(fallback_id),
            manifest_path,
            source,
            ProcessPluginDiagnostic::error(
                "manifest.schema_invalid",
                "Plugin manifest does not match the process-plugin schema.",
                json!({ "schema_error": error.to_string() }),
            ),
        );
    }

    let manifest = match serde_json::from_value::<ProcessPluginManifest>(manifest_json.clone()) {
        Ok(manifest) => manifest,
        Err(error) => {
            return invalid_candidate(
                manifest_json_id(&manifest_json).unwrap_or(fallback_id),
                manifest_path,
                source,
                ProcessPluginDiagnostic::error(
                    "manifest.decode_failed",
                    "Plugin manifest passed schema validation but could not be decoded.",
                    json!({ "message": error.to_string() }),
                ),
            );
        }
    };

    candidate_from_manifest(root, manifest_path, source, manifest)
}

fn candidate_from_manifest(
    root: &ProcessPluginRoot,
    manifest_path: PathBuf,
    source: ProcessPluginSource,
    manifest: ProcessPluginManifest,
) -> ProcessPluginCandidate {
    let plugin_dir = source.plugin_dir.clone();
    let mut diagnostics = Vec::new();
    let mut invalid = false;
    let mut incompatible = false;
    let mut resolved_schema_paths = BTreeMap::new();

    if !root.explicit_development && plugin_dir_name(&plugin_dir) != manifest.id {
        invalid = true;
        diagnostics.push(ProcessPluginDiagnostic::error(
            "manifest.directory_id_mismatch",
            "Plugin directory name must match manifest id outside explicit development roots.",
            json!({
                "directory_name": plugin_dir_name(&plugin_dir),
                "manifest_id": manifest.id,
            }),
        ));
    }

    validate_manifest_schema_uri(&manifest, &mut diagnostics, &mut invalid);

    if !is_supported_process_plugin_protocol_version(&manifest.protocol_version) {
        incompatible = true;
        diagnostics.push(ProcessPluginDiagnostic::error(
            "plugin.protocol_unsupported",
            "Plugin protocol version is not supported by this VoidB Core.",
            json!({
                "protocol_version": manifest.protocol_version,
                "selected_protocol_version": PROCESS_PLUGIN_PROTOCOL_VERSION,
                "supported_protocol_versions": PROCESS_PLUGIN_SUPPORTED_PROTOCOL_VERSIONS,
            }),
        ));
    }

    if manifest.runtime.transport != PROCESS_PLUGIN_TRANSPORT_STDIO_JSONRPC {
        incompatible = true;
        diagnostics.push(ProcessPluginDiagnostic::error(
            "plugin.transport_unsupported",
            "Plugin runtime transport is not supported by this VoidB Core.",
            json!({
                "transport": manifest.runtime.transport,
                "supported_transports": PROCESS_PLUGIN_SUPPORTED_TRANSPORTS,
            }),
        ));
    }

    let resolved_runtime_command =
        match resolve_runtime_command(&plugin_dir, root, &manifest.runtime.command) {
            Ok(path) => Some(path),
            Err(diagnostic) => {
                invalid = true;
                diagnostics.push(diagnostic);
                None
            }
        };

    validate_capability_semantics(&manifest, &mut diagnostics, &mut invalid);
    validate_requirements(&manifest, &mut diagnostics, &mut invalid, &mut incompatible);

    resolve_schema_ref(
        &plugin_dir,
        "connections.profile_schema",
        &manifest.connections.profile_schema,
        &mut diagnostics,
        &mut invalid,
        &mut resolved_schema_paths,
    );
    for capability in &manifest.capabilities {
        resolve_schema_ref(
            &plugin_dir,
            &format!("capabilities.{}.input_schema", capability.id),
            &capability.input_schema,
            &mut diagnostics,
            &mut invalid,
            &mut resolved_schema_paths,
        );
        resolve_schema_ref(
            &plugin_dir,
            &format!("capabilities.{}.output_schema", capability.id),
            &capability.output_schema,
            &mut diagnostics,
            &mut invalid,
            &mut resolved_schema_paths,
        );
    }

    let mut state = if invalid {
        ProcessPluginCandidateState::Invalid
    } else if incompatible {
        ProcessPluginCandidateState::Incompatible
    } else {
        ProcessPluginCandidateState::Available
    };
    if state == ProcessPluginCandidateState::Available
        && install_record_disables_candidate(&source.root, &manifest.id)
    {
        state = ProcessPluginCandidateState::Disabled;
        diagnostics.push(ProcessPluginDiagnostic::warning(
            "plugin.disabled_by_install_record",
            "Plugin is installed but disabled by its install record.",
            json!({ "plugin_id": manifest.id }),
        ));
    }

    ProcessPluginCandidate {
        id: manifest.id.clone(),
        name: Some(manifest.name.clone()),
        version: Some(manifest.version.clone()),
        protocol_version: Some(manifest.protocol_version.clone()),
        manifest_path,
        source,
        state,
        transport: Some(manifest.runtime.transport.clone()),
        capability_count: manifest.capabilities.len(),
        tui: manifest.ui.as_ref().is_some_and(|ui| ui.tui),
        diagnostics,
        manifest: Some(manifest),
        resolved_runtime_command,
        resolved_schema_paths,
    }
}

fn invalid_candidate(
    id: String,
    manifest_path: PathBuf,
    source: ProcessPluginSource,
    diagnostic: ProcessPluginDiagnostic,
) -> ProcessPluginCandidate {
    ProcessPluginCandidate {
        id,
        name: None,
        version: None,
        protocol_version: None,
        manifest_path,
        source,
        state: ProcessPluginCandidateState::Invalid,
        transport: None,
        capability_count: 0,
        tui: false,
        diagnostics: vec![diagnostic],
        manifest: None,
        resolved_runtime_command: None,
        resolved_schema_paths: BTreeMap::new(),
    }
}

fn validate_manifest_schema_uri(
    manifest: &ProcessPluginManifest,
    diagnostics: &mut Vec<ProcessPluginDiagnostic>,
    invalid: &mut bool,
) {
    let Some(schema_uri) = manifest.schema.as_ref() else {
        return;
    };

    if schema_uri != PROCESS_PLUGIN_MANIFEST_SCHEMA_URI {
        *invalid = true;
        diagnostics.push(ProcessPluginDiagnostic::error(
            "manifest.schema_uri_unsupported",
            "Manifest $schema must reference the supported VoidB process-plugin schema.",
            json!({
                "schema_uri": schema_uri,
                "supported_schema_uri": PROCESS_PLUGIN_MANIFEST_SCHEMA_URI,
            }),
        ));
    }
}

fn validate_capability_semantics(
    manifest: &ProcessPluginManifest,
    diagnostics: &mut Vec<ProcessPluginDiagnostic>,
    invalid: &mut bool,
) {
    let mut capability_ids = HashSet::new();
    let declared_secret_classes = manifest
        .connections
        .secret_classes
        .iter()
        .cloned()
        .collect::<HashSet<_>>();

    for capability in &manifest.capabilities {
        let declared_risk = capability
            .risk
            .unwrap_or_else(|| CapabilityRiskLevel::from_destructive(capability.destructive));
        let effective_risk =
            if capability.destructive && declared_risk == CapabilityRiskLevel::ReadOnly {
                CapabilityRiskLevel::Destructive
            } else {
                declared_risk
            };

        if !capability_ids.insert(capability.id.clone()) {
            *invalid = true;
            diagnostics.push(ProcessPluginDiagnostic::error(
                "manifest.capability_id_duplicate",
                "Capability IDs must be unique within one plugin manifest.",
                json!({ "capability_id": capability.id }),
            ));
        }

        for secret_class in &capability.required_secret_classes {
            if !declared_secret_classes.contains(secret_class) {
                *invalid = true;
                diagnostics.push(ProcessPluginDiagnostic::error(
                    "manifest.required_secret_class_undeclared",
                    "Capability requires a secret class not declared by the plugin connection section.",
                    json!({
                        "capability_id": capability.id,
                        "secret_class": secret_class,
                    }),
                ));
            }
        }

        if !capability.connection_required && !capability.required_secret_classes.is_empty() {
            *invalid = true;
            diagnostics.push(ProcessPluginDiagnostic::error(
                "manifest.stateless_capability_requires_secrets",
                "Capabilities that do not require a connection profile cannot request profile secret classes.",
                json!({
                    "capability_id": capability.id,
                    "required_secret_classes": &capability.required_secret_classes,
                }),
            ));
        }

        if capability.destructive && capability.permissions.is_empty() {
            *invalid = true;
            diagnostics.push(ProcessPluginDiagnostic::error(
                "manifest.destructive_capability_missing_permission",
                "Destructive capabilities must declare at least one permission string.",
                json!({ "capability_id": capability.id }),
            ));
        } else if effective_risk.has_target_side_effects() && capability.permissions.is_empty() {
            *invalid = true;
            diagnostics.push(ProcessPluginDiagnostic::error(
                "manifest.side_effect_capability_missing_permission",
                "Side-effecting capabilities must declare at least one permission string.",
                json!({
                    "capability_id": capability.id,
                    "risk": effective_risk,
                }),
            ));
        }

        if capability.destructive && capability.risk == Some(CapabilityRiskLevel::ReadOnly) {
            diagnostics.push(ProcessPluginDiagnostic::warning(
                "manifest.destructive_capability_read_only_risk",
                "Destructive compatibility flags override read-only risk during policy evaluation.",
                json!({
                    "capability_id": capability.id,
                    "effective_risk": effective_risk,
                }),
            ));
        }

        if capability.supports_dry_run && !effective_risk.has_target_side_effects() {
            diagnostics.push(ProcessPluginDiagnostic::warning(
                "manifest.dry_run_on_non_destructive_capability",
                "Dry-run support is meaningful only for side-effecting capabilities.",
                json!({ "capability_id": capability.id }),
            ));
        }
    }

    if let Some(entrypoint) = manifest
        .ui
        .as_ref()
        .and_then(|ui| ui.entrypoint_capability.as_ref())
        && !capability_ids.contains(entrypoint)
    {
        *invalid = true;
        diagnostics.push(ProcessPluginDiagnostic::error(
            "manifest.ui_entrypoint_missing",
            "UI entrypoint capability does not exist in the plugin capability catalog.",
            json!({ "entrypoint_capability": entrypoint }),
        ));
    }
}

fn validate_requirements(
    manifest: &ProcessPluginManifest,
    diagnostics: &mut Vec<ProcessPluginDiagnostic>,
    invalid: &mut bool,
    incompatible: &mut bool,
) {
    let Some(requirements) = &manifest.requirements else {
        return;
    };

    if let Some(platforms) = &requirements.platforms {
        let current = current_platform();
        if !platforms.iter().any(|platform| platform == current) {
            *incompatible = true;
            diagnostics.push(ProcessPluginDiagnostic::error(
                "plugin.platform_incompatible",
                "Plugin does not support the current platform.",
                json!({
                    "current_platform": current,
                    "supported_platforms": platforms,
                }),
            ));
        }
    }

    if let Some(requirement) = &requirements.voidb_core {
        let version_req = match VersionReq::parse(requirement) {
            Ok(version_req) => version_req,
            Err(error) => {
                *invalid = true;
                diagnostics.push(ProcessPluginDiagnostic::error(
                    "manifest.core_requirement_invalid",
                    "Plugin VoidB Core version requirement is not valid semver requirement syntax.",
                    json!({ "message": error.to_string() }),
                ));
                return;
            }
        };
        let core_version =
            Version::parse(env!("CARGO_PKG_VERSION")).expect("crate version is semver-compatible");
        if !core_version_matches_requirement(&version_req, &core_version) {
            *incompatible = true;
            diagnostics.push(ProcessPluginDiagnostic::error(
                "plugin.core_incompatible",
                "Plugin requires a VoidB Core version incompatible with this build.",
                json!({
                    "current_core_version": core_version.to_string(),
                    "required_core_version": requirement,
                }),
            ));
        }
    }
}

fn core_version_matches_requirement(requirement: &VersionReq, core_version: &Version) -> bool {
    if requirement.matches(core_version) {
        return true;
    }

    if core_version.pre.is_empty() {
        return false;
    }

    let mut stable_equivalent = core_version.clone();
    stable_equivalent.pre = Prerelease::EMPTY;
    if !requirement.matches(&stable_equivalent) {
        return false;
    }

    let core_base = (
        stable_equivalent.major,
        stable_equivalent.minor,
        stable_equivalent.patch,
    );

    requirement.comparators.iter().all(|comparator| {
        if !comparator.pre.is_empty() {
            return true;
        }

        let comparator_base = (
            comparator.major,
            comparator.minor.unwrap_or(0),
            comparator.patch.unwrap_or(0),
        );

        match comparator.op {
            Op::Exact | Op::Greater | Op::GreaterEq | Op::Tilde | Op::Caret => {
                comparator_base < core_base
            }
            Op::Less | Op::LessEq | Op::Wildcard => true,
            _ => true,
        }
    })
}

fn resolve_runtime_command(
    plugin_dir: &Path,
    root: &ProcessPluginRoot,
    command: &str,
) -> Result<PathBuf, ProcessPluginDiagnostic> {
    if command_has_path_separator(command) {
        let command_path = Path::new(command);
        let resolved = if command_path.is_absolute() {
            command_path.to_path_buf()
        } else {
            resolve_plugin_relative_path(plugin_dir, command).map_err(|message| {
                ProcessPluginDiagnostic::error(
                    "manifest.runtime_command_path_invalid",
                    "Runtime command path is not a safe plugin-relative path.",
                    json!({ "message": message }),
                )
            })?
        };
        return ensure_executable_file(
            resolved,
            "manifest.runtime_command_missing",
            "Runtime command path does not point to an executable file.",
        );
    }

    let bin_dir = plugin_dir.join("bin");
    let package_local = bin_dir.join(command);
    if is_executable_file(&package_local) {
        return Ok(package_local);
    }

    #[cfg(windows)]
    {
        if !command.ends_with(".exe") {
            let package_local_exe = bin_dir.join(format!("{command}.exe"));
            if is_executable_file(&package_local_exe) {
                return Ok(package_local_exe);
            }
        }
    }

    if root.explicit_development {
        if let Some(path) = find_command_in_path(command) {
            return Ok(path);
        }
        #[cfg(windows)]
        {
            if !command.ends_with(".exe")
                && let Some(path) = find_command_in_path(&format!("{command}.exe"))
            {
                return Ok(path);
            }
        }
    }

    Err(ProcessPluginDiagnostic::error(
        "manifest.runtime_command_unresolved",
        "Runtime command could not be resolved from the plugin package. Only explicit development roots may fall back to PATH.",
        json!({
            "command": command,
            "trust_level": root.trust_level(),
        }),
    ))
}

fn ensure_executable_file(
    path: PathBuf,
    code: &str,
    message: &str,
) -> Result<PathBuf, ProcessPluginDiagnostic> {
    if is_executable_file(&path) {
        return Ok(path);
    }

    #[cfg(windows)]
    {
        if !path.ends_with(".exe") {
            let path_exe = path.with_extension("exe");
            if is_executable_file(&path_exe) {
                return Ok(path_exe);
            }
        }
    }

    Err(ProcessPluginDiagnostic::error(
        code,
        message,
        json!({ "path": path }),
    ))
}

fn resolve_schema_ref(
    plugin_dir: &Path,
    label: &str,
    schema_ref: &str,
    diagnostics: &mut Vec<ProcessPluginDiagnostic>,
    invalid: &mut bool,
    resolved_schema_paths: &mut BTreeMap<String, PathBuf>,
) {
    if let Some(scheme) = uri_scheme(schema_ref) {
        if matches!(scheme, "http" | "https") {
            diagnostics.push(ProcessPluginDiagnostic::warning(
                "manifest.schema_uri_not_locally_validated",
                "Schema URI references are accepted but not fetched during local discovery.",
                json!({ "field": label, "scheme": scheme }),
            ));
        } else {
            *invalid = true;
            diagnostics.push(ProcessPluginDiagnostic::error(
                "manifest.schema_uri_scheme_unsupported",
                "Schema URI references must use http or https so local discovery never reads arbitrary URI schemes.",
                json!({ "field": label, "scheme": scheme }),
            ));
        }
        return;
    }

    if Path::new(schema_ref).is_absolute() {
        *invalid = true;
        diagnostics.push(ProcessPluginDiagnostic::error(
            "manifest.schema_ref_absolute",
            "Schema references must be plugin-relative paths or URIs.",
            json!({ "field": label }),
        ));
        return;
    }

    let schema_path = match resolve_plugin_relative_path(plugin_dir, schema_ref) {
        Ok(path) => path,
        Err(message) => {
            *invalid = true;
            diagnostics.push(ProcessPluginDiagnostic::error(
                "manifest.schema_ref_invalid",
                "Schema reference is not a safe plugin-relative path.",
                json!({ "field": label, "message": message }),
            ));
            return;
        }
    };

    let content = match fs::read_to_string(&schema_path) {
        Ok(content) => content,
        Err(error) => {
            *invalid = true;
            diagnostics.push(ProcessPluginDiagnostic::error(
                "manifest.schema_unreadable",
                "Referenced schema could not be read.",
                json!({ "field": label, "message": error.to_string() }),
            ));
            return;
        }
    };

    let schema_json: Value = match serde_json::from_str(&content) {
        Ok(value) => value,
        Err(error) => {
            *invalid = true;
            diagnostics.push(ProcessPluginDiagnostic::error(
                "manifest.schema_json_invalid",
                "Referenced schema is not valid JSON.",
                json!({ "field": label, "message": error.to_string() }),
            ));
            return;
        }
    };

    if let Err(error) = jsonschema::validator_for(&schema_json) {
        *invalid = true;
        diagnostics.push(ProcessPluginDiagnostic::error(
            "manifest.schema_invalid",
            "Referenced schema is not a valid JSON Schema document.",
            json!({ "field": label, "message": error.to_string() }),
        ));
        return;
    }

    resolved_schema_paths.insert(label.into(), schema_path);
}

fn apply_shadowing(candidates: &mut [ProcessPluginCandidate]) {
    let mut available_by_id = HashMap::<String, usize>::new();
    let mut order = (0..candidates.len()).collect::<Vec<_>>();
    order.sort_by(|left, right| {
        candidates[*left]
            .source
            .precedence
            .cmp(&candidates[*right].source.precedence)
            .then_with(|| {
                candidates[*left]
                    .manifest_path
                    .cmp(&candidates[*right].manifest_path)
            })
    });

    for index in order {
        if candidates[index].state != ProcessPluginCandidateState::Available {
            continue;
        }

        if let Some(winner_index) = available_by_id.get(&candidates[index].id).copied() {
            candidates[index].state = ProcessPluginCandidateState::Shadowed;
            candidates[index].diagnostics.push(ProcessPluginDiagnostic::warning(
                "plugin.shadowed_by_higher_precedence_candidate",
                "A higher-precedence available plugin candidate already provides this plugin id.",
                json!({
                    "winner_manifest_path": candidates[winner_index].manifest_path,
                    "winner_root": candidates[winner_index].source.root,
                }),
            ));
        } else {
            available_by_id.insert(candidates[index].id.clone(), index);
        }
    }
}

pub fn current_platform() -> &'static str {
    if cfg!(target_os = "macos") {
        "darwin"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(windows) {
        "windows"
    } else {
        "unknown"
    }
}

fn resolve_plugin_relative_path(plugin_dir: &Path, relative: &str) -> Result<PathBuf, String> {
    let path = Path::new(relative);
    if path.is_absolute() {
        return Err("absolute paths are not plugin-relative".into());
    }
    if path
        .components()
        .any(|component| matches!(component, Component::ParentDir))
    {
        return Err("parent directory components are not allowed".into());
    }
    Ok(plugin_dir.join(path))
}

fn uri_scheme(value: &str) -> Option<&str> {
    let (scheme, _) = value.split_once("://")?;
    if scheme.is_empty()
        || !scheme
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'))
    {
        return None;
    }
    Some(scheme)
}

fn command_has_path_separator(command: &str) -> bool {
    command.contains('/') || command.contains('\\')
}

fn find_command_in_path(command: &str) -> Option<PathBuf> {
    let path_var = std::env::var_os("PATH")?;
    std::env::split_paths(&path_var)
        .map(|path| path.join(command))
        .find(|path| is_executable_file(path))
}

#[cfg(unix)]
fn is_executable_file(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;

    let Ok(metadata) = fs::metadata(path) else {
        return false;
    };
    metadata.is_file() && metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable_file(path: &Path) -> bool {
    path.is_file()
}

fn is_dot_prefixed(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with('.'))
}

fn plugin_dir_name(plugin_dir: &Path) -> String {
    plugin_dir
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("unknown")
        .to_string()
}

fn manifest_id_from_value(value: &toml::Value) -> Option<String> {
    value
        .get("id")
        .and_then(toml::Value::as_str)
        .map(str::to_string)
}

fn manifest_json_id(value: &Value) -> Option<String> {
    value.get("id").and_then(Value::as_str).map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn collects_roots_in_documented_order_without_current_directory() {
        let env_roots = std::env::join_paths(["/dev/a", "/dev/b"]).expect("join env roots");
        let roots = process_plugin_roots_from_parts(
            Some(env_roots.as_os_str()),
            Some(PathBuf::from("/user/plugins")),
            vec![PathBuf::from("/system/a"), PathBuf::from("/system/b")],
            vec![PathBuf::from("/bundled")],
        );

        let paths = roots
            .iter()
            .map(|root| root.path.as_path())
            .collect::<Vec<_>>();
        assert_eq!(
            paths,
            vec![
                Path::new("/dev/a"),
                Path::new("/dev/b"),
                Path::new("/user/plugins"),
                Path::new("/system/a"),
                Path::new("/system/b"),
                Path::new("/bundled"),
            ]
        );
        assert_eq!(roots[0].kind, ProcessPluginRootKind::EnvPath);
        assert!(roots[0].explicit_development);
        assert!(!paths.contains(&std::env::current_dir().expect("cwd").as_path()));

        let trust_levels = roots
            .iter()
            .map(ProcessPluginRoot::trust_level)
            .collect::<Vec<_>>();
        assert_eq!(
            trust_levels,
            vec![
                ProcessPluginTrustLevel::ExplicitDevelopment,
                ProcessPluginTrustLevel::ExplicitDevelopment,
                ProcessPluginTrustLevel::UserInstalled,
                ProcessPluginTrustLevel::AdministratorManaged,
                ProcessPluginTrustLevel::AdministratorManaged,
                ProcessPluginTrustLevel::Bundled,
            ]
        );
    }

    #[test]
    fn default_roots_include_user_config_and_data_plugin_directories() {
        let default_roots = default_process_plugin_roots();
        let user_roots = default_user_plugin_roots();
        for user_root in user_roots {
            assert!(
                default_roots.iter().any(|r| r.path == user_root && r.kind == ProcessPluginRootKind::User),
                "default roots should include user root: {:?}",
                user_root
            );
        }
    }

    #[test]
    fn discovers_valid_plugin_manifest() {
        let temp = TempDir::new("valid");
        write_valid_plugin(temp.path(), "mysql", "mysql", "1", &[current_platform()]);

        let discovery = discover_process_plugins_from_roots(vec![ProcessPluginRoot::new(
            temp.path(),
            ProcessPluginRootKind::User,
            0,
        )]);

        assert_eq!(discovery.candidates.len(), 1);
        let candidate = &discovery.candidates[0];
        assert_eq!(candidate.id, "mysql");
        assert_eq!(candidate.state, ProcessPluginCandidateState::Available);
        assert_eq!(
            candidate.source.trust_level,
            ProcessPluginTrustLevel::UserInstalled
        );
        assert_eq!(candidate.capability_count, 2);
        assert!(candidate.resolved_runtime_command.is_some());
        assert_eq!(candidate.resolved_schema_paths.len(), 5);
        let manifest = candidate.manifest.as_ref().expect("decoded manifest");
        assert!(manifest.capabilities.iter().all(|capability| {
            capability.execution_mode == CapabilityExecutionMode::Stateless
                && capability.session_handoff.is_none()
        }));
    }

    #[test]
    fn manifest_schema_accepts_session_execution_metadata() {
        let temp = TempDir::new("session-execution-metadata");
        write_valid_plugin(temp.path(), "mysql", "mysql", "1", &[current_platform()]);
        let manifest_path = temp.path().join("mysql").join(MANIFEST_FILE_NAME);
        let manifest_toml: toml::Value = toml::from_str(
            &fs::read_to_string(manifest_path).expect("read generated manifest"),
        )
        .expect("parse generated manifest");
        let mut manifest_json =
            serde_json::to_value(manifest_toml).expect("convert manifest to JSON");
        let capability = manifest_json["capabilities"][0]
            .as_object_mut()
            .expect("capability object");
        capability.insert("execution_mode".into(), json!("both"));
        capability.insert(
            "session_handoff".into(),
            json!({
                "purpose": { "kind": "database_query" },
                "capabilities": ["mysql.get"]
            }),
        );

        jsonschema::validate(&PLUGIN_MANIFEST_SCHEMA, &manifest_json)
            .expect("session execution metadata should match the manifest schema");
    }

    #[test]
    fn prerelease_core_matches_older_stable_process_plugin_requirement() {
        let requirement = VersionReq::parse(">=0.1.0").expect("version requirement");
        let core_version = Version::parse("0.3.0-rc.1").expect("core version");

        assert!(core_version_matches_requirement(
            &requirement,
            &core_version
        ));
    }

    #[test]
    fn prerelease_core_does_not_match_same_final_process_plugin_requirement() {
        let requirement = VersionReq::parse(">=0.3.0").expect("version requirement");
        let core_version = Version::parse("0.3.0-rc.1").expect("core version");

        assert!(!core_version_matches_requirement(
            &requirement,
            &core_version
        ));
    }

    #[test]
    fn invalid_manifest_is_isolated_and_does_not_shadow_lower_available_candidate() {
        let high = TempDir::new("invalid-high");
        let low = TempDir::new("valid-low");
        write_invalid_manifest(high.path(), "redis", "id = \"redis\"\n");
        write_valid_plugin(low.path(), "redis", "redis", "1", &[current_platform()]);

        let discovery = discover_process_plugins_from_roots(vec![
            ProcessPluginRoot::new(high.path(), ProcessPluginRootKind::User, 0),
            ProcessPluginRoot::new(low.path(), ProcessPluginRootKind::System, 1),
        ]);

        let redis = discovery.candidates_for_id("redis");
        assert_eq!(redis.len(), 2);
        assert!(redis.iter().any(|candidate| {
            candidate.state == ProcessPluginCandidateState::Invalid
                && candidate.diagnostics[0].code == "manifest.schema_invalid"
        }));
        assert!(
            redis
                .iter()
                .any(|candidate| candidate.state == ProcessPluginCandidateState::Available)
        );
    }

    #[test]
    fn valid_lower_precedence_candidate_is_shadowed() {
        let high = TempDir::new("shadow-high");
        let low = TempDir::new("shadow-low");
        write_valid_plugin(high.path(), "mysql", "mysql", "1", &[current_platform()]);
        write_valid_plugin(low.path(), "mysql", "mysql", "1", &[current_platform()]);

        let discovery = discover_process_plugins_from_roots(vec![
            ProcessPluginRoot::new(high.path(), ProcessPluginRootKind::User, 0),
            ProcessPluginRoot::new(low.path(), ProcessPluginRootKind::System, 1),
        ]);

        let mysql = discovery.candidates_for_id("mysql");
        assert_eq!(mysql.len(), 2);
        assert!(
            mysql
                .iter()
                .any(|candidate| candidate.state == ProcessPluginCandidateState::Available)
        );
        assert!(mysql.iter().any(|candidate| {
            candidate.state == ProcessPluginCandidateState::Shadowed
                && candidate.diagnostics.iter().any(|diagnostic| {
                    diagnostic.code == "plugin.shadowed_by_higher_precedence_candidate"
                })
        }));
    }

    #[test]
    fn dot_prefixed_directories_are_ignored() {
        let temp = TempDir::new("dot-prefixed");
        write_valid_plugin(
            temp.path(),
            ".manager",
            "manager",
            "1",
            &[current_platform()],
        );
        write_valid_plugin(
            temp.path(),
            "visible",
            "visible",
            "1",
            &[current_platform()],
        );

        let discovery = discover_process_plugins_from_roots(vec![ProcessPluginRoot::new(
            temp.path(),
            ProcessPluginRootKind::User,
            0,
        )]);

        assert_eq!(discovery.candidates.len(), 1);
        assert_eq!(discovery.candidates[0].id, "visible");
    }

    #[test]
    fn disabled_install_record_marks_candidate_disabled() {
        let temp = TempDir::new("disabled-record");
        write_valid_plugin(temp.path(), "redis", "redis", "1", &[current_platform()]);
        let record = ProcessPluginInstallRecord {
            schema_version: PROCESS_PLUGIN_INSTALL_RECORD_SCHEMA_VERSION,
            plugin_id: "redis".into(),
            installed_version: "0.1.0".into(),
            manifest_digest: "sha256:manifest".into(),
            package_digest: "sha256:package".into(),
            source: ProcessPluginInstallSourceRecord {
                kind: ProcessPluginPackageSourceKind::LocalDirectory,
                locator: "/tmp/redis".into(),
                redacted_locator: "/tmp/redis".into(),
            },
            install_root: temp.path().to_path_buf(),
            installed_at: Utc::now(),
            installed_by: "test".into(),
            enabled: false,
            previous_version: None,
            compatibility: ProcessPluginInstallCompatibilityRecord {
                state: ProcessPluginCandidateState::Available,
                core_version: env!("CARGO_PKG_VERSION").into(),
                protocol_version: Some("1".into()),
                diagnostics: Vec::new(),
            },
        };
        write_process_plugin_install_record(&record).expect("write install record");

        let discovery = discover_process_plugins_from_roots(vec![ProcessPluginRoot::new(
            temp.path(),
            ProcessPluginRootKind::User,
            0,
        )]);

        assert_eq!(discovery.candidates.len(), 1);
        assert_eq!(
            discovery.candidates[0].state,
            ProcessPluginCandidateState::Disabled
        );
        assert!(
            discovery.candidates[0]
                .diagnostics
                .iter()
                .any(|diagnostic| {
                    diagnostic.code == "plugin.disabled_by_install_record"
                        && diagnostic.severity == ProcessPluginDiagnosticSeverity::Warning
                })
        );
    }

    #[test]
    fn incompatible_protocol_is_reported_as_incompatible() {
        let temp = TempDir::new("incompatible");
        write_valid_plugin(temp.path(), "redis", "redis", "2", &[current_platform()]);

        let discovery = discover_process_plugins_from_roots(vec![ProcessPluginRoot::new(
            temp.path(),
            ProcessPluginRootKind::User,
            0,
        )]);

        let candidate = &discovery.candidates[0];
        assert_eq!(candidate.state, ProcessPluginCandidateState::Incompatible);
        assert!(
            candidate
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "plugin.protocol_unsupported")
        );
    }

    #[test]
    fn unsupported_minor_protocol_is_reported_as_incompatible() {
        let temp = TempDir::new("minor-protocol");
        write_valid_plugin(temp.path(), "redis", "redis", "1.2", &[current_platform()]);

        let discovery = discover_process_plugins_from_roots(vec![ProcessPluginRoot::new(
            temp.path(),
            ProcessPluginRootKind::User,
            0,
        )]);

        let candidate = &discovery.candidates[0];
        assert_eq!(candidate.state, ProcessPluginCandidateState::Incompatible);
        assert!(
            candidate
                .diagnostics
                .iter()
                .any(
                    |diagnostic| diagnostic.code == "plugin.protocol_unsupported"
                        && diagnostic.details["selected_protocol_version"] == "1.1"
                )
        );
    }

    #[test]
    fn unsupported_transport_is_reported_as_incompatible() {
        let temp = TempDir::new("unsupported-transport");
        write_valid_plugin(temp.path(), "redis", "redis", "1", &[current_platform()]);
        replace_manifest_fragment(
            temp.path(),
            "redis",
            r#"transport = "stdio-jsonrpc""#,
            r#"transport = "stdio-websocket""#,
        );

        let discovery = discover_process_plugins_from_roots(vec![ProcessPluginRoot::new(
            temp.path(),
            ProcessPluginRootKind::User,
            0,
        )]);

        let candidate = &discovery.candidates[0];
        assert_eq!(candidate.state, ProcessPluginCandidateState::Incompatible);
        assert!(
            candidate
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "plugin.transport_unsupported")
        );
    }

    #[test]
    fn unsupported_manifest_schema_uri_is_invalid() {
        let temp = TempDir::new("manifest-schema-uri");
        write_valid_plugin(temp.path(), "redis", "redis", "1", &[current_platform()]);
        prepend_manifest(
            temp.path(),
            "redis",
            r#""$schema" = "https://example.invalid/plugin-manifest.schema.json""#,
        );

        let discovery = discover_process_plugins_from_roots(vec![ProcessPluginRoot::new(
            temp.path(),
            ProcessPluginRootKind::User,
            0,
        )]);

        let candidate = &discovery.candidates[0];
        assert_eq!(candidate.state, ProcessPluginCandidateState::Invalid);
        assert!(
            candidate
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "manifest.schema_uri_unsupported")
        );
    }

    #[test]
    fn schema_ref_uri_scheme_must_be_http_or_https() {
        let temp = TempDir::new("schema-uri-scheme");
        write_valid_plugin(temp.path(), "redis", "redis", "1", &[current_platform()]);
        replace_manifest_fragment(
            temp.path(),
            "redis",
            r#"profile_schema = "schemas/profile.schema.json""#,
            r#"profile_schema = "file:///etc/passwd""#,
        );

        let discovery = discover_process_plugins_from_roots(vec![ProcessPluginRoot::new(
            temp.path(),
            ProcessPluginRootKind::User,
            0,
        )]);

        let candidate = &discovery.candidates[0];
        assert_eq!(candidate.state, ProcessPluginCandidateState::Invalid);
        assert!(candidate.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "manifest.schema_uri_scheme_unsupported"
                && diagnostic.details["scheme"] == "file"
        }));
    }

    #[test]
    fn non_development_roots_require_package_local_bare_runtime_commands() {
        let temp = TempDir::new("runtime-command-root");
        write_valid_plugin(temp.path(), "redis", "redis", "1", &[current_platform()]);
        fs::remove_file(
            temp.path()
                .join("redis")
                .join("bin")
                .join("voidb-plugin-test"),
        )
        .expect("remove package-local command");

        let discovery = discover_process_plugins_from_roots(vec![ProcessPluginRoot::new(
            temp.path(),
            ProcessPluginRootKind::User,
            0,
        )]);

        let candidate = &discovery.candidates[0];
        assert_eq!(candidate.state, ProcessPluginCandidateState::Invalid);
        assert!(candidate.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "manifest.runtime_command_unresolved"
                && diagnostic.details["trust_level"] == "user_installed"
        }));
    }

    #[test]
    fn destructive_capabilities_must_declare_permissions() {
        let temp = TempDir::new("destructive-permissions");
        write_valid_plugin(temp.path(), "redis", "redis", "1", &[current_platform()]);
        replace_manifest_fragment(
            temp.path(),
            "redis",
            r#"permissions = ["connection.read"]
destructive = true"#,
            r#"permissions = []
destructive = true"#,
        );

        let discovery = discover_process_plugins_from_roots(vec![ProcessPluginRoot::new(
            temp.path(),
            ProcessPluginRootKind::User,
            0,
        )]);

        let candidate = &discovery.candidates[0];
        assert_eq!(candidate.state, ProcessPluginCandidateState::Invalid);
        assert!(candidate.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "manifest.destructive_capability_missing_permission"
        }));
    }

    #[test]
    fn side_effecting_risk_capabilities_must_declare_permissions() {
        let temp = TempDir::new("side-effect-permissions");
        write_valid_plugin(temp.path(), "redis", "redis", "1", &[current_platform()]);
        replace_manifest_fragment(
            temp.path(),
            "redis",
            r#"permissions = ["connection.read"]
destructive = true"#,
            r#"permissions = []
risk = "mutating"
destructive = false"#,
        );

        let discovery = discover_process_plugins_from_roots(vec![ProcessPluginRoot::new(
            temp.path(),
            ProcessPluginRootKind::User,
            0,
        )]);

        let candidate = &discovery.candidates[0];
        assert_eq!(candidate.state, ProcessPluginCandidateState::Invalid);
        assert!(candidate.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "manifest.side_effect_capability_missing_permission"
                && diagnostic.details["risk"] == "mutating"
        }));
    }

    #[test]
    fn destructive_read_only_risk_mismatch_is_reported() {
        let temp = TempDir::new("destructive-read-only-risk");
        write_valid_plugin(temp.path(), "redis", "redis", "1", &[current_platform()]);
        replace_manifest_fragment(
            temp.path(),
            "redis",
            r#"permissions = ["connection.read"]
destructive = true"#,
            r#"permissions = ["connection.read"]
risk = "read_only"
destructive = true"#,
        );

        let discovery = discover_process_plugins_from_roots(vec![ProcessPluginRoot::new(
            temp.path(),
            ProcessPluginRootKind::User,
            0,
        )]);

        let candidate = &discovery.candidates[0];
        assert_eq!(candidate.state, ProcessPluginCandidateState::Available);
        assert!(candidate.diagnostics.iter().any(|diagnostic| {
            diagnostic.code == "manifest.destructive_capability_read_only_risk"
                && diagnostic.severity == ProcessPluginDiagnosticSeverity::Warning
                && diagnostic.details["effective_risk"] == "destructive"
        }));
    }

    #[test]
    fn missing_referenced_schema_is_invalid() {
        let temp = TempDir::new("missing-schema");
        write_valid_plugin(temp.path(), "redis", "redis", "1", &[current_platform()]);
        fs::remove_file(
            temp.path()
                .join("redis")
                .join("schemas")
                .join("get-output.schema.json"),
        )
        .expect("remove schema");

        let discovery = discover_process_plugins_from_roots(vec![ProcessPluginRoot::new(
            temp.path(),
            ProcessPluginRootKind::User,
            0,
        )]);

        let candidate = &discovery.candidates[0];
        assert_eq!(candidate.state, ProcessPluginCandidateState::Invalid);
        assert!(
            candidate
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "manifest.schema_unreadable")
        );
    }

    #[test]
    fn environment_roots_allow_directory_id_mismatch_for_development() {
        let temp = TempDir::new("dev-mismatch");
        write_valid_plugin(
            temp.path(),
            "workspace-plugin",
            "redis",
            "1",
            &[current_platform()],
        );

        let discovery = discover_process_plugins_from_roots(vec![ProcessPluginRoot::new(
            temp.path(),
            ProcessPluginRootKind::EnvPath,
            0,
        )]);

        assert_eq!(discovery.candidates[0].id, "redis");
        assert_eq!(
            discovery.candidates[0].state,
            ProcessPluginCandidateState::Available
        );
    }

    #[test]
    fn validates_directory_package_and_builds_install_record() {
        let source = TempDir::new("package-dir");
        let install_root = TempDir::new("install-root");
        write_valid_plugin(source.path(), "redis", "redis", "1", &[current_platform()]);

        let validation = validate_process_plugin_package(
            ProcessPluginPackageSource::local_directory(source.path()),
            install_root.path(),
        )
        .expect("validate directory package");

        assert_eq!(validation.plugin_id, "redis");
        assert_eq!(validation.version, "0.1.0");
        assert_eq!(
            validation.candidate.state,
            ProcessPluginCandidateState::Available
        );
        assert!(validation.manifest_digest.starts_with("sha256:"));
        assert!(validation.package_digest.starts_with("sha256:"));
        assert_eq!(validation.install_record.plugin_id, "redis");
        assert_eq!(validation.install_record.installed_version, "0.1.0");
        assert!(validation.install_record.enabled);
        assert_eq!(
            validation.install_record.compatibility.state,
            ProcessPluginCandidateState::Available
        );
        assert!(validation.staged_plugin_dir.exists());
        assert!(!install_root.path().join("redis").exists());

        let record_path = write_process_plugin_install_record(&validation.install_record)
            .expect("write install record");
        let record = read_process_plugin_install_record(&record_path).expect("read install record");
        assert_eq!(record.plugin_id, "redis");
        assert_eq!(record.manifest_digest, validation.manifest_digest);
        cleanup_process_plugin_package_staging(&validation.staging_root).expect("cleanup staging");
    }

    #[test]
    fn validates_root_manifest_package_under_manifest_id() {
        let source = TempDir::new("root-package");
        let install_root = TempDir::new("root-install");
        write_valid_plugin(
            source.path(),
            "workspace-plugin",
            "renamed",
            "1",
            &[current_platform()],
        );

        let validation = validate_process_plugin_package(
            ProcessPluginPackageSource::local_directory(source.path().join("workspace-plugin")),
            install_root.path(),
        )
        .expect("validate root package");

        assert_eq!(validation.plugin_id, "renamed");
        assert_eq!(
            validation
                .staged_plugin_dir
                .file_name()
                .and_then(|name| name.to_str()),
            Some("renamed")
        );
        assert_eq!(
            validation.candidate.state,
            ProcessPluginCandidateState::Available
        );
        cleanup_process_plugin_package_staging(&validation.staging_root).expect("cleanup staging");
    }

    #[test]
    fn validates_tar_archive_package() {
        let source = TempDir::new("archive-source");
        let install_root = TempDir::new("archive-install");
        let archive_dir = TempDir::new("archive-file");
        let archive_path = archive_dir.path().join("redis-0.1.0.voidb-plugin.tar");
        write_valid_plugin(source.path(), "redis", "redis", "1", &[current_platform()]);
        write_tar_archive(source.path(), &archive_path);

        let validation = validate_process_plugin_package(
            ProcessPluginPackageSource::local_archive(&archive_path),
            install_root.path(),
        )
        .expect("validate archive package");

        assert_eq!(validation.plugin_id, "redis");
        assert_eq!(
            validation.source.kind,
            ProcessPluginPackageSourceKind::LocalArchive
        );
        assert_eq!(
            validation.candidate.state,
            ProcessPluginCandidateState::Available
        );
        cleanup_process_plugin_package_staging(&validation.staging_root).expect("cleanup staging");
    }

    #[test]
    fn archive_traversal_is_rejected_without_replacing_active_plugin() {
        let archive_dir = TempDir::new("archive-traversal");
        let install_root = TempDir::new("archive-traversal-install");
        let archive_path = archive_dir.path().join("evil.tar");
        let active_marker = install_root.path().join("redis").join("active.txt");
        fs::create_dir_all(active_marker.parent().expect("active marker parent"))
            .expect("create active plugin dir");
        fs::write(&active_marker, "active").expect("write active marker");
        write_tar_file(&archive_path, "../evil.txt", b"evil");

        let error = validate_process_plugin_package(
            ProcessPluginPackageSource::local_archive(&archive_path),
            install_root.path(),
        )
        .expect_err("reject traversal archive");

        assert_eq!(error.code, "package.archive_path_unsafe");
        assert_eq!(
            fs::read_to_string(&active_marker).expect("read active marker"),
            "active"
        );
    }

    #[cfg(unix)]
    #[test]
    fn world_writable_executable_package_is_rejected() {
        use std::os::unix::fs::PermissionsExt;

        let source = TempDir::new("world-writable");
        let install_root = TempDir::new("world-writable-install");
        write_valid_plugin(source.path(), "redis", "redis", "1", &[current_platform()]);
        let command = source
            .path()
            .join("redis")
            .join("bin")
            .join("voidb-plugin-test");
        let mut permissions = fs::metadata(&command)
            .expect("command metadata")
            .permissions();
        permissions.set_mode(0o777);
        fs::set_permissions(&command, permissions).expect("chmod command");

        let error = validate_process_plugin_package(
            ProcessPluginPackageSource::local_directory(source.path()),
            install_root.path(),
        )
        .expect_err("reject world-writable executable");

        assert_eq!(error.code, "package.executable_world_writable");
    }

    #[test]
    fn package_source_summary_redacts_secret_segments() {
        let summary = summarize_package_source(&ProcessPluginPackageSource::local_archive(
            "/tmp/token-secret/passworded-plugin.tar",
        ));

        assert_eq!(summary.locator, summary.redacted_locator);
        assert!(!summary.locator.contains("token-secret"));
        assert!(!summary.locator.contains("passworded"));
    }

    #[test]
    fn package_source_error_redacts_secret_segments() {
        let error = ProcessPluginPackageSource::from_path(
            "/tmp/token-secret/passworded-plugin.voidb-plugin.tar",
        )
        .expect_err("missing source");
        let encoded = serde_json::to_string(&error).expect("serialize error");

        assert!(!encoded.contains("token-secret"));
        assert!(!encoded.contains("passworded"));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_escape_package_is_rejected() {
        let source = TempDir::new("symlink-escape");
        let install_root = TempDir::new("symlink-escape-install");
        write_valid_plugin(source.path(), "redis", "redis", "1", &[current_platform()]);
        std::os::unix::fs::symlink(
            "/etc/passwd",
            source.path().join("redis").join("schemas").join("escape"),
        )
        .expect("create escaping symlink");

        let error = validate_process_plugin_package(
            ProcessPluginPackageSource::local_directory(source.path()),
            install_root.path(),
        )
        .expect_err("reject symlink escape");

        assert_eq!(error.code, "package.symlink_escape");
    }

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(label: &str) -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock")
                .as_nanos();
            let path =
                std::env::temp_dir().join(format!("voidb-process-plugin-{}-{}", label, nonce));
            fs::create_dir_all(&path).expect("create temp dir");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn write_invalid_manifest(root: &Path, dir: &str, manifest: &str) {
        let plugin_dir = root.join(dir);
        fs::create_dir_all(&plugin_dir).expect("create plugin dir");
        fs::write(plugin_dir.join(MANIFEST_FILE_NAME), manifest).expect("write manifest");
    }

    fn prepend_manifest(root: &Path, dir: &str, prefix: &str) {
        let manifest_path = root.join(dir).join(MANIFEST_FILE_NAME);
        let manifest = fs::read_to_string(&manifest_path).expect("read manifest");
        fs::write(&manifest_path, format!("{prefix}\n{manifest}")).expect("write manifest");
    }

    fn replace_manifest_fragment(root: &Path, dir: &str, from: &str, to: &str) {
        let manifest_path = root.join(dir).join(MANIFEST_FILE_NAME);
        let manifest = fs::read_to_string(&manifest_path).expect("read manifest");
        let updated = manifest.replace(from, to);
        assert_ne!(updated, manifest, "manifest fixture fragment was not found");
        fs::write(&manifest_path, updated).expect("write manifest");
    }

    fn write_valid_plugin(
        root: &Path,
        dir: &str,
        id: &str,
        protocol_version: &str,
        platforms: &[&str],
    ) {
        let plugin_dir = root.join(dir);
        let schemas = plugin_dir.join("schemas");
        let bin = plugin_dir.join("bin");
        fs::create_dir_all(&schemas).expect("create schemas dir");
        fs::create_dir_all(&bin).expect("create bin dir");

        for schema_name in [
            "profile.schema.json",
            "get-input.schema.json",
            "get-output.schema.json",
            "set-input.schema.json",
            "set-output.schema.json",
        ] {
            fs::write(schemas.join(schema_name), r#"{"type":"object"}"#).expect("write schema");
        }

        let command = bin.join("voidb-plugin-test");
        fs::write(&command, "#!/bin/sh\nexit 0\n").expect("write command");
        make_executable(&command);

        let platform_list = platforms
            .iter()
            .map(|platform| format!("\"{}\"", platform))
            .collect::<Vec<_>>()
            .join(", ");
        let manifest = format!(
            r#"
id = "{id}"
name = "{id}"
version = "0.1.0"
protocol_version = "{protocol_version}"
description = "Test plugin."

[runtime]
command = "voidb-plugin-test"
args = []
transport = "stdio-jsonrpc"

[connections]
profile_schema = "schemas/profile.schema.json"
secret_classes = ["password"]

[[capabilities]]
id = "get"
description = "Read one key."
input_schema = "schemas/get-input.schema.json"
output_schema = "schemas/get-output.schema.json"
permissions = ["connection.read"]
destructive = false
streaming = false
connection_required = true
required_secret_classes = []
supports_dry_run = false
default_timeout_ms = 10000

[[capabilities]]
id = "set"
description = "Write one key."
input_schema = "schemas/set-input.schema.json"
output_schema = "schemas/set-output.schema.json"
permissions = ["connection.read"]
destructive = true
streaming = false
connection_required = true
required_secret_classes = []
supports_dry_run = true
default_timeout_ms = 10000

[ui]
tui = false

[requirements]
voidb_core = ">=0.1.0"
platforms = [{platform_list}]
"#
        );
        fs::write(plugin_dir.join(MANIFEST_FILE_NAME), manifest).expect("write manifest");
    }

    #[cfg(unix)]
    fn make_executable(path: &Path) {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = fs::metadata(path).expect("metadata").permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).expect("chmod");
    }

    #[cfg(not(unix))]
    fn make_executable(_path: &Path) {}

    fn write_tar_archive(source: &Path, archive_path: &Path) {
        let file = File::create(archive_path).expect("create archive");
        let mut builder = tar::Builder::new(file);
        builder
            .append_dir_all(".", source)
            .expect("append source directory");
        builder.finish().expect("finish archive");
    }

    fn write_tar_file(archive_path: &Path, path: &str, contents: &[u8]) {
        assert!(path.len() < 100, "test tar path must fit in name field");
        let mut file = File::create(archive_path).expect("create archive");
        let mut header = [0_u8; 512];
        header[..path.len()].copy_from_slice(path.as_bytes());
        write_tar_octal_field(&mut header[100..108], 0o644);
        write_tar_octal_field(&mut header[108..116], 0);
        write_tar_octal_field(&mut header[116..124], 0);
        write_tar_octal_field(&mut header[124..136], contents.len() as u64);
        write_tar_octal_field(&mut header[136..148], 0);
        header[148..156].fill(b' ');
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let checksum = header.iter().map(|byte| *byte as u64).sum::<u64>();
        let checksum_field = format!("{checksum:06o}\0 ");
        header[148..156].copy_from_slice(checksum_field.as_bytes());

        file.write_all(&header).expect("write tar header");
        file.write_all(contents).expect("write tar contents");
        let padding = (512 - (contents.len() % 512)) % 512;
        if padding > 0 {
            file.write_all(&vec![0_u8; padding])
                .expect("write tar padding");
        }
        file.write_all(&[0_u8; 1024]).expect("write tar trailer");
    }

    fn write_tar_octal_field(field: &mut [u8], value: u64) {
        let value = format!("{value:0width$o}\0", width = field.len() - 1);
        field.copy_from_slice(value.as_bytes());
    }
}
