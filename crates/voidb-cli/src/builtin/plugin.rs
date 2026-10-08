//! Built-in `plugin` CLI for process-plugin discovery and local package management.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use async_trait::async_trait;
use chrono::Utc;
use clap::{Arg, ArgAction, ArgMatches, Command};
use semver::Version;
use serde::Serialize;
use serde_json::{Value, json};
use voidb_core::capability::{CapabilityErrorCategory, RedactionStatus};
use voidb_core::plugin::cli::{CliContext, CliPlugin};
use voidb_core::{
    PluginCategory, PluginRegistryIndex, RegistryPackageArtifact, RegistryPluginEntry,
    RegistryPluginVersion, DEFAULT_OFFICIAL_REGISTRY_URL,
    default_signature_path, generate_signing_keypair, sign_file, verify_file_signature, SignatureVerificationResult,
    SIGNATURE_SCHEME_ED25519,
    ProcessPluginCandidate, ProcessPluginCandidateState, ProcessPluginDiagnostic,
    ProcessPluginDiscovery, ProcessPluginInstallRecord, ProcessPluginManifest,
    ProcessPluginPackageFormat, ProcessPluginPackageResult, ProcessPluginPackageSource,
    ProcessPluginPackageValidation, ProcessPluginPackageValidationError,
    ProcessPluginPreviousVersionRecord, ProcessPluginRoot, ProcessPluginRootKind, VoidbError,
    cleanup_process_plugin_package_staging, default_bundled_plugin_roots,
    default_user_process_plugin_install_root, discover_process_plugins,
    discover_process_plugins_from_roots, package_process_plugin,
    process_plugin_install_record_path, read_process_plugin_install_record,
    validate_process_plugin_package, write_process_plugin_install_record,
};

const PLUGIN_CLI_SCHEMA_VERSION: u32 = 1;

/// Default official core database and protocol plugins bundled or recommended by VoidB.
pub const DEFAULT_OFFICIAL_CORE_PLUGINS: &[&str] = &[
    "mysql", "postgres", "sqlite", "redis", "ssh", "duckdb",
];

pub struct PluginCliPlugin;

impl PluginCliPlugin {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl CliPlugin for PluginCliPlugin {
    fn plugin_id(&self) -> &str {
        "plugin"
    }

    fn name(&self) -> &str {
        "Process Plugin Discovery"
    }

    fn commands(&self) -> Vec<Command> {
        vec![
            Command::new("list")
                .about("List discovered process-plugin candidates as JSON")
                .arg(format_arg())
                .arg(state_arg())
                .arg(
                    Arg::new("include-shadowed")
                        .long("include-shadowed")
                        .action(ArgAction::SetTrue)
                        .help("Include lower-precedence candidates shadowed by an available plugin"),
                )
                .arg(
                    Arg::new("include-invalid")
                        .long("include-invalid")
                        .action(ArgAction::SetTrue)
                        .help("Include invalid candidates and redacted validation diagnostics"),
                ),
            Command::new("describe")
                .about("Describe one discovered process-plugin candidate as JSON")
                .arg(
                    Arg::new("plugin")
                        .required(true)
                        .value_name("PLUGIN_ID")
                        .help("Process plugin ID to describe"),
                )
                .arg(format_arg())
                .arg(
                    Arg::new("include")
                        .long("include")
                        .value_name("PARTS")
                        .help("Comma-separated parts: runtime, connections, capabilities, schemas, ui, requirements, diagnostics"),
                )
                .arg(
                    Arg::new("state-any")
                        .long("state-any")
                        .action(ArgAction::SetTrue)
                        .help("Allow describing non-available candidates"),
                ),
            Command::new("install")
                .about("Install a plugin from registry or local path/archive")
                .arg(
                    Arg::new("source")
                        .required(true)
                        .value_name("PLUGIN_OR_PATH")
                        .help("Plugin ID (from registry), local directory, or archive (.tar, .tar.zst)"),
                )
                .arg(
                    Arg::new("registry-url")
                        .long("registry-url")
                        .value_name("URL")
                        .help("Remote registry index URL (defaults to official repository index)"),
                )
                .arg(
                    Arg::new("version")
                        .long("version")
                        .value_name("VERSION")
                        .help("Specific plugin version to install from registry (defaults to latest)"),
                )
                .arg(
                    Arg::new("verify-key")
                        .long("verify-key")
                        .value_name("HEX_PUBKEY")
                        .help("Ed25519 public key in hex to verify detached package signature (<archive>.sig)"),
                )
                .arg(
                    Arg::new("require-signature")
                        .long("require-signature")
                        .action(ArgAction::SetTrue)
                        .help("Fail installation if detached signature (<archive>.sig) is missing or invalid"),
                )
                .arg(format_arg())
                .arg(install_root_arg()),
            Command::new("install-default")
                .visible_alias("init-defaults")
                .about("Install or initialize default official database and protocol plugins (mysql, postgres, sqlite, redis, ssh, duckdb)")
                .arg(
                    Arg::new("plugins")
                        .long("plugins")
                        .value_name("PLUGINS")
                        .help("Comma-separated list of plugins to install (defaults to: mysql, postgres, sqlite, redis, ssh, duckdb)"),
                )
                .arg(
                    Arg::new("registry-url")
                        .long("registry-url")
                        .value_name("URL")
                        .help("Remote registry index URL (defaults to official repository index)"),
                )
                .arg(
                    Arg::new("force")
                        .long("force")
                        .action(ArgAction::SetTrue)
                        .help("Reinstall even if the plugin is already installed"),
                )
                .arg(
                    Arg::new("from-bundled")
                        .long("from-bundled")
                        .action(ArgAction::SetTrue)
                        .help("Only install from local bundled roots, do not download from remote registry"),
                )
                .arg(format_arg())
                .arg(install_root_arg()),
            Command::new("update")
                .about("Update an installed process plugin from registry or a local package")
                .arg(
                    Arg::new("plugin")
                        .required(true)
                        .value_name("PLUGIN_ID")
                        .help("Installed process plugin ID to update"),
                )
                .arg(
                    Arg::new("from")
                        .long("from")
                        .value_name("PATH")
                        .value_parser(clap::value_parser!(PathBuf))
                        .help("Optional local plugin directory or archive (.tar, .tar.zst)"),
                )
                .arg(
                    Arg::new("registry-url")
                        .long("registry-url")
                        .value_name("URL")
                        .help("Remote registry index URL (defaults to official repository index)"),
                )
                .arg(
                    Arg::new("version")
                        .long("version")
                        .value_name("VERSION")
                        .help("Target plugin version to update to (defaults to latest available)"),
                )
                .arg(
                    Arg::new("verify-key")
                        .long("verify-key")
                        .value_name("HEX_PUBKEY")
                        .help("Ed25519 public key in hex to verify detached package signature (<archive>.sig)"),
                )
                .arg(
                    Arg::new("require-signature")
                        .long("require-signature")
                        .action(ArgAction::SetTrue)
                        .help("Fail update if detached signature (<archive>.sig) is missing or invalid"),
                )
                .arg(
                    Arg::new("allow-downgrade")
                        .long("allow-downgrade")
                        .action(ArgAction::SetTrue)
                        .help("Allow installing a lower semver package version"),
                )
                .arg(format_arg())
                .arg(install_root_arg()),
            Command::new("search")
                .about("Search plugins in remote or cached registry by keyword")
                .arg(
                    Arg::new("query")
                        .required(true)
                        .value_name("QUERY")
                        .help("Search keyword matching plugin id, name, description, category, or tags"),
                )
                .arg(
                    Arg::new("registry-url")
                        .long("registry-url")
                        .value_name("URL")
                        .help("Remote registry index URL"),
                )
                .arg(format_arg()),
            Command::new("disable")
                .about("Disable an installed process plugin without removing package files")
                .arg(plugin_id_arg())
                .arg(format_arg())
                .arg(install_root_arg()),
            Command::new("enable")
                .about("Enable a disabled installed process plugin")
                .arg(plugin_id_arg())
                .arg(format_arg())
                .arg(install_root_arg()),
            Command::new("uninstall")
                .about("Remove an installed process-plugin package while preserving profiles, credentials, plugin data, and install metadata by default")
                .arg(plugin_id_arg())
                .arg(
                    Arg::new("keep-profiles")
                        .long("keep-profiles")
                        .action(ArgAction::SetTrue)
                        .help("Preserve connection profiles and credentials; currently the conservative default"),
                )
                .arg(format_arg())
                .arg(install_root_arg()),
            Command::new("package")
                .about("Package a process-plugin directory into an offline distribution archive (.tar.zst or .tar)")
                .arg(
                    Arg::new("source")
                        .required(true)
                        .value_name("DIR")
                        .value_parser(clap::value_parser!(PathBuf))
                        .help("Local plugin directory to package"),
                )
                .arg(
                    Arg::new("output")
                        .long("output")
                        .short('o')
                        .value_name("PATH")
                        .value_parser(clap::value_parser!(PathBuf))
                        .help("Output package file path (default: dist/<plugin-id>-<version>.<ext>)"),
                )
                .arg(
                    Arg::new("archive-format")
                        .long("archive-format")
                        .value_name("FORMAT")
                        .value_parser(["tar.zst", "tar"])
                        .default_value("tar.zst")
                        .help("Archive compression format: tar.zst (default) or tar"),
                )
                .arg(format_arg()),
            Command::new("registry")
                .about("Query or update official and custom remote plugin registries")
                .subcommand(
                    Command::new("list")
                        .about("List available plugins from remote or cached plugin registry")
                        .arg(
                            Arg::new("url")
                                .long("url")
                                .value_name("URL")
                                .help("Remote registry index URL (defaults to official repository index on raw.githubusercontent.com)"),
                        )
                        .arg(
                            Arg::new("category")
                                .long("category")
                                .value_name("CATEGORY")
                                .help("Filter plugins by category (storage, infrastructure, search, database, communication, other)"),
                        )
                        .arg(format_arg()),
                )
                .subcommand(
                    Command::new("update")
                        .about("Fetch and refresh the local registry cache from the remote registry URL")
                        .arg(
                            Arg::new("url")
                                .long("url")
                                .value_name("URL")
                                .help("Remote registry index URL to fetch"),
                        )
                        .arg(format_arg()),
                )
                .subcommand(
                    Command::new("show")
                        .about("Show detailed registry entry and version artifacts for a plugin")
                        .arg(
                            Arg::new("plugin")
                                .required(true)
                                .value_name("PLUGIN_ID")
                                .help("Plugin ID to inspect"),
                        )
                        .arg(
                            Arg::new("url")
                                .long("url")
                                .value_name("URL")
                                .help("Remote registry index URL"),
                        )
                        .arg(format_arg()),
                ),
            Command::new("registry-index")
                .about("Build or update an official Plugin Registry index manifest from plugin directories or archives")
                .arg(
                    Arg::new("inputs")
                        .required(true)
                        .num_args(1..)
                        .value_name("PATH")
                        .value_parser(clap::value_parser!(PathBuf))
                        .help("One or more plugin directories, .tar, .tar.gz, or .tar.zst package paths to index"),
                )
                .arg(
                    Arg::new("output")
                        .long("output")
                        .short('o')
                        .value_name("PATH")
                        .value_parser(clap::value_parser!(PathBuf))
                        .help("Output index manifest file path (.json or .toml; default: dist/registry/index.json)"),
                )
                .arg(
                    Arg::new("base-url")
                        .long("base-url")
                        .value_name("URL")
                        .help("Optional base URL for package download links (e.g. https://github.com/<owner>/<repo>/releases/download/<tag>)"),
                )
                .arg(
                    Arg::new("registry-name")
                        .long("registry-name")
                        .value_name("NAME")
                        .help("Optional custom registry catalog name"),
                )
                .arg(
                    Arg::new("merge")
                        .long("merge")
                        .value_name("EXISTING_INDEX")
                        .value_parser(clap::value_parser!(PathBuf))
                        .help("Optional existing registry index file to merge updates into"),
                )
                .arg(format_arg()),
            Command::new("sign")
                .about("Sign a plugin archive package using an Ed25519 private key, generating a detached signature file (.sig)")
                .arg(
                    Arg::new("package")
                        .required(true)
                        .value_name("PACKAGE_FILE")
                        .value_parser(clap::value_parser!(PathBuf))
                        .help("Path to package archive (.tar, .tar.gz, .tar.zst) to sign"),
                )
                .arg(
                    Arg::new("private-key")
                        .long("private-key")
                        .value_name("HEX_KEY_OR_FILE")
                        .help("Ed25519 secret key in hex or path to private key file. If omitted and --generate-key is set, a new keypair is generated."),
                )
                .arg(
                    Arg::new("generate-key")
                        .long("generate-key")
                        .action(ArgAction::SetTrue)
                        .help("Generate an ephemeral or new keypair if no private key is supplied"),
                )
                .arg(
                    Arg::new("output")
                        .long("output")
                        .short('o')
                        .value_name("SIG_PATH")
                        .value_parser(clap::value_parser!(PathBuf))
                        .help("Optional path for detached signature (default: <package>.sig)"),
                )
                .arg(format_arg()),
            Command::new("verify")
                .about("Verify the detached Ed25519 cryptographic signature of a plugin package")
                .arg(
                    Arg::new("package")
                        .required(true)
                        .value_name("PACKAGE_FILE")
                        .value_parser(clap::value_parser!(PathBuf))
                        .help("Path to package archive (.tar, .tar.gz, .tar.zst) to verify"),
                )
                .arg(
                    Arg::new("public-key")
                        .long("public-key")
                        .required(true)
                        .value_name("HEX_PUBKEY")
                        .help("Ed25519 public key in hex"),
                )
                .arg(
                    Arg::new("signature")
                        .long("signature")
                        .value_name("SIG_HEX_OR_FILE")
                        .help("Detached signature hex string or path to .sig file (defaults to <package>.sig)"),
                )
                .arg(format_arg()),
        ]
    }

    async fn execute(
        &self,
        command: &str,
        matches: &ArgMatches,
        _ctx: &CliContext,
    ) -> Result<(), VoidbError> {
        match command {
            "list" => {
                ensure_json_format(matches)?;
                let discovery = discover_process_plugins();
                handle_list(matches, &discovery)
            }
            "describe" => {
                ensure_json_format(matches)?;
                let discovery = discover_process_plugins();
                handle_describe(matches, &discovery)
            }
            "install" => handle_install(matches).await,
            "install-default" | "init-defaults" => handle_install_default(matches).await,
            "update" => handle_update(matches).await,
            "search" => handle_search(matches).await,
            "disable" => handle_lifecycle(matches, PluginLifecycleOperation::Disable),
            "enable" => handle_lifecycle(matches, PluginLifecycleOperation::Enable),
            "uninstall" => handle_lifecycle(matches, PluginLifecycleOperation::Uninstall),
            "package" => handle_package(matches),
            "registry" => handle_registry(matches).await,
            "registry-index" => handle_registry_index(matches),
            "sign" => handle_sign(matches),
            "verify" => handle_verify(matches),
            _ => Err(VoidbError::Plugin(format!("Unknown command: {}", command))),
        }
    }
}

fn format_arg() -> Arg {
    Arg::new("format")
        .long("format")
        .value_name("FORMAT")
        .value_parser(["json", "table"])
        .default_value("json")
        .help("Output format; json is stable for agents, table is human-readable")
}

fn install_root_arg() -> Arg {
    Arg::new("install-root")
        .long("install-root")
        .value_name("PATH")
        .value_parser(clap::value_parser!(PathBuf))
        .help("Writable process-plugin install root; defaults to the user install root")
}

fn plugin_id_arg() -> Arg {
    Arg::new("plugin")
        .required(true)
        .value_name("PLUGIN_ID")
        .help("Installed process plugin ID")
}

fn state_arg() -> Arg {
    Arg::new("state")
        .long("state")
        .value_name("STATE")
        .value_parser([
            "available",
            "invalid",
            "incompatible",
            "shadowed",
            "disabled",
            "failed",
        ])
        .help("Filter by discovery state")
}

fn ensure_json_format(matches: &ArgMatches) -> Result<(), VoidbError> {
    match matches.get_one::<String>("format").map(String::as_str) {
        Some("json") | None => Ok(()),
        Some(other) => Err(VoidbError::Plugin(format!(
            "Unsupported plugin output format '{}'; use --format json",
            other
        ))),
    }
}

fn handle_list(matches: &ArgMatches, discovery: &ProcessPluginDiscovery) -> Result<(), VoidbError> {
    let state_filter = matches
        .get_one::<String>("state")
        .and_then(|state| state.parse::<ProcessPluginCandidateState>().ok());
    let include_shadowed = matches.get_flag("include-shadowed")
        || state_filter == Some(ProcessPluginCandidateState::Shadowed);
    let include_invalid = matches.get_flag("include-invalid")
        || state_filter == Some(ProcessPluginCandidateState::Invalid);

    print_json(&success_envelope(PluginListData {
        plugins: plugin_list_items(
            discovery,
            PluginListOptions {
                state_filter,
                include_shadowed,
                include_invalid,
            },
        ),
    }))
}

fn handle_describe(
    matches: &ArgMatches,
    discovery: &ProcessPluginDiscovery,
) -> Result<(), VoidbError> {
    let plugin_id = matches
        .get_one::<String>("plugin")
        .expect("required by clap");
    let include = IncludeParts::from_matches(matches)?;
    let state_any = matches.get_flag("state-any");

    match select_candidate_for_describe(discovery, plugin_id, state_any) {
        Ok(candidate) => print_json(&success_envelope(PluginDescribeData {
            plugin: PluginDescription::from_candidate(candidate, include),
        })),
        Err(error) => print_json(&JsonErrorEnvelope {
            ok: false,
            schema_version: PLUGIN_CLI_SCHEMA_VERSION,
            command: "plugin",
            error: *error,
        }),
    }
}

async fn handle_install(matches: &ArgMatches) -> Result<(), VoidbError> {
    let format = output_format(matches)?;
    let install_root = install_root_from_matches(matches)?;
    let source_arg = matches
        .get_one::<String>("source")
        .expect("required by clap")
        .trim();
    let registry_url_opt = matches.get_one::<String>("registry-url").map(String::as_str);
    let version_opt = matches.get_one::<String>("version").map(String::as_str);
    let verify_key = matches.get_one::<String>("verify-key").map(String::as_str);
    let require_signature = matches.get_flag("require-signature");

    let source_path = PathBuf::from(source_arg);
    let (effective_path, _download_temp_dir) = if source_path.exists() {
        (source_path, None)
    } else {
        // Source is not a local path; treat as plugin id from registry
        let plugin_id = source_arg;
        let (index, source_url) = resolve_registry_index(registry_url_opt).await?;
        let entry = index.get_plugin(plugin_id).ok_or_else(|| {
            VoidbError::Plugin(format!(
                "Plugin '{}' neither exists as a local path nor in registry ({})",
                plugin_id, source_url
            ))
        })?;

        let version_entry = entry.get_version(version_opt).ok_or_else(|| {
            VoidbError::Plugin(format!(
                "Version '{:?}' not found for plugin '{}' in registry",
                version_opt, plugin_id
            ))
        })?;

        let current_plat = voidb_core::process_plugin::current_platform();
        let current_target = std::env::consts::ARCH; // architecture or target
        let artifact = version_entry
            .find_matching_package(current_target, current_plat)
            .ok_or_else(|| {
                VoidbError::Plugin(format!(
                    "No compatible artifact found for plugin '{}' ({}) on platform '{}'",
                    plugin_id, version_entry.version, current_plat
                ))
            })?;

        let download_dir = std::env::temp_dir().join(format!("voidb-download-{}", Utc::now().timestamp_nanos_opt().unwrap_or(0)));
        let dest_file = download_dir.join(&artifact.filename);

        PluginRegistryIndex::download_artifact(artifact, &dest_file).await?;
        (dest_file, Some(download_dir))
    };

    if let Err(error) = check_package_signature_gate(&effective_path, verify_key, require_signature) {
        return print_plugin_error(error);
    }

    let source = match ProcessPluginPackageSource::from_path(effective_path) {
        Ok(source) => source,
        Err(error) => return print_plugin_error(package_validation_error_to_plugin_error(error)),
    };

    match install_plugin_package(source, install_root) {
        Ok(result) => print_operation_result(format, result),
        Err(error) => print_plugin_error(*error),
    }
}

async fn handle_install_default(matches: &ArgMatches) -> Result<(), VoidbError> {
    let format = output_format(matches)?;
    let install_root = install_root_from_matches(matches)?;
    let registry_url_opt = matches.get_one::<String>("registry-url").map(String::as_str);
    let force = matches.get_flag("force");
    let from_bundled = matches.get_flag("from-bundled");

    let plugins_to_install: Vec<String> = if let Some(custom) = matches.get_one::<String>("plugins") {
        custom
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    } else {
        DEFAULT_OFFICIAL_CORE_PLUGINS
            .iter()
            .map(|s| s.to_string())
            .collect()
    };

    let bundled_roots = default_bundled_plugin_roots();
    let mut results = Vec::new();
    let mut registry_index: Option<PluginRegistryIndex> = None;

    for plugin_id in &plugins_to_install {
        let active_dir = install_root.join(plugin_id);
        if active_dir.join("plugin.toml").exists() && !force {
            results.push(json!({
                "plugin": plugin_id,
                "status": "already_installed",
                "message": "Plugin is already installed in user install root",
            }));
            continue;
        }

        // 1. Check bundled roots
        let mut installed_from_bundled = false;
        for bundled_root in &bundled_roots {
            let candidate_dir = bundled_root.join(plugin_id);
            if candidate_dir.join("plugin.toml").is_file() {
                if active_dir.exists() && force {
                    let _ = fs::remove_dir_all(&active_dir);
                }
                match ProcessPluginPackageSource::from_path(&candidate_dir) {
                    Ok(source) => {
                        match install_plugin_package(source, install_root.clone()) {
                            Ok(res) => {
                                results.push(json!({
                                    "plugin": plugin_id,
                                    "status": "installed",
                                    "source": "bundled",
                                    "version": res.data.plugin.installed_version,
                                    "message": "Installed from local bundled root",
                                }));
                                installed_from_bundled = true;
                                break;
                            }
                            Err(err) => {
                                results.push(json!({
                                    "plugin": plugin_id,
                                    "status": "failed",
                                    "source": "bundled",
                                    "error": err.message,
                                }));
                                installed_from_bundled = true;
                                break;
                            }
                        }
                    }
                    Err(err) => {
                        results.push(json!({
                            "plugin": plugin_id,
                            "status": "failed",
                            "source": "bundled",
                            "error": format!("{:?}", err),
                        }));
                        installed_from_bundled = true;
                        break;
                    }
                }
            }
        }

        if installed_from_bundled {
            continue;
        }

        if from_bundled {
            results.push(json!({
                "plugin": plugin_id,
                "status": "failed",
                "source": "bundled",
                "error": "Plugin not found in bundled roots",
            }));
            continue;
        }

        // 2. Fetch from registry
        if registry_index.is_none() {
            match resolve_registry_index(registry_url_opt).await {
                Ok((idx, _)) => registry_index = Some(idx),
                Err(e) => {
                    results.push(json!({
                        "plugin": plugin_id,
                        "status": "failed",
                        "source": "registry",
                        "error": format!("Failed to resolve registry: {}", e),
                    }));
                    continue;
                }
            }
        }

        let index = registry_index.as_ref().unwrap();
        let entry = match index.get_plugin(plugin_id) {
            Some(e) => e,
            None => {
                results.push(json!({
                    "plugin": plugin_id,
                    "status": "failed",
                    "source": "registry",
                    "error": format!("Plugin '{}' not found in registry", plugin_id),
                }));
                continue;
            }
        };

        let version_entry = match entry.get_version(None) {
            Some(v) => v,
            None => {
                results.push(json!({
                    "plugin": plugin_id,
                    "status": "failed",
                    "source": "registry",
                    "error": "No version available in registry",
                }));
                continue;
            }
        };

        let current_plat = voidb_core::process_plugin::current_platform();
        let current_target = std::env::consts::ARCH;
        let artifact = match version_entry.find_matching_package(current_target, current_plat) {
            Some(a) => a,
            None => {
                results.push(json!({
                    "plugin": plugin_id,
                    "status": "failed",
                    "source": "registry",
                    "error": format!("No compatible artifact found for platform '{}'", current_plat),
                }));
                continue;
            }
        };

        let download_dir = std::env::temp_dir().join(format!(
            "voidb-download-default-{}",
            Utc::now().timestamp_nanos_opt().unwrap_or(0)
        ));
        let dest_file = download_dir.join(&artifact.filename);

        if let Err(e) = PluginRegistryIndex::download_artifact(artifact, &dest_file).await {
            results.push(json!({
                "plugin": plugin_id,
                "status": "failed",
                "source": "registry",
                "error": format!("Download failed: {}", e),
            }));
            let _ = fs::remove_dir_all(&download_dir);
            continue;
        }

        if active_dir.exists() && force {
            let _ = fs::remove_dir_all(&active_dir);
        }

        let source = match ProcessPluginPackageSource::from_path(&dest_file) {
            Ok(s) => s,
            Err(e) => {
                results.push(json!({
                    "plugin": plugin_id,
                    "status": "failed",
                    "source": "registry",
                    "error": format!("Package validation error: {:?}", e),
                }));
                let _ = fs::remove_dir_all(&download_dir);
                continue;
            }
        };

        match install_plugin_package(source, install_root.clone()) {
            Ok(res) => {
                results.push(json!({
                    "plugin": plugin_id,
                    "status": "installed",
                    "source": "registry",
                    "version": res.data.plugin.installed_version,
                    "message": "Installed from official registry",
                }));
            }
            Err(err) => {
                results.push(json!({
                    "plugin": plugin_id,
                    "status": "failed",
                    "source": "registry",
                    "error": err.message,
                }));
            }
        }
        let _ = fs::remove_dir_all(&download_dir);
    }

    match format {
        PluginOutputFormat::Json => print_json(&success_envelope(json!({
            "operation": "install-default",
            "results": results,
        }))),
        PluginOutputFormat::Table => {
            println!("PLUGIN\tSTATUS\tSOURCE\tDETAILS");
            for r in &results {
                let plugin = r.get("plugin").and_then(|v| v.as_str()).unwrap_or("-");
                let status = r.get("status").and_then(|v| v.as_str()).unwrap_or("-");
                let source = r.get("source").and_then(|v| v.as_str()).unwrap_or("-");
                let details = r
                    .get("version")
                    .and_then(|v| v.as_str())
                    .or_else(|| r.get("message").and_then(|v| v.as_str()))
                    .or_else(|| r.get("error").and_then(|v| v.as_str()))
                    .unwrap_or("-");
                println!("{}\t{}\t{}\t{}", plugin, status, source, details);
            }
            Ok(())
        }
    }
}

async fn handle_update(matches: &ArgMatches) -> Result<(), VoidbError> {
    let format = output_format(matches)?;
    let install_root = install_root_from_matches(matches)?;
    let plugin_id = matches
        .get_one::<String>("plugin")
        .expect("required by clap")
        .clone();
    let from_path_opt = matches.get_one::<PathBuf>("from").cloned();
    let registry_url_opt = matches.get_one::<String>("registry-url").map(String::as_str);
    let version_opt = matches.get_one::<String>("version").map(String::as_str);
    let verify_key = matches.get_one::<String>("verify-key").map(String::as_str);
    let require_signature = matches.get_flag("require-signature");
    let allow_downgrade = matches.get_flag("allow-downgrade");

    let (effective_path, _download_temp_dir) = if let Some(from_path) = from_path_opt {
        (from_path, None)
    } else {
        // Resolve from registry
        let (index, source_url) = resolve_registry_index(registry_url_opt).await?;
        let entry = index.get_plugin(&plugin_id).ok_or_else(|| {
            VoidbError::Plugin(format!(
                "Plugin '{}' not found in registry ({}) for update",
                plugin_id, source_url
            ))
        })?;

        let version_entry = entry.get_version(version_opt).ok_or_else(|| {
            VoidbError::Plugin(format!(
                "Version '{:?}' not found for plugin '{}' in registry",
                version_opt, plugin_id
            ))
        })?;

        let current_plat = voidb_core::process_plugin::current_platform();
        let current_target = std::env::consts::ARCH;
        let artifact = version_entry
            .find_matching_package(current_target, current_plat)
            .ok_or_else(|| {
                VoidbError::Plugin(format!(
                    "No compatible artifact found for plugin '{}' ({}) on platform '{}'",
                    plugin_id, version_entry.version, current_plat
                ))
            })?;

        let download_dir = std::env::temp_dir().join(format!("voidb-download-{}", Utc::now().timestamp_nanos_opt().unwrap_or(0)));
        let dest_file = download_dir.join(&artifact.filename);

        PluginRegistryIndex::download_artifact(artifact, &dest_file).await?;
        (dest_file, Some(download_dir))
    };

    if let Err(error) = check_package_signature_gate(&effective_path, verify_key, require_signature) {
        return print_plugin_error(error);
    }

    let source = match ProcessPluginPackageSource::from_path(effective_path) {
        Ok(source) => source,
        Err(error) => return print_plugin_error(package_validation_error_to_plugin_error(error)),
    };

    match update_plugin_package(
        &plugin_id,
        source,
        install_root,
        UpdateOptions { allow_downgrade },
    ) {
        Ok(result) => print_operation_result(format, result),
        Err(error) => print_plugin_error(*error),
    }
}

async fn handle_search(matches: &ArgMatches) -> Result<(), VoidbError> {
    let format = output_format(matches)?;
    let query = matches
        .get_one::<String>("query")
        .expect("required by clap")
        .to_lowercase();
    let url_opt = matches.get_one::<String>("registry-url").map(String::as_str);

    let (index, source_url) = resolve_registry_index(url_opt).await?;
    let mut matches_list = Vec::new();

    for plugin in &index.plugins {
        let id_match = plugin.id.to_lowercase().contains(&query);
        let name_match = plugin.name.to_lowercase().contains(&query);
        let desc_match = plugin.description.as_deref().unwrap_or("").to_lowercase().contains(&query);
        let tag_match = plugin.tags.iter().any(|t| t.to_lowercase().contains(&query));
        let cat_match = plugin.category.map(|c| c.as_str().contains(&query)).unwrap_or(false);

        if id_match || name_match || desc_match || tag_match || cat_match {
            matches_list.push(plugin.clone());
        }
    }

    match format {
        PluginOutputFormat::Json => print_json(&success_envelope(json!({
            "operation": "plugin.search",
            "query": query,
            "source_url": source_url,
            "count": matches_list.len(),
            "plugins": matches_list,
        }))),
        PluginOutputFormat::Table => {
            if matches_list.is_empty() {
                println!("No plugins found matching '{}'", query);
            } else {
                println!("ID\tNAME\tLATEST\tCATEGORY\tDESCRIPTION");
                for p in &matches_list {
                    println!(
                        "{}\t{}\t{}\t{}\t{}",
                        p.id,
                        p.name,
                        p.latest_version,
                        p.category.map(|c| c.as_str()).unwrap_or("-"),
                        p.description.as_deref().unwrap_or("-")
                    );
                }
            }
            Ok(())
        }
    }
}

fn handle_lifecycle(
    matches: &ArgMatches,
    operation: PluginLifecycleOperation,
) -> Result<(), VoidbError> {
    let format = output_format(matches)?;
    let install_root = install_root_from_matches(matches)?;
    let plugin_id = matches
        .get_one::<String>("plugin")
        .expect("required by clap")
        .clone();

    match apply_lifecycle_operation(&plugin_id, install_root, operation) {
        Ok(result) => print_lifecycle_result(format, result),
        Err(error) => print_plugin_error(*error),
    }
}

fn handle_package(matches: &ArgMatches) -> Result<(), VoidbError> {
    let format = output_format(matches)?;
    let source_dir = matches
        .get_one::<PathBuf>("source")
        .expect("required by clap")
        .clone();
    let archive_format_str = matches
        .get_one::<String>("archive-format")
        .map(String::as_str)
        .unwrap_or("tar.zst");
    let package_format = match archive_format_str {
        "tar" => ProcessPluginPackageFormat::Tar,
        _ => ProcessPluginPackageFormat::TarZst,
    };

    // First validate package source directory
    let temp_staging_root = match default_user_process_plugin_install_root() {
        Some(root) => root,
        None => std::env::temp_dir().join("voidb-packaging-validation"),
    };
    let validation = match validate_process_plugin_package(
        ProcessPluginPackageSource::local_directory(&source_dir),
        &temp_staging_root,
    ) {
        Ok(validation) => validation,
        Err(error) => return print_plugin_error(package_validation_error_to_plugin_error(error)),
    };
    cleanup_validated_staging(&validation);

    // Determine output path
    let output_path = if let Some(out) = matches.get_one::<PathBuf>("output") {
        out.clone()
    } else {
        PathBuf::from("dist").join(format!(
            "{}-{}.{}",
            validation.plugin_id,
            validation.version,
            package_format.extension()
        ))
    };

    match package_process_plugin(&source_dir, &output_path, package_format) {
        Ok(result) => print_package_result(format, result),
        Err(error) => print_plugin_error(package_validation_error_to_plugin_error(error)),
    }
}

fn handle_registry_index(matches: &ArgMatches) -> Result<(), VoidbError> {
    let format = output_format(matches)?;
    let inputs = matches
        .get_many::<PathBuf>("inputs")
        .expect("required by clap")
        .cloned()
        .collect::<Vec<_>>();
    let base_url = matches.get_one::<String>("base-url").map(String::as_str);
    let registry_name = matches.get_one::<String>("registry-name").map(String::as_str);

    let output_path = if let Some(out) = matches.get_one::<PathBuf>("output") {
        out.clone()
    } else {
        PathBuf::from("dist").join("registry").join("index.json")
    };

    let mut index = if let Some(merge_path) = matches.get_one::<PathBuf>("merge") {
        if merge_path.exists() {
            PluginRegistryIndex::load_from_file(merge_path)?
        } else {
            PluginRegistryIndex::new()
        }
    } else if output_path.exists() {
        PluginRegistryIndex::load_from_file(&output_path).unwrap_or_else(|_| PluginRegistryIndex::new())
    } else {
        PluginRegistryIndex::new()
    };

    if let Some(name) = registry_name {
        index.registry_name = Some(name.to_string());
    }

    let temp_staging_root = match default_user_process_plugin_install_root() {
        Some(root) => root,
        None => std::env::temp_dir().join("voidb-registry-indexing"),
    };

    let mut indexed_count = 0;
    for input_path in &inputs {
        if !input_path.exists() {
            return print_plugin_error(plugin_error(
                CapabilityErrorCategory::Validation,
                "validation.input_missing",
                format!("Input path does not exist: {}", input_path.display()),
                json!({ "path": input_path }),
                false,
            ));
        }

        let source = if input_path.is_dir() {
            ProcessPluginPackageSource::local_directory(input_path)
        } else {
            ProcessPluginPackageSource::local_archive(input_path)
        };

        let validation = match validate_process_plugin_package(source, &temp_staging_root) {
            Ok(v) => v,
            Err(error) => {
                return print_plugin_error(package_validation_error_to_plugin_error(error));
            }
        };

        let manifest = validation.candidate.manifest.as_ref().expect("validated manifest present");
        let plugin_id = manifest.id.clone();
        let version_str = manifest.version.clone();
        let protocol_version_str = manifest.protocol_version.clone();
        let platforms = manifest.requirements.as_ref()
            .and_then(|r| r.platforms.clone())
            .unwrap_or_else(|| vec!["darwin".into(), "linux".into(), "windows".into()]);
        let voidb_core_constraint = manifest.requirements.as_ref()
            .and_then(|r| r.voidb_core.clone());

        let (filename, format_str, target_triple, size_bytes, sha256_digest) = if input_path.is_file() {
            let fname = input_path.file_name().unwrap_or_default().to_string_lossy().to_string();
            let fmt = if fname.ends_with(".tar.zst") {
                "tar.zst".to_string()
            } else if fname.ends_with(".tar.gz") {
                "tar.gz".to_string()
            } else {
                "tar".to_string()
            };
            let size = fs::metadata(input_path).map(|m| m.len()).unwrap_or(0);
            (fname, fmt, None, Some(size), validation.package_digest.clone())
        } else {
            let fname = format!("{}-{}.tar.gz", plugin_id, version_str);
            (fname, "tar.gz".to_string(), None, None, validation.package_digest.clone())
        };

        let download_url = if let Some(b) = base_url {
            format!("{}/{}", b.trim_end_matches('/'), filename)
        } else if let Some(homepage) = &manifest.homepage {
            format!("{}/releases/download/v{}/{}", homepage.trim_end_matches('/'), version_str, filename)
        } else {
            format!("https://github.com/limmytian/voidb-plugin-{}/releases/download/v{}/{}", plugin_id, version_str, filename)
        };

        let sig_path = default_signature_path(input_path);
        let signature_str = if sig_path.is_file() {
            fs::read_to_string(&sig_path).ok().map(|s| s.trim().to_string())
        } else {
            None
        };

        let artifact = RegistryPackageArtifact {
            filename,
            format: format_str,
            target: target_triple,
            url: download_url,
            sha256: sha256_digest,
            size_bytes,
            signature: signature_str,
        };

        let category = match plugin_id.as_str() {
            "s3" | "webdav" => Some(PluginCategory::Storage),
            "docker" | "kubernetes" | "jenkins" | "ssh" => Some(PluginCategory::Infrastructure),
            "elasticsearch" => Some(PluginCategory::Search),
            "mongodb" | "mysql" | "postgres" | "sqlite" | "redis" | "duckdb" => Some(PluginCategory::Database),
            "email" => Some(PluginCategory::Communication),
            _ => Some(PluginCategory::Other),
        };

        let capabilities = manifest.capabilities.iter().map(|c| c.id.clone()).collect::<Vec<_>>();
        let tags = vec![plugin_id.clone()];

        let mut existing_entry = index.get_plugin(&plugin_id).cloned().unwrap_or_else(|| RegistryPluginEntry {
            id: plugin_id.clone(),
            name: manifest.name.clone(),
            description: manifest.description.clone(),
            homepage: manifest.homepage.clone(),
            license: manifest.license.clone(),
            category,
            tags,
            capabilities,
            latest_version: version_str.clone(),
            versions: Vec::new(),
        });

        existing_entry.latest_version = version_str.clone();
        if let Some(pos) = existing_entry.versions.iter().position(|v| v.version == version_str) {
            let v = &mut existing_entry.versions[pos];
            if let Some(pkg_idx) = v.packages.iter().position(|p| p.filename == artifact.filename) {
                v.packages[pkg_idx] = artifact;
            } else {
                v.packages.push(artifact);
            }
        } else {
            existing_entry.versions.push(RegistryPluginVersion {
                version: version_str,
                protocol_version: protocol_version_str,
                released_at: Some(Utc::now()),
                voidb_core: voidb_core_constraint,
                platforms,
                signature_scheme: None,
                packages: vec![artifact],
            });
        }

        cleanup_validated_staging(&validation);
        index.upsert_plugin(existing_entry);
        indexed_count += 1;
    }

    index.save_to_file(&output_path)?;

    match format {
        PluginOutputFormat::Json => print_json(&success_envelope(json!({
            "operation": "registry-index",
            "output_path": output_path.to_string_lossy(),
            "indexed_count": indexed_count,
            "plugins_total": index.plugins.len(),
            "updated_at": index.updated_at.to_rfc3339(),
        }))),
        PluginOutputFormat::Table => {
            println!("Field\tValue");
            println!("operation\tregistry-index");
            println!("output_path\t{}", output_path.display());
            println!("indexed_count\t{}", indexed_count);
            println!("plugins_total\t{}", index.plugins.len());
            println!("updated_at\t{}", index.updated_at.to_rfc3339());
            Ok(())
        }
    }
}

fn local_registry_cache_path(url: &str) -> PathBuf {
    let sanitized: String = url
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect();
    let cache_filename = format!("registry-cache-{}.json", sanitized.trim_matches('_'));

    if let Some(user_root) = default_user_process_plugin_install_root() {
        user_root.join(cache_filename)
    } else {
        PathBuf::from(format!(".voidb-plugins/{}", cache_filename))
    }
}

async fn resolve_registry_index(url_opt: Option<&str>) -> Result<(PluginRegistryIndex, String), VoidbError> {
    let url = url_opt.unwrap_or(DEFAULT_OFFICIAL_REGISTRY_URL);

    // If it's a file:// URL or local path, fetch directly without cache
    if url.starts_with("file://") || std::path::Path::new(url).is_file() {
        let index = PluginRegistryIndex::fetch_from_url(url).await?;
        return Ok((index, url.to_string()));
    }

    let cache_file = local_registry_cache_path(url);

    // 1-hour cache TTL
    let ttl = std::time::Duration::from_secs(3600);
    let index = PluginRegistryIndex::fetch_with_cache(url, &cache_file, ttl).await?;
    Ok((index, url.to_string()))
}

async fn handle_registry(matches: &ArgMatches) -> Result<(), VoidbError> {
    let (subcmd, sub_matches) = matches.subcommand().unwrap_or(("list", matches));

    match subcmd {
        "list" => {
            let format = output_format(sub_matches)?;
            let url_opt = sub_matches.get_one::<String>("url").map(String::as_str);
            let category_filter = sub_matches.get_one::<String>("category").map(String::as_str);

            let (index, source_url) = resolve_registry_index(url_opt).await?;
            let mut plugins = index.plugins;

            if let Some(cat) = category_filter {
                plugins.retain(|p| p.category.map(|c| c.as_str() == cat).unwrap_or(false));
            }

            match format {
                PluginOutputFormat::Json => print_json(&success_envelope(json!({
                    "operation": "registry.list",
                    "source_url": source_url,
                    "registry_name": index.registry_name,
                    "count": plugins.len(),
                    "plugins": plugins,
                }))),
                PluginOutputFormat::Table => {
                    println!("ID\tNAME\tLATEST\tCATEGORY\tDESCRIPTION");
                    for p in &plugins {
                        println!(
                            "{}\t{}\t{}\t{}\t{}",
                            p.id,
                            p.name,
                            p.latest_version,
                            p.category.map(|c| c.as_str()).unwrap_or("-"),
                            p.description.as_deref().unwrap_or("-")
                        );
                    }
                    Ok(())
                }
            }
        }
        "update" => {
            let format = output_format(sub_matches)?;
            let url = sub_matches
                .get_one::<String>("url")
                .map(String::as_str)
                .unwrap_or(DEFAULT_OFFICIAL_REGISTRY_URL);
            let cache_file = local_registry_cache_path(url);

            let index = PluginRegistryIndex::fetch_from_url(url).await?;
            index.save_to_file(&cache_file)?;

            match format {
                PluginOutputFormat::Json => print_json(&success_envelope(json!({
                    "operation": "registry.update",
                    "source_url": url,
                    "cache_path": cache_file.to_string_lossy(),
                    "plugins_count": index.plugins.len(),
                    "updated_at": index.updated_at.to_rfc3339(),
                }))),
                PluginOutputFormat::Table => {
                    println!("Field\tValue");
                    println!("operation\tregistry.update");
                    println!("source_url\t{}", url);
                    println!("cache_path\t{}", cache_file.display());
                    println!("plugins_count\t{}", index.plugins.len());
                    println!("updated_at\t{}", index.updated_at.to_rfc3339());
                    Ok(())
                }
            }
        }
        "show" => {
            let format = output_format(sub_matches)?;
            let plugin_id = sub_matches
                .get_one::<String>("plugin")
                .expect("required by clap")
                .trim();
            let url_opt = sub_matches.get_one::<String>("url").map(String::as_str);

            let (index, source_url) = resolve_registry_index(url_opt).await?;
            let entry = index.get_plugin(plugin_id).ok_or_else(|| {
                VoidbError::Plugin(format!("Plugin '{plugin_id}' not found in registry ({source_url})"))
            })?;

            match format {
                PluginOutputFormat::Json => print_json(&success_envelope(json!({
                    "operation": "registry.show",
                    "source_url": source_url,
                    "plugin": entry,
                }))),
                PluginOutputFormat::Table => {
                    println!("Field\tValue");
                    println!("id\t{}", entry.id);
                    println!("name\t{}", entry.name);
                    println!("latest_version\t{}", entry.latest_version);
                    println!("category\t{}", entry.category.map(|c| c.as_str()).unwrap_or("-"));
                    println!("description\t{}", entry.description.as_deref().unwrap_or("-"));
                    println!("homepage\t{}", entry.homepage.as_deref().unwrap_or("-"));
                    println!("license\t{}", entry.license.as_deref().unwrap_or("-"));
                    println!("versions_count\t{}", entry.versions.len());
                    Ok(())
                }
            }
        }
        _ => Err(VoidbError::Plugin(format!("Unknown registry subcommand: {subcmd}"))),
    }
}

fn handle_sign(matches: &ArgMatches) -> Result<(), VoidbError> {
    let format = output_format(matches)?;
    let package_path = matches
        .get_one::<PathBuf>("package")
        .expect("required by clap")
        .clone();

    if !package_path.is_file() {
        return print_plugin_error(plugin_error(
            CapabilityErrorCategory::Validation,
            "validation.package_missing",
            format!("Package archive does not exist: {}", package_path.display()),
            json!({ "path": package_path }),
            false,
        ));
    }

    let priv_key_arg = matches.get_one::<String>("private-key").map(String::as_str);
    let generate_key = matches.get_flag("generate-key");

    let (signing_key, verifying_key) = if let Some(key_str) = priv_key_arg {
        let key_hex = if Path::new(key_str).is_file() {
            fs::read_to_string(key_str)?.trim().to_string()
        } else {
            key_str.trim().to_string()
        };
        let key_bytes = hex::decode(&key_hex).map_err(|e| {
            VoidbError::Crypto(format!("Invalid private key hex encoding: {e}"))
        })?;
        if key_bytes.len() != 32 {
            return print_plugin_error(plugin_error(
                CapabilityErrorCategory::Validation,
                "crypto.invalid_key_length",
                "Ed25519 secret key must be 32 bytes (64 hex characters).",
                json!({ "length_bytes": key_bytes.len() }),
                false,
            ));
        }
        let mut key_arr = [0u8; 32];
        key_arr.copy_from_slice(&key_bytes);
        let sk = ed25519_dalek::SigningKey::from_bytes(&key_arr);
        let vk = sk.verifying_key();
        (sk, vk)
    } else if generate_key {
        generate_signing_keypair()
    } else {
        return print_plugin_error(plugin_error(
            CapabilityErrorCategory::Validation,
            "crypto.missing_private_key",
            "Must provide --private-key or pass --generate-key to create a new keypair.",
            json!({}),
            false,
        ));
    };

    let sig_path = if let Some(out) = matches.get_one::<PathBuf>("output") {
        out.clone()
    } else {
        default_signature_path(&package_path)
    };

    let sig_hex = sign_file(&package_path, &signing_key)?;
    fs::write(&sig_path, &sig_hex)?;

    let pubkey_hex = hex::encode(verifying_key.to_bytes());
    let privkey_hex = hex::encode(signing_key.to_bytes());

    match format {
        PluginOutputFormat::Json => print_json(&success_envelope(json!({
            "operation": "sign",
            "package": package_path.to_string_lossy(),
            "signature_file": sig_path.to_string_lossy(),
            "signature": sig_hex,
            "public_key": pubkey_hex,
            "private_key": if generate_key { Some(privkey_hex) } else { None },
            "scheme": SIGNATURE_SCHEME_ED25519,
        }))),
        PluginOutputFormat::Table => {
            println!("Field\tValue");
            println!("operation\tsign");
            println!("package\t{}", package_path.display());
            println!("signature_file\t{}", sig_path.display());
            println!("signature\t{}", sig_hex);
            println!("public_key\t{}", pubkey_hex);
            if generate_key {
                println!("generated_private_key\t{}", privkey_hex);
            }
            Ok(())
        }
    }
}

fn handle_verify(matches: &ArgMatches) -> Result<(), VoidbError> {
    let format = output_format(matches)?;
    let package_path = matches
        .get_one::<PathBuf>("package")
        .expect("required by clap")
        .clone();
    let pubkey_hex = matches
        .get_one::<String>("public-key")
        .expect("required by clap")
        .trim();

    if !package_path.is_file() {
        return print_plugin_error(plugin_error(
            CapabilityErrorCategory::Validation,
            "validation.package_missing",
            format!("Package archive does not exist: {}", package_path.display()),
            json!({ "path": package_path }),
            false,
        ));
    }

    let sig_hex = if let Some(sig_arg) = matches.get_one::<String>("signature") {
        let sig_trimmed = sig_arg.trim();
        if Path::new(sig_trimmed).is_file() {
            fs::read_to_string(sig_trimmed)?.trim().to_string()
        } else {
            sig_trimmed.to_string()
        }
    } else {
        let default_sig_path = default_signature_path(&package_path);
        if !default_sig_path.is_file() {
            return print_plugin_error(plugin_error(
                CapabilityErrorCategory::Validation,
                "validation.signature_missing",
                format!("Detached signature file not found: {}", default_sig_path.display()),
                json!({ "expected_path": default_sig_path }),
                false,
            ));
        }
        fs::read_to_string(default_sig_path)?.trim().to_string()
    };

    let result = verify_file_signature(&package_path, &sig_hex, pubkey_hex)?;

    if !result.valid {
        return print_plugin_error(plugin_error(
            CapabilityErrorCategory::Validation,
            "crypto.signature_verification_failed",
            result.message,
            json!({
                "package": package_path,
                "public_key": pubkey_hex,
                "signature": sig_hex,
            }),
            false,
        ));
    }

    match format {
        PluginOutputFormat::Json => print_json(&success_envelope(json!({
            "operation": "verify",
            "package": package_path.to_string_lossy(),
            "valid": true,
            "public_key": pubkey_hex,
            "scheme": SIGNATURE_SCHEME_ED25519,
            "message": result.message,
        }))),
        PluginOutputFormat::Table => {
            println!("Field\tValue");
            println!("operation\tverify");
            println!("package\t{}", package_path.display());
            println!("valid\ttrue");
            println!("public_key\t{}", pubkey_hex);
            println!("scheme\t{}", SIGNATURE_SCHEME_ED25519);
            println!("message\t{}", result.message);
            Ok(())
        }
    }
}

fn check_package_signature_gate(
    source_path: &Path,
    verify_key: Option<&str>,
    require_signature: bool,
) -> Result<Option<SignatureVerificationResult>, PluginError> {
    if !source_path.is_file() {
        if require_signature {
            return Err(plugin_error(
                CapabilityErrorCategory::Validation,
                "validation.signature_required_for_archive_only",
                "Signature verification requires an archive file (.tar, .tar.gz, .tar.zst), not an unpacked directory.",
                json!({ "path": source_path }),
                false,
            ));
        }
        return Ok(None);
    }

    let default_sig_path = default_signature_path(source_path);

    if let Some(pubkey) = verify_key {
        if !default_sig_path.is_file() {
            return Err(plugin_error(
                CapabilityErrorCategory::Validation,
                "validation.signature_file_missing",
                format!("Detached signature file missing: {}", default_sig_path.display()),
                json!({ "expected_signature": default_sig_path }),
                false,
            ));
        }
        let sig_hex = fs::read_to_string(&default_sig_path).map_err(|e| {
            filesystem_plugin_error("filesystem.read_signature_failed", "Failed to read signature file", &default_sig_path, e)
        })?;
        let res = verify_file_signature(source_path, sig_hex.trim(), pubkey).map_err(|e| {
            plugin_error(CapabilityErrorCategory::Validation, "crypto.verification_error", e.to_string(), json!({}), false)
        })?;
        if !res.valid {
            return Err(plugin_error(
                CapabilityErrorCategory::Validation,
                "crypto.signature_invalid",
                res.message,
                json!({ "path": source_path, "public_key": pubkey }),
                false,
            ));
        }
        return Ok(Some(res));
    } else if require_signature {
        return Err(plugin_error(
            CapabilityErrorCategory::Validation,
            "validation.verify_key_required",
            "--require-signature was passed but no --verify-key was provided.",
            json!({}),
            false,
        ));
    }

    Ok(None)
}

fn output_format(matches: &ArgMatches) -> Result<PluginOutputFormat, VoidbError> {
    match matches.get_one::<String>("format").map(String::as_str) {
        Some("json") | None => Ok(PluginOutputFormat::Json),
        Some("table") => Ok(PluginOutputFormat::Table),
        Some(other) => Err(VoidbError::Plugin(format!(
            "Unsupported plugin output format '{}'; use --format json or --format table",
            other
        ))),
    }
}

fn install_root_from_matches(matches: &ArgMatches) -> Result<PathBuf, VoidbError> {
    if let Some(path) = matches.get_one::<PathBuf>("install-root") {
        return Ok(path.clone());
    }

    default_user_process_plugin_install_root().ok_or_else(|| {
        VoidbError::Plugin(
            "Could not resolve a user process-plugin install root for this platform.".into(),
        )
    })
}

fn apply_lifecycle_operation(
    plugin_id: &str,
    install_root: PathBuf,
    operation: PluginLifecycleOperation,
) -> Result<PluginLifecycleOperationResult, Box<PluginError>> {
    let mut record = load_lifecycle_record(&install_root, plugin_id)?;
    let active_dir = install_root.join(plugin_id);
    let record_path = process_plugin_install_record_path(&install_root, plugin_id);
    let mut removed_active_package = false;

    match operation {
        PluginLifecycleOperation::Disable => {
            record.enabled = false;
        }
        PluginLifecycleOperation::Enable => {
            if !active_dir.is_dir() {
                return Err(Box::new(plugin_error(
                    CapabilityErrorCategory::Unavailable,
                    "unavailable.plugin_package_missing",
                    "The plugin install record exists, but the active package directory is missing.",
                    json!({
                        "plugin_id": plugin_id,
                        "active_plugin_dir": active_dir,
                    }),
                    false,
                )));
            }
            record.enabled = true;
        }
        PluginLifecycleOperation::Uninstall => {
            if active_dir.exists() {
                fs::remove_dir_all(&active_dir).map_err(|error| {
                    Box::new(filesystem_plugin_error(
                        "filesystem.plugin_uninstall_failed",
                        "Installed plugin package directory could not be removed.",
                        &active_dir,
                        error,
                    ))
                })?;
                removed_active_package = true;
            }
            record.enabled = false;
        }
    }

    write_process_plugin_install_record(&record)
        .map_err(|error| Box::new(package_validation_error_to_plugin_error(error)))?;

    Ok(PluginLifecycleOperationResult {
        data: PluginLifecycleOperationData {
            operation,
            plugin: PluginLifecycleItem {
                id: record.plugin_id,
                installed_version: record.installed_version,
                enabled: record.enabled,
                active_plugin_dir: active_dir.to_string_lossy().into_owned(),
                active_package_present: active_dir.is_dir(),
                install_root: install_root.to_string_lossy().into_owned(),
                install_record_path: record_path.to_string_lossy().into_owned(),
                removed_active_package,
                preserved_profiles: true,
                preserved_credentials: true,
                preserved_plugin_data: true,
                preserved_install_metadata: true,
            },
        },
        warnings: Vec::new(),
    })
}

fn load_lifecycle_record(
    install_root: &Path,
    plugin_id: &str,
) -> Result<ProcessPluginInstallRecord, Box<PluginError>> {
    let record_path = process_plugin_install_record_path(install_root, plugin_id);
    match read_process_plugin_install_record(&record_path) {
        Ok(record) => Ok(record),
        Err(error) if error.code == "package.io_failed" => Err(Box::new(plugin_error(
            CapabilityErrorCategory::Unavailable,
            "unavailable.install_record_missing",
            "The plugin install record is missing. Install or update the plugin before lifecycle operations.",
            json!({
                "plugin_id": plugin_id,
                "install_record_path": record_path,
            }),
            false,
        ))),
        Err(error) => Err(Box::new(package_validation_error_to_plugin_error(error))),
    }
}

fn install_plugin_package(
    source: ProcessPluginPackageSource,
    install_root: PathBuf,
) -> Result<PluginPackageOperationResult, Box<PluginError>> {
    let validation = validate_process_plugin_package(source, install_root)
        .map_err(|error| Box::new(package_validation_error_to_plugin_error(error)))?;
    let active_dir = validation.install_root.join(&validation.plugin_id);

    if active_dir.exists() {
        cleanup_validated_staging(&validation);
        return Err(Box::new(plugin_error(
            CapabilityErrorCategory::Conflict,
            "conflict.plugin_already_installed",
            "A process plugin with this id is already installed in the user install root. Use plugin update instead.",
            json!({
                "plugin_id": validation.plugin_id,
                "active_plugin_dir": active_dir,
            }),
            false,
        )));
    }

    let record = validation.install_record.clone();
    activate_validated_package(
        PluginPackageOperation::Install,
        validation,
        record,
        Vec::new(),
    )
}

fn update_plugin_package(
    plugin_id: &str,
    source: ProcessPluginPackageSource,
    install_root: PathBuf,
    options: UpdateOptions,
) -> Result<PluginPackageOperationResult, Box<PluginError>> {
    let validation = validate_process_plugin_package(source, &install_root)
        .map_err(|error| Box::new(package_validation_error_to_plugin_error(error)))?;

    if validation.plugin_id != plugin_id {
        cleanup_validated_staging(&validation);
        return Err(Box::new(plugin_error(
            CapabilityErrorCategory::Validation,
            "validation.plugin_id_mismatch",
            "The package plugin id does not match the requested update target.",
            json!({
                "requested_plugin_id": plugin_id,
                "package_plugin_id": validation.plugin_id,
            }),
            false,
        )));
    }

    let active_dir = install_root.join(plugin_id);
    if !active_dir.is_dir() {
        cleanup_validated_staging(&validation);
        return Err(Box::new(plugin_error(
            CapabilityErrorCategory::Unavailable,
            "unavailable.plugin_not_installed",
            "The requested process plugin is not installed in the user install root.",
            json!({
                "plugin_id": plugin_id,
                "active_plugin_dir": active_dir,
            }),
            false,
        )));
    }

    let previous_record = read_process_plugin_install_record(&process_plugin_install_record_path(
        &install_root,
        plugin_id,
    ))
    .ok();
    let previous_candidate = installed_candidate(&install_root, plugin_id);
    let previous_version = previous_record
        .as_ref()
        .map(|record| record.installed_version.clone())
        .or_else(|| {
            previous_candidate
                .as_ref()
                .and_then(|candidate| candidate.version.clone())
        })
        .unwrap_or_else(|| "unknown".into());

    if is_downgrade(&previous_version, &validation.version) && !options.allow_downgrade {
        cleanup_validated_staging(&validation);
        return Err(Box::new(plugin_error(
            CapabilityErrorCategory::Conflict,
            "conflict.plugin_downgrade_blocked",
            "The package version is lower than the installed version. Retry with --allow-downgrade to proceed.",
            json!({
                "plugin_id": plugin_id,
                "installed_version": previous_version,
                "package_version": validation.version,
            }),
            false,
        )));
    }

    let previous_dir = next_previous_version_dir(&install_root, plugin_id, &previous_version);
    let previous_version_record = ProcessPluginPreviousVersionRecord {
        version: previous_version,
        path: previous_dir.clone(),
        manifest_digest: previous_record
            .as_ref()
            .map(|record| record.manifest_digest.clone()),
        package_digest: previous_record
            .as_ref()
            .map(|record| record.package_digest.clone()),
        recorded_at: Utc::now(),
    };
    let mut record = validation.install_record.clone();
    record.previous_version = Some(previous_version_record);

    let update_warnings = update_review_warnings(previous_candidate.as_ref(), &validation);
    replace_active_package_with_rollback(
        validation,
        record,
        active_dir,
        previous_dir,
        update_warnings,
    )
}

fn activate_validated_package(
    operation: PluginPackageOperation,
    validation: ProcessPluginPackageValidation,
    record: ProcessPluginInstallRecord,
    extra_warnings: Vec<PluginWarning>,
) -> Result<PluginPackageOperationResult, Box<PluginError>> {
    let active_dir = validation.install_root.join(&validation.plugin_id);
    fs::rename(&validation.staged_plugin_dir, &active_dir).map_err(|error| {
        cleanup_validated_staging(&validation);
        Box::new(filesystem_plugin_error(
            "filesystem.plugin_activate_failed",
            "Validated plugin package could not be activated.",
            &active_dir,
            error,
        ))
    })?;

    finish_package_operation(operation, validation, record, active_dir, extra_warnings)
}

fn replace_active_package_with_rollback(
    validation: ProcessPluginPackageValidation,
    record: ProcessPluginInstallRecord,
    active_dir: PathBuf,
    previous_dir: PathBuf,
    extra_warnings: Vec<PluginWarning>,
) -> Result<PluginPackageOperationResult, Box<PluginError>> {
    if let Some(parent) = previous_dir.parent() {
        fs::create_dir_all(parent).map_err(|error| {
            cleanup_validated_staging(&validation);
            Box::new(filesystem_plugin_error(
                "filesystem.previous_directory_create_failed",
                "Previous-version metadata directory could not be created.",
                parent,
                error,
            ))
        })?;
    }

    fs::rename(&active_dir, &previous_dir).map_err(|error| {
        cleanup_validated_staging(&validation);
        Box::new(filesystem_plugin_error(
            "filesystem.previous_version_preserve_failed",
            "Installed plugin could not be preserved for rollback.",
            &previous_dir,
            error,
        ))
    })?;

    if let Err(error) = fs::rename(&validation.staged_plugin_dir, &active_dir) {
        let rollback_result = fs::rename(&previous_dir, &active_dir);
        cleanup_validated_staging(&validation);
        let rollback_message = rollback_result.err().map(|error| error.to_string());
        return Err(Box::new(plugin_error(
            CapabilityErrorCategory::Internal,
            "filesystem.plugin_update_activate_failed",
            "Validated plugin package could not be activated during update.",
            json!({
                "plugin_id": validation.plugin_id,
                "active_plugin_dir": active_dir,
                "previous_version_dir": previous_dir,
                "message": error.to_string(),
                "rollback_error": rollback_message,
            }),
            true,
        )));
    }

    finish_package_operation(
        PluginPackageOperation::Update,
        validation,
        record,
        active_dir,
        extra_warnings,
    )
}

fn finish_package_operation(
    operation: PluginPackageOperation,
    validation: ProcessPluginPackageValidation,
    record: ProcessPluginInstallRecord,
    active_dir: PathBuf,
    extra_warnings: Vec<PluginWarning>,
) -> Result<PluginPackageOperationResult, Box<PluginError>> {
    let record_path = write_process_plugin_install_record(&record)
        .map_err(|error| Box::new(package_validation_error_to_plugin_error(error)))?;
    let mut warnings = validation_warnings(&validation);
    warnings.extend(extra_warnings);
    if let Err(error) = cleanup_process_plugin_package_staging(&validation.staging_root) {
        warnings.push(package_error_warning(
            "plugin.package_staging_cleanup_failed",
            "Package staging directory could not be removed after activation.",
            *error.details,
        ));
    }

    Ok(PluginPackageOperationResult {
        data: PluginPackageOperationData {
            operation,
            plugin: PluginPackageItem {
                id: record.plugin_id,
                installed_version: record.installed_version,
                candidate_state: record.compatibility.state,
                manifest_path: active_dir
                    .join("plugin.toml")
                    .to_string_lossy()
                    .into_owned(),
                active_plugin_dir: active_dir.to_string_lossy().into_owned(),
                install_root: record.install_root.to_string_lossy().into_owned(),
                install_record_path: record_path.to_string_lossy().into_owned(),
                manifest_digest: record.manifest_digest,
                package_digest: record.package_digest,
                previous_version: record.previous_version.map(PluginPreviousVersionItem::from),
            },
        },
        warnings,
    })
}

fn installed_candidate(install_root: &Path, plugin_id: &str) -> Option<ProcessPluginCandidate> {
    let discovery = discover_process_plugins_from_roots(vec![ProcessPluginRoot::new(
        install_root,
        ProcessPluginRootKind::User,
        0,
    )]);
    discovery.effective_candidate(plugin_id).cloned()
}

fn is_downgrade(installed_version: &str, package_version: &str) -> bool {
    let Ok(installed_version) = Version::parse(installed_version) else {
        return false;
    };
    let Ok(package_version) = Version::parse(package_version) else {
        return false;
    };
    package_version < installed_version
}

fn next_previous_version_dir(install_root: &Path, plugin_id: &str, version: &str) -> PathBuf {
    let base = process_plugin_install_record_path(install_root, plugin_id)
        .parent()
        .expect("record path has plugin metadata parent")
        .join("previous");
    let version = sanitize_path_segment(version);
    let candidate = base.join(&version);
    if !candidate.exists() {
        return candidate;
    }

    base.join(format!("{}-{}", version, Utc::now().timestamp_millis()))
}

fn sanitize_path_segment(value: &str) -> String {
    let sanitized = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    if sanitized.is_empty() {
        "unknown".into()
    } else {
        sanitized
    }
}

fn update_review_warnings(
    previous_candidate: Option<&ProcessPluginCandidate>,
    validation: &ProcessPluginPackageValidation,
) -> Vec<PluginWarning> {
    let Some(previous_manifest) =
        previous_candidate.and_then(|candidate| candidate.manifest.as_ref())
    else {
        return Vec::new();
    };
    let Some(next_manifest) = validation.candidate.manifest.as_ref() else {
        return Vec::new();
    };

    let mut warnings = Vec::new();
    if previous_manifest.connections.profile_schema != next_manifest.connections.profile_schema {
        warnings.push(package_error_warning(
            "plugin.update_profile_schema_changed",
            "Connection profile schema changed during plugin update.",
            json!({
                "previous_profile_schema": previous_manifest.connections.profile_schema,
                "next_profile_schema": next_manifest.connections.profile_schema,
            }),
        ));
    }

    let previous_secret_classes = previous_manifest
        .connections
        .secret_classes
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    let next_secret_classes = next_manifest
        .connections
        .secret_classes
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    if previous_secret_classes != next_secret_classes {
        warnings.push(package_error_warning(
            "plugin.update_secret_classes_changed",
            "Declared connection secret classes changed during plugin update.",
            json!({
                "previous_secret_classes": previous_secret_classes,
                "next_secret_classes": next_secret_classes,
            }),
        ));
    }

    let previous_permissions = manifest_permissions(previous_manifest);
    let next_permissions = manifest_permissions(next_manifest);
    if previous_permissions != next_permissions {
        warnings.push(package_error_warning(
            "plugin.update_permissions_changed",
            "Declared capability permissions changed during plugin update.",
            json!({
                "previous_permissions": previous_permissions,
                "next_permissions": next_permissions,
            }),
        ));
    }

    warnings
}

fn manifest_permissions(manifest: &ProcessPluginManifest) -> BTreeSet<String> {
    manifest
        .capabilities
        .iter()
        .flat_map(|capability| capability.permissions.iter().cloned())
        .collect()
}

fn validation_warnings(validation: &ProcessPluginPackageValidation) -> Vec<PluginWarning> {
    validation
        .warnings
        .iter()
        .map(|diagnostic| {
            package_error_warning(
                &diagnostic.code,
                &diagnostic.message,
                (*diagnostic.details).clone(),
            )
        })
        .collect()
}

fn cleanup_validated_staging(validation: &ProcessPluginPackageValidation) {
    let _ = cleanup_process_plugin_package_staging(&validation.staging_root);
}

fn package_validation_error_to_plugin_error(
    error: ProcessPluginPackageValidationError,
) -> PluginError {
    let category = match error.code.as_str() {
        "package.compatibility_failed" => CapabilityErrorCategory::Unavailable,
        "package.source_missing"
        | "package.source_not_directory"
        | "package.source_not_archive"
        | "package.archive_unsupported" => CapabilityErrorCategory::Validation,
        _ => CapabilityErrorCategory::Validation,
    };

    PluginError {
        category,
        code: error.code,
        message: error.message,
        details: json!({
            "details": *error.details,
            "diagnostics": error.diagnostics,
        }),
        target: None,
        retryable: false,
        redaction: RedactionStatus::Applied,
    }
}

fn filesystem_plugin_error(
    code: impl Into<String>,
    message: impl Into<String>,
    path: &Path,
    error: std::io::Error,
) -> PluginError {
    plugin_error(
        CapabilityErrorCategory::Internal,
        code,
        message,
        json!({
            "path": path,
            "message": error.to_string(),
        }),
        true,
    )
}

fn package_error_warning(code: &str, message: &str, details: Value) -> PluginWarning {
    PluginWarning {
        code: code.into(),
        message: message.into(),
        details,
    }
}

fn print_operation_result(
    format: PluginOutputFormat,
    result: PluginPackageOperationResult,
) -> Result<(), VoidbError> {
    match format {
        PluginOutputFormat::Json => print_json(&success_envelope_with_warnings(
            result.data,
            result.warnings,
        )),
        PluginOutputFormat::Table => {
            print_operation_table(&result.data, &result.warnings);
            Ok(())
        }
    }
}

fn print_lifecycle_result(
    format: PluginOutputFormat,
    result: PluginLifecycleOperationResult,
) -> Result<(), VoidbError> {
    match format {
        PluginOutputFormat::Json => print_json(&success_envelope_with_warnings(
            result.data,
            result.warnings,
        )),
        PluginOutputFormat::Table => {
            print_lifecycle_table(&result.data, &result.warnings);
            Ok(())
        }
    }
}

fn print_operation_table(data: &PluginPackageOperationData, warnings: &[PluginWarning]) {
    println!("Field\tValue");
    println!("operation\t{}", data.operation.as_str());
    println!("plugin_id\t{}", data.plugin.id);
    println!("version\t{}", data.plugin.installed_version);
    println!("state\t{}", data.plugin.candidate_state.as_str());
    println!("active_plugin_dir\t{}", data.plugin.active_plugin_dir);
    println!("install_record\t{}", data.plugin.install_record_path);
    if let Some(previous) = &data.plugin.previous_version {
        println!("previous_version\t{}", previous.version);
        println!("previous_path\t{}", previous.path);
    }
    for warning in warnings {
        println!("warning\t{}\t{}", warning.code, warning.message);
    }
}

fn print_lifecycle_table(data: &PluginLifecycleOperationData, warnings: &[PluginWarning]) {
    println!("Field\tValue");
    println!("operation\t{}", data.operation.as_str());
    println!("plugin_id\t{}", data.plugin.id);
    println!("version\t{}", data.plugin.installed_version);
    println!("enabled\t{}", data.plugin.enabled);
    println!(
        "active_package_present\t{}",
        data.plugin.active_package_present
    );
    println!("active_plugin_dir\t{}", data.plugin.active_plugin_dir);
    println!("install_record\t{}", data.plugin.install_record_path);
    println!("preserved_profiles\t{}", data.plugin.preserved_profiles);
    println!(
        "preserved_credentials\t{}",
        data.plugin.preserved_credentials
    );
    println!(
        "preserved_plugin_data\t{}",
        data.plugin.preserved_plugin_data
    );
    for warning in warnings {
        println!("warning\t{}\t{}", warning.code, warning.message);
    }
}

fn print_package_result(
    format: PluginOutputFormat,
    result: ProcessPluginPackageResult,
) -> Result<(), VoidbError> {
    match format {
        PluginOutputFormat::Json => print_json(&success_envelope(result)),
        PluginOutputFormat::Table => {
            print_package_table(&result);
            Ok(())
        }
    }
}

fn print_package_table(result: &ProcessPluginPackageResult) {
    println!("Field\tValue");
    println!("operation\tpackage");
    println!("plugin_id\t{}", result.plugin_id);
    println!("version\t{}", result.version);
    println!("archive_path\t{}", result.archive_path.display());
    println!("format\t{}", result.format.extension());
    println!("package_digest\t{}", result.package_digest);
    println!("total_size\t{}", result.total_size);
    println!("file_count\t{}", result.files.len());
}

fn plugin_list_items(
    discovery: &ProcessPluginDiscovery,
    options: PluginListOptions,
) -> Vec<PluginListItem> {
    discovery
        .candidates
        .iter()
        .filter(|candidate| {
            options
                .state_filter
                .is_none_or(|state| candidate.state == state)
        })
        .filter(|candidate| {
            candidate.state != ProcessPluginCandidateState::Shadowed || options.include_shadowed
        })
        .filter(|candidate| {
            candidate.state != ProcessPluginCandidateState::Invalid || options.include_invalid
        })
        .map(PluginListItem::from_candidate)
        .collect()
}

fn select_candidate_for_describe<'a>(
    discovery: &'a ProcessPluginDiscovery,
    plugin_id: &str,
    state_any: bool,
) -> Result<&'a ProcessPluginCandidate, Box<PluginError>> {
    let candidates = discovery.candidates_for_id(plugin_id);
    let Some(candidate) = candidates
        .iter()
        .copied()
        .find(|candidate| candidate.state == ProcessPluginCandidateState::Available)
        .or_else(|| candidates.first().copied())
    else {
        return Err(Box::new(plugin_error(
            CapabilityErrorCategory::Validation,
            "validation.plugin_not_found",
            "No process-plugin candidate was discovered for the requested plugin id.",
            json!({ "plugin_id": plugin_id }),
            false,
        )));
    };

    if !state_any && candidate.state != ProcessPluginCandidateState::Available {
        return Err(Box::new(plugin_error(
            CapabilityErrorCategory::Unavailable,
            "unavailable.plugin_candidate_not_available",
            "The process-plugin candidate is not available. Retry with --state-any to inspect diagnostics.",
            json!({ "plugin_id": plugin_id, "state": candidate.state }),
            false,
        )));
    }

    Ok(candidate)
}

fn plugin_error(
    category: CapabilityErrorCategory,
    code: impl Into<String>,
    message: impl Into<String>,
    details: Value,
    retryable: bool,
) -> PluginError {
    PluginError {
        category,
        code: code.into(),
        message: message.into(),
        details,
        target: None,
        retryable,
        redaction: RedactionStatus::NotRequired,
    }
}

fn success_envelope<T: Serialize>(data: T) -> JsonSuccessEnvelope<T> {
    success_envelope_with_warnings(data, Vec::new())
}

fn success_envelope_with_warnings<T: Serialize>(
    data: T,
    warnings: Vec<PluginWarning>,
) -> JsonSuccessEnvelope<T> {
    JsonSuccessEnvelope {
        ok: true,
        schema_version: PLUGIN_CLI_SCHEMA_VERSION,
        command: "plugin",
        data,
        warnings,
    }
}

fn print_plugin_error(error: PluginError) -> Result<(), VoidbError> {
    print_json(&JsonErrorEnvelope {
        ok: false,
        schema_version: PLUGIN_CLI_SCHEMA_VERSION,
        command: "plugin",
        error,
    })
}

fn print_json(value: &impl Serialize) -> Result<(), VoidbError> {
    let output = serde_json::to_string_pretty(value)
        .map_err(|e| VoidbError::Plugin(format!("Failed to serialize JSON output: {}", e)))?;
    println!("{}", output);
    Ok(())
}

#[derive(Debug, Clone, Copy)]
struct PluginListOptions {
    state_filter: Option<ProcessPluginCandidateState>,
    include_shadowed: bool,
    include_invalid: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PluginOutputFormat {
    Json,
    Table,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct UpdateOptions {
    allow_downgrade: bool,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum PluginPackageOperation {
    Install,
    Update,
}

impl PluginPackageOperation {
    fn as_str(self) -> &'static str {
        match self {
            Self::Install => "install",
            Self::Update => "update",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum PluginLifecycleOperation {
    Disable,
    Enable,
    Uninstall,
}

impl PluginLifecycleOperation {
    fn as_str(self) -> &'static str {
        match self {
            Self::Disable => "disable",
            Self::Enable => "enable",
            Self::Uninstall => "uninstall",
        }
    }
}

#[derive(Debug, Serialize)]
struct PluginPackageOperationResult {
    data: PluginPackageOperationData,
    warnings: Vec<PluginWarning>,
}

#[derive(Debug, Serialize)]
struct PluginPackageOperationData {
    operation: PluginPackageOperation,
    plugin: PluginPackageItem,
}

#[derive(Debug, Serialize)]
struct PluginPackageItem {
    id: String,
    installed_version: String,
    candidate_state: ProcessPluginCandidateState,
    manifest_path: String,
    active_plugin_dir: String,
    install_root: String,
    install_record_path: String,
    manifest_digest: String,
    package_digest: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    previous_version: Option<PluginPreviousVersionItem>,
}

#[derive(Debug, Serialize)]
struct PluginPreviousVersionItem {
    version: String,
    path: String,
    manifest_digest: Option<String>,
    package_digest: Option<String>,
    recorded_at: chrono::DateTime<Utc>,
}

impl From<ProcessPluginPreviousVersionRecord> for PluginPreviousVersionItem {
    fn from(record: ProcessPluginPreviousVersionRecord) -> Self {
        Self {
            version: record.version,
            path: record.path.to_string_lossy().into_owned(),
            manifest_digest: record.manifest_digest,
            package_digest: record.package_digest,
            recorded_at: record.recorded_at,
        }
    }
}

#[derive(Debug, Serialize)]
struct PluginLifecycleOperationResult {
    data: PluginLifecycleOperationData,
    warnings: Vec<PluginWarning>,
}

#[derive(Debug, Serialize)]
struct PluginLifecycleOperationData {
    operation: PluginLifecycleOperation,
    plugin: PluginLifecycleItem,
}

#[derive(Debug, Serialize)]
struct PluginLifecycleItem {
    id: String,
    installed_version: String,
    enabled: bool,
    active_plugin_dir: String,
    active_package_present: bool,
    install_root: String,
    install_record_path: String,
    removed_active_package: bool,
    preserved_profiles: bool,
    preserved_credentials: bool,
    preserved_plugin_data: bool,
    preserved_install_metadata: bool,
}

#[derive(Debug, Clone, Copy, Default)]
struct IncludeParts {
    runtime_detail: bool,
    schemas: bool,
    requirements: bool,
    diagnostics: bool,
}

impl IncludeParts {
    fn from_matches(matches: &ArgMatches) -> Result<Self, VoidbError> {
        let mut include = Self::default();
        let Some(parts) = matches.get_one::<String>("include") else {
            return Ok(include);
        };

        for part in parts
            .split(',')
            .map(str::trim)
            .filter(|part| !part.is_empty())
        {
            match part {
                "runtime" => include.runtime_detail = true,
                "connections" | "capabilities" | "ui" => {}
                "schemas" => include.schemas = true,
                "requirements" => include.requirements = true,
                "diagnostics" => include.diagnostics = true,
                other => {
                    return Err(VoidbError::Plugin(format!(
                        "Unsupported plugin describe include part '{}'",
                        other
                    )));
                }
            }
        }

        Ok(include)
    }
}

#[derive(Debug, Serialize)]
struct JsonSuccessEnvelope<T> {
    ok: bool,
    schema_version: u32,
    command: &'static str,
    data: T,
    warnings: Vec<PluginWarning>,
}

#[derive(Debug, Serialize)]
struct JsonErrorEnvelope {
    ok: bool,
    schema_version: u32,
    command: &'static str,
    error: PluginError,
}

#[derive(Debug, Serialize)]
struct PluginWarning {
    code: String,
    message: String,
    details: Value,
}

#[derive(Debug, Serialize)]
struct PluginError {
    category: CapabilityErrorCategory,
    code: String,
    message: String,
    details: Value,
    target: Option<Value>,
    retryable: bool,
    redaction: RedactionStatus,
}

#[derive(Debug, Serialize)]
struct PluginListData {
    plugins: Vec<PluginListItem>,
}

#[derive(Debug, Serialize)]
struct PluginListItem {
    id: String,
    name: Option<String>,
    version: Option<String>,
    protocol_version: Option<String>,
    state: ProcessPluginCandidateState,
    manifest_path: String,
    source: PluginSourceItem,
    transport: Option<String>,
    capability_count: usize,
    tui: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    diagnostics: Vec<ProcessPluginDiagnostic>,
}

impl PluginListItem {
    fn from_candidate(candidate: &ProcessPluginCandidate) -> Self {
        let diagnostics = if candidate.state == ProcessPluginCandidateState::Invalid {
            candidate.diagnostics.clone()
        } else {
            Vec::new()
        };

        Self {
            id: candidate.id.clone(),
            name: candidate.name.clone(),
            version: candidate.version.clone(),
            protocol_version: candidate.protocol_version.clone(),
            state: candidate.state,
            manifest_path: candidate.manifest_path.to_string_lossy().into_owned(),
            source: PluginSourceItem {
                kind: candidate.source.kind,
                trust_level: candidate.source.trust_level,
                precedence: candidate.source.precedence,
            },
            transport: candidate.transport.clone(),
            capability_count: candidate.capability_count,
            tui: candidate.tui,
            diagnostics,
        }
    }
}

#[derive(Debug, Serialize)]
struct PluginSourceItem {
    kind: voidb_core::ProcessPluginRootKind,
    trust_level: voidb_core::ProcessPluginTrustLevel,
    precedence: usize,
}

#[derive(Debug, Serialize)]
struct PluginDescribeData {
    plugin: PluginDescription,
}

#[derive(Debug, Serialize)]
struct PluginDescription {
    id: String,
    name: Option<String>,
    version: Option<String>,
    protocol_version: Option<String>,
    state: ProcessPluginCandidateState,
    manifest_path: String,
    runtime: Option<RuntimeDescription>,
    connections: Option<ConnectionsDescription>,
    capabilities: Vec<CapabilityDescription>,
    ui: Option<UiDescription>,
    #[serde(skip_serializing_if = "Option::is_none")]
    requirements: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    schemas: Option<BTreeMap<String, Value>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    diagnostics: Vec<ProcessPluginDiagnostic>,
}

impl PluginDescription {
    fn from_candidate(candidate: &ProcessPluginCandidate, include: IncludeParts) -> Self {
        let manifest = candidate.manifest.as_ref();

        Self {
            id: candidate.id.clone(),
            name: candidate.name.clone(),
            version: candidate.version.clone(),
            protocol_version: candidate.protocol_version.clone(),
            state: candidate.state,
            manifest_path: candidate.manifest_path.to_string_lossy().into_owned(),
            runtime: manifest.map(|manifest| RuntimeDescription::from_manifest(manifest, include)),
            connections: manifest.map(ConnectionsDescription::from_manifest),
            capabilities: manifest
                .map(|manifest| {
                    let mut capabilities = manifest
                        .capabilities
                        .iter()
                        .map(|capability| CapabilityDescription {
                            id: capability.id.clone(),
                            qualified_id: format!("{}.{}", manifest.id, capability.id),
                            description: capability.description.clone(),
                            permissions: capability.permissions.clone(),
                            destructive: capability.destructive,
                            streaming: capability.streaming,
                            execution_mode: capability.execution_mode,
                            session_handoff: capability.session_handoff.clone(),
                            connection_required: capability.connection_required,
                            supports_dry_run: capability.supports_dry_run,
                            default_timeout_ms: capability.default_timeout_ms,
                        })
                        .collect::<Vec<_>>();
                    capabilities.sort_by(|left, right| left.id.cmp(&right.id));
                    capabilities
                })
                .unwrap_or_default(),
            ui: manifest.and_then(UiDescription::from_manifest),
            requirements: include
                .requirements
                .then(|| {
                    manifest.and_then(|manifest| serde_json::to_value(&manifest.requirements).ok())
                })
                .flatten(),
            schemas: include
                .schemas
                .then(|| load_schema_documents(candidate))
                .flatten(),
            diagnostics: if include.diagnostics {
                candidate.diagnostics.clone()
            } else {
                Vec::new()
            },
        }
    }
}

#[derive(Debug, Serialize)]
struct RuntimeDescription {
    transport: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    command_ref: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    arg_count: Option<usize>,
}

impl RuntimeDescription {
    fn from_manifest(manifest: &ProcessPluginManifest, include: IncludeParts) -> Self {
        Self {
            transport: manifest.runtime.transport.clone(),
            command_ref: include
                .runtime_detail
                .then(|| manifest.runtime.command.clone()),
            arg_count: include
                .runtime_detail
                .then_some(manifest.runtime.args.len()),
        }
    }
}

#[derive(Debug, Serialize)]
struct ConnectionsDescription {
    profile_schema_ref: String,
    secret_classes: Vec<String>,
}

impl ConnectionsDescription {
    fn from_manifest(manifest: &ProcessPluginManifest) -> Self {
        Self {
            profile_schema_ref: manifest.connections.profile_schema.clone(),
            secret_classes: manifest.connections.secret_classes.clone(),
        }
    }
}

#[derive(Debug, Serialize)]
struct CapabilityDescription {
    id: String,
    qualified_id: String,
    description: String,
    permissions: Vec<String>,
    destructive: bool,
    streaming: bool,
    execution_mode: voidb_core::CapabilityExecutionMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_handoff: Option<voidb_core::CapabilitySessionHandoff>,
    connection_required: bool,
    supports_dry_run: bool,
    default_timeout_ms: Option<u64>,
}

#[derive(Debug, Serialize)]
struct UiDescription {
    tui: bool,
    entrypoint_capability: Option<String>,
    raw_input: bool,
}

impl UiDescription {
    fn from_manifest(manifest: &ProcessPluginManifest) -> Option<Self> {
        manifest.ui.as_ref().map(|ui| Self {
            tui: ui.tui,
            entrypoint_capability: ui.entrypoint_capability.clone(),
            raw_input: ui.raw_input,
        })
    }
}

fn load_schema_documents(candidate: &ProcessPluginCandidate) -> Option<BTreeMap<String, Value>> {
    let mut schemas = BTreeMap::new();
    for (label, path) in &candidate.resolved_schema_paths {
        let content = std::fs::read_to_string(path).ok()?;
        let value = serde_json::from_str::<Value>(&content).ok()?;
        schemas.insert(label.clone(), value);
    }
    Some(schemas)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};
    use voidb_core::{
        ProcessPluginRootKind, ProcessPluginRuntime, ProcessPluginSource, ProcessPluginTrustLevel,
        ProcessPluginUi,
    };

    #[test]
    fn list_hides_invalid_and_shadowed_by_default() {
        let discovery = discovery_with_candidates(vec![
            candidate("mysql", ProcessPluginCandidateState::Available),
            candidate("broken", ProcessPluginCandidateState::Invalid),
            candidate("mysql", ProcessPluginCandidateState::Shadowed),
        ]);

        let default_items = plugin_list_items(
            &discovery,
            PluginListOptions {
                state_filter: None,
                include_shadowed: false,
                include_invalid: false,
            },
        );
        assert_eq!(default_items.len(), 1);
        assert_eq!(default_items[0].id, "mysql");

        let all_items = plugin_list_items(
            &discovery,
            PluginListOptions {
                state_filter: None,
                include_shadowed: true,
                include_invalid: true,
            },
        );
        assert_eq!(all_items.len(), 3);
    }

    #[test]
    fn describe_requires_state_any_for_invalid_candidate() {
        let discovery = discovery_with_candidates(vec![candidate(
            "broken",
            ProcessPluginCandidateState::Invalid,
        )]);

        let error =
            select_candidate_for_describe(&discovery, "broken", false).expect_err("blocked");
        assert_eq!(error.code, "unavailable.plugin_candidate_not_available");

        let candidate =
            select_candidate_for_describe(&discovery, "broken", true).expect("state-any");
        assert_eq!(candidate.id, "broken");
    }

    #[test]
    fn describe_omits_diagnostics_until_requested() {
        let candidate = candidate("mysql", ProcessPluginCandidateState::Available);
        let without_diagnostics = serde_json::to_value(PluginDescription::from_candidate(
            &candidate,
            IncludeParts::default(),
        ))
        .expect("serialize description");
        let with_diagnostics = serde_json::to_value(PluginDescription::from_candidate(
            &candidate,
            IncludeParts {
                diagnostics: true,
                ..IncludeParts::default()
            },
        ))
        .expect("serialize description");

        assert!(without_diagnostics.get("diagnostics").is_none());
        assert_eq!(
            without_diagnostics["capabilities"][0]["execution_mode"],
            "stateless"
        );
        assert!(
            without_diagnostics["capabilities"][0]
                .get("session_handoff")
                .is_none()
        );
        assert!(with_diagnostics.get("diagnostics").is_some());
    }

    #[test]
    fn list_includes_source_trust_level() {
        let item = PluginListItem::from_candidate(&candidate(
            "mysql",
            ProcessPluginCandidateState::Available,
        ));
        let value = serde_json::to_value(item).expect("serialize list item");

        assert_eq!(value["source"]["kind"], "user");
        assert_eq!(value["source"]["trust_level"], "user_installed");
    }

    #[test]
    fn success_envelope_is_versioned_for_agents() {
        let value = serde_json::to_value(success_envelope(PluginListData {
            plugins: Vec::new(),
        }))
        .expect("serialize envelope");

        assert_eq!(value["ok"], true);
        assert_eq!(value["schema_version"], PLUGIN_CLI_SCHEMA_VERSION);
        assert_eq!(value["command"], "plugin");
        assert_eq!(value["warnings"], serde_json::json!([]));
        assert!(value["data"]["plugins"].as_array().is_some());
    }

    #[test]
    fn install_command_requires_explicit_source_path() {
        let install_command = PluginCliPlugin::new()
            .commands()
            .into_iter()
            .find(|command| command.get_name() == "install")
            .expect("install command");
        let error = install_command
            .try_get_matches_from(["install", "--format", "json"])
            .expect_err("source is required");

        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn install_package_moves_plugin_and_writes_record() {
        let source = TempDir::new("install-source");
        let install_root = TempDir::new("install-root");
        write_valid_plugin(source.path(), "redis", "redis", "0.1.0", "connection.read");

        let result = install_plugin_package(
            ProcessPluginPackageSource::local_directory(source.path()),
            install_root.path().to_path_buf(),
        )
        .expect("install package");

        assert_eq!(result.data.operation, PluginPackageOperation::Install);
        assert_eq!(result.data.plugin.id, "redis");
        assert_eq!(result.data.plugin.installed_version, "0.1.0");
        assert!(
            install_root
                .path()
                .join("redis")
                .join("plugin.toml")
                .is_file()
        );
        let record = read_process_plugin_install_record(&process_plugin_install_record_path(
            install_root.path(),
            "redis",
        ))
        .expect("read install record");
        assert_eq!(record.plugin_id, "redis");
        assert_eq!(record.installed_version, "0.1.0");
        assert!(record.previous_version.is_none());
    }

    #[test]
    fn update_package_preserves_previous_version_metadata() {
        let install_source = TempDir::new("update-install-source");
        let update_source = TempDir::new("update-source");
        let install_root = TempDir::new("update-install-root");
        write_valid_plugin(
            install_source.path(),
            "redis",
            "redis",
            "0.1.0",
            "connection.read",
        );
        write_valid_plugin(
            update_source.path(),
            "redis",
            "redis",
            "0.2.0",
            "connection.write",
        );

        install_plugin_package(
            ProcessPluginPackageSource::local_directory(install_source.path()),
            install_root.path().to_path_buf(),
        )
        .expect("install package");
        let result = update_plugin_package(
            "redis",
            ProcessPluginPackageSource::local_directory(update_source.path()),
            install_root.path().to_path_buf(),
            UpdateOptions {
                allow_downgrade: false,
            },
        )
        .expect("update package");

        assert_eq!(result.data.operation, PluginPackageOperation::Update);
        assert_eq!(result.data.plugin.installed_version, "0.2.0");
        assert!(
            result
                .warnings
                .iter()
                .any(|warning| warning.code == "plugin.update_permissions_changed")
        );
        let previous = result
            .data
            .plugin
            .previous_version
            .as_ref()
            .expect("previous version");
        assert_eq!(previous.version, "0.1.0");
        assert!(Path::new(&previous.path).join("plugin.toml").is_file());
        let active_manifest =
            fs::read_to_string(install_root.path().join("redis").join("plugin.toml"))
                .expect("read active manifest");
        assert!(active_manifest.contains("version = \"0.2.0\""));
    }

    #[test]
    fn update_package_rejects_downgrade_without_flag() {
        let install_source = TempDir::new("downgrade-install-source");
        let update_source = TempDir::new("downgrade-source");
        let install_root = TempDir::new("downgrade-install-root");
        write_valid_plugin(
            install_source.path(),
            "redis",
            "redis",
            "0.2.0",
            "connection.read",
        );
        write_valid_plugin(
            update_source.path(),
            "redis",
            "redis",
            "0.1.0",
            "connection.read",
        );

        install_plugin_package(
            ProcessPluginPackageSource::local_directory(install_source.path()),
            install_root.path().to_path_buf(),
        )
        .expect("install package");
        let error = update_plugin_package(
            "redis",
            ProcessPluginPackageSource::local_directory(update_source.path()),
            install_root.path().to_path_buf(),
            UpdateOptions {
                allow_downgrade: false,
            },
        )
        .expect_err("reject downgrade");

        assert_eq!(error.code, "conflict.plugin_downgrade_blocked");
        let active_manifest =
            fs::read_to_string(install_root.path().join("redis").join("plugin.toml"))
                .expect("read active manifest");
        assert!(active_manifest.contains("version = \"0.2.0\""));
    }

    #[test]
    fn disable_and_enable_toggle_install_record_and_discovery_state() {
        let source = TempDir::new("lifecycle-source");
        let install_root = TempDir::new("lifecycle-install-root");
        write_valid_plugin(source.path(), "redis", "redis", "0.1.0", "connection.read");
        install_plugin_package(
            ProcessPluginPackageSource::local_directory(source.path()),
            install_root.path().to_path_buf(),
        )
        .expect("install package");

        let disabled = apply_lifecycle_operation(
            "redis",
            install_root.path().to_path_buf(),
            PluginLifecycleOperation::Disable,
        )
        .expect("disable plugin");

        assert!(!disabled.data.plugin.enabled);
        let disabled_discovery = discover_process_plugins_from_roots(vec![ProcessPluginRoot::new(
            install_root.path(),
            ProcessPluginRootKind::User,
            0,
        )]);
        assert_eq!(
            disabled_discovery.candidates[0].state,
            ProcessPluginCandidateState::Disabled
        );

        let enabled = apply_lifecycle_operation(
            "redis",
            install_root.path().to_path_buf(),
            PluginLifecycleOperation::Enable,
        )
        .expect("enable plugin");

        assert!(enabled.data.plugin.enabled);
        let enabled_discovery = discover_process_plugins_from_roots(vec![ProcessPluginRoot::new(
            install_root.path(),
            ProcessPluginRootKind::User,
            0,
        )]);
        assert_eq!(
            enabled_discovery.candidates[0].state,
            ProcessPluginCandidateState::Available
        );
    }

    #[test]
    fn package_creates_archive_and_validates_cleanly() {
        let source = TempDir::new("package-source");
        let dist = TempDir::new("package-dist");
        write_valid_plugin(source.path(), "redis", "redis", "0.1.0", "connection.read");

        let archive_path = dist.path().join("redis-0.1.0.tar.zst");
        let result = package_process_plugin(
            source.path().join("redis"),
            &archive_path,
            ProcessPluginPackageFormat::TarZst,
        )
        .expect("package plugin");

        assert_eq!(result.plugin_id, "redis");
        assert_eq!(result.version, "0.1.0");
        assert!(archive_path.is_file());
        assert!(!result.package_digest.is_empty());
        assert!(!result.files.is_empty());

        // Now install from the packaged archive into a fresh install root
        let install_root = TempDir::new("packaged-install-root");
        let installed = install_plugin_package(
            ProcessPluginPackageSource::local_archive(&archive_path),
            install_root.path().to_path_buf(),
        )
        .expect("install packaged archive");

        assert_eq!(installed.data.plugin.id, "redis");
        assert_eq!(installed.data.plugin.installed_version, "0.1.0");
        assert_eq!(
            installed.data.plugin.candidate_state,
            ProcessPluginCandidateState::Available
        );
    }

    #[test]
    fn uninstall_removes_package_but_preserves_install_metadata() {
        let source = TempDir::new("uninstall-source");
        let install_root = TempDir::new("uninstall-root");
        write_valid_plugin(source.path(), "redis", "redis", "0.1.0", "connection.read");
        install_plugin_package(
            ProcessPluginPackageSource::local_directory(source.path()),
            install_root.path().to_path_buf(),
        )
        .expect("install package");

        let uninstalled = apply_lifecycle_operation(
            "redis",
            install_root.path().to_path_buf(),
            PluginLifecycleOperation::Uninstall,
        )
        .expect("uninstall plugin");

        assert!(uninstalled.data.plugin.removed_active_package);
        assert!(!uninstalled.data.plugin.active_package_present);
        assert!(uninstalled.data.plugin.preserved_profiles);
        assert!(uninstalled.data.plugin.preserved_credentials);
        assert!(uninstalled.data.plugin.preserved_plugin_data);
        assert!(uninstalled.data.plugin.preserved_install_metadata);
        assert!(!install_root.path().join("redis").exists());
        let record = read_process_plugin_install_record(&process_plugin_install_record_path(
            install_root.path(),
            "redis",
        ))
        .expect("read install record");
        assert!(!record.enabled);
    }

    fn discovery_with_candidates(
        candidates: Vec<ProcessPluginCandidate>,
    ) -> ProcessPluginDiscovery {
        ProcessPluginDiscovery {
            roots: Vec::new(),
            candidates,
        }
    }

    fn candidate(id: &str, state: ProcessPluginCandidateState) -> ProcessPluginCandidate {
        let manifest = ProcessPluginManifest {
            schema: None,
            id: id.into(),
            name: id.into(),
            version: "0.1.0".into(),
            protocol_version: "1".into(),
            description: None,
            license: None,
            homepage: None,
            runtime: ProcessPluginRuntime {
                command: "voidb-plugin-test".into(),
                args: Vec::new(),
                transport: "stdio-jsonrpc".into(),
                env: BTreeMap::new(),
            },
            connections: voidb_core::ProcessPluginConnections {
                profile_schema: "schemas/profile.schema.json".into(),
                secret_classes: vec!["password".into()],
            },
            capabilities: vec![voidb_core::ProcessPluginCapability {
                id: "query".into(),
                description: "Query data.".into(),
                input_schema: "schemas/query-input.schema.json".into(),
                output_schema: "schemas/query-output.schema.json".into(),
                permissions: vec!["connection.read".into()],
                authorization: Default::default(),
                risk: None,
                destructive: false,
                streaming: false,
                execution_mode: voidb_core::CapabilityExecutionMode::Stateless,
                session_handoff: None,
                connection_required: true,
                required_secret_classes: Vec::new(),
                supports_dry_run: false,
                default_timeout_ms: Some(30_000),
            }],
            ui: Some(ProcessPluginUi {
                tui: false,
                entrypoint_capability: None,
                raw_input: false,
            }),
            requirements: None,
        };

        ProcessPluginCandidate {
            id: id.into(),
            name: Some(id.into()),
            version: Some("0.1.0".into()),
            protocol_version: Some("1".into()),
            manifest_path: PathBuf::from(format!("/plugins/{id}/plugin.toml")),
            source: ProcessPluginSource {
                root: PathBuf::from("/plugins"),
                plugin_dir: PathBuf::from(format!("/plugins/{id}")),
                kind: ProcessPluginRootKind::User,
                trust_level: ProcessPluginTrustLevel::UserInstalled,
                precedence: 0,
            },
            state,
            transport: Some("stdio-jsonrpc".into()),
            capability_count: 1,
            tui: false,
            diagnostics: vec![ProcessPluginDiagnostic {
                severity: voidb_core::ProcessPluginDiagnosticSeverity::Warning,
                code: "test.warning".into(),
                message: "Test warning.".into(),
                details: Box::new(Value::Null),
            }],
            manifest: Some(manifest),
            resolved_runtime_command: None,
            resolved_schema_paths: BTreeMap::new(),
        }
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
            let path = std::env::temp_dir().join(format!("voidb-cli-plugin-{label}-{nonce}"));
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

    fn write_valid_plugin(root: &Path, dir: &str, id: &str, version: &str, permission: &str) {
        let plugin_dir = root.join(dir);
        let schemas = plugin_dir.join("schemas");
        let bin = plugin_dir.join("bin");
        fs::create_dir_all(&schemas).expect("create schemas dir");
        fs::create_dir_all(&bin).expect("create bin dir");

        for schema_name in [
            "profile.schema.json",
            "query-input.schema.json",
            "query-output.schema.json",
        ] {
            fs::write(schemas.join(schema_name), r#"{"type":"object"}"#).expect("write schema");
        }

        let command = bin.join("voidb-plugin-test");
        fs::write(&command, "#!/bin/sh\nexit 0\n").expect("write command");
        make_executable(&command);

        let manifest = format!(
            r#"
id = "{id}"
name = "{id}"
version = "{version}"
protocol_version = "1"
description = "Test plugin."

[runtime]
command = "voidb-plugin-test"
args = []
transport = "stdio-jsonrpc"

[connections]
profile_schema = "schemas/profile.schema.json"
secret_classes = ["password"]

[[capabilities]]
id = "query"
description = "Query data."
input_schema = "schemas/query-input.schema.json"
output_schema = "schemas/query-output.schema.json"
permissions = ["{permission}"]
destructive = false
streaming = false
connection_required = true
required_secret_classes = []
supports_dry_run = false
default_timeout_ms = 30000

[ui]
tui = false

[requirements]
voidb_core = ">=0.1.0"
platforms = ["{platform}"]
"#,
            platform = current_platform(),
        );
        fs::write(plugin_dir.join("plugin.toml"), manifest).expect("write manifest");
    }

    fn current_platform() -> &'static str {
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

    #[cfg(unix)]
    fn make_executable(path: &Path) {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = fs::metadata(path).expect("metadata").permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions).expect("chmod");
    }

    #[cfg(not(unix))]
    fn make_executable(_path: &Path) {}

    #[test]
    fn registry_index_builds_and_updates_manifest_cleanly() {
        let source = TempDir::new("registry-source");
        let dist = TempDir::new("registry-dist");
        write_valid_plugin(source.path(), "s3", "s3", "0.3.0", "connection.read");

        let index_path = dist.path().join("index.json");

        // 1. Index local plugin directory
        let plugin_dir = source.path().join("s3");
        let plugin_cli = PluginCliPlugin::new();
        let cmd = Command::new("plugin").subcommands(plugin_cli.commands());

        let matches = cmd.clone().get_matches_from(vec![
            "plugin",
            "registry-index",
            plugin_dir.to_str().unwrap(),
            "--output",
            index_path.to_str().unwrap(),
            "--base-url",
            "https://downloads.voidb.dev/plugins",
            "--registry-name",
            "Test VoidB Registry",
        ]);

        let (subcmd, submatches) = matches.subcommand().expect("subcommand matches");
        assert_eq!(subcmd, "registry-index");
        handle_registry_index(submatches).expect("handle_registry_index");

        assert!(index_path.is_file());
        let index = PluginRegistryIndex::load_from_file(&index_path).expect("load index");
        assert_eq!(index.registry_name, Some("Test VoidB Registry".to_string()));
        assert_eq!(index.plugins.len(), 1);

        let s3 = index.get_plugin("s3").expect("s3 plugin found");
        assert_eq!(s3.latest_version, "0.3.0");
        assert_eq!(s3.category, Some(PluginCategory::Storage));
        assert_eq!(s3.versions.len(), 1);
        assert_eq!(s3.versions[0].packages.len(), 1);
        assert_eq!(
            s3.versions[0].packages[0].url,
            "https://downloads.voidb.dev/plugins/s3-0.3.0.tar.gz"
        );
        assert!(!s3.versions[0].packages[0].sha256.is_empty());

        // 2. Package into tar.zst and index the archive (merging into existing index)
        let archive_path = dist.path().join("s3-0.3.0.tar.zst");
        package_process_plugin(&plugin_dir, &archive_path, ProcessPluginPackageFormat::TarZst)
            .expect("package s3");

        let matches2 = cmd.get_matches_from(vec![
            "plugin",
            "registry-index",
            archive_path.to_str().unwrap(),
            "--output",
            index_path.to_str().unwrap(),
            "--merge",
            index_path.to_str().unwrap(),
        ]);
        let (_, submatches2) = matches2.subcommand().unwrap();
        handle_registry_index(submatches2).expect("handle_registry_index merge");

        let updated_index = PluginRegistryIndex::load_from_file(&index_path).expect("load updated index");
        let updated_s3 = updated_index.get_plugin("s3").unwrap();
        assert_eq!(updated_s3.versions[0].packages.len(), 2);
        assert!(updated_s3.versions[0].packages.iter().any(|p| p.format == "tar.zst"));
        assert!(updated_s3.versions[0].packages.iter().any(|p| p.format == "tar.gz"));
    }

    #[tokio::test]
    async fn package_sign_verify_and_install_gate() {
        let source = TempDir::new("sign-source");
        let dist = TempDir::new("sign-dist");
        let install_root = TempDir::new("sign-install-root");
        write_valid_plugin(source.path(), "redis", "redis", "0.1.0", "connection.read");

        let archive_path = dist.path().join("redis-0.1.0.tar.zst");
        package_process_plugin(
            source.path().join("redis"),
            &archive_path,
            ProcessPluginPackageFormat::TarZst,
        )
        .expect("package plugin");

        let (sk, vk) = generate_signing_keypair();
        let pub_hex = hex::encode(vk.to_bytes());
        let priv_hex = hex::encode(sk.to_bytes());

        let plugin_cli = PluginCliPlugin::new();
        let cmd = Command::new("plugin").subcommands(plugin_cli.commands());

        // 1. Sign package using generated private key
        let sign_matches = cmd.clone().get_matches_from(vec![
            "plugin",
            "sign",
            archive_path.to_str().unwrap(),
            "--private-key",
            &priv_hex,
        ]);
        let (_, sign_sub) = sign_matches.subcommand().unwrap();
        handle_sign(sign_sub).expect("handle_sign");

        let sig_path = default_signature_path(&archive_path);
        assert!(sig_path.is_file());

        // 2. Verify signature using public key
        let verify_matches = cmd.clone().get_matches_from(vec![
            "plugin",
            "verify",
            archive_path.to_str().unwrap(),
            "--public-key",
            &pub_hex,
        ]);
        let (_, verify_sub) = verify_matches.subcommand().unwrap();
        handle_verify(verify_sub).expect("handle_verify");

        // 3. Install package with signature gate (--verify-key and --require-signature)
        let install_matches = cmd.get_matches_from(vec![
            "plugin",
            "install",
            archive_path.to_str().unwrap(),
            "--install-root",
            install_root.path().to_str().unwrap(),
            "--verify-key",
            &pub_hex,
            "--require-signature",
        ]);
        let (_, install_sub) = install_matches.subcommand().unwrap();
        handle_install(install_sub).await.expect("handle_install with valid signature");

        let record_path = process_plugin_install_record_path(install_root.path(), "redis");
        assert!(record_path.is_file());
    }

    #[tokio::test]
    async fn registry_subcommands_list_and_update() {
        let temp = TempDir::new("registry-test");
        let index_file = temp.path().join("index.json");

        let mut index = PluginRegistryIndex::new();
        index.upsert_plugin(RegistryPluginEntry {
            id: "sample".into(),
            name: "Sample Plugin".into(),
            description: Some("A test sample plugin".into()),
            homepage: None,
            license: Some("Apache-2.0".into()),
            category: Some(PluginCategory::Database),
            tags: vec!["sample".into()],
            capabilities: vec!["query".into()],
            latest_version: "1.0.0".into(),
            versions: vec![],
        });
        index.save_to_file(&index_file).expect("save test index");

        let plugin_cli = PluginCliPlugin::new();
        let cmd = Command::new("plugin").subcommands(plugin_cli.commands());

        // Test list with file url
        let list_url = format!("file://{}", index_file.display());
        let matches = cmd.clone().get_matches_from(vec![
            "plugin",
            "registry",
            "list",
            "--url",
            &list_url,
        ]);
        let (_, sub) = matches.subcommand().unwrap();
        let res = handle_registry(sub).await;
        assert!(res.is_ok());

        // Test search
        let search_matches = cmd.clone().get_matches_from(vec![
            "plugin",
            "search",
            "sample",
            "--registry-url",
            &list_url,
        ]);
        let (_, search_sub) = search_matches.subcommand().unwrap();
        let search_res = handle_search(search_sub).await;
        assert!(search_res.is_ok());
    }

    #[tokio::test]
    async fn test_online_registry_install_and_update() {
        let source = TempDir::new("online-source");
        let dist = TempDir::new("online-dist");
        let install_root = TempDir::new("online-install-root");
        write_valid_plugin(source.path(), "myplug", "myplug", "1.0.0", "storage.read");

        let pkg_path = dist.path().join("myplug-1.0.0.tar.zst");
        package_process_plugin(
            source.path().join("myplug"),
            &pkg_path,
            ProcessPluginPackageFormat::TarZst,
        )
        .expect("package");

        let validation = validate_process_plugin_package(
            ProcessPluginPackageSource::local_archive(&pkg_path),
            install_root.path().join("staging"),
        )
        .expect("validate package");
        let sha256_hex = validation.package_digest;

        let index_file = dist.path().join("index.json");
        let mut index = PluginRegistryIndex::new();
        index.upsert_plugin(RegistryPluginEntry {
            id: "myplug".into(),
            name: "My Plugin".into(),
            description: Some("Online installable test plugin".into()),
            homepage: None,
            license: Some("Apache-2.0".into()),
            category: Some(PluginCategory::Storage),
            tags: vec!["myplug".into()],
            capabilities: vec!["storage.read".into()],
            latest_version: "1.0.0".into(),
            versions: vec![RegistryPluginVersion {
                version: "1.0.0".into(),
                protocol_version: "1".into(),
                released_at: Some(Utc::now()),
                voidb_core: None,
                platforms: vec![voidb_core::process_plugin::current_platform().into()],
                signature_scheme: None,
                packages: vec![RegistryPackageArtifact {
                    filename: "myplug-1.0.0.tar.zst".into(),
                    format: "tar.zst".into(),
                    target: Some(voidb_core::process_plugin::current_platform().into()),
                    url: format!("file://{}", pkg_path.display()),
                    sha256: sha256_hex,
                    size_bytes: Some(fs::metadata(&pkg_path).map(|m| m.len()).unwrap_or(0)),
                    signature: None,
                }],
            }],
        });
        index.save_to_file(&index_file).expect("save index");

        let plugin_cli = PluginCliPlugin::new();
        let cmd = Command::new("plugin").subcommands(plugin_cli.commands());

        // Install by name from online registry
        let install_matches = cmd.clone().get_matches_from(vec![
            "plugin",
            "install",
            "myplug",
            "--registry-url",
            &format!("file://{}", index_file.display()),
            "--install-root",
            install_root.path().to_str().unwrap(),
        ]);
        let (_, install_sub) = install_matches.subcommand().unwrap();
        handle_install(install_sub).await.expect("online install myplug");

        let record_path = process_plugin_install_record_path(install_root.path(), "myplug");
        assert!(record_path.is_file());

        // Update plugin online to 1.1.0
        let source_v2 = TempDir::new("online-source-v2");
        write_valid_plugin(source_v2.path(), "myplug", "myplug", "1.1.0", "storage.read");
        let pkg_v2_path = dist.path().join("myplug-1.1.0.tar.zst");
        package_process_plugin(
            source_v2.path().join("myplug"),
            &pkg_v2_path,
            ProcessPluginPackageFormat::TarZst,
        )
        .expect("package v2");

        let validation_v2 = validate_process_plugin_package(
            ProcessPluginPackageSource::local_archive(&pkg_v2_path),
            install_root.path().join("staging_v2"),
        )
        .expect("validate v2 package");

        let mut entry = index.get_plugin("myplug").unwrap().clone();
        entry.latest_version = "1.1.0".into();
        entry.versions.push(RegistryPluginVersion {
            version: "1.1.0".into(),
            protocol_version: "1".into(),
            released_at: Some(Utc::now()),
            voidb_core: None,
            platforms: vec![voidb_core::process_plugin::current_platform().into()],
            signature_scheme: None,
            packages: vec![RegistryPackageArtifact {
                filename: "myplug-1.1.0.tar.zst".into(),
                format: "tar.zst".into(),
                target: Some(voidb_core::process_plugin::current_platform().into()),
                url: format!("file://{}", pkg_v2_path.display()),
                sha256: validation_v2.package_digest,
                size_bytes: Some(fs::metadata(&pkg_v2_path).map(|m| m.len()).unwrap_or(0)),
                signature: None,
            }],
        });
        index.upsert_plugin(entry);
        index.save_to_file(&index_file).expect("save updated index");

        let update_matches = cmd.clone().get_matches_from(vec![
            "plugin",
            "update",
            "myplug",
            "--registry-url",
            &format!("file://{}", index_file.display()),
            "--install-root",
            install_root.path().to_str().unwrap(),
        ]);
        let (_, update_sub) = update_matches.subcommand().unwrap();
        handle_update(update_sub).await.expect("online update myplug");

        let record = read_process_plugin_install_record(&record_path).expect("read updated record");
        assert_eq!(record.installed_version, "1.1.0");
        assert!(record.previous_version.is_some());
        assert_eq!(record.previous_version.unwrap().version, "1.0.0");
    }
}
