use serde_json::json;
use voidb_core::capability::{
    CapabilityDefinition, CapabilityError, CapabilityErrorCategory, CapabilityRiskLevel,
};
#[cfg(not(test))]
use voidb_core::discover_process_plugins;
use voidb_core::{ProcessPluginCandidate, ProcessPluginCandidateState, ProcessPluginDiscovery};
#[cfg(feature = "sync")]
use voidb_plugin_sync::sync_capabilities;

use super::SUPPORTED_INVOKE_PLUGINS;
use super::execution::{credential_class_from_manifest, resolve_capability, schema_value};
use super::output::capability_error;

#[cfg(not(test))]
pub(super) fn authorization_discovery() -> ProcessPluginDiscovery {
    discover_process_plugins()
}

#[cfg(test)]
pub(super) fn authorization_discovery() -> ProcessPluginDiscovery {
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use voidb_core::{ProcessPluginManifest, ProcessPluginRootKind, ProcessPluginSource};

    static FIXTURE: std::sync::LazyLock<ProcessPluginDiscovery> = std::sync::LazyLock::new(|| {
        // Policy tests use metadata snapshots, never the user's plugin installation.
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/authorization");
        let candidates = [
            "mysql",
            "postgres",
            "sqlite",
            "redis",
            "ssh",
            "duckdb",
            "mongodb",
            "elasticsearch",
        ]
        .into_iter()
        .map(|id| {
            let plugin_dir = root.join(id);
            let manifest_path = plugin_dir.join("plugin.toml");
            let content = std::fs::read_to_string(&manifest_path).expect("read catalog fixture");
            let decoded: toml::Value = toml::from_str(&content).expect("decode catalog fixture");
            voidb_core::process_plugin::validate_process_plugin_manifest_json(
                &serde_json::to_value(decoded).expect("encode manifest JSON"),
            )
            .expect("catalog fixture must satisfy discovery schema");
            let manifest: ProcessPluginManifest =
                toml::from_str(&content).expect("decode catalog contract");
            let mut resolved_schema_paths = BTreeMap::new();
            for capability in &manifest.capabilities {
                for (kind, path) in [
                    ("input_schema", &capability.input_schema),
                    ("output_schema", &capability.output_schema),
                ] {
                    resolved_schema_paths.insert(
                        format!("capabilities.{}.{kind}", capability.id),
                        plugin_dir.join(path),
                    );
                }
            }
            ProcessPluginCandidate {
                id: manifest.id.clone(),
                name: Some(manifest.name.clone()),
                version: Some(manifest.version.clone()),
                protocol_version: Some(manifest.protocol_version.clone()),
                manifest_path,
                source: ProcessPluginSource {
                    root: root.clone(),
                    plugin_dir,
                    kind: ProcessPluginRootKind::EnvPath,
                    trust_level: ProcessPluginRootKind::EnvPath.trust_level(),
                    precedence: 0,
                },
                state: ProcessPluginCandidateState::Available,
                transport: Some(manifest.runtime.transport.clone()),
                capability_count: manifest.capabilities.len(),
                tui: false,
                diagnostics: Vec::new(),
                manifest: Some(manifest),
                resolved_runtime_command: None,
                resolved_schema_paths,
            }
        })
        .collect();
        ProcessPluginDiscovery {
            roots: Vec::new(),
            candidates,
        }
    });
    FIXTURE.clone()
}

pub(crate) fn resolved_capability_risk(
    capability_ref: &str,
) -> Result<CapabilityRiskLevel, String> {
    let discovery = authorization_discovery();
    resolve_capability(capability_ref, &discovery)
        .map(|capability| capability.effective_risk())
        .map_err(|error| error.message)
}

pub(crate) fn resolved_authorization_capabilities(
    plugin_id: Option<&str>,
) -> Result<Vec<CapabilityDefinition>, String> {
    let discovery = authorization_discovery();
    match plugin_id {
        Some(plugin_id) => {
            capabilities_for_plugin(plugin_id, &discovery).map_err(|error| error.message)
        }
        None => Ok(supported_capabilities(&discovery)),
    }
}

pub(super) fn capabilities_for_plugin(
    plugin_id: &str,
    discovery: &ProcessPluginDiscovery,
) -> Result<Vec<CapabilityDefinition>, Box<CapabilityError>> {
    #[cfg(feature = "sync")]
    if plugin_id == "sync" {
        return Ok(sync_capabilities());
    }
    let candidate = select_available_process_candidate(discovery, plugin_id)?;
    process_capability_definitions(candidate)
}

pub(crate) fn builtin_capabilities() -> Vec<CapabilityDefinition> {
    let mut capabilities = Vec::new();
    #[cfg(feature = "sync")]
    capabilities.extend(sync_capabilities());
    capabilities.sort_by_key(CapabilityDefinition::qualified_id);
    capabilities
}

pub(super) fn supported_capabilities(
    discovery: &ProcessPluginDiscovery,
) -> Vec<CapabilityDefinition> {
    let mut capabilities = builtin_capabilities();
    for candidate in &discovery.candidates {
        if candidate.state == ProcessPluginCandidateState::Available
            && !is_builtin_invoke_plugin(&candidate.id)
            && let Ok(process_capabilities) = process_capability_definitions(candidate)
        {
            capabilities.extend(process_capabilities);
        }
    }
    capabilities.sort_by_key(CapabilityDefinition::qualified_id);
    capabilities
}

pub(super) fn is_builtin_invoke_plugin(plugin_id: &str) -> bool {
    SUPPORTED_INVOKE_PLUGINS.contains(&plugin_id)
}

pub(super) fn select_available_process_candidate<'a>(
    discovery: &'a ProcessPluginDiscovery,
    plugin_id: &str,
) -> Result<&'a ProcessPluginCandidate, Box<CapabilityError>> {
    let candidates = discovery.candidates_for_id(plugin_id);
    let Some(candidate) = candidates
        .iter()
        .copied()
        .find(|candidate| candidate.state == ProcessPluginCandidateState::Available)
        .or_else(|| candidates.first().copied())
    else {
        return Err(Box::new(capability_error(
            CapabilityErrorCategory::Unavailable,
            "unavailable.plugin_not_found",
            "Generic invoke supports built-in plugins and available process plugins.",
            json!({
                "plugin_id": plugin_id,
                "built_in_plugins": SUPPORTED_INVOKE_PLUGINS,
            }),
            None,
            true,
        )));
    };

    if candidate.state != ProcessPluginCandidateState::Available {
        return Err(Box::new(capability_error(
            CapabilityErrorCategory::Unavailable,
            "unavailable.process_plugin_candidate_not_available",
            "Discovered process-plugin candidate is not available for invocation.",
            json!({
                "plugin_id": plugin_id,
                "state": candidate.state,
                "diagnostics": candidate.diagnostics,
            }),
            None,
            true,
        )));
    }

    Ok(candidate)
}

fn process_capability_definitions(
    candidate: &ProcessPluginCandidate,
) -> Result<Vec<CapabilityDefinition>, Box<CapabilityError>> {
    let manifest = candidate.manifest.as_ref().ok_or_else(|| {
        Box::new(capability_error(
            CapabilityErrorCategory::Unavailable,
            "unavailable.process_plugin_manifest_missing",
            "Discovered process-plugin candidate does not have a decoded manifest.",
            json!({ "plugin_id": candidate.id }),
            None,
            false,
        ))
    })?;

    manifest
        .capabilities
        .iter()
        .map(|capability| {
            let input_label = format!("capabilities.{}.input_schema", capability.id);
            let output_label = format!("capabilities.{}.output_schema", capability.id);
            Ok(CapabilityDefinition {
                plugin_id: manifest.id.clone(),
                id: capability.id.clone(),
                description: capability.description.clone(),
                input_schema: schema_value(candidate, &input_label, &capability.input_schema)?,
                output_schema: schema_value(candidate, &output_label, &capability.output_schema)?,
                permissions: capability.permissions.clone(),
                authorization: {
                    let mut auth = capability.authorization.clone();
                    if !auth.declared {
                        auth.declared = true;
                        auth.capability_wide_allowed = true;
                    }
                    auth
                },
                risk: capability.risk.unwrap_or_else(|| {
                    CapabilityRiskLevel::from_destructive(capability.destructive)
                }),
                destructive: capability.destructive,
                streaming: capability.streaming,
                execution_mode: capability.execution_mode,
                session_handoff: capability.session_handoff.clone(),
                connection_required: capability.connection_required,
                required_secret_classes: capability
                    .required_secret_classes
                    .iter()
                    .map(|class| credential_class_from_manifest(class))
                    .collect(),
                supports_dry_run: capability.supports_dry_run,
                default_timeout_ms: capability.default_timeout_ms,
            })
        })
        .collect()
}
