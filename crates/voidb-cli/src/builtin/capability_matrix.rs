use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;

use serde::Serialize;
use voidb_core::capability::{CapabilityDefinition, CapabilityExecutionMode, CapabilityRiskLevel};
use voidb_core::{AgentLiveSessionCancelBehavior, AgentLiveSessionCloseEffect, VoidbError};

const MATRIX_SCHEMA_VERSION: u32 = 1;
const GENERATED_DOCUMENT: &str = "docs/agent-capability-matrix.md";

#[derive(Debug, Clone, Serialize)]
pub struct CapabilityMatrix {
    pub schema_version: u32,
    pub generated_from: &'static str,
    pub plugin_experience: Vec<PluginExperienceRow>,
    pub capabilities: Vec<CapabilityRow>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PluginExperienceRow {
    pub plugin_id: String,
    pub release_posture: &'static str,
    pub capability_count: usize,
    pub risk_counts: BTreeMap<&'static str, usize>,
    pub execution_modes: Vec<&'static str>,
    pub default_timeouts_ms: Vec<u64>,
    pub streaming_capability_count: usize,
    pub authorization_metadata_complete: bool,
    pub persistent_agent_session: bool,
    pub standalone_tui: bool,
    pub tui_context_handoff: &'static str,
    pub validation_coverage: &'static str,
    pub known_limit: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct CapabilityRow {
    pub qualified_id: String,
    pub risk: &'static str,
    pub execution_mode: &'static str,
    pub default_timeout_ms: Option<u64>,
    pub streaming: bool,
    pub cancellation: String,
    pub supports_dry_run: bool,
    pub authorization_declared: bool,
    pub live_session_protocol: Option<u32>,
}

#[derive(Debug, Clone, Copy)]
struct PluginExperience {
    plugin_id: &'static str,
    release_posture: &'static str,
    standalone_tui: bool,
    tui_context_handoff: &'static str,
    validation_coverage: &'static str,
    known_limit: &'static str,
}

const PLUGIN_EXPERIENCE: &[PluginExperience] = &[
    PluginExperience {
        plugin_id: "connections",
        release_posture: "platform",
        standalone_tui: true,
        tui_context_handoff: "Profile metadata, credential approval, and JIT authorization only",
        validation_coverage: "`cargo test -p voidb-tui`; `scripts/tui-quality-gate.sh`",
        known_limit: "Owns no target driver, live capability session, or target operation dispatch.",
    },
    PluginExperience {
        plugin_id: "docker",
        release_posture: "release_candidate",
        standalone_tui: true,
        tui_context_handoff: "Bounded current-view share with local operation review",
        validation_coverage: "`scripts/check-infrastructure-live-session-conformance.sh`; Docker plugin tests; `scripts/tui-quality-gate.sh`",
        known_limit: "Provider-specific daemon behavior still requires an opt-in disposable live fixture.",
    },
    PluginExperience {
        plugin_id: "duckdb",
        release_posture: "beta",
        standalone_tui: false,
        tui_context_handoff: "None; capability and agent-owned session only",
        validation_coverage: "DuckDB plugin tests; CLI invoke tests; Core SQL contract",
        known_limit: "Bundled native DuckDB makes clean builds and full gates materially slower.",
    },
    PluginExperience {
        plugin_id: "elasticsearch",
        release_posture: "release_candidate",
        standalone_tui: false,
        tui_context_handoff: "None; capability and agent-owned session only",
        validation_coverage: "`scripts/check-data-search-live-session-conformance.sh`; Elasticsearch plugin tests",
        known_limit: "Disposable target evidence remains an opt-in promotion gate.",
    },
    PluginExperience {
        plugin_id: "kubernetes",
        release_posture: "release_candidate",
        standalone_tui: true,
        tui_context_handoff: "Bounded current-view share with local operation review",
        validation_coverage: "`scripts/check-infrastructure-live-session-conformance.sh`; Kubernetes plugin tests; `scripts/tui-quality-gate.sh`",
        known_limit: "Cluster-specific RBAC and admission behavior still needs an opt-in disposable fixture.",
    },
    PluginExperience {
        plugin_id: "mongodb",
        release_posture: "release_candidate",
        standalone_tui: false,
        tui_context_handoff: "None; capability and agent-owned session only",
        validation_coverage: "`scripts/check-data-search-live-session-conformance.sh`; MongoDB plugin tests",
        known_limit: "Replica-set and provider-specific behavior remains an opt-in live-fixture claim.",
    },
    PluginExperience {
        plugin_id: "mysql",
        release_posture: "release_candidate",
        standalone_tui: false,
        tui_context_handoff: "None; capability and agent-owned session only",
        validation_coverage: "MySQL plugin tests; CLI invoke tests; Core SQL contract; MySQL fixture smoke",
        known_limit: "Server-version and provider-specific compatibility still requires fixture evidence.",
    },
    PluginExperience {
        plugin_id: "postgres",
        release_posture: "release_candidate",
        standalone_tui: false,
        tui_context_handoff: "None; capability and agent-owned session only",
        validation_coverage: "PostgreSQL plugin tests; CLI invoke tests; Core SQL contract",
        known_limit: "Live PostgreSQL fixture coverage remains opt-in.",
    },
    PluginExperience {
        plugin_id: "redis",
        release_posture: "release_candidate",
        standalone_tui: false,
        tui_context_handoff: "None; capability and agent-owned session only",
        validation_coverage: "`scripts/check-data-search-live-session-conformance.sh`; Redis plugin tests",
        known_limit: "Cluster/provider behavior remains outside deterministic local coverage.",
    },
    PluginExperience {
        plugin_id: "s3",
        release_posture: "release_candidate",
        standalone_tui: true,
        tui_context_handoff: "None; capability and agent-owned session only",
        validation_coverage: "S3 plugin tests; local-filesystem boundary gate; S3 fixture smoke; `scripts/tui-quality-gate.sh`",
        known_limit: "Provider-specific multipart and consistency behavior needs opt-in fixture evidence.",
    },
    PluginExperience {
        plugin_id: "sqlite",
        release_posture: "release_candidate",
        standalone_tui: false,
        tui_context_handoff: "None; capability and agent-owned session only",
        validation_coverage: "SQLite plugin tests; CLI invoke tests; Core SQL contract",
        known_limit: "Local filesystem policy applies; there is intentionally no human data-inspector TUI.",
    },
    PluginExperience {
        plugin_id: "ssh",
        release_posture: "release_candidate",
        standalone_tui: true,
        tui_context_handoff: "Explicit bounded live-PTY share with one-shot local review",
        validation_coverage: "SSH plugin tests; external-agent boundary gate; SSH fixture smoke; `scripts/tui-quality-gate.sh`",
        known_limit: "Host-key, authentication-agent, and terminal-application behavior needs opt-in live evidence.",
    },
    PluginExperience {
        plugin_id: "sync",
        release_posture: "beta_opt_in",
        standalone_tui: false,
        tui_context_handoff: "None; encrypted plugin-owned operations only",
        validation_coverage: "`scripts/release-sync-smoke.sh`; Sync plugin and standalone server tests",
        known_limit: "Must remain opt-in; no generic live handle, plaintext key, or decrypted bundle may cross the boundary.",
    },
];

pub fn build() -> Result<CapabilityMatrix, VoidbError> {
    let capabilities = super::invoke::builtin_capabilities();
    validate_experience_catalog(&capabilities)?;

    let rows = capabilities
        .iter()
        .map(|capability| CapabilityRow {
            qualified_id: capability.qualified_id(),
            risk: risk_name(capability.effective_risk()),
            execution_mode: execution_mode_name(capability.execution_mode),
            default_timeout_ms: capability.default_timeout_ms,
            streaming: capability.streaming,
            cancellation: cancellation_summary(capability),
            supports_dry_run: capability.supports_dry_run,
            authorization_declared: capability.authorization.declared,
            live_session_protocol: capability
                .session_handoff
                .as_ref()
                .and_then(|handoff| handoff.live_session.as_ref())
                .map(|contract| contract.protocol_version),
        })
        .collect();

    let plugin_experience = PLUGIN_EXPERIENCE
        .iter()
        .map(|experience| summarize_plugin(*experience, &capabilities))
        .collect();

    Ok(CapabilityMatrix {
        schema_version: MATRIX_SCHEMA_VERSION,
        generated_from: "built-in CapabilityDefinition values plus checked CLI experience metadata",
        plugin_experience,
        capabilities: rows,
    })
}

fn validate_experience_catalog(capabilities: &[CapabilityDefinition]) -> Result<(), VoidbError> {
    let capability_plugins = capabilities
        .iter()
        .map(|capability| capability.plugin_id.as_str())
        .collect::<BTreeSet<_>>();
    let experience_plugins = PLUGIN_EXPERIENCE
        .iter()
        .map(|experience| experience.plugin_id)
        .collect::<BTreeSet<_>>();

    if experience_plugins.len() != PLUGIN_EXPERIENCE.len() {
        return Err(VoidbError::Plugin(
            "Capability matrix experience metadata contains duplicate plugin IDs.".into(),
        ));
    }

    let documented_capability_plugins = experience_plugins
        .iter()
        .copied()
        .filter(|plugin_id| *plugin_id != "connections")
        .collect::<BTreeSet<_>>();
    if capability_plugins != documented_capability_plugins {
        return Err(VoidbError::Plugin(format!(
            "Capability matrix plugin coverage is stale: capability plugins={capability_plugins:?}, documented plugins={documented_capability_plugins:?}"
        )));
    }

    let qualified_ids = capabilities
        .iter()
        .map(CapabilityDefinition::qualified_id)
        .collect::<BTreeSet<_>>();
    if qualified_ids.len() != capabilities.len() {
        return Err(VoidbError::Plugin(
            "Built-in capability catalog contains duplicate qualified IDs.".into(),
        ));
    }

    Ok(())
}

fn summarize_plugin(
    experience: PluginExperience,
    capabilities: &[CapabilityDefinition],
) -> PluginExperienceRow {
    let definitions = capabilities
        .iter()
        .filter(|capability| capability.plugin_id == experience.plugin_id)
        .collect::<Vec<_>>();
    let mut risk_counts = BTreeMap::new();
    let mut modes = BTreeSet::new();
    let mut timeouts = BTreeSet::new();
    let mut streaming_capability_count = 0;
    let mut authorization_metadata_complete = true;
    let mut persistent_agent_session = false;

    for capability in &definitions {
        *risk_counts
            .entry(risk_name(capability.effective_risk()))
            .or_insert(0) += 1;
        modes.insert(execution_mode_name(capability.execution_mode));
        if let Some(timeout) = capability.default_timeout_ms {
            timeouts.insert(timeout);
        }
        streaming_capability_count += usize::from(capability.streaming);
        authorization_metadata_complete &= capability.authorization.declared;
        persistent_agent_session |= capability.supports_session_execution();
    }

    PluginExperienceRow {
        plugin_id: experience.plugin_id.into(),
        release_posture: experience.release_posture,
        capability_count: definitions.len(),
        risk_counts,
        execution_modes: modes.into_iter().collect(),
        default_timeouts_ms: timeouts.into_iter().collect(),
        streaming_capability_count,
        authorization_metadata_complete,
        persistent_agent_session,
        standalone_tui: experience.standalone_tui,
        tui_context_handoff: experience.tui_context_handoff,
        validation_coverage: experience.validation_coverage,
        known_limit: experience.known_limit,
    }
}

fn risk_name(risk: CapabilityRiskLevel) -> &'static str {
    match risk {
        CapabilityRiskLevel::ReadOnly => "read_only",
        CapabilityRiskLevel::Mutating => "mutating",
        CapabilityRiskLevel::Destructive => "destructive",
        CapabilityRiskLevel::ExternalSideEffect => "external_side_effect",
    }
}

fn execution_mode_name(mode: CapabilityExecutionMode) -> &'static str {
    match mode {
        CapabilityExecutionMode::Stateless => "stateless",
        CapabilityExecutionMode::SessionOnly => "session_only",
        CapabilityExecutionMode::Both => "both",
    }
}

fn cancellation_summary(capability: &CapabilityDefinition) -> String {
    let mut controls = Vec::new();
    if capability.supports_stateless_execution() {
        controls.push("invoke caller-token/SIGINT".to_string());
    }
    if capability.supports_session_execution() {
        let detail = capability
            .session_handoff
            .as_ref()
            .and_then(|handoff| handoff.live_session.as_ref())
            .map(|contract| {
                format!(
                    "session {} + {}",
                    cancel_behavior_name(contract.control.cancel),
                    close_effect_name(contract.control.close)
                )
            })
            .unwrap_or_else(|| "session call-cancel + close".to_string());
        controls.push(detail);
    }
    controls.join("; ")
}

fn cancel_behavior_name(behavior: AgentLiveSessionCancelBehavior) -> &'static str {
    match behavior {
        AgentLiveSessionCancelBehavior::CallOnly => "call-only cancel",
        AgentLiveSessionCancelBehavior::CallAndSource => "call-and-source cancel",
    }
}

fn close_effect_name(effect: AgentLiveSessionCloseEffect) -> &'static str {
    match effect {
        AgentLiveSessionCloseEffect::StopObservation => "stop-observation close",
        AgentLiveSessionCloseEffect::DetachRemote => "detach-remote close",
        AgentLiveSessionCloseEffect::TerminateRemote => "terminate-remote close",
    }
}

pub fn render_markdown(matrix: &CapabilityMatrix) -> String {
    let mut output = String::new();
    writeln!(output, "# Agent Capability and Experience Matrix").unwrap();
    writeln!(output).unwrap();
    writeln!(
        output,
        "<!-- GENERATED by `voidb-cli invoke matrix --format markdown`; do not edit by hand. -->"
    )
    .unwrap();
    writeln!(output).unwrap();
    writeln!(
        output,
        "This is the canonical current inventory for built-in Agent capabilities and plugin experiences. It is generated from runtime `CapabilityDefinition` values and checked experience metadata. Process plugins are intentionally excluded because their installed catalog is node-local."
    )
    .unwrap();
    writeln!(output).unwrap();
    writeln!(
        output,
        "The committed output is `{GENERATED_DOCUMENT}`. Regenerate with `cargo run -p voidb-cli -- invoke matrix --format markdown` and verify drift with `scripts/check-agent-capability-matrix.sh`."
    )
    .unwrap();
    writeln!(output).unwrap();
    writeln!(output, "## Plugin Experience Summary").unwrap();
    writeln!(output).unwrap();
    writeln!(
        output,
        "| Plugin | Posture | Capabilities | Risks | Modes | Timeouts (ms) | Stream | Agent session | Standalone TUI | TUI context handoff | Validation | Known limit |"
    )
    .unwrap();
    writeln!(
        output,
        "|---|---|---:|---|---|---|---:|---|---|---|---|---|"
    )
    .unwrap();
    for plugin in &matrix.plugin_experience {
        let risks = plugin
            .risk_counts
            .iter()
            .map(|(risk, count)| format!("{risk}:{count}"))
            .collect::<Vec<_>>()
            .join(", ");
        let modes = plugin.execution_modes.join(", ");
        let timeouts = plugin
            .default_timeouts_ms
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        writeln!(
            output,
            "| `{}` | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} |",
            markdown_cell(&plugin.plugin_id),
            markdown_cell(plugin.release_posture),
            plugin.capability_count,
            markdown_cell(&risks),
            markdown_cell(&modes),
            markdown_cell(&timeouts),
            plugin.streaming_capability_count,
            yes_no(plugin.persistent_agent_session),
            yes_no(plugin.standalone_tui),
            markdown_cell(plugin.tui_context_handoff),
            markdown_cell(plugin.validation_coverage),
            markdown_cell(plugin.known_limit),
        )
        .unwrap();
    }

    writeln!(output).unwrap();
    writeln!(output, "## Capability Inventory").unwrap();
    writeln!(output).unwrap();
    writeln!(
        output,
        "| Capability | Risk | Mode | Timeout (ms) | Stream | Cancellation | Dry run | Authorization | Live protocol |"
    )
    .unwrap();
    writeln!(output, "|---|---|---|---:|---|---|---|---|---:|").unwrap();
    for capability in &matrix.capabilities {
        writeln!(
            output,
            "| `{}` | {} | {} | {} | {} | {} | {} | {} | {} |",
            markdown_cell(&capability.qualified_id),
            capability.risk,
            capability.execution_mode,
            capability
                .default_timeout_ms
                .map(|timeout| timeout.to_string())
                .unwrap_or_else(|| "host default".into()),
            yes_no(capability.streaming),
            markdown_cell(&capability.cancellation),
            yes_no(capability.supports_dry_run),
            if capability.authorization_declared {
                "declared"
            } else {
                "custom-only"
            },
            capability
                .live_session_protocol
                .map(|version| version.to_string())
                .unwrap_or_else(|| "—".into()),
        )
        .unwrap();
    }

    writeln!(output).unwrap();
    writeln!(output, "## Interpretation").unwrap();
    writeln!(output).unwrap();
    writeln!(
        output,
        "- `stateless` uses one-shot generic invoke; `session_only` requires an explicit agent-owned session handoff; `both` supports either transport."
    )
    .unwrap();
    writeln!(
        output,
        "- One-shot cancellation is caller-owned through the cancellation token and `SIGINT`. Session cancellation and close remain generation-bound and plugin-owned."
    )
    .unwrap();
    writeln!(
        output,
        "- A standalone human TUI does not imply a human-session share. Only SSH shares a live PTY; Docker, Kubernetes, and Jenkins share bounded current-view context; all other plugin TUIs are capability/session-only for Agents."
    )
    .unwrap();
    writeln!(
        output,
        "- `release_candidate` is a release-planning posture, not a stable API promise. Sync remains `beta_opt_in`, and DuckDB remains beta because of its native-build and release-planning boundary."
    )
    .unwrap();
    writeln!(
        output,
        "- Installed process plugins remain discoverable through `voidb-cli invoke list`; they are excluded from this repository-owned matrix because their manifests and trust roots are installation-specific."
    )
    .unwrap();
    writeln!(
        output,
        "- Current documentation ownership and historical evidence rules are in [Readiness Documentation Map](readiness.md)."
    )
    .unwrap();

    output.trim_end().to_string()
}

fn markdown_cell(value: &str) -> String {
    value.replace('|', "\\|").replace('\n', " ")
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

#[cfg(all(test, feature = "full"))]
mod tests {
    use super::*;

    #[test]
    fn matrix_covers_every_builtin_plugin_and_capability() {
        let matrix = build().expect("build matrix");
        assert!(matrix.capabilities.len() > 100);
        assert!(
            matrix
                .capabilities
                .iter()
                .any(|capability| capability.qualified_id == "sync.status")
        );
        assert!(
            matrix
                .plugin_experience
                .iter()
                .any(|plugin| plugin.plugin_id == "connections" && plugin.standalone_tui)
        );
    }

    #[test]
    fn standalone_tui_metadata_matches_registered_cli_commands() {
        let registered_tuis = crate::build_cli_manager()
            .build_commands()
            .into_iter()
            .filter(|command| {
                command
                    .get_subcommands()
                    .any(|subcommand| subcommand.get_name() == "tui")
            })
            .map(|command| command.get_name().to_string())
            .collect::<BTreeSet<_>>();
        let documented_tuis = PLUGIN_EXPERIENCE
            .iter()
            .filter(|plugin| plugin.standalone_tui)
            .map(|plugin| plugin.plugin_id.to_string())
            .collect::<BTreeSet<_>>();

        assert_eq!(registered_tuis, documented_tuis);
    }

    #[test]
    fn generated_markdown_has_stable_ownership_markers() {
        let markdown = render_markdown(&build().expect("build matrix"));
        assert!(markdown.contains(GENERATED_DOCUMENT));
        assert!(markdown.contains("do not edit by hand"));
        assert!(markdown.contains("## Capability Inventory"));
    }
}
