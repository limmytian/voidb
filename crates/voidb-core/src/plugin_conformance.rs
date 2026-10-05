//! Static plugin conformance and certification checks.
//!
//! This module intentionally starts with deterministic checks that do not
//! launch plugin processes or contact live target systems. Runtime behavior,
//! audit, timeout, and cancellation checks can build on the same report model.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::capability::CapabilityRiskLevel;
use crate::process_plugin::{
    ProcessPluginCandidate, ProcessPluginCandidateState, ProcessPluginCapability,
    ProcessPluginDiagnosticSeverity, ProcessPluginManifest,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginMaturityLevel {
    Internal,
    Experimental,
    Beta,
    Stable,
}

impl PluginMaturityLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Internal => "internal",
            Self::Experimental => "experimental",
            Self::Beta => "beta",
            Self::Stable => "stable",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginMaturityCriteria {
    pub level: PluginMaturityLevel,
    pub summary: String,
    pub required_evidence: Vec<String>,
    pub blocking_gaps: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginConformanceStatus {
    Pass,
    Warn,
    Fail,
    Skipped,
}

impl PluginConformanceStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Warn => "warn",
            Self::Fail => "fail",
            Self::Skipped => "skipped",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PluginConformanceCheck {
    pub id: String,
    pub category: String,
    pub status: PluginConformanceStatus,
    pub message: String,

    #[serde(default)]
    pub details: Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PluginConformanceReport {
    pub plugin_id: String,
    pub target_maturity: PluginMaturityLevel,
    pub overall_status: PluginConformanceStatus,
    pub criteria: Vec<PluginMaturityCriteria>,
    pub checks: Vec<PluginConformanceCheck>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PluginPromotionDecision {
    Ready,
    ReadyWithWarnings,
    Blocked,
}

impl PluginPromotionDecision {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ready => "ready",
            Self::ReadyWithWarnings => "ready_with_warnings",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PluginCertificationSummary {
    pub plugin_id: String,
    pub target_maturity: PluginMaturityLevel,
    pub overall_status: PluginConformanceStatus,
    pub promotion_decision: PluginPromotionDecision,
    pub pass_count: usize,
    pub warning_count: usize,
    pub failure_count: usize,
    pub skipped_count: usize,
    pub blocking_failures: Vec<String>,
    pub warnings: Vec<String>,
    pub skipped_checks: Vec<String>,
    pub recommended_follow_ups: Vec<String>,
}

impl PluginConformanceReport {
    pub fn extend_checks<I>(&mut self, checks: I)
    where
        I: IntoIterator<Item = PluginConformanceCheck>,
    {
        self.checks.extend(checks);
        self.overall_status = aggregate_status(&self.checks);
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PluginConformanceEvidence {
    pub passed: bool,
    pub summary: String,

    #[serde(default)]
    pub details: Value,
}

impl PluginConformanceEvidence {
    pub fn passed(summary: impl Into<String>) -> Self {
        Self {
            passed: true,
            summary: summary.into(),
            details: Value::Null,
        }
    }

    pub fn failed(summary: impl Into<String>, details: Value) -> Self {
        Self {
            passed: false,
            summary: summary.into(),
            details,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PluginRuntimeConformanceEvidence {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub structured_errors: Option<PluginConformanceEvidence>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub redaction: Option<PluginConformanceEvidence>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<PluginConformanceEvidence>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cancellation: Option<PluginConformanceEvidence>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health_check: Option<PluginConformanceEvidence>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_events: Option<PluginConformanceEvidence>,
}

pub fn default_plugin_maturity_criteria() -> Vec<PluginMaturityCriteria> {
    vec![
        PluginMaturityCriteria {
            level: PluginMaturityLevel::Internal,
            summary: "Private, development, or bundled implementation detail.".into(),
            required_evidence: vec![
                "Plugin is intentionally hidden, private, or implementation-specific.".into(),
                "Known risks are documented for maintainers.".into(),
            ],
            blocking_gaps: vec![
                "No claim of agent-facing readiness.".into(),
                "May skip public capability or runtime conformance.".into(),
            ],
        },
        PluginMaturityCriteria {
            level: PluginMaturityLevel::Experimental,
            summary: "Discoverable plugin with valid static metadata and disclosed gaps.".into(),
            required_evidence: vec![
                "Manifest decodes and is compatible with the current process-plugin schema.".into(),
                "Runtime declaration, profile schema, capability schemas, risks, and permissions pass static conformance.".into(),
                "Supported capability classes, unsupported behavior, and live-smoke requirements are disclosed.".into(),
            ],
            blocking_gaps: vec![
                "Any manifest, schema, risk, or permission conformance failure.".into(),
                "Undisclosed side effects or credential exposure risk.".into(),
            ],
        },
        PluginMaturityCriteria {
            level: PluginMaturityLevel::Beta,
            summary: "Agent-facing plugin with deterministic contract evidence.".into(),
            required_evidence: vec![
                "All experimental criteria pass.".into(),
                "Structured errors and redaction invariants have deterministic tests.".into(),
                "Timeout, cancellation, health-check, and audit-event behavior are covered without live secrets.".into(),
            ],
            blocking_gaps: vec![
                "Missing deterministic coverage for policy, redaction, audit, timeout, or cancellation behavior.".into(),
                "Unbounded outputs or undocumented skipped live checks.".into(),
            ],
        },
        PluginMaturityCriteria {
            level: PluginMaturityLevel::Stable,
            summary: "Release-ready plugin with repeatable promotion evidence.".into(),
            required_evidence: vec![
                "All beta criteria pass.".into(),
                "Version compatibility, release smoke, live-skip rationale, and user-facing limitations are documented.".into(),
                "No blocking conformance failures remain for supported capability classes.".into(),
            ],
            blocking_gaps: vec![
                "Any high-risk unsupported behavior without a documented mitigation or follow-up.".into(),
                "Any secret, policy, schema, runtime, or audit regression.".into(),
            ],
        },
    ]
}

pub fn certify_process_plugin_candidate(
    candidate: &ProcessPluginCandidate,
    target_maturity: PluginMaturityLevel,
) -> PluginConformanceReport {
    let mut checks = Vec::new();

    checks.push(candidate_state_check(candidate));
    checks.push(candidate_diagnostics_check(candidate));

    if let Some(manifest) = candidate.manifest.as_ref() {
        checks.extend(manifest_checks(candidate, manifest));
        checks.extend(schema_checks(candidate, manifest));
    } else {
        checks.push(fail_check(
            "manifest.present",
            "manifest",
            "Candidate does not include a decoded manifest.",
            json!({ "candidate_state": candidate.state }),
        ));
    }

    let overall_status = aggregate_status(&checks);
    PluginConformanceReport {
        plugin_id: candidate.id.clone(),
        target_maturity,
        overall_status,
        criteria: default_plugin_maturity_criteria(),
        checks,
    }
}

pub fn summarize_conformance_report(
    report: &PluginConformanceReport,
) -> PluginCertificationSummary {
    let pass_count = count_checks(report, PluginConformanceStatus::Pass);
    let warning_count = count_checks(report, PluginConformanceStatus::Warn);
    let failure_count = count_checks(report, PluginConformanceStatus::Fail);
    let skipped_count = count_checks(report, PluginConformanceStatus::Skipped);
    let blocking_failures = check_messages(report, PluginConformanceStatus::Fail);
    let warnings = check_messages(report, PluginConformanceStatus::Warn);
    let skipped_checks = check_messages(report, PluginConformanceStatus::Skipped);
    let promotion_decision = promotion_decision(
        report.target_maturity,
        failure_count,
        warning_count,
        skipped_count,
    );
    let recommended_follow_ups = recommended_follow_ups(report);

    PluginCertificationSummary {
        plugin_id: report.plugin_id.clone(),
        target_maturity: report.target_maturity,
        overall_status: report.overall_status,
        promotion_decision,
        pass_count,
        warning_count,
        failure_count,
        skipped_count,
        blocking_failures,
        warnings,
        skipped_checks,
        recommended_follow_ups,
    }
}

pub fn render_conformance_report_markdown(report: &PluginConformanceReport) -> String {
    let summary = summarize_conformance_report(report);
    let mut output = String::new();

    output.push_str(&format!(
        "# Plugin Certification Report: {}\n\n",
        summary.plugin_id
    ));
    output.push_str(&format!(
        "- Target maturity: `{}`\n",
        summary.target_maturity.as_str()
    ));
    output.push_str(&format!(
        "- Overall status: `{}`\n",
        summary.overall_status.as_str()
    ));
    output.push_str(&format!(
        "- Promotion decision: `{}`\n",
        summary.promotion_decision.as_str()
    ));
    output.push_str(&format!(
        "- Checks: {} passed, {} warnings, {} failures, {} skipped\n\n",
        summary.pass_count, summary.warning_count, summary.failure_count, summary.skipped_count
    ));

    push_report_section(
        &mut output,
        "Blocking Failures",
        &summary.blocking_failures,
        "None.",
    );
    push_report_section(&mut output, "Warnings", &summary.warnings, "None.");
    push_report_section(
        &mut output,
        "Skipped Checks",
        &summary.skipped_checks,
        "None.",
    );
    push_report_section(
        &mut output,
        "Recommended Follow-Ups",
        &summary.recommended_follow_ups,
        "None.",
    );

    output
}

pub fn runtime_conformance_checks(
    evidence: &PluginRuntimeConformanceEvidence,
) -> Vec<PluginConformanceCheck> {
    vec![
        evidence_check(
            "runtime.structured_errors",
            "runtime",
            "Structured errors use stable categories and machine-readable fields.",
            &evidence.structured_errors,
        ),
        evidence_check(
            "runtime.redaction",
            "runtime",
            "Runtime failures and outputs never expose plaintext secrets or sensitive target metadata.",
            &evidence.redaction,
        ),
        evidence_check(
            "runtime.timeout",
            "runtime",
            "Timeout behavior is deterministic and returns a structured timeout error.",
            &evidence.timeout,
        ),
        evidence_check(
            "runtime.cancellation",
            "runtime",
            "Cancellation behavior is deterministic and leaves no orphaned invocation state.",
            &evidence.cancellation,
        ),
        evidence_check(
            "runtime.health_check",
            "runtime",
            "Startup and health-check behavior are covered by deterministic fixtures.",
            &evidence.health_check,
        ),
        evidence_check(
            "audit.invocation_events",
            "audit",
            "Capability invocations emit redacted audit events with actor, profile, policy, duration, and result metadata.",
            &evidence.audit_events,
        ),
    ]
}

pub fn apply_runtime_conformance_evidence(
    report: &mut PluginConformanceReport,
    evidence: &PluginRuntimeConformanceEvidence,
) {
    report.extend_checks(runtime_conformance_checks(evidence));
}

fn candidate_state_check(candidate: &ProcessPluginCandidate) -> PluginConformanceCheck {
    if candidate.state == ProcessPluginCandidateState::Available {
        pass_check(
            "candidate.available",
            "manifest",
            "Candidate is available for conformance evaluation.",
            json!({ "state": candidate.state }),
        )
    } else {
        fail_check(
            "candidate.available",
            "manifest",
            "Candidate must be available before certification.",
            json!({ "state": candidate.state }),
        )
    }
}

fn evidence_check(
    id: &str,
    category: &str,
    requirement: &str,
    evidence: &Option<PluginConformanceEvidence>,
) -> PluginConformanceCheck {
    match evidence {
        Some(evidence) if evidence.passed => pass_check(
            id,
            category,
            requirement,
            json!({
                "summary": evidence.summary,
                "details": evidence.details,
            }),
        ),
        Some(evidence) => fail_check(
            id,
            category,
            requirement,
            json!({
                "summary": evidence.summary,
                "details": evidence.details,
            }),
        ),
        None => fail_check(
            id,
            category,
            "Required deterministic conformance evidence is missing.",
            json!({ "requirement": requirement }),
        ),
    }
}

fn candidate_diagnostics_check(candidate: &ProcessPluginCandidate) -> PluginConformanceCheck {
    let errors = candidate
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.severity == ProcessPluginDiagnosticSeverity::Error)
        .count();
    let warnings = candidate
        .diagnostics
        .iter()
        .filter(|diagnostic| diagnostic.severity == ProcessPluginDiagnosticSeverity::Warning)
        .count();
    let details = json!({
        "errors": errors,
        "warnings": warnings,
        "diagnostics": candidate.diagnostics,
    });

    if errors > 0 {
        fail_check(
            "candidate.discovery_diagnostics",
            "manifest",
            "Discovery reported blocking diagnostics.",
            details,
        )
    } else if warnings > 0 {
        warn_check(
            "candidate.discovery_diagnostics",
            "manifest",
            "Discovery reported non-blocking diagnostics.",
            details,
        )
    } else {
        pass_check(
            "candidate.discovery_diagnostics",
            "manifest",
            "Discovery reported no diagnostics.",
            details,
        )
    }
}

fn manifest_checks(
    candidate: &ProcessPluginCandidate,
    manifest: &ProcessPluginManifest,
) -> Vec<PluginConformanceCheck> {
    let mut checks = Vec::new();

    checks.push(if candidate.id == manifest.id {
        pass_check(
            "manifest.identity",
            "manifest",
            "Manifest id matches the candidate id.",
            json!({ "id": manifest.id }),
        )
    } else {
        fail_check(
            "manifest.identity",
            "manifest",
            "Manifest id must match the candidate id.",
            json!({ "candidate_id": candidate.id, "manifest_id": manifest.id }),
        )
    });

    checks.push(if semver::Version::parse(&manifest.version).is_ok() {
        pass_check(
            "manifest.version",
            "manifest",
            "Manifest version is valid semver.",
            json!({ "version": manifest.version }),
        )
    } else {
        fail_check(
            "manifest.version",
            "manifest",
            "Manifest version must be valid semver.",
            json!({ "version": manifest.version }),
        )
    });

    checks.push(if manifest.runtime.transport == "stdio-jsonrpc" {
        pass_check(
            "manifest.runtime.transport",
            "manifest",
            "Runtime transport is supported.",
            json!({ "transport": manifest.runtime.transport }),
        )
    } else {
        fail_check(
            "manifest.runtime.transport",
            "manifest",
            "Runtime transport is not supported.",
            json!({ "transport": manifest.runtime.transport }),
        )
    });

    checks.push(if candidate.resolved_runtime_command.is_some() {
        pass_check(
            "manifest.runtime.command",
            "manifest",
            "Runtime command resolves inside an allowed plugin root.",
            json!({ "command": manifest.runtime.command }),
        )
    } else {
        fail_check(
            "manifest.runtime.command",
            "manifest",
            "Runtime command must resolve before certification.",
            json!({ "command": manifest.runtime.command }),
        )
    });

    checks.push(if manifest.capabilities.is_empty() {
        fail_check(
            "manifest.capabilities.present",
            "capability",
            "Manifest must declare at least one capability.",
            Value::Null,
        )
    } else {
        pass_check(
            "manifest.capabilities.present",
            "capability",
            "Manifest declares capabilities.",
            json!({ "capability_count": manifest.capabilities.len() }),
        )
    });

    let capability_ids = manifest
        .capabilities
        .iter()
        .map(|capability| capability.id.as_str())
        .collect::<HashSet<_>>();
    if let Some(entrypoint) = manifest
        .ui
        .as_ref()
        .and_then(|ui| ui.entrypoint_capability.as_ref())
    {
        checks.push(if capability_ids.contains(entrypoint.as_str()) {
            pass_check(
                "manifest.ui.entrypoint",
                "manifest",
                "TUI entrypoint capability exists.",
                json!({ "entrypoint_capability": entrypoint }),
            )
        } else {
            fail_check(
                "manifest.ui.entrypoint",
                "manifest",
                "TUI entrypoint capability must exist in the manifest capability list.",
                json!({ "entrypoint_capability": entrypoint }),
            )
        });
    }

    checks.extend(
        manifest
            .capabilities
            .iter()
            .flat_map(capability_static_checks),
    );

    checks
}

fn capability_static_checks(capability: &ProcessPluginCapability) -> Vec<PluginConformanceCheck> {
    let mut checks = Vec::new();
    let declared_risk = capability
        .risk
        .unwrap_or_else(|| CapabilityRiskLevel::from_destructive(capability.destructive));
    let effective_risk = if capability.destructive && declared_risk == CapabilityRiskLevel::ReadOnly
    {
        CapabilityRiskLevel::Destructive
    } else {
        declared_risk
    };
    let risk_details = json!({
        "capability_id": capability.id,
        "risk": capability.risk,
        "destructive": capability.destructive,
        "effective_risk": effective_risk,
    });

    checks.push(if capability.risk.is_some() {
        pass_check(
            format!("capability.{}.risk_declared", capability.id),
            "capability",
            "Capability declares an explicit risk level.",
            risk_details.clone(),
        )
    } else {
        fail_check(
            format!("capability.{}.risk_declared", capability.id),
            "capability",
            "Capability must declare an explicit risk level for certification.",
            risk_details.clone(),
        )
    });

    checks.push(if capability.permissions.is_empty() {
        fail_check(
            format!("capability.{}.permissions", capability.id),
            "capability",
            "Capability must declare at least one stable permission string.",
            json!({ "capability_id": capability.id }),
        )
    } else {
        pass_check(
            format!("capability.{}.permissions", capability.id),
            "capability",
            "Capability declares stable permission strings.",
            json!({
                "capability_id": capability.id,
                "permissions": capability.permissions,
            }),
        )
    });

    checks.push(
        if capability.destructive && capability.risk == Some(CapabilityRiskLevel::ReadOnly) {
            warn_check(
                format!("capability.{}.risk_compatibility", capability.id),
                "capability",
                "Destructive compatibility flag raises effective risk despite read-only risk.",
                risk_details,
            )
        } else {
            pass_check(
                format!("capability.{}.risk_compatibility", capability.id),
                "capability",
                "Risk and destructive compatibility metadata are consistent.",
                risk_details,
            )
        },
    );

    checks.push(
        if capability.supports_dry_run && !effective_risk.has_target_side_effects() {
            warn_check(
                format!("capability.{}.dry_run", capability.id),
                "capability",
                "Dry-run support is meaningful only for side-effecting capabilities.",
                json!({ "capability_id": capability.id }),
            )
        } else {
            pass_check(
                format!("capability.{}.dry_run", capability.id),
                "capability",
                "Dry-run metadata is consistent with capability risk.",
                json!({
                    "capability_id": capability.id,
                    "supports_dry_run": capability.supports_dry_run,
                    "effective_risk": effective_risk,
                }),
            )
        },
    );

    checks
}

fn schema_checks(
    candidate: &ProcessPluginCandidate,
    manifest: &ProcessPluginManifest,
) -> Vec<PluginConformanceCheck> {
    let mut checks = Vec::new();
    checks.push(schema_document_check(
        "connections.profile_schema",
        &candidate.resolved_schema_paths,
    ));

    for capability in &manifest.capabilities {
        checks.push(schema_document_check(
            &format!("capabilities.{}.input_schema", capability.id),
            &candidate.resolved_schema_paths,
        ));
        checks.push(schema_document_check(
            &format!("capabilities.{}.output_schema", capability.id),
            &candidate.resolved_schema_paths,
        ));
    }

    checks
}

fn schema_document_check(
    label: &str,
    resolved_schema_paths: &BTreeMap<String, PathBuf>,
) -> PluginConformanceCheck {
    let Some(path) = resolved_schema_paths.get(label) else {
        return fail_check(
            format!("schema.{}", label),
            "schema",
            "Schema reference did not resolve during discovery.",
            json!({ "field": label }),
        );
    };

    validate_schema_document(label, path)
}

fn validate_schema_document(label: &str, path: &Path) -> PluginConformanceCheck {
    let content = match fs::read_to_string(path) {
        Ok(content) => content,
        Err(error) => {
            return fail_check(
                format!("schema.{}", label),
                "schema",
                "Schema document could not be read.",
                json!({
                    "field": label,
                    "path": path.display().to_string(),
                    "message": error.to_string(),
                }),
            );
        }
    };
    let schema_json = match serde_json::from_str::<Value>(&content) {
        Ok(value) => value,
        Err(error) => {
            return fail_check(
                format!("schema.{}", label),
                "schema",
                "Schema document is not valid JSON.",
                json!({
                    "field": label,
                    "path": path.display().to_string(),
                    "message": error.to_string(),
                }),
            );
        }
    };

    match jsonschema::validator_for(&schema_json) {
        Ok(_) => pass_check(
            format!("schema.{}", label),
            "schema",
            "Schema document is valid JSON Schema.",
            json!({
                "field": label,
                "path": path.display().to_string(),
            }),
        ),
        Err(error) => fail_check(
            format!("schema.{}", label),
            "schema",
            "Schema document is not valid JSON Schema.",
            json!({
                "field": label,
                "path": path.display().to_string(),
                "message": error.to_string(),
            }),
        ),
    }
}

fn aggregate_status(checks: &[PluginConformanceCheck]) -> PluginConformanceStatus {
    if checks
        .iter()
        .any(|check| check.status == PluginConformanceStatus::Fail)
    {
        PluginConformanceStatus::Fail
    } else if checks
        .iter()
        .any(|check| check.status == PluginConformanceStatus::Warn)
    {
        PluginConformanceStatus::Warn
    } else {
        PluginConformanceStatus::Pass
    }
}

fn count_checks(report: &PluginConformanceReport, status: PluginConformanceStatus) -> usize {
    report
        .checks
        .iter()
        .filter(|check| check.status == status)
        .count()
}

fn check_messages(
    report: &PluginConformanceReport,
    status: PluginConformanceStatus,
) -> Vec<String> {
    report
        .checks
        .iter()
        .filter(|check| check.status == status)
        .map(|check| format!("{}: {}", check.id, check.message))
        .collect()
}

fn promotion_decision(
    target_maturity: PluginMaturityLevel,
    failure_count: usize,
    warning_count: usize,
    skipped_count: usize,
) -> PluginPromotionDecision {
    if failure_count > 0 || skipped_count > 0 {
        PluginPromotionDecision::Blocked
    } else if warning_count > 0 {
        match target_maturity {
            PluginMaturityLevel::Internal | PluginMaturityLevel::Experimental => {
                PluginPromotionDecision::ReadyWithWarnings
            }
            PluginMaturityLevel::Beta | PluginMaturityLevel::Stable => {
                PluginPromotionDecision::Blocked
            }
        }
    } else {
        PluginPromotionDecision::Ready
    }
}

fn recommended_follow_ups(report: &PluginConformanceReport) -> Vec<String> {
    let mut follow_ups = Vec::new();
    for check in &report.checks {
        match check.status {
            PluginConformanceStatus::Fail => follow_ups.push(format!(
                "Fix conformance check `{}` before promotion: {}",
                check.id, check.message
            )),
            PluginConformanceStatus::Warn => follow_ups.push(format!(
                "Document or resolve warning `{}`: {}",
                check.id, check.message
            )),
            PluginConformanceStatus::Skipped => follow_ups.push(format!(
                "Provide deterministic evidence for skipped check `{}` before beta/stable promotion.",
                check.id
            )),
            PluginConformanceStatus::Pass => {}
        }
    }
    follow_ups
}

fn push_report_section(output: &mut String, title: &str, items: &[String], empty: &str) {
    output.push_str(&format!("## {}\n\n", title));
    if items.is_empty() {
        output.push_str(empty);
        output.push('\n');
    } else {
        for item in items {
            output.push_str(&format!("- {}\n", item));
        }
    }
    output.push('\n');
}

fn pass_check(
    id: impl Into<String>,
    category: impl Into<String>,
    message: impl Into<String>,
    details: Value,
) -> PluginConformanceCheck {
    check(
        id,
        category,
        PluginConformanceStatus::Pass,
        message,
        details,
    )
}

fn warn_check(
    id: impl Into<String>,
    category: impl Into<String>,
    message: impl Into<String>,
    details: Value,
) -> PluginConformanceCheck {
    check(
        id,
        category,
        PluginConformanceStatus::Warn,
        message,
        details,
    )
}

fn fail_check(
    id: impl Into<String>,
    category: impl Into<String>,
    message: impl Into<String>,
    details: Value,
) -> PluginConformanceCheck {
    check(
        id,
        category,
        PluginConformanceStatus::Fail,
        message,
        details,
    )
}

fn check(
    id: impl Into<String>,
    category: impl Into<String>,
    status: PluginConformanceStatus,
    message: impl Into<String>,
    details: Value,
) -> PluginConformanceCheck {
    PluginConformanceCheck {
        id: id.into(),
        category: category.into(),
        status,
        message: message.into(),
        details,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    use serde_json::{Value, json};

    use super::*;
    use crate::process_plugin::{
        ProcessPluginConnections, ProcessPluginRootKind, ProcessPluginRuntime, ProcessPluginSource,
        ProcessPluginTrustLevel, ProcessPluginUi,
    };

    #[test]
    fn default_criteria_define_all_maturity_levels() {
        let criteria = default_plugin_maturity_criteria();

        assert_eq!(
            criteria.iter().map(|item| item.level).collect::<Vec<_>>(),
            vec![
                PluginMaturityLevel::Internal,
                PluginMaturityLevel::Experimental,
                PluginMaturityLevel::Beta,
                PluginMaturityLevel::Stable,
            ]
        );
        assert!(criteria.iter().any(|item| {
            item.required_evidence
                .iter()
                .any(|evidence| evidence.contains("Supported capability classes"))
        }));
    }

    #[test]
    fn valid_candidate_passes_static_schema_conformance() {
        let temp = TempDir::new("conformance-valid");
        let candidate = candidate_with_schemas(temp.path(), true, r#"{"type":"object"}"#);

        let report = certify_process_plugin_candidate(&candidate, PluginMaturityLevel::Beta);

        assert_eq!(report.overall_status, PluginConformanceStatus::Pass);
        assert!(report.checks.iter().all(|check| {
            check.status == PluginConformanceStatus::Pass
                || check.status == PluginConformanceStatus::Skipped
        }));
        assert!(has_check(
            &report,
            "capability.query.risk_declared",
            PluginConformanceStatus::Pass
        ));
        assert!(has_check(
            &report,
            "schema.capabilities.query.input_schema",
            PluginConformanceStatus::Pass
        ));
    }

    #[test]
    fn missing_risk_and_invalid_schema_fail_conformance() {
        let temp = TempDir::new("conformance-invalid");
        let candidate = candidate_with_schemas(temp.path(), false, r#"{"type":42}"#);

        let report =
            certify_process_plugin_candidate(&candidate, PluginMaturityLevel::Experimental);

        assert_eq!(report.overall_status, PluginConformanceStatus::Fail);
        assert!(has_check(
            &report,
            "capability.query.risk_declared",
            PluginConformanceStatus::Fail
        ));
        assert!(has_check(
            &report,
            "schema.capabilities.query.input_schema",
            PluginConformanceStatus::Fail
        ));
    }

    #[test]
    fn complete_runtime_evidence_passes_required_checks() {
        let evidence = complete_runtime_evidence();

        let checks = runtime_conformance_checks(&evidence);

        assert_eq!(checks.len(), 6);
        assert!(checks.iter().all(|check| {
            check.status == PluginConformanceStatus::Pass
                && matches!(check.details["summary"], Value::String(_))
        }));
        assert!(
            checks
                .iter()
                .any(|check| check.id == "audit.invocation_events")
        );
    }

    #[test]
    fn missing_or_failed_runtime_evidence_blocks_conformance() {
        let evidence = PluginRuntimeConformanceEvidence {
            structured_errors: Some(PluginConformanceEvidence::passed(
                "Structured errors used stable categories.",
            )),
            redaction: Some(PluginConformanceEvidence::failed(
                "Redaction test exposed forbidden material.",
                json!({ "forbidden_field": "password" }),
            )),
            ..PluginRuntimeConformanceEvidence::default()
        };

        let checks = runtime_conformance_checks(&evidence);

        assert!(checks.iter().any(|check| {
            check.id == "runtime.redaction" && check.status == PluginConformanceStatus::Fail
        }));
        assert!(checks.iter().any(|check| {
            check.id == "runtime.timeout"
                && check.status == PluginConformanceStatus::Fail
                && check.message == "Required deterministic conformance evidence is missing."
        }));
    }

    #[test]
    fn applying_runtime_evidence_updates_report_status() {
        let temp = TempDir::new("conformance-runtime-report");
        let candidate = candidate_with_schemas(temp.path(), true, r#"{"type":"object"}"#);
        let mut report = certify_process_plugin_candidate(&candidate, PluginMaturityLevel::Beta);

        assert_eq!(report.overall_status, PluginConformanceStatus::Pass);

        apply_runtime_conformance_evidence(
            &mut report,
            &PluginRuntimeConformanceEvidence {
                health_check: Some(PluginConformanceEvidence::passed(
                    "Health check fixture succeeded.",
                )),
                ..PluginRuntimeConformanceEvidence::default()
            },
        );

        assert_eq!(report.overall_status, PluginConformanceStatus::Fail);
        assert!(has_check(
            &report,
            "runtime.health_check",
            PluginConformanceStatus::Pass
        ));
        assert!(has_check(
            &report,
            "audit.invocation_events",
            PluginConformanceStatus::Fail
        ));
    }

    #[test]
    fn certification_summary_counts_outcomes_and_blocks_beta_warnings() {
        let temp = TempDir::new("conformance-summary");
        let candidate = candidate_with_schemas(temp.path(), true, r#"{"type":"object"}"#);
        let mut report = certify_process_plugin_candidate(&candidate, PluginMaturityLevel::Beta);
        report.extend_checks(vec![
            warn_check(
                "runtime.redaction",
                "runtime",
                "Redaction fixture is incomplete.",
                Value::Null,
            ),
            check(
                "runtime.live_smoke",
                "runtime",
                PluginConformanceStatus::Skipped,
                "Live smoke requires an opt-in target.",
                Value::Null,
            ),
        ]);

        let summary = summarize_conformance_report(&report);

        assert_eq!(summary.warning_count, 1);
        assert_eq!(summary.skipped_count, 1);
        assert_eq!(summary.promotion_decision, PluginPromotionDecision::Blocked);
        assert!(summary.recommended_follow_ups.iter().any(|item| {
            item.contains("runtime.redaction") && item.contains("Document or resolve")
        }));
        assert!(
            summary
                .recommended_follow_ups
                .iter()
                .any(|item| item.contains("runtime.live_smoke"))
        );
    }

    #[test]
    fn markdown_report_lists_failures_skips_and_followups() {
        let report = PluginConformanceReport {
            plugin_id: "example".into(),
            target_maturity: PluginMaturityLevel::Stable,
            overall_status: PluginConformanceStatus::Fail,
            criteria: default_plugin_maturity_criteria(),
            checks: vec![
                fail_check(
                    "schema.capabilities.query.input_schema",
                    "schema",
                    "Schema document is not valid JSON Schema.",
                    Value::Null,
                ),
                check(
                    "runtime.live_smoke",
                    "runtime",
                    PluginConformanceStatus::Skipped,
                    "Live smoke requires an opt-in target.",
                    Value::Null,
                ),
            ],
        };

        let rendered = render_conformance_report_markdown(&report);

        assert!(rendered.contains("# Plugin Certification Report: example"));
        assert!(rendered.contains("- Promotion decision: `blocked`"));
        assert!(rendered.contains("## Blocking Failures"));
        assert!(rendered.contains("schema.capabilities.query.input_schema"));
        assert!(rendered.contains("## Skipped Checks"));
        assert!(rendered.contains("runtime.live_smoke"));
        assert!(rendered.contains("## Recommended Follow-Ups"));
    }

    fn has_check(
        report: &PluginConformanceReport,
        id: &str,
        status: PluginConformanceStatus,
    ) -> bool {
        report
            .checks
            .iter()
            .any(|check| check.id == id && check.status == status)
    }

    fn complete_runtime_evidence() -> PluginRuntimeConformanceEvidence {
        PluginRuntimeConformanceEvidence {
            structured_errors: Some(PluginConformanceEvidence::passed(
                "Structured target failures map to stable categories.",
            )),
            redaction: Some(PluginConformanceEvidence::passed(
                "Failure and output fixtures contain no secret material.",
            )),
            timeout: Some(PluginConformanceEvidence::passed(
                "Timeout fixture returns timeout.invocation_timed_out.",
            )),
            cancellation: Some(PluginConformanceEvidence::passed(
                "Cancellation fixture reports cancellation without orphaning state.",
            )),
            health_check: Some(PluginConformanceEvidence::passed(
                "Startup health fixture reaches ready state.",
            )),
            audit_events: Some(PluginConformanceEvidence::passed(
                "Invocation audit fixture includes actor, profile, policy, duration, and result.",
            )),
        }
    }

    fn candidate_with_schemas(
        root: &Path,
        declare_risk: bool,
        input_schema: &str,
    ) -> ProcessPluginCandidate {
        let plugin_dir = root.join("example");
        let schema_dir = plugin_dir.join("schemas");
        let bin_dir = plugin_dir.join("bin");
        fs::create_dir_all(&schema_dir).expect("create schema dir");
        fs::create_dir_all(&bin_dir).expect("create bin dir");
        let profile_schema =
            write_schema(&schema_dir, "profile.schema.json", r#"{"type":"object"}"#);
        let query_input_schema = write_schema(&schema_dir, "query-input.schema.json", input_schema);
        let query_output_schema = write_schema(
            &schema_dir,
            "query-output.schema.json",
            r#"{"type":"object"}"#,
        );
        let runtime_command = bin_dir.join("voidb-plugin-example");
        fs::write(&runtime_command, "#!/bin/sh\nexit 0\n").expect("write runtime");

        let capability = ProcessPluginCapability {
            id: "query".into(),
            description: "Run a bounded query.".into(),
            input_schema: "schemas/query-input.schema.json".into(),
            output_schema: "schemas/query-output.schema.json".into(),
            permissions: vec!["connection.read".into()],
            authorization: Default::default(),
            risk: declare_risk.then_some(CapabilityRiskLevel::ReadOnly),
            destructive: false,
            streaming: false,
            execution_mode: crate::CapabilityExecutionMode::Stateless,
            session_handoff: None,
            connection_required: true,
            required_secret_classes: Vec::new(),
            supports_dry_run: false,
            default_timeout_ms: Some(30_000),
        };
        let manifest = ProcessPluginManifest {
            schema: None,
            id: "example".into(),
            name: "Example".into(),
            version: "0.1.0".into(),
            protocol_version: "1".into(),
            description: Some("Example plugin.".into()),
            license: None,
            homepage: None,
            runtime: ProcessPluginRuntime {
                command: "voidb-plugin-example".into(),
                args: Vec::new(),
                transport: "stdio-jsonrpc".into(),
                env: BTreeMap::new(),
            },
            connections: ProcessPluginConnections {
                profile_schema: "schemas/profile.schema.json".into(),
                secret_classes: Vec::new(),
            },
            capabilities: vec![capability],
            ui: Some(ProcessPluginUi {
                tui: false,
                entrypoint_capability: None,
                raw_input: false,
            }),
            requirements: None,
        };

        let mut resolved_schema_paths = BTreeMap::new();
        resolved_schema_paths.insert("connections.profile_schema".into(), profile_schema);
        resolved_schema_paths.insert("capabilities.query.input_schema".into(), query_input_schema);
        resolved_schema_paths.insert(
            "capabilities.query.output_schema".into(),
            query_output_schema,
        );

        ProcessPluginCandidate {
            id: "example".into(),
            name: Some("Example".into()),
            version: Some("0.1.0".into()),
            protocol_version: Some("1".into()),
            manifest_path: plugin_dir.join("plugin.toml"),
            source: ProcessPluginSource {
                root: root.to_path_buf(),
                plugin_dir,
                kind: ProcessPluginRootKind::User,
                trust_level: ProcessPluginTrustLevel::UserInstalled,
                precedence: 0,
            },
            state: ProcessPluginCandidateState::Available,
            transport: Some("stdio-jsonrpc".into()),
            capability_count: 1,
            tui: false,
            diagnostics: Vec::new(),
            manifest: Some(manifest),
            resolved_runtime_command: Some(runtime_command),
            resolved_schema_paths,
        }
    }

    fn write_schema(root: &Path, name: &str, content: &str) -> PathBuf {
        let path = root.join(name);
        fs::write(&path, content).expect("write schema");
        path
    }

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(name: &str) -> Self {
            let nonce = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time after epoch")
                .as_nanos();
            let path = std::env::temp_dir().join(format!("voidb-{}-{}", name, nonce));
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
}
