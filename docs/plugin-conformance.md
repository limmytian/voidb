# Plugin Conformance And Certification

VoidB promotes plugins with evidence, not manual judgment. The conformance kit
starts with deterministic checks that need no live credentials and no target
services, then layers runtime behavior, audit, and reporting checks on top.

The core entry point for static checks is
`certify_process_plugin_candidate(candidate, target_maturity)` in
`voidb-core::plugin_conformance`.

## Maturity Levels

| Level | Meaning | Required evidence |
|---|---|---|
| `internal` | Private, development, or bundled implementation detail. | Maintainer-facing risks are documented. No agent-facing readiness claim. |
| `experimental` | Discoverable plugin with valid static metadata and disclosed gaps. | Manifest decodes; runtime declaration, profile schema, capability schemas, risk, and permissions pass static conformance; supported capability classes and known unsupported behavior are documented. |
| `beta` | Agent-facing plugin with deterministic contract evidence. | Experimental checks pass; structured errors, redaction, timeout/cancellation, health checks, and audit events have deterministic coverage without live secrets. |
| `stable` | Release-ready plugin with repeatable promotion evidence. | Beta checks pass; version compatibility, release smoke, live-skip rationale, and supported capability limitations are documented; no blocking conformance failures remain. |

Promotion can stop at any lower level when gaps are intentional. Stable and
beta decisions must disclose skipped live checks separately from regressions.

## Static Checks

The first conformance slice covers process-plugin manifests and capability
schema metadata:

- Candidate state must be `available`.
- Discovery diagnostics must have no blocking errors. Warnings are carried into
  the conformance report.
- Manifest `id` must match the candidate id.
- Manifest `version` must parse as semver.
- Runtime transport must be `stdio-jsonrpc`.
- Runtime command must resolve inside an allowed plugin root.
- Manifest must declare at least one capability.
- Optional TUI entrypoint capability must refer to a declared capability.
- Every capability must declare explicit `risk` and stable permission strings.
- `destructive = true` with `risk = read_only` is reported as a warning because
  Core raises the effective risk to `destructive`.
- `supports_dry_run = true` on read-only capabilities is reported as a warning.
- Connection profile, capability input, and capability output schema references
  must resolve and compile as JSON Schema documents.

These checks are deterministic and safe to run in CI. They do not start plugin
processes, open network connections, read credentials, or invoke target systems.

## Report Contract

`PluginConformanceReport` contains:

- `plugin_id`
- `target_maturity`
- `overall_status`: `pass`, `warn`, or `fail`
- `criteria`: the default maturity criteria used for interpretation
- `checks`: individual `PluginConformanceCheck` records with stable ids,
  category, status, message, and structured details

`PluginCertificationSummary` is the compact JSON promotion surface. It
contains the target maturity, aggregate status, promotion decision, pass/warn/
fail/skipped counts, blocking failure messages, warning messages, skipped
checks, and recommended follow-up requirements.

`render_conformance_report_markdown(report)` produces the human-readable form
for release notes, Task Weaver summaries, and manual review. It includes:

- target maturity and aggregate status
- promotion decision
- pass/warn/fail/skipped counts
- blocking failures
- warnings
- skipped checks, including skipped live checks
- recommended follow-up requirements

Promotion decisions are intentionally conservative:

- `ready`: no failures, warnings, or skipped checks.
- `ready_with_warnings`: warnings only, and the target maturity is
  `internal` or `experimental`.
- `blocked`: any failure or skipped check, or any warning for `beta` or
  `stable` promotion.

Runtime and safety checks use `PluginRuntimeConformanceEvidence` and append to
the same report shape through `apply_runtime_conformance_evidence`. A beta or
stable candidate must provide deterministic evidence for all of these checks:

- `runtime.structured_errors`: stable error categories and machine-readable
  fields.
- `runtime.redaction`: failures and outputs do not expose plaintext secrets,
  sensitive aliases, hosts, usernames, labels, or credential material.
- `runtime.timeout`: timeout fixtures return structured timeout errors.
- `runtime.cancellation`: cancellation fixtures complete without orphaned
  invocation state.
- `runtime.health_check`: startup and health-check fixtures exercise ready and
  failure paths.
- `audit.invocation_events`: invocation audit fixtures include actor, profile,
  policy decision, duration, and result metadata while staying redacted.

Missing runtime evidence is a conformance failure. Failed evidence is also a
failure. Skipped live checks should be represented as skipped checks in the
report, and the follow-up recommendation should name the disposable fixture or
opt-in environment required to close the gap. Evidence details should summarize
the fixture or inherited gap without copying secrets, raw command output, raw
SQL, or target credentials.

Later slices should add report generation and promotion workflow features to
the same report shape instead of introducing parallel maturity or status
models.

## Author Obligations

Plugin authors should treat a conformance failure as a promotion blocker.
Warnings are allowed for experimental work only when the risk is documented and
the plugin roadmap names a follow-up. A plugin must not be promoted to beta or
stable while static schema, risk, permission, or manifest checks fail.
