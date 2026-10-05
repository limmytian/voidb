# Readiness Documentation Map

This page defines which VoidB documents describe current behavior and which
files are retained only as point-in-time evidence. Use it before relying on a
readiness, release, Agent, or TUI claim.

## Current Sources

| Area | Canonical source | Ownership |
|---|---|---|
| Architecture | [Architecture](architecture.md) and [Service Layer Design](service-layer-design.md) | Shell, Core, plugin, service, and live-handle boundaries. |
| Plugin development | [Plugin Development Guide](plugin-development-guide.md) | Current plugin APIs, capability metadata, service modes, and validation patterns. |
| Agent capability inventory | [Agent Capability and Experience Matrix](agent-capability-matrix.md) | Generated built-in capability list, risk, mode, timeout, streaming, cancellation, sessions, standalone TUIs, context handoff, validation, and known limits. |
| Agent interaction | [External-Agent Interaction Contract](assist-handoff.md) | Human-TUI context sharing, operation review, principal binding, replay, redaction, and ownership policy. |
| Agent operations | [Agent Operator, Migration, and Troubleshooting Guide](agent-operator-guide.md) | Adoption, JSON compatibility, execution-mode migration, authorization presets, session cleanup, local staging, common errors, upgrade, and rollback. |
| TUI | [Plugin-Owned TUI Development Guide](plugin-owned-tui-development-guide.md) and [TUI CI and Real-Terminal Coverage](tui-terminal-coverage.md) | Retained TUI lifecycle, PTY journeys, performance thresholds, and evidence. |
| Security | [Security Notes](security.md), [Security Release Checklist](security-release-checklist.md), and [Secret Brokering and Redaction Policy](secret-brokering-redaction-policy.md) | Credential, authorization, acknowledgement, local-path, and redaction boundaries. |
| Validation | [CI Check Tiers](ci-checks.md), [Agent and TUI Aggregate Release Gate](agent-tui-release-gate.md), and [Release Candidate Checklist](release-candidate-checklist.md) | Focused checks, aggregate gates, full workspace tests, Clippy, fixtures, and packaging. |
| Sync | [Sync Boundary](sync-boundary.md), [Sync Plugin](sync-plugin.md), and Sync Beta Readiness | E2E encryption, opt-in posture, recovery, and stable/default non-goals. |

The generated matrix is authoritative for the current built-in capability and
plugin-experience inventory. Generate it as JSON for tooling or Markdown for
documentation:

```bash
cargo run -p voidb-cli -- invoke matrix --format json
cargo run -p voidb-cli -- invoke matrix --format markdown
scripts/check-agent-capability-matrix.sh
```

Installed process plugins remain discoverable with `voidb-cli invoke list`.
They are intentionally absent from the repository-owned matrix because their
manifests and trust roots are node-local.

## Historical Evidence Rules

The following documents are evidence, not current product contracts:

- filenames containing a dated evidence, report, rehearsal, baseline, smoke,
  handoff, or readiness snapshot;
- All-Plugin RC Readiness Matrix, which is
  the Req52 planning snapshot from 2026-07-05;
- [Plugin Maturity and Release Gates](plugin-roadmap.md), whose detailed
  inventory records the earlier Req46-Req83 planning program;
- Cloud Operations Promotion Report
  and other requirement-specific promotion reports.

Historical files keep the facts, skips, commits, and commands that were true
for their recorded date and requirement. They must not be edited to look like a
current aggregate inventory. When current code supersedes one of their claims,
the file should retain a visible historical banner and link here.

## Change Rules

- Add or change built-in capabilities in code, regenerate the matrix, and run
  the drift check. The check fails for added, removed, or changed capability
  rows and for undocumented built-in plugin IDs.
- Adding or removing a standalone TUI must update the checked experience
  metadata. CLI tests compare the metadata with registered `tui` commands.
- Update this page when ownership moves between current documents. Do not
  create another manually maintained aggregate matrix.
- Release evidence belongs under `target/tmp/` unless a dated, scoped handoff
  document is intentionally committed.
