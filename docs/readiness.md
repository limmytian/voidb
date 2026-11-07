# Readiness Documentation Map

This page defines which VoidB documents describe current behavior and which
files are retained only as point-in-time evidence. Use it before relying on a
readiness, release, Agent, or TUI claim.

## Current Sources

| Area | Canonical source | Ownership |
|---|---|---|
| Architecture | [Architecture](architecture.md) and [Service Layer Design](service-layer-design.md) | Shell, Core, plugin, service, and live-handle boundaries. |
| Plugin development | [Process Plugin Development Guide](process-plugin-development-guide.md) | Process plugin contract, packaging, certification, and validation patterns. |
| Agent capability inventory | [Agent Capability and Experience Matrix](agent-capability-matrix.md) | Generated built-in capability list, risk, mode, timeout, streaming, cancellation, sessions, standalone TUIs, context handoff, validation, and known limits. |
| Agent interaction | [External-Agent Interaction Contract](assist-handoff.md) | Human-TUI context sharing, operation review, principal binding, replay, redaction, and ownership policy. |
| Agent operations | [Agent Operator, Migration, and Troubleshooting Guide](agent-operator-guide.md) | Adoption, JSON compatibility, execution-mode migration, authorization presets, session cleanup, local staging, common errors, upgrade, and rollback. |
| MCP gateway | [MCP Server](mcp-server.md) and [ADR: MCP Agent Gateway](adr-mcp-agent-gateway.md) | `vb mcp serve` protocol revision, tool/annotation mapping, broker-gated execution, resources, and the pinned-revision decision. |
| Iteration scope | [0.4.2 Iteration Roadmap](roadmap-0.4.2.md) | 0.4.2 workstreams (profile lifecycle CLI, release automation, quality batch, TUI dedup pilot), scope decisions, and non-goals. |
| TUI | [Plugin-Owned TUI Development Guide](plugin-owned-tui-development-guide.md) and [TUI CI and Real-Terminal Coverage](tui-terminal-coverage.md) | Retained TUI lifecycle, PTY journeys, performance thresholds, and evidence. |
| Security | [Security Notes](security.md), [Security Release Checklist](security-release-checklist.md), and [Secret Brokering and Redaction Policy](secret-brokering-redaction-policy.md) | Credential, authorization, acknowledgement, local-path, and redaction boundaries. |
| Validation | [CI Check Tiers](ci-checks.md), [Agent and TUI Aggregate Release Gate](agent-tui-release-gate.md), and [Release Candidate Checklist](release-candidate-checklist.md) | Focused checks, aggregate gates, full workspace tests, Clippy, fixtures, and packaging. |
| Sync | [Sync Boundary](sync-boundary.md), [Sync Plugin](sync-plugin.md), and [Object-Level Sync Model](object-level-sync-model.md) | E2E encryption, opt-in posture, recovery, and stable/default non-goals. |

The generated matrix is authoritative for the current built-in capability and
plugin-experience inventory. Generate it as JSON for tooling or Markdown for
documentation:

```bash
cargo run -p voidb-cli -- invoke matrix --format json
cargo run -p voidb-cli -- invoke matrix --format markdown
scripts/check-agent-capability-matrix.sh
```

Installed process plugins remain discoverable with `vb invoke list`.
They are intentionally absent from the repository-owned matrix because their
manifests and trust roots are node-local.

## Historical Evidence Rules

Files whose names carry a dated evidence, report, rehearsal, baseline, smoke,
handoff, or readiness snapshot are point-in-time evidence, not current product
contracts. Superseded design and planning documents have been removed from the
documentation tree; git history preserves their content.

Historical material keeps the facts, skips, commits, and commands that were
true for its recorded date and requirement. It must not be edited to look like
a current aggregate inventory, and it must not be restored into the tree as
one. When current code supersedes a historical claim, the current document
wins.

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
