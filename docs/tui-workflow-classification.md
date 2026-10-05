# TUI Workflow Classification

This document classifies which VoidB workflows should retain TUI support after
the capability-first migration, and which should move to CLI-first capability
execution.

It belongs to Requirement 05 and builds on:

- [Capability-First CLI Architecture ADR](adr-capability-first-cli-architecture.md)
- [Capability Discovery and Invocation CLI Contract](capability-cli.md)
- [First Protocol Plugin Migration Pair](first-protocol-plugin-migration.md)
- [Plugin Maturity and Release Gates](plugin-roadmap.md)
- [TUI Adapter Boundary](tui-adapter-boundary.md)
- Database TUI Downscoping Plan

## Decision

The TUI remains valuable, but only as an optional human frontend. It should not
be the core plugin contract, the primary agent interface, or the only path for
protocol execution. For future plugin workflows, "TUI" means a new
plugin-owned standalone command, not a default router-hosted shell tab.

Retain TUI surfaces when a workflow is inherently interactive, spatial,
long-lived, or visually triaged by a human:

- interactive terminal sessions
- SFTP and local/remote file browsing
- live log tailing, shell attach, exec, and port-forward sessions
- manual connection profile creation, editing, testing, and launch
- large human-readable inspectors where keyboard navigation is materially
  better than repeated commands

Move workflows to CLI-first capability execution when they are repeatable,
scriptable, auditable, or agent-oriented:

- schema, profile, plugin, and capability discovery
- query, command, search, and metadata requests
- create, update, delete, sync, trigger, and deploy operations
- import, export, upload, download, and transfer operations
- health checks, diagnostics, and structured error reporting

## Classification Labels

| Label | Meaning | Implementation direction |
|---|---|---|
| Retain TUI | A future plugin-owned standalone TUI may be a first-class optional frontend for human workflows. | Add it only after CLI/capability coverage and plugin-owned TUI gates pass. |
| Thin TUI Adapter | Keep or rebuild a smaller TUI only after the capability contract is stable. | Stop growing bespoke router-hosted UI; prefer CLI-first behavior or plugin-owned standalone apps. |
| CLI First | The workflow should be driven through CLI/capability execution. | Prioritize JSON/NDJSON output, schemas, policies, audit, and tests before TUI polish. |
| Defer TUI | No TUI is shipped yet, but the workflow may justify future plugin-owned UI. | Use CLI and docs until the core protocol and boundary settle. |

## Plugin Classification

| Plugin or surface | TUI classification | Human TUI surface | Move to CLI-first capabilities | Rationale |
|---|---|---|---|---|
| Connection Manager | Retain TUI | Manual profile catalog, connection dialog, test connection, open tabs, tab launcher. | Profile list/get/create/update/delete/test/validate with secret-safe JSON. | Human setup and visual launch are useful, but agents need profile commands that never depend on TUI state. |
| MySQL | CLI First | No shipped TUI. | Query, exec, schema list/describe, import/export, copy table, table mutations, diagnostics. | SQL work is highly scriptable; no standalone TUI is retained until a plugin-specific design beats CLI/capability workflows. |
| PostgreSQL | CLI First | No shipped TUI. | Same as MySQL, plus server-specific schema and metadata capabilities. | Keep parity with MySQL through shared SQL abstractions rather than separate TUI growth. |
| SQLite | CLI First | No shipped TUI. | `query`, `exec`, `tables`, `describe_table`, export/import, diagnostics. | SQLite is the first local SQL capability path; future TUI work must be plugin-owned and evidence-backed. |
| DuckDB | CLI First | No shipped TUI. | Query, exec, schema discovery, import/export, file metadata. | DuckDB is useful interactively, but native build cost and analytics use cases favor CLI-first repeatability. |
| Redis | CLI First | No shipped TUI. | `keys`, `get`, `set`, `del`, `ttl`, `info`, `exec`, bounded scans. | Redis validates non-SQL capabilities first; no standalone key inspector is retained until it passes the rebuild gate. |
| MongoDB | CLI First | No shipped TUI. | Collection discovery, find, aggregate, insert, update, delete, index metadata. | Document operations need structured JSON and stable error handling more than key-driven UI state. |
| Elasticsearch | CLI First | No shipped TUI. | Search, raw API, index metadata, mapping, document mutation, cluster health. | JSON search and index operations are agent-friendly; future standalone search triage needs plugin-specific evidence. |
| Email | Defer TUI | No shipped TUI. | List folders, search messages, fetch message, send message, attachment metadata, SMTP/IMAP diagnostics. | Humans may benefit from a reader/composer, but the current product surface is deterministic mailbox capabilities. |
| SSH | Defer TUI | No shipped TUI. | `ssh.test`, `ssh.exec`, SFTP list/get/put/mkdir/rm, diagnostics, and future tunnel create/list/close capabilities. | SSH terminal and SFTP are interactive, but future UI must be plugin-owned and separately evidenced. |
| Docker | Defer TUI | No shipped TUI. | List/inspect/start/stop/restart/remove, log fetch, exec command, image/network/volume operations. | Live logs and shell attach may justify future UI; resource operations should be capability driven. |
| Kubernetes | Defer TUI | No shipped TUI. | List/describe/get logs/apply/delete/scale/rollout operations with structured output. | Operators may need interactive triage; agents need auditable capability calls first. |
| WebDAV | Defer TUI | No shipped TUI. | List, stat, upload, download, delete, mkdir, rename, sync plan/apply. | Manual file navigation may benefit from panels; transfer actions need scriptable, auditable commands. |
| S3 | Defer TUI | No shipped TUI. | List buckets/objects, get/put/delete/copy, sync plan/apply, metadata, presign. | Object storage is mostly scriptable; future UI must prove human browsing value. |
| Jenkins | Defer TUI | No shipped TUI. | List jobs/builds, trigger build, stop build, fetch console log, activity/queue status. | Live logs and pipeline status are visual human workflows; automation should use CLI capabilities. |
| Sync | CLI First | Optional minimal human status and setup only after sync policy stabilizes. | Register, login, push, pull, status, conflict resolution, force/revision handling. | Sync is a policy and automation surface; it should not drive TUI architecture decisions. |

## Workflow Classification

| Workflow | Classification | Notes |
|---|---|---|
| Plugin and capability discovery | CLI First | Agents need deterministic JSON. TUI can display discovered metadata later. |
| Connection profile CRUD | CLI First plus retained TUI setup | The TUI dialog is useful for humans, but the public contract should be profile commands. |
| Connection testing | CLI First plus retained TUI trigger | Test results should use the same structured error model as capabilities. |
| SQL querying and schema introspection | CLI First | Query outputs, pagination, errors, and audit should be stable JSON/NDJSON. |
| SQL table editing and paste preview | Thin TUI Adapter | Useful for humans, but should be rebuilt on shared SQL services after capability work settles. |
| Key/document/object browsing | Thin TUI Adapter | Browsers can stay as human inspectors, while mutations move to capabilities. |
| Interactive terminals | Retain TUI | Raw input and screen state are a natural TUI domain. |
| Live logs and attach/exec sessions | Retain TUI | Continuous streams and manual search/scroll are high-value TUI features. |
| File transfer panels | Thin TUI Adapter | TUI panels are useful for selection; actual operations should map to capabilities. |
| Sync and distribution workflows | CLI First | Keep machine-readable state, conflict handling, and audit ahead of TUI. |

## Near-Term Guidance

1. Do not add new shell-level UI responsibilities for plugin features.
2. Do not expand database browser or table UI work until the shared SQL
   capability and [TUI adapter boundary](tui-adapter-boundary.md) are defined.
   Apply the Database TUI Downscoping Plan while
   that work is in progress.
3. Keep SSH, SFTP, terminal, live logs, attach/exec, and port-forward UX
   working while capability work proceeds. Use the fixture-backed SSH smoke in
   [SSH Plugin](ssh-plugin.md) after changes to raw input, host-key prompts,
   SFTP, forwarding, reconnect, or session persistence.
4. Route manual profile management through a profile service that the CLI and
   TUI can both consume.
5. Treat plugin TUI code as an adapter over services/capabilities, not as the
   authoritative protocol implementation.
6. Launch retained plugin TUIs from plugin CLI commands and validate them with
   the standalone PTY gate in
   [Standalone TUI UX Acceptance Criteria](standalone-tui-ux-acceptance.md).

## Non-Goals

- Removing the existing TUI shell.
- Removing compatibility plugin factories immediately.
- Rewriting plugin UIs in this slice.
