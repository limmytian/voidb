---
name: voidb-plugin-sqlite
description: Guide for the VoidB SQLite plugin. Use when modifying crates/plugins/voidb-plugin-sqlite, sqlite.* capabilities, SQLite CLI commands, SqliteService, SqliteAgentSessionFactory, SyncWorker-backed local database access, or first protocol pair capability behavior.
---

# VoidB SQLite Plugin

## Start Here

Primary crate: `crates/plugins/voidb-plugin-sqlite`.

Inspect:

- `src/config.rs` for `SqliteConfig`.
- `src/service/` for `SqliteService`, `SqliteCommand`, `SqliteEvent`, schema, CRUD, paging, and conversion.
- `src/capabilities.rs` for `sqlite.*` metadata and invocation.
- `src/cli_plugin.rs` for `voidb-cli sqlite ...`.
- `src/agent_session.rs` for persistent agent sessions.
- `docs/service-layer-design.md` for the `SyncWorker` pattern.

## Boundaries

- `rusqlite::Connection` is `!Send`; keep it on the dedicated `SyncWorker` thread.
- Do not call SQLite driver APIs from TUI shell or generic CLI code.
- Preserve the shared SQL capability contract: `query`, `explain`, `exec`, `tables`, `describe_table`.
- Keep file-path validation, target errors, mutation gates, pagination, and redaction deterministic.
- SQLite and Redis form the first protocol pair for generic invoke behavior; changes often need both pair and CLI invoke checks.

## CLI And Capabilities

- CLI commands: `query`, `tables`, `describe`.
- Capabilities: `sqlite.query`, `sqlite.explain`, `sqlite.exec`, `sqlite.tables`, `sqlite.describe_table`.

## Validation

- Focused gate: `cargo test -p voidb-plugin-sqlite`.
- Add `cargo test -p voidb-plugin-redis` and `cargo test -p voidb-cli invoke` for first-pair or generic invoke changes.
- Add `cargo test -p voidb-core sql_contract` for SQL contract behavior.
- Always run `git diff --check`.
