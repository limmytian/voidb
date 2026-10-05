---
name: voidb-plugin-duckdb
description: Guide for the VoidB DuckDB plugin. Use when modifying crates/plugins/voidb-plugin-duckdb, duckdb.* capabilities, DuckDB CLI import/export/extensions, DuckDbService, DuckDbAgentSessionFactory, or SyncWorker-backed DuckDB table loading and SQL contract behavior.
---

# VoidB DuckDB Plugin

## Start Here

Primary crate: `crates/plugins/voidb-plugin-duckdb`.

Inspect:

- `src/config.rs` for `DuckDbConfig`.
- `src/service/` for `DuckDbService`, `DuckDbCommand`, `DuckDbEvent`, schema, CRUD, data loading, and value conversion.
- `src/capabilities.rs` for `duckdb.*` metadata and invocation.
- `src/cli_plugin.rs` for query, import/export, extension, and test commands.
- `src/agent_session.rs` for persistent agent sessions.
- `docs/duckdb-redis-release-readiness.md` for release-readiness decisions.

## Boundaries

- DuckDB connections are `!Send`; keep live connections inside `SyncWorker`.
- Expect slow clean builds because `libduckdb-sys` compiles native code.
- Preserve the shared SQL capability contract: `query`, `explain`, `exec`, `tables`, `describe_table`.
- Keep import/export/extension behavior explicit in CLI/service code, not hidden inside shell routing.
- Keep pagination, mutation gates, target errors, and redaction consistent with other SQL plugins.

## CLI And Capabilities

- CLI commands: `query`, `tables`, `describe`, `schemas`, `import`, `export`, `extensions`, `install-ext`, `test`.
- Capabilities: `duckdb.query`, `duckdb.explain`, `duckdb.exec`, `duckdb.tables`, `duckdb.describe_table`.

## Validation

- Focused gate: `cargo test -p voidb-plugin-duckdb`.
- Add `cargo test -p voidb-cli invoke` and `cargo test -p voidb-core sql_contract` for capability or SQL contract changes.
- Add `cargo test -p voidb-plugin-redis` and `cargo test -p voidb-cli duckdb_and_redis_release_readiness_catalog` for DuckDB/Redis release-readiness decisions.
- Always run `git diff --check`.
