---
name: voidb-plugin-postgres
description: Guide for the VoidB PostgreSQL plugin. Use when modifying crates/plugins/voidb-plugin-postgres, postgres.* capabilities, PostgreSQL CLI commands, PostgresService, PostgresAgentSessionFactory, schema/table introspection, or SQL contract behavior with legacy postgresql profile compatibility.
---

# VoidB PostgreSQL Plugin

## Start Here

Primary crate: `crates/plugins/voidb-plugin-postgres`.

Inspect:

- `src/lib.rs` for `PostgresPlugin`, adapter exports, and public re-exports.
- `src/config.rs` for `PostgresConfig` and compatibility fields.
- `src/service/` for `PostgresService`, channel/direct modes, schema, CRUD, paging, and value conversion.
- `src/capabilities.rs` for `postgres.*` capability metadata and invocation.
- `src/cli_plugin.rs` for `voidb-cli postgres ...` commands.
- `src/agent_session.rs` for persistent agent sessions.

## Boundaries

- Keep `tokio-postgres`, TLS, and driver-specific types inside the plugin crate.
- Preserve legacy protocol/profile compatibility for `postgresql` while current CLI/capability namespace is `postgres`.
- Preserve the shared SQL capability contract: `query`, `explain`, `exec`, `tables`, `describe_table`.
- Keep schema handling explicit. PostgreSQL table listing and describe paths usually need schema context.
- Keep redaction, target errors, mutation gates, and dry-run behavior aligned with the SQL contract.

## CLI And Capabilities

- CLI commands: `query`, `databases`, `tables`, `describe`.
- Capabilities: `postgres.query`, `postgres.explain`, `postgres.exec`, `postgres.tables`, `postgres.describe_table`.
- Native descriptor protocols: `postgres`, `postgresql`.

## Validation

- Focused gate: `cargo test -p voidb-plugin-postgres capabilities`.
- Add `cargo test -p voidb-cli invoke` and `cargo test -p voidb-core sql_contract` for capability or contract changes.
- Use `scripts/postgres-session-fixture-smoke.sh` when persistent session behavior or live fixture evidence changes.
- Always run `git diff --check`.
