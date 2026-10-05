---
name: voidb-plugin-mysql
description: Guide for the VoidB MySQL plugin. Use when modifying crates/plugins/voidb-plugin-mysql, MySQL profiles, mysql.* capabilities, MySQL CLI commands, MySqlService, MySqlAgentSessionFactory, diagnostics, fixture smoke, or shared SQL contract behavior for MySQL/MariaDB.
---

# VoidB MySQL Plugin

## Start Here

Primary crate: `crates/plugins/voidb-plugin-mysql`.

Read the touched surface first:

- `src/lib.rs` for `MySqlPlugin`, adapter exports, diagnostics, and public re-exports.
- `src/config.rs` for `MySqlConfig`, credential refs, and profile metadata.
- `src/service/` for `MySqlService`, channel/direct modes, schema, CRUD, paging, and value conversion.
- `src/capabilities.rs` for `mysql.*` capability metadata and invocation.
- `src/cli_plugin.rs` for `voidb-cli mysql ...` commands.
- `src/agent_session.rs` for persistent agent sessions.
- `docs/mysql-capability-migration.md` and `docs/mysql-release-readiness.md` when changing capability behavior.

## Boundaries

- Keep `mysql_async` usage inside this plugin crate, mainly adapter/service/capability code.
- TUI or shell code must not import MySQL driver types.
- Preserve the shared SQL capability contract: `query`, `explain`, `exec`, `tables`, `describe_table`.
- Keep mutation gates, dry-run behavior, database-selection validation, and redaction stable.
- Use `MySqlService` direct mode for CLI/capabilities and channel mode for TUI-style flows.

## CLI And Capabilities

- CLI commands: `query`, `databases`, `tables`, `describe`.
- Capabilities: `mysql.query`, `mysql.explain`, `mysql.exec`, `mysql.tables`, `mysql.describe_table`.
- Native descriptor protocols: `mysql`, `mariadb`.

## Validation

- Focused gate: `cargo check -p voidb-plugin-mysql --example fixture_smoke`.
- Run `cargo test -p voidb-plugin-mysql`.
- Add `cargo test -p voidb-cli invoke` and `cargo test -p voidb-core sql_contract` for capability or contract changes.
- Local fixture gate when feasible: `scripts/mysql-fixture-smoke.sh --report target/tmp/mysql-fixture-smoke-evidence.md`.
- Always run `git diff --check`.
