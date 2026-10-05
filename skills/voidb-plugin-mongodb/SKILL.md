---
name: voidb-plugin-mongodb
description: Guide for the VoidB MongoDB plugin. Use when modifying crates/plugins/voidb-plugin-mongodb, mongodb.* capabilities, MongoDB CLI commands, MongoService document/database/index operations, MongoAgentSessionFactory, BSON/JSON conversion, diagnostics, or fixture smoke behavior.
---

# VoidB MongoDB Plugin

## Start Here

Primary crate: `crates/plugins/voidb-plugin-mongodb`.

Inspect:

- `src/config.rs` for `MongoConfig`, auth, and TLS options.
- `src/mongo_ops.rs` for low-level MongoDB operations.
- `src/service/` for database, document, index, command, event, and shared types.
- `src/capabilities.rs` for `mongodb.*` metadata and invocation.
- `src/cli_plugin.rs` for `voidb-cli mongodb ...`.
- `src/agent_session.rs` for persistent agent sessions.
- `docs/mongodb-release-readiness.md` when changing capability or release behavior.

## Boundaries

- Keep `mongodb` and `bson` driver types inside this plugin crate.
- Use service/domain types at the boundary; avoid leaking raw BSON details into shared core or shell code.
- Preserve bounded reads, pagination/limit defaults, target errors, diagnostics, and redaction.
- Treat `insert`, `update`, `delete`, `create_index`, and `run_command` as policy-sensitive operations.
- Keep JSON/BSON conversion explicit and covered by tests.

## CLI And Capabilities

- CLI commands: `dbs`, `collections`, `stats`, `find`, `count`, `insert`, `update`, `delete`, `aggregate`, `indexes`, `create-index`, `exec`, `test`.
- Capabilities: `mongodb.diagnostics`, `mongodb.databases`, `mongodb.collections`, `mongodb.find`, `mongodb.count`, `mongodb.aggregate`, `mongodb.indexes`, `mongodb.insert`, `mongodb.update`, `mongodb.delete`, `mongodb.create_index`, `mongodb.run_command`.

## Validation

- Focused gate: `cargo check -p voidb-plugin-mongodb --example fixture_smoke`.
- Run `cargo test -p voidb-plugin-mongodb`.
- Add `cargo test -p voidb-cli invoke` for capability or generic invoke changes.
- Fixture gate when feasible: `scripts/mongodb-fixture-smoke.sh --report target/tmp/mongodb-fixture-smoke-evidence.md`.
- Always run `git diff --check`.
