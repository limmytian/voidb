---
name: voidb-plugin-postgres
description: Guide for the VoidB PostgreSQL plugin. Use when working on the external VoidB PostgreSQL plugin repository, postgres.* capabilities, PostgreSQL CLI commands, PostgresService, PostgresAgentSessionFactory, schema/table introspection, or SQL contract behavior with legacy postgresql profile compatibility.
---

# VoidB PostgreSQL Plugin

## Where It Lives

The PostgreSQL plugin is a decoupled process plugin that lives in its own
independent repository (`voidb-plugin-postgres`), not in this repository.
Install it with `voidb-cli plugin install-default` and run it through
`voidb-cli postgres ...` or the `postgres.*` capabilities.

## What It Does

PostgreSQL capability plugin for VoidB: SQL `query`, `explain`, `exec`,
`tables`, and `describe_table` capabilities backed by `PostgresService` with
schema-aware introspection, plus `voidb-cli postgres` domain commands
(`query`, `databases`, `tables`, `describe`) and persistent agent sessions.
Native descriptor protocols: `postgres`, `postgresql`.

## Development Guidance

Current development guidance lives in this repository:

- `docs/process-plugin-development-guide.md` for the service-layer and
  tri-modal (`test` / `tui` / `serve`) plugin contract.
- `templates/process-plugin-template/` for the plugin skeleton to start from.
- `docs/sql-capability-contract.md` for the shared SQL capability contract.
