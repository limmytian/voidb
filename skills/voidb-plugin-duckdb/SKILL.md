---
name: voidb-plugin-duckdb
description: Guide for the VoidB DuckDB plugin. Use when working on the external VoidB DuckDB plugin repository, duckdb.* capabilities, DuckDB CLI import/export/extensions, DuckDbService, DuckDbAgentSessionFactory, or SyncWorker-backed DuckDB table loading and SQL contract behavior.
---

# VoidB DuckDB Plugin

## Where It Lives

The DuckDB plugin is a decoupled process plugin that lives in its own
independent repository (`voidb-plugin-duckdb`), not in this repository. Install
it with `voidb-cli plugin install-default` and run it through
`voidb-cli duckdb ...` or the `duckdb.*` capabilities.

## What It Does

DuckDB analytics capability plugin for VoidB: SQL `query`, `explain`, `exec`,
`tables`, and `describe_table` capabilities backed by `DuckDbService`, plus
`voidb-cli duckdb` domain commands for query, import/export, extensions, and
tests, and persistent agent sessions.

## Development Guidance

Current development guidance lives in this repository:

- `docs/process-plugin-development-guide.md` for the service-layer and
  tri-modal (`test` / `tui` / `serve`) plugin contract.
- `templates/process-plugin-template/` for the plugin skeleton to start from.
- `docs/sql-capability-contract.md` for the shared SQL capability contract.
