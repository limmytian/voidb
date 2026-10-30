---
name: voidb-plugin-sqlite
description: Guide for the VoidB SQLite plugin. Use when working on the external VoidB SQLite plugin repository, sqlite.* capabilities, SQLite CLI commands, SqliteService, SqliteAgentSessionFactory, SyncWorker-backed local database access, or first protocol pair capability behavior.
---

# VoidB SQLite Plugin

## Where It Lives

The SQLite plugin is a decoupled process plugin that lives in its own
independent repository (`voidb-plugin-sqlite`), not in this repository. Install
it with `voidb-cli plugin install-default` and run it through
`voidb-cli sqlite ...` or the `sqlite.*` capabilities.

## What It Does

SQLite capability plugin for VoidB: local-database SQL `query`, `explain`,
`exec`, `tables`, and `describe_table` capabilities backed by `SqliteService`,
plus `voidb-cli sqlite` domain commands (`query`, `tables`, `describe`) and
persistent agent sessions. SQLite and Redis form the first protocol pair for
generic invoke behavior.

## Development Guidance

Current development guidance lives in this repository:

- `docs/process-plugin-development-guide.md` for the service-layer and
  tri-modal (`test` / `tui` / `serve`) plugin contract.
- `templates/process-plugin-template/` for the plugin skeleton to start from.
- `docs/sql-capability-contract.md` for the shared SQL capability contract.
