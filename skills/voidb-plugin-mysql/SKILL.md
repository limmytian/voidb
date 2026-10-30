---
name: voidb-plugin-mysql
description: Guide for the VoidB MySQL plugin. Use when working on the external VoidB MySQL plugin repository, MySQL profiles, mysql.* capabilities, MySQL CLI commands, MySqlService, MySqlAgentSessionFactory, diagnostics, fixture smoke, or shared SQL contract behavior for MySQL/MariaDB.
---

# VoidB MySQL Plugin

## Where It Lives

The MySQL plugin is a decoupled process plugin that lives in its own
independent repository (`voidb-plugin-mysql`), not in this repository. Install
it with `voidb-cli plugin install-default` and run it through
`voidb-cli mysql ...` or the `mysql.*` capabilities.

## What It Does

MySQL and MariaDB capability plugin for VoidB: SQL `query`, `explain`, `exec`,
`tables`, and `describe_table` capabilities backed by `MySqlService`, plus
`voidb-cli mysql` domain commands (`query`, `databases`, `tables`, `describe`)
and persistent agent sessions. Native descriptor protocols: `mysql`,
`mariadb`.

## Development Guidance

Current development guidance lives in this repository:

- `docs/process-plugin-development-guide.md` for the service-layer and
  tri-modal (`test` / `tui` / `serve`) plugin contract.
- `templates/process-plugin-template/` for the plugin skeleton to start from.
- `docs/sql-capability-contract.md` for the shared SQL capability contract.
