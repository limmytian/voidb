# First Protocol Plugin Migration Pair

This document selects the first two plugins to migrate to the capability-first
protocol. It belongs to Requirement 04 and builds on:

- [Capability-First CLI Architecture ADR](adr-capability-first-cli-architecture.md)
- [Plugin Manifest Schema](plugin-manifest-schema.md)
- [Capability Discovery and Invocation CLI Contract](capability-cli.md)
- [Agent-Friendly Execution Controls](agent-friendly-execution-controls.md)
- [Plugin Maturity and Release Gates](plugin-roadmap.md)

## Decision

Migrate **SQLite plus Redis** first.

SQLite is the first SQL plugin. Redis is the first non-SQL plugin. Together
they cover local file-backed execution, networked service execution, SQL query
shapes, key-value workflows, pagination, destructive operations, and different
service-layer runtime models without requiring two external services for the
first protocol slice.

MySQL remains the first follow-up SQL migration after the SQLite and Redis
protocol path is working. It is the right plugin for validating networked SQL,
authentication variants, connection pools, and server-side database selection,
but it should not be the first SQL plugin because it makes the initial protocol
test harness depend on an external database.

## Options Compared

| Pair | Coverage | Cost | Decision |
|---|---|---|---|
| SQLite + Redis | Local SQL, `SyncWorker`, networked non-SQL, pagination, destructive commands | One external service for Redis only | Selected |
| MySQL + Redis | Networked SQL, connection pools, networked non-SQL, pagination, destructive commands | Two external services or fixtures for useful tests | Defer MySQL to follow-up |

## Selection Criteria

The first pair should maximize protocol learning while keeping feedback loops
short:

- one SQL plugin and one non-SQL plugin
- one deterministic local plugin for tests and examples
- one networked plugin for connection and transport failures
- existing service-layer direct mode usable by the CLI
- operations that exercise query/list/describe and get/set/delete workflows
- meaningful pagination or streaming pressure
- destructive operation metadata and policy checks
- credential and redaction paths without forcing broad secret-broker plumbing
- enough maturity to avoid chasing unrelated plugin bugs

SQLite plus Redis gives the best mix for the first protocol slice.

## SQLite Scope

SQLite should expose the first SQL capability set:

| Capability | Purpose | Notes |
|---|---|---|
| `query` | Execute read-oriented SQL and return rows. | Non-destructive by default. |
| `exec` | Execute SQL that may mutate schema or data. | Destructive unless a statement classifier proves otherwise. |
| `tables` | List tables and views. | Bounded metadata output. |
| `describe_table` | Return columns, indexes, and foreign keys. | Exercises schema-shaped output. |

Why SQLite first:

- It has direct-mode service methods already used by the CLI.
- It is file-backed and can be tested with temporary databases.
- It exercises the `SyncWorker` path for `!Send` driver state.
- It validates that capability invocations do not assume a network pool.
- It can produce deterministic examples for schema discovery and repeated
  runtime instances from one profile.

Expected SQLite protocol coverage:

- profile schema for a local database path
- `connection_required = true`
- query input/output schemas
- destructive `exec` metadata
- JSON output for row sets and schema metadata
- validation errors for invalid SQL input shapes
- target-system errors for SQLite execution failures

SQLite gaps that remain for later SQL plugins:

- network authentication
- TLS and network transport failures
- pool lifecycle
- server/database selection
- multi-tenant credential variants

Those gaps are why MySQL should follow after the first pair.

## Redis Scope

Redis should expose the first non-SQL capability set:

| Capability | Purpose | Notes |
|---|---|---|
| `keys` | Scan keys by pattern with a limit or cursor. | Exercises pagination and bounded listing. |
| `get` | Fetch one key value and metadata. | Read-only key-value output. |
| `set` | Set a string key. | Destructive. |
| `del` | Delete a key. | Destructive. |
| `ttl` | Read one key TTL. | Read-only; mutation is not accepted. |
| `expire` | Set or remove one key TTL. | Destructive and dry-run capable. |
| `info` | Fetch server info sections. | Useful health and metadata surface. |
| `exec` | Execute a raw Redis command. | Destructive by default unless restricted later. |

Why Redis first:

- It is already a direct-mode service consumer.
- It exercises a networked target without requiring SQL-specific behavior.
- It has natural pagination through key scanning.
- It includes read, write, delete, TTL, and raw command flows.
- It validates structured target errors and unavailable-service handling.
- It represents common agent automation needs beyond databases.

Expected Redis protocol coverage:

- profile schema for host, port, database, TLS, and credential references
- target unavailable and auth failure mapping
- paginated or limited key scans
- destructive metadata for `set`, `del`, mutating `ttl`, and unrestricted
  `exec`
- redaction of command diagnostics and target messages
- optional NDJSON streaming for large key scans after the basic JSON path

## Why Not MySQL First

MySQL is a strong second SQL migration, not the first.

Reasons to defer it:

- Useful tests require a running server or container fixture.
- Connection setup includes host, port, database, username, password, and
  server availability failure modes.
- Pool lifecycle and networked SQL errors add complexity before the protocol
  harness is proven.
- MySQL duplicates many SQL capability shapes that SQLite can validate with a
  faster local fixture.

Reasons to migrate it next:

- It validates networked SQL, auth, pool lifecycle, and database selection.
- It is classified as release candidate in the plugin roadmap.
- It is representative of PostgreSQL and other networked SQL plugins.

The intended order is:

1. SQLite protocol capability metadata and handlers.
2. Redis protocol capability metadata and handlers.
3. Shared examples and tests for the selected pair.
4. MySQL as the first networked SQL follow-up.

## Implementation Guidance

The next slice, `Expose capability metadata and handlers`, should target
SQLite and Redis only. It should keep compatibility with the current direct CLI
commands while adding the new capability-first metadata and invocation path.

Minimum deliverables:

- manifest capability entries for SQLite and Redis
- input and output JSON Schemas for the selected capabilities
- capability metadata exposed through the new discovery model
- invocation handlers that call existing service-layer direct methods
- structured success envelopes and `CapabilityError` mapping
- redaction-safe output summaries
- focused tests for schema discovery and at least one invocation per plugin

Non-goals for the next slice:

- broad migration of all SQL plugins
- replacing the existing TUI shell
- implementing a plugin marketplace
- complete credential broker internals beyond safe profile references
- full MySQL migration

## Validation Plan

SQLite validation should use temporary databases and run in normal cargo tests.
It should cover:

- profile schema validation for a database path
- `query` returning row JSON
- `tables` or `describe_table` returning schema metadata
- `exec` requiring destructive metadata
- one SQL target error mapped to `target_system`

Redis validation may use unit tests around metadata and schema shape first,
then an opt-in integration test for a real Redis server. It should cover:

- profile schema validation
- `keys` limit or cursor behavior
- `get` read output shape
- `set` or `del` destructive metadata
- unavailable target mapped to `transport` or `unavailable`

## Invariants

- The first migration pair is SQLite plus Redis.
- SQLite validates local SQL and `SyncWorker` behavior.
- Redis validates networked non-SQL behavior and pagination pressure.
- MySQL is deferred only to keep the first protocol loop deterministic; it
  remains the first networked SQL follow-up.
- The selected plugins must use service-layer direct methods for CLI and
  protocol execution.
- TUI code must not become the protocol boundary.
