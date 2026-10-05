# ADR: Capability-First CLI Architecture

## Status

Accepted for planning.

## Date

2026-07-04

## Context

VoidB v4 is currently shaped around a pure-router TUI shell. The shell routes
events, owns tabs, and delegates full-screen rendering and state to autonomous
plugins. This is a cleaner architecture than earlier shell-owned UI designs, but
the product direction is still TUI-first.

That priority no longer matches the most important usage pattern. AI agents are
now a primary operator for developer and infrastructure tools. A TUI is useful
for some human workflows, but it is a poor primary interface for agents:

- State is visual and hard to inspect reliably.
- Actions are key-driven and difficult to compose.
- Output is optimized for reading, not structured automation.
- Error handling and retries are hard to standardize.

A CLI is better for agents, but the real architectural shift is broader than
"add more subcommands". VoidB should become capability-first:

- Core manages connection profiles, credentials, policy, plugin discovery, and
  audit logs.
- Plugins expose structured capabilities with schemas and permission
  declarations.
- The CLI is the first frontend for those capabilities.
- TUI surfaces become optional frontends owned by plugins or adapters.

VoidB still has a clear product value after stepping back from a TUI-first
identity. Its durable value is a unified, user-owned connection management layer
that can safely broker access to databases, infrastructure, storage, and remote
services without exposing raw connection secrets to AI agents.

## Decision

VoidB will shift from a TUI-first terminal database manager to a
capability-first connection and execution platform.

The first-class interface will be a machine-readable CLI backed by a stable
plugin capability protocol. The TUI will remain available where it provides real
value, but it will no longer define the core plugin contract.

The target architecture is:

```text
VoidB Core
  connection profiles
  credential storage and brokering
  plugin discovery and lifecycle
  permission policy
  invocation audit logs
  structured errors

VoidB Plugin Protocol
  manifest
  capability catalog
  input/output schemas
  permission declarations
  invocation transport

VoidB CLI
  human and agent entrypoint
  structured JSON / NDJSON output
  stable error codes
  command discovery

Plugins
  protocol-specific execution capabilities
  optional TUI surfaces
  optional background workers

Optional Extensions
  sync
  hosted catalogs
  richer human UI
```

## Connection Model

The architecture must separate saved connection information from runtime
connection entities.

The concrete profile, runtime instance, and invocation type boundaries are
defined in [Capability Core Model](capability-core-model.md).

### Connection Profile

A connection profile is user-managed metadata and credential configuration. It
contains the stable identity that users and agents reference, for example:

- alias or ID
- plugin ID
- host, port, database, region, bucket, namespace, or service metadata
- credential references or encrypted credential blobs
- policy and default options

Profiles are managed by VoidB Core. Agents should reference profiles by ID or
alias, not by raw secret values.

### Connection Instance

A connection instance is a runtime entity created from a profile for a specific
operation, session, tunnel, worker, or plugin-defined purpose.

One profile can produce zero, one, or many runtime instances. Some connection
information is intentionally reusable and may be instantiated multiple times,
including concurrently. Examples include:

- multiple SQL sessions from the same database profile
- separate read-only and migration execution sessions
- concurrent Redis command streams
- SSH terminal, SFTP, and tunnel sessions derived from the same SSH profile
- repeated short-lived object storage clients from one S3 profile

VoidB Core must not assume a saved profile maps to a singleton live connection.
Plugins own their runtime connection lifecycle, pools, workers, and cleanup.
Core brokers profile access and credential material according to policy.

### Capability Invocation

A capability invocation is one structured request to a plugin command. It may
reuse an existing instance, create a new instance, or run without a persistent
instance. That choice belongs to the plugin and must be described through
capability metadata when it affects behavior.

## Security Model

VoidB should protect secrets from accidental or routine exposure to AI agents,
but it should not overstate what is possible in a local process model.

The security promise is:

> VoidB does not expose plaintext connection secrets through the agent-facing
> CLI or plugin capability protocol. Agents invoke controlled capabilities by
> connection profile ID or alias.

This is not the same as claiming that a fully local agent with arbitrary file
and process access can never obtain secrets. Stronger guarantees would require
additional OS-level isolation, keychain mediation, or a broker process with a
smaller trust boundary.

Required baseline behaviors:

- CLI output must never include passwords, tokens, private keys, or decrypted
  secret blobs.
- Plugins receive only the credential material required for an invocation.
- Plugin manifests declare required credential classes and permissions.
- Destructive operations are explicitly marked and can require policy approval,
  confirmation, or allowlist configuration.
- All capability invocations produce audit records with actor, profile,
  plugin, command, arguments metadata, result status, and timing.
- Structured errors must distinguish validation, auth, permission, transport,
  timeout, plugin, and target-system failures.
- Redaction must be applied before logs, traces, and CLI output are written.

The detailed data exposure, credential grant, redaction, and local trust-boundary
rules are defined in
[Secret Brokering and Redaction Policy](secret-brokering-redaction-policy.md).
Invocation audit fields, stable error categories, timing metadata, actor
attribution, and target-system failure reporting are defined in
[Audit and Structured Error Schema](audit-and-error-schema.md).

## Plugin Protocol

Runtime plugin loading should be process-based first, not Rust dynamic-library
based.

Rust dynamic library ABI stability, dependency conflicts, and crash isolation
make dynamic linking a poor first step. Process plugins give VoidB a cleaner
extension boundary and allow plugins to be distributed, upgraded, and executed
independently.

The draft process-plugin manifest shape is defined in
[Plugin Manifest Schema](plugin-manifest-schema.md), with a machine-readable
schema at
[`schemas/plugin-manifest.schema.json`](../schemas/plugin-manifest.schema.json).
The first invocation transport is defined in
[Plugin Invocation Transport](plugin-invocation-transport.md), with a
machine-readable envelope schema at
[`schemas/plugin-invocation-transport.schema.json`](../schemas/plugin-invocation-transport.schema.json).
Installed plugin search paths, manifest validation, on-demand process startup,
crash handling, and version compatibility are defined in
[Runtime Plugin Discovery](runtime-plugin-discovery.md).
Agent-facing saved profile commands are defined in
[Connection Profile CLI Contract](connection-profile-cli.md).
Agent-facing plugin discovery, capability discovery, and generic invocation
commands are defined in
[Capability Discovery and Invocation CLI Contract](capability-cli.md).
Timeout, cancellation, pagination, streaming, dry-run, destructive operation,
and exit-code behavior are defined in
[Agent-Friendly Execution Controls](agent-friendly-execution-controls.md).

Each plugin should ship a manifest similar to:

```toml
id = "mysql"
name = "MySQL"
version = "0.1.0"
protocol_version = "1"

[runtime]
command = "voidb-plugin-mysql"
transport = "stdio-jsonrpc"

[connections]
profile_schema = "schemas/mysql-profile.schema.json"
secret_classes = ["password", "client_certificate"]

[[capabilities]]
id = "query"
description = "Execute a read-oriented SQL query."
input_schema = "schemas/query-input.schema.json"
output_schema = "schemas/query-output.schema.json"
permissions = ["connection.read", "sql.query"]
destructive = false
streaming = false

[[capabilities]]
id = "exec"
description = "Execute a SQL statement that may mutate data."
input_schema = "schemas/exec-input.schema.json"
output_schema = "schemas/exec-output.schema.json"
permissions = ["connection.read", "sql.exec"]
destructive = true
streaming = false

[ui]
tui = false
```

The protocol must support:

- plugin metadata discovery
- profile schema discovery
- capability listing
- input and output JSON Schema
- synchronous invocation
- streaming invocation through NDJSON or JSON-RPC notifications
- cancellation
- timeouts
- structured error responses
- plugin health checks
- version negotiation

## CLI Shape

The CLI should be stable, discoverable, and easy for agents to parse.

Examples:

```bash
voidb profile list --format json
voidb profile create --plugin mysql --name prod --input profile.json
voidb profile test prod --format json

voidb plugin list --format json
voidb plugin describe mysql --format json
voidb plugin install mysql

voidb capability list mysql --format json
voidb capability describe mysql.query --format json

voidb invoke mysql.query --profile prod --input query.json --format json
voidb invoke redis.get --profile cache --input-json '{"key":"user:1"}' --format json
voidb invoke s3.list --profile assets --input-json '{"bucket":"logs"}' --format ndjson
```

CLI guarantees:

- every command that returns data supports JSON output
- streaming commands support NDJSON
- table output is only a human convenience layer
- errors have stable codes and machine-readable details
- commands support timeout and cancellation where applicable
- commands that can mutate remote state are marked destructive
- dry-run is supported where the target capability can implement it correctly
- large outputs require limit, pagination, or explicit streaming

## TUI Role

The TUI remains useful, but it becomes optional.

Good TUI candidates:

- SSH terminal sessions
- long-running interactive shells
- SFTP or log-tail workflows
- manual connection profile editing
- dashboards where continuous visual state matters

Poor TUI candidates for the core roadmap:

- basic SQL query execution
- schema introspection
- object listing
- key-value reads
- repeatable infrastructure commands

Database and storage plugins should prioritize capability execution first.
Human browsing surfaces can be reintroduced as optional plugin-owned TUI
frontends after the protocol and CLI are stable.

## Migration Plan

### Phase 1: Document and Preserve

- Record this direction as an ADR.
- Keep the existing v4 TUI working.
- Stop expanding the shell as the primary product surface.
- Treat existing service layers as the execution foundation for CLI and
  protocol work.

### Phase 2: Core Capability Model

- Define connection profile vs connection instance types.
- Define plugin manifest format.
- Define capability metadata and JSON Schema conventions.
- Define structured error codes and audit event schema.

### Phase 3: CLI Foundation

- Rework `voidb-cli` around connection and capability commands.
- Add stable JSON output and structured errors.
- Add profile creation, listing, testing, and redaction guarantees.
- Add generic `voidb invoke` support.

### Phase 4: First Protocol Plugins

- Pick two representative plugins before migrating the whole workspace.
- Recommended pair: one SQL plugin and one non-SQL plugin, such as SQLite and
  Redis, or MySQL and Redis.
- Convert them to expose capability metadata and invocation handlers.
- Validate direct CLI usage, agent usage, and audit logging.

The selected first migration pair is SQLite plus Redis. The comparison and
follow-up order are documented in
[First Protocol Plugin Migration Pair](first-protocol-plugin-migration.md).

### Phase 5: Runtime Plugin Loading

- Add process-based plugin discovery from installed manifests.
- Start plugins on demand.
- Add health checks, cancellation, timeout, and crash handling.
- Keep Rust SDK support as a convenience, not as the protocol boundary.

### Phase 6: Optional TUI Recomposition

- Rebuild TUI surfaces as consumers of the same capability protocol where
  practical.
- Allow plugins to provide their own TUI commands for workflows that are
  genuinely interactive.
- Keep shell responsibilities small: routing, launch, and global controls.

### Phase 7: Sync and Distribution

- Revisit cloud sync after local profile, policy, plugin, and audit boundaries
  are stable.
- Sync should be an extension over connection metadata and encrypted profile
  state, not a prerequisite for the architecture shift.

## Consequences

Positive:

- VoidB becomes more useful to AI agents and automation.
- Plugins can iterate independently of the TUI shell.
- The execution layer becomes easier to test.
- Process plugins create a practical path toward hot-pluggable extensions.
- Connection governance becomes the core product value instead of a supporting
  feature.

Negative:

- Existing TUI-heavy plugin work will become less central.
- The project needs a stable protocol contract before broad plugin migration.
- Some human workflows may temporarily lose priority.
- Process plugins introduce packaging, versioning, and lifecycle complexity.

## Non-Goals

- Remove the TUI immediately.
- Rewrite every plugin at once.
- Implement VS Code-level marketplace behavior in the first iteration.
- Promise absolute local secret isolation from an agent with arbitrary host
  access.
- Move cloud sync ahead of the local capability and connection model.

## Open Questions

- Which two plugins should be the first protocol migration pair?
- Should profile schemas be pure JSON Schema or a small VoidB-specific schema
  layer with JSON Schema export?
- Should plugin processes communicate only over stdio JSON-RPC initially, or
  should local sockets be supported from the start?
- What policy language is sufficient for destructive operations and secret
  access?
- How much of the existing TUI shell should survive after the first protocol
  plugins are stable?
