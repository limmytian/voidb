# Plugin Manifest Schema

This document defines the first process-plugin manifest shape for the
capability-first VoidB migration. It turns the ADR manifest sketch into a
stable draft that plugin discovery, CLI capability listing, and future process
loading can share.

The machine-readable JSON Schema lives at
[`schemas/plugin-manifest.schema.json`](../schemas/plugin-manifest.schema.json).
Manifests are authored as `plugin.toml`, parsed into the TOML data model, and
then validated against that JSON Schema.

## Scope

This slice defines the manifest contract only. Invocation messages are defined
in [Plugin Invocation Transport](plugin-invocation-transport.md). This document
does not implement capability handlers or schema validation wiring. Runtime
discovery and startup are defined in
[Runtime Plugin Discovery](runtime-plugin-discovery.md).
Agent-facing plugin and capability discovery commands that consume manifest
metadata are defined in
[Capability Discovery and Invocation CLI Contract](capability-cli.md).
Runtime behavior for timeout, cancellation, pagination, streaming, dry-run,
destructive operations, and exit codes is defined in
[Agent-Friendly Execution Controls](agent-friendly-execution-controls.md).
Manifest ownership and package installation lifecycle are defined in
[Future Plugin Installation Model](plugin-installation-model.md).

The manifest must describe:

- plugin identity
- runtime command and transport
- connection profile schema
- credential secret classes
- capability catalog
- capability risk levels and destructive operation flags
- streaming support
- optional TUI declaration

## Root Fields

| Field | Required | Meaning |
|---|---:|---|
| `$schema` | no | Supported VoidB process-plugin manifest schema URI for editors and validation diagnostics. |
| `id` | yes | Stable plugin identifier, lower-case kebab case. |
| `name` | yes | Human-readable plugin name. |
| `version` | yes | Plugin package version using semantic version syntax. |
| `protocol_version` | yes | VoidB process-plugin protocol version implemented by the plugin. |
| `description` | no | Short human-readable plugin description. |
| `license` | no | SPDX-style license identifier or license label. |
| `homepage` | no | Plugin project URL. |
| `runtime` | yes | Process launch and transport declaration. |
| `connections` | yes | Connection profile and credential-class declaration. |
| `capabilities` | yes | Capability catalog exposed by the plugin. |
| `ui` | no | Optional human UI declaration. |
| `requirements` | no | Core version and platform constraints. |

Plugin IDs are local package IDs such as `mysql`, `redis`, `ssh`, or
`kubernetes`. Agent-facing capability names are formed by qualifying the local
capability ID with the plugin ID, such as `mysql.query`.

## Runtime

The first supported runtime is a process launched by VoidB Core and connected
over stdio JSON-RPC.

```toml
[runtime]
command = "voidb-plugin-mysql"
args = []
transport = "stdio-jsonrpc"
```

Runtime fields:

- `command`: executable name or path that Core starts on demand.
- `args`: optional fixed argument list.
- `transport`: transport identifier. JSON Schema validates this as a string;
  semantic discovery marks unsupported transports incompatible. The first
  accepted value is `stdio-jsonrpc`.
- `env`: optional string map for non-secret environment defaults.

Secrets do not belong in `runtime.env`. Credential material is brokered per
invocation or runtime instance according to
[Secret Brokering and Redaction Policy](secret-brokering-redaction-policy.md).
Runtime command resolution and installed search paths are defined in
[Runtime Plugin Discovery](runtime-plugin-discovery.md).
For user, system, and bundled roots, bare commands must resolve to
`<plugin-dir>/bin/<command>`; only explicit development roots may fall back to
`PATH`.

## Connections

The connection section declares the saved profile schema and the credential
classes the plugin may request.

```toml
[connections]
profile_schema = "schemas/mysql-profile.schema.json"
secret_classes = ["password", "client_certificate"]
```

Connection fields:

- `profile_schema`: relative path or URI for the plugin's connection profile
  JSON Schema.
- `secret_classes`: credential classes that may be brokered to this plugin.

Supported secret classes in the first draft:

- `password`
- `token`
- `api_key`
- `private_key`
- `client_certificate`
- `cloud_access_key`
- `cloud_secret_key`
- `other`

The manifest declares eligibility. It does not grant credentials by itself.
Core still evaluates the selected profile, actor, capability permissions, and
policy before creating a scoped credential grant.

## Capabilities

Each capability is one structured operation that can be discovered by CLI,
agents, and optional TUI adapters.

```toml
[[capabilities]]
id = "query"
description = "Execute a read-oriented SQL query."
input_schema = "schemas/query-input.schema.json"
output_schema = "schemas/query-output.schema.json"
permissions = ["connection.read", "sql.query"]
risk = "read_only"
destructive = false
streaming = false
execution_mode = "stateless"
connection_required = true
required_secret_classes = ["password"]
supports_dry_run = false
default_timeout_ms = 30000
```

Capability fields:

- `id`: local capability identifier, unique within the plugin.
- `description`: human-readable summary for discovery output.
- `input_schema`: JSON Schema for invocation input.
- `output_schema`: JSON Schema for successful output.
- `permissions`: stable permission strings required to invoke the capability.
- `risk`: optional policy classification: `read_only`, `mutating`,
  `destructive`, or `external_side_effect`. If omitted, Core derives
  compatibility behavior from `destructive`.
- `destructive`: whether the capability may mutate or delete target-system
  state.
- `streaming`: whether the capability may stream NDJSON or protocol
  notifications.
- `execution_mode`: `stateless`, `session_only`, or `both`. Omitted legacy
  descriptors default to `stateless`.
- `session_handoff`: optional structured metadata for session-capable
  operations. `purpose` uses the shared plugin-session purpose shape and
  `capabilities` contains fully qualified capability IDs to bind when opening
  the session. It is descriptive and grants no access by itself.
- `connection_required`: whether invocation requires a connection profile or
  existing runtime instance.
- `required_secret_classes`: credential classes this capability may request.
- `supports_dry_run`: whether dry-run controls are meaningful for this
  capability.
- `default_timeout_ms`: plugin-recommended default timeout.

For a capability that supports both transports, the optional handoff is
encoded as a nested table:

```toml
execution_mode = "both"

[capabilities.session_handoff]
purpose = { kind = "database_query" }
capabilities = ["example.query"]
```

Use `session_only` for operations that cannot run through generic one-shot
invoke. The handoff capability list is fully qualified and describes the exact
binding to request; it does not bypass grant or policy checks.

New manifests should set `risk` first and keep `destructive` for compatibility
with existing filters and confirmation flows. `destructive = true` is still
required for any capability that can delete data, drop schema, overwrite
state, or otherwise needs destructive confirmation. Capabilities that trigger
jobs, send email, execute commands, or perform Docker/Kubernetes operations
should use `risk = "external_side_effect"` and keep `destructive = true` until
the legacy boolean is retired.

A manifest cannot downgrade actual destructive behavior by setting
`risk = "read_only"` while `destructive = true`. Discovery keeps the candidate
available for compatibility, reports
`manifest.destructive_capability_read_only_risk`, and Core evaluates the
effective risk as `destructive`.

Side-effecting capabilities must also declare at least one permission string so
profile policy and audit output have a stable control point. Permission strings
should describe the target action (`redis.key.write`, `s3.object.delete`,
`email.message.send`) rather than UI commands. Discovery rejects non-read-only
risk declarations without permissions as
`manifest.side_effect_capability_missing_permission`; legacy destructive
capabilities keep the older
`manifest.destructive_capability_missing_permission` diagnostic.

Capabilities with `connection_required = false` cannot request
`required_secret_classes`, because those classes are brokered from connection
profiles. Put any future runtime-instance credential model behind a separate
manifest field instead of overloading stateless capabilities.

`streaming = true` means callers must be prepared for streamed output. The
message contract is defined in
[Plugin Invocation Transport](plugin-invocation-transport.md).

## Optional TUI Declaration

Plugins can declare whether they provide a human TUI surface. This is not part
of the core capability contract, but it lets Core and future installers expose
the right human affordances.

For retained standalone TUIs, the launch and lifecycle rules are defined in
[Plugin-Owned TUI Launch Contract](plugin-owned-tui-launch-contract.md). The
fields below are discovery metadata; they do not make Core host plugin
rendering or pass secrets to a TUI process.

```toml
[ui]
tui = true
entrypoint_capability = "browse"
raw_input = false
```

UI fields:

- `tui`: whether the plugin has an optional TUI surface.
- `entrypoint_capability`: capability to open when a human launches the TUI.
- `raw_input`: whether the TUI may need raw input routing, as terminal plugins
  do.

Capability execution remains the primary protocol even when a plugin also
provides a TUI.

## Requirements

The optional requirements section declares compatibility constraints.

```toml
[requirements]
voidb_core = ">=0.1.0"
platforms = ["darwin", "linux", "windows"]
```

`voidb_core` is a semver requirement string interpreted by Core tooling.
`platforms` limits plugin installation or launch to supported target platforms.

## Full Example

```toml
id = "mysql"
name = "MySQL"
version = "0.1.0"
protocol_version = "1"
description = "MySQL and MariaDB capability plugin for VoidB."
license = "MIT"
homepage = "https://github.com/voidb-plugins/mysql"

[runtime]
command = "voidb-plugin-mysql"
args = []
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
risk = "read_only"
destructive = false
streaming = false
execution_mode = "stateless"
connection_required = true
required_secret_classes = ["password"]
supports_dry_run = false
default_timeout_ms = 30000

[[capabilities]]
id = "exec"
description = "Execute a SQL statement that may mutate data."
input_schema = "schemas/exec-input.schema.json"
output_schema = "schemas/exec-output.schema.json"
permissions = ["connection.read", "sql.exec"]
risk = "destructive"
destructive = true
streaming = false
execution_mode = "stateless"
connection_required = true
required_secret_classes = ["password"]
supports_dry_run = true
default_timeout_ms = 30000

[ui]
tui = false

[requirements]
voidb_core = ">=0.1.0"
platforms = ["darwin", "linux", "windows"]
```

## Invariants

- A manifest is metadata. It never contains plaintext credentials, decrypted
  profile data, tokens, private keys, signed URLs, or connection strings with
  embedded secrets.
- If `$schema` is present, it must be the supported VoidB process-plugin
  manifest schema URI:
  `https://voidb.dev/schemas/plugin-manifest.schema.json`.
- Schema references are plugin-relative paths or `http`/`https` URIs. Local
  discovery validates plugin-relative files and records remote URI references
  without fetching them.
- `plugin.toml` is package-owned metadata. VoidB install state, disable state,
  trust decisions, and rollback metadata live outside the manifest.
- Capability IDs are local to a plugin; CLI and protocol surfaces qualify them
  with the plugin ID.
- `permissions` are stable machine-readable strings, not display labels.
- `secret_classes` and `required_secret_classes` declare eligible classes only;
  Core still brokers credentials per invocation or instance.
- Destructive capabilities must be marked explicitly.
- Streaming capabilities must be marked explicitly.
- Profile, input, and output schemas are JSON Schema documents referenced by
  path or URI.
- Optional TUI metadata cannot replace the capability catalog.
