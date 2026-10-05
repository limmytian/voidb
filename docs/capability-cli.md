# Capability Discovery and Invocation CLI Contract

This document defines the first public CLI contract for plugin discovery,
capability discovery, and generic capability invocation. It complements:

- [Capability Core Model](capability-core-model.md)
- [Connection Profile CLI Contract](connection-profile-cli.md)
- [Plugin Manifest Schema](plugin-manifest-schema.md)
- [Plugin Invocation Transport](plugin-invocation-transport.md)
- [Runtime Plugin Discovery](runtime-plugin-discovery.md)
- [Audit and Structured Error Schema](audit-and-error-schema.md)
- [Agent-Friendly Execution Controls](agent-friendly-execution-controls.md)

The design contract below is broader than the current implementation. Runtime
plugin discovery and focused stdio process-plugin invocation now exist, while
long-lived process pooling, installation commands, marketplace behavior, and
full credential brokering remain future work. The current MVP status is
documented next.

## Current Built-In MVP

The current in-repo implementation exposes the first generic invocation path
through the existing CLI plugin router:

```bash
voidb-cli plugin list --format json
voidb-cli plugin list --include-invalid --format json
voidb-cli plugin describe mysql --include diagnostics,schemas --state-any --format json
voidb-cli audit list --operation capability_invoke --format json
voidb-cli audit export --plugin redis --status failed --format json
voidb-cli invoke list --format json
voidb-cli invoke list ssh --format json
voidb-cli invoke describe sqlite.query --format json
voidb-cli invoke describe sqlite.explain --format json
voidb-cli invoke describe duckdb.query --format json
voidb-cli invoke describe ssh.exec --format json
voidb-cli invoke run sqlite.query --profile local --input-json '{"sql":"select 1"}' --format json
voidb-cli invoke run sqlite.explain --profile local --input-json '{"sql":"select 1"}' --format json
voidb-cli invoke run sqlite.exec --profile local --input-json '{"sql":"insert into users(name) values (\"Ada\")"}' --yes --format json
voidb-cli invoke run postgres.query --profile warehouse --input-json '{"sql":"select 1"}' --format json
voidb-cli invoke run postgres.exec --profile warehouse --input-json '{"sql":"drop table scratch"}' --dry-run --format json
voidb-cli invoke run duckdb.query --profile analytics --input-json '{"sql":"select 1"}' --format json
voidb-cli invoke run duckdb.exec --profile analytics --input-json '{"sql":"drop table scratch"}' --dry-run --format json
voidb-cli invoke run redis.set --profile cache --input-json '{"key":"agent:test","value":"ok"}' --dry-run --format json
voidb-cli invoke run ssh.diagnostics --profile shell --input-json '{}' --format json
voidb-cli invoke run ssh.exec --profile shell --input-json '{"command":"uname -a"}' --yes --format json
voidb-cli invoke run s3.list --profile assets --input-json '{"bucket":"logs","prefix":"2026/"}' --format json
voidb-cli invoke run webdav.mkdir --profile dav --input-json '{"path":"/agent"}' --dry-run --format json
voidb-cli invoke run email.diagnostics --profile mail --input-json '{}' --format json
voidb-cli invoke describe docker.list_containers --format json
voidb-cli invoke run docker.container_action --profile local-docker --dry-run --input-json '{"id":"abc123","action":"restart"}' --format json
voidb-cli invoke describe kubernetes.list --format json
voidb-cli invoke run kubernetes.apply --profile staging --dry-run --input-json '{"yaml":"apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: agent-probe\n"}' --format json
voidb-cli invoke describe mongodb.find --format json
voidb-cli invoke run mongodb.insert --profile documents --dry-run --input-json '{"database":"app","collection":"users","document":{"name":"Ada"}}' --format json
voidb-cli invoke describe elasticsearch.search --format json
voidb-cli invoke run elasticsearch.raw_api --profile search --dry-run --input-json '{"method":"POST","path":"/users/_doc/1","body":{"name":"Ada"}}' --format json
voidb-cli invoke describe jenkins.jobs --format json
voidb-cli invoke run jenkins.trigger_build --profile ci --dry-run --input-json '{"job_full_name":"folder/build"}' --format json
```

This MVP supports SQLite, Redis, MySQL, PostgreSQL, DuckDB, SSH, S3, WebDAV,
Email, Docker, Kubernetes, MongoDB, Elasticsearch, and Jenkins built-in
capability handlers, legacy
ConnectionConfig-backed profiles,
JSON Schema input validation, structured JSON success/error envelopes,
versioned NDJSON run events, dry-run controls, capability-default and explicit
invocation timeouts, redaction of legacy credential and sensitive
metadata values, stable SQL row pagination, SQL mutation gate metadata, and
deny-by-default destructive policy with explicit per-invocation
acknowledgement. SSH non-interactive invocations use strict `known_hosts`
verification and expose structured `ssh.host_key_unknown` /
`ssh.host_key_changed` target errors rather than learning host keys silently.
Docker exposes bounded list/inspect/log paths plus gated lifecycle actions.
Kubernetes exposes bounded resource list/get/log paths, blocks Secret YAML
payloads, and gates delete/scale/restart/apply behind dry-run or explicit
acknowledgement. MongoDB exposes bounded database, collection, find, aggregate,
count, and index read paths; insert/update/delete/create_index/run_command are
destructive-gated and support dry-run. Elasticsearch exposes bounded
health/node/index/search/get/count/mapping read paths; raw API calls are
destructive-gated and support dry-run. Jenkins exposes bounded diagnostics,
jobs, job detail, activity, console, and pipeline read paths; trigger, abort,
and queue-cancel side effects are destructive-gated and support dry-run.
Default tests cover schemas and gates without requiring live Docker,
Kubernetes, MongoDB, Elasticsearch, or Jenkins targets.

Static discovery is credential-independent. `plugin list/describe`, `invoke
list/describe`, `profile list/show`, legacy `connections list/show`, and
`agent catalog` read only raw or separately redacted metadata. They do not
decrypt protected connection configuration, consult `VOIDB_MASTER_PASSWORD`,
or prompt for a master password. Commands that open or test a live connection
continue to require an unlocked credential context.

Every capability descriptor includes `execution_mode`: `stateless`,
`session_only`, or `both`. Session-capable descriptors may also include a
`session_handoff` object containing the persistent-session purpose and the
fully qualified capability set needed to open that session. Legacy process
plugin descriptors that omit the field deserialize as `stateless`.

`invoke list` and `agent catalog` accept repeatable `--execution-mode` filters.
Filtering for `stateless` or `session_only` includes capabilities declared as
`both`. For `invoke list`, filtering for `both` selects dual-transport
definitions. For `agent catalog`, `both` selects the union available to an
explicit combined grant, while every returned descriptor still carries its
actual declared mode. Both commands also support `--format table` for a compact
mode/risk/session-purpose view, while JSON remains the stable agent interface.
`invoke describe` supports the same JSON/table output choice.

A one-shot `invoke run` or `agent exec` rejects `session_only` before profile or
credential resolution. The structured error contains secret-free
`authorize_args` and `session_open_args` derived from `session_handoff`; clients
must not attempt to reinterpret a session-only operation as a one-shot call.

The process-plugin discovery MVP scans only documented plugin roots:
`VOIDB_PLUGIN_PATH`, user install roots, system install roots, and optional
bundled roots. It ignores dot-prefixed metadata directories, does not scan the
current working directory, parses `plugin.toml`, validates referenced local JSON
Schemas, and reports deterministic `available`, `invalid`, `incompatible`, and
`shadowed` candidate states. Discovery output includes root `trust_level`
metadata. Generic `invoke run` can execute an available process-plugin
capability through the focused stdio JSON-RPC runtime host; lifecycle behavior
is covered by the process-plugin runtime gate in
[CI Check Tiers](ci-checks.md).

The local audit MVP persists redacted JSONL events for profile list/show/test
and generic invoke operations. Audit metadata records stable refs and JSON shape
summaries rather than plaintext inputs, credentials, or decrypted legacy
`plugin_config`. Audit files rotate locally, grant lifecycle events are linked
by `grant_id`, and `audit list/export` include pagination plus export metadata
for source files, event count, generated timestamp, and normalized filters.

## Command Groups

The canonical command groups are:

```bash
voidb plugin <command>
voidb capability <command>
voidb invoke <capability-ref>
```

`plugin` commands expose installed plugin metadata and discovery state.
`capability` commands expose capability catalogs and schemas. `invoke` executes
one capability through the `CapabilityInvocation` model.

## References

Plugin references use the plugin ID from the manifest:

```text
<plugin-ref> := <plugin-id>
```

Capability references use a qualified capability ID:

```text
<capability-ref> := <plugin-id>.<capability-id>
```

Examples:

```text
mysql.query
redis.get
s3.list_objects
ssh.exec
```

The CLI should reject unqualified capability IDs with
`validation.capability_ref_unqualified`. If a user supplies an unknown plugin
or capability, the error should be `unavailable.plugin_not_found` or
`unavailable.capability_not_found`.

Profile references follow the grammar in
[Connection Profile CLI Contract](connection-profile-cli.md).

## Output Formats

Commands that return bounded data support:

| Format | Meaning |
|---|---|
| `table` | Human-readable table or summary. This is a convenience layer only. |
| `json` | One stable JSON object. Required for agents. |

Commands that may stream support:

| Format | Meaning |
|---|---|
| `json` | One final JSON object after the invocation completes. |
| `ndjson` | One JSON event per line as the invocation runs. |

`ndjson` is the caller-facing streaming format. It is not JSON-RPC; Core maps
plugin transport notifications into stable CLI events.

Non-streaming successful JSON output uses:

```json
{
  "ok": true,
  "schema_version": 1,
  "command": "invoke",
  "data": {},
  "warnings": []
}
```

Failed JSON output uses:

```json
{
  "ok": false,
  "schema_version": 1,
  "command": "invoke",
  "exit_code": 2,
  "error": {
    "category": "validation",
    "code": "validation.input_schema_mismatch",
    "message": "Input did not match the capability schema.",
    "details": {},
    "target": null,
    "retryable": false,
    "redaction": "not_required"
  }
}
```

Human messages may change. Agents should branch on `ok`, `error.category`,
`error.code`, `error.retryable`, and redacted structured details.

## Plugin Commands

### `plugin list`

List discovered process plugins.

```bash
voidb plugin list --format json
voidb plugin list --state available --format table
voidb plugin list --include-shadowed --format json
```

Options:

| Option | Meaning |
|---|---|
| `--state <state>` | Filter by discovery state: `available`, `invalid`, `incompatible`, `shadowed`, `disabled`, or `failed`. |
| `--include-shadowed` | Include lower-precedence candidates shadowed by an available plugin. |
| `--include-invalid` | Include invalid candidates and redacted validation diagnostics. |

JSON output:

```json
{
  "ok": true,
  "schema_version": 1,
  "command": "plugin",
  "data": {
    "plugins": [
      {
        "id": "mysql",
        "name": "MySQL",
        "version": "0.1.0",
        "protocol_version": "1",
        "state": "available",
        "manifest_path": "/plugins/mysql/plugin.toml",
        "source": {
          "kind": "user",
          "trust_level": "user_installed",
          "precedence": 1
        },
        "transport": "stdio-jsonrpc",
        "capability_count": 2,
        "tui": false
      }
    ]
  },
  "warnings": []
}
```

`manifest_path` is allowed for diagnostics. It must not include environment
values, credentials, command-line secrets, or unredacted plugin stderr.

### `plugin describe`

Describe one plugin and its manifest-derived metadata.

```bash
voidb plugin describe mysql --format json
voidb plugin describe mysql --include schemas,capabilities --format json
```

Options:

| Option | Meaning |
|---|---|
| `--include <parts>` | Comma-separated parts: `runtime`, `connections`, `capabilities`, `schemas`, `ui`, `requirements`, `diagnostics`. |
| `--state-any` | Allow describing non-available candidates when diagnostics are requested. |

Default JSON output includes plugin identity, state, connection declaration,
capability summaries, and optional TUI metadata. Full schema documents are only
included when `schemas` is requested.

Example:

```json
{
  "ok": true,
  "schema_version": 1,
  "command": "invoke",
  "data": {
    "plugin": {
      "id": "mysql",
      "name": "MySQL",
      "version": "0.1.0",
      "protocol_version": "1",
      "state": "available",
      "runtime": {
        "transport": "stdio-jsonrpc"
      },
      "connections": {
        "profile_schema_ref": "schemas/mysql-profile.schema.json",
        "secret_classes": ["password", "client_certificate"]
      },
      "capabilities": [
        {
          "id": "query",
          "qualified_id": "mysql.query",
          "description": "Execute a read-oriented SQL query.",
          "risk": "read_only",
          "destructive": false,
          "streaming": false,
          "connection_required": true
        }
      ],
      "ui": {
        "tui": false
      }
    }
  },
  "warnings": []
}
```

## Capability Commands

### `capability list`

List capabilities from one plugin or from all available plugins.

```bash
voidb capability list --format json
voidb capability list mysql --format json
voidb capability list --destructive false --streaming true --format table
```

Options:

| Option | Meaning |
|---|---|
| `<plugin-id>` | Optional plugin filter. |
| `--destructive <true|false>` | Filter by destructive operation flag. |
| `--risk <risk>` | Future filter for `read_only`, `mutating`, `destructive`, or `external_side_effect`. Current built-in CLI output already includes `risk`. |
| `--streaming <true|false>` | Filter by streaming support. |
| `--connection-required <true|false>` | Filter by whether a profile or instance is required. |
| `--permission <permission>` | Return capabilities that require one permission string. |

JSON output:

```json
{
  "ok": true,
  "schema_version": 1,
  "command": "invoke",
  "data": {
    "capabilities": [
      {
        "plugin_id": "mysql",
        "id": "query",
        "qualified_id": "mysql.query",
        "description": "Execute a read-oriented SQL query.",
        "permissions": ["connection.read", "sql.query"],
        "risk": "read_only",
        "destructive": false,
        "streaming": false,
        "connection_required": true,
        "required_secret_classes": ["password"],
        "supports_dry_run": false,
        "default_timeout_ms": 30000
      }
    ]
  },
  "warnings": []
}
```

### `capability describe`

Describe one capability, including input and output schemas.

```bash
voidb capability describe mysql.query --format json
voidb capability describe mysql.query --include schemas,examples --format json
```

Options:

| Option | Meaning |
|---|---|
| `--include <parts>` | Comma-separated parts: `schemas`, `examples`, `permissions`, `policy`, `plugin`. |

JSON output:

```json
{
  "ok": true,
  "schema_version": 1,
  "command": "invoke",
  "data": {
    "capability": {
      "plugin_id": "mysql",
      "id": "query",
      "qualified_id": "mysql.query",
      "description": "Execute a read-oriented SQL query.",
      "input_schema_ref": "schemas/query-input.schema.json",
      "output_schema_ref": "schemas/query-output.schema.json",
      "input_schema": {
        "type": "object",
        "required": ["sql"],
        "properties": {
          "sql": {
            "type": "string"
          }
        }
      },
      "output_schema": {
        "type": "object"
      },
      "permissions": ["connection.read", "sql.query"],
      "risk": "read_only",
      "destructive": false,
      "streaming": false,
      "connection_required": true,
      "required_secret_classes": ["password"],
      "supports_dry_run": false,
      "default_timeout_ms": 30000
    }
  },
  "warnings": []
}
```

Schemas are agent-facing metadata and must not contain plaintext secrets.
Schema examples that include credential-shaped fields must use credential
references or redacted placeholders.

## Invoke Command

`invoke` runs one capability.

```bash
voidb invoke mysql.query --profile prod-db --input query.json --format json
voidb invoke redis.get --profile cache --input-json '{"key":"user:1"}' --format json
voidb invoke s3.list --profile assets --input-json '{"bucket":"logs"}' --format json
voidb invoke webdav.get --profile dav --input-json '{"path":"/reports/q2.csv"}' --format json
voidb invoke email.list --profile mail --input-json '{"folder":"INBOX"}' --format json
voidb invoke ssh.sftp_list --profile shell --input-json '{"path":"."}' --format json
```

The canonical profile flag is `--profile`. `--conn` may be kept as a
compatibility alias for the ADR's early examples and existing scripts.

Connection target options:

| Option | Meaning |
|---|---|
| `--profile <profile-ref>` | Invoke from a saved profile. |
| `--instance <instance-id>` | Invoke against an existing runtime instance. |
| `--stateless` | Invoke a capability that does not require a profile or instance. |
| `--reuse <never|allow|require>` | Reuse policy for `--profile`. Default is `allow`. |

Input options:

| Option | Meaning |
|---|---|
| `--input-json <json>` | Read JSON input from an inline string. |
| `--input-file <path>` | Read JSON input from a file. |

Execution options:

| Option | Meaning |
|---|---|
| `--format <json|ndjson>` | Stable single-document JSON or flushed versioned NDJSON events. |
| `--timeout <duration>` | Override the capability timeout with a positive unit-bearing duration such as `250ms`, `10s`, `2m`, or `1h`. |
| `--timeout-ms <milliseconds>` | Legacy-compatible positive millisecond override. |
| `--call-id <id>` | Use a caller-owned public invocation ID; otherwise VoidB generates one before work begins. |
| `--cancellation-token <token>` | Correlate cooperative cancellation without exposing the token in output or audit records. |
| `--max-output-bytes <bytes>` | Bound the serialized terminal result; defaults to 4 MiB and cannot exceed 16 MiB. |
| `--dry-run` | Request dry-run behavior when the capability supports it. |
| `--yes` | Add an `InvocationAcknowledgement` for a destructive or external-side-effect invocation. This is not permission. |
| `--page-limit <n>` | First page limit for pageable capabilities. |
| `--page-cursor <cursor>` | Continue a pageable invocation from a previous cursor. |

Input source rules:

- Exactly one of `--input-json` or `--input-file` may be used.
- Inline JSON must parse before capability schema validation.
- The merged input is validated against the capability `input_schema` before
  Core starts plugin execution.

Connection target mapping:

| CLI flags | `CapabilityInvocation.connection` |
|---|---|
| `--stateless` | `{"kind":"stateless"}` |
| `--profile prod-db --reuse allow` | `{"kind":"from_profile","profile":{"kind":"name","value":"prod-db"},"purpose":{"kind":"capability_invocation"},"reuse":"allow"}` |
| `--profile id:profile_01 --reuse never` | `{"kind":"from_profile","profile":{"kind":"id","value":"profile_01"},"purpose":{"kind":"capability_invocation"},"reuse":"never"}` |
| `--instance inst_01` | `{"kind":"existing_instance","instance_id":"inst_01"}` |

Core must reject incompatible combinations, such as `--stateless --profile`,
with `validation.connection_target_conflict`.

SSH release smoke for `ssh.test`, `ssh.exec`, SFTP list/get/put/mkdir/rm, and
diagnostics is documented in [SSH Plugin](ssh-plugin.md). Use that fixture gate
when changing SSH capability metadata, strict host-key behavior, output
bounding, destructive policy, or profile redaction.

### Agent Authorization Catalog And Presets

`voidb-cli agent catalog [--plugin <id>] [--execution-mode <mode>]` is
password-free and returns raw
capability definitions plus centrally normalized plugin support and preset
records under `data.plugins`. Presets are projected separately for `stateless`,
`session_only`, and explicitly combined `both` grants. Read-only,
Interactive/Execute, and Full access contain exact qualified capability IDs; an
empty list never means all. Full access is a mode-bounded snapshot of the
current catalog, so capabilities added by a later plugin upgrade are not
inherited. Process plugins with missing authorization declarations are
Custom-only, and Sync is reported as deferred because it uses its dedicated
encrypted protocol.

`voidb-cli agent authorize` defaults to a stateless Read-only grant. Select
`--execution-mode session_only` for a persistent-session grant or
`--execution-mode both` for an explicit combined grant. Use
`--preset interactive_execute` for the narrow centrally declared execute scope,
`--preset full_access` for an exact snapshot of every currently declared
capability supported by the selected grant mode, or pass explicit
`--capability` values for an inferred Custom grant. Named presets reject
mismatched explicit scopes. Stateless grants cannot open sessions;
session-only grants cannot authorize one-shot invocation. Legacy grant files
without mode metadata remain stateless. `--allow-destructive --yes` permits
destructive calls in the grant but does not replace the later per-call `--yes`.
Grant lifecycle, frontend-safe status, broker recovery, and persistent session
commands are documented in
[Agent Authorization Broker](agent-authorization-broker.md).

Interactive agents should prefer `voidb-cli agent exec <plugin.capability>
--profile <name> --input-json <json> --purpose <specific-use>`. It infers the plugin, resolves the
immutable Profile ID, reuses matching access, and creates an exact JIT request
when an identified agent needs approval. JIT requests are deliberately
stateless-only; session access requires a proactive mode-bounded grant and the
descriptor's declared handoff. Advanced integrations may use
`agent request create` with capability, constrained, or exact scope directly;
that command also requires `--purpose`. The purpose is part of the canonical
request shown during review. Requests that reach their TTL without approval are
automatically denied and cannot be revived by a late decision. Humans may
review pending requests through the preferred local CLI command emitted by the
broker, or secondarily by pressing `p` in Connection Manager. The full
state/exit-code and security contract is documented in
[Just-in-Time Agent Authorization](jit-agent-authorization.md).

### Non-Streaming JSON Output

For `--format json`, Core waits for terminal completion and returns one object:

```json
{
  "ok": true,
  "schema_version": 1,
  "command": "invoke",
  "data": {
    "invocation_id": "invoke-01",
    "plugin_id": "mysql",
    "capability_id": "query",
    "status": "succeeded",
    "output": {
      "columns": ["?column?"],
      "rows": [[1]]
    },
    "output_summary": {
      "row_count": 1
    },
    "page": {
      "next_cursor": null
    },
    "timing": {
      "duration_ms": 42,
      "timeout_ms": 30000,
      "timeout_source": "capability_default"
    },
    "output_limits": {
      "max_bytes": 4194304,
      "serialized_bytes": 204,
      "truncated": false,
      "continuation_available": false
    },
    "redaction": "not_required"
  },
  "warnings": []
}
```

The `output` field is validated against the capability `output_schema`.
`output_summary` is redacted metadata suitable for audit records.
Results that exceed the effective output limit fail with
`plugin.output_limit_exceeded` and do not emit a partial payload. Page limits
must be `1..=1000`, and page cursors are limited to 4096 UTF-8 bytes.

### Shared SQL Metadata Output

Built-in SQL plugins expose the same metadata capability names:

- `<plugin>.tables`
- `<plugin>.describe_table`

`tables` output includes `scope`, `capabilities`, `tables`, and `views`.
`describe_table` output includes `scope`, `capabilities`, `table`, `columns`,
`indexes`, `foreign_keys`, and `constraints`. `scope.kind` is one of
`local_database`, `database`, or `schema`; `database` and `schema` may also be
present as top-level compatibility fields when the target supports them.

The `capabilities` object contains booleans such as `supports_databases`,
`supports_schemas`, `supports_row_counts`, `supports_indexes`,
`supports_foreign_keys`, `supports_constraints`, and `supports_comments`.
Agents should use those flags for branching instead of plugin-name heuristics.

### Shared SQL Query And Mutation Output

Built-in SQL plugins expose `<plugin>.query`, `<plugin>.explain`, and
`<plugin>.exec` with shared schemas. `query` and `explain` use bounded JSON
pagination, not NDJSON. Their output always includes `row_limit`, `row_count`,
`source_row_count`, `truncated`, `cursor`, and `next_cursor`; when
`next_cursor` is non-null, the top-level invocation `page.next_cursor` is also
set.

Built-in `explain` accepts exactly one read-oriented statement and rejects
`analyze = true` with `policy.explain_analyze_disabled` before opening the
target connection. Successful output includes `analyze = false`, `format`,
`dialect`, and `explained_statement_count`.

Built-in SQL `exec` capabilities are destructive and require `--dry-run` or
`--yes` through generic invoke. Dry-run output includes `statement_count`,
heuristic `classifications`, `checks`, and `mutation_gate`. Real exec output
includes `rows_affected` plus `mutation_gate`, whose `acknowledged` field
reflects whether the invocation carried an acknowledgement such as CLI
`--yes`.

### Streaming NDJSON Output

`invoke run --format ndjson` writes one flushed JSON object per line. Every
line carries protocol version `1`, a zero-based monotonically increasing
sequence number, and the invocation ID. Event types are `start`, `data`,
`progress`, `warning`, `error`, and `end`. A non-streaming handler emits one
`data` event for its final result; process-plugin streaming handlers may emit
multiple data and progress events before the terminal result.
Process-plugin `voidb.stream.*` notifications are mapped into these events
after invocation-ID and exact-sequence validation. Delivery uses a bounded
32-event channel so a slow stdout consumer applies backpressure.

```json
{"protocol_version":1,"sequence":0,"invocation_id":"invoke-02","type":"start","data":{"capability_ref":"s3.list","timeout_ms":30000}}
{"protocol_version":1,"sequence":1,"invocation_id":"invoke-02","type":"progress","data":{"message":"Fetched first page.","current":1,"total":2}}
{"protocol_version":1,"sequence":2,"invocation_id":"invoke-02","type":"warning","data":{"warning":{"code":"result.truncated"}}}
{"protocol_version":1,"sequence":3,"invocation_id":"invoke-02","type":"data","data":{"value":{"status":"succeeded","output":{"items":[]}}}}
{"protocol_version":1,"sequence":4,"invocation_id":"invoke-02","type":"end","data":{"status":"succeeded","duration_ms":42}}
```

Failure events use the same structured error shape as JSON output:

```json
{"protocol_version":1,"sequence":1,"invocation_id":"invoke-02","type":"error","data":{"error":{"category":"target_system","code":"s3.access_denied","message":"Target system denied the request.","details":{},"target":{"system":"s3","code":"AccessDenied","message":"Access denied."},"retryable":false,"redaction":"applied"}}}
{"protocol_version":1,"sequence":2,"invocation_id":"invoke-02","type":"end","data":{"status":"failed"}}
```

NDJSON output must be flush-friendly. Each line is a complete UTF-8 JSON
object followed by `\n`. After a structured terminal error, Core emits exactly
one `end` event when stdout remains writable.

### Table Output

`--format table` is human convenience output. It is allowed only when Core has
a known renderer for the output shape or the plugin declares a safe table
projection later. Agents should not depend on table output.

When no renderer is available, table output may fall back to a compact summary
and suggest `--format json`. It must still apply redaction.

## Validation Order

Core validates an invocation in this order:

1. Parse the capability reference.
2. Resolve the plugin candidate and capability metadata.
3. Parse and validate input JSON.
4. Validate connection target flags against capability requirements.
5. Resolve the profile or runtime instance descriptor when required.
6. Evaluate profile policy, capability risk, acknowledgements, scoped
   approvals, and actor permissions.
7. Validate requested controls against capability metadata.
8. Broker credential grants for declared required secret classes.
9. Start or reuse the plugin process.
10. Send one transport invocation.

Validation failures that occur before plugin execution still produce structured
errors and audit records when an invocation ID has been allocated.

## Exit Behavior

Stable timeout, cancellation, pagination, streaming, dry-run, destructive
operation, and exit code behaviors are defined in
[Agent-Friendly Execution Controls](agent-friendly-execution-controls.md).
JSON and NDJSON error payloads remain authoritative for agents.

## Redaction And Audit

The CLI must apply the same redaction rules as the profile CLI and plugin
transport:

- Do not print plaintext credentials, decrypted profile payloads, signed URLs,
  authorization headers, cookies, or unredacted plugin stderr.
- Redact input summaries and target diagnostics before output.
- Treat plugin stderr as diagnostics, not as protocol output.
- Record invocation audit data using the audit/error schema.
- Preserve credential reference IDs and classes where useful, but never secret
  values.

## Invariants

- Plugin and capability discovery is manifest-derived and deterministic.
- Plugin and capability lists sort lexicographically unless a command documents
  a different order.
- Capability references are qualified as `<plugin-id>.<capability-id>`.
- `invoke` executes exactly one capability per process invocation.
- Input is JSON and is schema-validated before plugin execution.
- Output is JSON or NDJSON for agent workflows.
- NDJSON events are stable CLI events, not leaked JSON-RPC messages.
- Profile-based invocations use profile references, not plaintext secrets.
- Destructive and dry-run behavior follows manifest metadata and policy.
- Capability risk is the preferred policy input; the legacy `destructive`
  boolean remains for compatibility and filters.
- Structured errors use stable categories and codes from the audit/error
  contract.
