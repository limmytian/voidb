# Agent Capability Examples

This document gives agents concrete examples for capability-first workflows.
SQLite and Redis are the reference implementations for local SQL and networked
key-value workflows. MySQL and PostgreSQL expose the shared networked SQL
baseline, and DuckDB now follows the same baseline for local analytics profiles.
S3 and WebDAV extend the same model to storage operations with bounded read
output and destructive-operation gates. Email exposes bounded, privacy-aware
mailbox reads, guarded mutations, attachment transfers, and agent-owned IDLE
sessions. Docker and Kubernetes now
expose agent-facing operations capabilities with bounded read paths and
destructive-operation gates. MongoDB and Elasticsearch expose agent-facing
document/search capabilities with bounded read paths, payload summaries, and
destructive-operation gates for raw or mutating operations. Jenkins exposes
agent-facing CI capabilities with bounded read paths and explicit side-effect
gates for build trigger, abort, and queue cancel operations.

The snippets use the current built-in MVP command surface documented in
[Capability Discovery and Invocation CLI Contract](capability-cli.md):

```bash
voidb-cli invoke list --format json
voidb-cli invoke describe sqlite.query --format json
voidb-cli invoke run sqlite.query --profile local-dev --input-json '{"sql":"select 1"}' --format json
```

## Discovery

Agents discover capabilities before invoking them. Discovery output must include
input and output schemas, permission labels, destructive metadata, dry-run
support, and secret-class requirements without exposing plaintext connection
secrets.

```bash
voidb-cli invoke describe sqlite.query --format json
```

Abridged expected shape:

```json
{
  "ok": true,
  "data": {
    "capability": {
      "plugin_id": "sqlite",
      "id": "query",
      "input_schema": {
        "required": ["sql"],
        "additionalProperties": false
      },
      "output_schema": {
        "required": [
          "statements",
          "row_limit",
          "row_count",
          "source_row_count",
          "truncated"
        ]
      },
      "permissions": ["connection.read", "sql.query"],
      "destructive": false,
      "supports_dry_run": false,
      "required_secret_classes": []
    }
  }
}
```

Redis follows the same discovery model:

```bash
voidb-cli invoke describe redis.set --format json
```

`redis.set` is destructive, supports dry-run, and accepts only `key` plus a
string `value`. Discovery output must not include Redis username, password, or
connection URL values.

PostgreSQL follows the shared SQL capability contract:

```bash
voidb-cli invoke describe postgres.query --format json
voidb-cli invoke describe postgres.describe_table --format json
```

`postgres.query` is read-oriented only. `postgres.exec` is destructive and
supports `--dry-run`. Metadata capabilities accept an optional `schema` field;
the connected database comes from the profile and is not overridden per
invocation.

DuckDB follows the shared SQL capability contract for local analytics profiles:

```bash
voidb-cli invoke describe duckdb.query --format json
voidb-cli invoke describe duckdb.describe_table --format json
```

`duckdb.query` is read-oriented only. `duckdb.exec` is destructive and supports
`--dry-run`. Baseline invocation uses only the configured DuckDB path or
`:memory:` profile; file ingest/export forms such as `read_csv`, `COPY`,
`ATTACH`, `INSTALL`, and `LOAD` remain out of the default query capability.

Shared SQL metadata capabilities use a common introspection shape across
PostgreSQL, MySQL, SQLite, and DuckDB. `*.tables` returns `scope`,
`capabilities`, `tables`, and `views`; networked plugins may also include
top-level `database` or `schema` for compatibility. `*.describe_table` returns
`scope`, `capabilities`, `table`, `columns`, `indexes`, `foreign_keys`, and
`constraints`. Agents should branch on `scope.kind` (`local_database`,
`database`, or `schema`) and the boolean `capabilities` flags instead of
inferring plugin behavior from the plugin name.

S3 and WebDAV storage capabilities use the same list/stat/get/put/delete/mkdir
shape. `get` returns bounded `content_base64`; `put` accepts either
`content_base64` or `content_text` and never echoes object content back in the
result.

```bash
voidb-cli invoke describe s3.put --format json
voidb-cli invoke describe webdav.sync_plan --format json
```

`put`, `delete`, and `mkdir` are destructive and support `--dry-run`.
`sync_plan` is read-only planning; it computes changes but does not apply them.
Agents should use `--yes` only when the human/user intent is explicit.

Email reads remain bounded, while side effects require preview and explicit
authorization:

```bash
voidb-cli invoke describe email.folders --format json
voidb-cli invoke describe email.fetch --format json
voidb-cli invoke describe email.send --format json
voidb-cli invoke describe email.delete --format json
voidb-cli invoke describe email.idle --format json
```

`email.fetch` uses the service's read-only fetch path and does not mark IMAP
messages read. `email.send`, `email.move`, `email.delete`, and `email.flag`
require redacted previews, dry-run/acknowledgement policy, and stable mailbox
identity checks. Attachment downloads are restricted to approved local roots,
and `email.idle` runs only in an agent-owned, bounded, cancellable session.
Message bodies, recipient lists, credentials, and attachment contents remain
out of default audit summaries.

Docker and Kubernetes operations capabilities follow the same discovery and
policy model:

```bash
voidb-cli invoke describe docker.list_containers --format json
voidb-cli invoke describe docker.container_action --format json
voidb-cli invoke describe kubernetes.list --format json
voidb-cli invoke describe kubernetes.apply --format json
```

Docker read capabilities include `docker.diagnostics`,
`docker.list_containers`, `docker.list_images`, `docker.list_networks`,
`docker.list_volumes`, `docker.inspect_container`, and `docker.logs`.
`docker.inspect_container` returns a redacted summary rather than raw inspect
JSON, and `docker.logs` is bounded and non-following. `docker.container_action`
supports `start`, `stop`, `restart`, and `remove`; it is destructive and
supports `--dry-run`.

Kubernetes read capabilities include `kubernetes.diagnostics`,
`kubernetes.contexts`, `kubernetes.namespaces`, `kubernetes.list`,
`kubernetes.get_yaml`, and `kubernetes.logs`. `kubernetes.get_yaml` blocks
Secret YAML payloads; use `kubernetes.list` with `resource_type:"secrets"` for
metadata-only secret summaries. `kubernetes.delete`, `kubernetes.scale`,
`kubernetes.restart`, and `kubernetes.apply` are destructive and support
`--dry-run`.

MongoDB and Elasticsearch document/search capabilities follow the same
discovery and policy model:

```bash
voidb-cli invoke describe mongodb.find --format json
voidb-cli invoke describe mongodb.run_command --format json
voidb-cli invoke describe elasticsearch.search --format json
voidb-cli invoke describe elasticsearch.raw_api --format json
```

MongoDB read capabilities include `mongodb.diagnostics`, `mongodb.databases`,
`mongodb.collections`, `mongodb.find`, `mongodb.count`, `mongodb.aggregate`,
and `mongodb.indexes`. `mongodb.aggregate` rejects `$out` and `$merge` in the
read-only path. `mongodb.insert`, `mongodb.update`, `mongodb.delete`,
`mongodb.create_index`, and `mongodb.run_command` are destructive and support
`--dry-run`.

Elasticsearch read capabilities include `elasticsearch.diagnostics`,
`elasticsearch.health`, `elasticsearch.nodes`, `elasticsearch.indices`,
`elasticsearch.search`, `elasticsearch.get`, `elasticsearch.count`, and
`elasticsearch.mapping`. `elasticsearch.mapping` returns property metadata and
omits the raw mapping body. `elasticsearch.raw_api` is always
destructive-gated; agents should use the explicit read capabilities first.

Jenkins CI capabilities follow the same discovery and policy model:

```bash
voidb-cli invoke describe jenkins.jobs --format json
voidb-cli invoke describe jenkins.console --format json
voidb-cli invoke describe jenkins.trigger_build --format json
```

Jenkins read capabilities include `jenkins.diagnostics`, `jenkins.jobs`,
`jenkins.job_detail`, `jenkins.activity`, `jenkins.console`, and
`jenkins.pipeline`. Console output is byte-bounded and returns `next_offset`
metadata for continued fetches. `jenkins.trigger_build`,
`jenkins.abort_build`, and `jenkins.cancel_queue_item` are destructive and
support `--dry-run`.

## Current Non-Promoted Boundary

No built-in plugin should be invoked by inferring capability IDs from TUI or
traditional CLI command names. Agents must discover `*.capability` IDs through
`voidb-cli invoke list` or `voidb-cli invoke describe` and treat absent
capabilities as unsupported.

## Agent Workflow Recipes

These recipes use redacted saved profiles and fixture-safe input. Agents should
parse the top-level JSON envelope first: `ok`, `schema_version`, `command`, and
then the command-specific `data` or `error` object. Human text and table output
are not stable contracts.

### Inspect Profiles And Schemas

Start by listing profiles and selecting a profile by explicit alias or ID:

```bash
voidb-cli profile list --format json
voidb-cli profile show alias:local-dev --format json
voidb-cli profile test alias:local-dev --format json
```

Then discover the exact capability schema before constructing input:

```bash
voidb-cli invoke list sqlite --format json
voidb-cli invoke describe sqlite.query --format json
```

Use `data.capability.input_schema` and `data.capability.output_schema` as the
authoritative shape. Do not infer hidden connection fields from examples.

### Run A Safe SQL Query

Use read-only query capabilities for inspection. Keep page limits explicit and
pass returned cursors back unchanged:

```bash
voidb-cli invoke run sqlite.query \
  --profile local-dev \
  --page-limit 100 \
  --input-json '{"sql":"select name from users order by id"}' \
  --format json
```

Use `explain` for one read-oriented statement when the next step depends on
the target plan:

```bash
voidb-cli invoke run sqlite.explain \
  --profile local-dev \
  --input-json '{"sql":"select name from users order by id"}' \
  --format json
```

For a networked SQL profile, use the same flow with the target plugin:

```bash
voidb-cli invoke describe postgres.query --format json
voidb-cli invoke run postgres.query \
  --profile warehouse \
  --page-limit 100 \
  --input-json '{"sql":"select id, total from invoices order by id"}' \
  --format json
```

### Analyze Local Data With DuckDB

DuckDB uses the same bounded SQL result contract as the other SQL plugins. The
profile owns the database path; the input owns only SQL and pagination:

```bash
voidb-cli invoke describe duckdb.query --format json
voidb-cli invoke run duckdb.query \
  --profile analytics \
  --page-limit 100 \
  --input-json '{"sql":"select region, revenue from sales order by region"}' \
  --format json
```

Use `duckdb.exec --dry-run` before any mutation:

```bash
voidb-cli invoke run duckdb.exec \
  --profile analytics \
  --dry-run \
  --input-json '{"sql":"drop table scratch"}' \
  --format json
```

Inspect the dry-run `output.mutation_gate` and `output.classifications` before
running a real mutation. They are redacted metadata; they do not echo raw SQL
literal values.

### Plan Storage Writes Before Applying Them

For object storage or WebDAV mutations, dry-run first and inspect structured
intent rather than object contents:

```bash
voidb-cli invoke run s3.put \
  --profile assets \
  --dry-run \
  --input-json '{"bucket":"logs","key":"agent/probe.txt","content_text":"hello"}' \
  --format json

voidb-cli invoke run webdav.mkdir \
  --profile dav \
  --dry-run \
  --input-json '{"path":"/agent"}' \
  --format json
```

Only add `--yes` when the user has explicitly requested the side effect.

### Plan Operations Changes Before Applying Them

For Docker lifecycle and Kubernetes mutation operations, dry-run first:

```bash
voidb-cli invoke run docker.container_action \
  --profile local-docker \
  --dry-run \
  --input-json '{"id":"abc123","action":"restart"}' \
  --format json

voidb-cli invoke run kubernetes.apply \
  --profile staging \
  --dry-run \
  --input-json '{"yaml":"apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: agent-probe\n"}' \
  --format json
```

Inspect the dry-run `output.details` and policy decision before rerunning with
`--yes`. Live daemon or cluster smoke is opt-in and must use disposable
containers, namespaces, or scratch resources.

### Inspect Documents And Search Results

For MongoDB document reads, keep page limits explicit and pass returned cursors
back unchanged:

```bash
voidb-cli invoke run mongodb.find \
  --profile documents \
  --page-limit 100 \
  --input-json '{"database":"app","collection":"users","filter":{"active":true}}' \
  --format json

voidb-cli invoke run mongodb.aggregate \
  --profile documents \
  --page-limit 100 \
  --input-json '{"database":"app","collection":"users","pipeline":[{"$match":{"active":true}}]}' \
  --format json
```

For Elasticsearch search reads, use the same cursor flow:

```bash
voidb-cli invoke run elasticsearch.search \
  --profile search \
  --page-limit 100 \
  --input-json '{"index":"users","query":{"query":{"match_all":{}}}}' \
  --format json
```

Outputs include bounded document/hit arrays and separate payload summaries.
Audit metadata and summaries must be treated as shape-only; they are not a
place to recover plaintext document values.

### Plan Document Mutations Before Applying Them

MongoDB mutations and Elasticsearch raw API calls are destructive-gated. Dry
run first and inspect intent summaries:

```bash
voidb-cli invoke run mongodb.update \
  --profile documents \
  --dry-run \
  --input-json '{"database":"app","collection":"users","filter":{"id":1},"update":{"$set":{"active":false}}}' \
  --format json

voidb-cli invoke run elasticsearch.raw_api \
  --profile search \
  --dry-run \
  --input-json '{"method":"POST","path":"/users/_doc/1","body":{"active":false}}' \
  --format json
```

Only add `--yes` when the user explicitly requested the side effect. Prefer
explicit read capabilities over raw commands or raw APIs whenever they cover
the task.

### Inspect CI Jobs Before Triggering Builds

For Jenkins, use read-only capabilities to inspect jobs, activity, and logs:

```bash
voidb-cli invoke run jenkins.jobs \
  --profile ci \
  --page-limit 50 \
  --input-json '{"folder":"team"}' \
  --format json

voidb-cli invoke run jenkins.job_detail \
  --profile ci \
  --page-limit 20 \
  --input-json '{"job_full_name":"team/build"}' \
  --format json

voidb-cli invoke run jenkins.console \
  --profile ci \
  --input-json '{"job_full_name":"team/build","build_number":42,"max_bytes":65536}' \
  --format json
```

Use `data.page.next_cursor` or `output.next_offset` for continuation. Console
summaries must not be used as a way to recover hidden output; they are metadata
only.

### Plan CI Side Effects Before Applying Them

Triggering, aborting, and queue cancellation are destructive-gated. Dry-run
first:

```bash
voidb-cli invoke run jenkins.trigger_build \
  --profile ci \
  --dry-run \
  --input-json '{"job_full_name":"team/build"}' \
  --format json

voidb-cli invoke run jenkins.abort_build \
  --profile ci \
  --dry-run \
  --input-json '{"job_full_name":"team/build","build_number":42}' \
  --format json
```

Only rerun with `--yes` when the user explicitly requested the side effect and
the target job/build/queue item is disposable or otherwise approved.

### Inspect Sync Status And Conflicts

Sync status is local and redacted. JSON output uses the sync envelope and keeps
object details under `data.objects`:

```bash
voidb-cli sync status --format json
voidb-cli sync conflict list --format json
```

Conflict resolution commands must use opaque IDs from the JSON output, not
local profile IDs or labels:

```bash
voidb-cli sync conflict resolve \
  --mode keep-remote \
  --object-kind profile \
  --object-id sync_profile_abc
```

For credential-record conflicts, use the handoff command and follow the
returned `data.command` with local secret-source flags. The handoff output does
not print credential material:

```bash
voidb-cli sync conflict credential-handoff \
  --object-id sync_credrec_abc \
  --format json
```

## SQLite Query

SQLite invocation uses a saved profile reference. The profile resolves to the
database path inside VoidB; the agent supplies only capability input and optional
execution controls.

```bash
voidb-cli invoke run sqlite.query \
  --profile local-dev \
  --page-limit 100 \
  --input-json '{"sql":"select name from users order by id"}' \
  --format json
```

Abridged success shape:

```json
{
  "ok": true,
  "data": {
    "status": "succeeded",
    "output": {
      "statements": [
        {
          "kind": "select",
          "columns": [{ "name": "name", "data_type": "TEXT" }],
          "rows": [{ "name": "Ada" }],
          "row_count": 1,
          "source_row_count": 1,
          "truncated": false
        }
      ],
      "row_limit": 100,
      "row_count": 1,
      "source_row_count": 1,
      "truncated": false,
      "cursor": null,
      "next_cursor": null
    },
    "output_summary": {
      "statement_count": 1,
      "row_count": 1,
      "truncated": false
    }
  }
}
```

When `next_cursor` is present, pass it back through `--page-cursor` with the
same SQL and profile:

```bash
voidb-cli invoke run sqlite.query \
  --profile local-dev \
  --page-limit 100 \
  --page-cursor 100 \
  --input-json '{"sql":"select name from users order by id"}' \
  --format json
```

## PostgreSQL Query

PostgreSQL uses the same shared SQL result shape as SQLite and MySQL. The
profile selects the target database. Metadata calls default to the `public`
schema unless the input includes `schema`.

```bash
voidb-cli invoke run postgres.query \
  --profile warehouse \
  --page-limit 100 \
  --input-json '{"sql":"select id, total from invoices order by id"}' \
  --format json
```

Plan inspection:

```bash
voidb-cli invoke run postgres.explain \
  --profile warehouse \
  --input-json '{"sql":"select id, total from invoices order by id"}' \
  --format json
```

Schema discovery:

```bash
voidb-cli invoke run postgres.tables \
  --profile warehouse \
  --input-json '{"schema":"analytics"}' \
  --format json

voidb-cli invoke run postgres.describe_table \
  --profile warehouse \
  --input-json '{"schema":"analytics","table":"daily_revenue"}' \
  --format json
```

Destructive SQL remains denied by default. Use `--dry-run` to inspect intent,
or `--yes` only when the user explicitly requested a real mutation.

```bash
voidb-cli invoke run postgres.exec \
  --profile warehouse \
  --dry-run \
  --input-json '{"sql":"drop table analytics.old_rollup"}' \
  --format json
```

Abridged dry-run output:

```json
{
  "data": {
    "output": {
      "dry_run": true,
      "statement_count": 1,
      "classifications": [
        {
          "index": 0,
          "classification": "schema",
          "confidence": "heuristic",
          "reason_code": "statement.schema"
        }
      ],
      "mutation_gate": {
        "destructive": true,
        "acknowledged": false,
        "dry_run": true,
        "transaction_control": false
      }
    }
  }
}
```

## DuckDB Query

DuckDB uses the same local direct-mode shape as SQLite while preserving the
service-owned `SyncWorker` path for the native driver.

```bash
voidb-cli invoke run duckdb.query \
  --profile analytics \
  --page-limit 100 \
  --input-json '{"sql":"select region, revenue from sales order by region"}' \
  --format json
```

Schema discovery:

```bash
voidb-cli invoke run duckdb.tables \
  --profile analytics \
  --input-json '{}' \
  --format json

voidb-cli invoke run duckdb.describe_table \
  --profile analytics \
  --input-json '{"table":"sales"}' \
  --format json
```

Use `duckdb.exec --dry-run` first for destructive SQL, then `--yes` only when
the user explicitly requested mutation.

Use `duckdb.explain` for read-only plan inspection. Built-in SQL explain
capabilities reject `analyze = true` by default to avoid executing target work.

## Redis Keys

Redis key scans use `InvocationControls.page` for cursor and limit. The current
capability accepts the legacy Redis SCAN cursor form (`"42"`) and the
capability-owned local page cursor form (`"42:100"`). Agents must treat cursors
as opaque and pass them back unchanged.

```bash
voidb-cli invoke run redis.keys \
  --profile cache-dev \
  --page-limit 50 \
  --input-json '{"pattern":"agent:*"}' \
  --format json
```

Abridged success shape:

```json
{
  "ok": true,
  "data": {
    "status": "succeeded",
    "output": {
      "pattern": "agent:*",
      "cursor": null,
      "next_cursor": "0:50",
      "limit": 50,
      "key_count": 50,
      "scan_count": 200,
      "truncated": true,
      "keys": [
        { "key": "agent:test", "key_type": "string", "ttl": -1 }
      ]
    },
    "page": { "next_cursor": "0:50" }
  }
}
```

Next page:

```bash
voidb-cli invoke run redis.keys \
  --profile cache-dev \
  --page-limit 50 \
  --page-cursor '0:50' \
  --input-json '{"pattern":"agent:*"}' \
  --format json
```

## S3 Storage

S3 list results use the provider's bounded `ListObjects` page and return its
opaque continuation token unchanged.

```bash
voidb-cli invoke run s3.list \
  --profile assets \
  --page-limit 50 \
  --input-json '{"bucket":"logs","prefix":"2026/07/"}' \
  --format json
```

Abridged success shape:

```json
{
  "ok": true,
  "data": {
    "status": "succeeded",
    "output": {
      "bucket": "logs",
      "prefix": "2026/07/",
      "entries": [
        {
          "key": "2026/07/app.log",
          "display_name": "app.log",
          "entry_type": "object",
          "size": 1204
        }
      ],
      "entry_count": 1,
      "next_cursor": null,
      "truncated": false
    }
  }
}
```

Dry-run upload returns only metadata about the intended write:

```bash
voidb-cli invoke run s3.put \
  --profile assets \
  --dry-run \
  --input-json '{"bucket":"logs","key":"agent/probe.txt","content_text":"hello"}' \
  --format json
```

Bucket discovery, verified copy/move, and delegated URLs are also explicit
capabilities:

```bash
voidb-cli invoke run s3.buckets --profile assets --input-json '{}' --format json
voidb-cli invoke run s3.copy --profile assets --dry-run \
  --input-json '{"source_bucket":"logs","source_key":"a.log","destination_bucket":"archive","destination_key":"a.log","replace":false}' \
  --format json
voidb-cli invoke run s3.presign --profile assets \
  --input-json '{"bucket":"logs","key":"a.log","method":"get","expires_seconds":900}' \
  --format json
```

## WebDAV Storage

WebDAV capabilities use `path` for item operations and `remote_path` plus
`local_path` for sync planning.

```bash
voidb-cli invoke run webdav.list \
  --profile dav \
  --page-limit 50 \
  --input-json '{"path":"/reports"}' \
  --format json
```

Feature probing and conditional server-side copy are available without
exposing lock tokens:

```bash
voidb-cli invoke run webdav.probe --profile dav \
  --input-json '{"path":"/reports"}' --format json
voidb-cli invoke run webdav.copy --profile dav --dry-run \
  --input-json '{"source":"/reports/a.pdf","destination":"/archive/a.pdf","overwrite":false,"depth":"0"}' \
  --format json
```

Long-running `s3.transfer` and `webdav.transfer` capabilities are session-only.
Their catalog entries provide a `file_transfer` handoff family; direct
stateless invocation returns `unavailable.session_required`.

Directory creation is destructive and stays denied by default unless the
invocation uses `--dry-run`, the profile explicitly allows it, or the user
passes `--yes`:

```bash
voidb-cli invoke run webdav.mkdir \
  --profile dav \
  --dry-run \
  --input-json '{"path":"/agent"}' \
  --format json
```

Sync planning is non-destructive:

```bash
voidb-cli invoke run webdav.sync_plan \
  --profile dav \
  --input-json "{\"remote_path\":\"/reports\",\"local_root\":\"$PWD\",\"local_path\":\"reports\",\"mode\":\"pull\"}" \
  --format json
```

`local_root` is an absolute human-approved scope and `local_path` is relative
to it. Agent grants for local filesystem capabilities must use a structured or
exact JIT scope; capability-wide proactive grants are rejected. Sync plans
return an opaque `local_scope_id` and opaque entry references unless
`disclose_relative_paths` is explicitly approved.

## Email Mailbox

Email diagnostics are profile-shape checks only; they do not connect to IMAP,
POP3, or SMTP and do not emit the email address or password.

```bash
voidb-cli invoke run email.diagnostics \
  --profile mail \
  --input-json '{}' \
  --format json
```

Folder and message listing use bounded service direct-mode calls:

```bash
voidb-cli invoke run email.folders \
  --profile mail \
  --input-json '{}' \
  --format json

voidb-cli invoke run email.list \
  --profile mail \
  --page-limit 25 \
  --input-json '{"folder":"INBOX","unread_only":false}' \
  --format json
```

`email.search` filters the fetched envelope page by sender or subject; agents
should follow `next_cursor` for additional pages.

```bash
voidb-cli invoke run email.search \
  --profile mail \
  --page-limit 25 \
  --input-json '{"folder":"INBOX","query":"invoice"}' \
  --format json
```

Message fetch returns bounded text and attachment metadata only. Attachment
bytes are not exposed by this capability.

```bash
voidb-cli invoke run email.fetch \
  --profile mail \
  --input-json '{"folder":"INBOX","uid":42,"max_text_bytes":65536}' \
  --format json
```

## Dry-Run Writes

Destructive Redis writes should be inspected with dry-run before an agent asks
for a real mutation. Dry-run output intentionally does not echo sensitive value
payloads.

```bash
voidb-cli invoke run redis.set \
  --profile cache-dev \
  --dry-run \
  --input-json '{"key":"agent:test","value":"ready"}' \
  --format json
```

Expected dry-run shape:

```json
{
  "ok": true,
  "data": {
    "status": "succeeded",
    "output": {
      "dry_run": true,
      "would_execute": true,
      "destructive": true,
      "operation": "set",
      "details": { "key": "agent:test" }
    },
    "output_summary": { "dry_run": true, "operation": "set" }
  }
}
```

For a real destructive invocation, the CLI requires explicit acknowledgement:

```bash
voidb-cli invoke run redis.del \
  --profile cache-dev \
  --yes \
  --input-json '{"key":"agent:test"}' \
  --format json
```

## Structured Errors

Agents should branch on stable error categories and codes instead of parsing
human display text.

Attempting a mutating statement through `sqlite.query` fails before opening the
target database:

```bash
voidb-cli invoke run sqlite.query \
  --profile local-dev \
  --input-json '{"sql":"delete from users"}' \
  --format json
```

Expected error shape:

```json
{
  "ok": false,
  "error": {
    "category": "policy",
    "code": "policy.destructive_requires_exec_capability",
    "details": { "capability_id": "query" },
    "target": null,
    "retryable": false,
    "redaction": "not_required"
  }
}
```

An invalid Redis pagination cursor returns a validation error and does not open
a Redis connection:

```bash
voidb-cli invoke run redis.keys \
  --profile cache-dev \
  --page-cursor not-a-cursor \
  --input-json '{"pattern":"agent:*"}' \
  --format json
```

Expected error code:

```json
{
  "ok": false,
  "error": {
    "category": "validation",
    "code": "validation.invalid_cursor",
    "redaction": "not_required"
  }
}
```

Redis target failures use `target_system` errors. If a lower layer includes a
Redis URL with auth material, the capability redacts the auth segment before the
error reaches agent-facing output.

```json
{
  "ok": false,
  "error": {
    "category": "target_system",
    "code": "redis.get_failed",
    "target": {
      "system": "redis",
      "message": "failed rediss://<redacted>@127.0.0.1:6379/0"
    },
    "redaction": "applied"
  }
}
```

## Repeated Invocations

A saved connection profile is not a singleton live connection. Repeated
invocations may reference the same profile name while Core creates distinct
invocation IDs and grants.

```bash
voidb-cli invoke run sqlite.query \
  --profile local-dev \
  --input-json '{"sql":"select count(*) as total from users"}' \
  --format json

voidb-cli invoke run sqlite.query \
  --profile local-dev \
  --input-json '{"sql":"select name from users order by id limit 1"}' \
  --format json
```

This model is expected for SQLite direct-mode execution, Redis command streams,
SSH sessions, object storage clients, and future protocol plugins.
