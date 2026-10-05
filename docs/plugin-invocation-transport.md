# Plugin Invocation Transport

This document defines the first invocation transport for process-based VoidB
plugins. It complements:

- [Plugin Manifest Schema](plugin-manifest-schema.md), which declares
  `runtime.transport = "stdio-jsonrpc"`.
- [Capability Core Model](capability-core-model.md), which defines
  `CapabilityInvocation`.
- [Audit and Structured Error Schema](audit-and-error-schema.md), which defines
  `CapabilityError` and invocation status values.

The machine-readable transport envelope schema lives at
[`schemas/plugin-invocation-transport.schema.json`](../schemas/plugin-invocation-transport.schema.json).
The agent-facing CLI commands that create invocations and map streaming output
to JSON or NDJSON are defined in
[Capability Discovery and Invocation CLI Contract](capability-cli.md).
Timeout, cancellation, pagination, streaming, dry-run, and destructive
operation controls are defined in
[Agent-Friendly Execution Controls](agent-friendly-execution-controls.md).

## Scope

This slice chooses the first transport and defines the message contract. It
does not implement process discovery, plugin installation, process supervision,
credential brokering internals, or plugin capability handlers.
Process discovery and startup rules are defined in
[Runtime Plugin Discovery](runtime-plugin-discovery.md).

The first transport is `stdio-jsonrpc`:

- VoidB Core starts the plugin process declared by the manifest.
- Core writes JSON-RPC 2.0 messages to plugin stdin.
- The plugin writes JSON-RPC 2.0 responses and notifications to stdout.
- Each JSON-RPC message is one UTF-8 JSON object followed by `\n`.
- Plugin stderr is diagnostic text only and is never part of the protocol.

JSON-RPC uses `jsonrpc = "2.0"` and method names under the `voidb.*` namespace.
Request IDs are strings or integers. Core generates request IDs and correlates
responses.

## Protocol V1 Surface

Protocol v1 is intentionally small and stable:

| Contract item | Stable value |
|---|---|
| Transport | `stdio-jsonrpc` |
| Protocol version sent by Core | `1` |
| Compatible protocol spelling | `1` and `1.0` |
| JSON-RPC version | `2.0` |
| Implemented Core requests | `voidb.initialize`, `voidb.health`, `voidb.invoke` |
| Reserved cooperative request | `voidb.cancel` |
| Reserved stream notifications | `voidb.stream.item`, `voidb.stream.progress`, `voidb.stream.end` |

The current Rust runtime host uses fixed request IDs (`initialize`, `health`,
and `invoke`) because it runs one request at a time per short-lived process.
Plugins and SDKs must still echo whichever JSON-RPC `id` Core sends; future
process pooling may use different IDs.

Core starts the process with a cleared environment, applies non-secret
manifest `runtime.env`, and then overwrites these Core-owned variables:

- `VOIDB_PLUGIN_ID`
- `VOIDB_PLUGIN_DIR`
- `VOIDB_PROTOCOL_VERSION`
- `VOIDB_LOG_FORMAT=json`

Manifests must not rely on overriding those names. Plaintext secrets must never
be passed through manifest env or Core-owned env.

## Startup And Version Negotiation

After Core starts a process, it sends `voidb.initialize`.

```json
{
  "jsonrpc": "2.0",
  "id": "initialize",
  "method": "voidb.initialize",
  "params": {
    "protocol_version": "1",
    "core_version": "0.1.0",
    "plugin_id": "mysql",
    "manifest_path": "/plugins/mysql/plugin.toml",
    "started_at": "2026-07-04T00:00:00Z"
  }
}
```

The plugin returns the selected protocol version and runtime state:

```json
{
  "jsonrpc": "2.0",
  "id": "initialize",
  "result": {
    "plugin_id": "mysql",
    "protocol_version": "1",
    "status": "ready"
  }
}
```

If the plugin cannot support the requested protocol version, it returns a
structured JSON-RPC error with `category = "plugin"` or
`category = "unavailable"`.

## Health Check

Core can send `voidb.health` before invocation, while idle, or after a suspected
failure.

```json
{
  "jsonrpc": "2.0",
  "id": "health",
  "method": "voidb.health",
  "params": {
    "include_runtime": true
  }
}
```

Expected result:

```json
{
  "jsonrpc": "2.0",
  "id": "health",
  "result": {
    "status": "ready",
    "active_invocations": 0
  }
}
```

Stable health statuses are:

- `starting`: process is alive but not ready for invocation.
- `ready`: process can accept invocations.
- `busy`: process is alive but temporarily saturated.
- `draining`: process is shutting down and should not receive new work.
- `failed`: process is alive but cannot execute correctly.

## Invocation Request

Core sends one `voidb.invoke` request for one `CapabilityInvocation`.

```json
{
  "jsonrpc": "2.0",
  "id": "invoke",
  "method": "voidb.invoke",
  "params": {
    "invocation": {
      "id": "invoke-01",
      "plugin_id": "mysql",
      "capability_id": "query",
      "connection": {
        "kind": "from_profile",
        "profile": {
          "kind": "name",
          "value": "prod-db"
        },
        "purpose": {
          "kind": "capability_invocation"
        },
        "reuse": "allow",
        "options": null
      },
      "input": {
        "sql": "select 1"
      },
      "controls": {
        "timeout_ms": 30000,
        "cancellation_token": "cancel-token-01",
        "max_output_bytes": 4194304,
        "stream": false
      },
      "actor": {
        "id": "agent:test",
        "actor_type": "agent"
      },
      "requested_at": "2026-07-04T00:00:00Z"
    },
    "credential_grants": [
      {
        "grant_id": "grant-01",
        "credential_ref_id": "cred-01",
        "class": "password",
        "expires_at": "2026-07-04T00:01:00Z",
        "purpose": "capability_invocation"
      }
    ]
  }
}
```

`credential_grants` are descriptors, not plaintext secret values. The grant
resolution mechanism is intentionally outside this transport slice; whatever
mechanism is chosen later must preserve the rules in
[Secret Brokering and Redaction Policy](secret-brokering-redaction-policy.md).

For a non-streaming capability, the plugin returns a single result:

```json
{
  "jsonrpc": "2.0",
  "id": "invoke",
  "result": {
    "invocation_id": "invoke-01",
    "status": "succeeded",
    "output": {
      "columns": ["?column?"],
      "rows": [[1]]
    },
    "output_summary": {
      "row_count": 1
    }
  }
}
```

The `output` payload is validated against the capability `output_schema`.
The `output_summary` is redacted metadata suitable for audit records.

## Streaming Invocation

For `streaming = true` capabilities or invocations with `controls.stream =
true`, the plugin still receives one `voidb.invoke` request. It then emits
notifications before returning or ending the stream.

Stream item notification:

```json
{
  "jsonrpc": "2.0",
  "method": "voidb.stream.item",
  "params": {
    "invocation_id": "invoke-02",
    "sequence": 0,
    "item": {
      "key": "user:1"
    }
  }
}
```

Progress notification:

```json
{
  "jsonrpc": "2.0",
  "method": "voidb.stream.progress",
  "params": {
    "invocation_id": "invoke-02",
    "sequence": 1,
    "message": "Fetched first page.",
    "progress": 0.25
  }
}
```

Stream end notification:

```json
{
  "jsonrpc": "2.0",
  "method": "voidb.stream.end",
  "params": {
    "invocation_id": "invoke-02",
    "sequence": 2,
    "status": "succeeded",
    "output_summary": {
      "items": 1
    }
  }
}
```

`sequence` starts at `0` and is monotonically increasing per invocation.
The stream aggregator must treat duplicate or out-of-order sequence numbers as
`plugin` errors.

The plugin may also return a final JSON-RPC response to the original
`voidb.invoke` request with the same terminal status. Core should tolerate the
response arriving after `voidb.stream.end`, but it should use exactly one
terminal audit record.

The Rust runtime host validates every stream notification against the
caller-owned invocation ID and exact zero-based sequence. Item and progress
notifications are mapped to caller-facing NDJSON through a bounded 32-event
channel, so a slow consumer applies transport backpressure. `voidb.stream.end`
is mapped to one terminal `CapabilityInvocationResult`; a normal non-streaming
response must carry the same caller-owned invocation ID.

## Cancellation

`voidb.cancel` is the v1 cooperative cancellation request. Core sends it when a
caller cancels an invocation or when Core is enforcing timeout cleanup.

```json
{
  "jsonrpc": "2.0",
  "id": "cancel-01",
  "method": "voidb.cancel",
  "params": {
    "invocation_id": "invoke-02",
    "cancellation_token": "cancel-token-02",
    "reason": "caller requested cancellation"
  }
}
```

Expected response:

```json
{
  "jsonrpc": "2.0",
  "id": "cancel-01",
  "result": {
    "invocation_id": "invoke-02",
    "accepted": true,
    "status": "cancelled"
  }
}
```

Cancellation is cooperative. A plugin should stop work promptly, release
runtime resources, and end any stream with `status = "cancelled"`. If work has
already reached a terminal state, the plugin returns the terminal state instead
of inventing a new cancellation result.

On caller cancellation, the Rust runtime host emits `voidb.cancel` with the
invocation ID and opaque cancellation token. It waits for a bounded cooperative
grace period, then closes and kills the per-invocation process if necessary.
The CLI's first Ctrl-C triggers this path; a second Ctrl-C or the outer grace
deadline forces the same bounded cleanup.

## Timeouts

Timeouts are controlled by Core and described by invocation controls:

- Core validates requested `timeout_ms` against policy.
- Core includes the effective timeout in `invocation.controls.timeout_ms`.
- Core includes the effective terminal result limit in
  `invocation.controls.max_output_bytes`.
- The plugin should enforce that timeout locally where practical.
- Core remains authoritative and may send `voidb.cancel` after the effective
  timeout.
- The current Rust runtime host returns `timeout.process_plugin_request_timed_out`
  when a request exceeds the effective timeout and redacts any stderr gathered
  during process cleanup.

The stdio reader rejects an individual JSON-RPC line larger than the 16 MiB
terminal-result host maximum plus fixed protocol overhead. The final decoded
result is serialized and checked against the caller's effective limit before
it can reach JSON or NDJSON output.

Timeout failures use `category = "timeout"` and an error code that identifies
the boundary:

- `timeout.core`
- `timeout.plugin`
- `timeout.target`

## Structured Errors

Transport failures and invocation failures use JSON-RPC error responses with a
`CapabilityError` in `error.data`.

```json
{
  "jsonrpc": "2.0",
  "id": "rpc-01",
  "error": {
    "code": -32010,
    "message": "Target system rejected the query.",
    "data": {
      "category": "target_system",
      "code": "postgres.syntax_error",
      "message": "Target system rejected the query.",
      "details": null,
      "target": {
        "system": "postgres",
        "code": "42601",
        "message": "syntax error at or near \"from\""
      },
      "retryable": false,
      "redaction": "applied"
    }
  }
}
```

JSON-RPC `code` is a transport-level integer. Agents should branch on
`error.data.category` and `error.data.code`, not on the JSON-RPC integer or
display message.

Recommended JSON-RPC code ranges:

- `-32600` to `-32603`: standard JSON-RPC errors.
- `-32010`: invocation failed with a structured capability error.
- `-32020`: plugin rejected cancellation.
- `-32030`: stream protocol violation.
- `-32040`: plugin unavailable or not initialized.

Errors, stream items, progress messages, target diagnostics, and plugin stderr
must be redacted before they are shown to agents, written to logs, or persisted
in audit records.

## Invariants

- The only first transport value is `stdio-jsonrpc`.
- Only stdout carries protocol messages; stderr is diagnostics only.
- Every message is one JSON object followed by a newline.
- Core generates request IDs and correlates responses.
- Every invocation has exactly one terminal audit outcome.
- Stream events are tied to `invocation_id` and ordered by `sequence`.
- Cancellation and timeout are cooperative at the plugin boundary, but Core is
  authoritative for caller-facing terminal status.
- Plaintext credentials never appear in transport messages.
- Structured transport errors carry `CapabilityError` under `error.data`.
