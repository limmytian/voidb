# Agent-Friendly Execution Controls

This document defines the first agent-facing execution control contract for
VoidB capability invocations. It complements:

- [Capability Core Model](capability-core-model.md)
- [Capability Discovery and Invocation CLI Contract](capability-cli.md)
- [Plugin Invocation Transport](plugin-invocation-transport.md)
- [Audit and Structured Error Schema](audit-and-error-schema.md)
- [Secret Brokering and Redaction Policy](secret-brokering-redaction-policy.md)

The scope is execution behavior only: timeout, cancellation, pagination,
streaming, dry-run, destructive operation handling, and stable exit codes. It
does not implement process supervision, policy storage, audit persistence, or
plugin handlers.

## Goals

Agent-facing execution must be predictable:

- every invocation has an effective timeout
- cancellation is cooperative but caller-visible
- large outputs are paginated or streamed
- dry-run is never silently ignored
- destructive operations require explicit metadata and policy checks
- CLI exit codes are stable enough for scripts
- JSON and NDJSON payloads remain the authoritative machine-readable result

## Control Fields

The `CapabilityInvocation.controls` fields are:

| Field | CLI source | Meaning |
|---|---|---|
| `timeout_ms` | `--timeout <duration>` or legacy `--timeout-ms <milliseconds>` | Effective invocation timeout in milliseconds. |
| `cancellation_token` | generated or `--cancellation-token <token>` | Token used to correlate cooperative cancellation. |
| `max_output_bytes` | `--max-output-bytes <bytes>` | Maximum serialized terminal result accepted by Core. |
| `dry_run` | `--dry-run` | Request validation or simulation without target mutation. |
| `acknowledgement` | `--yes` | Per-invocation acknowledgement with actor, timestamp, optional reason, and optional approval reference. This is not permission. |
| `approval_refs` | policy store or future CLI | References to scoped approvals the policy engine may use. |
| `stream` | `--format ndjson` or `--stream` | Request streamed caller-facing output. |
| `page.limit` | `--page-limit <n>` | First or next page size. |
| `page.cursor` | `--page-cursor <cursor>` | Continue from a previous page cursor. |

The CLI may add convenience flags, but they must map into these fields before
Core starts plugin execution.

## Timeout

Every capability invocation has an effective timeout. Timeout selection uses
this order:

1. `--timeout <duration>`, when provided by the caller.
2. Capability manifest `default_timeout_ms`.
3. Core default timeout.

Core policy may clamp the requested timeout to configured minimum and maximum
values. If a caller requests a timeout outside policy and clamping would change
semantics materially, Core should fail with `validation.timeout_out_of_range`
instead of silently changing it.

Duration syntax:

| Syntax | Meaning |
|---|---|
| `500ms` | milliseconds |
| `5s` | seconds |
| `2m` | minutes |
| `1h` | hours |

Plain numbers are rejected in the CLI with `validation.timeout_unit_required`.
They are accepted only in internal JSON fields that explicitly use
milliseconds.

Timeout enforcement:

- Core records the effective timeout in `invocation.controls.timeout_ms`.
- Core starts timing before plugin execution begins.
- Plugins should enforce the same timeout locally where practical.
- Core remains authoritative for caller-facing terminal status.
- On timeout, Core sends `voidb.cancel` to the plugin and returns
  `status = "timed_out"` unless the invocation already reached a terminal
  state.

Timeout error codes identify the boundary:

| Code | Use |
|---|---|
| `timeout.core` | Core deadline expired before or while supervising execution. |
| `timeout.plugin` | Plugin did not respond or did not complete in time. |
| `timeout.target` | Target system operation exceeded its timeout. |

Timeouts use CLI exit code `9`.

## Cancellation

Cancellation is cooperative at the plugin boundary and authoritative at the
Core boundary.

The CLI supports:

| Control | Meaning |
|---|---|
| `--cancellation-token <token>` | Provide a caller-generated token for correlation. |
| `--call-id <id>` | Provide the public caller-owned invocation ID; VoidB generates a UUID-backed ID when omitted. |
| first `SIGINT` / Ctrl-C | Request cooperative cancellation through Core. |
| second `SIGINT` / Ctrl-C | Abort the local CLI process after a short grace period. |

When no token is provided, Core generates one. The token must be included in
`invocation.controls.cancellation_token` before execution starts.

Cancellation behavior:

1. Core sends `voidb.cancel` with the invocation ID and cancellation token.
2. The plugin should stop work promptly and release runtime resources.
3. Streaming invocations should emit a terminal stream event with
   `status = "cancelled"` when possible.
4. If the target already reached a terminal state, Core reports that terminal
   state instead of overwriting it with cancellation.
5. If the plugin does not respond within the cancellation grace period, Core
   closes and then kills the per-invocation process if needed, returning
   `cancellation.requested` without leaving an orphan.

Caller-provided IDs and cancellation tokens are limited to 128 bytes and the
public ASCII identifier characters `A-Z`, `a-z`, `0-9`, `-`, `_`, `.`, and
`:`. Cancellation tokens are never emitted or written to audit metadata.

Caller-requested cancellation uses:

```json
{
  "category": "cancellation",
  "code": "cancellation.requested",
  "retryable": false
}
```

Cancellation uses CLI exit code `10`. If the operating system terminates the
process before Core can emit a structured result, the shell may report a
signal-derived code such as `130`; JSON and NDJSON output are authoritative
only when the CLI produced them.

## Pagination

Large bounded outputs must be paginated or streamed. Capabilities that can
return many rows, keys, objects, log lines, documents, or messages must support
at least one of:

- `InvocationControls.page`
- `InvocationControls.stream`
- a plugin-defined input filter that makes output naturally bounded

Pagination fields:

```json
{
  "page": {
    "limit": 100,
    "cursor": "opaque-next-cursor"
  }
}
```

Rules:

- `--page-limit` must be between `1` and `1000`; an omitted limit paired with
  a cursor defaults to `100`.
- `--page-cursor` is limited to 4096 UTF-8 bytes.
- Cursors are opaque strings owned by the plugin.
- Agents must not parse cursor internals.
- Output includes `page.next_cursor` when more data is available.
- A missing or null `next_cursor` means the current result is terminal for that
  query shape.

Example output:

```json
{
  "ok": true,
  "data": {
    "status": "succeeded",
    "output": {
      "rows": []
    },
    "page": {
      "next_cursor": "cursor_02"
    }
  },
  "warnings": []
}
```

Pagination validation failures use `validation.page_limit_invalid` or
`validation.page_cursor_too_large`. Capability-level target cursor failures use
`target_system` when the target rejected the cursor and `plugin` when the
plugin returned a malformed cursor.

## Streaming

NDJSON is the stable caller-facing streaming format. It is separate from the
plugin JSON-RPC transport.

Streaming is selected by:

- `--format ndjson`
- `--stream`, when a command wants streaming with a non-default format
- capability metadata that requires streaming for safe output size

Stable NDJSON event types use one common envelope containing
`protocol_version`, `sequence`, and `invocation_id`:

| Event | Required fields | Meaning |
|---|---|---|
| `start` | `data.capability_ref`, optional `data.timeout_ms` | Invocation accepted with its effective deadline. |
| `data` | `data.value` | One redacted output item, page, or final bounded result. |
| `progress` | optional message/current/total fields | Progress metadata or heartbeat. |
| `warning` | `data.warning` | Redacted non-terminal warning. |
| `error` | `data.error` | Structured terminal or stream-level error. |
| `end` | `data.status`, optional `data.duration_ms` | Terminal stream outcome. |

Rules:

- Each line is one complete UTF-8 JSON object followed by `\n`.
- Event lines must be flushed promptly.
- `protocol_version` is `1` for the current contract.
- `sequence` starts at `0` and increases by one for every event.
- Stream items and diagnostics must be redacted before they are written.
- A stream has exactly one `end` event unless the local process is killed.
- `error` should be followed by `end` when Core can still write a terminal
  event.
- Process-plugin stream notifications are validated for invocation ID and exact
  source sequence, then passed through a bounded 32-event channel. A slow
  consumer therefore applies backpressure instead of growing memory without
  limit.

The terminal `CapabilityInvocationResult` defaults to a 4 MiB serialized limit
and may be raised by the caller only up to the 16 MiB host maximum. Oversized
results fail with `plugin.output_limit_exceeded`; the error reports byte counts
and whether a continuation cursor was available, but never includes a partial
payload.

If a capability can only run safely in streaming mode and the caller requests
`--format json`, Core must fail with `validation.streaming_required` rather
than buffering unbounded output.

Streaming protocol violations use `plugin.stream_protocol_violation` and CLI
exit code `12`.

## Dry-Run

Dry-run is an explicit capability contract. It must never be silently ignored.

Rules:

- `--dry-run` maps to `InvocationControls.dry_run = true`.
- Core accepts `--dry-run` only when the capability metadata has
  `supports_dry_run = true`.
- If unsupported, Core returns `validation.dry_run_not_supported`.
- A plugin that advertises dry-run must not mutate target-system state while
  `dry_run = true`.
- Dry-run output should describe the planned action and validation result, not
  execute side effects.

Dry-run successful output should include:

```json
{
  "dry_run": true,
  "would_execute": true,
  "destructive": true,
  "checks": []
}
```

If a target system cannot fully validate without side effects, the plugin must
make that limitation explicit in output or warnings. It must not claim success
for checks it did not perform.

## Destructive Operations

Destructive operation handling uses three separate concepts:

| Concept | Source | Meaning |
|---|---|---|
| Risk metadata | Manifest/core `risk` plus legacy `destructive` | Classifies the capability as `read_only`, `mutating`, `destructive`, or `external_side_effect`. |
| Acknowledgment | CLI `--yes` | The caller intentionally requested a destructive operation. |
| Permission | Core policy/profile policy | VoidB allows this actor/profile/capability combination. |

`--yes` is not permission. It creates an `InvocationAcknowledgement` that can
be audited. Core must still evaluate profile policy, actor policy, capability
permissions, active scoped approvals, and credential grants.

Destructive rules:

- Any capability that can mutate or delete target state must declare
  `destructive = true`.
- New capabilities should also declare `risk`; older `destructive = true`
  metadata is folded into `effective_risk() = destructive`.
- Non-interactive destructive invocations require `--yes` unless policy
  explicitly marks confirmation as pre-approved for the actor and profile.
- `external_side_effect` invocations follow the same acknowledgement rule as
  destructive invocations.
- If confirmation is missing, Core returns
  `policy.destructive_denied_by_default`.
- If scoped approval is required before execution, Core returns
  `policy.approval_required`.
- If a profile explicitly denies a capability, Core returns
  `policy.capability_denied` even when `--yes` or approval references are
  present.
- If `--dry-run` is requested for a capability that does not support it, Core
  returns `validation.dry_run_not_supported`.
- `--dry-run` may be allowed without `--yes` when the capability supports
  dry-run and Core can guarantee no target mutation.
- Destructive invocation audit records must include the capability ID, profile
  reference, actor, acknowledgment status, and redacted policy decision.
- Scoped approvals have actor, scope, issue time, optional TTL, optional
  revocation time, and redacted reason fields. Expired or revoked approvals
  fail closed.

Capabilities that are not marked destructive must still obey target permissions
and profile policy. A plugin returning side effects from a non-destructive
capability is a plugin contract violation.

Audit records should store structured policy outcomes, not prompt text. The
`CapabilityPolicyDecision` outcome (`allow`, `deny`, `requires_approval`,
`requires_acknowledgement`, or `dry_run_only`) and its redacted reason are the
machine-readable contract for agents and supervisors.

## Stable CLI Exit Codes

JSON and NDJSON payloads are authoritative. Exit codes are a compact routing
signal for shells and supervisors.

| Exit code | Category | Use |
|---:|---|---|
| `0` | success | Invocation or command reached `succeeded`. |
| `1` | internal | VoidB failed unexpectedly or no structured category was available. |
| `2` | validation | CLI usage, input parsing, schema validation, or invalid controls failed. |
| `3` | unavailable | Required plugin, profile, capability, service, or target was unavailable. |
| `4` | auth | Target-system authentication failed. |
| `5` | permission | VoidB permission check denied execution. |
| `6` | credential | Credential reference or brokered grant was missing, expired, or incompatible. |
| `7` | policy | Non-auth policy blocked execution. |
| `8` | conflict | Version, lock, cursor, instance, or state conflict. |
| `9` | timeout | Core, plugin, or target timeout. |
| `10` | cancellation | Caller or Core cancelled execution. |
| `11` | transport | Pipe, socket, TLS, DNS, process I/O, or network transport failure. |
| `12` | plugin | Plugin crash, malformed protocol data, or plugin contract violation. |
| `13` | target_system | Remote database, service, host, or API rejected the operation. |

For non-invocation commands, use the closest category. For example, invalid
CLI flags return `2`, an unavailable plugin returns `3`, and an unreadable
manifest caused by malformed plugin metadata returns `12`.

If multiple failures occur, the first terminal structured error determines the
exit code. Warnings do not affect the exit code.

## Retry Guidance

Agents should use structured error fields before retrying:

- Retry only when `retryable = true`.
- Prefer retrying `transport`, `timeout`, and `unavailable` failures with
  bounded backoff.
- Do not retry `validation`, `permission`, `credential`, or `policy` failures
  without changing input, credentials, or policy.
- Treat `target_system` retryability as plugin-specific.
- Do not retry destructive operations automatically unless policy explicitly
  allows idempotent retry and the capability documents idempotency.

## Invariants

- Every invocation has an effective timeout.
- Cancellation is cooperative at the plugin boundary and authoritative at the
  Core boundary.
- Large outputs are paginated, streamed, or rejected before unbounded buffering.
- Dry-run is honored only when the capability advertises support.
- Destructive capabilities require explicit metadata and policy evaluation.
- `--yes` records acknowledgment but does not grant permission.
- Exit codes are stable, but JSON and NDJSON payloads remain authoritative.
- Redaction happens before any execution control diagnostics reach stdout,
  stderr, logs, or audit records.
