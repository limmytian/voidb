# Infrastructure Agent Live-Session Contract

This document records the shared protocol and its bundled Docker, Kubernetes,
and Jenkins implementations. A workflow is supported only when its capability
catalog entry declares this contract and the broker registers the owning
plugin's live-session factory.

## Ownership Boundary

Target clients and live handles stay inside the owning plugin service:

- Docker owns Bollard streams, exec IDs, stdin bridges, and resize calls.
- Kubernetes owns kube clients, watch streams, exec channels, and listeners.
- Jenkins owns HTTP clients, progressive offsets, queue/build state, and polling.

Core owns only secret-free discovery metadata and bounded request, event, and
audit envelopes. The agent broker continues to own grants, immutable Profile ID
binding, call IDs, serialization, cancellation priority, leases, and bounded
close/shutdown. Neither Core nor the shell stores a target client or stream
handle.

## Discovery Descriptor

`CapabilitySessionHandoff.live_session` carries an optional
`AgentLiveSessionContract`. Protocol version 1 declares:

- the operation kind, such as `log`, `watch`, `exec`, or `progressive_output`;
- a resource type, JSON Schema, and scalar identity fields;
- the schema for session-open parameters and each event payload;
- the capability IDs used to read events and, where relevant, send input,
  resize, or signal;
- retained event/byte bounds and overflow behavior;
- reconnect and resume semantics;
- delivery semantics for buffered/source-paced backpressure, scoped cursors,
  heartbeat/idle bounds, and the maximum pull wait;
- call-cancel and session-close effects; and
- the risk of starting the live target operation.

Every operation capability is fully qualified and must be included in the
handoff capability family. Generic catalog and execution-mode mismatch output
therefore exposes enough information to authorize and open the right session
without a plugin-specific discovery command. A malformed descriptor fails
closed before the factory opens a target handle.

## Start Envelope

Live factories decode `AgentSessionOpenRequest.input` as this stable envelope:

```json
{
  "resource": {
    "container_id": "<target selected by caller>"
  },
  "parameters": {
    "tail": 200,
    "follow": true
  },
  "resume_from": {
    "kind": "timestamp",
    "value": "<opaque bounded cursor>"
  },
  "buffer": {
    "max_events": 500,
    "max_bytes": 524288,
    "overflow": "drop_oldest"
  }
}
```

The descriptor validates `resource` and `parameters` independently. Declared
identity values must be scalar, but they are never copied into the shared audit
projection. Start input is capped at 64 KiB. A caller may request a smaller
buffer with the declared overflow behavior, never a larger or semantically
different one.

If starting the source has any target or external side effect, the contract
sets `start_risk` to `mutating`, `destructive`, or `external_side_effect`.
`agent session open` then requires both a grant that permits the risk and a
per-open `--yes`. The grant is not treated as acknowledgement. Read-only
observation remains openable without destructive consent.

## Pull-Based Event Delivery

The underlying source may run continuously, but agent delivery is pull-based.
The descriptor's `events` capability accepts an
`AgentLiveSessionReadRequest` with an optional prior sequence plus event and
byte limits and a bounded `wait_timeout_ms`. A zero wait is non-blocking; an
otherwise empty batch reports `timed_out: true` when its protocol wait expires.
The existing session call timeout remains the outer bound;
`agent session start`, `status`, `wait`, and `cancel` remain the asynchronous
control path.

Each `AgentLiveSessionEventEnvelope` contains:

- protocol version and a positive, strictly increasing sequence;
- observation time and `data`, `progress`, `state`, content-free `heartbeat`,
  `warning`, `error`, or `end` kind;
- a schema-checked payload and exact serialized byte count;
- an optional bounded cursor;
- redaction status; and
- terminal-source state.

An individual payload is capped at 256 KiB. Withheld or failed-closed events
carry no payload. A returned `AgentLiveSessionEventBatch` is capped by the
caller's event limit and the generic 1 MiB session-output ceiling. It also
reports the next sequence, latest resumable cursor, source-closed state,
explicit sequence-bound checkpoint, oldest retained sequence, truncation and
timeout state, dropped event/byte counts, coalesced events, and reconnect
attempts. `resume_cursor` remains the protocol-v1 compatibility projection of
the checkpoint cursor.

## Buffer, Reconnect, And Resume Rules

The authoritative plugin queue is always bounded. Version 1 permits up to
10,000 events and 8 MiB retained per session, while the common default is 2,000
events or 2 MiB. Overflow is explicit:

- `drop_oldest` preserves the newest diagnostic context;
- `drop_newest` preserves a paused historical window; or
- `coalesce` replaces superseded metrics or state snapshots.

Every batch discloses losses. Plugins must not hide dropped or coalesced data in
a status string.

The default delivery mode is `bounded_buffer`. A `source_paced` contract instead
advances its target only while serving a bounded read and is invalid if it
reports dropped, coalesced, or truncated data. Resumable data/search workflows
may also require an opaque resource-scope fingerprint and declare heartbeat and
source-idle bounds; see
[Data and Search Agent Live-Session Contract](data-search-agent-live-session-contract.md).

Reconnect policy is `never`, `transient`, or `always`, with at most 32 attempts
and backoff capped at 60 seconds. Authentication, authorization, RBAC, and
validation failures are not transient. Resume is one of:

- `unsupported`: close or reopen without claiming continuity;
- `restart`: reconnect from a documented fresh position;
- `best_effort_cursor`: duplicates or gaps remain possible and visible; or
- `exact_cursor`: the target guarantees continuation from the accepted cursor.

Cursor kinds are byte offset, event ID, resource version, timestamp, or opaque.
Cursor values are bounded agent-facing control data and never audit fields.
When the target rejects or compacts a cursor, the plugin emits a state event and
records `rejected` or `restarted`; it never silently claims exact continuity.

## Cancel And Close

The existing generic broker lifecycle remains authoritative:

- cancel addresses one caller-owned call ID and may stop only that wait or both
  the wait and its source, as declared;
- close addresses one session ID plus generation and stops observation,
  detaches remote work, or terminates remote work, as declared;
- close outranks cancel, shutdown outranks close, and terminal call state is
  immutable; and
- cancel, close, lease expiry, revocation, and shutdown are bounded and
  idempotent.

A close that may terminate remote work cannot be classified as a read-only
start. Cleanup must remain possible after grant-use exhaustion, so close itself
does not consume another data-operation use or require a second authorization.

## Standard Audit Projection

`AgentLiveSessionAuditSummary` contains only:

- protocol, operation kind, resource type, and optional opaque fingerprint;
- start risk and lifecycle state;
- start/finish timestamps;
- delivered, dropped, and coalesced event/byte counters;
- reconnect count and resume outcome; and
- redaction status.

There is intentionally no field for raw resource identity, cursor value, log or
console content, exec command/stdin, Kubernetes YAML, target error body, local
listener address, URL, token, cookie, crumb, or decrypted profile data. Plugins
may attach this projection to their normal agent-session audit records, but may
not add those forbidden values as ad hoc metadata.

## Infrastructure Mapping

The currently registered session-only capability families are:

| Plugin | Capability family |
|---|---|
| Docker | `docker.logs_follow`; `docker.stats_follow`; `docker.events_follow`; `docker.exec_read` + `docker.exec_input` + `docker.exec_resize` + `docker.exec_signal`; `docker.attach_read` + `docker.attach_input` + `docker.attach_resize` |
| Kubernetes | `kubernetes.watch_events`; `kubernetes.logs_follow`; `kubernetes.exec_read` + `kubernetes.exec_input` + `kubernetes.exec_resize`; `kubernetes.port_forward_events` |
| Jenkins | `jenkins.console_follow`; `jenkins.build_wait`; `jenkins.queue_watch` |

Each family must be granted and opened as the complete capability list returned
by generic discovery. The session-open envelope fixes the target resource,
command, filters, or ports before a plugin creates any remote handle. Exec,
attach, and port-forward starts require a destructive-capable grant and a
per-open `--yes`, even when the event-reading member of the family is itself
read-only.

| Plugin workflow | Kind and resource | Buffer/overflow | Resume | Start/control risk |
|---|---|---|---|---|
| Docker log follow | `log`, container | 2,000 events or 2 MiB, drop oldest | best-effort timestamp | read-only; close stops observation |
| Docker stats | `metrics`, container | bounded snapshots, coalesce | restart | read-only; close stops observation |
| Docker daemon events | `events`, daemon plus filters | 2,000 events or 2 MiB, drop oldest | best-effort timestamp | read-only; close stops observation |
| Docker exec/attach | `exec`/`attach`, container | 1,000 events or 1 MiB, drop oldest | unsupported | external side effect; close declares detach or terminate |
| Kubernetes watch | `watch`, API resource and namespace | 2,000 events or 2 MiB, drop oldest/coalesce | exact resource version until target rejection | read-only; close stops observation |
| Kubernetes pod logs | `log`, namespace/pod/container | 2,000 events or 2 MiB, drop oldest | best-effort timestamp | read-only; close stops observation |
| Kubernetes exec | `exec`, namespace/pod/container | 1,000 events or 1 MiB, drop oldest | unsupported | external side effect; close terminates the channel |
| Kubernetes port-forward | `port_forward`, pod/service | bounded state events | restart only through a new generation | external side effect; close releases listener and tunnel |
| Jenkins progressive console | `progressive_output`, job/build | 5,000 events or 5 MiB, drop oldest | exact byte offset when accepted | read-only; close stops polling, never aborts the build |
| Jenkins build wait | `wait`, job/build | bounded state events, coalesce | restart from target state | read-only; close stops polling |
| Jenkins queue tracking | `queue`, queue item | bounded state events, coalesce | restart from target state | read-only; close stops polling |

Plugin implementations may choose smaller bounds or stricter reconnect rules.
They may not exceed the Core caps, weaken start-risk classification, omit loss
counters, or reinterpret generic cancel/close priority.
