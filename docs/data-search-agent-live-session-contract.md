# Data and Search Agent Live-Session Contract

This document defines how Redis, MongoDB, and Elasticsearch map cursor and
stream workflows onto VoidB's shared Agent live-session protocol. The bundled
plugins now advertise the capabilities listed below and register native
live-session factories. Shared deterministic conformance and disposable
Redis, MongoDB replica-set, and Elasticsearch fixture gates are available
through `scripts/check-data-search-live-session-conformance.sh`.

The shared Rust types live in `voidb_core::live_session`. Infrastructure
plugins use the same protocol; their currently supported families and defaults
are recorded in [Infrastructure Agent Live-Session Contract](infrastructure-agent-live-session-contract.md).

## Ownership and handle boundary

The owning plugin service keeps every driver value and target handle:

- Redis connections, Pub/Sub streams, MONITOR connections, and blocking-read
  state stay in the Redis crate.
- MongoDB clients, sessions, cursors, change streams, BSON resume tokens, and
  transaction state stay in the MongoDB crate.
- Elasticsearch HTTP clients, PIT IDs, scroll IDs, search-after state, and bulk
  request state stay in the Elasticsearch crate.

Core, the shell, generic discovery, audit records, and Agent JSON output may
contain only schemas, bounded envelopes, opaque control tokens, counters, and
redacted state. They never contain a Rust driver object, pointer, connection,
raw BSON value, authentication material, or reusable target client.

## Discovery contract

`CapabilitySessionHandoff.live_session` carries
`AgentLiveSessionContract` protocol version 1. Data and search families use the
existing resource, start-parameter, event-schema, operation, reconnect, buffer,
and control declarations plus `delivery`:

```json
{
  "backpressure": "source_paced",
  "cursor_scope": "required",
  "heartbeat": {
    "interval_ms": 5000,
    "idle_timeout_ms": 20000
  },
  "max_read_wait_ms": 20000
}
```

The delivery field is optional for protocol-v1 compatibility. Its default is
`bounded_buffer`, optional cursor scope, no heartbeat, and a 30-second maximum
read wait. New resumable data/search families use a required scope fingerprint
and choose backpressure explicitly.

Malformed schemas, capabilities outside the handoff family, incompatible
cursor settings, invalid heartbeat bounds, and unsafe start-risk declarations
fail before a target handle is opened.

## Cursor identity and resume tokens

An `AgentLiveSessionCursor` contains:

- a generic kind: byte offset, event ID, resource version, timestamp, or
  opaque;
- a bounded token of at most 1,024 bytes; and
- an optional `sha256:` resource-scope fingerprint with a complete 64-digit
  hexadecimal digest.

The token is agent-facing control data, not an audit field. A plugin may encode
native continuation data into an opaque token, but it must not expose a driver
object or credential. When `cursor_scope` is `required`, every event cursor and
`resume_from` token includes a one-way scope fingerprint. The plugin computes
that fingerprint from the fixed session resource and rejects a token whose
scope does not match. The fingerprint never substitutes for the profile,
grant, session ID, or generation checks performed by the broker.

Resume behavior remains one of:

- `unsupported`: reject `resume_from`;
- `restart`: reopen from a documented fresh position without continuity;
- `best_effort_cursor`: attempt the token while exposing possible duplicates,
  gaps, expiry, or compaction; or
- `exact_cursor`: claim exact continuation only while the target guarantees it.

Rejected, expired, compacted, or target-invalid tokens produce a typed state or
terminal error. A plugin never silently falls back from exact continuation.

## Sequence, checkpoints, and truncation

Every event has a positive session-local sequence. Sequences increase even
when a bounded buffer drops or coalesces an event; they restart for a new
session generation and are never a cross-session cursor.

Each returned batch may contain an `AgentLiveSessionCheckpoint` pairing a safe
resume cursor with the sequence that produced it. `resume_cursor` remains the
protocol-v1 compatibility projection of the same cursor. Consumers persist the
checkpoint only after accepting the batch and pass only its cursor back through
the next session's `resume_from` field.

`oldest_available_sequence` identifies the front of the retained window.
`truncated` is true whenever the requested window contains a missing or
coalesced sequence. `dropped_events`, `dropped_bytes`, and `coalesced_events`
remain cumulative diagnostics. A consumer must not infer continuity merely
because `next_sequence` advanced.

Checkpoint semantics are source-specific but use the same envelope:

- Redis Streams use the last accepted stream entry ID.
- MongoDB change streams use a bounded opaque resume token, including an empty
  batch's post-batch token when the driver declares it safe.
- Elasticsearch cursor searches use a plugin-owned opaque continuation token
  that binds PIT/scroll/search-after state to the resource scope and expiry.

## Heartbeats and idle timeout

`AgentLiveSessionEventKind::Heartbeat` is content-free, non-terminal, and may
carry a checkpoint cursor. A contract that emits heartbeats declares both an
interval from 250 milliseconds through 60 seconds and a larger idle timeout no
greater than five minutes. Heartbeats obey the same sequence and buffer bounds
as other events.

The plugin service owns heartbeat scheduling and idle detection. Source
traffic or a valid heartbeat resets its source-idle timer. Missing the declared
idle deadline produces a retryable reconnect transition when policy permits;
otherwise the plugin closes the source with a typed timeout. Heartbeats never
hide authentication, authorization, validation, cursor-rejection, or target
errors.

## Pull timeout and retry

Agent delivery is pull-based. `AgentLiveSessionReadRequest` contains:

- optional `after_sequence`;
- bounded event and byte limits; and
- `wait_timeout_ms`, capped by the discovery descriptor and by the protocol
  maximum of 30 seconds.

An omitted value uses the protocol default and is clamped to the descriptor's
smaller cap; an explicit larger value is likewise clamped. Zero is a
non-blocking poll. When the wait expires without an event, a loss
transition, or source closure, the batch is empty with `timed_out: true`.
Retrying the same request is safe. A source close, truncation, or available
event wins a timeout race and is returned normally. Broker call timeout and
caller-owned cancellation remain outer bounds and may end the call before the
protocol wait expires.

## Backpressure

The descriptor chooses one of two modes:

- `bounded_buffer`: a producer may run ahead only into the declared event and
  byte bounds. Its `drop_oldest`, `drop_newest`, or `coalesce` overflow policy
  is visible through sequences, truncation, and counters.
- `source_paced`: the plugin advances the target cursor only while serving a
  bounded read. It must not prefetch into an unbounded queue, and its batches
  may not report dropped or coalesced events.

Redis Pub/Sub and MONITOR are producer-driven and therefore use a bounded
buffer. Blocking Redis Stream reads, MongoDB cursor polling, and Elasticsearch
cursor pages can use source pacing. Plugins may choose stricter bounded-buffer
behavior when a native API requires a background reader, but may never claim
source pacing after losing data.

## Cancel, close, and cleanup

The generic broker lifecycle is authoritative:

- cancel addresses one caller-owned call ID; `call_only` stops the current
  wait, while `call_and_source` also stops its stream;
- close addresses the exact session ID and generation, is idempotent, and
  declares `stop_observation`, `detach_remote`, or `terminate_remote`;
- close outranks cancel, shutdown outranks close, and terminal call state is
  immutable; and
- timeout, cancel, close, grant revocation, lease expiry, and shutdown have
  bounded cleanup.

Closing a data/search session releases its subscription, server cursor, PIT,
scroll, change stream, or blocking operation inside the owning service. Cleanup
does not require another data-operation grant use. Bulk mutations remain
separate acknowledged capabilities and are never smuggled through a read-event
operation.

## Implemented plugin mapping

| Capability and workflow | Shared kind/cursor | Delivery and continuity | Required safety |
|---|---|---|---|
| `redis.pubsub_read` | `subscription`; no resume cursor | bounded buffer, drop oldest, heartbeat/idle timeout | bounded channel and pattern set, reconnect disclosure, cancel/close unsubscribe |
| `redis.monitor_read` | `events`; no resume cursor | bounded buffer, drop oldest, restart-only continuity | per-open external-side-effect acknowledgement, command-name-only projection, no arguments or raw line |
| `redis.stream_read` | `cursor`; event-ID cursor | source paced, scoped best-effort cursor | bounded blocking read, key/group/consumer scope, consumer-group pending-to-new transition, cancel closes source |
| `mongodb.cursor_read` find/aggregate | `cursor`; no cross-generation cursor | source paced, no server-handle resume claim | bounded batch/max-time, cursor kill on drop, query and collection bound to the open handle |
| `mongodb.change_stream_read` | `cursor`; opaque cursor | source paced, scoped exact resume while MongoDB accepts the token, heartbeat | post-batch checkpoint, resumable/non-resumable error split, raw BSON token and session metadata omitted |
| `elasticsearch.search_stream_read` PIT mode | `cursor`; opaque checkpoint | source paced, scoped best-effort `search_after` continuation with expiry | bounded PIT keepalive, PIT reopen on retry, partial-shard events, raw PIT ID omitted and closed |
| `elasticsearch.search_stream_read` scroll mode | `cursor`; no cross-generation resume | source paced with bounded pages | bounded keepalive, clear scroll on cancel/close, partial-shard events, raw scroll ID omitted |

Redis TTL inspection remains read-only. TTL mutation is a distinct mutating
operation and cannot inherit the inspection capability's authorization.

## Compatibility and validation

Protocol version 1 remains readable when older descriptors omit `delivery`,
older cursors omit `scope`, older reads omit `wait_timeout_ms`, and older
batches omit checkpoint, timeout, and truncation fields. New producers emit the
expanded fields and must pass Core validation.

Focused contract coverage lives in `voidb-core` live-session and buffer tests,
plus the Redis, MongoDB, and Elasticsearch plugin suites. The CLI conformance
matrix snapshots every live family and applies the shared slow-consumer,
source-pacing, resume, cancellation, authorization, redaction, audit, and
cleanup invariants. `--live` adds disposable target checks for Redis
Pub/Sub/MONITOR/Streams, MongoDB cursors/change streams/bulk, and Elasticsearch
PIT/scroll/bulk. The recorded 2026-07-24 evidence is in
Data/Search Live-Session Conformance.
