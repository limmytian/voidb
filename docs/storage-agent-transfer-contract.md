# Storage Agent Transfer Contract

This document defines the shared machine-readable transfer lifecycle for S3
and WebDAV. The S3 and WebDAV plugins now implement the contract through
plugin-owned `FileTransfer` sessions registered by the Agent broker.

The shared Rust types live in `voidb_core::transfer`. S3 and WebDAV publish
driver-free policy mappings through `s3_transfer_contract()` and
`webdav_transfer_contract()`. Capability discovery publishes structured
session handoff metadata; stateless invocation of session-only operations
still fails closed.

## Ownership boundary

The owning plugin service keeps every live or sensitive value:

- S3 clients, multipart upload IDs, completed-part ETags, request signing,
  provider endpoints, bucket/key identities, and open local files stay in the
  S3 crate.
- WebDAV clients, lock tokens, cookies, authorization headers, server URLs,
  range negotiation, remote paths, and open local files stay in the WebDAV
  crate.
- Local staging handles and resume records remain bound to the plugin service,
  exact Agent principal, profile, capability, local-path grant, and session
  generation.

Core, the shell, generic discovery, CLI JSON, TUI service events, audit data,
and Task Weaver comments may contain only schemas, opaque IDs and fingerprints,
bounded counters, stable policy codes, and redaction state. They never contain
raw local paths, bucket names, remote paths, URLs, multipart IDs, lock tokens,
signed URLs, credentials, object bodies, or driver handles.

## Static backend contract

`AgentTransferContract` declares:

- protocol version and a public target class;
- upload, download, server-side copy, and safe move composition;
- single-request, byte-range, and multipart chunk modes;
- checksum and target-identity algorithms;
- fail, skip, and explicitly authorized replacement policy;
- source match, destination absence/match, and WebDAV lock preconditions;
- bounded retry attempts and exponential-backoff ceilings;
- unsupported, best-effort, or exact resume behavior;
- required local path access modes; and
- bounded cancellation and failure cleanup actions.

Contract validation fails closed when a backend omits an authority needed by
its declared behavior. In particular:

- upload requires `read_file` local-path authority;
- download requires `create_file` authority;
- local replacement requires `replace_file` in addition to explicit overwrite
  input, destructive policy, and per-call acknowledgement;
- resume requires `resume_transfer`, an expiring opaque token, and a one-way
  resource-scope fingerprint;
- multipart failure must abort remote partial state or retain a bound resume
  checkpoint; and
- a lock-token workflow must release the lock during cancellation cleanup.

Absolute local path disclosure is invalid in every contract.

## Backend mapping

Both plugins map to protocol version 1 and the same operation, conflict, local
path, progress, retry, cancellation, cleanup, and event shapes.

| Concern | S3 | WebDAV |
|---|---|---|
| Target class | `s3_object` | `webdav_resource` |
| Chunking | Single request, byte range, multipart; at most 10,000 chunks and 16 in flight | Single request and byte range; at most 10,000 chunks and 8 in flight |
| Identity/checksum | SHA-256, MD5, ETag | SHA-256, ETag, WebDAV Digest |
| Resume claim | Exact only while source, destination, multipart state, grant, and preconditions still match | Best effort after range/capability probing; gaps or restart are explicit |
| Resume lifetime | At most 24 hours | At most 1 hour |
| Retry | At most 5 retries, 250 ms to 30 s backoff | At most 4 retries, 250 ms to 30 s backoff |
| Cancellation | Remove local staging and abort remote partial work | Remove local staging, abort partial work, and release any owned lock |
| Failure | Remove unsafe staging; retain only a scope-bound checkpoint | Remove unsafe staging; retain only a scope-bound checkpoint; release owned locks |

The exact S3 resume claim does not mean every provider guarantees indefinite
multipart continuity. It is valid only inside the declared token lifetime and
while the service can prove the same upload, source, destination, completed
part set, local grant, actor, profile, capability, and target preconditions.
Any mismatch is `conflict.local_resume_mismatch` or a more specific redacted
target conflict, never a silent restart.

WebDAV uses best-effort resume because range writes, partial uploads, ETag
behavior, and lock support differ between servers. Capability probing is part
of preparation. Unsupported behavior falls back only to a fresh, explicitly
reported transfer; it never reuses a stale token or claims exact continuity.

## Portable lifecycle event

`AgentTransferEvent` is the common payload for Agent live-session events, CLI
JSON/stream output, and plugin service events consumed by TUIs. It contains:

- `transfer_id`: opaque and bounded, scoped to one transfer generation;
- a positive monotonically increasing `sequence` and UTC observation time;
- operation and lifecycle phase;
- bytes, objects, and chunks completed plus optional totals;
- optional current chunk range and completion state;
- optional scoped resume checkpoint;
- optional whole-transfer, object, or chunk checksum state;
- bounded retry attempt, backoff, and stable reason code;
- conflict policy and resolution without source or destination values;
- local staging, remote partial, and remote lock cleanup state;
- terminal and redaction state.

The shared JSON Schema is returned by `agent_transfer_event_schema()`. Runtime
validation adds invariants that JSON Schema cannot express: backend limits,
resume binding, totals, monotonic progress, legal phase transitions, retry and
conflict policy matching, and settled terminal cleanup.

Example progress event:

```json
{
  "protocol_version": 1,
  "transfer_id": "transfer:opaque:7",
  "sequence": 12,
  "observed_at": "2026-07-24T16:00:00Z",
  "operation": "download",
  "phase": "transferring",
  "progress": {
    "bytes_completed": 8388608,
    "bytes_total": 33554432,
    "objects_completed": 0,
    "objects_total": 1,
    "chunks_completed": 2,
    "chunks_total": 8
  },
  "current_chunk": {
    "index": 2,
    "offset": 4194304,
    "length": 4194304,
    "completed": true
  },
  "terminal": false,
  "redaction": "not_required"
}
```

## Phase state machine

The portable phases are:

1. `planned`
2. `awaiting_authorization`
3. `queued`
4. `preparing`
5. `transferring`
6. optional `paused`, `conflict`, or `retry_waiting`
7. `verifying`
8. `committing`
9. optional `cancelling`
10. `cleaning_up`
11. terminal `completed`, `cancelled`, or `failed`

Plugins may omit phases that do not apply, but may not move backward, escape a
terminal state, change the transfer ID or operation, reduce verified progress,
or change a known total. Retry returns to preparation or transfer. Conflict
resolution may return to preparation/transfer, continue to commit for an
authorized replacement, skip the item, or fail. Cancellation always reaches a
settled terminal cleanup result within the contract timeout.

The `terminal` field exactly matches a terminal phase. A completed event must
satisfy every known byte, object, and chunk total and cannot retain a resume
checkpoint. A terminal cleanup report cannot contain `pending`.

## Progress and multipart state

Byte totals may be absent when the target does not supply a reliable size.
Object and chunk totals follow the same rule. Consumers render an indeterminate
state when a total is absent; they must not invent a percentage.

The current chunk is identified by a one-based index, byte offset, non-zero
length, and completion state. Full provider part maps remain plugin-owned. An
opaque checkpoint records only the safe completed-byte/chunk counters, expiry,
and a `sha256:` scope fingerprint; the token carries provider state without
exposing it. Checkpoints never claim progress beyond the current event.

S3 multipart completion verifies the accepted part set and final target
identity. WebDAV range resume verifies the observed server capability,
destination identity, and accepted range before advancing the checkpoint.

## Retry, conflict, and preconditions

Retry metadata is valid only in `retry_waiting`. The reason is a stable,
lowercase code such as `unavailable.target` or `timeout.transfer`; it is not a
raw target error. Authentication, authorization, invalid input, checksum
mismatch, changed source identity, expired grant, and incompatible resume state
are not blindly retried.

Upload and download calls may provide `expected_sha256`. The value is exactly
64 hexadecimal characters and applies only to whole-transfer upload/download
verification. Upload verifies local bytes before target mutation and verifies
the committed remote bytes before reporting success. Download verifies all
assembled bytes before creating the local destination. COPY/MOVE reject this
field instead of silently ignoring it.

An interrupted multipart or ranged request enters `retry_waiting` with a
redacted `target_unavailable` reason and an expiring, scope-bound checkpoint.
The plugin retains only the state needed for an explicit resume. A subsequent
call must still prove the same binding, target identity, chunk geometry, and
resource size; otherwise it fails with a binding conflict.

No-overwrite is the default. `fail`, `skip`, and `replace` have matching
machine-readable resolutions. Replacement requires the capability policy,
local path grant where applicable, validated `overwrite=true`, and explicit
acknowledgement. Source and destination fingerprints or ETags are checked again
at commit. A stale precondition becomes a conflict rather than a write against
a replacement object.

S3 move is server-side copy followed by conditional source delete only after
the destination is verified. WebDAV COPY/MOVE preserve Destination, Overwrite,
If-Match/If-None-Match, Depth, and lock-token semantics inside the service.

## Cancellation and cleanup

Cancel addresses the current transfer generation. It stops new chunk work,
requests cancellation of in-flight I/O, and enters `cancelling` or
`cleaning_up`. Close, grant revocation, lease expiry, plugin shutdown, and
process shutdown use the same bounded cleanup path.

Cleanup reports three independent classes:

- local staging: not applicable, pending, removed, retained for resume, or
  failed closed;
- remote partial state: not applicable, pending, aborted, retained for resume,
  or failed closed; and
- remote lock: not applicable, pending, released, or failed closed.

A failed cleanup remains an explicit terminal failure with redacted diagnosis.
It is never reported as a successful cancellation. Cleanup does not consume a
new operation-grant use, but it cannot broaden authority or start new target
work.

## Local path binding and redaction

Every local endpoint follows [Local Path Authorization Policy](local-path-authorization-policy.md).
The resume token is bound to the exact actor, grant, profile, capability,
canonical source/destination fingerprint, remote object fingerprint, expected
size, completed range, and expiry. A caller cannot select or recover the raw
staging path.

Agent output and audit contain an opaque local scope ID, counters, lifecycle
state, policy codes, and redaction status only. Relative names require a
separate disclosure grant; absolute roots, submitted local paths, staging
paths, home/volume names, object keys, remote paths, URLs, and tokens never
appear in the portable event.

## Availability and validation

S3 publishes `buckets`, native continuation-token `list`, verified `copy` and
`move`, bounded `presign`, plus session-only `transfer` and `transfer_status`.
The session supports bounded multipart upload, byte-range download, scoped
resume tokens, cancellation checkpoints, destination verification, and
cleanup on close.

WebDAV publishes `probe`, conditional `copy` and `move`, plus session-only
`transfer`, `transfer_status`, `lock_acquire`, and `lock_release`. The session
keeps lock tokens private, returns opaque lock references, releases owned locks
on close, and uses byte ranges only when the server advertises and honors
them. Unsupported partial upload and range behavior is reported explicitly.

The direct storage CLI transfer commands expose `human`, `json`, and `ndjson`
lifecycle views and treat Ctrl-C as a cancellation with fail-closed remote
state. Standalone TUI service events carry the same redacted lifecycle,
overwrite is explicit, retry is available after failure, and network work
remains in channel-mode background tasks.

Focused checks for contract changes:

```bash
cargo test -p voidb-core transfer
cargo test -p voidb-plugin-s3
cargo test -p voidb-plugin-webdav
cargo test -p voidb-cli storage_plugins_map_to_one_fail_closed_transfer_lifecycle
scripts/check-local-filesystem-boundaries.sh
scripts/check-external-agent-interaction.sh
git diff --check
```

Run the live reliability proofs with:

```bash
scripts/s3-fixture-smoke.sh \
  --report target/tmp/s3-transfer-reliability.md
scripts/webdav-fixture-smoke.sh \
  --report target/tmp/webdav-transfer-reliability.md
```

The S3 wrapper proves provider discovery, prefix-marker pagination, no-overwrite
conflicts, server-side copy/move, expired presigns, SHA-256 mismatch rejection,
multipart cancellation/resume, exact byte round-trip, and retained multipart
cleanup on close. The WebDAV wrapper proves conditional COPY/MOVE against
rclone, SHA-256 mismatch rejection, byte-range cancellation/resume, stale lock
isolation, lock release on close, exact byte round-trip, and explicit
unsupported-feature degradation.
