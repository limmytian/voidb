# Persistent Agent Session Release Handoff

Requirement 85 adds grant-scoped persistent execution without moving live
credentials or driver handles into shared metadata. The authoritative bundled
plugin decision table is [Persistent Agent Session Adoption](persistent-agent-session-adoption.md).

## Supported

- SSH shell, SFTP listing, and local TCP forwarding.
- SQLite and DuckDB query/transaction sessions on one `SyncWorker` connection.
- MySQL and PostgreSQL query/transaction sessions on one authenticated connection.
- Redis connection state including selected DB and WATCH/MULTI/EXEC.
- Redis Pub/Sub, redacted MONITOR observation, and blocking Stream reads.
- MongoDB driver transactions and causal `run_command` state.
- MongoDB persistent find/aggregate cursors and resumable change streams.
- Elasticsearch PIT/scroll search streaming with plugin-owned target handles.
- Docker bounded live logs, stats, daemon events, and controlled exec/attach.
- Kubernetes bounded resource watches, pod logs, controlled exec, and loopback-only port-forwarding.
- Jenkins progressive console offsets, build completion waits, and queue-to-build tracking.
- External process-plugin protocol 1.1 session negotiation and lifecycle RPC.

All other bundled capabilities remain stateless. Email IDLE, S3 multipart
continuation, and WebDAV locks still fail closed as sessions until those
plugins declare a bounded live-session contract and expose actual live
handles. S3/WebDAV now have a shared driver-free
[transfer contract](storage-agent-transfer-contract.md), but discovery remains
stateless until their service implementations and factories are complete. The
shared cursor, checkpoint, heartbeat, timeout, and backpressure
rules for the implemented Redis/MongoDB/Elasticsearch families are defined in
[Data and Search Agent Live-Session Contract](data-search-agent-live-session-contract.md).
HTTP client reuse and repeated snapshot polling are not user-visible sessions.

## Operator Workflow

Use `voidb-cli agent session open/call/start/status/wait/list/renew/cancel/close --help`
and the copyable examples in
[Agent Authorization Broker](agent-authorization-broker.md). Connection Manager
continues to show profile metadata only; inspect live sessions with `agent
session list`. Revoking the grant (`agent revoke <grant-id>`) is the emergency
close-all operation and removes private broker runtime artifacts.

## Lifecycle And Performance Budgets

- Open, renew, and call leases never exceed grant expiry.
- Default call output is 64 KiB, hard-capped at 1 MiB; SQL rows cap at 1,000.
- Process-plugin descriptors cap at 4 KiB and reject credential-shaped keys.
- Calls serialize unless a plugin explicitly negotiates safe multiplexing.
- `start` returns before plugin completion; call-level `status` is non-blocking
  and `wait` is capped at 30 seconds per request. The synchronous `call` command
  uses the same lifecycle registry.
- The listener handles clients independently from data-call execution. A
  serialized session has a per-session gate, while status, wait, cancel, and
  close remain responsive during a blocked call.
- A control request can win while a serialized call is still queued. The call
  becomes terminal without entering the plugin driver or waiting for the call
  ahead of it to release the gate.
- Host call timeout requests cancellation; shutdown/close uses bounded waits.
- Agent-broker wire versions 1 and 2 interoperate; version 2 carries explicit
  negotiation and caller-owned call IDs, while missing fields select version 1.
- Cancel defaults to 1 second, close to 5 seconds, and either is capped at 30
  seconds. Cancel timeout escalates to close; close timeout drops the live host
  handle after marking the session failed.
- Repeated cancel/close is idempotent. Control priority is shutdown, then close,
  then cancel, and terminal call state is immutable.
- Exhausting data-operation uses rejects new work but preserves the online
  control path for already accepted calls until revocation or grant expiry.
- Process-plugin children are kill-on-drop and protocol 1.0 falls back to
  stateless invocation with an explicit compatibility error.

## Upgrade Notes

No profile or grant-file migration is required. Existing process plugins using
protocol 1/1.0 continue to work for stateless invocation. Plugins opt into
sessions by declaring protocol 1.1 and returning `session_protocol: "1"` from
initialize. Reconnect or owner replacement increments generation and never
claims prior semantic state survived.

## Validation Evidence

- SSH disposable fixture: shell cwd/environment across calls, SFTP reuse, live
  forwarding, forged framing, cancel/close.
- PostgreSQL disposable fixture: temp object, setting, transaction rollback,
  failed-transaction recovery, advisory lock, credential scan.
- Redis disposable fixture: WATCH/MULTI/EXEC reuse and DISCARD-on-close.
- Deterministic host tests: scope/generation denial, lease expiry, timeout
  cancellation, bounded shutdown, secret-free audit, and runtime cleanup.
- Concurrent Unix-socket broker test: two starts on one serialized session,
  responsive status/list/cancel while the first call is blocked, terminal wait
  results, and a measured maximum driver-call concurrency of one.
- Deterministic race suite: cancel-before-driver-start, cancel-during-I/O,
  close-during-call, broker restart with stale session/call IDs, repeated
  eight-caller duplicate-ID races, exact use reservation, and socket/grant-file
  removal. The broker fixture verifies one cleanup and zero active calls after
  close or shutdown.
- Shared infrastructure conformance: every Docker, Kubernetes, and Jenkins
  live family runs the same slow-consumer/loss, reconnect/resume,
  cancel/timeout, close, authorization denial, redaction, secret-free audit,
  snapshot/live CLI parity, and standalone-TUI fixture gates through
  `scripts/check-infrastructure-live-session-conformance.sh`.
- Shared data/search conformance: Redis, MongoDB, and Elasticsearch run the
  same protocol snapshot, slow-consumer/source-pacing, resume, cancellation,
  authorization, redaction, audit, and cleanup matrix. The optional live tier
  adds disposable Redis, MongoDB replica-set, and Elasticsearch PIT/scroll
  evidence through `scripts/check-data-search-live-session-conformance.sh --live`.
- SQLite and DuckDB file-backed transaction tests verify that both explicit
  cancel and close roll back uncommitted schema changes before a new session
  reopens the database.
- Full workspace test and clippy commands are the final release gate described
  in [CI Checks](ci-checks.md).
