# Plugin Session Capability

This document defines the reusable session capability for plugins that keep
authenticated or stateful target resources alive across operations. It extends
the profile/instance boundary from [Capability Core Model](capability-core-model.md)
without turning the shell into a connection pool.

## Goals

- Give sessionful plugins one lifecycle vocabulary for create, reuse, lease,
  health-check, invalidate, close, and shutdown.
- Let the shell observe and coordinate session descriptors without holding
  database, protocol, storage, or infrastructure driver handles.
- Preserve plugin isolation: each plugin service owns its live connections,
  clients, workers, sockets, channels, and protocol state.
- Keep TUI work non-blocking through channel/service boundaries.
- Keep session metadata secret-free and suitable for audit, support bundles,
  and release readiness reports.

## Non-Goals

- A shared connection pool for all plugins.
- A generic `PluginService` trait.
- Moving driver crates or live handles into `voidb-core`.
- Exposing live driver or protocol handles to agents, other plugins, or the shell.
- Persisting runtime sessions across process restarts. Plugins may persist
  UI restoration state, such as SSH SFTP paths, but not live session state.

## Lifecycle Inventory

| Plugin family | Session need | Reuse boundary | Teardown and health notes |
|---|---|---|---|
| SSH terminal/SFTP/forwarding | Long-lived authenticated SSH handle, PTY channel, optional SFTP worker, forwarding manager, metrics collector. | Same SSH profile can back terminal, SFTP, and tunnel purposes concurrently. Reuse is plugin-owned and purpose-specific. | Ordered shutdown: metrics, forwarding, SFTP, SSH session. Health covers connected, reconnecting, host-key blocked, disconnected, and failed. |
| SQL databases | Short or medium-lived query sessions, optional pools, transactions, search path/session variables, and migration sessions. | Reuse only when transaction state, role, database, schema/search path, and destructive policy are compatible. Mutating and read-only work should not share hidden state unless plugin opts in. | Health is ping or lightweight query. Stale transaction/session state must invalidate reuse. |
| SQLite and DuckDB | Local `!Send` native connections behind `SyncWorker`, plus local file locks and in-memory databases. | Reuse stays inside the owning worker. `:memory:` and temp-file sessions are local-only and must not be shared across unrelated invocations. | Worker drop and explicit close release native handles. Health is worker liveness plus optional lightweight query. |
| Redis | Network connection/client manager, selected DB, scan cursors, optional pub/sub or monitor streams. | Reuse must include DB index, TLS/auth settings, and purpose. Pub/sub or monitor streams should be separate from ordinary commands. | Health is ping or connection liveness. Broken streams invalidate only the affected purpose. |
| S3 and WebDAV | HTTP clients, transfer workers, scratch-directory state, optional sync planning. | Reuse is safe for stateless clients with same profile and endpoint policy. Long uploads/downloads are active leases, not shared sessions. | Cancellation flags close active transfers. Health can be deferred until next request or run as lightweight metadata call when explicitly requested. |
| Docker and Kubernetes | API clients plus optional exec/log/watch streams. | Ordinary list/inspect clients can reuse by profile/context. Exec, logs, and watches are separate streaming sessions. | Health is daemon/cluster reachability. Streaming sessions need explicit cancellation and bounded output policy. |
| MongoDB and Elasticsearch | Authenticated client handles, database/index context, cursors, and optional raw-command sessions. | Reuse by profile plus database/index context and risk policy. Raw/destructive command sessions should not leak state into read-only use. | Health is ping/cluster health. Failed auth or topology changes invalidate matching sessions. |
| Jenkins | HTTP client, crumb/session metadata, queued build actions, and console streaming cursors. | Reuse by profile and Jenkins base URL. Build trigger/abort operations remain destructive and require dry-run or acknowledgement policy. | Health is crumb/auth validation or lightweight job endpoint. Console streams close independently. |
| Sync | Local client/server session state, device auth, sync config, object conflict state, and compatibility-bundle operations. | Sync remains plugin-owned. Hosted/manual server sessions and local disposable config dirs must stay explicit. | Health distinguishes local config availability, auth, server reachability, conflict state, and failed-decrypt/unavailable credentials. |

## Session Descriptor

Core stores descriptors, not handles. A descriptor is safe to list, audit, and
attach to support bundles.

```text
PluginSessionDescriptor
  session_id: opaque stable ID for this runtime session
  plugin_id: owner plugin
  owner_id: plugin-defined owner, such as tab ID, service instance ID, or CLI invocation ID
  profile_ref: optional profile ID or alias ref, never plaintext config
  purpose: standardized purpose plus optional plugin-defined subtype
  scope: local_only | local_process | remote_target | hosted_service
  health: starting | ready | busy | degraded | stale | closing | closed | failed
  authenticated: bool
  destructive_capable: bool
  stream_capable: bool
  created_at, last_used_at, lease_expires_at, closed_at
  generation: monotonically increasing counter for stale-handle detection
  redaction: applied | failed_closed
  metadata: plugin-defined, redacted, bounded JSON object
```

Recommended purposes:

- `interactive_terminal`
- `file_transfer`
- `port_forward`
- `database_query`
- `database_transaction`
- `cache_command`
- `log_stream`
- `watch_stream`
- `infrastructure_client`
- `sync_client`
- `capability_invocation`
- `plugin_defined:<name>`

`metadata` must not contain hostnames, usernames, bucket names, database names,
paths, SQL text, object keys, tokens, passwords, private key paths, ciphertext,
or decrypted `plugin_config` unless the value has an explicit redaction rule in
the owning plugin.

## Lifecycle Operations

The shared capability should provide these operations through
`ShellCapabilities` or an equivalent core service injected into plugin services:

| Operation | Caller | Behavior |
|---|---|---|
| `register(descriptor, close_handle)` | owning plugin service | Registers a descriptor and an owner-only close callback or close command. The live handle stays in the plugin. |
| `acquire(reuse_key, policy)` | owning plugin service | Returns a compatible active session descriptor or asks the plugin to create one. Policies are `never`, `allow`, and `require`. |
| `renew(session_id, lease)` | owning plugin service | Extends an active lease and updates `last_used_at`. |
| `release(session_id)` | owning plugin service | Decrements lease use. A zero-lease session may remain idle until TTL expiry. |
| `update_health(session_id, health, reason)` | owning plugin service | Records state transitions and emits an audit event. |
| `invalidate(session_id, reason)` | owner or shell shutdown | Marks stale/failed and prevents future reuse. |
| `close(session_id, reason)` | owner, shell shutdown, or explicit user action | Requests graceful plugin-owned teardown. It must not block the render loop. |
| `close_owner(owner_id, reason)` | shell/tab manager | Closes sessions owned by a tab or plugin instance during tab close. |
| `list(filter)` | shell/CLI/support tooling | Returns descriptors only, with bounded redacted metadata. |

`reuse_key` should include `plugin_id`, `profile_ref`, `purpose`, `scope`, and
any plugin-defined compatibility fingerprint. It must exclude secrets and raw
target details. Plugins decide whether a descriptor is compatible with their
live state.

## ShellCapabilities Boundary

The session capability may add a field such as `sessions` to
`ShellCapabilities`, but only as a descriptor registry and lifecycle coordinator.
It must not add driver-specific APIs.

Allowed through core:

- descriptor registration and listing;
- lease timestamps and health state;
- owner-scoped close/invalidate requests;
- audit emission of lifecycle events;
- shutdown coordination.

Must remain inside plugin services:

- database pools and native connections;
- SSH `russh` handles, PTY channels, SFTP workers, and forwarding loops;
- Redis clients, pub/sub streams, and selected DB state;
- HTTP clients for S3, WebDAV, Elasticsearch, Jenkins, and Kubernetes;
- Sync client auth/session material;
- all credential material and decrypted profile config.

## Security And Audit Boundary

Session descriptors are redacted by construction. When a plugin cannot prove
metadata is safe, it must set `redaction = failed_closed` and omit the field.

Security flags:

- `scope`: whether the session is local-only, local process scoped, remote
  target scoped, or hosted-service scoped.
- `authenticated`: true when the session has completed target authentication.
- `destructive_capable`: true when the session can mutate target state without
  re-authenticating.
- `stream_capable`: true for PTY, log, watch, transfer, or forwarding sessions.

Audit events should use stable operation names:

- `session.register`
- `session.acquire`
- `session.reuse`
- `session.renew`
- `session.release`
- `session.health`
- `session.invalidate`
- `session.close`
- `session.shutdown`

Audit fields:

- actor and actor type when available;
- `session_id`, `plugin_id`, `owner_id`, `purpose`, `scope`, and `health`;
- optional profile ref, credential grant IDs, and policy decision references;
- reason code such as `ttl_expired`, `owner_closed`, `health_failed`,
  `tab_closed`, `app_shutdown`, `target_disconnected`, or
  `incompatible_reuse`;
- duration and timeout metadata for close/shutdown attempts.

Audit output must not include plaintext passwords, tokens, private key paths,
raw SQL, message bodies, object keys, hostnames/usernames unless explicitly
redacted, decrypted config, sync passwords, KEK/DEK material, or session-local
file paths.

## Error Contract

Session lifecycle errors should map to structured target or plugin errors:

| Code | Meaning |
|---|---|
| `session.not_found` | Descriptor does not exist or is already closed. |
| `session.stale` | Descriptor generation no longer matches the live owner state. |
| `session.owner_unavailable` | Owning plugin instance or service is gone. |
| `session.incompatible_reuse` | A required reuse policy could not find a compatible session. |
| `session.health_failed` | Health check failed and the session was degraded or invalidated. |
| `session.close_timeout` | Graceful close did not complete before deadline. |
| `session.control_timeout` | Cancel did not complete before its deadline and close escalation was requested. |
| `session.call_id_invalid` | Caller-owned call ID is empty, oversized, or contains non-public characters. |
| `session.call_id_mismatch` | Plugin response did not echo the caller-owned call ID exactly. |
| `session.call_id_conflict` | That session generation already owns the public call ID. |
| `session.call_not_found` | No call with that ID belongs to the requested session generation. |
| `session.aborted` | Close, shutdown, or recovery ended the call before a result could be returned. |
| `session.protocol_unsupported` | Requested local agent-broker protocol version is unsupported. |
| `session.policy_denied` | Policy prevented reuse or close request. |
| `session.redaction_failed` | Descriptor metadata failed closed and was omitted. |

## Shutdown Requirements

Shell shutdown and tab close must be ordered and bounded:

1. Stop accepting new leases for the owner being closed.
2. Send plugin-owned close commands for each active session.
3. Wait up to a small grace period for graceful teardown.
4. Mark remaining sessions `failed` or `closed` with `close_timeout`.
5. Drop plugin services and runtime tasks without blocking the render thread.

Plugins that own background tasks should still implement `Drop` defensively.
The shared registry is coordination, not a substitute for service cleanup.

## Implementation Status

`voidb-core` provides the descriptor and registry types through
`ShellCapabilities.sessions`. The registry supports:

- registering and listing redacted descriptors;
- compatible reuse and incompatible reuse;
- stale generation rejection;
- explicit close and owner close;
- TTL expiry and health transitions;
- shutdown cleanup;
- audit event shape and redaction guarantees.

The SSH plugin is the first in-repo reference consumer. Its channel-mode service
maps terminal, SFTP, and forwarding lifecycles onto descriptors while preserving
the existing service boundary:

- terminal PTY: `interactive_terminal`, remote target scope, authenticated,
  destructive-capable, stream-capable;
- SFTP worker: `file_transfer`, remote target scope, authenticated,
  destructive-capable, stream-capable;
- port forwarding: `port_forward`, remote target scope, authenticated,
  destructive-capable, stream-capable.

SSH close callbacks send existing service commands and do not expose `russh`
handles through core. Path-only SFTP session persistence remains separate from
runtime descriptors.

## Persistent Agent Execution Contract

Requirement 85 adds an agent-facing continuation contract without changing the
Requirement 51 ownership boundary. `voidb-core` now defines:

- `AgentSessionRef`, an opaque session ID plus generation used for stale-state
  rejection;
- `AgentSessionBinding`, which immutably binds a session to a grant, Profile ID,
  plugin, purpose, capability scope, and host generation;
- typed open, synchronous call, asynchronous start/call-status/wait, session
  status/list, renew, cancel, and close request envelopes;
- agent-broker protocol versions 1 and 2, where omitted version fields select
  legacy version 1 and version 2 adds explicit negotiation;
- caller-owned, validated call IDs known before execution begins;
- `AgentSessionView`, `AgentSessionCallView`, bounded structured call results,
  and a bounded wait result that distinguishes client wait timeout from call
  timeout;
- serialized-by-default versus explicitly multiplexed concurrency; and
- `PluginAgentSessionFactory` / `PluginAgentSession`, the plugin-owned live
  handle API used by a persistent host.

Session leases are positive and capped at grant expiry. Generic structured
output defaults to 64 KiB and may never exceed 1 MiB; a plugin must paginate,
stream through a bounded protocol, or fail with `session.output_limit` rather
than emit partial JSON. Call results carry an explicit redaction status; withheld
or failed-closed results cannot include a payload. Reconnection changes
generation and sets continuity to
`reconnected_state_lost`; callers must reopen semantic state instead of assuming
that a shell, transaction, cursor, subscription, or stream survived.

The agent contract adds stable errors for binding mismatch, expiry,
cancellation, unsupported operations, and output bounds. The existing
`PluginSessionDescriptor`, registry, lease, and close callback APIs remain
source-compatible.

Infrastructure and other continuously producing sessions build on this broker
lifecycle through the versioned
[Infrastructure Agent Live-Session Contract](infrastructure-agent-live-session-contract.md).
`CapabilitySessionHandoff.live_session` exposes a bounded resource/start/event
descriptor in generic discovery. Session open validates that descriptor and its
start envelope, including per-open acknowledgement when starting the source has
side effects. Call cancel and session close continue to use the lifecycle below;
plugins retain every target stream and buffer handle.

### Call And Control Lifecycle

The shared lifecycle projection uses these monotonic states:

| State | Terminal | Meaning |
|---|---:|---|
| `accepted` | no | The host reserved the caller-owned call ID. |
| `running` | no | Plugin execution began. |
| `cancel_requested` | no | A cancel, close, or shutdown request won the control race. |
| `succeeded` | yes | Output passed bounds and redaction checks. |
| `failed` | yes | Validation, plugin, or target execution failed. |
| `cancelled` | yes | Explicit cancel won before terminal completion. |
| `timed_out` | yes | The data-call deadline elapsed. |
| `aborted` | yes | Close, shutdown, owner loss, or recovery ended the call. |

Control priority is `shutdown > close > cancel`. Repeating the same or a lower
priority control is idempotent; a higher priority request escalates without
restarting cleanup. Once terminal, a late result or control request cannot
change the state. The lifecycle object contains only the public call ID and
timestamps—never input, output, credentials, or target metadata.

Cancel and close requests carry optional deadlines. Defaults are 1 second and
5 seconds respectively, with a 30-second hard maximum. Cancel timeout escalates
to close; close timeout releases the live handle and records failure so the
plugin's defensive drop path owns final socket, worker, transaction, process,
or tunnel cleanup.

The local broker owns the call registry. `start` reserves the ID and returns an
`accepted` or already-running view without waiting for output. Call-level
`status` snapshots that registry; `wait` uses notification rather than holding
the driver lock and returns after terminal state or a 30-second maximum client
wait. The synchronous `call` path uses the same registry and waits internally.

Driver-facing calls execute outside the broker state lock. Serialized sessions
share one per-session gate, so queued work cannot overlap, while controls and
registry reads do not acquire that gate. A close/shutdown marks matching calls
before plugin cleanup and aborts queued/running broker tasks after bounded close;
a late successful plugin result therefore cannot overwrite `aborted`.
