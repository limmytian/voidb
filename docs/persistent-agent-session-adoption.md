# Persistent Agent Session Adoption

This inventory is the Requirement 85 baseline for moving from the descriptor-only
session lifecycle introduced by Requirement 51 to grant-scoped, persistent agent
execution. It distinguishes semantic state that agents may deliberately continue
from ordinary transport or HTTP client pooling.

## Current Boundary

The long-lived agent authorization broker owns the generic session host,
grant/Profile binding, leases, cancellation, call serialization, and opaque
session references. Each registered factory keeps its protocol handles inside
the owning plugin service or worker. Core and grant files retain only bounded,
secret-free descriptors; revocation and broker shutdown close all hosted
sessions without moving driver handles into shared state.

One-shot `profile test` and `invoke run` requests still execute in scoped child
processes. Semantic continuation instead uses `agent session open/call/start`
with a `session_only` or `both` grant.

## Adoption Matrix

The classification values are:

- **required**: user-visible semantic state is part of Requirement 85 acceptance;
- **useful**: a real session exists, but it is not needed to prove the foundation;
- **stateless**: pooling is an implementation detail and must not become an agent
  session; and
- **deferred**: the plugin has state, but exposing it through this contract would
  mix a separate lifecycle or product boundary into Requirement 85.

| Plugin or component | Semantic persistent state | Current live-handle owner and concurrency | Required cleanup | Classification and delivery slice |
|---|---|---|---|---|
| Connection Manager | Observes profile and registry metadata; it owns no protocol continuation state. | Shell capability registry; UI event loop only. | Revoke grants and request owner-scoped close without handling drivers. | **stateless**; remain an observer and add visibility in the release slice. |
| SSH | Shell cwd, environment, variables, PTY process, SFTP channel, and forwarding tasks. | `SshService`/`SshSession`; command channel serializes service work, while forwarding owns child tasks. | Close PTY/SFTP/forwards on explicit close, cancellation, lease expiry, revoke, or host exit; reconnect increments generation and never claims shell state survived. | **required**; reference implementation in slice 1. |
| MySQL | Transaction, temporary tables, prepared statements, session variables, and advisory locks. | `MySqlAgentSessionFactory` retains one authenticated `PersistentMySqlConnection` instead of returning it to the pool between calls. | Serialized query/exec, destructive acknowledgement, rollback, disconnect, bounded/redacted rows. | **implemented**; database slice 2. |
| PostgreSQL | Transaction, temporary objects, prepared statements, search path/session variables, advisory locks, and failed-transaction state. | `PostgresAgentSessionFactory` retains one plugin-owned `PostgresService` client and connection task. | Serialized query/exec, explicit failed-transaction rollback, connection-close lock cleanup, bounded/redacted rows. | **implemented**; database slice 2 remote SQL fixture reference. |
| SQLite | In-memory database, attached databases, temporary objects, pragmas, and transaction state. | `SqliteAgentSessionFactory` owns one `SqliteService` `SyncWorker`; the worker thread exclusively holds the `!Send` connection across calls. | Serialized `sqlite.query`/`sqlite.exec`, bounded rows, rollback and worker drop on cancel/close/lease cleanup. | **implemented**; database slice 2. |
| DuckDB | In-memory database, attached state, temporary objects, settings, and transactions. | `DuckDbAgentSessionFactory` owns one `DuckDbService` `SyncWorker`; the worker thread exclusively holds the native connection across calls. | Serialized `duckdb.query`/`duckdb.exec`, bounded rows, rollback and worker drop on cancel/close/lease cleanup. | **implemented**; database slice 2. |
| Redis | Selected DB, WATCH/MULTI state, Pub/Sub subscriptions, redacted MONITOR observation, and blocking Stream reads. | `RedisAgentSessionFactory` keeps transaction state on one `PersistentRedisConnection`; each live-read family owns its native source inside the Redis service. | `DISCARD`/`UNWATCH`, unsubscribe or drop the observation transport, close blocking reads on cancel, and close on lease/revoke. | **implemented** for transactions plus `redis.pubsub_read`, `redis.monitor_read`, and `redis.stream_read`. |
| MongoDB | Driver session, transaction and causal state, persistent find/aggregate cursor, and change-stream resume state. | `MongoAgentSessionFactory` retains one `ClientSession` for transaction actions; live cursor services own driver cursors/change streams and expose only bounded events and scoped tokens. | Abort transactions, kill/drop cursors and change streams, split resumable from terminal errors, and drop the client/session on cancel/close/topology error. | **implemented** for transactions, causal `run_command`, `mongodb.cursor_read`, and `mongodb.change_stream_read`. |
| Email | IMAP selected mailbox, sequence/UID context, IDLE, and long-lived mailbox observation. POP3 command reuse alone is not semantic. | Current agent capabilities perform bounded mailbox operations and expose no IDLE/selected-mailbox handle. | Future process protocol 1.1 handle must exit IDLE, close the mailbox, and stop workers. | **deferred/fail-closed** until an IMAP IDLE capability exists; ordinary mail calls remain stateless. |
| Docker | Exec/attach processes, log/stats/event streams, and their cursors. Ordinary API client reuse is not semantic. | `DockerAgentSessionFactory` retains Bollard streams, bounded event buffers, exec IDs, and terminal I/O controls inside the Docker service. | Stop observation; detach attach sessions; terminate and verify controlled exec cleanup; abort readers; disclose drops/coalescing. | **implemented** for logs, stats, events, controlled exec, and attach; ordinary snapshots remain stateless. |
| Kubernetes | Exec channels, logs/watch streams, and port-forward tasks. Ordinary API client reuse is not semantic. | `K8sAgentSessionFactory` retains kube watch/log readers, attached processes, resize channels, and loopback listener/tunnel tasks inside the Kubernetes service. | Cancel watches, close exec channels, release listener/tunnels, reap tasks, and report resource-version restart. | **implemented** for watch, logs, controlled exec, and loopback-only port-forwarding; ordinary snapshots remain stateless. |
| Jenkins | Progressive console cursor, build-wait lifecycle, and queue transition state. Crumb or HTTP client caching alone is not semantic. | `JenkinsAgentSessionFactory` retains the authenticated client plus bounded polling task and exact progressive byte offset. | Stop polling without aborting target builds, preserve accepted offsets across retry, and classify terminal build/queue outcomes. | **implemented** for console follow, build wait, and queue tracking. |
| Elasticsearch | Point-in-time and scroll IDs with server-side expiry. Ordinary HTTP client reuse is not semantic. | `EsAgentSessionFactory` and the Elasticsearch service own PIT/scroll handles; Agent output receives bounded hits, partial-shard events, and opaque continuation only. | Close PIT, clear scroll, tolerate expiry/reopen where declared, reject scroll resume across generations, and drop the source on cancel/close. | **implemented** as `elasticsearch.search_stream_read`; ordinary snapshots remain stateless. |
| S3 | Multipart upload ID, completed part set, and long transfer cancellation. Ordinary SDK client reuse is not semantic. | The driver-free S3 mapping now uses the shared storage transfer contract, but current agent operations still expose no multipart handle or part continuation. | The owning service must abort incomplete uploads, cancel I/O, remove unsafe staging, and retain only scope-bound resume state. | **contract defined, execution deferred/fail-closed**; ordinary object operations remain stateless until the capability/service slice registers a real factory. |
| WebDAV | WebDAV lock token and long transfer continuation. Ordinary HTTP reuse is not semantic. | The driver-free WebDAV mapping now uses the shared storage transfer contract, but current agent operations still expose no lock or resumable handle. | The owning service must unlock, cancel I/O, remove unsafe staging, and retain only scope-bound resume state without path leaks. | **contract defined, execution deferred/fail-closed**; ordinary requests remain stateless until the capability/service slice registers a real factory. |
| Sync | Device authorization, compatibility negotiation, conflict state, and sync transactions belong to the dedicated sync protocol rather than a connection-profile capability session. | Sync `ops`, client/server, and its own `Session`; concurrency and recovery are already protocol-specific. | Existing logout, token expiry, conflict, and client/server shutdown paths. | **deferred**; do not wrap Sync in the agent session host during Requirement 85. |
| External process plugins | Any semantic state declared by a plugin, including streams or transactions. | Protocol 1.1 keeps one kill-on-drop child runtime alive; SDK methods map opaque plugin handles to host-bound sessions. | Protocol cancel/close, plugin lease enforcement, kill-on-drop crash cleanup, 4 KiB secret-free descriptors, and explicit protocol 1.0 stateless fallback. | **implemented** contract and SDK in slice 3. |

## Host Invariants

All adoption work follows these invariants:

1. An opaque session reference is bound to one agent grant, immutable Profile ID,
   plugin, purpose, capability scope, and host generation.
2. The host keeps plugin services alive, but core and grant files keep only
   secret-free descriptors. Passwords, tokens, configuration secrets, live
   clients, and driver handles stay in process memory at their existing owner.
3. Calls are serialized by default. Multiplexing requires an explicit plugin
   declaration and cannot weaken cancellation or output bounds.
4. Lease expiry never exceeds grant expiry. Use exhaustion, revoke, cancellation,
   broker failure, and normal process shutdown request bounded plugin cleanup.
5. Destructive policy and acknowledgement are evaluated for every call, not only
   when the session opens.
6. Reconnect changes the session generation and reports state loss. It never
   silently presents a new transport as the old transaction, shell, cursor, or
   stream.
7. Audit records contain opaque identity, lifecycle, policy, timing, and bounded
   result metadata only. They never contain target output or credential material.
