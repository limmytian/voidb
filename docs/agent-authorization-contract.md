# Unified Agent Authorization Contract

This document records the Requirement 86 authorization contract and its
implemented capability normalization. It defines the frontend-safe boundary
used by the central broker, CLI, Connection Manager, built-in plugins, and
process-plugin manifests.

Requirement 87 extends this baseline with interactive requests, local review,
structured/exact scopes, and immutable grant revisions. See
[Just-in-Time Agent Authorization](jit-agent-authorization.md) for the current
interactive workflow. The proactive preset contract below remains supported for
automation and backward compatibility.

## Ownership Boundary

Connection Manager is the single human authorization surface. The CLI broker is
the single grant store and enforcement boundary. Plugins may declare capability
risk, streaming behavior, semantic session purposes, and recommended preset
membership. Plugins must not persist grants, evaluate grant policy, render an
authorization screen, or infer destructive consent from launching a plugin.

Every grant remains bound to one immutable Profile ID and plugin. An empty
capability list means no capabilities, never all capabilities. Grant creation,
replacement, and renewal must receive an exact capability list after preset
resolution. Batch review may create several grants in one local CLI workflow,
but it never creates a cross-profile grant.

## Presets

| Preset | Meaning | Consent |
|---|---|---|
| Read-only | Exact capabilities whose effective risk is `read_only`. This is the recommended default. | No destructive grant acknowledgement. |
| Interactive/Execute | A plugin-declared, narrow set needed for a real semantic session or command workflow. It is not an alias for every destructive capability. | Explicit destructive acknowledgement when any selected capability requires it; each destructive call is acknowledged again. |
| Full access | Every capability in the plugin's catalog at authorization time, persisted as an exact snapshot. Capabilities added later are not inherited. | `--allow-destructive --yes` when any selected capability requires it; each destructive call is acknowledged again. |
| Custom | An exact user-selected subset of the catalog. | Derived from the selected capability risks. |

No preset overrides a capability declaration with
`capability_wide_allowed=false`. Such a capability may appear in a catalog or
exact preset snapshot, but an agent execution must also present a structured or
exact JIT scope. This is used by local-filesystem capabilities so a broad
read-only or Full access grant cannot choose a local root.

Unsupported profiles have no agent-ready capability catalog. Deferred profiles
have a catalog or protocol-specific workflow, but not a safe central grant path
yet. Both states are rendered explicitly and cannot issue an empty or wildcard
grant.

## Frontend-Safe State

The shared Rust contract lives in
`crates/voidb-core/src/agent_authorization.rs`. A profile summary contains only:

- immutable Profile ID, display name, and plugin ID;
- supported, deferred, or unsupported state with a user-facing reason;
- broker health (`online`, `starting`, `offline`, or `stale_socket`);
- one optional scoped grant projection and active session count; and
- the refresh timestamp.

The public grant projection contains scope, preset, destructive consent, issue
and expiry timestamps, optional remaining uses, broker health, and active
session count. `remaining_uses: null` means time-only access. It cannot contain
a broker token, socket path, master password, decrypted configuration, or
credential material.

The public JIT request projection contains a required, reviewable `purpose`
alongside the principal fingerprint, immutable Profile ID, plugin, scope, risk,
status, request expiry, and optional decision reason. The purpose participates
in request deduplication, so a changed intended use cannot inherit an earlier
explanation. A request that reaches its TTL while pending is persisted as
`denied` with `timed_out: true`; approve, deny, and cancel paths recheck the
deadline while holding the request lock. The compatibility reader accepts the
legacy JSON key `reason`, but new output and CLI guidance use `purpose`.

Grant usability is classified in fail-closed order: expired, exhausted, stale
socket, broker offline, expiring, then active. `starting` is visible broker
health but remains usable only when the central service has positively verified
the broker. The default expiring window is two minutes.

## Bundled Capability Audit

The audit used the machine-readable `voidb-cli invoke list --format json`
catalog from commit `639e8ef`. It contained 104 capabilities across 14 generic
invoke plugins and classified them as `read_only` or `destructive`. The table is
that audit snapshot. Subsequent hardening classifies `ssh.sftp_get` as
`mutating`, adds streaming/session capabilities, and uses scoped-only
authorization for local filesystem operations rather than silently widening
presets.

| Plugin | Catalog (RO / destructive) | Semantic session support | Preset decision and granularity finding |
|---|---:|---|---|
| SSH | 5 / 5 | Implemented: terminal, SFTP, forwarding | Read-only excludes local-writing `ssh.sftp_get`. Interactive/Execute selects `ssh.exec` only. SFTP get/put require an exact local root/path JIT scope; other SFTP writes and forwarding stay Custom. |
| MySQL | 4 / 1 | Implemented: query and transaction | Read-only plus narrow Execute=`mysql.exec`; SQL text still receives per-call policy. |
| PostgreSQL | 4 / 1 | Implemented: query and transaction | Read-only plus narrow Execute=`postgres.exec`; SQL text still receives per-call policy. |
| SQLite | 4 / 1 | Implemented: query and transaction | Read-only plus narrow Execute=`sqlite.exec`; SQL text still receives per-call policy. |
| DuckDB | 4 / 1 | Implemented: query and transaction | Read-only plus narrow Execute=`duckdb.exec`; SQL text still receives per-call policy. |
| Redis | 6 / 4 | Implemented: connection state, transactions, Pub/Sub, MONITOR, and Streams | `redis.ttl` is read-only and TTL mutation is isolated in destructive `redis.expire`. The externally visible `redis.monitor_read` is counted separately from RO/destructive and, with `redis.exec`, remains Custom. |
| MongoDB | 9 / 6 | Implemented: driver transaction, persistent cursor, and change stream | `run_command` and `bulk_write` are intentionally broad destructive surfaces. Transactional writes remain Custom; no default Execute preset yet. |
| Email | 5 / 0 | IMAP selected-mailbox/IDLE deferred | Read-only supported. Send/mutation is absent, so Interactive/Execute is unavailable. |
| Docker | 7 / 1 | Exec/attach/follow handles deferred | `container_action` conflates start, stop, restart, pause, unpause, and remove. Keep it Custom until split. |
| Kubernetes | 6 / 4 | Exec/attach/watch/port-forward deferred | Existing apply/delete/restart/scale are Custom; no interactive capability exists. |
| Jenkins | 6 / 3 | Progressive console/build-wait deferred | Trigger, abort, and queue cancellation are distinct but not interactive; keep Custom. |
| Elasticsearch | 9 / 2 | Implemented: PIT/scroll search streaming | `raw_api` and `bulk` are destructive Custom surfaces; streamed search remains scoped read-only. |
| S3 | 4 / 3 | Multipart/transfer continuation deferred | Put/mkdir/delete remain Custom; no interactive session preset. |
| WebDAV | 4 / 3 | Locks/resumable transfers deferred | Put/mkdir/delete remain Custom; no interactive session preset. |
| Sync | no generic invoke catalog | Dedicated sync protocol owns its session | Deferred by product boundary; do not wrap Sync in the agent grant broker. |

Process plugins are evaluated from their manifests at runtime. Missing risk or
session metadata fails closed to Custom-only, and protocol 1.0 plugins remain
stateless. Connection Manager itself is an observer and authorization frontend,
not an agent capability plugin.

## Capability Authorization Metadata

Every `CapabilityDefinition` now carries `authorization` metadata:

- `declared` proves the plugin reviewed the capability for central grants;
- `interactive_execute` opts one exact capability into that narrow preset;
- `session_purposes` describes semantic terminal, transfer, transaction, cache,
  or infrastructure usage; and
- `note` records a bounded or deferred behavior without changing policy.

Requirement 87 additionally uses `approval_schema` and
`capability_wide_allowed`. Schema fields are non-secret normalized-input JSON
pointers with Core-enforced exact, prefix, subset, or maximum semantics. Plugins
declare labels and enforcement metadata only; Core owns review rendering,
narrowing validation, persistence, policy, and audit. Missing, secret-bearing,
unknown-version, or incompatible schemas fail closed.

The password-free `voidb-cli agent catalog` groups definitions into shared
plugin catalogs and builds execution-mode-bounded presets centrally. Read-only
contains reviewed read-only definitions supported by the selected transport.
Interactive/Execute contains only explicitly opted-in definitions. Full access
captures every current capability supported by the selected grant mode as an
exact list, never a wildcard. Custom exposes exact selection across that same
boundary. `stateless` and `session_only` projections include dual-transport
capabilities; the `both` projection is an explicit combined grant. A missing
declaration disables the centrally derived presets and leaves Custom only; Sync
is reported as deferred with no generic presets.

Grant files and frontend-safe projections persist `execution_mode`. The broker
rechecks both the grant mode and the current capability declaration on every
one-shot or session call. Legacy grants default to `stateless`; they cannot gain
session authority during deserialization. JIT `agent exec` authorization also
remains stateless-only. A session-only operation returns the descriptor's
secret-free handoff commands and requires a separately reviewed proactive
session grant.

Process-plugin manifests accept the same optional object. Older manifests
deserialize with `declared=false`, so an upgrade cannot silently broaden agent
access. SDK authors opt in explicitly with
`CapabilityBuilder::authorization(...)`; semantic purposes use the serialized
`{ kind = "..." }` form (and `value` for `plugin_defined`).

Connection Manager consumes the catalog metadata rather than maintaining a
plugin-ID allowlist. The selected preset is persisted with the grant and is
visible in frontend-safe lifecycle projections. Broker queries remain keyed by
immutable Profile ID and plugin, probe liveness without a master password, and
count only grant-bound live sessions.
