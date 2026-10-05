# Capability Core Model

This document defines the first capability-first domain slice for VoidB. It
turns the planning language from the ADR into concrete model boundaries that
the new CLI, plugin protocol, and process-plugin work can share.

The goal of this slice is narrow: distinguish saved connection profiles,
runtime connection instances, and capability invocations. Secret brokering and
redaction are defined separately in
[Secret Brokering and Redaction Policy](secret-brokering-redaction-policy.md).
Audit fields and structured errors are defined in
[Audit and Structured Error Schema](audit-and-error-schema.md). Audit storage
is follow-up work. Process plugin manifest details are defined in
[Plugin Manifest Schema](plugin-manifest-schema.md). Migration compatibility
risks are tracked in
[Migration Compatibility Notes](migration-compatibility-notes.md).

## Model Summary

```text
ConnectionProfile
  stable saved profile owned by VoidB Core
  referenced by ID or alias
  contains non-secret metadata, credential references, defaults, and policy

ConnectionInstanceDescriptor
  observable descriptor for a plugin-owned runtime instance
  created from one profile for one purpose
  never contains the plugin's live socket, pool, session, or client handle

CapabilityInvocation
  one structured request to run one plugin capability
  may be stateless, may use a profile, or may target an existing instance
  carries schema-validated input plus execution controls

CapabilityPolicyRequest / CapabilityPolicyDecision
  one machine-readable policy evaluation shape
  carries risk, redacted reasons, scoped approvals, and acknowledgement state
```

The Rust types live in `crates/voidb-core/src/capability.rs` and are re-exported
from `voidb_core`.
The agent-facing profile command contract is defined in
[Connection Profile CLI Contract](connection-profile-cli.md).
Timeout, cancellation, pagination, streaming, dry-run, destructive operation,
and exit-code behavior are defined in
[Agent-Friendly Execution Controls](agent-friendly-execution-controls.md).

## Connection Profile

A connection profile is stable saved configuration. Users and agents reference
it by ID or alias. It is not a live connection and it is not a singleton.

Required profile fields:

- `id`: stable internal profile identifier.
- `alias`: user-facing stable name for CLI usage.
- `plugin_id`: plugin that owns interpretation and execution.
- `metadata`: non-secret plugin-defined profile metadata.
- `default_options`: plugin-defined invocation defaults.
- `credential_refs`: references to brokered credentials, never plaintext
  secrets.
- `policy`: high-level capability allow/deny defaults.

The existing `ConnectionConfig` remains the current persistence shape during
the transition. New capability-first work should treat `ConnectionConfig` as a
legacy storage adapter and converge on `ConnectionProfile` at the public CLI
and protocol boundary.

## Runtime Connection Instance

A runtime connection instance is created from a profile for a specific purpose:

- a SQL query session
- an SSH terminal
- an SFTP browser
- a tunnel
- a background worker
- a pool member

The `ConnectionInstanceDescriptor` is only an observable descriptor. Plugins
own the actual runtime lifecycle, pooling, worker threads, reconnection, and
cleanup. Core should not hold plugin driver handles or assume that a profile
maps to a singleton runtime connection.

One profile can back multiple instances at the same time. For example, one SSH
profile can produce a terminal instance, an SFTP instance, and a tunnel
instance concurrently. One database profile can produce separate read-only and
migration sessions.

## Capability Invocation

A capability invocation is one structured request to run one capability:

- `plugin_id`: plugin that exposes the capability.
- `capability_id`: capability command, such as `query`, `exec`, `get`, or
  `list`.
- `connection`: how the invocation relates to profiles and instances.
- `input`: JSON input validated against the capability schema.
- `controls`: timeout, cancellation token, dry-run, streaming, and pagination.
- `controls.acknowledgement`: optional explicit caller acknowledgement such as
  CLI `--yes`; this is audit evidence, not permission.
- `controls.approval_refs`: optional references to previously issued scoped
  approvals.
- `actor`: optional human, agent, or system attribution.
- `requested_at`: request time for audit and timeout calculations.

Invocation connection targets are intentionally explicit:

- `stateless`: no profile or runtime instance is required.
- `from_profile`: use a profile and a reuse policy.
- `existing_instance`: target a known runtime instance.

The `from_profile` target carries an `InstanceReusePolicy`:

- `never`: create a fresh runtime instance for this invocation.
- `allow`: reuse a compatible instance or create a new one.
- `require`: fail unless a compatible existing instance is available.

This lets a profile create many independent instances while still allowing
plugins to pool or reuse when that is safe.

## Examples

### Multiple SQL Sessions

```text
profile: alias=prod-db, plugin_id=mysql

invocation A:
  capability=query
  connection=from_profile(prod-db, purpose=capability_invocation, reuse=never)
  input={ "sql": "select * from orders limit 50" }

invocation B:
  capability=exec
  connection=from_profile(prod-db, purpose=capability_invocation, reuse=never)
  input={ "sql": "alter table orders add column source text" }
```

Both invocations come from the same saved profile, but the plugin may create
separate runtime sessions so read-only and migration behavior do not share
session state.

### SSH Terminal, SFTP, And Tunnel

```text
profile: alias=prod-shell, plugin_id=ssh

instance A:
  purpose=interactive_session

instance B:
  purpose=other("sftp")

instance C:
  purpose=tunnel
```

All three runtime instances derive from one profile. Closing the terminal must
not implicitly close the tunnel unless the SSH plugin intentionally models them
as one shared session.

### Agent-Friendly Short-Lived Invocation

```text
invocation:
  plugin_id=s3
  capability_id=list_objects
  connection=from_profile(assets, purpose=capability_invocation, reuse=allow)
  controls={ stream=true, timeout_ms=30000 }
```

The S3 plugin can create a short-lived client or reuse a safe pooled client.
The CLI contract remains one structured invocation with NDJSON streaming when
requested.

## Capability Execution Modes

`CapabilityDefinition.execution_mode` distinguishes one-shot operations from
persistent-session operations:

| Mode | Meaning |
|---|---|
| `stateless` | Available through ordinary one-shot invocation. This is the compatibility default for older descriptors. |
| `session_only` | Available only through a persistent Agent Session. |
| `both` | Available through both one-shot invocation and a persistent session. |

Session-capable definitions can attach `session_handoff`, which declares the
shared `PluginSessionPurpose` and fully qualified capability set used to open a
session. This metadata is discovery guidance only; authorization and session
binding still fail closed through the existing grant and policy checks.

The current built-in session-aware catalog classifies SSH terminal and port
forward operations as `session_only`. SQL `query`/`exec` operations for MySQL,
PostgreSQL, SQLite, and DuckDB, plus `redis.exec`, `mongodb.run_command`,
`ssh.exec`, and `ssh.sftp_list`, are `both`. All other current built-in
capabilities are explicitly `stateless`.

## Capability Risk And Policy

Every `CapabilityDefinition` now has a stable `risk` classification:

| Risk | Meaning | Default policy posture |
|---|---|---|
| `read_only` | Reads metadata or target data without changing target state. | Allowed unless profile or actor policy denies it. |
| `mutating` | Creates or updates target state without destructive semantics. | Requires scoped policy approval before broad use. |
| `destructive` | Deletes, drops, overwrites, or otherwise risks irreversible target change. | Requires scoped approval and explicit acknowledgement unless dry-run policy allows planning only. |
| `external_side_effect` | Triggers externally visible work such as CI jobs, email sending, SSH execution, Docker/Kubernetes operations, or queue changes. | Requires scoped approval and explicit acknowledgement. |

The legacy `destructive` boolean remains serialized for compatibility with the
existing CLI, process-plugin manifests, release smoke, and `--destructive`
filters. Core folds `destructive = true` into `effective_risk() =
destructive` when a capability has not yet declared a more specific `risk`.

Policy evaluation uses these shared shapes:

- `CapabilityPolicyRequest`: input to the policy engine, including actor,
  profile, plugin/capability IDs, effective risk, dry-run status,
  acknowledgement, active approvals, and redacted input summary.
- `CapabilityPolicyDecision`: output from the policy engine, including
  `allow`, `deny`, `requires_approval`, `requires_acknowledgement`, or
  `dry_run_only`, plus a redacted `PolicyReason`.
- `CapabilityApprovalRequirement`: machine-readable scope, risk, TTL, and
  acknowledgement requirement needed to satisfy a decision.
- `ScopedApproval`: issued approval with actor, scope, issued time, optional
  expiry, optional revocation time, and redacted reason.
- `InvocationAcknowledgement`: per-invocation caller acknowledgement, including
  actor, timestamp, optional reason, and optional approval reference.

Approval scopes can target a profile, a profile-bound capability, or one
invocation. Expired or revoked approvals fail closed. Policy reasons are
redacted structured fields; they must not contain plaintext secrets, raw SQL,
object content, command output, tokens, or unredacted target diagnostics.

The policy engine evaluates requests in this order:

1. Profile-level denied capabilities win over every acknowledgement or
   approval.
2. Unsupported dry-run requests fail with
   `validation.dry_run_not_supported`; a plugin must not silently ignore
   `dry_run = true`.
3. `read_only` capabilities are allowed unless denied by policy.
4. Side-effecting capabilities can return `dry_run_only` only when their
   metadata advertises `supports_dry_run = true`.
5. Active scoped approvals must match scope, profile, risk, capability, and
   invocation time. Expired or revoked approvals are ignored.
6. `destructive` and `external_side_effect` capabilities require an explicit
   `InvocationAcknowledgement` for the concrete invocation, even when a scoped
   approval is present.
7. A destructive compatibility flag always raises the effective risk at least
   to `destructive`; a manifest cannot downgrade an actual destructive
   operation by declaring `risk = "read_only"`.

`--yes` is only an acknowledgement. It is audited as
`policy.destructive_invocation_acknowledged` for the current invocation, but it
does not create a reusable permission grant. Reusable policy comes from profile
policy or active scoped approvals.

Plugin authors must keep the declared risk conservative. Any capability that
creates, updates, deletes, overwrites, sends, executes, triggers, or otherwise
changes target-visible state is non-read-only and must declare stable
permission strings. If a plugin advertises dry-run support, the service layer
must prove that it performs validation/planning without mutating target state.

## Invariants

- Agents reference profiles by ID or alias, not by plaintext secrets.
- A profile is saved configuration, not a live connection.
- A runtime instance belongs to a plugin and may outlive one invocation.
- Core may record descriptors and audit metadata, but plugin code owns live
  runtime handles.
- A capability invocation is the unit of CLI execution, timeout, cancellation,
  error reporting, and audit.
- Invocation audit records and structured errors must follow
  [Audit and Structured Error Schema](audit-and-error-schema.md).
- Invocation input and output are JSON values validated by capability schemas.
- Secrets must stay behind credential references and brokering APIs.
- Capability risk, approvals, acknowledgements, and policy decisions are
  machine-readable audit inputs; human prompts are only a presentation layer.
- Agent/plugin data exposure and credential grants must follow
  [Secret Brokering and Redaction Policy](secret-brokering-redaction-policy.md).

## Migration Notes

The current v4 system has these useful foundations:

- `ConnectionConfig` stores plugin-specific config in encrypted
  `plugin_config`.
- TUI plugins already own runtime connection state and service layers.
- CLI plugins already route command execution through per-plugin code.

The capability-first migration should preserve those properties while changing
the public contract:

1. Treat saved `ConnectionConfig` values as storage-backed profiles.
2. Expose profile references through CLI commands without printing secrets.
3. Add capability metadata and schema discovery per plugin.
4. Route `voidb invoke` requests into `CapabilityInvocation`.
5. Let plugins decide instance creation and reuse behind the protocol boundary.

Compatibility requirements for existing configs, TUI workflows, built-in
plugin factories, and service direct mode are detailed in
[Migration Compatibility Notes](migration-compatibility-notes.md).
