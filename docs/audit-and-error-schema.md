# Audit and Structured Error Schema

This document defines the capability-first audit and error contract for VoidB.
It complements the connection model and the secret brokering policy:

- [Capability Core Model](capability-core-model.md) defines profiles,
  runtime instances, and invocations.
- [Secret Brokering and Redaction Policy](secret-brokering-redaction-policy.md)
  defines what may cross agent and plugin boundaries.
- [Agent-Friendly Execution Controls](agent-friendly-execution-controls.md)
  defines timeout, cancellation, pagination, streaming, dry-run, destructive
  operation, and exit-code behavior.

The Rust schema types live in `crates/voidb-core/src/capability.rs` and are
re-exported from `voidb_core`.

## Goals

The schema must make every capability invocation observable without exposing
plaintext secrets or unredacted diagnostics. It must also give agents stable
error categories that support retries, policy handling, and target-specific
failure reporting.

The schema is intentionally narrow. It defines the record shape and stable
categories. The current implementation persists a local rotating
newline-delimited JSON audit stream under the VoidB data directory and exposes
it through `voidb-cli audit list --format json` and
`voidb-cli audit export --format json`, with aggregate triage through
`voidb-cli audit summary --format json` and redacted reproduction bundles
through `voidb-cli audit bundle --format json`. This local backend is the
first storage abstraction, not the final sync policy.

## Current Local Audit MVP

The current implementation records redacted events for:

- `profile list`
- `profile show` / `profile inspect`
- `profile test`
- `profile migrate`
- `invoke run`
- credential grant lifecycle events emitted by `invoke run`
- governed team-share invite, import-plan, revoke, and credential
  re-enrollment activity records

Audit entries store stable operation names, status, actor attribution, profile
references, plugin and capability IDs, invocation IDs when allocated, duration,
credential grant IDs, credential references, structured errors, and redacted
metadata. Raw invocation input and decrypted `plugin_config` are not persisted;
invocation inputs are summarized by JSON shape and field names only.

The CLI query/export command supports filters for operation, actor ID, actor
type, profile, plugin, capability, invocation ID, credential grant ID,
credential reference ID, policy decision outcome, policy reason code, error
category, error code, redaction status, status, and RFC3339 time ranges. The
local file is created with private permissions on Unix-like systems.

## Local Retention and Export

The default local audit store writes `events.jsonl` and rotates it when the
current file would exceed 5 MiB. Up to five rotated files are retained as
`events.jsonl.1` through `events.jsonl.5`; older rotated files are removed
during rotation. Tests can override this policy through `AuditRetentionPolicy`.

Queries read the current file and retained rotated files, sort events by newest
timestamp first, and support opaque page tokens in the `offset:<number>` form.
The stable JSON response for `audit list` and `audit export` uses the same
agent-facing envelope style as the other CLI command groups:

```json
{
  "ok": true,
  "schema_version": 1,
  "command": "audit",
  "data": {
    "events": [],
    "page": {
      "next_page_token": null
    },
    "export": {
      "generated_at": "2026-07-04T20:00:00Z",
      "source_files": [],
      "event_count": 0,
      "filters": {
        "operation": "capability_invoke",
        "actor_id": "agent:test",
        "actor_type": "agent",
        "policy_outcome": "requires_acknowledgement"
      }
    }
  },
  "warnings": []
}
```

The `data` object for `audit list` and `audit export` includes:

- `events`: matching audit events.
- `page.next_page_token`: token for the next page when more events match.
- `export.generated_at`: export generation timestamp.
- `export.source_files`: local files and byte sizes included in the query.
- `export.event_count`: number of returned events.
- `export.filters`: normalized filter criteria used for the query.

Useful agent-facing query examples:

```bash
voidb-cli audit list \
  --operation capability_invoke \
  --status blocked \
  --actor-type agent \
  --policy-outcome requires_acknowledgement \
  --format json

voidb-cli audit export \
  --plugin redis \
  --capability set \
  --error-category target_system \
  --redaction applied \
  --since 2026-07-04T00:00:00Z \
  --format json
```

`audit summary` uses the same filters and envelope, but returns aggregates
instead of raw event records. It is the preferred first query for agents that
need to triage a large audit window without exposing event details:

```bash
voidb-cli audit summary \
  --operation capability_invoke \
  --since 2026-07-04T00:00:00Z \
  --format json
```

The summary `data.summary` object contains:

- `event_count`: number of matching events included in the summary.
- `status_counts`, `operation_counts`, `plugin_counts`, and
  `capability_counts`: stable count pairs.
- `error_category_counts` and `error_code_counts`: structured failure counts
  without target-system messages.
- `policy_outcome_counts`: counts by serialized policy decision outcome.
- `latency`: count, min, max, and integer average duration in milliseconds for
  events that recorded `duration_ms`.
- `security_signals`: explicit categories with counts and up to five sample
  audit event IDs.

Security signal categories are intentionally coarse and redacted:

- `policy_block`: blocked policy or permission outcomes, including denied
  destructive operations and acknowledgement/approval-required policy
  decisions.
- `approval_attention`: approval-required, expired, revoked, or otherwise
  approval-related policy reasons.
- `credential_attention`: credential errors, unavailable credential sync
  records, and credential re-enrollment handoff events.
- `redaction_failure`: events whose redaction state failed closed.

`audit bundle` uses the same filters and envelope, but packages a bounded
event excerpt with the matching summary and export metadata for support or bug
reproduction:

```bash
voidb-cli audit bundle \
  --operation capability_invoke \
  --status failed \
  --limit 50 \
  --format json
```

The bundle lives at `data.bundle` and includes:

- `schema_version`: support-bundle schema version.
- `generated_at`: bundle generation timestamp.
- `voidb`: CLI package version and target platform.
- `audit.events`: matching redacted audit events.
- `audit.summary`: the same aggregate shape returned by `audit summary`.
- `audit.page`: pagination metadata for the event excerpt.
- `audit.export`: source files, event count, generation timestamp, and filters.
- `redaction`: applied redaction statement, guarantees, and excluded data
  classes.

Support bundles inherit the audit-store redaction contract. They must not
include plaintext credentials, decrypted connection configuration,
authorization headers, cookies, raw invocation input, raw output, or
unredacted target-system diagnostics. They are intended to be shareable
diagnostic artifacts, not complete forensic archives.

### Optional TUI Audit Viewer Decision

VoidB does not ship a separate TUI audit viewer in this slice. The CLI JSON
contract above is the authoritative agent and support surface for now.

A future TUI audit viewer should be a thin read-only adapter over the same
query, summary, and bundle primitives rather than a second audit backend. It
should support filter entry, list/detail navigation, summaries, and bundle
generation; respect shell raw-input boundaries; and never render data that is
excluded from the support-bundle redaction contract.

Credential grant lifecycle events use these operation names:

- `credential_grant_issued`
- `credential_grant_used`
- `credential_grant_released`

Grant events record `grant_id`, `invocation_id`, profile, plugin, capability,
credential refs, and outcome status. They do not store plaintext credential
material, raw invocation input, raw output, decrypted `plugin_config`, or
connection URLs.

Persistent agent session lifecycle events use these operation names:

- `session_open`
- `session_call`
- `session_status`
- `session_list`
- `session_renew`
- `session_cancel`
- `session_close`

Session events record the opaque grant, Profile ID, plugin, session ID,
generation, public caller-owned call ID when applicable, selected broker
protocol version, purpose, qualified capability, duration, remaining uses,
grant expiry, outcome status, and stable error code. They never store the broker
token, master password, decrypted profile configuration, session open or call
input, target output, stdout/stderr, or live-handle metadata. Call IDs are
validated as bounded public identifiers before they may enter audit metadata.
The event is marked `applied` redaction even when no secret was present so
support tooling can distinguish the deliberate session audit projection from
raw plugin results.

Asynchronous `start` records one `session_call` event when the call reaches a
terminal state. Call-level `status` and bounded `wait` requests use
`session_status`; their audit records include the public call ID but never the
retained result. `session.call_id_conflict`, `session.call_not_found`, and
`session.aborted` distinguish duplicate ownership, lookup failure, and
higher-priority close/shutdown without placing call input or output in the
error or audit envelope. A client wait timeout is returned in data as
`wait_timed_out: true`; it is not misclassified as a call timeout.

Governed team-share events use these operation names:

- `team_share_invite_created`
- `team_share_invite_accepted`
- `team_share_import_planned`
- `team_share_import_blocked`
- `team_share_access_revoked`
- `team_share_credential_reenrollment_required`

Team-share events record opaque collection, invite, member, and revocation
target IDs plus counts for profiles, unavailable profiles, credential
re-enrollments, and blocked imports. They do not store profile aliases, plugin
IDs, hostnames, usernames, bucket names, database names, credential labels,
credential values, target-system diagnostics, or `sync.toml` device state.

## Invocation Audit Record

An invocation audit record is written for every accepted capability invocation,
including invocations that fail validation, policy checks, connection setup,
plugin execution, or target-system execution.

Required fields:

- `invocation_id`: stable invocation identifier.
- `actor`: resolved human, agent, or system attribution.
- `plugin_id`: plugin selected for the invocation.
- `capability_id`: capability command selected on that plugin.
- `connection`: the invocation connection target.
- `timing`: request, start, completion, duration, and timeout metadata.
- `status`: invocation lifecycle result.
- `redaction`: whether redaction was needed, applied, withheld, or failed
  closed.

Optional and defaulted fields:

- `profile`: resolved profile ID or alias when one is known.
- `credential_refs`: credential reference IDs and classes used for brokering.
- `grant_id`: credential grant identifier when the invocation reached
  credential brokering.
- `input_summary`: redacted input metadata, such as schema name, field names,
  validation shape, row limits, or redacted field names.
- `output_summary`: redacted output metadata, such as row count, object count,
  stream frame count, or affected row count.
- `error`: structured error details when the invocation did not succeed.

Audit records must not contain plaintext passwords, tokens, API keys, private
keys, passphrases, decrypted `plugin_config`, signed URLs, authorization
headers, cookies, or unredacted plugin diagnostics.

## Timing Metadata

The `InvocationTiming` fields are:

- `requested_at`: when Core accepted or began validating the request.
- `started_at`: when plugin or target execution started.
- `completed_at`: when the invocation reached a terminal status.
- `duration_ms`: completed duration in milliseconds when known.
- `timeout_ms`: requested or effective timeout in milliseconds when applicable.

Timing fields are audit metadata, not scheduling guarantees. A validation or
policy failure may have `requested_at` and `completed_at` without `started_at`
because plugin execution never began.

## Invocation Status

Stable status values:

- `accepted`: Core accepted the request and has not started execution yet.
- `running`: execution is in progress.
- `succeeded`: execution completed successfully.
- `failed`: execution reached a terminal failure.
- `cancelled`: execution was cancelled by the caller or Core.
- `timed_out`: execution exceeded the effective timeout.

Failed invocations must include a `CapabilityError` unless the failure happened
while constructing the audit record itself. Timeout and cancellation may also
include an error when useful to explain which boundary timed out or cancelled.

## Structured Error Shape

`CapabilityError` fields:

- `category`: stable machine-readable error category.
- `code`: stable error code suitable for CLI and protocol output.
- `message`: redacted human-readable summary.
- `details`: redacted structured details.
- `target`: target-system failure details when the error came from the remote
  database, service, host, or API.
- `retryable`: whether retrying the same invocation may reasonably succeed.
- `redaction`: redaction status for the error payload.

The `code` should be stable within a category. Examples:

- `validation.schema_mismatch`
- `credential.missing`
- `permission.denied`
- `transport.connection_refused`
- `timeout.target`
- `plugin.crashed`
- `target.syntax_error`

Codes may be plugin-specific when the category is stable and documented.

## Stable Error Categories

The category vocabulary is fixed for agent-facing behavior:

| Category | Use |
|---|---|
| `validation` | Input did not match a schema, required field, range, or type. |
| `auth` | Target-system authentication failed after credentials were granted. |
| `permission` | VoidB policy or caller permission denied the invocation. |
| `credential` | Credential reference was missing, expired, incompatible, or unavailable. |
| `policy` | Non-auth policy blocked execution, such as destructive-operation approval. |
| `transport` | Network, pipe, socket, TLS, DNS, or process transport failed. |
| `timeout` | Core, plugin, or target execution exceeded its timeout. |
| `cancellation` | Caller or Core cancelled the invocation. |
| `plugin` | Plugin crashed, returned malformed protocol data, or violated its contract. |
| `target_system` | The remote database, service, host, or API rejected the operation. |
| `conflict` | Requested state conflicts with current state, locks, or versions. |
| `unavailable` | Required plugin, service, profile, or target is temporarily unavailable. |
| `internal` | VoidB Core failed unexpectedly. |

Agents should branch on `category` first, then on `code`. Human-facing messages
may change, but categories and documented codes must remain stable across minor
releases.

## Target-System Failures

Target failures describe errors returned by the remote system, not by VoidB
Core. They belong in `CapabilityError.target` with these fields:

- `system`: target system identifier, such as `postgres`, `mysql`, `redis`,
  `ssh`, `s3`, or a plugin-defined service name.
- `code`: redacted target error code, SQLSTATE, HTTP status, errno, or provider
  code when available.
- `message`: redacted target message when it is safe to expose.

Target messages are diagnostics and must be redacted before they are placed in
CLI output or audit records. If a target message may contain submitted secrets,
connection strings, signed URLs, or authorization material, Core should replace
the message or withhold it.

## Redaction Status

Stable redaction values:

- `not_required`: no sensitive field was present in this payload.
- `applied`: sensitive fields were detected and redacted.
- `withheld`: a field or diagnostic was omitted because it could not be safely
  represented.
- `failed_closed`: redaction could not be applied confidently, so Core returned
  or stored only a generic safe error.

When redaction cannot be applied confidently, `failed_closed` is preferred over
leaking a partially redacted diagnostic.

## Example

```json
{
  "invocation_id": "invoke-02",
  "actor": {
    "id": "agent:test",
    "actor_type": "agent"
  },
  "plugin_id": "postgres",
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
  "timing": {
    "requested_at": "2026-07-04T00:00:00Z",
    "started_at": "2026-07-04T00:00:00Z",
    "completed_at": "2026-07-04T00:00:02Z",
    "duration_ms": 2000,
    "timeout_ms": 30000
  },
  "status": "failed",
  "profile": {
    "kind": "name",
    "value": "prod-db"
  },
  "credential_refs": [
    {
      "id": "cred-01",
      "class": {
        "kind": "password"
      }
    }
  ],
  "input_summary": {
    "schema": "query-input",
    "fields": ["sql"],
    "redacted_fields": ["sql"]
  },
  "output_summary": null,
  "error": {
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
  },
  "redaction": "applied"
}
```

## Invariants

- Every audit record has actor attribution.
- Every terminal failed invocation has a stable error category and code.
- Target failures use `target_system` and put target-specific data under
  `target`.
- Error messages and details are redacted before CLI output, logs, traces, or
  audit persistence.
- Credential references may be recorded; plaintext credential material may not.
- Agents rely on `category`, `code`, `retryable`, and `status`, not on message
  text.
