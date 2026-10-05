# Just-in-Time Agent Authorization

Requirement 87 makes just-in-time (JIT) authorization the default interactive
workflow. Agents should normally request a reusable, time-bounded scope for
expected follow-up work and let the operator review it in the local CLI.
Proactive grants remain available for known multi-profile work and unattended
automation, while exact one-shot requests remain appropriate for destructive or
uncertain operations.

## Request, Decision, Grant, Revision

These are separate records and must not be conflated:

1. A **request** is a short-lived, secret-free statement of principal, immutable
   Profile ID, plugin, specific intended purpose, risk, and requested scope.
   The purpose is required, shown verbatim during review, and included in the
   request fingerprint so a different use cannot reuse a stale explanation.
2. A **decision** denies the request or approves the same/narrower scope once,
   for bounded time with an optional use limit, or as an addition to the
   principal's logical grant.
3. A **logical grant** is bound to one agent principal, Profile ID, and plugin.
4. A **grant revision** is immutable. Scope additions, TTL extensions, and use
   increases create a new revision; they never silently mutate history.

Execution reloads the current capability declaration, normalizes the operation,
and revalidates capability-wide, constrained, or exact-invocation scope. The
same check runs for stateless calls and persistent session calls. Revocation
closes the broker and its sessions, marks the logical ledger revoked, clears its
effective scopes, and prevents later amendment.

## Principal Isolation

The stable principal consists of `client_id`, `task_id`, and optional
`instance_id`. Its public fingerprint, not the raw identity, appears in review,
grant, revision, and audit projections. Two agents using one SSH profile receive
different logical grants and cannot inspect, consume, amend, or reuse each
other's authority. Profile, plugin, broker-instance, and invocation-fingerprint
substitution also fail closed.

## Agent CLI Workflow

The normal interactive path is a single command:

```bash
voidb-cli agent exec ssh.exec \
  --profile prod \
  --input-json '{"command":"uptime"}' \
  --purpose "Check production uptime while triaging incident INC-42" \
  --yes
```

The facade resolves the profile and plugin, reuses an applicable grant, or
creates one exact request and waits for the local decision. Agent integrations
with their own identity set `VOIDB_AGENT_CLIENT_ID` and
`VOIDB_AGENT_TASK_ID`; Codex tasks are bound automatically through
`CODEX_THREAD_ID`. The request commands below remain the advanced protocol for
callers that need explicit request, polling, cancellation, or constrained-scope
control.

Copy the review command emitted by `agent exec` into a local interactive
terminal:

```bash
voidb-cli agent request review auth-request:<uuid>
```

The command displays the canonical request before prompting for a decision and
reads the master password with terminal echo disabled. The recommended decision
is time-bounded; omitting the optional use limit means the grant is limited only
by expiry. The agent process never receives the password. If the bounded
`agent exec` wait already ended, rerun the original operation after approval so
it can select the activated grant.

An agent creates a request with explicit identity and one scope:

```bash
# Whole capability
voidb-cli agent request create \
  --client-id agent --task-id task-123 \
  --profile id:profile-ssh --plugin ssh --capability ssh.exec \
  --scope capability \
  --purpose "Inspect service health while triaging incident INC-42"

# Structured constraint declared by the plugin
voidb-cli agent request create \
  --client-id agent --task-id task-123 \
  --profile id:profile-ssh --plugin ssh --capability ssh.exec \
  --scope constrained --constraints-json '{"/command":"systemctl status api"}' \
  --purpose "Verify the API service state before restarting the deployment"

# One exact normalized invocation
voidb-cli agent request create \
  --client-id agent --task-id task-123 \
  --profile id:profile-ssh --plugin ssh --capability ssh.exec \
  --scope exact --input-json '{"command":"uptime"}' \
  --purpose "Confirm production uptime for the incident report"
```

The JSON result returns an opaque `auth-request:<uuid>` ID, expiry, deduplication
state, and a copy/paste review command. The command contains only the opaque ID;
copying it never approves anything.

Agents may use `get`, `list`, bounded `wait --timeout-ms`, or `cancel` with the
same principal flags. Stable terminal states use these exit codes:

| State | Exit code |
|---|---:|
| approved | 0 |
| pending / bounded wait timeout | 10 |
| denied | 11 |
| request TTL elapsed / automatically denied | 11 |
| expired legacy record | 12 |
| cancelled | 13 |
| superseded after broker restart | 14 |
| broker offline | 15 |
| queue/rate/cooldown limited | 16 |
| invalid request/scope/principal | 17 |
| concurrent decision conflict | 18 |

## Local Review Surfaces

### CLI

Run the broker-provided command in a local interactive terminal:

```bash
voidb-cli agent request review auth-request:<uuid>
```

The CLI is the preferred review surface. It fetches canonical state, displays
the principal fingerprint, profile, plugin, purpose, risk, requested scope, and
expiry, then offers time-bounded (recommended), once, add-to-grant, or deny.
Time-bounded approval prompts for a TTL and accepts an optional use limit;
pressing Enter at the use prompt creates time-only access. Approval may add only
declared non-secret constraints and must remain equal to or narrower than the
request. The master password is read from a hidden controlling TTY and is never
accepted in argv, environment, piped stdin, JSON, audit, or agent-visible
output.

### Connection Manager (secondary)

Open `voidb-cli connections tui`, then press `p`. The non-blocking inbox refreshes
canonical broker state every two seconds, groups requests by principal and
immutable profile, marks stale snapshots, and shows revision history. `Enter`
opens the Core-owned form; `d` opens denial review. The form renders plugin
declarations, supports once/bounded/add-to-grant/deny and optional narrowing,
then requires a second confirmation. Every TUI decision, including denial,
uses the already unlocked local master password through a private stdin pipe to
the local CLI; it never enters the command line, environment, or rendered state.

## Abuse Controls and Recovery

- Pending requests are globally and per-principal bounded.
- Equivalent pending requests with the same purpose deduplicate to one ID.
- Per-principal request rate limits return retry metadata.
- Denied equivalent requests enter a cooldown.
- A pending request whose TTL elapses is atomically persisted as
  `denied` with `timed_out: true`; approval and cancellation recheck the
  deadline under the request lock, so a late decision cannot win the race.
- Timeout denial, cancellation, concurrent decisions, and broker restart have
  stable, audited terminal behavior.
- Request IDs must be UUID-shaped opaque values; traversal and shell-bearing
  strings are rejected before filesystem access.
- Audit records contain fingerprints, IDs, action, binding, scope fingerprint,
  and time only. They omit purposes, decision reasons, inputs, outputs, credentials, tokens,
  sockets, and raw principals.

## Plugin Declaration and Enforcement

Plugins declare reviewable fields in
`CapabilityAuthorizationMetadata.approval_schema`. Each field is a normalized
input JSON pointer with a display label, non-secret value type, exact/prefix/
subset/maximum constraint, required flag, and optional destructive or
privilege-escalation emphasis. Core owns rendering and enforcement.

Bundled declarations cover SQL text/database/schema/table, Redis key/command,
MongoDB database/collection, S3 bucket/object prefix, WebDAV path prefix,
Docker container/action, Kubernetes resource/namespace/replica/manifest,
Jenkins job/build/queue, Email folder/message, Elasticsearch index/method/path,
and SSH command/SFTP/forwarding targets. Capability-wide approval remains
available where declared. Exact invocation always fingerprints the complete
normalized input, including fields not suitable for reusable constraints.

Process plugins with missing, secret-bearing, unknown-version, duplicate, or
otherwise incompatible schemas fail closed. Sync remains outside the generic
broker because its dedicated encrypted protocol owns its command/session
surface.

## When to Use Proactive Authorization

Use JIT for interactive agents, uncertain scope, destructive work, and any
workflow where the needed operation becomes known during execution. Prefer a
time-bounded approval when follow-up calls are expected; add a use limit only
when the operator explicitly wants one. Use `voidb-cli agent authorize` for one
known profile or `voidb-cli agent authorize-batch --spec <path>` for several
known profiles. Batch authorization still creates one isolated grant per
Profile ID/plugin, requires a concrete purpose for every plan entry, and
performs one local CLI review and hidden password prompt.
Existing proactive grants remain compatible and have empty JIT scope history;
they are never silently converted into JIT revisions.
