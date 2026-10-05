# Agent Authorization Broker

VoidB agents use short-lived grants instead of receiving the credential master
password. The local broker holds one master password in memory, owns one
profile-scoped grant, and executes approved VoidB commands on behalf of an
agent.

## Security Model

Every grant is bound to:

- one immutable Profile ID and its plugin;
- an explicit capability list, or policy-approved capabilities for that plugin;
- an expiration time;
- an optional remaining-use counter; and
- whether destructive `--yes` acknowledgements are permitted.

Defaults are 15 minutes, no operation-count limit, and no destructive
acknowledgement. Passing `--uses <n>` adds a finite budget of 1–100 accepted
broker commands. A `profile test` or `invoke run` that passes a finite grant's
scope checks consumes one command even if the target operation later fails; a
request rejected by the broker does not. TTL is limited to one hour. When the
time limit or an explicit use limit is reached, the broker exits and removes
its socket and grant record. Grant files and sockets are accessible only to the
current operating-system user. Frontend JSON uses `remaining_uses: null` for a
time-only grant.

Revocation unlinks the broker socket immediately, so no new invocation can
start. An invocation that was already running may finish, but it cannot run
past the grant's expiration time.

The broker also owns the grant-scoped persistent session host. A plugin may
register a session factory that keeps its service actor and live handle in the
broker process across calls. Grant files contain only the existing opaque grant
metadata; session references, master passwords, decrypted configuration, and
live handles are never written to grant files, argv, or environment variables.

The broker accepts only these command shapes:

```text
profile test id:<profile-id> --plugin <plugin>
invoke run <plugin.capability> --profile id:<profile-id> --input-json <json>
```

It rejects other profiles, plugins, capabilities, local input files, and
`--yes` unless the user explicitly authorized destructive operations. Child
commands still pass through VoidB capability policy, redaction, and audit.

This protects against routine or accidental master-password disclosure. It
does not claim isolation from a hostile process with same-user debugger or
memory-reading privileges; stronger isolation would require an OS sandbox or a
separately privileged service.

## CLI Workflow

For normal agent calls, use the facade command:

```bash
voidb-cli agent exec jenkins.jobs \
  --profile prod-jenkins \
  --input-json '{}' \
  --purpose "Inspect failed production builds for incident INC-42"
```

`agent exec` infers `jenkins` from the qualified capability, resolves the
friendly profile name to its immutable ID, and selects a compatible live grant.
The executed child command and its stable JSON output remain the same as
`invoke run`. If an identified interactive agent has no matching access, the
command creates an exact JIT request, prints both the interactive CLI review
command and the Connection Manager inbox shortcut, waits up to 30 seconds, and
continues automatically after approval. The CLI review command shows canonical
request details, including the required specific purpose, and prompts for the
master password with terminal echo disabled;
the agent process never receives it. Codex tasks use `CODEX_THREAD_ID`
automatically. Other
integrations can set `VOIDB_AGENT_CLIENT_ID`, `VOIDB_AGENT_TASK_ID`, and the
optional `VOIDB_AGENT_INSTANCE_ID`, or pass the equivalent advanced flags.

If no stable agent identity is available, the command fails safely with an
`agent_identity_required` response containing quick-authorization guidance.
`--no-request` disables automatic JIT creation for unattended callers. If the
bounded wait ends before approval, `data.review_command` remains available in
the JSON result; approve locally, then rerun the same `agent exec` operation.
When the request TTL elapses, the broker atomically records an automatic denial
with `timed_out: true`; a late review or approval cannot revive it.

The commands below are the compatible lower-level workflow for scripts that
need explicit lifecycle control.

Create a default grant. The password prompt is hidden:

```bash
voidb-cli agent authorize --profile prod --plugin ssh
```

The default resolves the central `read_only` preset to an exact capability
list for stateless execution, lasts 15 minutes, and has no operation-count
limit. Add `--uses <n>` only when a finite budget is required. Presets are
policy-reviewed scope builders, not permission shortcuts:

- `read_only` is recommended and contains only declared read-only operations;
- `interactive_execute` is a narrow plugin-declared workflow such as
  `ssh.exec`, never every destructive operation;
- `full_access` expands every capability currently in the plugin catalog into
  an exact stored snapshot and never grants future capabilities implicitly; and
- `custom` is an exact user-selected capability subset.

The CLI resolves a named preset when `--capability` is omitted and rejects a
capability list that does not exactly match that preset. Passing explicit
capabilities without `--preset` records the grant as Custom. Custom with no
capabilities is invalid; an empty scope never means all capabilities.

Every grant has an explicit transport boundary. Omitted mode flags default to
`stateless`; use `--execution-mode session_only` for persistent-session access
or `--execution-mode both` only when one reviewed grant genuinely needs both
transports. Presets and custom scopes are resolved inside that boundary.
Stateless grants cannot open sessions, session-only grants cannot run one-shot
invocations, and legacy grant files deserialize as stateless. JIT `agent exec`
approval is intentionally stateless-only.

Agent authorization is unavailable while credentials still use VoidB's legacy
default passphrase. Set a user-controlled master password first.

### Batch CLI review

For several known profiles, place the requested isolated grants in a local JSON
file:

```json
{
  "grants": [
    {
      "profile": "prod-postgres",
      "plugin": "postgres",
      "purpose": "Inspect replication health while triaging incident INC-42",
      "preset": "read_only"
    },
    {
      "profile": "prod-ssh",
      "plugin": "ssh",
      "purpose": "Verify production uptime while triaging incident INC-42",
      "capabilities": ["ssh.exec"]
    }
  ]
}
```

Review and authorize the whole plan from a local terminal:

```bash
voidb-cli agent authorize-batch \
  --spec grants.json \
  --ttl-minutes 30 \
  --allow-destructive
```

The CLI resolves every friendly profile to its immutable Profile ID and renders
each required `purpose` beside the complete capability and risk summary. It
requires the operator to type `AUTHORIZE` and prompts for the master password
once with terminal echo disabled. It then starts one independent broker grant
per Profile ID/plugin.
The command rolls back newly started grants when batch startup fails.
`--replace` reviews replacement of matching active scopes. `--uses <n>` applies
the same optional finite budget to each new grant. `--yes` is available only
for callers that already reviewed the local spec and intentionally skip the
interactive batch confirmation.

Limit the grant to selected capabilities or shorten it:

```bash
voidb-cli agent authorize \
  --profile prod \
  --plugin ssh \
  --execution-mode stateless \
  --capability ssh.sftp_list \
  --capability ssh.diagnostics \
  --ttl-minutes 5 \
  --uses 3
```

Use the immutable Profile ID returned by `authorize`; names are deliberately not
accepted at execution time so renaming or replacing a profile cannot widen an
existing grant. `--grant` may be omitted when exactly one active grant matches:

```bash
voidb-cli agent run -- \
  profile test id:<profile-id> --plugin ssh --format json

voidb-cli agent run -- \
  invoke run ssh.sftp_list --profile id:<profile-id> \
  --input-json '{"path":"."}' --format json
```

Inspect and revoke access:

```bash
voidb-cli agent list
voidb-cli agent list --profile id:<profile-id> --plugin ssh
voidb-cli agent renew agent-grant:<uuid> --ttl-minutes 15
voidb-cli agent renew agent-grant:<uuid> --ttl-minutes 15 --uses 10
voidb-cli agent revoke agent-grant:<uuid>
voidb-cli agent revoke --profile id:<profile-id> --plugin ssh
voidb-cli agent revoke --all
```

Only one central grant may exist for an immutable Profile ID and plugin. A new
authorization fails closed when that scope already has a grant. Use an explicit
replacement to start the new broker, verify it, close sessions owned by the
displaced broker, and remove its private artifacts:

```bash
voidb-cli agent authorize \
  --profile id:<profile-id> --plugin ssh --replace
```

Renewal changes only expiry and the optional use budget. Omitting `--uses`
renews as time-only access; passing it resets a finite remaining-use count.
Profile ID, plugin, capability scope, and destructive consent are immutable;
widening any of them requires a reviewed replacement. Default grants persist an
exact read-only capability list rather than a wildcard.

`agent list` is a password-free, frontend-safe query. It groups the newest grant
by immutable Profile ID and plugin under `data.profiles`, keeps a flat compatible
grant list under `data.grants`, and reports grant status, broker health, expiry,
remaining uses, destructive consent, and active session count. It never returns
the broker token, socket path, master password, or decrypted profile data.

A missing broker socket is `offline`; a path that exists but fails a bounded,
authenticated broker probe is `stale_socket`. Listing preserves these records so
frontends do not misreport them as valid authorization. Scoped revoke or explicit
replacement removes the orphaned metadata and socket safely. Renewal refuses
offline and stale brokers.

## Persistent Session Workflow

First create an explicit session grant. The catalog or a structured
`execution_mode_mismatch` response supplies the exact handoff capability set:

```bash
voidb-cli agent authorize \
  --profile prod --plugin ssh \
  --execution-mode session_only \
  --capability ssh.terminal_read \
  --capability ssh.terminal_snapshot \
  --capability ssh.terminal_write \
  --capability ssh.terminal_resize \
  --capability ssh.terminal_signal \
  --allow-destructive --yes
```

Then open a semantic plugin session with explicit capabilities from that grant.
The purpose must match each capability's declared `session_handoff`, and the
requested lease is capped at grant expiry:

```bash
voidb-cli agent session open \
  --grant agent-grant:<uuid> \
  --purpose interactive_terminal \
  --capability ssh.terminal_read \
  --capability ssh.terminal_snapshot \
  --capability ssh.terminal_write \
  --capability ssh.terminal_resize \
  --capability ssh.terminal_signal \
  --lease-seconds 300 \
  --input-json '{}'
```

The response returns an opaque `session_id` and `generation`. Pass both on later
operations so stale state is rejected explicitly:

```bash
voidb-cli agent session start \
  --grant agent-grant:<uuid> \
  agent-session:<uuid> --generation 1 \
  --call-id call:agent-task-42 \
  --capability ssh.terminal_read \
  --input-json '{"after_offset":0,"max_bytes":32768}'

voidb-cli agent session status \
  --grant agent-grant:<uuid> agent-session:<uuid> --generation 1 \
  --call-id call:agent-task-42
voidb-cli agent session wait \
  --grant agent-grant:<uuid> agent-session:<uuid> --generation 1 \
  --call-id call:agent-task-42 --wait-timeout-ms 30000
voidb-cli agent session list --grant agent-grant:<uuid>
voidb-cli agent session renew \
  --grant agent-grant:<uuid> agent-session:<uuid> --generation 1 \
  --lease-seconds 300
voidb-cli agent session cancel \
  --grant agent-grant:<uuid> agent-session:<uuid> --generation 1 \
  --call-id call:agent-task-42 --timeout-ms 1000
voidb-cli agent session close \
  --grant agent-grant:<uuid> agent-session:<uuid> --generation 1 \
  --timeout-ms 5000
```

`--call-id` is a caller-owned public identifier. Supplying it before starting a
call lets another process construct the matching cancel request without reading
credentials, process arguments, or a response that has not arrived yet. Omitting
the flag remains backward compatible and generates `call:<uuid>` in the client.
IDs are 1 to 128 bytes and may contain only ASCII letters, digits, `-`, `_`,
`.`, and `:`. Every call response, including a policy or target error, repeats
the selected protocol version and caller-owned call ID in the CLI envelope.
`start` returns the accepted lifecycle immediately. `status --call-id` is a
non-blocking snapshot, and `wait` holds only its own client connection for up to
30 seconds; a timed-out wait returns the current non-terminal lifecycle and can
be repeated. The existing `call` command remains the synchronous convenience
form and is implemented by the same start-and-wait registry.

The local broker wire is versioned independently from grant files and external
process-plugin JSON-RPC. Version 2 adds explicit negotiation and caller-owned
control identifiers. A request without `protocol_version` is legacy version 1;
the broker accepts versions 1 and 2 and answers with the selected version. A
version 2 client can therefore use an older broker response, which deserializes
as version 1, while unsupported future versions fail with
`session.protocol_unsupported` and the supported version list. Tokens, inputs,
and outputs remain outside protocol diagnostics.
Asynchronous `start`, call-level `status`, and `wait` require version 2. The CLI
probes the selected version first and returns a structured upgrade instruction
instead of sending an unknown action to a legacy broker.

Database sessions use `database_query` or `database_transaction` purposes. The
SQLite and DuckDB factories retain one plugin-owned `SyncWorker` connection, so
in-memory databases, temporary objects, attached state, settings, and open
transactions remain visible to later `sqlite.query`/`sqlite.exec` or
`duckdb.query`/`duckdb.exec` calls. Calls remain serialized; `exec` is checked
as destructive on every call. Cancel, close, grant expiry, revocation, and host
shutdown request rollback and drop the owning worker.

MySQL and PostgreSQL database sessions likewise retain exactly one authenticated
connection. This makes temporary objects, transaction state, session variables,
settings, prepared statements, and advisory locks observable across calls. A
failed PostgreSQL transaction remains failed until an explicit `ROLLBACK`; the
host never reconnects and claims that semantic state survived. The disposable
PostgreSQL session fixture covers transaction rollback/recovery, temporary
objects, a session setting, advisory locks, close cleanup, and credential scans.

Redis database sessions retain one transport so `WATCH`, `MULTI`, queued
commands, `EXEC`, the selected database, and connection-bound blocking or
subscription modes are not silently moved to another connection. Close sends
best-effort `DISCARD` and `UNWATCH` before dropping the transport. MongoDB
sessions retain one driver `ClientSession`; `begin`, `commit`, and `abort`
actions and `mongodb.run_command` share causal and transaction state. Dedicated
change-stream cursor polling is intentionally deferred to the stream/protocol
slice instead of presenting ordinary stateless operations as a live stream.

All session commands return one JSON envelope with `ok`, `data`, structured
`error`, `message`, `operation`, `protocol_version`, an optional public
`call_id`, and the grant's remaining uses and expiry. Accepted `open`, `call`,
and `start` operations consume grant uses only when the grant has a finite
budget; status, wait, list, renew, cancel, and close are lifecycle controls and
do not. Finite-use exhaustion rejects new data work but keeps an online broker
addressable for status, wait, cancel, renew, and close until explicit revocation
or grant expiry. This prevents the last accepted asynchronous call from losing
its control path.

The call lifecycle is monotonic: `accepted`, `running`, and
`cancel_requested` are non-terminal; `succeeded`, `failed`, `cancelled`,
`timed_out`, and `aborted` are terminal. Terminal state never changes on a
repeated control request. Cancel is idempotent for one session generation and
call ID. Close outranks cancel, and broker shutdown outranks close; a successful
plugin result racing with an accepted close/shutdown is projected as `aborted`,
not success.

Cancel defaults to a 1-second control deadline and close defaults to 5 seconds;
both may be overridden up to 30 seconds. A cancel deadline escalates to bounded
session close. A close deadline marks the session failed and releases the host's
last live-handle reference, so plugin-owned `Drop` cleanup can close sockets,
workers, transactions, subprocesses, and tunnels. Repeating cancel or close
does not invoke plugin cleanup twice.

Calls are serialized unless both the caller requests `--multiplexed` at open
and the plugin explicitly declares it safe. Every call rechecks grant capability
scope, capability risk, and destructive acknowledgement. Generic structured
output defaults to 64 KiB and is capped at 1 MiB.

The Unix listener accepts each client independently from call execution. A
per-session gate serializes driver-facing data calls when required, while call
status and wait use the broker lifecycle registry and cancel/close reach the
plugin handle without waiting for the data call to return. Different sessions,
and explicitly safe multiplexed sessions, can execute concurrently.

Destructive access requires an explicit authorization confirmation:

```bash
voidb-cli agent authorize \
  --profile prod --plugin ssh \
  --preset interactive_execute \
  --allow-destructive --yes \
  --ttl-minutes 5 --uses 10
```

The later `agent run` invocation must still include its own `--yes`, and profile
policy may still deny it.

To authorize every capability currently exposed by a plugin without listing
them individually, use the Full access preset. If any capability is destructive,
both acknowledgement flags remain mandatory:

```bash
voidb-cli agent authorize \
  --profile prod-jenkins --plugin jenkins \
  --preset full_access \
  --allow-destructive --yes \
  --ttl-minutes 15 --uses 10
```

The grant persists exact capability IDs resolved at authorization time. A later
plugin upgrade cannot add permissions to the existing grant.

## Connection Manager Workflow

After unlocking with `m`, select a profile and press `a`. The default view shows
one recommended action: read-only access for 15 minutes with no operation-count
limit.
Enter opens its review step. Press `a` again for advanced controls, where
Left/Right chooses Read-only, Interactive/Execute, Full access, or Custom; `t`
and `u` cycle TTL/use bounds; and Space toggles an exact Custom capability.
This dialog intentionally requests the stateless-compatible catalog and creates
stateless grants. Use the explicit CLI workflow above when persistent-session or
combined access is required.
Execute-capable scopes require explicit destructive acknowledgement, and every
later destructive call still requires its own acknowledgement.

The same manager inspects the current scope, renews only TTL/uses, replaces a
scope after review, revokes the selected immutable Profile ID/plugin grant, or
reviews the secondary revoke-all action. The master password travels only over
the child process stdin pipe and is removed from the environment.

Profile badges distinguish OFF, READ-ONLY, EXECUTE, EXPIRING, EXHAUSTED,
EXPIRED, STALE, BROKER OFFLINE, and UNSUPPORTED. A grant badge answers whether
future calls are authorized; the active-session count answers how many live
plugin-owned handles exist. An active grant can have zero sessions, and closing
the last session does not revoke the grant.

Missing sockets are offline. Unresponsive paths are stale. Both stay visible
until scoped revoke or reviewed replacement performs safe recovery; VoidB never
reconstructs or persists the master password to revive a dead broker.

## Audit

Issuance, use, and revocation emit `credential_grant_issued`,
`credential_grant_used`, and `credential_grant_released` audit events. Events
contain only grant ID, Profile ID, plugin, scope, expiry, and counters—never the
master password, broker token, or decrypted connection configuration.

Persistent operations additionally emit `session_open`, `session_call`,
`session_status`, `session_list`, `session_renew`, `session_cancel`, and
`session_close`. Their audit projection includes opaque binding and lifecycle
metadata only. Call input and output are deliberately omitted.
