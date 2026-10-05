# Agent Operator, Migration, and Troubleshooting Guide

This is the operational entry point for adopting VoidB's Agent surface,
upgrading an existing installation, and diagnosing failed invocations or
sessions. The generated
[Agent Capability and Experience Matrix](agent-capability-matrix.md) is
authoritative for current built-in capabilities, execution modes, timeouts,
streaming, cancellation, session support, standalone TUIs, and known limits.

Examples in this guide use profile references and placeholder identifiers. Do
not put passwords, tokens, private keys, decrypted plugin configuration,
authorization headers, cookies, signed URLs, or absolute local paths in command
arguments, logs, issue text, or retained test artifacts.

## Establish the Current Contract

Regenerate or query the matrix before changing automation:

```bash
mkdir -p target/tmp
voidb-cli invoke matrix --format json > target/tmp/voidb-agent-matrix.json
voidb-cli invoke list --format json > target/tmp/voidb-installed-capabilities.json
voidb-cli agent catalog --plugin ssh
```

The generated matrix covers repository-owned built-ins. `invoke list` also
discovers process plugins installed on the current node. Treat these fields as
routing inputs instead of inferring behavior from plugin names:

- `execution_mode`: `stateless`, `session_only`, or `both`;
- `risk`: `read_only`, `mutating`, `destructive`, or
  `external_side_effect`;
- `default_timeout_ms`, streaming support, and cancellation behavior;
- declared authorization metadata and persistent-session handoff;
- known limitations and the validation command for the plugin.

Machine consumers should use JSON or NDJSON. Table and Markdown output are for
humans and are not compatibility contracts.

## Upgrade and Profile Migration

### 1. Back up local state

Stop VoidB TUIs, agent brokers that are being replaced, and any local Sync
server. Then copy the complete config directory before installing binaries or
applying migration:

```bash
voidb_config_dir="${XDG_CONFIG_HOME:-$HOME/.config}/voidb"
voidb_backup_root="$HOME/.voidb-backups"
voidb_backup_dir="$voidb_backup_root/$(date +%Y%m%d-%H%M%S)"

test -d "$voidb_config_dir"
mkdir -p "$voidb_backup_dir"
cp -Rp "$voidb_config_dir" "$voidb_backup_dir/voidb"
test -f "$voidb_backup_dir/voidb/config.toml"
```

If an installation has no `config.toml`, replace the last assertion with a
check for an expected native file such as `profiles.json`. Keep the backup
outside the config directory so Sync and migration cannot modify it.

### 2. Install, inspect, and preview

Install the new `voidb`, `voidb-cli`, and optional `voidb-sync-server` binaries
from one versioned artifact set. Confirm the selected binary before writing
state:

```bash
voidb-cli --version
voidb-cli profile list --format json
voidb-cli profile migrate preview --format json
```

The preview is read-only. Review profile counts, plugin IDs, warnings, and
credential-reference outcomes. To limit the first migration, add
`--plugin <plugin-id>`; both `postgres` and legacy `postgresql` select
PostgreSQL records.

### 3. Apply explicitly

```bash
voidb-cli profile migrate apply --format json
voidb-cli profile list --format json
```

Migration is additive and non-destructive:

- legacy connections remain in `config.toml` as a rollback source;
- native identity and agent-safe metadata are written to `profiles.json`;
- encrypted plugin configuration and credential references are written to
  `credentials.json`;
- native profile resolution no longer reads live connection details from
  `config.toml`;
- migrated files are private (`0600` on Unix-like systems), and plaintext
  credential values are not persisted.

Use `--profile` in new scripts. `--conn` remains only as a compatibility alias.
Do not rewrite `postgresql` identifiers, unknown plugin JSON fields, encrypted
`plugin_config` blobs, or legacy connection keys in place.

## JSON and Protocol Compatibility

The current behavior is additive for existing machine clients:

| Existing client behavior | Current handling | Migration action |
|---|---|---|
| `invoke run --format json` | Still returns one terminal schema-versioned JSON document. | Keep it for one-shot clients. Inspect `ok`, structured `error`, and `schema_version`. |
| `--timeout-ms <n>` | Remains a positive-millisecond compatibility option. | Prefer unit-bearing `--timeout 30s` in new scripts. |
| Grant record without execution-mode metadata | Loads as `stateless`. | Replace it with an explicitly mode-bounded grant before opening sessions. |
| Broker request without `protocol_version` | Negotiates legacy broker wire version 1. | Use the current CLI for version 2 call IDs and asynchronous controls. |
| Process plugin protocol 1/1.0 | Continues to support stateless invocation. | Upgrade the plugin to protocol 1.1 before declaring persistent sessions. |
| Legacy PostgreSQL plugin ID `postgresql` | Resolves through the compatibility alias to `postgres`. | Keep persisted IDs unchanged until explicit migration. |

NDJSON is opt-in, not a replacement for JSON. Use it when progress or multiple
data events matter:

```bash
voidb-cli invoke run s3.list \
  --profile id:<profile-id> \
  --input-json '{"prefix":"","limit":100}' \
  --format ndjson \
  --timeout 30s \
  --call-id call:inventory-001
```

Each NDJSON line is a complete versioned object. Consume `start`, `data`,
`progress`, `warning`, `error`, and `end` events in sequence; do not parse
plugin stderr as protocol output. A structured error followed by `end` is one
terminal failure, not two failures.

## Execution Modes and Authorization Presets

Execution mode is an authorization boundary:

| Mode | Route | Operational meaning |
|---|---|---|
| `stateless` | `invoke run` or `agent exec` | One bounded operation; no live driver or semantic state survives. |
| `session_only` | `agent session open/...` | Capability is valid only through a grant-scoped persistent session. |
| `both` | Either route | The capability declares both forms; the grant still authorizes only its selected mode. |

List exact preset contents before granting access:

```bash
voidb-cli agent catalog --plugin ssh --execution-mode stateless
voidb-cli agent catalog --plugin ssh --execution-mode session_only
```

Presets expand to exact capability snapshots:

- `read_only` is the recommended default and never implies filesystem access;
- `interactive_execute` contains only the plugin-declared interactive execute
  scope;
- `full_access` contains every currently declared capability in the selected
  mode, but does not inherit capabilities added by a later upgrade;
- `custom` is an explicit set supplied with repeated `--capability` flags.

Create a short stateless grant:

```bash
voidb-cli agent authorize \
  --profile prod \
  --plugin ssh \
  --execution-mode stateless \
  --preset read_only \
  --ttl-minutes 5
```

Time-bounded grants have no operation-count limit by default. Add `--uses 3`
only when the operator explicitly wants a finite budget.

For multiple profiles, put each profile/plugin/preset or explicit capability
set in a local JSON `grants` array. Every entry must also include a concrete
`purpose` explaining why that scope is needed. Then run:

```bash
voidb-cli agent authorize-batch --spec grants.json --ttl-minutes 15
```

The CLI shows every purpose while reviewing the complete plan, prompts for the
master password once, and still creates separate grants for every immutable
Profile ID/plugin.

Create a session grant only after reviewing the matrix handoff:

```bash
voidb-cli agent authorize \
  --profile prod \
  --plugin ssh \
  --execution-mode session_only \
  --capability ssh.terminal_read \
  --capability ssh.terminal_snapshot \
  --ttl-minutes 5
```

Stateless grants cannot open sessions; session-only grants cannot run one-shot
invocations. `both` must be selected explicitly when one reviewed grant needs
both transports. JIT `agent exec` approval is stateless-only. A named preset
never means a wildcard, and `--yes` acknowledges one destructive call but does
not grant permission.

When `agent exec` may need JIT access, pass `--purpose` with the concrete task,
target, and expected outcome. The local CLI review displays that purpose before
the user decides. A pending request is automatically denied when its request
TTL elapses; create a new request with a current purpose instead of retrying a
late decision.

## Timeout, Cancellation, and Streaming

For a one-shot call through an existing grant, set a public call ID before work
begins and use a unit-bearing timeout:

```bash
voidb-cli agent run --grant agent-grant:<uuid> -- \
  invoke run jenkins.jobs \
  --profile id:<profile-id> \
  --input-json '{}' \
  --timeout 30s \
  --call-id call:jobs-001 \
  --format json
```

Timeout selection is caller override, capability default, then Core default.
Plain values such as `--timeout 30` are rejected because the unit is ambiguous.
Timeouts return structured category `timeout` and exit code `9`.

The first `Ctrl-C` requests cooperative cancellation. A second `Ctrl-C` aborts
the local CLI after the grace period and may produce shell exit code `130`
instead of structured output. Caller-provided cancellation tokens are for
correlation only and are never emitted or persisted:

```bash
voidb-cli invoke run elasticsearch.search \
  --profile id:<profile-id> \
  --input-json '{"query":{"match_all":{}}}' \
  --format ndjson \
  --timeout 20s \
  --call-id call:search-001 \
  --cancellation-token cancel:search-001
```

Use the structured category, code, and `retryable` field rather than the shell
code alone. Never automatically retry a destructive operation unless its
contract and policy explicitly make that retry idempotent.

## Persistent Session Lifecycle and Cleanup

Open a session from an explicit session-mode grant:

```bash
voidb-cli agent session open \
  --grant agent-grant:<uuid> \
  --purpose interactive_terminal \
  --capability ssh.terminal_read \
  --capability ssh.terminal_snapshot \
  --lease-seconds 300 \
  --input-json '{}'
```

Retain the returned opaque `session_id` and `generation`. Start one call, poll
without blocking, wait in bounded intervals, and cancel by the same public call
ID:

```bash
voidb-cli agent session start \
  --grant agent-grant:<uuid> \
  agent-session:<uuid> --generation 1 \
  --call-id call:terminal-read-001 \
  --capability ssh.terminal_read \
  --input-json '{"after_offset":0,"max_bytes":32768}'

voidb-cli agent session status \
  --grant agent-grant:<uuid> \
  agent-session:<uuid> --generation 1 \
  --call-id call:terminal-read-001

voidb-cli agent session wait \
  --grant agent-grant:<uuid> \
  agent-session:<uuid> --generation 1 \
  --call-id call:terminal-read-001 \
  --wait-timeout-ms 30000

voidb-cli agent session cancel \
  --grant agent-grant:<uuid> \
  agent-session:<uuid> --generation 1 \
  --call-id call:terminal-read-001 \
  --timeout-ms 1000

voidb-cli agent session close \
  --grant agent-grant:<uuid> \
  agent-session:<uuid> --generation 1 \
  --timeout-ms 5000
```

`start` returns after acceptance. `status` is non-blocking; a `wait` timeout
returns the current non-terminal lifecycle and may be repeated. Cancel defaults
to one second and close to five seconds; both are capped at 30 seconds. A cancel
timeout escalates to close, and repeated cancel/close is idempotent.

At task end:

```bash
voidb-cli agent session list --grant agent-grant:<uuid>
voidb-cli agent session close \
  --grant agent-grant:<uuid> \
  agent-session:<uuid> --generation 1
voidb-cli agent revoke agent-grant:<uuid>
```

Revocation is the emergency close-all operation for that grant. It removes
private broker runtime artifacts and prevents new calls. Also use scoped revoke
for an `offline` or `stale_socket` grant; do not delete socket or grant files by
hand. Reconnect or broker replacement increments `generation`, so stale
session/call IDs must fail rather than attach to new semantic state.

## Local Path Grants and Staging Roots

A capability grant never authorizes host filesystem access. Upload, download,
attachment, export/import, and sync-plan workflows also need a separate local
path grant bound to one actor, profile, plugin, capability, approved root,
access-mode subset, expiry, and use count.

Operator rules:

1. Approve the narrowest existing directory as the root. Do not approve a home
   directory, filesystem root, config directory, or secret store.
2. Pass relative paths beneath that root. Compatibility-absolute paths do not
   choose or widen the root.
3. Put `staging_root` inside the approved root and on the same filesystem as
   the final destination. If no safe staging location exists, the operation
   fails with `unavailable.local_staging`.
4. Keep no-overwrite as the default. Replacement additionally requires
   `replace_file`, validated `overwrite=true`, destructive/mutating policy, and
   a per-call acknowledgement.
5. On failure, cancellation, expiry, or checksum mismatch, verify that the
   private staging artifact was removed. Resume only with VoidB's opaque resume
   reference; never accept a caller-selected staging path.
6. Do not retain absolute roots, staging filenames, or submitted local paths in
   Agent output, logs, task text, or audit exports.

Symlinks, junctions, `..`, ungranted mounts, device paths, and identity changes
fail closed. Read-only presets do not imply `read_file` or `scan_directory`.

## TUI Release Thresholds

Run the release-quality gate in a real PTY:

```bash
scripts/tui-quality-gate.sh
```

Release mode uses one cold run, one warmup, and five measured warm runs. These
are blocking default budgets:

| Metric | Threshold |
|---|---:|
| First visible frame | warm p50 <= 500 ms; p95 <= 750 ms |
| Key to local repaint | warm p50 <= 30 ms; p95 <= 50 ms |
| Raw key echo/forwarding | warm p95 <= 35 ms, excluding target latency |
| Resize to stable frame | warm p50 <= 60 ms; p95 <= 100 ms |
| Quit to terminal restoration | warm p50 <= 150 ms; p95 <= 250 ms |
| Idle CPU | p95 <= 2% of one logical CPU |
| Idle repaint | p95 <= 2 events/s unless a visible spinner is active |

Quick journeys intentionally omit performance thresholds and are never release
evidence. A threshold failure should be reproduced on the same native runner;
inspect the retained ANSI and event timeline before changing a budget. Platform
release claims also require the manual terminal matrix in
[TUI CI and Real-Terminal Coverage](tui-terminal-coverage.md).

## Common Failures

| Symptom or code | Meaning | Safe action |
|---|---|---|
| `validation.execution_mode_mismatch` | The capability or grant is on the wrong route. | Re-read the matrix, then create a correctly mode-bounded grant or use the declared route. |
| `permission` / exit `5` | VoidB authorization denied the operation. | Inspect the exact capability scope and risk; do not add `--yes` as a workaround. |
| `credential` / exit `6` | Credential reference or broker grant is missing, expired, or incompatible. | Unlock locally, renew without widening, or replace the grant after review. Never put a secret on argv. |
| `policy` / exit `7` | A non-auth policy boundary rejected the call. | Inspect the structured code and change input or policy deliberately. |
| `conflict` / exit `8` | Generation, destination, cursor, lock, or state changed. | Refresh state; do not blindly replay a mutating call. |
| `timeout` / exit `9` | Core, plugin, or target deadline expired. | Inspect the timeout source and retryability; increase the bound only when the operation contract allows it. |
| `cancellation` / exit `10` | Cooperative cancellation won. | Confirm terminal state and cleanup before starting replacement work. |
| `transport` / exit `11` | Pipe, socket, TLS, DNS, process I/O, or network failed. | Retry with bounded backoff only when `retryable=true`; inspect retained redacted diagnostics. |
| `plugin` / exit `12` | Plugin crashed or violated its protocol/schema. | Check plugin version/protocol and the sanitized phase log; do not parse stderr as output. |
| `target_system` / exit `13` | The remote system rejected the operation. | Follow plugin-specific retryability and inspect target-safe details. |
| `permission.local_path_scope_required` | No matching local path grant exists. | Ask the local operator to approve one narrow root and access subset. |
| `policy.local_path_link_denied` | A symlink, junction, or ungranted mount was encountered. | Choose a real in-root path; never relax to string-prefix validation. |
| `conflict.local_path_exists` | No-overwrite commit found a destination. | Pick another destination or obtain explicit replacement authority and acknowledgement. |
| Grant shows `offline` or `stale_socket` | Broker is absent or its authenticated probe failed. | Revoke or explicitly replace the scoped grant; do not unlink runtime files manually. |

JSON/NDJSON error payloads are authoritative. The first terminal structured
error determines the exit code; warnings do not.

## Safe Rollback

If the upgrade fails, stop the new processes and preserve the failed state for
diagnosis instead of deleting it:

```bash
voidb_config_dir="${XDG_CONFIG_HOME:-$HOME/.config}/voidb"
voidb_backup_dir="<absolute-backup-directory>"
voidb_failed_dir="${voidb_config_dir}.failed-$(date +%Y%m%d-%H%M%S)"

test -d "$voidb_config_dir"
test -d "$voidb_backup_dir/voidb"
mv "$voidb_config_dir" "$voidb_failed_dir"
cp -Rp "$voidb_backup_dir/voidb" "$voidb_config_dir"
```

Restore the previous `voidb` and `voidb-cli` binaries from the same release
set. Restore `voidb-sync-server` and its data directory separately when its
on-disk format changed. Do not use the Sync server as the only backup of local
configuration.

After rollback, verify:

```bash
voidb-cli --version
voidb-cli profile list --format json
voidb-cli connections list
```

Then open Connection Manager without saving, verify protected config still
requires the expected master password, and run the previous release's smoke
gate. Keep both the backup and quarantined failed directory until diagnosis is
complete.

## Requirement and Release Gate

After focused edits are committed, run the expensive checks once at the
requirement or release boundary:

```bash
python3 scripts/agent_tui_release_gate.py --profile full
```

The command retains a redacted plan, JSON/Markdown report, and per-phase logs
under `target/tmp/agent-tui-release-gate/<run-id>/`. Add `--live-fixtures` only
when disposable providers and a usable local Docker daemon are available; an
omitted live tier is recorded as `not_requested`, not as passing provider
evidence.
