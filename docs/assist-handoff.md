# External-Agent Interaction Contract

This document is the normative product and migration contract for Requirement
93. Conversation belongs in the external agent. VoidB exposes only the target
context and operation surfaces that are necessary for the agent to work, while
the owning plugin keeps live handles and enforces local policy.

The terms **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are normative. Older
`Assist*`, `question`, and `response` names are compatibility details only; they
do not define a product workflow.

## Product Interaction Matrix

| Plugin or layer | External-agent surface | TUI-local context share | Agent operation path | Required local gate |
|---|---|---|---|---|
| SSH | Shared live PTY view plus agent-owned structured shell and interactive PTY sessions | Yes. The operator explicitly shares a bounded, redacted current PTY view. | A structured current-PTY operation request, or explicit terminal capabilities on a separate agent-owned PTY. | Generation, single writer, TTL, readonly, secret-prompt, output-bound, explicit approval, terminal-control grant, and human-reviewed terminal-state warnings. |
| Docker | Capabilities; optional selected container/log/stats context | Only when the current TUI contains material state that is not cheaply rediscovered. | Structured capability operation staged into the existing Docker operation plan. | Dry-run, destructive, readonly, denial, audit, and confirmation checks. |
| Kubernetes | Capabilities; optional selected resource/log/event/watch context | Only when the current TUI contains material state that is not cheaply rediscovered. | Structured capability operation staged into the existing Kubernetes operation plan. | RBAC, dry-run, destructive, readonly, denial, audit, and confirmation checks. |
| Jenkins | Capabilities; optional selected job/build/queue/console context | Only when the current TUI contains material state that is not cheaply rediscovered. | Structured capability operation staged into the existing Jenkins operation plan. | Parameter, readonly, destructive, denial, audit, and confirmation checks. |
| MySQL, PostgreSQL, SQLite, DuckDB | Capability discovery/invocation and plugin-owned persistent agent sessions | No human-TUI or live-session share. | Existing SQL query/exec capabilities or an agent-owned database session. | SQL classification, dry-run, acknowledgement, row/output bounds, redaction, and audit checks. |
| MongoDB | Capability discovery/invocation and plugin-owned persistent agent sessions | No human-TUI or live-session share. | Existing document capabilities or an agent-owned database session. | Read/mutation allowlist, dry-run, acknowledgement, bounded output, redaction, and audit checks. |
| Redis | Capability discovery/invocation and plugin-owned persistent agent sessions | No human-TUI or live-session share. | Existing key/value capabilities or an agent-owned Redis session. | Read/write allowlist, dry-run, acknowledgement, value/output bounds, redaction, and audit checks. |
| Elasticsearch | Capability discovery/invocation | No human-TUI or live-session share. | Existing search/document capabilities. | Raw API and mutation policy, dry-run, acknowledgement, bounded output, redaction, and audit checks. |
| S3, WebDAV | Capability discovery/invocation | No human-TUI or live-session share. | Existing object and sync-plan capabilities. | Local-path/content redaction, dry-run, destructive acknowledgement, confirmation, and audit checks. |
| Email | Capability discovery/invocation and plugin-owned IDLE sessions | No human-TUI or live-session share. | Bounded mailbox reads, guarded send/move/delete/flag operations, attachment transfer, and agent-owned IDLE sessions. | Preview, dry-run/acknowledgement, stable mailbox identity, local-path controls, body/attachment/credential redaction, bounded output, cancellation, and audit checks. |
| Connection Manager | Profile metadata and credential approval only | No plugin runtime share. | Opens plugin-owned tabs or supplies profile references. | Credential brokering and profile policy. |
| Sync | Existing sync command and encrypted object boundaries | No generic external-agent share. | Existing plugin-owned sync operations. | E2E encryption, conflict, credential, and confirmation policy. |
| Shell | Routing only | Never. | Never dispatches target operations. | Hard/soft global routing and tab lifecycle only. |

No TUI contains a question editor, agent chat transcript, “Ask Agent” action,
submit-question action, or response-poll action. A TUI may show a bounded share
status and a structured operation review because those are local control
surfaces, not conversation surfaces.

## Ownership Rules

- The owning plugin service keeps PTY writers, database drivers, Docker daemon
  clients, Kubernetes watches, Jenkins clients, storage clients, mail clients,
  and all other live handles.
- Core owns transport-neutral binding, redaction, expiry, principal identity,
  operation request, confirmation, denial, and audit value types. Core does not
  own a target runtime or dispatch a side effect.
- The CLI discovers capabilities, opens plugin-owned agent sessions, reads an
  explicitly shared context, and submits structured operation requests.
- The shell remains a pure router. `ShellCapabilities` does not become an agent
  broker or a shared connection pool.
- `ConnectionConfigRegistry` stores profile metadata only. A context share may
  contain a profile reference, never decrypted configuration or credentials.
- Every side effect re-enters the plugin's existing capability or operation
  plan. A share or operation envelope never upgrades authorization,
  acknowledgement, dry-run, or confirmation state.

## Canonical Contract

There are two distinct products:

1. A **context share** publishes a bounded, redacted snapshot that is bound to
   plugin ID, session ID, generation, owner ID, purpose, requester, expiry, and
   optional external-agent principal. It has a short label, not a question.
2. An **agent operation request** identifies the share, agent principal,
   creation time, summary, and structured operations. Operations are guidance,
   a permission request, a proposed command, or a capability call. They are
   inert until the owning plugin validates and approves them.

Context shares are discovered with list/show semantics. Clients MAY wait for a
change to a specific share as a transport optimization, but the product does
not expose a generic “poll for an answer” workflow. The canonical CLI wording
is `context`, `session`, `share`, `show`, `operation`, and `input`;
compatibility aliases MUST be hidden from normal help.

### External context protocol v1

`voidb-cli context` is the password-free, non-PTY automation boundary. Protocol
version 1 defines these commands and response shapes:

| Command | Required input | Successful `data` |
|---|---|---|
| `list` | external principal; optional plugin filter | `contexts[]` plus aggregated, path-free `diagnostics[]` |
| `show` | principal and exact `(plugin_id, context_id, generation)` | one bounded context projection, plugin state, and operation summaries |
| `operation` | principal, exact context reference, unique operation-request ID, summary, and exactly one structured operation | accepted operation reference and `created` idempotency status |
| `deny` | bound external principal, exact operation-request ID and action index, generation, and bounded reason | one recorded external withdrawal as a `denied` decision |
| `status` | principal and exact context reference | current context plus per-action decision status |
| `wait` | the `status` input plus a bounded timeout | the same status shape when it changes or a timeout error |

All six commands are implemented. `operation` atomically binds an unbound share
to the first accepted principal. An exact retry of the same operation ID and
payload succeeds with `created: false`; reusing the ID with a changed payload is
a `replay` error. `deny` is likewise idempotent only for the exact same indexed
denial and reason. `wait` polls bounded local records for at most 300 seconds and
never causes the owning TUI to block.

The owning TUI is the allow/deny authority. After `operation` succeeds, Docker
and Jenkins display `y` to stage or `n` to deny; Kubernetes displays `y` to
stage or `d` to deny. Staging records `allowed` for the external review while
retaining the plugin's ordinary local plan confirmation before dispatch. The
external `deny` command is not an allow bypass; it only lets the bound task
withdraw its own still-pending indexed operation.

Every JSON response contains `ok`, `protocol_version: 1`, `command`, and exactly
one of `data` or `error`. A context ID is opaque and is never sufficient by
itself: callers MUST also supply its owning plugin ID and positive generation.
An operation decision is individually keyed by
`(operation_request_id, operation_index)`; bulk approval of a multi-action
request is not part of the protocol. Protocol v1 therefore accepts exactly one
operation per non-PTY request. Multi-action and reordered requests fail before
principal binding or local plan staging.

The external principal is `(client_id, task_id, instance_id?)`. `list` omits
records bound to another principal and reports only an aggregate count; `show`
returns `principal_mismatch` only when the caller already knows the exact
context reference. An unbound context may be discovered, but the first accepted
operation atomically binds its principal. All later reads, writes, status calls,
and waits MUST match that principal. Expiry is projected at read time even when
the owning TUI is not running. Expired and stale list entries withhold their
labels, and `show` fails closed for them.

The CLI accepts `--client-id`, `--task-id`, and optional `--instance-id`; the
non-interactive environment fallbacks are `VOIDB_AGENT_CLIENT_ID`,
`VOIDB_AGENT_TASK_ID`, and `VOIDB_AGENT_INSTANCE_ID`. Discovery never decrypts
profiles or prompts for a master password. Current commands are:

```bash
voidb-cli context list \
  --client-id agent-cli --task-id task-123 [--plugin docker]

voidb-cli context show \
  --client-id agent-cli --task-id task-123 \
  --plugin docker --generation 4 context:docker:1720000000000:1

voidb-cli context operation \
  --client-id agent-cli --task-id task-123 \
  --plugin docker --generation 4 \
  --operation-request-id operation:task-123:1 \
  --summary 'Review stopping api' \
  --operations-json '[{"kind":"capability_call","capability_id":"docker.container_action","input_summary":{"action":"stop","target_id":"container-id","target_label":"api"},"rationale":"Stop the unhealthy fixture target","risk":"destructive","target":{"kind":"capability","capability_id":"docker.container_action"}}]' \
  context:docker:1720000000000:1

voidb-cli context status \
  --client-id agent-cli --task-id task-123 \
  --plugin docker --generation 4 context:docker:1720000000000:1

voidb-cli context wait \
  --client-id agent-cli --task-id task-123 \
  --plugin docker --generation 4 --timeout-ms 30000 \
  context:docker:1720000000000:1

voidb-cli context deny \
  --client-id agent-cli --task-id task-123 \
  --plugin docker --generation 4 \
  --operation-request-id operation:task-123:1 --operation-index 0 \
  --reason 'Task was cancelled' context:docker:1720000000000:1
```

The supported cross-process journey is:

1. In the Docker, Kubernetes, or Jenkins standalone TUI, press `a` to publish
   the bounded current view.
2. In another process, use `context list` and `context show`, retaining the
   exact plugin, opaque context ID, generation, and principal.
3. Submit exactly one capability operation with a caller-unique operation ID.
4. Keep the TUI open for its local `y`/deny review. Use `status` for a snapshot
   or `wait` for a bounded wait; a timeout is retryable and does not change the
   pending operation.
5. Retry only with the exact same payload. A changed operation or indexed
   decision is a replay error. If the external task is cancelled, use `deny` to
   withdraw it without staging a local plan.

Protocol errors use stable codes and process exit statuses:

| Error code | Exit | Meaning |
|---|---:|---|
| `invalid_request` | 2 | malformed identity, identifier, generation, or command input |
| `not_found` | 3 | no safe record matches the exact reference |
| `principal_mismatch` | 4 | the record is bound to another external principal |
| `expired` | 5 | the context TTL elapsed |
| `stale` | 6 | generation, owner, or session continuity is stale |
| `incompatible` | 7 | unsupported version or invalid typed record |
| `conflict` | 8 | duplicate or concurrently conflicting state |
| `replay` | 9 | an operation ID or indexed decision was already consumed |
| `timeout` | 10 | bounded wait elapsed without completion |
| `owner_unavailable` | 11 | the owning plugin cannot currently progress the request |
| `store_unavailable` | 12 | local store access or safety checks failed |
| `internal` | 70 | unexpected internal failure after redaction |

Store enumeration is read-only and never waits for a TUI. It rejects symlinked
or non-private roots, symlinked/non-private/non-regular records, records larger
than 512 KiB, and bounds each enumeration at 4,096 JSON records. Corrupt,
incompatible, unsafe, wrong-principal, duplicate, and over-limit records do not
abort `list`; they become aggregated diagnostics without record IDs or
filesystem paths. `show` returns a typed error for a known invalid record. New
Docker, Kubernetes, and Jenkins records use mode `0600` below a mode `0700`
store directory. New records also declare an owner lease whose private sidecar
is held by an operating-system file lock for the life of the owning TUI. The
sidecar path and contents are never projected. If the process crashes, the OS
releases the lock and external discovery immediately projects the non-terminal
record as `stale`; a replacement TUI can publish a new active context in the
same store. Records without the optional lease field remain readable for v1
compatibility.

### Context bounds

The default maximums remain intentionally small: 80 by 160 visible terminal
cells, a 16 KiB transcript tail, 4 KiB metadata, and 64 KiB operation output.
Snapshots expose byte counts, truncation flags, withheld-field reasons, and
redaction status. They MUST NOT expose passwords, tokens, API keys, private-key
paths, passphrases, decrypted plugin configuration, raw host details, local
filesystem paths, unbounded target output, broker tokens, grant files, or
process-local handles. Unprovable fields fail closed.

### Operation review

- A context generation mismatch is stale and blocks approval.
- A denied, cancelled, expired, or closed share cannot accept an operation.
- Non-PTY plugins cannot request or confirm current-PTY control.
- Capability operations contain bounded input shape or safe summaries, not raw
  SQL, document values, cache values, object contents, mail bodies, or secrets.
- Confirmation records bind share ID, operation request ID, operation index,
  generation, principal, target summary, expiry when applicable, and redaction
  status.
- Each operation request and operation index can be confirmed only once. The
  owning store rejects repeated approval or denial records as replay attempts.
- Docker, Kubernetes, and Jenkins poll their local record without sleeping in
  the render/event loop. A decision made by another process, owner shutdown,
  expiry, or stale generation clears pending review state. Agent-staged plans
  retain the context expiry and generation and are cleared before service
  dispatch when either is no longer current.
- SSH current-PTY input additionally enforces a single writer, explicit
  operator approval, visible owner, immediate revoke path, and share lifetime.
- SSH agent-owned interactive PTYs use separate `terminal_read`,
  `terminal_snapshot`, `terminal_write`, `terminal_resize`, and
  `terminal_signal` capabilities. Terminal control is Custom-only,
  destructive, lease-bound, output-bounded, and never upgrades permission to
  write the human-owned PTY.
- Alternate-screen and application-key modes are visible takeover warnings, not
  hard denials. The local operator decides whether the visible terminal is ready
  for the proposed input; the TUI records that reviewed warning before granting
  the single-writer lease.

## Compatibility Boundary

Compatibility is intentionally one-way: current code reads safe records written
by the previous release, while new user-facing output and help use the canonical
external-first vocabulary.

The following MAY remain temporarily for decoding or source compatibility:

- serialized store version 1 and `Assist*` Rust/JSON envelope names;
- legacy `question` decoded as a context-share label;
- legacy `response`, `diagnosis`, and `actions` decoded as an operation request,
  optional note, and operations;
- old `post_response`/`wait_for_response` helper spellings as non-advertised
  wrappers around operation methods;
- `voidb-cli ssh assist` as a hidden alias for `ssh session`; and
- historical audit event names beginning with `assist.` when changing them
  would break retained evidence.

Compatibility MUST NOT keep an Ask Agent button, question field, response panel,
submit-question command, poll-response command, or automatic action path alive.
No compatibility decoder may widen permissions or accept unredacted fields.

`crates/voidb-cli/src/agent_broker.rs` is not an assist mailbox. It implements
credential/JIT authorization grants and remains part of the security boundary.
It must not be removed or renamed as part of this migration.

## Migration Results

| Surface | Delivered result | Evidence |
|---|---|---|
| Shared contract | Canonical context-share and agent-operation aliases, serialization, store methods, and CLI wording landed while safe legacy decoding remains. | `859925b`; Core and CLI contract tests |
| External discovery | Versioned `context list/show` JSON discovers SSH, Docker, Kubernetes, and Jenkins stores without credential decryption; exact principal, generation, TTL, stale-state, store-version, size, permission, and symlink checks fail closed. SSH v1 `terminal_state` records project through the same bounded output. | `external_context` Core tests and `builtin::context` CLI tests |
| SQL plugins | MySQL, PostgreSQL, SQLite, and DuckDB no longer compile or export snapshot, broker, or returned-plan helpers. Capability policy and plugin-owned persistent sessions remain. | `d3369db`; SQL contract, plugin, and CLI invoke tests |
| Data and search plugins | MongoDB, Redis, and Elasticsearch are capability-only; obsolete share and plan APIs were removed. | `d3369db`; capability dry-run, mutation, redaction, and bounded-output tests |
| Storage and messaging plugins | S3, WebDAV, and Email do not share human-TUI state. Storage transfers and guarded Email mutations/sessions stay plugin-owned and pass through capability policy. | Storage, Email capability, local-path, cancellation, and fixture tests |
| Docker, Kubernetes, Jenkins | `a` explicitly shares bounded context, uppercase `A` has no shortcut behavior, structured operations are automatically discovered, local approval or denial reuses the existing plan, and owner leases detect hard process failure. | TUI operation-review tests and `scripts/check-external-context-handoff.sh` |
| SSH | The visible product is session share plus operation request review. The live PTY remains plugin-owned with operator-reviewed terminal-state warnings, one-shot confirmation, replay rejection, same-session approval, revoke, TTL, generation, principal, and redaction checks. | `859925b`, `749e475`, `e501b6f`; SSH session, TUI, and compatibility tests |
| Documentation and validation | Requirements 88-92 evidence is marked historical, current guides use this matrix, and deterministic static plus real-PTY assertions protect the boundary. | `scripts/check-external-agent-interaction.sh`, `scripts/check-external-context-handoff.sh` |
| Shell and Connection Manager | They remain routing, tab, profile, and credential surfaces only; no plugin live handle or operation dispatch moved into the shell. | Architecture review and repository assertion |

## Acceptance Gates

Run the deterministic boundary check before the focused and workspace tiers:

```bash
scripts/check-external-agent-interaction.sh
scripts/check-external-context-handoff.sh
```

The second command builds `voidb-cli`, launches all three fixture-backed TUIs
in real pseudo-terminals, and runs the identical `allow`, `deny`, `timeout`,
`replay`, `multi_action`, and `crash_recovery` scenario matrix from separate
CLI processes. Its generated JSON report and ANSI transcripts stay below
`target/tmp/external-context-handoff` and are not committed.

The migration remains complete only while all of the following hold:

- Repository source and rendered help contain no user-facing “Ask Agent”,
  question entry, submit-question, poll-response, diagnosis-chat, or returned
  answer workflow.
- SSH session list/show/input works through the canonical `ssh session` command;
  its old spelling is hidden and covered only by compatibility tests.
- Docker, Kubernetes, and Jenkins share only bounded plugin-owned context;
  another process can discover it with generic `context list/show`, while
  reviewed operations still enter the existing plan gates.
- Data, search, storage, and messaging plugins expose no TUI/session-share or
  file-mailbox frontend.
- Legacy records decode without weakening redaction, binding, generation,
  expiry, principal identity, denial, or confirmation checks.
- Tests prove stale generation, wrong principal, terminal share, readonly,
  destructive acknowledgement, denied operation, and non-PTY current-control
  paths fail closed.
- Focused crate tests, `cargo test --workspace --no-fail-fast`,
  `cargo clippy --workspace --all-targets --no-deps`, and `git diff --check`
  pass, with deterministic evidence recorded for the migration.

## Rollback Criteria

Rollback is a safety action, not restoration of the Ask Agent workflow. Disable
the affected new share or operation entry point and continue to expose the
plugin's ordinary capability/CLI path when any of these occur:

- a credential, local path, message body, object content, SQL/value payload, or
  live handle reaches a context share or operation record;
- an operation bypasses generation, principal, expiry, readonly, dry-run,
  destructive acknowledgement, confirmation, or audit policy;
- SSH permits two PTY writers, loses the escape-layer revoke path, or accepts
  input after owner loss/reconnect;
- a legacy decoder accepts a wider permission or less-redacted record than the
  canonical contract; or
- a plugin service or the shell acquires ownership that belongs to another
  plugin's live runtime.

Safe rollback removes or feature-disables the new share/operation surface,
invalidates outstanding records, and leaves capability discovery and direct
plugin operations available under their pre-existing policy gates. It never
re-enables a TUI question editor or response-poll workflow.
