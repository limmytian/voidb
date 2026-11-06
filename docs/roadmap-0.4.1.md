# 0.4.1 Iteration Roadmap

This roadmap scopes the 0.4.1 iteration. Iteration work happens on the `0.4.1`
branch; `main` receives only merged, validated slices. As with the 0.3.x
series, 0.4.1 carries additive features on top of v0.4.0.

The iteration lifts two documented `deferred/fail-closed` boundaries from
[Persistent Agent Session Adoption](persistent-agent-session-adoption.md) and
adds one new agent-facing transport:

1. **Email IDLE agent live session** — selected-mailbox observation for agents.
2. **S3/WebDAV storage transfer agent sessions** — execute the already-defined
   storage transfer contract through agent sessions instead of failing closed.
3. **MCP (Model Context Protocol) server MVP** — expose the capability catalog
   to MCP clients through the existing JIT authorization broker.

Everything else stays out of scope (see [Non-goals](#non-goals)).

## Current State Baseline

Verified against this repository at the start of the iteration:

- `registry/index.json` already declares the target capabilities for the
  external plugins at protocol 1: `email.idle`, `s3.transfer`,
  `s3.transfer_status`, `webdav.transfer`, `webdav.transfer_status`,
  `webdav.lock_acquire`, `webdav.lock_release`.
- [Persistent Agent Session Adoption](persistent-agent-session-adoption.md)
  classifies Email, S3, and WebDAV agent-session execution as
  **deferred/fail-closed**: Email exposes no IDLE/selected-mailbox handle;
  S3 exposes no multipart handle or part continuation; WebDAV exposes no lock
  or resumable handle. Ordinary stateless calls remain the only path.
- The storage transfer contract itself is fully specified and its shared
  types are implemented (`voidb_core::transfer`, 27 public types);
  [Storage Agent Transfer Contract](storage-agent-transfer-contract.md) is the
  lifecycle source of truth.
- `AgentLiveSessionKind` already contains the needed kinds — `Subscription`
  for mailbox observation and `Transfer` for storage transfers — so no core
  enum changes are required.
- External process plugins host semantic sessions through broker protocol 1.1.
  At iteration start the production broker registered no factories (Slice A
  finding 1); the host-side bridge over `ProcessPluginSessionRuntime` now
  exists, and the plugin-side session handles are the remaining external-repo
  work for all three workstreams.
- The transfer contract references reliability proofs
  (`scripts/s3-fixture-smoke.sh`, `scripts/webdav-fixture-smoke.sh`) that do
  not exist in this repository yet.
- The committed
  [agent capability matrix](agent-capability-matrix.md) intentionally excludes
  installed process plugins (node-local catalogs); the authoritative
  declarations for the three plugins live in `registry/index.json` and are
  verified through conformance runs, not the committed matrix.

### Slice A — Current-state reconciliation audit (completed 2026-11-05)

The audit is complete. Findings that reshape this roadmap:

1. **The production broker registered no session factories at all.** The
   non-test `register_session_factories` in the broker runtime was an empty
   stub, so `agent session open` failed closed with `session.unsupported` for
   every plugin — not only Email/S3/WebDAV but also the adoption matrix rows
   marked "implemented" (SQL transactions, Redis streams, MongoDB cursors,
   Docker/Kubernetes/Jenkins live families). The plugin-side factories moved
   into the external plugin repositories during the extraction, and the host
   side never received their protocol 1.1 counterpart. The postgres session
   fixture smoke exercises the plugin repository's own example, so CI stayed
   green while production was fail-closed.
2. **The host-side bridge is now wired** (this iteration): an external-plugin
   session factory over `ProcessPluginSessionRuntime` registers into the
   production broker for every non-built-in plugin with an installed
   candidate and matching profile, keeping fail-closed `Unsupported` for
   plugins that do not negotiate session protocol 1.1. Plugin-side session
   methods (Email IDLE, S3/WebDAV transfer handles) remain external-repo
   work in Workstreams 1 and 2.
3. **The three-way documentation contradiction is reconciled** in the docs:
   the transfer contract, capability examples, and session capability docs
   now describe declared-but-fail-closed state; the adoption matrix documents
   the host-wiring status; phantom evidence references were removed from the
   release and CI docs.

Verification obligation for Workstreams 1 and 2 (unchanged): after each
plugin-side session handle lands in its repository, run `vb invoke describe`
against the capability and open an agent session under a scoped grant,
record the exact behavior, and flip the adoption-matrix row only then.

### Slice A addendum — external plugin work items found during 0.4.1 (2026-11-06)

- `voidb-plugin-docker`: the standalone TUI does not auto-load its primary
  resource view after unlock — users see an empty `No resources loaded` pane
  and read it as "cannot get any data" (reproduced in tmux against the local
  daemon: data loads correctly on a manual refresh). Add a startup
  auto-refresh; `docs/standalone-tui-ux-acceptance.md` now requires it.
- `voidb-plugin-*` (all retained TUIs): audit against the same new startup
  auto-load criterion.

## Workstream 1 — Email IDLE Agent Live Session

**Goal:** agents can hold a bounded, revocable mailbox-observation session
instead of polling `email.list`/`email.search`.

### Scope

In `voidb-plugin-email` (external repository):

- Service-layer IMAP IDLE handle owned by the plugin service: one selected
  mailbox per session, sequence/UID context tracked, no mailbox state leaked
  into responses.
- Session capability declarations per
  [Plugin Session Capability](plugin-session-capability.md): open, serialized
  calls, renew, cancel, close; live-session descriptor per
  [Infrastructure Agent Live Session Contract](infrastructure-agent-live-session-contract.md)
  with `kind = subscription`, bounded event buffers, heartbeat, and declared
  resume semantics (`unsupported` or `best_effort_cursor` via UIDVALIDITY +
  high-water UID — exact-cursor resume is not promised for IMAP IDLE).
- Cleanup obligations from the adoption matrix row: exit IDLE, close the
  mailbox, and stop workers on cancel, close, lease expiry, revoke, broker
  failure, and process shutdown; reconnect increments the session generation
  and reports state loss.
- Events carry mailbox fingerprints and bounded counters/UID ranges only —
  no subject lines, sender addresses, or body excerpts without an explicit
  redaction rule.

In this repository:

- Flip the Email adoption-matrix row from `deferred/fail-closed` to
  `implemented` once conformance passes.
- Add `scripts/email-fixture-smoke.sh` proving: open under a scoped grant,
  bounded event delivery, cancel/close cleanup (server-side IDLE termination
  observed), lease-expiry cleanup, and revoke = close-all.
- Update [agent-capability-examples.md](agent-capability-examples.md) and
  [agent-operator-guide.md](agent-operator-guide.md) with an IDLE example and
  its grant/preset guidance.
- Regenerate the experience matrix and run
  `scripts/check-agent-capability-matrix.sh` for drift.

### Explicitly not in this workstream

POP3 command reuse stays non-semantic; no push (SOFT total/EXAMINE) support;
no agent-visible draft/send behavior changes from 0.4.0.

## Workstream 2 — S3/WebDAV Storage Transfer Agent Sessions

**Goal:** `transfer`/`transfer_status` (and WebDAV locks) execute through
grant-scoped agent sessions with the full cleanup, resume, and redaction
semantics the transfer contract already defines, replacing fail-closed.

### Scope

In `voidb-plugin-s3` / `voidb-plugin-webdav` (external repositories):

- Multipart/ranged session handles owned by the plugin service: opaque
  resume checkpoints (`sha256:` scope fingerprint, expiry ≤ 24 h for S3 and
  ≤ 1 h for WebDAV), completed-part counters only, no provider part maps
  across the boundary.
- WebDAV lock sessions: lock tokens stay private, opaque lock references in
  output, release on cancel/close/lease/revoke.
- Cleanup per contract: local staging removal, remote partial abort or
  scope-bound retention, lock release; failed cleanup is an explicit terminal
  failure, never a silent success.
- Every session validates the separate local-path grant per
  [Local Path Authorization Policy](local-path-authorization-policy.md);
  capability grants never imply local filesystem authority.

In this repository:

- Reconcile and flip the S3/WebDAV adoption-matrix rows to `implemented`
  after conformance passes.
- Add the two missing reliability proofs exactly as the contract specifies:
  `scripts/s3-fixture-smoke.sh` (provider discovery, no-overwrite conflicts,
  server-side copy/move, SHA-256 mismatch rejection, multipart
  cancellation/resume, exact byte round-trip, retained-part cleanup) and
  `scripts/webdav-fixture-smoke.sh` (conditional COPY/MOVE against rclone,
  byte-range cancellation/resume, stale-lock isolation, lock release on
  close, explicit unsupported-feature degradation).
- Keep `cargo test -p voidb-core transfer`,
  `cargo test -p voidb-cli storage_plugins_map_to_one_fail_closed_transfer_lifecycle`
  (renamed if the fail-closed gate becomes a success path), and
  `scripts/check-local-filesystem-boundaries.sh` /
  `scripts/check-external-agent-interaction.sh` green.
- Document the agent-facing transfer workflow in
  [agent-capability-examples.md](agent-capability-examples.md) and the
  operator guide, including the dual-grant requirement (capability grant +
  local path grant).

## Workstream 3 — MCP Server MVP

**Goal:** MCP clients (Claude Desktop, ZCode, Cursor, and other MCP hosts)
can call VoidB capabilities as MCP tools with every existing safety property
intact: JIT grants, destructive gates, redaction, bounded output, audit.

### Design summary

- New builtin command group `vb mcp serve` in `voidb-cli` (stdio transport,
  JSON-RPC per the MCP spec; pin the exact spec revision in the ADR before
  implementation starts).
- `tools/list` is generated from the runtime capability catalog (the same
  source as `vb invoke matrix`): tool names follow `<plugin>.<capability>`,
  input schemas derive from the declared capability input schemas, and risk
  levels map to MCP tool annotations (`read_only` → `readOnlyHint=true`;
  `destructive` → `destructiveHint=true`).
- `tools/call` never bypasses the broker. The MCP server acts as one agent
  principal (stable `client_id`/`instance_id` per client connection); a call
  without a matching active grant returns the standard structured error with
  guidance to run `vb agent authorize` / `vb agent exec`. No tool call ever
  sees the master password or decrypted profile config; the redaction policy
  applies to every response.
- Execution reuses the one-shot `invoke` path (scoped child process), so MCP
  adds no new credential or process surface.
- `resources/list` and `resources/read` are limited to non-secret,
  already-published material: the capability matrix and redacted profile
  references (IDs and policy metadata only).
- MVP is stateless tools only. Bridging agent sessions (SSH PTY share, SQL
  transactions, live streams, transfers) to MCP is deferred to 0.5 and named
  a non-goal below.
- Posture: beta, explicitly enabled (`vb mcp serve`), documented in a new
  `docs/mcp-server.md` plus an ADR recording the transport-choice decision
  (`docs/adr-mcp-agent-gateway.md`).

### Scope

In this repository:

- `vb mcp serve` implementation in `voidb-cli` with stdio transport,
  `initialize`, `tools/list`, `tools/call`, `resources/list`,
  `resources/read`; structured MCP errors map onto the existing error
  taxonomy (`category`/`code`/`retryable`).
- Grant enforcement tests: no grant → denied with guidance; read-only preset
  → destructive tool call rejected; TTL expiry mid-session → denied; revoke →
  immediate denial; audit entries carry the MCP principal identity.
- ADR, `docs/mcp-server.md`, README section, and matrix/experience docs
  updates.
- `scripts/mcp-fixture-smoke.sh`: drive the server with an MCP client
  fixture against a local SQLite profile, covering list, allowed call,
  denied destructive call, and redaction of an error path.

### Explicitly not in this workstream

MCP HTTP/SSE transport; prompts and sampling; resource templates; live
session bridging; tool-level write-through without broker grants.

## Non-goals (whole iteration)

- Sync roadmap items (recovery code at signup, failed-decrypt repair UX,
  automatic periodic sync, OAuth login, keyring token persistence).
- Team-share server API, invites, revoke, and audit storage.
- Long-lived process pooling; hosted marketplace beyond the static registry
  index; credential brokering beyond the current MVP.
- Deferred sessions other than the two named above: Sync agent sessions stay
  deferred; no S3/WebDAV live-session factories beyond the transfer contract.
- POP3 semantic reuse and any email send-path behavior change.

## Sequencing and Definition of Done

| Slice | Content | Depends on |
|---|---|---|
| A | Reconciliation audit + external work items filed | — |
| B | Email IDLE end-to-end (plugin + conformance + smoke) | A |
| C | S3/WebDAV transfer sessions end-to-end + reliability smokes | A |
| D | MCP MVP (`vb mcp serve` + ADR + docs + smoke) | A (independent of B/C) |
| E | Release: CHANGELOG, version bump to 0.4.1, matrix regen, readiness/docs map update, full workspace test + clippy tiers | B, C, D |

Per [ci-checks.md](ci-checks.md): fast crate tests for focused changes; the
full `cargo test --workspace --no-fail-fast` and
`cargo clippy --workspace --all-targets --no-deps` tiers run before the
release slice because this iteration touches credential, capability, and
validation-policy surfaces.

Definition of done per workstream: conformance run recorded, adoption matrix
updated, fixture smoke committed and green in CI, docs updated, and no
secrets, raw paths, or target metadata in audit or agent output.

## Documentation updates required

- `docs/persistent-agent-session-adoption.md` — Email, S3, WebDAV rows.
- `docs/storage-agent-transfer-contract.md` — mark reliability proofs as
  committed (remove "does not exist yet" caveat from this roadmap).
- `docs/agent-capability-examples.md`, `docs/agent-operator-guide.md` —
  IDLE, transfer, and MCP examples with grant guidance.
- `docs/readiness.md` documentation map — add this roadmap and
  `docs/mcp-server.md`; keep the generated matrix authoritative.
- New: `docs/mcp-server.md`, `docs/adr-mcp-agent-gateway.md`.
