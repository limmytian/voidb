# 0.4.2 Iteration Roadmap

This roadmap scopes the 0.4.2 iteration. Iteration work happens on the
`0.4.2` branch; `main` receives only merged, validated slices. As with the
0.3.x/0.4.x series, 0.4.2 carries additive features on top of v0.4.1.

Scope decisions (agreed 2026-11-07): the per-plugin TUI mutation backlog
is **excluded** (deferred to 0.5); the TUI template dedup starts as
**design + pilot** only.

## Current State Baseline

Verified at the start of the iteration:

- v0.4.1 is released (core + all 14 plugins at v0.3.6); the registry serves
  0.3.6 with ed25519 signatures and `voidb_core >= 0.4.1`.
- The session stack is live end to end: SDK `SessionBridge`/
  `CoreSessionAdapter`, all 13 external plugins register factories, and the
  broker opens sessions against installed binaries (docker verified:
  `health: ready`, call returns bounded log events, close clean).
- `vb plugin update --all` shipped on `main` after v0.4.1 (already in the
  `[Unreleased]` changelog section).
- `vb profile create/update/validate` are documented in
  [Connection Profile CLI Contract](connection-profile-cli.md) with a full
  contract (schema-driven fields, `--credential` secret sources,
  secret-in-payload rejection, `--expected-version` optimistic concurrency)
  but **do not exist in the CLI** — the profile CLI only ships
  `list/show/test/migrate`. Users can only create profiles through the TUI
  or legacy migration.

## Workstream 1 — Profile Lifecycle CLI (top user-facing gap)

**Goal:** close the documented-but-missing profile management commands so
the CLI contract in
[Connection Profile CLI Contract](connection-profile-cli.md) matches
reality.

### Scope (this repository)

- `vb profile create` — schema-driven creation: load the plugin's declared
  profile schema (`connections.profile_schema`), accept `--input` JSON,
  validate against the schema, reject secret-shaped fields in the payload
  with the documented `validation.secret_in_profile_payload` error, assign
  the immutable Profile ID, and honor per-plugin name uniqueness.
- `vb profile create --credential <class>:env=VAR|file=PATH` — secret
  sources convert into credential references before any agent-facing output;
  secret values never echo into stdout, stderr, logs, or audit.
- `vb profile update <ref>` — full/partial document update with
  `--expected-version` optimistic concurrency (conflict →
  `conflict.profile_version_mismatch`), credential add/replace, and the same
  secret-source rules.
- `vb profile validate` — validate a profile document without writing.
- Schema-driven interactive prompts for terminal users; JSON envelope
  parity with the rest of the profile commands.

### Deliverables

- Implementation in `crates/voidb-cli/src/builtin/profile.rs` reusing
  `LocalProfileStore` (create/update native profiles), the schema-driven
  form machinery the TUI already uses, and `grant_credentials_for_invocation`-style
  secret-source parsing.
- Tests: policy (secret rejection), optimistic concurrency, schema
  validation, name uniqueness, envelope shape.
- `docs/connection-profile-cli.md` gains shipped-command status; README and
  the readiness documentation map updated.

## Workstream 2 — Plugin Release Automation (S)

**Goal:** the registry updates itself when a plugin is released; nobody
re-runs `update-registry.yml` by hand.

### Scope (14 plugin repositories + template)

- Add a `repository_dispatch(plugin_released)` step at the end of each
  plugin's `release.yml` (after the signed payload publishes), targeting the
  core repository with `client_payload.release = v<version>`.
- Apply the same step to `.github/workflows/templates/plugin-release.yml`
  so future plugin repos inherit it.
- Verify the chain end to end with one patch release after wiring (this
  doubles as the Workstream 3 release vehicle).

## Workstream 3 — Quality and Security Batch (M)

**Goal:** close the survey findings that are small per-repo but broad.

### Scope

- **mongodb `diagnostics` is a config-only stub** — wire a real `hello`/
  `serverStatus` round-trip with redacted output.
- **mysql/postgres identifier escaping inconsistency** — `crud.rs` and
  `data_loader.rs` interpolate identifiers without the quoting that
  `browser.rs` applies; unify on the escaping helper (or a parameterized
  path) with tests.
- **Plugin config parse fail-closed** — replace `unwrap_or_default()` in
  every plugin `main.rs` (config typos silently become default configs) with
  a structured validation error naming the offending field.
- **CI gating** — remove `continue-on-error: true` from `cargo fmt --check`
  across the 14 plugin repositories and the core; wire the existing
  fixture-smoke examples into CI where a driver script exists (kubernetes,
  ssh, mysql, redis).
- **docker TLS design note** — investigate bollard 0.20 TLS support; either
  implement or record the fail-closed decision with an upgrade path in the
  plugin README.

## Workstream 4 — TUI Dedup: Design + Pilot

**Goal:** stop the one-line-fans-out-to-14-repos template drift without
touching every TUI's regression surface at once.

### Scope

- ADR: shared TUI kit location (SDK-adjacent crate vs workspace crate),
  ownership boundary (what is shared vs plugin-owned), versioning, and the
  migration order.
- Hoist the proven-duplicated helpers first: `safe_error_summary`,
  `window_start`, `centered_rect`, bounded-line buffers, the overlay/plan
  confirmation flow, and the startup auto-load rule.
- Pilot migration: two plugins (docker + jenkins) onto the shared kit with
  their full test suites green; the remaining twelve stay on the template
  until 0.5.
- Startup auto-load regression test in fixture mode (asserts the initial
  refresh command is queued), locking the 0.4.1 acceptance criterion.

## Workstream 5 — Release Slice

- Core version 0.4.2, changelog, registry untouched for core (not a plugin).
- Plugin patch releases (0.3.7) only for repositories with changes —
  exercised through the Workstream 2 automation as the end-to-end proof.
- Full workspace test + clippy tiers; plugin tests per repo.

## Non-goals (whole iteration)

- Per-plugin TUI mutation backlog (postgres mutations, redis edit dialogs,
  duckdb console/LIST-STRUCT decode, mongodb indexes view, ES index
  management, mysql server view) — deferred to 0.5.
- Full TUI dedup migration beyond the two-plugin pilot.
- MCP live-session bridging and HTTP/SSE transport (0.5).
- Sync TUI repair UX, periodic sync scheduler, OAuth login.

## Sequencing and Definition of Done

| Slice | Content | Depends on |
|---|---|---|
| 1 | Profile lifecycle CLI | — |
| 2 | Plugin release automation (14 + template) | — |
| 3 | Quality/security batch (mongodb, mysql/postgres, config parsing, CI gating) | — |
| 4 | TUI dedup ADR + kit + two-plugin pilot | — |
| 5 | Release: 0.4.2 core + patch plugin releases via the new automation | 2, 3 |

Slices 1–4 are mutually independent. Per
[ci-checks.md](ci-checks.md): fast crate tests for focused changes; full
`cargo test --workspace --no-fail-fast` and
`cargo clippy --workspace --all-targets --no-deps` before the release slice.

## Documentation updates required

- `docs/connection-profile-cli.md` — shipped-command status for
  create/update/validate.
- `docs/plugin-installation-model.md` — release-automation notes.
- New: TUI kit ADR.
- `docs/readiness.md` documentation map — add this roadmap and the ADR.
