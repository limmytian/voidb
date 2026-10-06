# CI Check Tiers

VoidB has a wide plugin surface, and some plugins pull heavy native dependencies.
In particular, `voidb-plugin-duckdb` builds `libduckdb-sys`, which can spend many
minutes compiling C++ code on a clean machine. Use tiered checks so common
feedback loops stay fast while full validation still runs before merging.
For release-candidate validation, use the unified
[Release Candidate Checklist](release-candidate-checklist.md) as the entry
point.

## Fast Local Checks

Use these while editing a focused area:

```bash
cargo test -p voidb-core
cargo test -p voidb-cli
cargo test -p voidb-plugin-sync
cargo test -p voidb-plugin-email
cargo test -p voidb-plugin-duckdb
cargo test -p voidb-tui
```

The aggregate runner preserves the same focused loop while producing
phase-addressable evidence:

```bash
python3 scripts/agent_tui_release_gate.py --profile focused
```

Pick the crates touched by the change and include shared crates that the change
depends on. Examples:

- Capability catalog, execution-mode, standalone-TUI registration, or release
  posture metadata: `scripts/check-agent-capability-matrix.sh`
- Core config, crypto, widgets, or shared traits: `cargo test -p voidb-core`
- CLI profile, plugin, audit, or invoke behavior: `cargo test -p voidb-cli`
- SQLite/Redis capability protocol pair:
  `cargo test -p voidb-plugin-sqlite`, `cargo test -p voidb-plugin-redis`,
  and `cargo test -p voidb-cli invoke`
- MySQL SQL capabilities:
  `cargo test -p voidb-plugin-mysql`, `cargo test -p voidb-cli invoke`, and
  `cargo test -p voidb-core sql_contract`
- PostgreSQL SQL capabilities:
  `cargo test -p voidb-plugin-postgres capabilities`,
  `cargo test -p voidb-cli invoke`, and `cargo test -p voidb-core sql_contract`
- DuckDB/Redis release-readiness decisions:
  `cargo test -p voidb-plugin-duckdb`,
  `cargo test -p voidb-plugin-redis`,
  `cargo test -p voidb-cli duckdb_and_redis_release_readiness_catalog`, and
  `cargo test -p voidb-core sql_contract`
- SSH capabilities, profile metadata, or host-key policy:
  `cargo test -p voidb-plugin-ssh`, `cargo test -p voidb-cli invoke`,
  `cargo test -p voidb-core profile_adapter`, and
  `cargo test -p voidb-core profile_store`
- Future plugin-owned standalone TUI launch code:
  `cargo test -p voidb-core tui_launch`,
  plus a plugin-owned PTY/lifecycle test target added with that future TUI.
  This gate is required only for newly accepted plugin-owned terminal apps.
- Process-plugin discovery or stdio runtime:
  `cargo test -p voidb-core process_plugin`,
  `cargo test -p voidb-core process_plugin_runtime`,
  `cargo test -p voidb-cli plugin`, and `cargo test -p voidb-cli invoke`
- TUI shell or Connection Manager default path: `cargo test -p voidb-tui`
- A plugin service or connection dialog: `cargo test -p voidb-plugin-<name>`
- Sync client changes: `cargo test -p voidb-plugin-sync`
- Sync beta readiness or object-sync boundary changes:
  `scripts/release-sync-smoke.sh` and `cargo test -p voidb-core object_sync`
- DuckDB table loading or service changes: `cargo test -p voidb-plugin-duckdb`
- Docker/Kubernetes external-agent context and operation review:
  `scripts/check-external-agent-interaction.sh`,
  `scripts/check-infrastructure-live-session-conformance.sh`,
  `cargo test -p voidb-core external_context`,
  `cargo test -p voidb-cli builtin::context`,
  `cargo test -p voidb-plugin-docker`,
  `cargo test -p voidb-plugin-kubernetes`, and `git diff --check`
- Redis/MongoDB/Elasticsearch live-session or cursor changes:
  `scripts/check-data-search-live-session-conformance.sh`. Use
  `scripts/check-data-search-live-session-conformance.sh --live` when a local
  Docker daemon is available to add disposable target evidence.
- Agent-triggered SSH/S3/WebDAV local filesystem access:
  `scripts/check-local-filesystem-boundaries.sh` and
  `scripts/check-external-agent-interaction.sh`

For formatting, avoid whole-repo churn until the repository has a clean
`cargo fmt --check` baseline. Format touched Rust files with the project edition:

```bash
rustfmt --edition 2024 path/to/file.rs
```

For focused code changes, run the relevant fast tests before committing. When a
change crosses crate boundaries, touches shared capability or credential code, or
updates validation policy, also run the full workspace tier below.

## Data And Search Live-Session Gate

The deterministic gate snapshots all six Redis, MongoDB, and Elasticsearch
live capability contracts, then checks bounded-buffer loss, source pacing,
resume policy, cursor scope, cancellation, authorization, redaction, audit,
plugin edge cases, and fixture-example compilation:

```bash
scripts/check-data-search-live-session-conformance.sh
```

The optional live tier provisions and tears down three isolated targets. It
verifies Redis Pub/Sub/MONITOR/Streams, MongoDB replica-set cursors/change
streams/bulk, and Elasticsearch PIT/scroll/bulk:

```bash
scripts/check-data-search-live-session-conformance.sh --live
```

Reports are written under `target/tmp/`; generated credentials and target
identifiers are restricted to fixture state and redacted evidence.

## Promoted Plugin Smoke Helper

Release-candidate preparation for SSH and MySQL can use
the secret-free helper:

```bash
scripts/release-plugin-smoke.sh
```

To focus one plugin:

```bash
scripts/release-plugin-smoke.sh --plugin ssh
```

The helper intentionally runs only local deterministic tests and
`git diff --check`; live service smoke remains opt-in and is documented in
Release Plugin Smoke.

S3 and other external process plugins are verified within their independent
repositories (`voidb-plugin-s3`, `voidb-plugin-webdav`, `voidb-plugin-email`,
`voidb-plugin-jenkins`).

## Local Docker Fixture Helper

Before relying on Docker-backed local fixtures for release evidence, run the
shared lifecycle helper:

```bash
scripts/local-fixture-smoke.sh run \
  --fixture probe \
  --report target/tmp/local-fixture-probe-evidence.md
git diff --check
```

This opt-in tier requires a usable local Docker daemon and the lightweight
probe image. It validates fixture network creation, random port assignment,
health waiting, redacted log capture, evidence writing, and teardown without
promoting any plugin. Plugin-specific local fixtures should extend the same
helper and use the evidence format in
[Live Fixture Smoke Harness](live-fixture-smoke-harness.md#evidence-format).

## Sync Smoke Helper

Sync client/server release smoke can use the secret-free helper:

```bash
scripts/release-sync-smoke.sh
```

To focus one side:

```bash
scripts/release-sync-smoke.sh --client-only
scripts/release-sync-smoke.sh --server-only
```

This runs the sync plugin e2e tests plus the standalone `voidb-sync-server`
test suite. The helper uses disposable in-process servers and temporary config
directories; hosted sync smoke remains opt-in and is documented in
Release Sync Smoke.
When a release rehearsal needs a real local server process, run:

```bash
scripts/release-sync-smoke.sh --hosted
```

The hosted run writes evidence under
`target/tmp/voidb-sync-hosted-smoke/<run-id>/evidence.md`.
The beta readiness decision and stable/default boundary are recorded in
Sync Beta Readiness.

## Package Smoke Helper

Release-candidate package staging can use the local artifact helper:

```bash
scripts/stage-release-artifacts.sh --build
scripts/package-smoke.sh \
  --artifact-root target/package/voidb-0.3.0-rc.1-darwin-arm64
git diff --check
```

The stage helper creates a platform-qualified artifact directory and writes
`SHA256SUMS` plus `artifact-manifest.json`. The smoke helper verifies executable
bits, checksum integrity, manifest consistency, CLI help/version output, sync
server help/version output, and TUI staging prerequisites. The retained
standalone TUI automated gate is:

```bash
scripts/tui-quality-gate.sh
```

It builds the CLI and TUI binaries, validates fixture-backed structural evidence,
then runs Connection Manager and all seven retained standalone TUIs through real
PTY journeys with blocking p50/p95, idle, cancellation, restoration, and cleanup
thresholds. Trend rows, failure captures, and a checksummed artifact manifest are
written under `target/tmp/tui-quality-gate/`. CI must retain that entire directory
on failure. Local reproduction and the required real-terminal emulator matrix are
defined in [TUI CI And Real-Terminal Coverage](tui-terminal-coverage.md); package
runner and platform-claim rules remain in Package CI Matrix.

## First Protocol Pair Gates

SQLite and Redis are the reference capability pair for local SQL and networked
key-value protocols. Changes to `sqlite.*`, `redis.*`, generic invoke, audit
summaries, pagination controls, destructive-operation policy, target errors, or
redaction should run this focused test gate:

```bash
cargo test -p voidb-plugin-sqlite
cargo test -p voidb-plugin-redis
cargo test -p voidb-cli invoke
git diff --check
```

For release candidates, broad capability changes, or any change that modifies
shared validation and policy behavior used by this pair, add the focused clippy
gate before the full workspace tier:

```bash
cargo clippy -p voidb-plugin-sqlite --all-targets --no-deps
cargo clippy -p voidb-plugin-redis --all-targets --no-deps
cargo clippy -p voidb-cli --all-targets --no-deps
```

These gates prove the first-pair contract stays stable in three places:
capability metadata discovery, direct plugin invocation handlers, and the
agent-facing generic invoke CLI. They intentionally avoid requiring an external
Redis server; Redis target-error coverage uses deterministic unavailable-service
tests and dry-run paths.
Release-readiness decisions for Redis are recorded in
DuckDB and Redis Release Readiness.

## MySQL Capability Gates

MySQL is the first networked SQL plugin on the shared SQL contract. Changes to
`mysql.query`, `mysql.exec`, `mysql.tables`, `mysql.describe_table`, MySQL
profile diagnostics, generic invoke registration, or SQL contract validation
should run:

```bash
cargo check -p voidb-plugin-mysql --example fixture_smoke
cargo test -p voidb-plugin-mysql
cargo test -p voidb-cli invoke
cargo test -p voidb-core sql_contract
scripts/mysql-fixture-smoke.sh --report target/tmp/mysql-fixture-smoke-evidence.md
git diff --check
```

These tests include deterministic fixtures for schema discovery, policy, dry
run, redaction, unavailable target errors, and database-selection validation.
The fixture-smoke script provisions its own local MySQL server through the
shared Docker fixture harness, so it does not require external credentials.

The older ignored test remains available when an already provisioned disposable
target is useful:

```bash
cargo test -p voidb-plugin-mysql --test capability_fixtures \
  live_mysql_query_metadata_smoke -- --ignored
```

Set `VOIDB_MYSQL_TEST_HOST`, `VOIDB_MYSQL_TEST_PORT`,
`VOIDB_MYSQL_TEST_USER`, `VOIDB_MYSQL_TEST_PASSWORD`, and
`VOIDB_MYSQL_TEST_DATABASE` for the live target.
Release-readiness decisions for MySQL are recorded in
MySQL Release Readiness.

## PostgreSQL Capability Gate

PostgreSQL follows the same shared SQL contract as MySQL while preserving
legacy `postgresql` profile compatibility. Changes to `postgres.query`,
`postgres.exec`, `postgres.tables`, `postgres.describe_table`, generic invoke
registration, or SQL contract validation should run:

```bash
cargo test -p voidb-plugin-postgres capabilities
cargo test -p voidb-cli invoke
cargo test -p voidb-core sql_contract
git diff --check
```

This gate is secret-free and does not require a live PostgreSQL server. Add an
opt-in live PostgreSQL smoke only after a disposable fixture exists.

## DuckDB Capability Gate

DuckDB follows the shared SQL contract for local analytics profiles while
keeping the bundled native driver behind `DuckDbService` and `SyncWorker`.
Changes to `duckdb.query`, `duckdb.exec`, `duckdb.tables`,
`duckdb.describe_table`, generic invoke registration, or SQL contract
validation should run:

```bash
cargo test -p voidb-plugin-duckdb
cargo test -p voidb-cli invoke
cargo test -p voidb-core sql_contract
git diff --check
```

This gate uses temporary DuckDB databases and does not require a live service.
Keep broader DuckDB native build cost out of unrelated fast gates.
Release-readiness decisions for DuckDB are recorded in
DuckDB and Redis Release Readiness.

## Operations Plugin Capability Gates

Docker, Kubernetes, MongoDB, and Elasticsearch expose agent-facing
infrastructure, document/search, and CI capabilities. Changes to their generic
invoke registration, bounded output contracts, destructive gates, or fixture
promotion status should run:

```bash
cargo test -p voidb-plugin-docker -p voidb-plugin-kubernetes \
  -p voidb-plugin-mongodb -p voidb-plugin-elasticsearch capabilities
cargo test -p voidb-cli invoke
git diff --check
```

These checks are secret-free and do not require live targets. Fixture-backed
promotion results are recorded in
Fixture-Backed Operations Plugin Promotion Smoke 2026-07-05.
Docker completed disposable daemon smoke in Req50; Kubernetes, MongoDB,
and Elasticsearch were still fixture-pending at that point. Req67
completed Kubernetes local kind fixture-backed capability evidence in
Kubernetes Release Readiness. Req68
completed MongoDB local fixture-backed capability evidence in
MongoDB Release Readiness. Req69 completed
Elasticsearch local fixture-backed capability evidence in
Elasticsearch Release Readiness. Use the local
fixture probe first when those fixtures are provisioned through the shared local
Docker harness:

```bash
scripts/local-fixture-smoke.sh run --fixture probe
```

For MongoDB release-candidate checks after capability changes, run:

```bash
scripts/mongodb-fixture-smoke.sh --report target/tmp/mongodb-fixture-smoke-evidence.md
```

For Elasticsearch release-candidate checks after capability changes, run:

```bash
scripts/elasticsearch-fixture-smoke.sh --report target/tmp/elasticsearch-fixture-smoke-evidence.md
```

## External-Agent Interaction Gates

Any change to session sharing, TUI context sharing, structured agent operation
review, or the capability-only plugin boundary must first run:

```bash
scripts/check-external-agent-interaction.sh
git diff --check
```

The script scans all runtime source for retired conversation workflows, proves
that the ten capability-only plugins contain no share/frontend module, verifies
the SSH and infrastructure evidence markers and local plan/denial tests, checks
the normative plugin matrix, and requires supersession banners on Requirements
88-92 historical evidence.

Infrastructure live-session changes additionally run the shared deterministic
conformance suite:

```bash
scripts/check-infrastructure-live-session-conformance.sh
```

That gate exercises every Docker, Kubernetes, and Jenkins live capability
family through the same bounded-buffer, slow-consumer, reconnect/resume,
cancel/timeout, close, authorization, redaction, and audit assertions. It then
runs each full plugin suite, which includes the representative standalone-TUI
fixture, local operation-plan staging, and denial flows.

Shared cursor or stream-envelope changes also run:

```bash
cargo test -p voidb-core live_session
```

That focused gate covers protocol-v1 compatibility, scoped resume cursors,
sequence-bound checkpoints, heartbeat validation, structured pull timeout,
truncation accounting, and buffered versus source-paced backpressure. The
Redis/MongoDB/Elasticsearch capability and factory implementations additionally
run their plugin tests. Native live-target fixtures and a shared data/search
conformance script remain a separate promotion gate.

Shared S3/WebDAV transfer-contract changes run:

```bash
cargo test -p voidb-core transfer
cargo test -p voidb-plugin-s3
cargo test -p voidb-plugin-webdav
cargo test -p voidb-cli storage_plugins_map_to_one_fail_closed_transfer_lifecycle
scripts/check-local-filesystem-boundaries.sh
scripts/check-external-agent-interaction.sh
git diff --check
```

The descriptor-only contract must leave discovery fail-closed until both a
validated session handoff and a plugin-owned factory exist. Service slices add
the relevant MinIO/WebDAV fixture gates; reliability slices add interruption,
resume, checksum, conflict, cancellation, and cleanup fault injection.

Choose the relevant focused group in addition to the script:

```bash
# Shared context-share and operation contract
cargo test -p voidb-core assist
cargo test -p voidb-core session
cargo test -p voidb-cli agent_broker

# SSH live PTY sharing and infrastructure current-view sharing
cargo test -p voidb-plugin-ssh
cargo test -p voidb-plugin-docker -p voidb-plugin-kubernetes --no-fail-fast

# Capability-only data, search, storage, and messaging plugins
cargo test -p voidb-core sql_contract
cargo test -p voidb-plugin-mysql -p voidb-plugin-postgres \
  -p voidb-plugin-sqlite -p voidb-plugin-duckdb --no-fail-fast
cargo test -p voidb-plugin-mongodb -p voidb-plugin-redis \
  -p voidb-plugin-elasticsearch --no-fail-fast
cargo test -p voidb-plugin-s3 -p voidb-plugin-webdav \
  -p voidb-plugin-email --no-fail-fast
cargo test -p voidb-cli invoke
```

The capability suites must retain SQL/document/cache mutation classification,
storage destructive dry-run and acknowledgement, bounded output, target-error
redaction, and Email guarded-mutation denial/preview behavior. They must not recreate a TUI
or advertise a live-session family without both a validated shared descriptor
and a plugin-owned factory. Cross-plugin or requirement-level changes also run
the full workspace test and Clippy tiers below. See
External-Agent Interaction Evidence.

## SSH Capability and TUI Smoke Gates

SSH is both an interactive human TUI plugin and an agent-facing capability
plugin. Changes to `ssh.*` capabilities, SSH profile metadata, generic invoke
registration, host-key verification, redaction, SFTP behavior, human or
agent-owned terminal session lifecycle, or forwarding should run:

```bash
cargo test -p voidb-plugin-ssh capabilities
cargo test -p voidb-plugin-ssh service
cargo test -p voidb-plugin-ssh
cargo test -p voidb-cli invoke
cargo test -p voidb-core profile_adapter
cargo test -p voidb-core profile_store
git diff --check
```

These checks cover deterministic capability metadata, dry-run and destructive
policy, strict non-interactive host-key errors, bounded command output, SFTP
pagination and transfer metadata, profile credential refs, and redacted SSH
diagnostics. Agent-owned PTY changes must additionally retain bounded offset
windows, gap reporting, redacted snapshots, password-prompt input blocking,
Custom-only destructive control, and close/lease/revoke behavior. The offline
checks intentionally do not require a live SSH server; run
`scripts/ssh-fixture-smoke.sh` before promotion when the PTY transport changes.

Changes to SSH external-session sharing, agent operation requests, approval,
current-PTY ownership, compatibility audit identifiers, or evidence should also
run the focused session-share subset and regenerate deterministic TUI evidence:

```bash
cargo test -p voidb-core assist
cargo test -p voidb-core external_context
cargo test -p voidb-cli builtin::context
cargo test -p voidb-core session
cargo test -p voidb-cli agent_broker
cargo test -p voidb-plugin-ssh
scripts/check-external-agent-interaction.sh
cargo run -p voidb-cli -- ssh tui \
  --fixture crates/plugins/voidb-plugin-ssh/fixtures/ssh_tui_terminal_core.json \
  --evidence target/tmp/ssh-tui-fixture-evidence.json
```

The session-share subset covers snapshot redaction and live refresh, stale
generations, store cancel/close behavior, external operation review,
one-shot decision and replay rejection, same-agent approvals, single-writer
current-PTY ownership, operator-reviewed terminal-state warnings, TTL/revoke
behavior, blocked takeover contexts, and marker-based secret-leak scanning. The
evidence artifact must stay under `target/tmp`; do not commit generated
share-store records or fixture credentials.

Changes to the shared non-PTY context-share contract used by SSH, Docker,
or Kubernetes should run:

```bash
cargo test -p voidb-core assist
cargo test -p voidb-core external_context
cargo test -p voidb-cli builtin::context
cargo test -p voidb-core session
cargo test -p voidb-plugin-ssh
cargo test -p voidb-plugin-docker -p voidb-plugin-kubernetes --no-fail-fast
scripts/check-external-agent-interaction.sh
scripts/check-external-context-handoff.sh
git diff --check
```

These checks prove that non-PTY context-share stores reject
`take_control`/`CurrentPty` and multi-action operations, atomically bind
principals, preserve exact-retry idempotency, reject replay substitutions,
project indexed allow/deny status, bound waits, block stale generations, keep
TUI polling non-blocking, detect crashed TUI owners through private OS-locked
leases, recover with a replacement context, and isolate current-PTY behavior in
the SSH plugin. The real-PTY conformance report must show the same six scenarios
for Docker, Kubernetes, and Jenkins.

Run the fixture-backed manual smoke before a release candidate or after broad
SSH UI/session changes. The fixture strategy and command list live in
[SSH Plugin](ssh-plugin.md).

For release candidates or broad SSH security policy changes, add:

```bash
cargo clippy -p voidb-plugin-ssh --all-targets --no-deps
cargo clippy -p voidb-cli --all-targets --no-deps
```

## Process Plugin Runtime Gates

Process plugins are local executable code loaded from documented roots and
invoked over stdio JSON-RPC. Changes to process-plugin discovery, manifest
validation, trust roots, runtime command resolution, stdio protocol handling,
timeouts, cancellation, crash diagnostics, stderr redaction, or generic
process-plugin invocation should run:

```bash
cargo test -p voidb-core process_plugin
cargo test -p voidb-core process_plugin_runtime
cargo test -p voidb-cli plugin
cargo test -p voidb-cli invoke
git diff --check
```

This gate uses deterministic fixture plugins and does not require installing an
external plugin package. It covers:

- documented root precedence, trust levels, and invalid-candidate isolation;
- manifest schema, protocol, transport, schema-ref, and capability metadata
  diagnostics;
- package-local runtime command resolution and explicit development-root
  `PATH` fallback;
- initialization, health, invocation, timeout, crash, malformed protocol,
  graceful shutdown, and redacted stderr behavior;
- CLI plugin discovery output and generic process-plugin invocation routing.

For release candidates or broad runtime policy changes, add:

```bash
cargo clippy -p voidb-core --all-targets --no-deps
cargo clippy -p voidb-cli --all-targets --no-deps
```

## Full Workspace Checks

Run this before merging broad changes or release candidates:

```bash
cargo test --workspace --no-fail-fast
```

This validates all workspace members, integration tests, and doctests. On a clean
machine it may take 20+ minutes because `libduckdb-sys` compiles bundled DuckDB
C++ sources.

Run full linting as a separate full-tier job:

```bash
cargo clippy --workspace --all-targets --no-deps
```

The one-command requirement/release equivalent is:

```bash
python3 scripts/agent_tui_release_gate.py --profile full
```

See [Agent and TUI Aggregate Release Gate](agent-tui-release-gate.md) for the
deterministic journey plan, retained evidence, failure triage, and optional
`--live-fixtures` tier.

## Warning Budget Policy

The full clippy gate is currently a zero-error gate with a tracked warning
budget, not a zero-warning gate. `cargo clippy --workspace --all-targets
--no-deps` must exit successfully. The remaining warnings are accepted only when
they match the dated inventory in
Warning Budget Inventory and are not expanded by
the current change.

Accepted temporary warnings:

- existing Clippy warning locations and lint classes already recorded in the
  warning budget inventory, when they are outside files changed by the current
  patch;
- documented example or fixture warnings outside touched code, when they are
  recorded in the current baseline or release notes.

Regressions:

- any new Clippy warning or Rust compiler warning in a touched Rust file;
- any new warning class or new warning source crate not listed in the warning
  budget inventory;
- any future-incompatibility notice;
- any change that suppresses warnings by adding broad `allow` attributes instead
  of fixing the local issue or documenting a narrow exception;
- any clippy error, test failure, or `git diff --check` failure.

For focused warning-cleanup work, the touched-crate clippy command should be
clean for the crate being cleaned. If inherited warnings remain in the same
crate but outside the cleanup scope, record the exact inherited class in the
slice summary and keep the diff limited to the selected warning group.

| Touched area | Required focused checks | Clean expectation |
|---|---|---|
| Rust code in one crate | `cargo test -p <crate>` and `cargo clippy -p <crate> --all-targets --no-deps` | No warnings from touched files. Warning-cleanup slices should leave the selected crate clean unless unrelated inherited warnings are explicitly recorded. |
| TUI shell or default TUI | `cargo test -p voidb-tui` and `cargo clippy -p voidb-tui --all-targets --no-deps` | No new shell or tab-routing warnings. |
| Sync server | `cargo test --manifest-path voidb-sync-server/Cargo.toml` and `cargo clippy --manifest-path voidb-sync-server/Cargo.toml --all-targets --no-deps` | Standalone server checks should stay clean. |
| Shared capability, credential, validation, release, or CI policy code | Relevant focused tests from this document plus the full workspace and full lint tiers when practical | No new warning classes; full clippy may report only accepted budget items. |
| Documentation-only changes | `git diff --check` | No whitespace or Markdown churn outside the touched policy surface. |

## Suggested CI Layout

| Tier | Trigger | Commands | Notes |
|---|---|---|---|
| Aggregate Agent/TUI release | Requirement or release boundary | `python3 scripts/agent_tui_release_gate.py --profile full` | Runs the current focused and deterministic Agent/TUI journeys, full workspace tests, and full Clippy with per-phase evidence. |
| Agent capability matrix | Pull request touching built-in capability metadata, session handoffs, standalone TUI registration, or readiness posture | `scripts/check-agent-capability-matrix.sh` | Regenerates the repository-owned matrix from runtime definitions and fails on added, removed, changed, or undocumented rows. |
| Fast core | Pull request, every push | `cargo test -p voidb-core` | Catches shared API, crypto, config, widget regressions. |
| Fast CLI | Pull request touching `crates/voidb-cli` | `cargo test -p voidb-cli` | Catches profile, invoke, audit, and plugin command regressions. |
| Promoted plugin smoke | Release-candidate prep or plugin smoke doc changes | `scripts/release-plugin-smoke.sh` | Runs secret-free focused checks for SSH and MySQL; local fixture wrappers cover promoted Docker-backed services such as Kubernetes and MongoDB when provisioned; live service commands stay opt-in. |
| Sync smoke | Release-candidate prep or sync client/server changes | `scripts/release-sync-smoke.sh` | Runs sync plugin e2e tests and standalone sync server smoke with disposable local state. |
| Package smoke | Release-candidate prep or package automation changes | `scripts/stage-release-artifacts.sh --build`; `scripts/package-smoke.sh --artifact-root target/package/voidb-<version>-<platform>` | Stages default TUI, CLI, and sync-server artifacts; verifies checksums, manifest consistency, executable bits, CLI and sync-server entry points, and TUI prerequisites. Use Package CI Matrix for macOS, Linux, Windows, and runner-skip rules. |
| First protocol pair | Pull request touching SQLite/Redis capabilities or generic invoke | `cargo test -p voidb-plugin-sqlite`; `cargo test -p voidb-plugin-redis`; `cargo test -p voidb-cli invoke` | Proves the SQLite/Redis reference capability pair, including pagination, dry-run, structured target errors, and redaction. |
| MySQL capability | Pull request touching MySQL SQL capabilities or diagnostics | `cargo check -p voidb-plugin-mysql --example fixture_smoke`; `cargo test -p voidb-plugin-mysql`; `cargo test -p voidb-cli invoke`; `cargo test -p voidb-core sql_contract`; `scripts/mysql-fixture-smoke.sh --report target/tmp/mysql-fixture-smoke-evidence.md` | Proves the first networked SQL capability path through a disposable local fixture without external credentials. |
| MongoDB capability | Pull request touching MongoDB document capabilities or diagnostics | `cargo check -p voidb-plugin-mongodb --example fixture_smoke`; `cargo test -p voidb-plugin-mongodb`; `cargo test -p voidb-cli invoke`; `scripts/mongodb-fixture-smoke.sh --report target/tmp/mongodb-fixture-smoke-evidence.md` | Proves the MongoDB capability path through a disposable local fixture without external credentials. |
| External-agent interaction | Pull request touching SSH session sharing, Docker/Kubernetes/Jenkins current-view sharing, capability-only plugin boundaries, or related docs | `scripts/check-external-agent-interaction.sh`; relevant plugin tests from the focused group above | Prevents retired conversation UI, protects capability-only plugins, and verifies session/context-share operation gates. |
| Local filesystem boundary | Pull request touching agent-triggered local reads, writes, scans, transfer staging, SSH SFTP, or authorization/audit projection | `scripts/check-local-filesystem-boundaries.sh`; `scripts/check-external-agent-interaction.sh` | Proves traversal/alias rejection, Unicode handling, no-follow behavior, root-identity conflicts, no-replace races, bounded scans, capability-wide denial, and audit redaction across the affected plugins. |
| SSH capability and TUI smoke | Pull request touching SSH capabilities, profiles, host-key policy, terminal/SFTP/forwarding sessions, external-agent sharing, or generic invoke | `cargo test -p voidb-plugin-ssh`; `cargo test -p voidb-cli invoke`; `cargo test -p voidb-core profile_adapter`; `cargo test -p voidb-core profile_store`; for sharing changes also `cargo test -p voidb-core assist`, `cargo test -p voidb-core session`, `cargo test -p voidb-cli agent_broker`, `scripts/check-external-agent-interaction.sh`, and the SSH TUI `--evidence` command above | Proves SSH capability metadata, strict non-interactive host-key errors, destructive gates, profile redaction, session-share redaction/confirmation/revoke behavior, and the documented manual fixture smoke boundary. |
| Process plugin runtime/package management | Pull request touching process-plugin discovery, manifests, trust roots, package install/update/lifecycle commands, stdio runtime, or process invocation | `cargo test -p voidb-core process_plugin`; `cargo test -p voidb-core process_plugin_runtime`; `cargo test -p voidb-cli plugin`; `cargo test -p voidb-cli invoke` | Proves deterministic local process-plugin discovery, package validation, compatibility diagnostics, lifecycle handling, and redacted runtime failures. |
| Fast TUI | Pull request touching `crates/voidb-tui` | `cargo test -p voidb-tui` | Builds the default lightweight TUI surface: shell, tab manager, and Connection Manager only. |
| Fast plugin | Pull request touching one plugin | `cargo test -p voidb-plugin-<name>` | Keeps plugin feedback scoped. |
| Full workspace | Merge queue, nightly, release candidate | `cargo test --workspace --no-fail-fast` | Slow but authoritative; includes DuckDB native build. |
| Full lint | Nightly, release candidate | `cargo clippy --workspace --all-targets --no-deps` | Keep separate from fast tests to avoid slowing every push. |

## Current Baseline

As of 2026-07-13, focused migration tests and
`cargo clippy --workspace --all-targets --no-deps` pass from `main` with the
accepted warning budget. `cargo test --workspace --no-fail-fast` passes all
deterministic targets; the hosted Sync E2E may occasionally receive an external
HTTP 502 and must pass an immediate exact rerun before the failure is classified
as transient. No deterministic DuckDB or heavy-plugin failures are known.

The observed warnings that remain accepted are unrelated to current release
gates.

As of 2026-07-05, `cargo clippy --workspace --all-targets --no-deps` exits
successfully, but the workspace still has non-blocking clippy warnings. The
current warning buckets and cleanup order are recorded in
Warning Budget Inventory.
Use the warning budget policy above for accepted temporary warnings, regressions,
and touched-crate clean-check expectations. Clean up inherited warning groups in
focused follow-up slices rather than mixing broad lint churn into feature work.
