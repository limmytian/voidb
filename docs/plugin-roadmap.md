# Plugin Maturity and Release Gates

> **Historical planning inventory.** The detailed classifications and
> priorities below record the Req46-Req83 release program and include claims
> superseded by later capability work. Use the generated
> [Agent Capability and Experience Matrix](agent-capability-matrix.md) for
> current plugin posture and [Release Candidate Checklist](release-candidate-checklist.md)
> for current validation. See [Readiness Documentation Map](readiness.md) for
> document ownership.

This document preserves the earlier plugin maturity rubric, promotion sequence,
and release gates. Its linked reports are point-in-time evidence.

Maturity labels are release-planning signals, not API compatibility promises.
Capability and CLI readiness is the release surface. The default TUI contains
the shell, tab manager, and Connection Manager; legacy database/browser UIs and
old router-hosted plugin factories are intentionally removed.

- **Release candidate**: covered by focused capability/CLI tests and expected
  to stay enabled for the next release after smoke testing.
- **Beta**: useful, but needs broader manual smoke coverage, service-layer
  hardening, or UX validation before being called stable.
- **Experimental**: present in the workspace, but should be treated as opt-in
  until its feature scope, tests, and failure behavior are tightened.
- **Platform / internal**: part of the shell or supporting infrastructure rather
  than a standalone end-user data-source plugin.

## Historical Plugin Classification Snapshot

| Plugin | Role | Maturity | Release gate focus |
|--------|------|----------|--------------------|
| Connection Manager | Connection catalog and plugin launcher | Platform / internal | Add/edit/delete, test connection, CLI/capability guidance, encrypted config save. |
| MySQL | SQL database | Release candidate / CLI-first | Service-mode queries, capability migration, shared SQL contract, diagnostics, and fixture-backed SQL smoke. |
| PostgreSQL | SQL database | Release candidate / CLI-first | Service-mode query and metadata parity, shared SQL contract, diagnostics, and opt-in live PostgreSQL smoke. |
| SQLite | Embedded SQL database | Release candidate / CLI-first | `SyncWorker` path, local file handling, capability schemas, shared SQL contract, and bounded local SQL operations. |
| DuckDB | Embedded analytics database | Beta certified / CLI-first | Shared SQL `duckdb.query`/`exec`/`tables`/`describe_table`, `SyncWorker` path, bounded result paging, dry-run mutation gates, and DuckDB native build cost. |
| Redis | Key-value database | Release candidate / CLI-first | Fixture-backed capability scans/reads/writes, bounded values and raw command output, dry-run mutation gates, timeout/error handling. |
| MongoDB | Document database | Release candidate / CLI-first | Req68 fixture-backed `mongodb.*` invoke capabilities for bounded databases, collections, find, count, aggregate, indexes, and dry-run/ack-gated insert/update/delete/create_index/run_command. |
| Elasticsearch | Search database | Release candidate / CLI-first | Req69 fixture-backed `elasticsearch.*` invoke capabilities for health, nodes, indices, search, get, count, mapping, and dry-run/ack-gated raw API calls. |
| Email | IMAP/POP3 + SMTP | Release candidate / CLI-first | Read-only `email.*` invoke capabilities, TLS verification default, bounded mailbox reads, deferred send/delete gates, and Req62 local disposable mailbox fixture smoke. |
| SSH | SSH/SFTP | Release candidate / CLI-first | `ssh.*` capabilities, strict non-interactive host-key behavior, SFTP/forwarding service smoke, key/password/agent auth, profile redaction. |
| Docker | Infrastructure | Release candidate / CLI-first | `docker.*` invoke capabilities for bounded diagnostics/list/inspect/logs and dry-run/ack-gated lifecycle actions; Req50 completed disposable daemon smoke. |
| Kubernetes | Infrastructure | Release candidate / CLI-first | `kubernetes.*` invoke capabilities for contexts, resource browsing, bounded YAML/logs, dry-run/ack-gated delete/apply/scale/restart, and Req67 local kind fixture smoke. |
| WebDAV | Storage | Release candidate / CLI-first | `webdav.*` invoke capabilities, bounded list/get output, dry-run/ack-gated writes, sync planning, credential handling, opt-in fixture smoke. |
| S3 | Object storage | Release candidate / CLI-first | `s3.*` invoke capabilities, bounded list/get output, dry-run/ack-gated writes, sync planning, credential handling, opt-in fixture smoke. |
| Jenkins | CI service | Release candidate / CLI-first | Req70 fixture-backed `jenkins.*` invoke capabilities for diagnostics, jobs, job detail, activity, bounded console, pipeline metadata, and dry-run/ack-gated trigger/abort/queue cancel. |
| Sync | Encrypted config sync client | Beta certified / opt-in | Object-level profile/credential sync, encrypted payload invariants, conflict helpers, local/server smoke, and explicit stable/default boundary. |

## Data Inspector TUI Status

Requirement 83 accepts no data inspector TUI pilot. MySQL, PostgreSQL, and
DuckDB remain `CLI-only`. SQLite, Redis, MongoDB, and Elasticsearch are
`Later candidate` surfaces but still ship as CLI-only until a future
plugin-owned pilot passes the data inspector gate in
[Data Inspector CLI-First Decisions](data-inspector-cli-first-decisions.md).
Release notes and UI copy must not advertise `mysql tui`, `postgres tui`,
`sqlite tui`, `duckdb tui`, `redis tui`, `mongodb tui`, or `elasticsearch tui`.

## Cloud Operations Promotion Evidence

TW 42 slice 1 promotes S3, WebDAV, and SSH to release-candidate status for the
agent-facing capability surface. The evidence and remaining live-smoke boundary
are recorded in Cloud Operations Promotion Slice 1.
TW 42 slice 2 certifies Docker, Kubernetes, MongoDB, and Elasticsearch beta
capability surfaces. Their deterministic evidence and live-fixture boundary are
recorded in Cloud Operations Promotion Slice 2.
The final maturity decisions, skipped live checks, and follow-up boundary are
recorded in Cloud Operations Promotion Report.
Req50 adds fixture-backed promotion evidence in
Fixture-Backed Operations Plugin Promotion Smoke 2026-07-05.
Req55 starts the next fixture-backed promotion wave with a shared
Live Fixture Smoke Harness for Email, Redis,
Kubernetes, MongoDB, Elasticsearch, and Jenkins. Its final decisions are in
Beta Plugin Fixture Promotion Report 2026-07-05:
all six live fixtures were skipped at that point. Req61 later completed Redis
local fixture-backed capability smoke and moved Redis onto the release-candidate
path for the capability surface. Req62 later completed Email local fixture
lifecycle and read-only capability smoke, promoting Email for the read-only
fixture-backed capability surface. Req67 later completed Kubernetes local kind
fixture lifecycle and capability smoke, promoting Kubernetes for the
fixture-backed capability surface. Req68 later completed MongoDB local fixture
lifecycle and capability smoke, promoting MongoDB for the fixture-backed
capability surface. Req69 later completed Elasticsearch local fixture lifecycle
and capability smoke, promoting Elasticsearch for the fixture-backed capability
surface. Req70 later completed Jenkins local fixture lifecycle and capability
smoke, promoting Jenkins for the fixture-backed capability surface.

## Readiness Refresh

This inventory records the current state of the larger plugin readiness gaps
and recent promotions. Req50 adds fixture-backed Docker evidence and explicit
live-fixture skips for the remaining operations plugins.

| Plugin | Current code evidence | Release decision | Follow-up |
|--------|-----------------------|------------------|-----------|
| Docker | `docker.*` invoke capabilities cover agent-safe diagnostics, container/image/network/volume listing, redacted container inspect summaries, bounded non-following logs, and dry-run/ack-gated start/stop/restart/remove. Req50 completed disposable local daemon smoke. | Release candidate by Req50; keep the promotion tied to disposable daemon smoke evidence and rerun before tag if the Docker capability surface changes. | Fixture-Backed Operations Plugin Promotion Smoke 2026-07-05 |
| Kubernetes | `K8sService::new_direct()`, `voidb-cli kubernetes`, and `kubernetes.*` invoke capabilities cover contexts, namespaces, resource lists, bounded non-Secret YAML, bounded logs, dry-run/ack-gated delete/apply/scale/restart, and redacted kubeconfig/API server diagnostics. Req67 completed local kind fixture lifecycle and capability smoke for namespace isolation, bounded output, scratch configmap apply/delete, and redaction. | Release candidate by Req67 for the fixture-backed capability surface. | Kubernetes Release Readiness, [Release Plugin Smoke](release-plugin-smoke.md#kubernetes-live-smoke) |
| Elasticsearch | `elasticsearch.*` invoke capabilities cover diagnostics, health, nodes, bounded indices/search/get/count/mapping, and dry-run/ack-gated raw API calls. Req69 completed local Elasticsearch fixture lifecycle and capability smoke for bounded search reads, scratch raw API PUT/DELETE, cleanup, and endpoint/auth/index/document redaction. | Release candidate by Req69 for the fixture-backed capability surface. | Elasticsearch Release Readiness, [Release Plugin Smoke](release-plugin-smoke.md#elasticsearch-live-smoke) |
| MongoDB | `mongodb.*` invoke capabilities cover diagnostics, bounded databases/collections/find/count/aggregate/indexes, read-only aggregate stage checks, and dry-run/ack-gated insert/update/delete/create_index/run_command. Req68 completed local MongoDB fixture lifecycle and capability smoke for bounded reads, scratch insert/update/delete, dry-run create_index/run_command, mutating aggregate rejection, cleanup, and redaction. | Release candidate by Req68 for the fixture-backed capability surface. | MongoDB Release Readiness, [Release Plugin Smoke](release-plugin-smoke.md#mongodb-live-smoke) |
| Jenkins | `jenkins.*` invoke capabilities cover diagnostics, bounded jobs/job detail/activity/console/pipeline reads, and dry-run/ack-gated trigger/abort/queue cancel side effects. Req70 adds local Jenkins fixture lifecycle and capability smoke for job discovery, bounded console output, acknowledged trigger behavior, bad-auth/unavailable-target errors, cleanup, and redaction. | Release candidate by Req70 for the fixture-backed capability surface. | Rerun `scripts/jenkins-fixture-smoke.sh` if Jenkins capabilities, destructive safeguards, console bounds, target-error redaction, or fixture setup changes; current evidence is in Jenkins Release Readiness. |
| Email | `email.*` invoke capabilities cover diagnostics, folder list, bounded message list/search, and read-only fetch. TLS verification defaults to enabled. Req62 completed local GreenMail lifecycle and read-only capability smoke, including SMTP seeding, pagination, empty-page behavior, truncation, unsupported IMAP ID compatibility, and failed-auth redaction. Send/delete are deliberately absent from generic invoke until real destructive gates exist. | Release candidate by Req62 for the read-only fixture-backed capability surface; real-provider TLS smoke remains optional and must be recorded as run or skipped when claimed. | Email Release Readiness, [Release Plugin Smoke](release-plugin-smoke.md#email-live-smoke) |
| DuckDB | `duckdb.*` invoke capabilities follow the shared SQL contract for read-only query/explain/introspection and dry-run-gated `exec`; tests use temporary DuckDB databases. Native DuckDB build cost is documented as release planning overhead. | Beta certified by Req48 for the CLI/capability surface. | DuckDB and Redis Release Readiness |
| Redis | `redis.*` invoke capabilities cover bounded key scan/get/info and dry-run-gated set/delete/TTL/raw exec. Req61 completed local Redis fixture lifecycle and capability smoke for read/list/write/TTL/delete/exec dry-run, scratch-prefix cleanup, and auth redaction diagnostics. | Release candidate by Req61 for the fixture-backed capability surface; rerun fixture smoke if Redis capabilities change. | DuckDB and Redis Release Readiness, Live Fixture Smoke Harness |
| Sync | Object-level sync covers profiles, profile policy, credential refs, encrypted credential records, plugin compatibility metadata, app preferences, conflict markers, compatibility quarantine, explicit opt-in periodic sync, redacted audit events, and standalone server object storage. | Beta certified by Req49; keep opt-in and do not claim stable/default Sync until the stable object-sync gate is accepted by the release owner. | Sync Beta Readiness |

## Release Gates

### Fast Local Gate

Run this before merging a targeted change:

```bash
cargo test -p voidb-core
cargo test -p voidb-tui
cargo test -p voidb-plugin-sync
cargo test -p voidb-plugin-email
```

For plugin-specific changes, also run the touched plugin crate:

```bash
cargo test -p voidb-plugin-<name>
```

### Promoted Plugin Smoke Gate

Email, SSH, S3, and WebDAV share a promoted-plugin smoke surface. Before
promoting one of these plugins for a release candidate, run the secret-free
helper and then complete any applicable fixture-backed live smoke:

```bash
scripts/release-plugin-smoke.sh
```

Focused helper runs are also available:

```bash
scripts/release-plugin-smoke.sh --plugin email
scripts/release-plugin-smoke.sh --plugin ssh
scripts/release-plugin-smoke.sh --plugin s3
scripts/release-plugin-smoke.sh --plugin webdav
```

Live fixture prerequisites, commands, expected outputs, and default-CI secret
boundaries are documented in Release Plugin Smoke
and Live Fixture Smoke Harness.

### Full Workspace Gate

Run before tagging a release candidate:

```bash
cargo test --workspace --no-fail-fast
```

The DuckDB plugin builds bundled native DuckDB code through `libduckdb-sys`, so a
cold full workspace run can be much slower than focused plugin tests.

### CLI Gate

The CLI should remain a direct-mode consumer of plugin services. Before release,
verify:

```bash
cargo test -p voidb-cli
cargo run -p voidb-cli -- --help
```

Manual smoke coverage:

- Global help renders without panics.
- Each enabled command family prints help.
- Direct-mode operations do not depend on TUI event routing or `Frame`.
- Connection/config loading uses the same encrypted config path as the TUI.

### Process Plugin Runtime Gate

Process-plugin support is local executable-code loading from documented roots,
plus stdio JSON-RPC invocation. Before broadening external process-plugin use,
verify:

```bash
cargo test -p voidb-core process_plugin
cargo test -p voidb-core process_plugin_runtime
cargo test -p voidb-cli plugin
cargo test -p voidb-cli invoke
```

Manual smoke coverage:

- `voidb-cli plugin list --include-invalid --format json` reports root
  `trust_level`, candidate state, and redacted diagnostics without scanning the
  current working directory.
- Invalid or incompatible higher-precedence candidates do not shadow a
  lower-precedence available candidate with the same plugin ID.
- User, system, and bundled roots resolve bare runtime commands only from the
  package-local `bin/` directory; `VOIDB_PLUGIN_PATH` remains the explicit
  development override for `PATH` fallback.
- Generic `invoke run` can initialize, health-check, invoke, time out, and
  gracefully shut down a fixture process plugin without leaking raw stderr.

### SSH Gate

SSH must pass both its focused automated gate and the documented fixture-backed
manual smoke before being tagged as release-ready:

```bash
cargo test -p voidb-plugin-ssh capabilities
cargo test -p voidb-plugin-ssh service
cargo test -p voidb-plugin-ssh
cargo test -p voidb-cli invoke
cargo test -p voidb-core profile_adapter
cargo test -p voidb-core profile_store
git diff --check
```

Manual smoke coverage is defined in [SSH Plugin](ssh-plugin.md) and must cover:

- password, public-key, and SSH-agent auth against a disposable fixture;
- unknown, trusted, and changed host-key behavior;
- `ssh.test`, `ssh.exec`, `ssh.sftp_list`, `ssh.sftp_get`, `ssh.sftp_put`,
  `ssh.sftp_mkdir`, `ssh.sftp_rm`, and `ssh.diagnostics`;
- terminal raw input, `Ctrl+\` shell escape, SFTP browser, forwarding panel,
  reconnect behavior, and SFTP path persistence.

### TUI Gate

Before release, verify:

```bash
cargo test -p voidb-tui
cargo run
```

Manual smoke coverage:

- `Ctrl+Q` restores the terminal from every Connection Manager state.
- Connection Manager can add, edit, delete, search, test, and open profile guidance.
- Database profiles show CLI/capability guidance in the default TUI and do not
  require database browser/table/query-editor plugin factories.
- Long-running connection tests run asynchronously through the structured
  profile CLI contract.
- The default Connection Manager does not construct `ShellCapabilities`,
  implement `Plugin`, or reuse router-hosted screen state.

### Standalone Plugin TUI Gate

Before retaining a plugin-owned TUI for release, verify:

```bash
cargo test -p voidb-core tui_launch
cargo test -p voidb-plugin-<name> <plugin-owned-pty-gate>
```

The plugin-owned gate covers secret-free preflight output, PTY startup, resize,
quit/restore behavior, cleanup transcript checks, and timing metrics under
`target/tmp/standalone-tui-ux/`.

### Sync Client Gate

Before enabling Sync by default for a release, verify:

```bash
scripts/release-sync-smoke.sh --client-only
```

Manual smoke coverage:

- Register a device against a local sync server.
- Push a bundle and pull it into a fresh config directory.
- Confirm encrypted bundles do not expose plaintext connection data.
- Confirm conflict detection requires explicit force/revision behavior.
- Confirm sync config files are written with private permissions on Unix.
- Confirm the release boundary in Release Sync Smoke
  and Sync Beta Readiness is still accurate: Sync
  remains opt-in until the stable object-sync gate is complete and accepted.
- Before any stable/default Sync claim, also pass the stable object sync gate in
  Release Sync Smoke; bundle smoke alone proves only
  the compatibility backup path.

### Sync Server Gate

`voidb-sync-server` is intentionally excluded from the main workspace. Run its
own test suite before any release that documents or ships sync server support:

```bash
scripts/release-sync-smoke.sh --server-only
```

Manual smoke coverage:

- Server starts with a fresh SQLite store.
- Device registration returns usable credentials.
- Bundle upload/download round-trips.
- Unauthorized requests fail without leaking bundle metadata.
- Request limits and CORS defaults are acceptable for the intended deployment.

For full local sync release smoke, run:

```bash
scripts/release-sync-smoke.sh
```

## Security Gates

Security gates are mandatory for release candidates:

- Email TLS certificate verification defaults to enabled.
- Any insecure TLS override must be explicit in connection configuration.
- Main app config, sync config, profile, credential, and audit saves use private
  file permissions on Unix.
- Profile CLI output warns about default-passphrase credential risk only when
  credential material remains weakly protected, without exposing plaintext
  credential values.
- Destructive and dry-run capability paths pass the automated checks in
  [Security Release Checklist](security-release-checklist.md).
- SSH non-interactive paths use strict `known_hosts` verification and surface
  structured unknown/changed host-key errors.
- Release notes disclose residual default-passphrase risk for legacy configs
  until the TUI prompts for the user-controlled master-password path.
- New TUI plugin code must not import protocol/database/storage driver crates
  directly when a service-layer boundary exists.

## Roadmap Priorities

1. Promote database capability workflows to stable before restoring any
   database browser/table/query-editor surface to the default TUI. Per
   Requirement 83, no data inspector pilot is accepted in the current release
   path.
2. Migrate SQLite plus Redis first for the capability protocol, as documented
   in [First Protocol Plugin Migration Pair](first-protocol-plugin-migration.md).
3. Follow with MySQL as the first networked SQL protocol migration after the
   SQLite and Redis path is stable.
4. Treat any future TUI as new plugin-owned work, not as a resurrection of the
   removed router-hosted compatibility layer.
5. Keep future plugin TUIs on plugin-owned CLI commands and require the
   standalone TUI gate plus the
   [Plugin-Owned TUI Development Guide](plugin-owned-tui-development-guide.md)
   checklist before promotion.
6. Keep Email on the Req62 read-only fixture-backed release-candidate path, and
   promote S3 and WebDAV after the Release Plugin Smoke
   matrix is current and destructive actions have clear confirmation flows.
   Keep SSH on the release candidate path while its fixture-backed smoke
   remains current.
7. Keep Docker, Kubernetes, MongoDB, Elasticsearch, and Jenkins on the
   release-candidate path while their disposable fixture smoke remains current.
8. Keep Sync opt-in until the stable object-sync gate is complete and accepted,
   and the user-controlled master-password path is adopted by the TUI and sync
   release gates.
9. Rerun the Jenkins fixture smoke before preserving release-candidate status
   when Jenkins capabilities, destructive safeguards, console bounds,
   target-error redaction, or fixture setup changes.
