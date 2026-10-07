# Release Candidate Checklist

This checklist is the release-candidate entry point. It links the focused gate
docs, keeps fast checks usable, and records residual risk that should appear in
release notes.

It complements:

- [Readiness Documentation Map](readiness.md)
- [Agent Capability and Experience Matrix](agent-capability-matrix.md)
- [Agent and TUI Aggregate Release Gate](agent-tui-release-gate.md)
- [CI Check Tiers](ci-checks.md)
- [Security Release Checklist](security-release-checklist.md)
- [Plugin Maturity and Release Gates](plugin-roadmap.md)
- Release Plugin Smoke
- Release Sync Smoke
- Legacy TUI Removal Boundary
- [Data Inspector CLI-First Decisions](data-inspector-cli-first-decisions.md)
- Plugin-Owned TUI Release Readiness 2026-07-06
- Retained TUI Smoke Evidence 2026-07-07
- New TUI Generation Release Notes 2026-07-07
- [Release Packaging](release-packaging.md)
- SSH Release Readiness
- External-Agent Interaction Evidence 2026-07-13
- S3 Release Readiness
- WebDAV Release Readiness
- MySQL Release Readiness
- Kubernetes Release Readiness
- MongoDB Release Readiness
- Elasticsearch Release Readiness
- Jenkins Release Readiness
- Final Pre-Release Validation 2026-07-05
- Release Publish Handoff 2026-07-05

## Command Gate Matrix

| Gate | Required for release candidate | Commands | Source |
|---|---:|---|---|
| Aggregate Agent/TUI release evidence | Yes | `python3 scripts/agent_tui_release_gate.py --profile full` | [Agent and TUI Aggregate Release Gate](agent-tui-release-gate.md) |
| Agent capability matrix drift | Yes | `scripts/check-agent-capability-matrix.sh` | [Agent Capability and Experience Matrix](agent-capability-matrix.md) |
| Secret-free promoted plugin smoke | Yes | `scripts/release-plugin-smoke.sh` | Release Plugin Smoke |
| Local Docker fixture harness preflight | When local Docker-backed live fixtures are used | `scripts/local-fixture-smoke.sh run --fixture probe --report target/tmp/local-fixture-probe-evidence.md` | Live Fixture Smoke Harness |
| Sync client/server smoke | Yes, while Sync is documented or shipped | `scripts/release-sync-smoke.sh` | Release Sync Smoke |
| Stable object Sync claim | Only if release notes or UI copy call Sync stable/default | `cargo test -p voidb-core object_sync`, plus the stable object sync gate in Release Sync Smoke | Release Sync Smoke |
| Security release gate | Yes | Commands in [Security Release Checklist](security-release-checklist.md) | [Security Release Checklist](security-release-checklist.md) |
| Process-plugin runtime gate | Yes, while process plugins are enabled | `cargo test -p voidb-core process_plugin`; `cargo test -p voidb-core process_plugin_runtime`; `cargo test -p voidb-cli plugin`; `cargo test -p voidb-cli invoke` | [CI Check Tiers](ci-checks.md) |
| External-agent interaction boundary | Yes | `scripts/check-external-agent-interaction.sh`; focused SSH/infrastructure/capability-only plugin groups from the CI guide | External-Agent Interaction Evidence |
| First protocol pair | Yes, for capability contract confidence | `cargo test -p voidb-plugin-sqlite`; `cargo test -p voidb-plugin-redis`; `cargo test -p voidb-cli invoke`; `git diff --check` | [CI Check Tiers](ci-checks.md) |
| MySQL capability smoke | Yes, for MySQL release candidate status | `cargo check -p voidb-plugin-mysql --example fixture_smoke`; `cargo test -p voidb-plugin-mysql`; `cargo test -p voidb-cli invoke`; `cargo test -p voidb-core sql_contract`; `scripts/mysql-fixture-smoke.sh --report target/tmp/mysql-fixture-smoke-evidence.md`; `git diff --check` | MySQL Release Readiness |
| SSH capability smoke | Yes, for SSH release candidate status | `cargo check -p voidb-plugin-ssh --example fixture_smoke`; `cargo test -p voidb-plugin-ssh`; `cargo test -p voidb-cli invoke`; `cargo test -p voidb-core profile_adapter`; `cargo test -p voidb-core profile_store`; `scripts/ssh-fixture-smoke.sh --report target/tmp/ssh-fixture-smoke-evidence.md` | SSH Release Readiness |
| S3 capability smoke | Yes, for S3 release candidate status | `cargo check -p voidb-plugin-s3 --example fixture_smoke`; `cargo test -p voidb-plugin-s3`; `cargo test -p voidb-cli invoke`; `scripts/s3-fixture-smoke.sh --report target/tmp/s3-fixture-smoke-evidence.md` | S3 Release Readiness |
| WebDAV capability smoke | Yes, for WebDAV release candidate status | `cargo check -p voidb-plugin-webdav --example fixture_smoke`; `cargo test -p voidb-plugin-webdav`; `cargo test -p voidb-cli invoke`; `scripts/webdav-fixture-smoke.sh --report target/tmp/webdav-fixture-smoke-evidence.md` | WebDAV Release Readiness |
| Default native Connection Manager | Yes | `cargo test -p voidb-tui`; manual `cargo run` smoke | [Connection Manager TUI](connection-manager-tui.md) |
| Retained standalone TUI gate | Yes, while retained standalone TUIs are shipped | `scripts/tui-quality-gate.sh`; retain its full output on failure; use `--cli-bin` and `--tui-bin` for staged/package binaries | [TUI CI And Real-Terminal Coverage](tui-terminal-coverage.md) |
| Future plugin TUI UX gate | Only if a new plugin-owned TUI is accepted | `cargo test -p voidb-core tui_launch`; plugin-owned PTY/lifecycle test target | [Plugin-Owned TUI Development Guide](plugin-owned-tui-development-guide.md) |
| Data inspector TUI gate | Only if release notes or UI copy advertise a data inspector TUI | Requirement 83 currently accepts no pilot; rerun the accepted plugin's capability, fixture, and PTY gates before adding any `voidb-cli <data-plugin> tui` command. | [Data Inspector CLI-First Decisions](data-inspector-cli-first-decisions.md) |
| Package artifact smoke | Yes before tag | Commands in [Release Packaging](release-packaging.md), plus `scripts/linux-package-smoke.sh --report target/tmp/linux-package-smoke-evidence.md` when Linux Docker smoke is used; record platform evidence with the format in [Package CI Matrix](package-ci-matrix.md#package-evidence-format) | [Release Packaging](release-packaging.md) |
| Full workspace | Yes before tag | `cargo test --workspace --no-fail-fast` | [CI Check Tiers](ci-checks.md) |
| Full clippy | Yes before tag | `cargo clippy --workspace --all-targets --no-deps` | [CI Check Tiers](ci-checks.md) |

## Manual Smoke Matrix

| Surface | Required manual coverage | Skip policy |
|---|---|---|
| Native Connection Manager | `Ctrl+Q`, create/edit/delete, search, credential unlock, profile test, and capability guidance. | Do not skip for release candidates. |
| Default profile guidance | Profiles open CLI/capability guidance without default legacy browser/table/query-editor adapters. | Do not skip when default TUI changed. |
| Future plugin TUIs | PTY gate transcripts and metrics exist under `target/tmp/standalone-tui-ux/` before any new plugin-owned TUI is shipped. | Record as not applicable while no plugin-owned TUI is shipped. |
| SSH live fixture | Local OpenSSH lifecycle and capability/service smoke via `scripts/ssh-fixture-smoke.sh --report target/tmp/ssh-fixture-smoke-evidence.md`. | Rerun before RC promotion when SSH capabilities, host-key policy, or service channels change. |
| SSH external-agent share | Fixture evidence plus a real-terminal check of share/refresh, operation review, one-operation approval, same-agent approval, denial, and `Ctrl+]` then `v` revoke. | Do not claim the live interaction path from deterministic source checks alone. |
| Redis local fixture | Disposable local Redis container and scratch key prefix via `scripts/redis-fixture-smoke.sh --report target/tmp/redis-fixture-smoke-evidence.md`. | Rerun before RC promotion when Redis capabilities change; do not claim Redis fixture-backed readiness from Req55 skipped evidence alone. |
| Email local fixture | Disposable local GreenMail mailbox covering bounded reads, guarded send/move/delete/flag, attachment policy, and IDLE cancellation via `scripts/email-fixture-smoke.sh --report target/tmp/email-fixture-smoke-evidence.md`. | Rerun before RC promotion when Email capability, attachment, mutation, or IDLE behavior changes; real-provider interoperability remains opt-in. |
| S3 local fixture | Disposable local MinIO bucket and scratch prefix via `scripts/s3-fixture-smoke.sh --report target/tmp/s3-fixture-smoke-evidence.md`. | Rerun before RC promotion when S3 capabilities, destructive safeguards, pagination, sync planning, or redaction behavior change. |
| WebDAV local fixture | Disposable local rclone WebDAV collection via `scripts/webdav-fixture-smoke.sh --report target/tmp/webdav-fixture-smoke-evidence.md`. | Rerun before RC promotion when WebDAV capabilities, destructive safeguards, pagination, sync planning, or redaction behavior change. |
| MySQL local fixture | Disposable local MySQL database via `scripts/mysql-fixture-smoke.sh --report target/tmp/mysql-fixture-smoke-evidence.md`. | Rerun before RC promotion when MySQL SQL capabilities, schema metadata, destructive safeguards, pagination, database selection, or diagnostics redaction behavior change. |
| Kubernetes local fixture | Disposable local kind cluster and scratch namespace via `scripts/kubernetes-fixture-smoke.sh --report target/tmp/kubernetes-fixture-smoke-evidence.md`. | Rerun before RC promotion when Kubernetes capabilities, namespace isolation, destructive safeguards, bounded output, or kubeconfig redaction behavior change. |
| MongoDB local fixture | Disposable local MongoDB database and collection via `scripts/mongodb-fixture-smoke.sh --report target/tmp/mongodb-fixture-smoke-evidence.md`. | Rerun before RC promotion when MongoDB capabilities, destructive safeguards, pagination, aggregation policy, or diagnostics redaction behavior change. |
| Elasticsearch local fixture | Disposable local Elasticsearch index and documents via `scripts/elasticsearch-fixture-smoke.sh --report target/tmp/elasticsearch-fixture-smoke-evidence.md`. | Rerun before RC promotion when Elasticsearch capabilities, destructive safeguards, pagination, mapping output, or endpoint/auth redaction behavior change. |
| Jenkins local fixture | Disposable local Jenkins job/build via `scripts/jenkins-fixture-smoke.sh --report target/tmp/jenkins-fixture-smoke-evidence.md`. | Rerun before RC promotion when Jenkins capabilities, destructive safeguards, console bounds, target-error redaction, or fixture setup changes. |
| Sync manual/server process | Optional `scripts/release-sync-smoke.sh --hosted` local server process smoke and disposable `VOIDB_CONFIG_DIR` from Release Sync Smoke. | May skip if automated sync helper passes and no hosted/server deployment is being validated; record the `target/tmp/voidb-sync-hosted-smoke/<run-id>/evidence.md` path when run. |

## Residual Risk Notes

Include these notes in release-candidate notes when applicable:

- Plugin readiness: use the generated
  [Agent Capability and Experience Matrix](agent-capability-matrix.md) for
  current RC, beta, and opt-in boundaries. Dated reports are historical
  evidence only.
- Default-passphrase legacy configs: saved legacy `ConnectionConfig` credential
  material may still be protected by the compiled default passphrase until the
  user re-encrypts with `voidb-cli credential master reencrypt` or the
  Connection Manager `m` master-password flow. The TUI path exists, but release
  notes should still disclose risk for users who have not completed
  re-encryption.
- Legacy TUI removal: old database browser/table/query-editor adapters and old
  router-hosted plugin factories are removed. The stable functional surface is
  CLI, capabilities, and services; future TUIs require a new plugin-owned gate.
- Data inspector TUI status: Requirement 83 accepts no data inspector pilot.
  MySQL, PostgreSQL, and DuckDB are CLI-only; SQLite, Redis, MongoDB, and
  Elasticsearch are later candidates that still ship as CLI-only. Release notes
  must not advertise data-plugin `tui` commands unless a later requirement
  records the data inspector gate, capability/fixture evidence, and PTY
  evidence.
- External process plugins: process-plugin execution is local executable code
  loaded only from documented trust roots. Marketplace, installer, and hosted
  catalog semantics remain future work.
- Optional integration tests: provider compatibility for MySQL/MariaDB, SSH,
  WebDAV, and external hosted Sync
  smoke need external or local Docker fixtures and must be recorded as run,
  partially run, or skipped using the evidence format in
  [Live Fixture Smoke Harness](live-fixture-smoke-harness.md#evidence-format).
  Docker fixture smoke completed in
  Fixture-Backed Operations Plugin Promotion Smoke 2026-07-05.
  Req61 records Redis local fixture-backed capability evidence in
  DuckDB and Redis Release Readiness.
  Req62 records Email local fixture-backed capability evidence in
  Email Release Readiness. Req63 records SSH
  local OpenSSH fixture-backed capability/service evidence in
  SSH Release Readiness. Req64 records S3 local
  MinIO fixture-backed capability evidence in
  S3 Release Readiness. Req65 records WebDAV local
  rclone fixture-backed capability evidence in
  WebDAV Release Readiness. Req66 records MySQL
  local fixture-backed SQL capability evidence in
  MySQL Release Readiness. Req67 records
  Kubernetes local kind fixture-backed capability evidence in
  Kubernetes Release Readiness. Req68 records
  MongoDB local fixture-backed capability evidence in
  MongoDB Release Readiness. Req69 records
  Elasticsearch local fixture-backed capability evidence in
  Elasticsearch Release Readiness. Req70
  records Jenkins local fixture-backed capability evidence in
  Jenkins Release Readiness.
- Sync: Sync is beta-certified but opt-in. Req60 records the object-level gate
  and local hosted process smoke for profile and credential sync readiness. The
  full-directory bundle remains an encrypted compatibility path, not the stable
  profile/credential sync contract. A stable/default Sync claim still requires
  release-owner acceptance of the gate in Release Sync Smoke
  and the boundary in Sync Beta Readiness, not only
  the compatibility-bundle smoke.
- Clippy baseline: full clippy may still report inherited warnings recorded in
  the warning budget. New errors, new warning classes, or warnings in touched
  code are regressions.
- Package versions: Cargo package versions, binary `--version` output, changelog
  target sections, and tag names must agree before tagging.

## Release Note Template

```text
Release candidate validation:
- Commit:
- Validated source commit:
- Docs-only commits after validation:
- Date:
- Final validation evidence:
- Full workspace test:
- Full clippy:
- Security gate:
- Promoted plugin smoke:
- Sync smoke:
- TUI manual smoke:
- External-agent interaction boundary:
- Legacy DB TUI feature smoke:
- Optional live smoke run:
- Optional live smoke skipped:
- Local fixture harness evidence:
- Package artifact smoke:
- Package CI platforms run/skipped:
- Linux Docker package smoke evidence:
- macOS x64 package smoke/skipped:
- Windows x64 package smoke/skipped:
- Artifact checksums:
- Artifact manifest commit:
- Version/tag consistency:
- Publish handoff packet:
- Publish handoff owner:
- Artifacts uploaded/published by:
- Residual risks disclosed:
```

## Latest Rehearsal Result

Latest final validation record:
Final Pre-Release Validation 2026-07-05
records Task Weaver requirement 75 slice 1 for commit
`4019a9db0590d5aee2444f833a50c8f28510eba1`.

Historical final tag readiness record:
Release Tag Readiness 2026-07-05
summarizes Task Weaver requirement 53 and remains the source for the latest
real-terminal packaged TUI smoke evidence.

Supporting evidence:

- Final Pre-Release Validation 2026-07-05
  records the clean-worktree rerun of promoted plugin smoke, Sync smoke, full
  workspace tests, full clippy, darwin-arm64 package staging, and package
  smoke from requirement 75.
- Release Publish Handoff 2026-07-05
  records the human-controlled tag, artifact, platform, checksum, residual-risk,
  and non-publishing handoff boundary from requirement 75.
- Release Candidate Baseline Report 2026-07-05
  records the secret-free baseline gates from requirement 46.
- All-Plugin RC Readiness Report 2026-07-05
  records plugin dispositions from requirement 52.
- Fixture-Backed Operations Plugin Promotion Smoke 2026-07-05
  records Docker fixture smoke and skipped operations fixtures from requirement
  50.
- Beta Plugin Fixture Promotion Report 2026-07-05
  records Req55 skipped fixture evidence for Email, Redis, Kubernetes, MongoDB,
  Elasticsearch, and Jenkins. Redis was later superseded by Req61 fixture
  evidence in DuckDB and Redis Release Readiness;
  Email was later superseded by Req62 fixture evidence in
  Email Release Readiness. S3 was later
  superseded by Req64 fixture evidence in
  S3 Release Readiness. WebDAV was later
  superseded by Req65 fixture evidence in
  WebDAV Release Readiness. Kubernetes was later
  superseded by Req67 fixture evidence in
  Kubernetes Release Readiness. MongoDB was
  later superseded by Req68 fixture evidence in
  MongoDB Release Readiness. Elasticsearch was
  later superseded by Req69 fixture evidence in
  Elasticsearch Release Readiness.
  Jenkins was later superseded by Req70 fixture evidence in
  Jenkins Release Readiness.

Current go/no-go: **GO to prepare the human-controlled `v0.3.0-rc.1` publish
handoff after release notes include the documented waivers**.

Do not tag or upload artifacts automatically. The latest deterministic package
manifest was generated from commit `4019a9d`. If the release owner selects a
later docs-only commit for the tag, regenerate package metadata so
`artifact-manifest.json` records the selected tag commit.

The human-controlled tag and upload checklist is in
Release Publish Handoff 2026-07-05.

Passed release-candidate evidence:

- Focused security, credential, dry-run/destructive invoke, SSH, process-plugin,
  plugin CLI, generic invoke, and SQL contract gates passed in the 2026-07-05
  RC baseline and plugin readiness slices.
- Req75 reran `scripts/release-plugin-smoke.sh`,
  `scripts/release-sync-smoke.sh`,
  `cargo test --workspace --no-fail-fast`, and
  `cargo clippy --workspace --all-targets --no-deps` from a clean detached
  worktree at `4019a9d`; all passed.
- `cargo test --manifest-path voidb-sync-server/Cargo.toml` and
  `cargo clippy --manifest-path voidb-sync-server/Cargo.toml --all-targets --no-deps`
  passed.
- Default TUI package artifacts passed real-terminal smoke on disposable config
  state.
- CLI and sync-server package artifacts passed help/version smoke. Req75 reran
  darwin-arm64 package staging and package smoke from a clean worktree; the
  generated manifest recorded `git.dirty: false`.
- Req74 added Linux x64 Docker package-smoke evidence with
  `scripts/linux-package-smoke.sh --docker-platform linux/amd64 --package-platform linux-x64 --report target/tmp/linux-package-smoke-evidence.md`.
- Cargo package versions, `Cargo.lock`, binary version output, changelog target
  section, and intended tag name agree on `0.3.0-rc.1`.

No deterministic blocking items remain for the human publish handoff. The
release owner still needs to choose the exact tag commit, regenerate package
metadata if choosing a post-validation docs-only commit, and complete the
manual publish actions.

Accepted residual risks only if disclosed in release notes:

- Final deterministic validation targeted commit `4019a9d`. Subsequent
  evidence/checklist commits are docs-only; if a later commit is tagged, package
  staging should be rerun so manifest metadata and selected tag agree.
- Package evidence covers native macOS arm64 artifacts and Docker Linux x64
  package smoke. Native Linux x64 runner evidence, macOS x64, Windows x64, and
  Linux arm64 remain unclaimed unless their platform-specific smoke is rerun and
  recorded with the package evidence format.
- Default-passphrase risk remains for legacy configs that have not been
  re-encrypted.
- External process plugins execute trusted local code from documented roots
  only; marketplace and hosted catalog flows remain future work.
- Sync remains beta-certified and opt-in unless the stable object Sync gate,
  local hosted evidence, and release-owner acceptance are recorded.
- Live MySQL, external hosted Sync deployment, native Linux x64 runner package
  smoke, macOS x64 package smoke, Windows x64 package smoke, and Linux arm64
  package smoke were skipped because disposable fixtures, credentials, or
  platforms were not available. Local hosted Sync process smoke passed in
  Req60. Docker
  fixture smoke completed on 2026-07-05. Redis local fixture-backed capability
  smoke passed in Req61. Email local fixture-backed capability smoke passed in
  Req62 for the read-only scope. SSH local OpenSSH fixture-backed
  capability/service smoke passed in Req63; remaining SSH TUI checks are the
  visible `Ctrl+\` shell escape, forwarding panel UI, and SFTP path persistence.
  S3 local MinIO fixture-backed capability smoke passed in Req64. WebDAV local
  rclone fixture-backed capability smoke passed in Req65. Kubernetes local kind
  fixture-backed capability smoke passed in Req67. MongoDB local fixture-backed
  capability smoke passed in Req68. Elasticsearch local fixture-backed
  capability smoke passed in Req69. Jenkins local fixture-backed capability
  smoke passed in Req70.
- Inherited warnings remain non-blocking under the warning budget policy:
  existing clippy warning buckets are accepted only when they stay within the
  recorded inventory. New warnings in touched code are regressions. Req71
  removed the inherited `imap-proto v0.10.2` future-incompatibility warning by
  upgrading Email to exact-pinned `imap 3.0.0-alpha.15`.

## Stop Conditions

Do not tag a release candidate if any of these are true:

- security gates fail or expose plaintext credentials, tokens, private keys,
  decrypted `plugin_config`, credential-bearing URLs, or raw sensitive inputs;
- destructive capability policy regresses to allow mutation without dry-run,
  profile policy, or explicit acknowledgement where required;
- default TUI cannot create, test, or open connection profiles;
- process-plugin discovery scans undocumented roots or runs untrusted commands
  outside the documented trust model;
- sync server or client tests fail to reject unauthorized requests or fail to
  preserve encrypted bundle invariants;
- release notes or UI copy call Sync stable/default without recording the
  object-level sync gate, local hosted evidence, and release-owner acceptance;
- required TUI manual smoke is skipped without an explicit release-owner
  acceptance recorded in release notes;
- Cargo package versions, binary `--version` output, changelog target section,
  and tag name disagree;
- package automation creates or pushes tags, uploads public release artifacts,
  or marks release notes final without an explicit human publish handoff;
- release notes omit skipped external-service smoke coverage.
