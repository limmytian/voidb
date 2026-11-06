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
- [Release Packaging](release-packaging.md)

## Command Gate Matrix

| Gate | Required for release candidate | Commands | Source |
|---|---:|---|---|
| Aggregate Agent/TUI release evidence | Yes | `python3 scripts/agent_tui_release_gate.py --profile full` | [Agent and TUI Aggregate Release Gate](agent-tui-release-gate.md) |
| Agent capability matrix drift | Yes | `scripts/check-agent-capability-matrix.sh` | [Agent Capability and Experience Matrix](agent-capability-matrix.md) |
| Secret-free promoted plugin smoke | Yes | `scripts/release-plugin-smoke.sh` | `scripts/release-plugin-smoke.sh` |
| Local Docker fixture harness preflight | When local Docker-backed live fixtures are used | `scripts/local-fixture-smoke.sh run --fixture probe --report target/tmp/local-fixture-probe-evidence.md` | `scripts/local-fixture-smoke.sh` |
| Sync client/server smoke | Yes, while Sync is documented or shipped | `scripts/release-sync-smoke.sh` | `scripts/release-sync-smoke.sh` |
| Stable object Sync claim | Only if release notes or UI copy call Sync stable/default | `cargo test -p voidb-core object_sync`, plus the stable object sync gate in `scripts/release-sync-smoke.sh` | [Sync Boundary Under The Capability Model](sync-boundary.md) |
| Security release gate | Yes | Commands in [Security Release Checklist](security-release-checklist.md) | [Security Release Checklist](security-release-checklist.md) |
| Process-plugin runtime & tooling gate | Yes, while process plugins are enabled | `cargo test -p voidb-core process_plugin`; `cargo test -p voidb-core process_plugin_runtime`; `cargo test -p voidb-cli plugin`; `cargo test -p voidb-cli invoke`; `cargo test -p voidb-process-plugin-sdk` | [CI Check Tiers](ci-checks.md) |
| External-agent interaction boundary | Yes | `scripts/check-external-agent-interaction.sh`; focused SSH/infrastructure/capability-only plugin groups from the CI guide | `scripts/check-external-agent-interaction.sh` |
| Core protocol & RDBMS baseline | Yes, for core database contract confidence | `cargo test -p voidb-core`; `cargo test -p voidb-cli invoke`; `git diff --check`; the SQL plugin crates' own test suites run inside their repository checkouts per [CI Check Tiers](ci-checks.md) | [CI Check Tiers](ci-checks.md) |
| Decoupled long-tail protocol plugins | Verified in independent repos | Independent CI checks in `voidb-plugin-jenkins`, `voidb-plugin-webdav`, `voidb-plugin-email`, `voidb-plugin-s3`, `voidb-plugin-kubernetes`, `voidb-plugin-docker`, `voidb-plugin-elasticsearch`, `voidb-plugin-mongodb` | External Process Plugin Workflow |
| SSH capability smoke | Yes, for SSH release candidate status | `cargo test -p voidb-cli invoke`; `cargo test -p voidb-core profile_adapter`; `cargo test -p voidb-core profile_store`; `scripts/ssh-fixture-smoke.sh --report target/tmp/ssh-fixture-smoke-evidence.md`; `voidb-plugin-ssh` crate tests run in its repository checkout | [CI Check Tiers](ci-checks.md) |
| Default native Connection Manager | Yes | `cargo test -p voidb-tui`; manual `cargo run` smoke | [Connection Manager TUI](connection-manager-tui.md) |
| Retained standalone TUI gate | Yes, while retained standalone TUIs are shipped | `scripts/tui-quality-gate.sh`; retain its full output on failure; use `--cli-bin` and `--tui-bin` for staged/package binaries | [TUI CI And Real-Terminal Coverage](tui-terminal-coverage.md) |
| Future plugin TUI UX gate | Only if a new plugin-owned TUI is accepted | `cargo test -p voidb-core tui_launch`; plugin-owned PTY/lifecycle test target | [Plugin-Owned TUI Development Guide](plugin-owned-tui-development-guide.md) |
| Data inspector TUI gate | Only if release notes or UI copy advertise a data inspector TUI | Requirement 83 currently accepts no pilot; rerun the accepted plugin's capability, fixture, and PTY gates before adding any `vb <data-plugin> tui` command. | [Standalone TUI UX Acceptance Criteria](standalone-tui-ux-acceptance.md) |
| Package artifact smoke | Yes before tag | Commands in [Release Packaging](release-packaging.md), plus `scripts/linux-package-smoke.sh --report target/tmp/linux-package-smoke-evidence.md` when Linux Docker smoke is used; record platform evidence with a dated evidence entry under `target/tmp/` | [Release Packaging](release-packaging.md) |
| Full workspace | Yes before tag | `cargo test --workspace --no-fail-fast` | [CI Check Tiers](ci-checks.md) |
| Full clippy | Yes before tag | `cargo clippy --workspace --all-targets --no-deps` | [CI Check Tiers](ci-checks.md) |

## Manual Smoke Matrix

Fixture wrappers for Email, S3, WebDAV, Kubernetes, MongoDB, Elasticsearch,
and Jenkins are not present in `scripts/` yet: the Email, S3, and WebDAV
wrappers are 0.4.1 deliverables (see the
[0.4.1 Iteration Roadmap](roadmap-0.4.1.md)), and the remaining rows are
executed inside the matching plugin repositories. A fixture row is only
runnable when its script exists in `scripts/`.

| Surface | Required manual coverage | Skip policy |
|---|---|---|
| Native Connection Manager | `Ctrl+Q`, create/edit/delete, search, credential unlock, profile test, and capability guidance. | Do not skip for release candidates. |
| Default profile guidance | Profiles open CLI/capability guidance without default legacy browser/table/query-editor adapters. | Do not skip when default TUI changed. |
| Future plugin TUIs | PTY gate transcripts and metrics exist under `target/tmp/standalone-tui-ux/` before any new plugin-owned TUI is shipped. | Record as not applicable while no plugin-owned TUI is shipped. |
| SSH live fixture | Local OpenSSH lifecycle and capability/service smoke via `scripts/ssh-fixture-smoke.sh --report target/tmp/ssh-fixture-smoke-evidence.md`. | Rerun before RC promotion when SSH capabilities, host-key policy, or service channels change. |
| SSH external-agent share | Fixture evidence plus a real-terminal check of share/refresh, operation review, one-operation approval, same-agent approval, denial, and `Ctrl+]` then `v` revoke. | Do not claim the live interaction path from deterministic source checks alone. |
| Redis local fixture | Disposable local Redis container and scratch key prefix via `scripts/redis-fixture-smoke.sh --report target/tmp/redis-fixture-smoke-evidence.md`. | Rerun before RC promotion when Redis capabilities change; do not claim Redis fixture-backed readiness from skipped evidence alone. |
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
  user re-encrypts with `vb credential master reencrypt` or the
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
  partially run, or skipped with a dated evidence entry under `target/tmp/`.
  Historical per-requirement fixture evidence stays in git history and past
  release notes.
- Sync: Sync is beta-certified but opt-in. The object-level gate and local
  hosted process smoke run through `scripts/release-sync-smoke.sh`; the
  full-directory bundle remains an encrypted compatibility path, not the stable
  profile/credential sync contract. A stable/default Sync claim still requires
  release-owner acceptance of that gate and the boundary in
  [Sync Boundary Under The Capability Model](sync-boundary.md).
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

## Rehearsal Records

This checklist records current gates only. Dated rehearsal, validation, and
promotion records are historical evidence: they live in git history and past
release notes, not in this file. Record new rehearsal outcomes in the release
notes using the template above.

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
