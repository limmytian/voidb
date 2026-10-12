# v0.3.5 local release candidate readiness

Status: local candidate prepared; **not approved for public release**.
The public baseline remains core v0.3.4 and official plugins v0.3.3. No new tags,
pushes, releases, or signing-secret uploads were performed in this session.

The owner authorized implementation, verification and local commits on
2026-10-12. The existing Task Weaver requirement is
`5de6cf6c-d4a7-466e-815b-736683ed6132` under project
`02710c97-c2c3-4047-812d-58f03060e75f`. No requirement or task was recreated.

## Candidate version matrix

| Component | Candidate | Local evidence |
| --- | --- | --- |
| Core shell, CLI and core library | 0.3.5 | Workspace tests, Clippy and native release build |
| Process plugin SDK | 0.3.5 | Workspace SDK tests; proof types exported |
| All 14 official plugins | 0.3.4 | Native release builds, tests, strict Clippy, contract exports and signed packages |
| Plugin SDK/core dependency pin | Existing validated `31d22cd09c9b10f1d22f59d47e789a49c33a290d` | No driver or transport API change; native initialize/health succeeded |
| Homebrew public artifact version | 0.3.4 until full candidate assets exist | Core-only install logic prepared; old URLs/hashes retained |

The plugins are mysql, postgres, sqlite, redis, ssh, duckdb, docker, kubernetes,
s3, elasticsearch, mongodb, jenkins, webdav and email. Existing protocol 1
manifests remain supported. Published v0.3.3 plugin artifacts remain immutable.

## Changes reviewed and implemented

The earlier worktree changes were preserved and reviewed: core-only release
packaging and local staging, no automatic installer/Homebrew plugin installation,
no implicit prefix/system/bundled discovery, registry-first install-default,
optional onboarding, and contextual missing-plugin installation.

New enforcement requires valid managed installation records and authenticated
`provenance.json` before every new child launch. There is no legacy digest
backfill. Strict Ed25519 checks bind identity, version, protocol, host target,
executable path and all payload files to a compiled official public key. Managed
symlinks and unverified payload changes are rejected. Explicit unsigned development
requires both a development root and `VOIDB_ALLOW_UNSIGNED_PLUGINS=1` outside
standard managed user directories.

Installation/update verify proofs before activation, serialize mutation with an
OS file lock, atomically replace synced records and preserve old packages/records.
Metadata activation failures restore the previous package. Updates preserve disabled
state. `install-default --force` uses verified update instead of deleting first.
Registry selection checks signed ID/version, and the registry builder authenticates
target-qualified archives before publishing entries. Distribution validation can
inspect foreign targets, while runtime verification fixes the compiled host target.

Onboarding and contextual installer children close stdin and remove the master
password environment variable. Partial onboarding remains retryable. Existing
invalid, disabled or incompatible installations are not overwritten by contextual
installation. Normal and minimum-size PTY scenarios used the real CLI and signed
HTTP assets.

See [the trust contract](plugin-trust-v0.3.5.md) for the exact format, key lifecycle,
immutable package/data policy and residual filesystem execution race. Trusted core,
OS, invocation environment, signing-key confidentiality and approved publisher CI
remain assumptions. Existing authenticated live sessions are not retroactively
terminated by deleting disk metadata.

## Local validation evidence

The committed [evidence JSON](release-v0.3.5-local-evidence.json) records hashes and
results. Local candidate files are under `target/v0.3.5-candidate/` (Git-ignored).

- `cargo test --workspace --no-fail-fast`: passed.
- `cargo clippy --workspace --all-targets --no-deps`: passed, zero warnings.
- `cargo test -p voidb-cli --features full`: passed.
- All 14 repositories: `cargo build --offline --release`, locked all-target tests,
  strict Clippy (`-D warnings`) and `export_contract --check`: passed.
- Shared Python signing/staging/installer tests use independent test keys: passed.
- Shell/Ruby syntax, all edited workflow YAML and `git diff --check`: passed.
- Changed Rust files were formatted. The full repository formatting check still
  reports pre-existing unrelated formatting differences; no broad formatting churn
  was introduced.

The production CLI authenticated 14 actual native archives when generating an
index. Real loopback HTTP acceptance covered install-default and repeat installation,
all 14 individual installations and initialize/health responses, verified update,
signed previous-package rollback, full uninstall and no implicit bundled fallback.

Five attacks (record deletion, omitted digest, malformed record, binary/record
co-modification and forged proof) failed before domain, TUI, serve and test dispatch.
No child marker or synthetic secret output appeared and records were not backfilled.
Core runtime tests additionally cover wrong signer/key/ID/version/target/protocol/path,
schema substitution, extra files and symlinks across health/invoke/session launches.

A copied immutable v0.3.3 MySQL backup with a missing record was refused, then
migrated to signed v0.3.4 through the real candidate registry. The original backup
and user installation were not changed. Native PTY checks proved noninteractive
no-download behavior, six-plugin installation, partial five-plugin failure and
next-launch retry, persistent skipping, contextual cancellation, and minimum-size
failure/retry installing only MySQL. Profile and credential files remained unchanged.

The native core tar contains exactly `voidb` and `voidb-cli`. The local Homebrew
updater refuses to render v0.3.5 when any of the four Unix core archives is missing.
The installed Homebrew CLI remains v0.3.4 and its plugin list remains empty.

## Remaining gates and approval boundary

**Only macOS ARM64 was exercised natively in this session.** Linux x86_64,
Linux ARM64 and macOS Intel signed artifacts, exact-source native CI, public
registry acceptance and actual new Homebrew distribution remain pending. Windows
has a core package only; no official Windows plugin support is claimed.

The prepared release workflows support exact-source candidate dry runs, defaulting
to `publish_release=false`. They upload candidate artifacts without creating tags
or releases. Publishing requires a pre-existing tag matching the built source and
uses `gh release create`, which cannot replace an old release. Recovery reuses only
artifacts from the same source commit.

The new key ID is `official-2026-10`; its public key is
`2d00e2e461719c94b77cf0e9d1d49a9cf1c8dbe8f802696b801b432bfcc95ea2`.
Its private key remains outside repositories, mode 0600 under a mode 0700 directory.
Signing tools reject private keys within payloads or hard-linked private key files.
No production private key was used in synthetic regression tests.

Before remote candidate runs, review and configure `plugin-release-signing` in all
14 plugin repositories with an appropriate required reviewer/tag policy and the
`VOIDB_PLUGIN_SIGNING_KEY_PEM` environment secret. The sampled MySQL environment
returned 404; this session did not provision remote environments or secrets.
The key is available only to the protected signing step, never PR/build jobs.

Next authorized phase requires owner approval to push candidate branches, configure
protected signing environments/secrets and dispatch **non-publishing** exact-source
candidate CI. After all target artifacts are verified, complete the remaining
Task Weaver gates and update registry/formula hashes from real artifacts. Run
`scripts/update-homebrew-formula.py` only with all four verified Unix core archives.
Tags and public publication require another explicit review/confirmation. Publish
new signed plugin assets before advancing the public registry and core/Homebrew
release, preserving every old immutable asset.

## Task Weaver scheduling

Threat model and runtime/migration slices are complete. Signing work remains in
review for remote provisioning and foreign-target artifact acceptance; downstream
regression and distribution tasks must not be forced past that gate.

The existing core-only distribution task `37321655-4d3e-47d0-a18b-cd1395e2fa20`
was moved from sequential slice 2 to slice 4 and made dependent on signed regression,
because its real signed registry acceptance requires slice 3 artifacts. Its original
acceptance criteria were retained. Terminal task transitions auto-release claims;
there was no duplicate requirement creation or acceptance waiver.

## Local repository commits

All candidate branches are `codex/v0.3.5-trust-hardening`. The core implementation
and this evidence are committed together; use the current core branch HEAD as its
exact review identity. No branch has been pushed.

| Repository | Local commit |
| --- | --- |
| voidb-plugin-mysql | `9c93917eb91be953b4b9b40f91118c09e685ba4c` |
| voidb-plugin-postgres | `8a4d3355b0a54c310ecd18cd02465726ce4d0306` |
| voidb-plugin-sqlite | `376c3877fd2a827015a3ae8154689aa6ec9bb567` |
| voidb-plugin-redis | `4be2bb39070d571023718f2019f3a35b8eafa004` |
| voidb-plugin-ssh | `fda5e0a6d13a0f44ec98751df2dc5500ae959753` |
| voidb-plugin-duckdb | `bd4624f7cedc387d882da63ab0464045a06776c2` |
| voidb-plugin-docker | `51961489967c4ac2db849c3f809bb332d566a373` |
| voidb-plugin-kubernetes | `701f14816e7fbca14bdbebf2ac2c10427c80b4a3` |
| voidb-plugin-s3 | `84dd62d15a4cfee7fd3aa81edd5b2bae1d7fe9dd` |
| voidb-plugin-elasticsearch | `ef4935a2d3b378b659b594fed50b5709a68e91f6` |
| voidb-plugin-mongodb | `894018fdcee29a8b67b49e9678e194af5393fbd7` |
| voidb-plugin-jenkins | `bf95f9fdeccb216d4a16be97236d4be98c10cb15` |
| voidb-plugin-webdav | `779fa13401df3c4ce5958677d16d874005f58938` |
| voidb-plugin-email | `321ce7bf689b563218888d38b6227a99a859ba42` |
| homebrew-tap | `0c5c49e5c670bce935d64e79e2705a6d12fd5814` |
