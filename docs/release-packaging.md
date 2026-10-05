# Release Packaging

This document records the package and distribution contract for VoidB release
candidates. It complements the release-candidate gate matrix in
[Release Candidate Checklist](release-candidate-checklist.md) and the
cross-platform job contract in Package CI Matrix.

## Build Matrix

| Artifact | Command | Output | Notes |
|---|---|---|---|
| Default TUI | `cargo build --release` | `target/release/voidb` | The workspace `default-members` list only includes `crates/voidb-tui`, so this is the lightweight default TUI build. |
| CLI | `cargo build --release -p voidb-cli` | `target/release/voidb-cli` | Builds the machine-readable command surface and all CLI plugin command families. It is not produced by the default workspace build. |
| Standalone sync server | `cargo build --release --manifest-path voidb-sync-server/Cargo.toml` | `voidb-sync-server/target/release/voidb-sync-server` | Separate crate with its own workspace. Build only when shipping or validating sync server deployment artifacts. |

The release profile is size-oriented: LTO is enabled, symbols are stripped, and
`codegen-units = 1`. Release builds can therefore be much slower than focused
test builds.

## Platform Prerequisites

- Rust stable with edition 2024 support. This repository does not pin a
  `rust-toolchain.toml`.
- Cargo using workspace resolver 2.
- A native C/C++ build toolchain for bundled database dependencies such as
  SQLite and DuckDB.
- Platform support for the plugin dependencies included in the selected
  artifact. The 2026-07-04 package-readiness run was performed on macOS arm64.
- No live service secrets are required for these build commands.
- Cross-platform package CI should use the platform labels, runner
  prerequisites, and skip rules in Package CI Matrix.

## Artifact Naming

- `voidb` is the terminal UI binary.
- `voidb-cli` is the agent- and script-friendly CLI binary.
- `voidb-sync-server` is the optional standalone sync server binary.
- Legacy database TUI and router-hosted plugin bridge artifacts are no longer
  built or staged.

## Local State To Back Up

Before replacing binaries or running any release-candidate migration command,
back up the local VoidB config directory. On Linux and macOS this is normally:

```bash
VOIDB_CONFIG_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/voidb"
VOIDB_BACKUP_ROOT="$HOME/.voidb-backups"
VOIDB_BACKUP_DIR="$VOIDB_BACKUP_ROOT/$(date +%Y%m%d-%H%M%S)"

mkdir -p "$VOIDB_BACKUP_DIR"
test -d "$VOIDB_CONFIG_DIR"
cp -Rp "$VOIDB_CONFIG_DIR" "$VOIDB_BACKUP_DIR/voidb"
```

Back up these files when present:

| Path | Purpose | Upgrade expectation |
|---|---|---|
| `config.toml` | App settings, master-password verifier, and optional pre-migration connection backup. | Must remain readable; native profile CRUD does not write connections here. |
| `profiles.json` | Active native profile identity, metadata, policy, and credential references. | Updated by Connection Manager CRUD and explicit migration. |
| `credentials.json` | Encrypted local plugin configuration and credential records. | Must not contain plaintext secrets. |
| `saved_queries.json` | Saved SQL/query snippets. | Should be preserved unchanged by binary upgrades. |
| `query_history.txt` | Local query history. | Should be preserved unchanged by binary upgrades. |
| `sync.toml` | Sync plugin per-device bookkeeping. | Device-local. Do not treat it as portable shared state. |
| `plugins/` | Plugin-owned local state under the config directory. | Preserve unless a plugin release note says otherwise. |

If the config has been re-encrypted with a user master password, keep that
password available for the upgraded process. CLI operations that save protected
config require `VOIDB_MASTER_PASSWORD` in the current process; the TUI keeps an
entered password only in memory and drops it on exit.

Current migration expectations:

- Native profiles are the active source of truth.
- Legacy connections are never projected automatically into the profile list.
- Explicit migration imports self-contained native profiles and leaves
  `config.toml` unchanged only as a rollback backup.
- Migration commands must report what changed.
- Unknown plugin-specific JSON fields and encrypted `plugin_config` blobs must
  not be deleted during a binary-only upgrade.

The sync plugin separately supports `VOIDB_CONFIG_DIR` for disposable sync
smoke and multi-profile sync workflows. The main app config path still follows
the platform config directory used by `AppConfig`.

## Install And Upgrade

Use the local packaging script when preparing release-candidate artifacts. It
stages every shipped binary under a versioned, platform-qualified directory and
then generates `SHA256SUMS` plus `artifact-manifest.json`.

```bash
scripts/stage-release-artifacts.sh --build
```

The default output root is:

```text
target/package/voidb-<version>-<platform>/
  voidb-default/voidb
  cli/voidb-cli
  sync-server/voidb-sync-server
  SHA256SUMS
  artifact-manifest.json
```

For a faster packaging-only refresh after manually building binaries, copy the
current outputs without rebuilding:

```bash
scripts/stage-release-artifacts.sh --skip-build
```

When using `--skip-build`, pass `--tui-bin`, `--cli-bin`, or
`--sync-server-bin` when the prebuilt artifacts live outside the standard
`target/<profile>/` paths.

Regenerate manifest metadata for an existing staged directory:

```bash
scripts/generate-release-manifest.sh \
  --artifact-root target/package/voidb-0.3.0-rc.1-darwin-arm64
```

Install or replace user-local binaries:

```bash
mkdir -p "$HOME/.local/bin"
install -m 0755 target/package/voidb-0.3.0-rc.1-darwin-arm64/voidb-default/voidb "$HOME/.local/bin/voidb"
install -m 0755 target/package/voidb-0.3.0-rc.1-darwin-arm64/cli/voidb-cli "$HOME/.local/bin/voidb-cli"
```

Install `sync-server/voidb-sync-server` only for deployments that run a local or
hosted sync server.

Upgrade sequence:

1. Stop running `voidb` TUI sessions and any `voidb-sync-server` process being
   replaced.
2. Back up the config directory and any sync server data directory.
3. Build or unpack the selected release artifacts into a staging directory.
4. Replace binaries with `install -m 0755`.
5. Run the release smoke commands from this document and
   [Release Candidate Checklist](release-candidate-checklist.md).
6. Keep the backup until the TUI, CLI, and any optional sync server smoke pass.

## Rollback

Binary rollback:

```bash
install -m 0755 "$PREVIOUS_RELEASE_DIR/voidb" "$HOME/.local/bin/voidb"
install -m 0755 "$PREVIOUS_RELEASE_DIR/voidb-cli" "$HOME/.local/bin/voidb-cli"
```

Config rollback:

```bash
test -n "$VOIDB_CONFIG_DIR"
test -d "$VOIDB_BACKUP_DIR/voidb"
mkdir -p "$(dirname "$VOIDB_CONFIG_DIR")"
rm -rf -- "$VOIDB_CONFIG_DIR"
cp -Rp "$VOIDB_BACKUP_DIR/voidb" "$VOIDB_CONFIG_DIR"
```

Sync server rollback:

```bash
install -m 0755 \
  "$PREVIOUS_RELEASE_DIR/voidb-sync-server" \
  "$HOME/.local/bin/voidb-sync-server"
```

Restore the sync server data directory from its own backup if the server schema
or on-disk layout changed during the failed upgrade. Do not rely on the sync
server as the only rollback copy of local config: the current sync plugin is
experimental, opt-in, and still uses a full-directory compatibility bundle.

After rollback, rerun the previous release's smoke checks and confirm that:

- `voidb-cli --version` reports the restored version;
- profile listing or connection listing works with the restored config;
- master-password protected configs still require the expected password;
- the TUI can open the Connection Manager without rewriting config;
- optional sync server health checks use the restored server data.

## Packaging Smoke

Run packaging smoke after building or unpacking release artifacts. These checks
do not require live service credentials.

```bash
scripts/package-smoke.sh \
  --artifact-root target/package/voidb-0.3.0-rc.1-darwin-arm64
```

For native macOS x64 package evidence, run the same staging and smoke contract
on a runner where `uname -m` reports `x86_64`:

```bash
VOIDB_PACKAGE_VERSION=0.3.0-rc.1 \
VOIDB_PACKAGE_PLATFORM=darwin-x64 \
scripts/stage-release-artifacts.sh \
  --build \
  --out target/package-ci \
  --version 0.3.0-rc.1 \
  --platform darwin-x64

scripts/package-smoke.sh \
  --artifact-root target/package-ci/voidb-0.3.0-rc.1-darwin-x64
```

For native Windows x64 package evidence, run from Git Bash or an equivalent
Bash environment on a Windows x64 runner with the Rust MSVC toolchain:

```bash
scripts/stage-release-artifacts.sh \
  --build \
  --out target/package-ci \
  --version 0.3.0-rc.1 \
  --platform windows-x64

scripts/package-smoke.sh \
  --artifact-root target/package-ci/voidb-0.3.0-rc.1-windows-x64
```

Windows staged executable names are `voidb-default/voidb.exe`,
`cli/voidb-cli.exe`, and `sync-server/voidb-sync-server.exe`. Record skipped
POSIX install-command checks as Windows-not-applicable, not as package-smoke
failures.

For Linux package smoke from a Docker-capable non-Linux host or CI worker, use
the Docker wrapper. It builds inside the requested Linux container platform,
stages artifacts with a platform label, verifies `SHA256SUMS` and
`artifact-manifest.json`, runs the same package smoke, and writes review
evidence:

```bash
scripts/linux-package-smoke.sh \
  --docker-platform linux/amd64 \
  --package-platform linux-x64 \
  --report target/tmp/linux-package-smoke-evidence.md
```

The wrapper uses `target/linux-package-smoke/` for Linux build/cache state so it
does not overwrite host `target/release` binaries from macOS or Windows package
runs.

Manual TUI package smoke must run from a real terminal, not a non-interactive
shell:

```bash
target/package/voidb-0.3.0-rc.1-darwin-arm64/voidb-default/voidb
```

Record the following before promoting the artifact:

- the platform label, runner OS/architecture, Rust/Cargo versions, artifact
  root, commands, and SHA256SUMS are captured in the evidence entry described in
  [Package CI Matrix](package-ci-matrix.md#package-evidence-format);
- default TUI starts, opens the Connection Manager, and exits with `Ctrl+Q`;
- shell escape menu opens with `Ctrl+\`;
- tab manager opens with `Ctrl+L`;
- `q` returns home when the active plugin is not in raw-input mode;
- a password or master-password dialog keeps typed characters inside the dialog;
- profile open actions show CLI/capability guidance instead of legacy plugin UI.

For package archives, generate checksums after staging and before upload:

```bash
scripts/generate-release-manifest.sh \
  --artifact-root target/package/voidb-0.3.0-rc.1-darwin-arm64
```

## Publish Handoff

Packaging automation prepares release evidence. It does not publish a release.

Automation may:

- build release binaries;
- stage platform-qualified artifact directories;
- generate `SHA256SUMS` and `artifact-manifest.json`;
- run package smoke checks;
- retain private CI artifacts for release-owner review.

Automation must not:

- create or push git tags;
- create GitHub, Gitea, package-registry, installer-feed, or object-store
  releases;
- upload artifacts to a public release location;
- mark release notes final without a release-owner review;
- claim support for platforms whose package matrix jobs were skipped or failed.

The release owner performs the publish handoff after automated and manual gates
pass:

1. Review the staged artifact directory, `SHA256SUMS`, and
   `artifact-manifest.json`.
2. Confirm package versions, binary `--version` output, changelog target
   section, intended tag, and artifact directory agree.
3. Record package platforms, skipped platforms, live-smoke skips, manual TUI
   smoke, residual risks, and selected artifacts in the release notes.
4. Create the signed or annotated git tag.
5. Upload only the reviewed artifact files and checksums selected for the
   release.
6. Publish release notes that identify the human release owner or handoff
   record.

## Version, Tag, And Release Notes Checklist

Before tagging a release candidate:

- Pick the target SemVer version and decide whether the sync server uses the
  same version or a separately documented server version.
- Update every shipped crate `version` in `Cargo.toml`, including `voidb-core`,
  `voidb-tui`, `voidb-cli`, plugin crates, and `voidb-sync-server`.
- Refresh `Cargo.lock` after version changes.
- Move relevant `CHANGELOG.md` entries from `Unreleased` into the target version
  section and add the release date.
- Confirm binary versions with `voidb-cli --version` and
  `voidb-sync-server --version`.
- Create a signed or annotated tag named `vX.Y.Z` unless the release owner
  documents a different tag scheme.
- Record the commit SHA, platform, artifact names, checksums, skipped live
  smoke, and residual risks in the release notes.
- Include whether the package contains the default TUI, the CLI, the standalone
  sync server, or a subset of those artifacts.

Do not tag while Cargo package versions, binary `--version` output, changelog
sections, and artifact names disagree.

## Residual Packaging Risks

- Current `0.3.0-rc.1` package evidence covers native macOS arm64 artifacts and
  Docker Linux x64 package smoke. Native Linux x64 runner evidence, macOS x64,
  Windows x64, Linux arm64, and cross-compiled packages still need
  platform-specific smoke before release notes claim those boundaries.
- The TUI binary has no `--help`/`--version` command path today, so startup and
  router smoke remain manual terminal checks.
- Legacy database and router-hosted plugin TUI variants are removed from
  current packages. Any reintroduction requires a new explicit artifact name,
  release-owner approval, and release notes that distinguish it from the
  default capability-first TUI.
- Live S3, WebDAV, SSH, MySQL, external hosted Sync, native Linux x64 runner
  package smoke, macOS x64 package smoke, Windows x64 package smoke, and Linux
  arm64 package smoke require disposable external fixtures, credentials, or
  platforms and may be skipped only when recorded in release notes. Docker
  fixture smoke completed in
  Fixture-Backed Operations Plugin Promotion Smoke 2026-07-05.
  Redis local fixture-backed capability smoke completed in Req61; rerun
  `scripts/redis-fixture-smoke.sh` if Redis capabilities change before tag.
  Email local fixture-backed capability smoke now covers bounded reads, guarded
  mutations, attachment safety, and IDLE cancellation; rerun
  `scripts/email-fixture-smoke.sh` if those capabilities change before tag.
  Kubernetes local kind fixture-backed capability smoke completed in Req67;
  rerun `scripts/kubernetes-fixture-smoke.sh` if Kubernetes capabilities,
  namespace isolation, destructive safeguards, bounded output, or kubeconfig
  redaction behavior change before tag.
  MongoDB local fixture-backed capability smoke completed in Req68; rerun
  `scripts/mongodb-fixture-smoke.sh` if MongoDB capabilities, destructive
  safeguards, pagination, aggregation policy, or diagnostics redaction behavior
  change before tag.
  Elasticsearch local fixture-backed capability smoke completed in Req69; rerun
  `scripts/elasticsearch-fixture-smoke.sh` if Elasticsearch capabilities,
  destructive safeguards, pagination, mapping output, or endpoint/auth
  redaction behavior change before tag.
  Jenkins local fixture-backed capability smoke completed in Req70; rerun
  `scripts/jenkins-fixture-smoke.sh` if Jenkins capabilities, destructive
  safeguards, console bounds, target-error redaction, or fixture setup changes
  before tag.
- The current sync plugin is beta-certified but opt-in. Req60 completed the
  local object-level and hosted-process smoke gate; external hosted deployment
  smoke still requires release-specific infrastructure evidence. The
  full-directory bundle is useful for compatibility backup, but it is not the
  stable object-level profile/credential sync contract. Stable/default
  promotion still requires release-owner acceptance of the gate in
  Sync Beta Readiness.
- Req71 removed the inherited `imap-proto v0.10.2` future-incompatibility
  warning by upgrading Email to exact-pinned `imap 3.0.0-alpha.15`; current
  Email future-incompat checks report zero dependency notices.
- The 2026-07-04 package-readiness run found version/tag mismatch: shipped
  crates and binaries still reported `0.1.0` while `CHANGELOG.md` already
  contained a historical `0.2.0` section. Requirement 53 resolved this for
  `0.3.0-rc.1`; treat the 2026-07-04 mismatch as historical evidence only.

Historical package-smoke sections below predate Requirement 77 and may mention
legacy TUI artifacts or `legacy-db-tui` build commands. They are retained as
dated evidence only; current packaging no longer builds or stages those
artifacts.

## 2026-07-05 Req74 Linux Docker Package Smoke

Task Weaver requirement 74 added a Docker-backed Linux package smoke path and
ran it for `linux-x64` from a Docker-capable host:

```bash
scripts/linux-package-smoke.sh \
  --docker-platform linux/amd64 \
  --package-platform linux-x64 \
  --report target/tmp/linux-package-smoke-evidence.md
```

Evidence summary:

| Field | Value |
|---|---|
| Commit | `f1e9db0` |
| Result | Passed |
| Docker image | `rust:1-bookworm` |
| Docker platform | `linux/amd64` |
| Package platform label | `linux-x64` |
| Artifact root | `target/package-linux/voidb-0.3.0-rc.1-linux-x64` |
| Evidence path | `target/tmp/linux-package-smoke-evidence.md` |

Linux Docker staged checksums:

| Artifact | Path | SHA-256 |
|---|---|---|
| Default TUI | `voidb-default/voidb` | `4cfbcbdf9077d27db153b00c9254dfde202ff1aa93511ec6d23e22123af17ab4` |
| CLI | `cli/voidb-cli` | `3c6edf827d53b916e1ac44cd91e8189c101eed654f075e5b84b9f3e98ff4c3cb` |
| Legacy database TUI | `voidb-legacy/voidb` | `3c478326abc6722346704a5362250eae03b673c9b4227bd7a78c79461bcb2cfd` |
| Sync server | `sync-server/voidb-sync-server` | `559a159e9090044ef3b82acf6020da64cf7c525ed5fb1ac5fd5d09a4be3b084d` |

This is valid Linux x64 Docker package-smoke evidence. It is not native Linux
x64 runner evidence unless the same package contract is rerun on a native
Linux x86_64 runner.

## 2026-07-05 Req53 Final Tag Readiness Package Smoke

Task Weaver requirement 53 rebuilt and staged release-candidate artifacts at:

`target/package/voidb-0.3.0-rc.1-darwin-arm64`

| Check | Command | Result | Observed artifact |
|---|---|---|---|
| Default TUI release build | `cargo build --release` | passed | `target/package/voidb-0.3.0-rc.1-darwin-arm64/voidb-default/voidb`, macOS arm64 |
| CLI release build | `cargo build --release -p voidb-cli` | passed | `target/package/voidb-0.3.0-rc.1-darwin-arm64/cli/voidb-cli`, macOS arm64 |
| Legacy database TUI release build | `cargo build --release -p voidb-tui --features legacy-db-tui` | passed | `target/package/voidb-0.3.0-rc.1-darwin-arm64/voidb-legacy/voidb`, macOS arm64 |
| Sync server release build | `cargo build --release --manifest-path voidb-sync-server/Cargo.toml` | passed | `target/package/voidb-0.3.0-rc.1-darwin-arm64/sync-server/voidb-sync-server`, macOS arm64 |
| CLI entry point smoke | CLI version and command-family help | passed | `voidb 0.3.0-rc.1` |
| Sync server entry point smoke | Sync server version and help | passed | `voidb-sync-server 0.3.0-rc.1` |
| Default TUI real-terminal smoke | Packaged default `voidb` with disposable `HOME` | passed | Connection Manager, credential masking, profile CRUD/test/open, tab manager, shell escape, and terminal restore. |
| Legacy TUI real-terminal smoke | Packaged legacy `voidb` with disposable `HOME` | passed after fix | SQLite connection opened the legacy browser surface. |
| Staged artifact checksums | `shasum -a 256 ...` | passed | Checksums below. |

Final staged checksums:

| Artifact | Path | Size | SHA-256 |
|---|---|---:|---|
| Default TUI | `target/package/voidb-0.3.0-rc.1-darwin-arm64/voidb-default/voidb` | 15,187,584 | `0ec55001254216eaa7fb2fabdaf435dcf024372018078b15bb002e2d27db0295` |
| CLI | `target/package/voidb-0.3.0-rc.1-darwin-arm64/cli/voidb-cli` | 37,649,200 | `c080ccb34f96fc0173fbb5f04ccbdca53d70928b6884793f4a5ede2f4f3f2d00` |
| Legacy database TUI | `target/package/voidb-0.3.0-rc.1-darwin-arm64/voidb-legacy/voidb` | 37,813,408 | `40cd27696ad2a267896ea897ccf918f84fbbba49586acd19389f74f4d6f2baf4` |
| Sync server | `target/package/voidb-0.3.0-rc.1-darwin-arm64/sync-server/voidb-sync-server` | 6,500,576 | `27e54dfcc9e7f4f13308a1d08fd957865b67ba8444a28ae628142d8419ec287f` |

Refresh notes:

- This Req53 package smoke originally retained the inherited
  `imap-proto v0.10.2` future-incompatibility warning. Req71 later superseded
  that residual risk with the exact-pinned Email `imap 3.0.0-alpha.15` upgrade.
- The first legacy TUI package smoke exposed a composite-key lookup bug in
  legacy database factories. Requirement 53 fixed SQLite, PostgreSQL, and
  DuckDB factories to accept both composite keys and legacy display names.
- Version/tag consistency is resolved for `0.3.0-rc.1`: crate versions,
  `Cargo.lock`, `voidb-cli --version`, `voidb-sync-server --version`,
  changelog section, artifact directory, and intended tag agree.

## 2026-07-04 Package-Readiness Run

Local logs were written under
`target/tmp/package-readiness-2026-07-04/` and are not committed.

| Check | Command | Result | Duration | Observed artifact |
|---|---|---|---|---|
| Default TUI release build | `cargo build --release` | passed | 3m 15s | `target/release/voidb`, 14M, Mach-O arm64 |
| CLI release build | `cargo build --release -p voidb-cli` | passed | 5m 03s | `target/release/voidb-cli`, 34M, Mach-O arm64 |
| CLI entry point smoke | `./target/release/voidb-cli --help` | passed | <1s | Listed command families including `connections`, `credential`, `profile`, `plugin`, `invoke`, and protocol plugins. |
| Legacy database TUI release build | `cargo build --release -p voidb-tui --features legacy-db-tui` | passed | 2m 27s | `target/release/voidb`, 36M, Mach-O arm64 |
| Sync server release build | `cargo build --release --manifest-path voidb-sync-server/Cargo.toml` | passed | 36.92s | `voidb-sync-server/target/release/voidb-sync-server`, 5.9M, Mach-O arm64 |
| Sync server entry point smoke | `./voidb-sync-server/target/release/voidb-sync-server --help` | passed | <1s | Help and version output reported `voidb-sync-server 0.1.0`. |
| Staged package smoke | commands in `Packaging Smoke` | passed | <1s | Verified executable bits, CLI command-family help, sync server help/version. |
| Staged artifact checksums | `shasum -a 256 ...` | passed | <1s | Checksums generated for default TUI, legacy TUI, CLI, and sync server artifacts. |

Known warning:

- Cargo reported inherited future-incompatibility risk for `imap-proto v0.10.2`.
  This matched the release rehearsal warning set and did not fail the build.
  Req71 later superseded this historical warning with the exact-pinned Email
  `imap 3.0.0-alpha.15` upgrade.
- Manual TUI package smoke was not rerun as part of the staged artifact smoke;
  the release-candidate checklist still requires real-terminal TUI coverage
  before tagging.

## 2026-07-04 Requirement 34 Package Smoke Refresh

Requirement 34 slice 2 reran package smoke after Sync conflict UX and plugin
readiness updates landed. Local logs were written to
`/tmp/voidb-r34-package-smoke.log` and are not committed.

| Check | Command | Result | Duration | Observed artifact |
|---|---|---|---|---|
| Default TUI release build | `cargo build --release` | passed | 1m 38s | `target/package/voidb-default/voidb`, 14M, macOS arm64 |
| CLI release build | `cargo build --release -p voidb-cli` | passed | 1m 50s | `target/package/cli/voidb-cli`, 35M, macOS arm64 |
| Legacy database TUI release build | `cargo build --release -p voidb-tui --features legacy-db-tui` | passed | 1m 55s | `target/package/voidb-legacy/voidb`, 36M, macOS arm64 |
| Sync server release build | `cargo build --release --manifest-path voidb-sync-server/Cargo.toml` | passed | 4.07s | `voidb-sync-server/target/release/voidb-sync-server`, 6.2M, macOS arm64 |
| Staged executable smoke | executable bits, CLI help/version, sync-server help/version | passed | <1s | CLI reported `voidb 0.1.0`; sync server reported `voidb-sync-server 0.1.0`. |
| Staged artifact checksums | `shasum -a 256 ...` | passed | <1s | Checksums generated for default TUI, legacy TUI, CLI, and sync server artifacts. |

Refreshed staged checksums:

| Artifact | Path | SHA-256 |
|---|---|---|
| Default TUI | `target/package/voidb-default/voidb` | `614cb77e14294f838e359ed64906b64676f9432a20b0ce15afd4933b27c36ecf` |
| CLI | `target/package/cli/voidb-cli` | `52795513c9f9bd3addf9a72e49dc344fe9988a5e4e3415a84fd3afd4818bd5c8` |
| Legacy database TUI | `target/package/voidb-legacy/voidb` | `01f7b12eeb92495f2688e94ed8b188e9c404c2a278ed61d2b0d20f4003f04abd` |
| Sync server | `voidb-sync-server/target/release/voidb-sync-server` | `e8d5ca0223bcc5afb4a4df69c0bac2fd1d6f8b966cf309f25cc6a8ea12c4648c` |

Refresh notes:

- This refresh originally retained the inherited `imap-proto v0.10.2`
  future-incompatibility warning. Req71 later superseded that historical
  package-warning note with the exact-pinned Email `imap 3.0.0-alpha.15`
  upgrade.
- The TUI binary still has no `--help` or `--version` path, so default and
  legacy TUI artifacts still need real-terminal startup and key-routing smoke.
- The refreshed staged smoke did not reconcile release versions. All shipped
  crates and binary output still report `0.1.0`, while `CHANGELOG.md` already
  contains a historical `0.2.0` section.
