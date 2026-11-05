# Release Packaging

This document records the package and distribution contract for VoidB release
candidates. It complements the release-candidate gate matrix in
[Release Candidate Checklist](release-candidate-checklist.md), and the
cross-platform job contract is defined by the release workflow
(`.github/workflows/release.yml`) and the build matrix in this document.

## Build Matrix

| Artifact | Command | Output | Notes |
|---|---|---|---|
| Default TUI | `cargo build --release` | `target/release/vb-tui` | The workspace `default-members` list only includes `crates/voidb-tui`, so this is the lightweight default TUI build. |
| CLI | `cargo build --release -p vb` | `target/release/vb` | Builds the machine-readable command surface and all CLI plugin command families. It is not produced by the default workspace build. |
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
  artifact.
- No live service secrets are required for these build commands.
- Cross-platform package CI should use the platform labels, runner
  prerequisites, and skip rules defined in the release workflow
  (`.github/workflows/release.yml`).

## Artifact Naming

- `vb-tui` is the terminal UI binary.
- `vb` is the agent- and script-friendly CLI binary.
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
  cli/vb
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
  --artifact-root target/package/voidb-<version>-darwin-arm64
```

Install or replace user-local binaries:

```bash
mkdir -p "$HOME/.local/bin"
install -m 0755 target/package/voidb-<version>-darwin-arm64/voidb-default/voidb "$HOME/.local/bin/voidb"
install -m 0755 target/package/voidb-<version>-darwin-arm64/cli/vb "$HOME/.local/bin/vb"
```

Install `sync-server/voidb-sync-server` only for deployments that run a local or
hosted sync server.

Upgrade sequence:

1. Stop running `vb-tui` TUI sessions and any `voidb-sync-server` process being
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
install -m 0755 "$PREVIOUS_RELEASE_DIR/vb" "$HOME/.local/bin/vb"
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

- `vb --version` reports the restored version;
- profile listing or connection listing works with the restored config;
- master-password protected configs still require the expected password;
- the TUI can open the Connection Manager without rewriting config;
- optional sync server health checks use the restored server data.

## Packaging Smoke

Run packaging smoke after building or unpacking release artifacts. These checks
do not require live service credentials.

```bash
scripts/package-smoke.sh \
  --artifact-root target/package/voidb-<version>-darwin-arm64
```

For native macOS x64 package evidence, run the same staging and smoke contract
on a runner where `uname -m` reports `x86_64`:

```bash
VOIDB_PACKAGE_VERSION=<version> \
VOIDB_PACKAGE_PLATFORM=darwin-x64 \
scripts/stage-release-artifacts.sh \
  --build \
  --out target/package-ci \
  --version <version> \
  --platform darwin-x64

scripts/package-smoke.sh \
  --artifact-root target/package-ci/voidb-<version>-darwin-x64
```

For native Windows x64 package evidence, run from Git Bash or an equivalent
Bash environment on a Windows x64 runner with the Rust MSVC toolchain:

```bash
scripts/stage-release-artifacts.sh \
  --build \
  --out target/package-ci \
  --version <version> \
  --platform windows-x64

scripts/package-smoke.sh \
  --artifact-root target/package-ci/voidb-<version>-windows-x64
```

Windows staged executable names are `voidb-default/voidb.exe`,
`cli/vb.exe`, and `sync-server/voidb-sync-server.exe`. Record skipped
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
target/package/voidb-<version>-darwin-arm64/voidb-default/vb-tui
```

Record the following before promoting the artifact:

- the platform label, runner OS/architecture, Rust/Cargo versions, artifact
  root, commands, and SHA256SUMS are captured in a dated evidence entry under
  `target/tmp/`;
- default TUI starts, opens the Connection Manager, and exits with `Ctrl+Q`;
- shell escape menu opens with `Ctrl+\`;
- tab manager opens with `Ctrl+L`;
- `q` returns home when the active plugin is not in raw-input mode;
- a password or master-password dialog keeps typed characters inside the dialog;
- profile open actions show CLI/capability guidance instead of legacy plugin UI.

For package archives, generate checksums after staging and before upload:

```bash
scripts/generate-release-manifest.sh \
  --artifact-root target/package/voidb-<version>-darwin-arm64
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
  `voidb-tui`, `vb`, plugin crates, and `voidb-sync-server`.
- Refresh `Cargo.lock` after version changes.
- Move relevant `CHANGELOG.md` entries from `Unreleased` into the target version
  section and add the release date.
- Confirm binary versions with `vb --version` and
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

- Current `<version>` package evidence covers native macOS arm64 artifacts and
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
  platforms and may be skipped only when recorded in release notes. Existing
  local fixture wrappers in `scripts/` rerun before tag when the matching
  plugin capabilities change (`scripts/ssh-fixture-smoke.sh`,
  `scripts/mysql-fixture-smoke.sh`, `scripts/redis-fixture-smoke.sh`,
  `scripts/postgres-session-fixture-smoke.sh`). The Email, S3, and WebDAV
  fixture wrappers are 0.4.1 deliverables (see the
  [0.4.1 Iteration Roadmap](roadmap-0.4.1.md)); until they land, exercise
  those plugins inside their own repositories.
- The current sync plugin is beta-certified but opt-in. The local object-level
  and hosted-process smoke gate runs through `scripts/release-sync-smoke.sh`;
  external hosted deployment smoke still requires release-specific
  infrastructure evidence. The full-directory bundle is useful for
  compatibility backup, but it is not the stable object-level
  profile/credential sync contract. Stable/default promotion still requires
  release-owner acceptance of that gate and the boundary in
  [Sync Boundary Under The Capability Model](sync-boundary.md).
- Email pins `imap 3.0.0-alpha.15` exactly, which removed the inherited
  `imap-proto` future-incompatibility warning; current Email future-incompat
  checks report zero dependency notices.
- Version/tag consistency: shipped crates, binaries, `CHANGELOG.md` sections,
  and tag names must agree before tagging. Historical mismatches are recorded
  in git history only.
