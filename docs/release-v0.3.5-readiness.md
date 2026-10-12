# VoidB v0.3.5 release result

Status: **published; public distribution acceptance passed**.

- [Core v0.3.5](https://github.com/limmytian/voidb/releases/tag/v0.3.5) contains only `voidb` and `voidb-cli`.
- All 14 official plugins have new signed v0.3.4 Releases for Linux x86_64/ARM64 and macOS Intel/ARM64.
- The main official registry selects authenticated v0.3.4 packages and retains v0.3.3 history.
- Both Homebrew formulas use the four actual public Unix archive URLs and SHA-256 values.
- This machine's Homebrew CLI is v0.3.5, `brew test` passed, and its plugin list remains empty.
- All 680 pre-existing user-state/backup files remain byte-identical. Profiles, encrypted credentials, installation history and original backups were preserved. The old v0.3.4 keg was retained.
- Older plugin v0.3.3 tags/assets and core v0.3.4 assets remain unchanged.

The owner explicitly approved implementation, local release-key creation, candidate
pushes/protected CI, then merges/new tags/publication and public distribution checks.
No requirement or task was duplicated. Task Weaver project:
`02710c97-c2c3-4047-812d-58f03060e75f`; requirement:
`5de6cf6c-d4a7-466e-815b-736683ed6132`.

## Security and installation behavior

Managed execution requires valid installation records and strict Ed25519 provenance
anchored in the compiled official root. Proofs bind ID, version, protocol, host target,
executable and every payload file. Missing records/proofs, omitted legacy digests,
rewritten binary/digest pairs, forged proofs, extra files, changed schemas and managed
symlinks fail closed before child launch. No legacy digest backfill trusts current bytes.

Verified reinstall handles unsigned legacy installations. Install/update serialize
writers, verify before activation, atomically sync/replace records and restore matching
packages on activation failure. Disabled state is preserved. Rollback validates retained
proofs. Fresh legacy registry caches remain untouched while the trust-policy namespace
fetches signed metadata immediately after a core upgrade.

Core packages, shell installer and Homebrew install no plugins automatically. Explicit
registry-first `install-default` installs the recommended six; individual installation
and deliberately configured offline/development roots remain available. First interactive
startup offers install/skip, persists skip/completion and retries partial failure.
Noninteractive startup never downloads or prompts. Connection Manager `i` installs only
the selected missing official plugin, handles cancellation/error/retry and refreshes
state. Disabled, invalid and incompatible installations are not overwritten. Installation
children close stdin and do not receive the main password.

Explicit unsigned development requires a development root outside managed user paths
and `VOIDB_ALLOW_UNSIGNED_PLUGINS=1`. See the [trust contract](plugin-trust-v0.3.5.md)
for exact envelopes, root rotation and residual limits. Core/root/OS/invocation environment
and approved publisher CI remain trusted. The design does not defeat replacement of
those roots, a compromised signer, or every portable hash-to-execution race. Existing
trusted live sessions are not retroactively terminated by deleting disk metadata.

## Signing ownership and release identities

Key ID: `official-2026-10`; public key:
`2d00e2e461719c94b77cf0e9d1d49a9cf1c8dbe8f802696b801b432bfcc95ea2`.
The owner holds the private key outside repositories, mode 0600 in a mode 0700 directory.
Tools reject payload-local/hard-linked keys; synthetic tests use independent test keys.
All 14 signing environments require owner review and restrict branch/tag access; private
keys are available only to the protected signing step. Approved candidate source commits
were checked before environment approval. No private key was placed in an asset or log.

Plugin Releases promoted the exact authenticated, protected-CI-signed candidate bits.
Assets were uploaded into new drafts, checked against server digests and then published.
Duplicate tag-triggered rebuilds were cancelled. Core v0.3.5 uses exact-source five-platform
candidate artifacts built after the publication fixes; its tag points to
`a2cc72b6b730c56aefedbd218ad0c9f6612bf8e5`.

| Repository | v0.3.4 tag/source commit |
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

Core source CI: [38243282331](https://github.com/limmytian/voidb/actions/runs/38243282331),
all jobs passed. Core five-platform candidate:
[38243526017](https://github.com/limmytian/voidb/actions/runs/38243526017), passed;
public publication promoted those verified artifacts. Core PR 1 and all 14 plugin PRs
were merged. Homebrew PR 1 merged at `1143807e9046806b0ff864702ea3503fc61c6eb9`;
formula source commit `bcee67c356a9cca3a09d66912e987e0d0211ed63`.

## Acceptance evidence

The [publication evidence](release-v0.3.5-publication-evidence.json) records exact
release IDs, asset IDs/digests, source commits, CI, public downloads and acceptance.
The [candidate evidence](release-v0.3.5-remote-evidence.json) and
[original local evidence](release-v0.3.5-local-evidence.json) preserve preparation history.

- All 14 plugin PR CI, four native build targets and protected signing passed.
- All 168 archives, detached signatures, payload file maps and binary architectures were authenticated. All 350 published asset digests match those reviewed bits.
- All 56 actual public gzip platform archives and signatures were downloaded, provenance-verified and indexed before registry promotion.
- Five actual public core archives match checksums and contain exactly two regular binaries.
- Actual public core CLI and default main HTTPS registry passed default/all-14 installation, initialize/health, update, verified rollback, uninstall/no fallback and copied actual v0.3.3 recovery.
- Fresh seeded legacy registry caches were ignored for signed selection and preserved unchanged.
- Record deletion, omitted digest, malformed record, binary/digest co-modification and forged proof failed before domain/TUI/serve/test dispatch with no marker, secret output or backfill. Additional signer/ID/version/target/schema/extra-file/symlink gates passed in core tests.
- Actual public shell downloads passed clean installation and upgrade from real v0.3.4 binaries. Bad-checksum refusal before overwrite also passed in the controlled HTTP test.
- Actual Homebrew public upgrade/test passed; only two binaries were installed, global plugins remain absent and existing user-state files were preserved.
- Public Homebrew first-launch PTY with default main registry installed six signed plugins in isolated HOME and persisted completion. An initial public attempt reported incomplete installation; repeated acceptance passed. Controlled normal/minimum-size PTYs cover skip, partial failure, retry, cancellation and selected-only contextual installation.
- Full workspace tests/Clippy, CLI full-feature tests, 16 Python signing/staging tests, shell/Ruby syntax and diff checks passed. CI fixture fixes preserved production enforcement. Repository-wide formatting still has pre-existing unrelated differences; changed code was formatted without broad churn.

## Explicit platform limits

Full public installer/registry/CLI/TUI/rollback E2E ran on macOS ARM64. Other targets
have native CI/build and authenticated artifact evidence, not full live-database E2E.
Windows has a core package only; no official Windows plugin support is claimed.

Old tags/assets were not rewritten. Actual public artifact hashes were used to update
registry/formulas; staged candidate hashes were not assumed to survive a rebuild.
Final post-publication formula/evidence updates are committed separately from the
immutable release source.
