# v0.3.5 release candidate readiness

Status: owner approved publication; all 14 official plugins v0.3.4 are public.
Core v0.3.5 and final Homebrew/public installation acceptance are in preparation.
The public baseline remains core v0.3.4 and all 14 official plugins v0.3.3.
No new tags or public releases were created or replaced. The installed Homebrew
CLI remains v0.3.4, its plugin list is empty, and actual profiles, credentials,
installation history and uninstalled-plugin backups were preserved.

The owner authorized implementation, verification, local commits and creation of
a local release key, then approved candidate branch pushes, protected signing CI
and non-publishing cross-platform runs. All 16 candidate branches were pushed and
have draft pull requests. No requirement or task was recreated. Task Weaver:
project `02710c97-c2c3-4047-812d-58f03060e75f`, requirement
`5de6cf6c-d4a7-466e-815b-736683ed6132`.

## Candidate version matrix

| Component | Candidate | Verified scope |
| --- | --- | --- |
| Core shell, CLI, core library and SDK | 0.3.5 | Workspace tests/Clippy, five native CI platforms, five core-only archives |
| All 14 official plugins | 0.3.4 | PR CI, four native builds, 168 signed archives and detached signatures |
| Plugin SDK/core dependency pin | `31d22cd09c9b10f1d22f59d47e789a49c33a290d` | Existing driver/transport ABI; actual initialize/health acceptance |
| Homebrew published formula | 0.3.4 until final public assets exist | Core-only logic prepared; candidate four-platform hashes staged separately |

Official plugins: mysql, postgres, sqlite, redis, ssh, duckdb, docker, kubernetes,
s3, elasticsearch, mongodb, jenkins, webdav and email. Protocol 1 remains supported.
New signed plugin assets use v0.3.4; published v0.3.3 assets remain immutable.
Windows has a core package only; no official Windows plugin support is claimed.

## Implementation reviewed

The previous uncommitted core-only packaging, installer, discovery, onboarding and
contextual installation work was preserved, reviewed and committed.

Managed plugins require a valid installation record and strict Ed25519 provenance
before child launch. The compiled root binds plugin ID, version, protocol, target,
executable path and every payload file. Missing records, omitted digests, rewritten
binary/digest pairs, forged proofs, changed schemas, extra files and managed symlinks
fail closed. Existing binaries are never silently trusted or used to backfill old
records. Explicit unsigned development requires a development root outside managed
user directories and `VOIDB_ALLOW_UNSIGNED_PLUGINS=1`.

Install/update verify before activation, serialize writers with an OS file lock,
atomically sync/replace records and restore matching previous packages on activation
failure. Disabled state is preserved. Verified reinstall handles legacy missing
records; verified rollback retains matching proofs. Registry selection checks signed
identity/version, and registry indexing authenticates target-qualified archives.
Runtime uses the compiled host target; distribution tooling may inspect foreign targets.

Core packages contain only `voidb` and `voidb-cli`. Default discovery does not scan
system/prefix bundled locations. Registry-first `install-default` is explicit;
`--from-bundled` preserves deliberate offline roots. First interactive startup offers
install or skip, remembers skip and retries partial failure. Noninteractive startup
never prompts or downloads. Connection Manager contextual installation installs only
the selected missing official plugin, handles cancellation/error/retry and refreshes
state. Disabled/invalid/incompatible installations are not overwritten. Installer
children close stdin and remove the master-password environment variable.

The [trust contract](plugin-trust-v0.3.5.md) states the exact envelope, immutable
payload policy, key lifecycle and residual hash-to-execution race. Core executable,
embedded trust roots, OS, invocation environment and approved publisher CI remain
trusted. Replacing the main executable/trust roots or compromising the signer is
outside the guarantee. Existing authenticated live sessions are not retroactively
terminated when disk metadata is deleted.

## Signing ownership and protected CI

Key ID: `official-2026-10`. Public key:
`2d00e2e461719c94b77cf0e9d1d49a9cf1c8dbe8f802696b801b432bfcc95ea2`.
The owner holds the private key outside repositories in a mode 0700 directory with
a mode 0600, single-link key file. Tools reject payload-local or hard-linked keys.
Synthetic signing regression tests use independent test keys.

All 14 `plugin-release-signing` environments require `limmytian` review and permit
only `codex/v0.3.5-trust-hardening` or version tags. The environment secret
`VOIDB_PLUGIN_SIGNING_KEY_PEM` is available only in the protected signing step,
never PR/build jobs. Self-review is available because the owner is the sole reviewer.
Candidate reviews used the normal approval API after checking workflow-dispatch
identity and exact source commit; they did not bypass environment protection.

## Validation evidence

The committed [local evidence](release-v0.3.5-local-evidence.json) records original
native preparation. The [remote evidence](release-v0.3.5-remote-evidence.json) is the
current acceptance record, including exact CI runs, commits and archive hashes.

- All 14 plugin PR CI and four-target release candidate runs passed.
- All 168 plugin archives (14 plugins × 4 targets × 3 formats), detached signatures,
  payload proofs/file maps and declared ELF/Mach-O architecture were independently verified.
- The CI-built production CLI authenticated all 56 gzip platform packages into a
  14-plugin index.
- Core candidate run [38218876435](https://github.com/limmytian/voidb/actions/runs/38218876435)
  passed five native platforms. All archives contain exactly two regular core binaries.
- Core CI [38226398631](https://github.com/limmytian/voidb/actions/runs/38226398631)
  passed at `9295d28396f2de06b064a687b79e83d0c9b80d23`: fast/full tests, Clippy,
  capability drift and five native platform gates.
- Local full workspace tests/Clippy and 188 full-feature CLI tests passed after fixes.
  Shared Python signing/staging tests, shell/Ruby syntax and diff checks passed.
- Actual CI core/plugin binaries over real HTTP passed default and all-14 installs,
  initialize/health, verified update/rollback, uninstall with no fallback and migration
  of a copied actual immutable v0.3.3 MySQL backup.
- Five attack classes failed before domain/TUI/serve/test dispatch, with no child
  marker, secret output or digest backfill. Core tests cover additional signer,
  identity, target, schema, extra-file and symlink attacks.
- Real normal/minimum-size PTYs passed six-plugin onboarding, partial failure and
  next-launch retry, persistent skipping, noninteractive no-download, contextual
  cancellation and selected-only failure/retry. Profile/credential bytes were unchanged.
- The unchanged shell installer fetched actual CI core archives and checksums using
  real curl/HTTP with candidate GitHub URLs routed to loopback. Clean install,
  actual v0.3.4 binary upgrade and checksum refusal before overwrite passed.
- Actual Homebrew Formula DSL installed a verified candidate in an isolated prefix,
  with only two core binaries. The candidate four-platform formula was rendered from
  actual archive hashes and staged at `target/v0.3.5-remote-candidate/homebrew/voidb.rb`.

CI found unsigned transport fixtures without explicit development opt-in; they now
use isolated test subprocesses. CI also exposed a pre-existing 200 ms broker test
watchdog sensitive to scheduler load; it now allows 2 s while retaining the blocked
fixture, 100 ms request deadline, abort-state and exactly-once cleanup assertions.
Production trust/runtime behavior was not relaxed. The final CI passed both fixes.
The full repository formatting check still reports pre-existing unrelated differences;
changed code was formatted without broad unrelated churn.

## Explicit limits and publication sequence

Full installer/registry/CLI/TUI/rollback E2E ran natively on macOS ARM64. Other targets
have native build/CI gate and authenticated artifact evidence, not full live-database
E2E. Public GitHub Release and raw-registry transport cannot be accepted before the
new assets are published. Candidate artifact receipts do not claim public availability.

The release workflows default to `publish_release=false`; every candidate publication
job was skipped. Public workflows require a pre-existing tag matching the source and
create a new Release instead of replacing one. Recovery accepts only exact-source artifacts.

After separate owner approval:

1. Review/merge the 14 plugin candidates, create/push new v0.3.4 tags and publish signed
   assets through the protected environments. Preserve every previous tag/asset.
2. Download and authenticate the actual public plugin assets, rebuild the registry
   with actual signatures/hashes and perform public-transport installation acceptance.
   Only then advance the main public registry to v0.3.4.
3. Review/merge core changes, create/push a new v0.3.5 tag at the approved source,
   publish core-only packages and reverify the actual public packages.
4. Regenerate both Homebrew formulas from the four actual public Unix core archives,
   then review/merge the tap update and verify the public install/upgrade path.

Release rebuilds/repacking can change archive timestamps and hashes. Staged candidate
hashes must not be blindly copied to final public registry/formula metadata. The public
formula URLs/hashes remain v0.3.4 until actual v0.3.5 assets are available.

## Task Weaver and review identities

Slices 1–3 and the core-only/distribution implementation acceptance are complete.
The final documentation/readiness task is prepared for owner review; requirement and
slice 4 remain in review until that review is accepted. Public publication is a separate
explicit authorization, not implied by Task Weaver status.

All 16 repositories use branch `codex/v0.3.5-trust-hardening` and have draft PRs.
Core runtime implementation is `885ab03a8f2e993359881757a0bc39d9be231439`; test-only
CI fixes culminate in `9295d28396f2de06b064a687b79e83d0c9b80d23`. Use current branch
HEAD to review final evidence, release notes and distribution smoke script.

| Repository | Candidate commit |
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

## Authorized publication progress

The owner accepted the release review and explicitly approved merges, new tags,
public Releases and registry/Homebrew validation. All 14 plugin PRs were merged;
v0.3.4 tags point to the reviewed exact-source signing commits. The authenticated
candidate artifacts were promoted into new draft Releases, verified against server
asset digests and then published. All 350 new assets match the reviewed bits.
Duplicate tag-triggered rebuilds were cancelled to avoid duplicate publication.
No old tag or published asset was replaced. Old v0.3.3 tag objects and asset
metadata were independently checked and remain unchanged.

All 56 actual public gzip archives, retained detached signatures and payload
proofs were downloaded and authenticated before generating the registry.
The old v0.3.3 registry version history remains intact. Registry downloads now
retain and verify detached signatures, and the update workflow defaults to v0.3.4.
Fresh legacy metadata caches are preserved but are not used by the new trust-policy
cache namespace. An isolated production-CLI test seeded fresh v0.3.3 caches and
proved signed installation, user-state preservation and all lifecycle/attack checks.
See [publication evidence](release-v0.3.5-publication-evidence.json).
