# v0.3.3 Release Readiness

Initial audit date: 2026-10-11 (Asia/Shanghai).

Final distribution acceptance: 2026-10-12 (Asia/Shanghai).

The main and all fourteen plugin v0.3.3 releases are public. Published archives,
Mac ARM64 clean installation, real old-version upgrades, Homebrew staging and
Connection Manager/SSH PTY journeys passed. The released v0.3.3 registry client architecture/target-triple mismatch was
subsequently fixed in the owner-approved core-only v0.3.4 release. All independent
plugins remain at v0.3.3. See [final patch acceptance](release-v0.3.4-readiness.md).
Local verified archive installation and bundled defaults also work in v0.3.3.

Task Weaver requirement: `bc316195-9dde-40c9-bad4-568546bd7a3f`.

## Repository inventory

All working trees were clean at the initial audit. Remote SHAs were queried directly through GitHub.

| Repository | Local HEAD | Remote main | Cargo version |
|---|---|---|---|
| voidb | 367ccc71dfd85ed5cd37d53514a034961bf47d45 | 6979c4c5eb36126f3c5c0ef4933d1857e6071dda | 0.3.3 |
| voidb-plugin-mysql | d7a1d7ea8aef0ef9036cfb3561aac54933a26d6e | Unavailable (HTTP 404) | 0.3.3 |
| voidb-plugin-postgres | d11d760c59d68b0e601c3ed099f571885c2ccdec | Unavailable (HTTP 404) | 0.3.3 |
| voidb-plugin-sqlite | c54c8a3f42e061f1137ee2585f2fe96ab4ed7924 | Unavailable (HTTP 404) | 0.3.3 |
| voidb-plugin-redis | 2156e0f94621080eab32fdc730832e6e057c00c5 | Unavailable (HTTP 404) | 0.3.3 |
| voidb-plugin-ssh | 5d6cf8357d21a782a75676fc2cff3da1a58aed28 | Unavailable (HTTP 404) | 0.3.3 |
| voidb-plugin-duckdb | c26c5be981aabdabcfc3e52c2934221789b6a90c | Unavailable (HTTP 404) | 0.3.3 |
| voidb-plugin-docker | afedee99e853fe0209747354e65c2769a3ba89f9 | 93423c7c578e5801016f2eceaee6d0d1517a7661 | 0.3.3 |
| voidb-plugin-kubernetes | 819b87d9c861fc28a8ea2168b04ed917a20d9961 | 832257f376c246f6aa1c05ee585096bd9d505200 | 0.3.3 |
| voidb-plugin-s3 | cb03d5beeb625922acbe0400e6d94601927c32f7 | 26751b9bb67ba95854731bd17ccef9a738053d2f | 0.3.3 |
| voidb-plugin-elasticsearch | 5d996293c0ae940c6deadc0ee944301f8f7f0fbe | daf242e3d8c13d70e0080b523c0eda8f993fdc84 | 0.3.3 |
| voidb-plugin-mongodb | fd00ec72201d98d2b64cab055c21a51deff543e8 | 64658d5d4f7627afc0521cbda94e4f01011cb744 | 0.3.3 |
| voidb-plugin-jenkins | f6abaf075212ec1d168983e39c08d84b3a130f86 | 71651aeeedc89676260b60992c025ae5e75dfafd | 0.3.3 |
| voidb-plugin-webdav | 3ef27fca497e6aac0a9d523323f42b4eed517aaf | 1fe4533ad11cdd6f2f2bfe25fe7bc6484c3205d4 | 0.3.3 |
| voidb-plugin-email | 7e88732780ef4cdcefa64ac81f7b89b271966bfe | 0f2c515e1d6d2dc5c8e72a1347587e065effde62 | 0.3.3 |

## Initial diagnosis

- Main CI [37793911177](https://github.com/limmytian/voidb/actions/runs/37793911177) reported 15 failing broker tests because SSH process-plugin metadata was unavailable on a clean runner. Local `cargo test -p voidb-cli --bin voidb-cli` passed 138 tests. Running the same test executable with disposable HOME, XDG_CONFIG_HOME and VOIDB_PLUGIN_PATH reproduced exactly 15 broker failures (36 passed). Authorization resolution reads real installed-plugin roots. Deterministic fixtures must remove this dependency without changing production discovery or fail-closed policy. Logs: `/tmp/voidb-cli-baseline.log`, `/tmp/voidb-cli-isolated-baseline.log`.
- Release [37788201042](https://github.com/limmytian/voidb/actions/runs/37788201042), attempts 1 and 2, shows macOS arm64 cancelled and publication skipped. Linux x64, Linux arm64 and Windows x64 succeeded. Available macOS job records have no failed build step; this does not establish a compiler defect.
- Six extracted plugins have no origin and expected GitHub endpoints return 404. Eight existing plugins have successful CI only for earlier remote SHAs.
- Plugin Cargo manifests pin SDK/core to v0.3.0 or v0.3.1 and tracked Cargo config overrides them to sibling paths. MySQL requests removed core feature `mysql`. Clean independent builds must not require sibling paths.
- Main Release packages only two binaries and uses target triples with a v-prefixed version. Homebrew uses platform aliases and unprefixed versions, remains at 0.3.2 and has an empty Intel Mac checksum. Default plugin distribution needs reconciliation.
- Registry workflow checks out eight repositories while its builder enumerates fourteen. Index entries still describe older assets.

## Evidence policy

Final CI conclusions must match release SHAs. Validate actual downloadable archives and checksums. Source metadata and historical local smoke are insufficient. Platform claims must match validated artifacts.

## Execution authorization

On 2026-10-11, the release owner authorized proceeding through the recorded plan in order. The requirement was approved; actual repository inventory and CI diagnosis are complete.

## Contract repair

Authorization tests now use checked-in metadata snapshots from plugin service contracts, independent of user installations. The process adapter preserves explicit `capability_wide_allowed = false`; compatibility defaults apply only to undeclared authorization. Every plugin exports its service capability definitions into the process manifest and schema files through `examples/export_contract.rs`; CI runs its `--check` mode to reject drift. The main repository matrix owns only Connection Manager and optional Sync; external plugin coverage belongs to independent repositories.

Obsolete CLI tests that instantiated SQLite/DuckDB driver services or expected built-in database dispatch were removed from the shell crate. Real SQL/query/explain/transaction/cancellation coverage runs in the extracted plugin suites. Shared validation, policy, handoff, redaction, process dispatch and transport tests remain in the CLI; metadata-only runtime tests explicitly prove that service execution requires a process binary. Connection tests now assert argv contains only `test --stdin-config` and confirm the exact credential payload arrives through stdin in a disposable subprocess fixture, rather than relying on locally installed drivers.

All 14 plugin manifests now pin core/SDK to immutable revision `367ccc71dfd85ed5cd37d53514a034961bf47d45`. Active sibling-path overrides were replaced by explicitly opt-in `.cargo/config.local.example.toml`. Initial independent suites used a temporary bare mirror containing that exact revision; real GitHub resolution and current-commit CI remain required during synchronization.

The release owner confirmed that the six missing repositories should be public under `limmytian/voidb-plugin-<name>`.

## Local validation after contract repair

- `cargo test --workspace --no-fail-fast`: passed.
- `cargo clippy --workspace --all-targets --no-deps`: passed.
- `cargo test -p voidb-cli --features full`: 183 passed.
- Full CLI executable with disposable HOME/XDG_CONFIG_HOME/VOIDB_PLUGIN_PATH: 183 passed.
- `cargo clippy -p voidb-cli --features full --all-targets --no-deps -- -D warnings`: passed.
- `scripts/check-agent-capability-matrix.sh`: passed.
- All 14 independent repositories: contract `--check`, `cargo test --all-targets --no-fail-fast`, strict `cargo clippy --all-targets --no-deps -- -D warnings`, and `git diff --check` passed.

The main repair commit must be synchronized first so the immutable SDK/core revision becomes available on GitHub. This is a dependency-bootstrap push, not a release tag. Plugin remote synchronization and release publication remain separate gates.

## Distribution alignment

Unix release archives contain the shell, CLI and six default plugins, downloaded
from the matching verified plugin releases. Four Unix architectures are planned:
Linux x64/arm64 and macOS x64/arm64. Windows packages contain the shell and CLI;
no Windows plugin binaries are claimed. Publish the SDK source commit first,
then all fourteen plugin releases, and only then tag the main release that
consumes their assets. Registry generation reads published archives for all
four supported plugin targets instead of source checkouts.

Pre-release checks cover missing/corrupt checksums, unsafe archive paths,
installation records, architecture selection, manifest schema roundtrips and
unbounded live-session rejection. The isolated Connection Manager/SSH PTY
quality gate passed before publication; final downloadable package acceptance
remains a separate gate.

## Resumed validation checkpoint

All fourteen plugins passed contract/schema checks, all-target tests and strict
Clippy against published core/SDK revision
`0d565c4a7227f218c2b9c118aa2694d87243aa8f`. Explicit-target packagers now reject
missing release binaries rather than relabeling native/debug binaries.

The full aggregate gate passed at
`target/tmp/v033-resumed-full-gate/report.md`, including independent plugin
paths, external-agent boundaries, Sync client/server tests, real PTY journeys,
workspace tests and Clippy. The standalone Sync server remains at its existing
0.3.2 version and is not included in the main 0.3.3 archive. Its lockfile now
reflects that existing manifest version.

Six default plugin release builds and the native macOS arm64 staging package
passed checksums, artifact manifest and command smoke. All six installed through
CLI package validation in a disposable home. Remote CI run 38161164957 passed
workspace and three platform jobs but exposed a one-second concurrent-test
fixture startup timeout; fixture-only waits were extended to ten seconds. The
full CLI suite and strict Clippy pass after this change. Final candidate CI
must still be verified before tags.

The Linux full-feature broker race remained reproducible with longer fixture
waits. Test-only discovery now validates immutable metadata once and clones the
snapshot, removing repeated filesystem/TOML/schema work from concurrent broker
calls. The complete 183-test full CLI suite passes in about two seconds locally;
concurrency assertions and production discovery remain unchanged.

## Runtime integrity closure

The candidate CI gate reached 15/15 successful repositories. Acceptance
preparation then found that CLI forwarding and connection tests checked binary
integrity, while the shared JSON-RPC host did not. The host now checks the same
installation record immediately before process creation, covering health,
stateless invocation and persistent session launch. A regression test verifies
intact startup and rejects both binary and manifest tampering before credentials
can reach a child process. Final plugin SDK pins and CI must include this repair.

A real published core 0.3.2 package and Docker 0.3.0 package were downloaded and
SHA-256 verified for upgrade acceptance. A disposable old-version environment
contains encrypted credentials and four configuration/profile/credential files
whose hashes were saved for post-upgrade preservation checks.

## Published source and artifact verification

The final plugin SDK/core dependency is pinned to immutable source revision
`31d22cd09c9b10f1d22f59d47e789a49c33a290d`, including the shared runtime integrity gate.
All fourteen release source commits passed independent CI with tracked lockfiles
and `--locked` builds. Every plugin requires core `>=0.3.3`.

| Plugin | Immutable v0.3.3 source | Source CI | Successful release run |
|---|---|---|---|
| mysql | `d9638303cb22a180c0f1c079ffd71795367a6c93` | [38165152328](https://github.com/limmytian/voidb-plugin-mysql/actions/runs/38165152328) | [38166593410](https://github.com/limmytian/voidb-plugin-mysql/actions/runs/38166593410) |
| postgres | `68f9198582ec4c5531b92ba2a701ceb9d86c5bfc` | [38165154485](https://github.com/limmytian/voidb-plugin-postgres/actions/runs/38165154485) | [38166812730](https://github.com/limmytian/voidb-plugin-postgres/actions/runs/38166812730) |
| sqlite | `aa211f45609a12ad05ec10b1d2e83440de793090` | [38165156700](https://github.com/limmytian/voidb-plugin-sqlite/actions/runs/38165156700) | [38165515117](https://github.com/limmytian/voidb-plugin-sqlite/actions/runs/38165515117) |
| redis | `47dec20696a358b035e96445d4ae906a91f9db86` | [38165158733](https://github.com/limmytian/voidb-plugin-redis/actions/runs/38165158733) | [38165517660](https://github.com/limmytian/voidb-plugin-redis/actions/runs/38165517660) |
| ssh | `cf00c1f282f1ecffac287e6db49b458f69cbe4ea` | [38165160419](https://github.com/limmytian/voidb-plugin-ssh/actions/runs/38165160419) | [38165520205](https://github.com/limmytian/voidb-plugin-ssh/actions/runs/38165520205) |
| duckdb | `550f2fce9e5b7f6ea2b8e1f323a9be394df63317` | [38165162650](https://github.com/limmytian/voidb-plugin-duckdb/actions/runs/38165162650) | [38165522226](https://github.com/limmytian/voidb-plugin-duckdb/actions/runs/38165522226) |
| docker | `69aab2504582dd00f53ae8a04687b4e25702e898` | [38165164742](https://github.com/limmytian/voidb-plugin-docker/actions/runs/38165164742) | [38165524794](https://github.com/limmytian/voidb-plugin-docker/actions/runs/38165524794) |
| kubernetes | `d319d4b1b5c3192d9803cd3f5a9e6318721c7e72` | [38165166813](https://github.com/limmytian/voidb-plugin-kubernetes/actions/runs/38165166813) | [38165527302](https://github.com/limmytian/voidb-plugin-kubernetes/actions/runs/38165527302) |
| s3 | `2ba6edad0ef3de1855f80e2f25cd2764246d7150` | [38165169088](https://github.com/limmytian/voidb-plugin-s3/actions/runs/38165169088) | [38165529494](https://github.com/limmytian/voidb-plugin-s3/actions/runs/38165529494) |
| elasticsearch | `8b9f4b8d4cee44e3133d03b9131f635fc161f2ea` | [38165172626](https://github.com/limmytian/voidb-plugin-elasticsearch/actions/runs/38165172626) | [38165531677](https://github.com/limmytian/voidb-plugin-elasticsearch/actions/runs/38165531677) |
| mongodb | `c68a5e0eff9cb9862bd9e7409cf9e2b85ca5b749` | [38165175123](https://github.com/limmytian/voidb-plugin-mongodb/actions/runs/38165175123) | [38165534375](https://github.com/limmytian/voidb-plugin-mongodb/actions/runs/38165534375) |
| jenkins | `ab142d27ffaba0242ba616dfe252967eabf31469` | [38165177411](https://github.com/limmytian/voidb-plugin-jenkins/actions/runs/38165177411) | [38165537340](https://github.com/limmytian/voidb-plugin-jenkins/actions/runs/38165537340) |
| webdav | `2b3dfe278cf282e3494f1ac232f6c8ed6769ea4f` | [38165179538](https://github.com/limmytian/voidb-plugin-webdav/actions/runs/38165179538) | [38165540541](https://github.com/limmytian/voidb-plugin-webdav/actions/runs/38165540541) |
| email | `792a23f4446a682b1fd3634ca297c08810844fe9` | [38165181712](https://github.com/limmytian/voidb-plugin-email/actions/runs/38165181712) | [38165542940](https://github.com/limmytian/voidb-plugin-email/actions/runs/38165542940) |

The first MySQL and PostgreSQL release runs failed only for Linux ARM64 because
the cross-compilation image lacked target OpenSSL. Recovery workflows checked
the original run source SHA against the existing tag, reused its successful
platform artifacts, and built the missing target on a native ARM64 runner.
No published tag was moved. Future releases use native runners for all targets.

All 56 published plugin `.tar.gz` archives were downloaded, verified against
their published `SHA256SUMS`, and indexed. Each generated registry entry was
checked against the actual filename, target, download URL, byte size and digest.
The six published macOS ARM64 default packages were installed in a disposable
home; installation record binary digests and CLI help dispatch passed.

Main tag `v0.3.3` points to `8fa94d110bc0802d35cc7ce21545dd9b8b4b8d83`.
Exact-source [CI 38166534476](https://github.com/limmytian/voidb/actions/runs/38166534476)
passed all jobs. Its [release run 38167488068](https://github.com/limmytian/voidb/actions/runs/38167488068)
builds five native targets and verifies each CLI version and help before packaging.

## v0.3.3 distribution acceptance checkpoint

All five public core archives passed their published SHA-256 checksums and
archive layout checks. Unix archives contain exactly the six default plugin
packages at version 0.3.3; Windows contains the two shell/CLI executables.
All 56 plugin binaries match their declared native architectures.

The public core 0.3.2 upgrade baseline actually bundled plugin version 0.3.1.
The published installer preserved all four saved configuration, credential and
audit file hashes and kept those installed plugins. Explicit updates to 0.3.3
retained previous-version directories and digest records. Docker upgraded from
its real published 0.3.0 package to 0.3.3. No fixture passphrase appeared in
command output. Modified installed SQLite binaries were rejected before dispatch.

The published core and installed published SSH package passed the final real PTY
gate at `target/tmp/v033-published-package-gate-final/report.md`. Its first run
identified a stale test marker: the released invalid-choice prompt is
`host key prompt:` rather than `host key prompt requires`. The journey now checks
the actual prompt; all remaining actions and security checks are retained.

Homebrew formula commit
[`927d236`](https://github.com/limmytian/homebrew-tap/commit/927d236) publishes
all four real core archive digests, including Intel Mac, and corrects the license
to Apache-2.0. The actual formula install ran with Homebrew libraries against
the downloaded Mac ARM64 archive in a temporary prefix. Native CLI version,
share-directory discovery, six bundled installations and plugin help passed.
This acceptance did not replace the owner's globally installed Homebrew package.

Registry commit
[`bc33f2d`](https://github.com/limmytian/voidb/commit/bc33f2d)
indexes the 56 public plugin archives. Actual registry installation with the
released CLI exposed an architecture/triple mismatch. Fix commit
[`6a0287f`](https://github.com/limmytian/voidb/commit/6a0287f)
qualifies architecture names by platform without allowing another architecture
as a fallback. Workspace tests, Clippy and exact-source
[CI 38168359477](https://github.com/limmytian/voidb/actions/runs/38168359477) passed.
The fixed native client passed public registry install, update and six-default
initialization. Existing published v0.3.3 tags and binaries remain unchanged.
Until a forward patch is released, use bundled defaults or checksum-verified
local archives (`plugin install <archive>` / `plugin update <id> --from <archive>`).
The owner subsequently approved and published the core-only v0.3.4 patch;
plugin releases remain at their validated v0.3.3 versions. Final patch source,
artifact and acceptance evidence is in [v0.3.4 readiness](release-v0.3.4-readiness.md).
