# v0.3.3 Release Readiness

Audit date: 2026-10-11 (Asia/Shanghai).

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
