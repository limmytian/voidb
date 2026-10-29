# v0.3.4 Patch Release Acceptance

Accepted on 2026-10-12 (Asia/Shanghai), under Task Weaver requirement
`bc316195-9dde-40c9-bad4-568546bd7a3f`.

The owner approved a core-only patch after real v0.3.3 registry installation
exposed an architecture/target-triple mismatch. The shell, CLI and core are
0.3.4; all fourteen independent plugins remain at their validated 0.3.3 tags.
The published v0.3.3 tags and assets were retained.

## Source and publication

- Immutable main `v0.3.4` source: `c53463b5284035624fa3d8e24ee5997d19089980`.
- Exact-source [CI 38169235469](https://github.com/limmytian/voidb/actions/runs/38169235469): all jobs passed.
- Native five-platform [Release 38169616946](https://github.com/limmytian/voidb/actions/runs/38169616946): all jobs passed, including each CLI version/help check.
- [Public v0.3.4 Release](https://github.com/limmytian/voidb/releases/tag/v0.3.4) is GitHub's latest release.
- Local complete workspace tests, workspace Clippy and six staging/installer checks passed before tagging.
- Registry continues to index the 56 verified v0.3.3 plugin archives. Plugin source/CI/release evidence is in [v0.3.3 readiness](release-v0.3.3-readiness.md).

## Downloaded artifact acceptance

Every archive below was downloaded and checked against public `SHA256SUMS`.
Unix packages contain the six default v0.3.3 plugins. Windows contains only
`voidb.exe` and `voidb-cli.exe`. Optional Sync is not bundled.

| Archive | SHA-256 | Bytes |
|---|---|---|
| voidb-0.3.4-darwin-arm64.tar.gz | `f1afa88551739bbd6b47e8278c6b64953cd42c1cbd6bcf4180a4408ad58c7750` | 31914347 |
| voidb-0.3.4-darwin-x64.tar.gz | `8fd8ed7732b291ab2f0dffd030c1d52b8cb6f2e19d2978a4c96d5625924c7f49` | 33940511 |
| voidb-0.3.4-linux-arm64.tar.gz | `2c69da30e206a1004b652a25b9070813014dc89dfe5c15de538cea2b465207a9` | 35442894 |
| voidb-0.3.4-linux-x64.tar.gz | `ac90b0167e7e12ef8f9b44eb4927dd6a03cc548d8094f7976570020761fdd666` | 38484059 |
| voidb-0.3.4-windows-x64.zip | `300d1d596d26747313382125b9706459b0c338fa6ba46997282d04ff0b79da72` | 6405677 |

The published Mac ARM64 CLI passed public registry installation, update and
six-default initialization. The registry-default test used an empty install
root and confirmed newly installed packages came from the registry.

Clean installation and real v0.3.3-to-v0.3.4 upgrade ran in disposable homes.
Four configuration/credential/audit files and all six existing plugin installation
records retained their byte hashes. The native core reports 0.3.4 and the
installed defaults report 0.3.3. Modified SQLite binaries were blocked before
process dispatch, and no fixture passphrase appeared in command output.

Homebrew formula
[`897b06a`](https://github.com/limmytian/homebrew-tap/commit/897b06a)
uses the four actual Unix digests above. The formula was executed with Homebrew's
libraries in a temporary prefix, followed by native version, share-directory
plugin discovery, six-default initialization and help checks. The owner's
global installation was not replaced.

## Reproduction and platform limits

Download all five core archives and validate their public checksum file:

```bash
gh release download v0.3.4 --repo limmytian/voidb --dir /tmp/voidb-v034-core
cd /tmp/voidb-v034-core
shasum -a 256 -c SHA256SUMS
```

Run installation in a disposable home and install prefix (the following
plugin-root path is for macOS):

```bash
acceptance_home=$(mktemp -d)
HOME="$acceptance_home" INSTALL_DIR="$acceptance_home/bin" VOIDB_VERSION=v0.3.4 bash scripts/install.sh
HOME="$acceptance_home" "$acceptance_home/bin/voidb-cli" --version
HOME="$acceptance_home" "$acceptance_home/bin/voidb-cli" plugin install sqlite --install-root "$acceptance_home/registry-plugins" --format json
HOME="$acceptance_home" "$acceptance_home/bin/voidb-cli" plugin update sqlite --install-root "$acceptance_home/registry-plugins" --format json
HOME="$acceptance_home" "$acceptance_home/bin/voidb-cli" plugin install-default --install-root "$acceptance_home/registry-plugins" --format json
VOIDB_PLUGIN_PATH="$acceptance_home/Library/Application Support/voidb/plugins" bash scripts/tui-quality-gate.sh --skip-build --cli-bin "$acceptance_home/bin/voidb-cli" --tui-bin "$acceptance_home/bin/voidb" --out target/tmp/v034-reproduced-package-gate --no-diff-check
```

Run the installer and PTY commands from the repository root; the checksum
commands above run in the download directory. Homebrew acceptance executed the
actual formula method with Homebrew libraries and a temporary prefix, rather
than replacing a global installed keg.

Detailed clean-install, upgrade, public registry and PTY acceptance ran on
macOS ARM64. Linux x64/ARM64, Intel Mac and Windows binaries passed version/help
checks on native release runners, and all five downloaded archives passed
checksum and layout verification. Those checks do not claim full interactive
or clean-system installation coverage on the other four targets. Official
Windows plugins remain unavailable in this release. Existing plugin updates
retain previous-version directories for explicit rollback.

## Final interactive acceptance

The downloaded v0.3.4 shell/CLI and installed published v0.3.3 SSH binary passed
all fixture and real PTY Connection Manager/SSH journeys in
`target/tmp/v034-published-package-gate/report.md`. This retains cold/warm
latency, idle CPU/repaint, resize, host-key decision, raw input, help, secret
redaction and terminal restoration checks. All fourteen plugin working trees
were clean and their original v0.3.3 tag-to-source SHA mappings were unchanged.
