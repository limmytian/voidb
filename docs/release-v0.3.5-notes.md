# VoidB v0.3.5 candidate release notes

Unreleased candidate. Core v0.3.5 uses separately distributed official plugin v0.3.4
packages. Existing public releases remain immutable.

## Security

- Managed plugins require authenticated Ed25519 provenance before execution.
  Removing records, rewriting binary digests, omitting legacy digests or forging
  proofs cannot authorize an unsigned replacement.
- Proofs bind identity, version, protocol, platform, executable and all payload files
  to the compiled official trust root. Managed symlinks and changed payloads fail closed.
- Legacy unsigned installations require verified update/reinstall. Update/rollback
  preserve matching authenticated packages and profiles/credentials.
- Explicit development roots retain unsigned execution only with deliberate opt-in.
- The guarantee assumes a trusted main executable, embedded roots and signing owner;
  it does not defeat replacement of those roots or remove every filesystem execution race.

## Installation and interaction

- Main packages and Homebrew install only `voidb` and `voidb-cli`; plugins are separate.
- Install the recommended six with `voidb-cli plugin install-default`, or select an
  official plugin with `voidb-cli plugin install <name>`.
- First interactive startup offers install or skip. Skipping persists; failed/partial
  installation can retry. Noninteractive startup never prompts or downloads.
- In Connection Manager, select a missing official plugin connection and press `i`
  to confirm installation of that plugin. Cancellation is inert, errors are retryable
  and completed installation refreshes state. Existing disabled/invalid/incompatible
  plugins are preserved, and installation receives no main password.
- Explicit offline roots remain available with `install-default --from-bundled`.

## Compatibility and validation

All 14 official plugins prepare new signed v0.3.4 assets for Linux x86_64/ARM64 and
macOS Intel/ARM64. Windows includes the core package only. Protocol 1 remains supported.
Native CI, authenticated packages, adversarial lifecycle and real HTTP/PTY acceptance
passed within the scopes stated in [release readiness](release-v0.3.5-readiness.md).
Public transport checks follow separately authorized publication.
