# Security Release Checklist

Run this checklist before broadening external plugin/runtime use or cutting a
release candidate.
For the full release-candidate command and residual-risk matrix, start with
[Release Candidate Checklist](release-candidate-checklist.md).

## Required Automated Checks

```bash
cargo test -p voidb-plugin-email config::tests
cargo test -p voidb-core security_sensitive_local_files_are_private -- --nocapture
cargo test -p voidb-core reencrypt_config_file_sets_user_passphrase_metadata -- --nocapture
cargo test -p voidb-cli default_passphrase_warning_is_redacted_and_machine_readable -- --nocapture
cargo test -p voidb-cli user_passphrase_protection_suppresses_default_passphrase_warning -- --nocapture
cargo test -p voidb-cli dry_run_requires_capability_support -- --nocapture
cargo test -p voidb-cli destructive_sqlite_exec_requires_ack_or_dry_run -- --nocapture
cargo test -p voidb-plugin-ssh capabilities
cargo test -p voidb-plugin-ssh service
cargo test -p voidb-core process_plugin
cargo test -p voidb-core process_plugin_runtime
cargo test -p voidb-cli plugin
cargo test -p voidb-cli invoke
cargo test -p voidb-cli jit_authorization
cargo test -p voidb-cli ssh_reference_jit_flow
cargo test -p voidb-tui jit_
scripts/tui-quality-gate.sh
scripts/ssh-fixture-smoke.sh --report target/tmp/ssh-fixture-smoke-evidence.md
scripts/release-sync-smoke.sh
cargo test --workspace --no-fail-fast
cargo clippy --workspace --all-targets --no-deps
```

## Gate Expectations

- Email IMAP and POP3 TLS certificate verification defaults to enabled.
- Any insecure TLS behavior requires an explicit `verify_tls = false` profile
  setting and must not be implied by missing config.
- Config, profile, credential, and audit files are private on Unix-like systems.
- Profile CLI JSON output warns only when saved credential-shaped config is
  still protected by the compiled default passphrase.
- `invoke run --dry-run` fails with `validation.dry_run_not_supported` when a
  capability does not advertise dry-run support.
- Destructive capabilities remain denied by default unless the profile policy
  explicitly allows the capability or the invocation uses an accepted dry-run or
  explicit acknowledgement path.
- SSH non-interactive capability paths use strict `known_hosts` verification and
  return structured `ssh.host_key_unknown` / `ssh.host_key_changed` target
  errors instead of learning host keys silently.
- SSH diagnostics, profile metadata, target errors, and audit summaries do not
  expose passwords, key passphrases, private key material, private key paths,
  credential-bearing connection details, or decrypted `plugin_config`.
- SSH `exec`, `sftp_put`, `sftp_mkdir`, and `sftp_rm` stay destructive in
  capability metadata and continue to require dry-run support or explicit
  acknowledgement.
- Process-plugin discovery and runtime gates cover trust-root precedence,
  package-local command resolution, protocol compatibility, graceful shutdown,
  timeout/crash handling, and redacted stderr diagnostics.
- Sync client/server smoke covers registration, push/pull, unauthorized
  requests, conflict handling, and encrypted bundle round-trips without
  requiring hosted-service secrets.
- Audit and CLI outputs must not include plaintext passwords, tokens,
  credential-bearing URLs, raw SQL inputs, or decrypted `plugin_config`.
- Agent authorization defaults to the exact Read-only preset. Named presets
  reject mismatched explicit scopes; Custom rejects empty/wildcard scope.
- Interactive/Execute authorization requires grant acknowledgement and each
  destructive session call requires its own acknowledgement.
- Grant projections distinguish expiry, use exhaustion, offline/stale broker,
  and active-session count without returning tokens, sockets, passwords, or
  decrypted profile data.
- Scoped replacement/revoke and global revoke close displaced sessions; forged
  tokens and cross-profile/plugin requests do not consume a grant use.
- JIT requests use UUIDv4 opaque IDs, bounded queues/rate limits/cooldowns, one
  terminal decision, broker-restart supersession, and immutable revision locks.
- CLI review accepts only an opaque request ID and a controlling TTY. Every
  Connection Manager decision sends the unlocked password only through a private local
  stdin pipe. Neither surface accepts passwords in argv/environment or renders
  them in canonical state.
- Capability-wide, constrained, and exact-invocation scopes are revalidated at
  stateless and persistent-session execution. Cross-principal/profile/plugin,
  replay, command substitution, and stale revision attempts fail closed.
- JIT revoke closes the live broker/session, records a redacted revoke audit,
  clears effective scopes, and prevents future amendments to that logical grant.
- Every bundled approval-schema JSON pointer must exist in the capability's
  normalized input schema. Secret or incompatible process-plugin schemas fail
  closed; Sync remains on its dedicated encrypted protocol.

## Residual Risk

VoidB still supports legacy `ConnectionConfig.plugin_config` credentials. Those
records are encrypted at rest, but saves without a user-controlled master
password use the compiled default passphrase. The CLI can re-encrypt them with
`voidb-cli credential master reencrypt`, and Connection Manager can set/unlock
the same user-controlled path with `m`. Keep the residual risk visible whenever
legacy records have not yet been re-encrypted.

SSH live smoke is fixture-dependent. Release notes should record whether the
manual fixture from [SSH Plugin](ssh-plugin.md) was run, which auth methods were
covered, and whether host-key changed behavior was exercised.
