---
name: voidb-plugin-ssh
description: Guide for the VoidB SSH plugin. Use when modifying crates/plugins/voidb-plugin-ssh, ssh.* capabilities, SSH CLI commands, terminal/SFTP/port-forward services, host-key policy, standalone SSH TUI, external-agent session sharing or current-PTY control, SshAgentSessionFactory, or SSH profile metadata.
---

# VoidB SSH Plugin

## Start Here

Primary crate: `crates/plugins/voidb-plugin-ssh`.

Inspect:

- `src/config.rs` for `SshConfig`, auth methods, terminal config, and reconnect options.
- `src/service/` for session, SFTP worker, forwarding, metrics, commands, events, and types.
- `src/capabilities.rs` for `ssh.*` metadata and invocation.
- `src/cli_plugin.rs` for `voidb-cli ssh ...`.
- `src/agent_session.rs` for persistent agent sessions.
- `src/tui.rs` for standalone SSH TUI behavior.
- `docs/ssh-plugin.md`, `docs/ssh-release-readiness.md`,
  `docs/live-operations-tui-safety.md`, and `docs/assist-handoff.md`.

## Boundaries

- Keep `russh`, SFTP, and port-forward live handles inside the plugin service.
- Preserve strict non-interactive host-key behavior and clear target errors.
- Treat terminal, forwarding, SFTP write/delete, and remote exec as policy-sensitive.
- Keep PTY input/output channel-based; do not block the TUI update loop.
- Use raw-input handling only where terminal behavior needs shell soft globals to be bypassed.

## CLI And Capabilities

- CLI commands: `test`, `exec`, `sftp-ls`, `sftp-get`, `sftp-put`, `sftp-rm`, `sftp-mkdir`, `forward-local`, `forward-remote`, `forward-socks`, `tui`, and `session`.
- Session-share commands: `session list`, `show`, `wait`, `operation`, `input`,
  `cancel`, `close`, and `state`. Keep `ssh assist` hidden as a compatibility
  alias.
- Capabilities: `ssh.test`, `ssh.exec`, `ssh.forward_open`, `ssh.forward_status`, `ssh.sftp_list`, `ssh.sftp_get`, `ssh.sftp_put`, `ssh.sftp_mkdir`, `ssh.sftp_rm`, `ssh.diagnostics`.

## External-Agent Session Sharing

- Share or refresh the bounded, redacted live view with `Ctrl+]` then `a`; do
  not add an agent conversation to the TUI.
- Discover the share with `voidb-cli ssh session list/show` and propose one
  current-PTY command with `ssh session input`.
- Use `j/k` in operation review, `y` to approve once, `n` or `x` to deny, and
  `A` to approve while allowing later current-PTY commands from the exact same
  agent principal for the lifetime of the share.
- Treat a decision as one-shot per operation request ID and action index. Exit
  the review immediately after a successful decision and reject duplicate
  confirmations atomically in `SshAssistStore`.
- Keep one writer for current-PTY input. Make agent control generation-bound and
  short-lived; human terminal input is dropped while the agent owns the writer,
  but `Ctrl+]` then `v` must revoke immediately.
- Treat alternate-screen, application-keypad, and application-cursor modes as
  visible operator warnings, not hard denials. Record accepted warnings before
  granting the single-writer lease.
- Continue to hard-block stale bindings, host-key prompts, disconnected/error
  states, password-like prompts, pending local input, readonly launches,
  oversized commands, excessive retained output, conflicting ownership, and
  closed or revoking sessions.
- Prefer a separate authorized agent-side SSH session for inspection; it never
  writes the human PTY.

## Validation

- Focused gate: `cargo test -p voidb-plugin-ssh`.
- Add `cargo test -p voidb-cli invoke`, `cargo test -p voidb-core profile_adapter`, and `cargo test -p voidb-core profile_store` for profile/capability/host-key changes.
- Secret-free smoke: `scripts/release-plugin-smoke.sh --plugin ssh`.
- Fixture gate when feasible: `scripts/ssh-fixture-smoke.sh`.
- Session-share or current-PTY policy changes: run
  `scripts/check-external-agent-interaction.sh` and regenerate fixture evidence
  under `target/tmp` as documented in `docs/ci-checks.md`.
- Add the full workspace test and Clippy tiers for shared interaction or
  validation-policy changes.
- Always run `git diff --check`.
