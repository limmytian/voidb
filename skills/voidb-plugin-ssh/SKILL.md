---
name: voidb-plugin-ssh
description: Guide for the VoidB SSH plugin. Use when working on the external VoidB SSH plugin repository, ssh.* capabilities, SSH CLI commands, terminal/SFTP/port-forward services, host-key policy, standalone SSH TUI, external-agent session sharing or current-PTY control, SshAgentSessionFactory, or SSH profile metadata.
---

# VoidB SSH Plugin

## Where It Lives

The SSH plugin is a decoupled process plugin that lives in its own
independent repository (`voidb-plugin-ssh`), not in this repository. Install it
with `voidb-cli plugin install-default` and run it through `voidb-cli ssh ...`
or the `ssh.*` capabilities.

## What It Does

SSH capability plugin for VoidB: remote terminal, SFTP transfer, and port
forwarding with strict host-key policy, plus `voidb-cli ssh` domain commands
(`test`, `exec`, `sftp-*`, `forward-*`), a standalone full-screen SSH TUI
(`voidb-cli ssh tui`), session-share commands (`session list/show/wait/
operation/input/cancel/close/state`), and bounded, redacted external-agent
session sharing with one-shot current-PTY control.

## Development Guidance

Current development guidance lives in this repository:

- `docs/process-plugin-development-guide.md` for the service-layer and
  tri-modal (`test` / `tui` / `serve`) plugin contract.
- `templates/process-plugin-template/` for the plugin skeleton to start from.
- `docs/live-operations-tui-safety.md` and `docs/assist-handoff.md` for
  external-agent interaction and live-input policy.
