---
name: voidb-plugin-connection-manager
description: Guide for the VoidB built-in Connection Manager plugin. Use when modifying the home screen, profile list, connection dialogs, credential unlock/protection UI, capability browser, profile catalog rendering, or tab opening behavior in crates/voidb-tui/src/plugins/connection_manager.rs.
---

# VoidB Connection Manager Plugin

## Start Here

Use this for the built-in home screen plugin, not an external crate. Locate the repo root, then inspect:

- `crates/voidb-tui/src/plugins/connection_manager.rs`
- `crates/voidb-tui/src/plugins/connection_dialog.rs`
- `crates/voidb-tui/src/profile_forms.rs`
- `crates/voidb-tui/src/app_v4.rs`
- `crates/voidb-core/src/connection.rs`
- `crates/voidb-core/src/profile_store.rs`
- `crates/voidb-core/src/credential_protection.rs`
- `docs/connection-manager-tui.md`
- `docs/master-password-ux.md`

## Responsibilities

- Own writes to `ConnectionConfigRegistry`: create, edit, delete, save, and load connection metadata.
- Delegate plugin-specific form behavior to `ConnectionDialogComponent` or profile form adapters.
- Open work tabs through `caps.tabs.open(title, plugin_id, context)`.
- Render redacted profile metadata and credential state without leaking secrets.
- Show capability guidance through metadata, not by invoking live destructive operations.

## Boundaries

- Do not move plugin-specific connection logic into the shell.
- Do not let ordinary plugins write to the connection registry.
- Keep secret fields masked in status text, profile catalogs, logs, test output, and capability browser rows.
- When adding a new connection type, update both the form/type selector path and any CLI/profile metadata path that should recognize it.
- Check actual shell registration in `app_v4.rs`; some migration docs may describe planned or legacy external factory wiring.

## Validation

- Focused UI/profile changes: `cargo test -p voidb-tui`.
- Credential/profile storage changes: add `cargo test -p voidb-core profile_store` and `cargo test -p voidb-core profile_adapter`.
- Capability browser or invoke guidance changes: add `cargo test -p voidb-cli invoke`.
- Release or retained TUI work: run `scripts/tui-quality-gate.sh` when feasible.
- Always run `git diff --check`.
