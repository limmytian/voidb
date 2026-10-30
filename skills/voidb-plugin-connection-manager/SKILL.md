---
name: voidb-plugin-connection-manager
description: Guide for the VoidB native Connection Manager. Use when modifying the VoidB terminal app's profile list, profile editor dialogs, credential unlock/protection UI, plugin installation guidance, profile catalog rendering, or launch behavior in crates/voidb-tui/src/connection_manager_app/.
---

# VoidB Connection Manager

## Start Here

The Connection Manager is the native standalone VoidB terminal application in
`crates/voidb-tui/src/connection_manager_app/`. The legacy embedded shell
(`app_v4.rs`) was removed in v0.3.6; this app is the only terminal application.
Locate the repo root, then inspect:

- `crates/voidb-tui/src/connection_manager_app/` for app state, events,
  actions, background polling, and rendering (`render/` holds the profile
  editor, overlays, and screen rendering).
- `crates/voidb-tui/src/profile_forms.rs` for profile form schemas and
  plugin config defaults.
- `crates/voidb-tui/src/plugin_onboarding.rs` for first-run plugin install
  guidance.
- `crates/voidb-core/src/connection.rs` for `ConnectionConfig`.
- `crates/voidb-core/src/profile_store.rs` for `LocalProfileStore`
  (`profiles.json` / `credentials.json`).
- `crates/voidb-core/src/credential_protection.rs` for protection modes and
  master-password state.
- `crates/voidb-core/src/plugin/connection_dialog.rs` for the
  `ConnectionDialogComponent` trait used by plugins.
- `docs/connection-manager-tui.md` and `docs/master-password-ux.md`.

## Responsibilities

- Own the home screen: profile list, profile catalog, credential state, and
  plugin install/onboarding guidance.
- Create, edit, delete, and save native profiles through `LocalProfileStore`.
- Render redacted profile metadata and credential state without leaking secrets.
- Show capability and CLI guidance through metadata, not by invoking live
  destructive operations.
- Launch via `voidb` (no arguments), `voidb --connection-manager`, or
  `voidb-cli connections tui`.

## Boundaries

- New manager CRUD writes `profiles.json` / `credentials.json`; it never writes
  `AppConfig.connections`. Legacy `config.toml` connections migrate only
  through `voidb-cli profile migrate apply`.
- Do not let ordinary plugins write to the profile or connection stores.
- Keep secret fields masked in status text, profile catalogs, logs, test
  output, and guidance rows.
- The app owns its own state, rendering, and input model; it does not implement
  the router-hosted `Plugin` screen or construct `ShellCapabilities` for tabs.
- When adding a new connection type, update both the form/type selector path
  and any CLI/profile metadata path that should recognize it.

## Validation

- Focused UI/profile changes: `cargo test -p voidb-tui`.
- Credential/profile storage changes: add `cargo test -p voidb-core profile_store` and `cargo test -p voidb-core profile_adapter`.
- Invoke or capability guidance changes: add `cargo test -p voidb-cli invoke`.
- Release or retained TUI work: run `scripts/tui-quality-gate.sh` when feasible.
- Always run `git diff --check`.
