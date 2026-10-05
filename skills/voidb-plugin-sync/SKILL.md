---
name: voidb-plugin-sync
description: Guide for the VoidB Sync plugin. Use when modifying crates/plugins/voidb-plugin-sync, E2E encrypted config/object sync, sync CLI commands, credential handoff, conflict resolution, periodic sync, token storage, bundle crypto, client/server interactions, or sync release smoke behavior.
---

# VoidB Sync Plugin

## Start Here

Primary crate: `crates/plugins/voidb-plugin-sync`. Related server crate: `voidb-sync-server` outside the main workspace.

Inspect:

- `src/ops.rs` for the main command surface.
- `src/crypto.rs`, `src/bundler.rs`, and `src/token_store.rs` for encryption, bundle packaging, and local secret storage.
- `src/client.rs` and `src/session.rs` for server communication and session state.
- `src/config.rs` for sync config, periodic sync, object mappings, and conflicts.
- `src/cli_plugin.rs` for `voidb-cli sync ...`.
- `tests/e2e.rs` for end-to-end behavior.
- `docs/sync-plugin.md`, `docs/sync-boundary.md`, `docs/object-level-sync-model.md`, and `docs/sync-beta-readiness.md`.

## Boundaries

- Keep sync opt-in. Do not silently push, pull, enroll credentials, or enable periodic sync.
- Never sync plugin binaries, install roots, local executable code, or raw secret material.
- Preserve client-side encryption and recovery semantics. Treat key derivation, DEK handling, recovery codes, and token storage as security-critical.
- Keep object conflict handling explicit and auditable.
- `voidb-sync-server` is a separate workspace; run server checks separately when touched.

## CLI Surface

- CLI commands: `login`, `recover`, `logout`, `push`, `pull`.
- Credential commands: `credential migrate-mappings`, `credential re-enroll`.
- Conflict commands: `conflict list`, `conflict resolve`, `conflict credential-handoff`.
- Periodic commands: `periodic status`, `periodic configure`, `periodic run`.
- This plugin currently uses `ops`/client/server modules rather than a generic `service/` command surface.

## Validation

- Focused gate: `cargo test -p voidb-plugin-sync`.
- Sync smoke: `scripts/release-sync-smoke.sh --client-only` for client behavior, `--server-only` for server-only behavior, or no flag for both.
- Add `cargo test -p voidb-core object_sync` for object-sync boundary changes.
- Hosted/local server smoke is opt-in: `scripts/release-sync-smoke.sh --hosted`.
- Always run `git diff --check`.
