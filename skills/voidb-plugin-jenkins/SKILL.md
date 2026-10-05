---
name: voidb-plugin-jenkins
description: Guide for the VoidB Jenkins plugin. Use when modifying crates/plugins/voidb-plugin-jenkins, jenkins.* capabilities, Jenkins service commands/events, standalone Jenkins TUI, job/build/console/pipeline operations, trigger/abort/cancel policy, diagnostics, or fixture smoke checks.
---

# VoidB Jenkins Plugin

## Start Here

Primary crate: `crates/plugins/voidb-plugin-jenkins`.

Inspect:

- `src/config.rs` for `JenkinsConfig` and auth.
- `src/service/` for commands, events, and service facade.
- `src/capabilities.rs` for `jenkins.*` metadata and invocation.
- `src/cli_plugin.rs` for `voidb-cli jenkins tui`.
- `src/tui.rs` for standalone Jenkins build/console TUI.
- `docs/jenkins-release-readiness.md` and `docs/jenkins-tui-evidence-2026-07-07.md`.

## Boundaries

- Keep Jenkins HTTP/API details inside this plugin crate.
- Treat `trigger_build`, `abort_build`, and `cancel_queue_item` as policy-sensitive operations.
- Redact URLs, usernames, API tokens, crumb/session data, and console output sections that might contain secrets.
- Keep console and pipeline reads bounded.
- Keep unavailable-service diagnostics deterministic and non-leaky.

## CLI And Capabilities

- CLI commands: `tui`.
- Capabilities: `jenkins.diagnostics`, `jenkins.jobs`, `jenkins.job_detail`, `jenkins.activity`, `jenkins.console`, `jenkins.pipeline`, `jenkins.trigger_build`, `jenkins.abort_build`, `jenkins.cancel_queue_item`.

## Validation

- Focused gate: `cargo test -p voidb-plugin-jenkins`.
- Add `cargo test -p voidb-cli invoke` for capability or generic invoke changes.
- Fixture gate when feasible: `scripts/jenkins-fixture-smoke.sh`.
- Always run `git diff --check`.
