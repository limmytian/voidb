---
name: voidb-plugin-elasticsearch
description: Guide for the VoidB Elasticsearch plugin. Use when modifying crates/plugins/voidb-plugin-elasticsearch, elasticsearch.* capabilities, Elasticsearch CLI commands, cluster/index/document services, raw API policy, diagnostics, or fixture smoke behavior.
---

# VoidB Elasticsearch Plugin

## Start Here

Primary crate: `crates/plugins/voidb-plugin-elasticsearch`.

Inspect:

- `src/config.rs` for `EsConfig` and `EsAuth`.
- `src/es_ops.rs` for low-level operations.
- `src/service/` for HTTP, cluster, index, document, commands, events, and types.
- `src/capabilities.rs` for `elasticsearch.*` metadata and invocation.
- `src/cli_plugin.rs` for `voidb-cli elasticsearch ...`.
- `docs/elasticsearch-release-readiness.md` when changing release or smoke behavior.

## Boundaries

- Keep `reqwest` usage and Elasticsearch wire shapes inside the plugin crate.
- Preserve diagnostics and target-error behavior for unavailable clusters.
- Treat `raw_api` as policy-sensitive; keep method/path validation, dry-run behavior, and destructive acknowledgment gates intact.
- Keep search/count/mapping result shaping stable for CLI and capability consumers.
- Do not move cluster/index/document domain logic into shell or core.

## CLI And Capabilities

- CLI commands: `health`, `nodes`, `indices`, `search`, `get`, `count`, `mapping`, `api`.
- Capabilities: `elasticsearch.diagnostics`, `elasticsearch.health`, `elasticsearch.nodes`, `elasticsearch.indices`, `elasticsearch.search`, `elasticsearch.get`, `elasticsearch.count`, `elasticsearch.mapping`, `elasticsearch.raw_api`.

## Validation

- Focused gate: `cargo test -p voidb-plugin-elasticsearch`.
- Add `cargo test -p voidb-cli invoke` for capability or generic invoke changes.
- Fixture gate when feasible: `scripts/elasticsearch-fixture-smoke.sh`.
- Always run `git diff --check`.
