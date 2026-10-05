---
name: voidb-plugin-redis
description: Guide for the VoidB Redis plugin. Use when modifying crates/plugins/voidb-plugin-redis, redis.* capabilities, Redis CLI commands, RedisService, RedisAgentSessionFactory, redis_ops integration, first protocol pair behavior, or key/value mutation policy.
---

# VoidB Redis Plugin

## Start Here

Primary crate: `crates/plugins/voidb-plugin-redis`.

Inspect:

- `src/config.rs` for `RedisConfig`.
- `src/redis_ops.rs` for low-level Redis operations.
- `src/service/` for `RedisService`, `RedisCommand`, and `RedisEvent`.
- `src/capabilities.rs` for `redis.*` metadata and invocation.
- `src/cli_plugin.rs` for `voidb-cli redis ...`.
- `src/agent_session.rs` for persistent agent sessions.
- `docs/duckdb-redis-release-readiness.md` for release-readiness decisions.

## Boundaries

- Keep `redis` crate usage inside this plugin crate.
- Prefer the service facade over calling `redis_ops` from UI or CLI dispatch code.
- Preserve deterministic target-error behavior for unavailable Redis services; tests should not require a real Redis server unless using an explicit fixture smoke.
- Keep destructive operations (`del`, write-like `exec`) behind policy metadata and dry-run/mutation gates where applicable.
- Redis and SQLite are the first protocol pair for generic invoke behavior; coordinate changes with `voidb-cli invoke`.

## CLI And Capabilities

- CLI commands: `keys`, `get`, `set`, `del`, `ttl`, `type`, `info`, `exec`.
- Capabilities: `redis.keys`, `redis.get`, `redis.set`, `redis.del`, `redis.ttl`, `redis.info`, `redis.exec`.

## Validation

- Focused gate: `cargo test -p voidb-plugin-redis`.
- Add `cargo test -p voidb-plugin-sqlite` and `cargo test -p voidb-cli invoke` for first-pair or generic invoke changes.
- Fixture gate when feasible: `scripts/redis-fixture-smoke.sh`.
- Always run `git diff --check`.
