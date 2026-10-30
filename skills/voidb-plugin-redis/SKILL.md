---
name: voidb-plugin-redis
description: Guide for the VoidB Redis plugin. Use when working on the external VoidB Redis plugin repository, redis.* capabilities, Redis CLI commands, RedisService, RedisAgentSessionFactory, redis_ops integration, first protocol pair behavior, or key/value mutation policy.
---

# VoidB Redis Plugin

## Where It Lives

The Redis plugin is a decoupled process plugin that lives in its own
independent repository (`voidb-plugin-redis`), not in this repository. Install
it with `voidb-cli plugin install-default` and run it through
`voidb-cli redis ...` or the `redis.*` capabilities.

## What It Does

Redis key-value capability plugin for VoidB: `redis.keys`, `redis.get`,
`redis.set`, `redis.del`, `redis.ttl`, `redis.info`, and `redis.exec`
capabilities backed by `RedisService`, plus `voidb-cli redis` domain commands
(`keys`, `get`, `set`, `del`, `ttl`, `type`, `info`, `exec`) and persistent
agent sessions. Destructive operations sit behind mutation and dry-run gates.

## Development Guidance

Current development guidance lives in this repository:

- `docs/process-plugin-development-guide.md` for the service-layer and
  tri-modal (`test` / `tui` / `serve`) plugin contract.
- `templates/process-plugin-template/` for the plugin skeleton to start from.
