# VoidB - Terminal Database Manager

A terminal-based database management tool built with Rust + ratatui, replicating Navicat's core functionality with vim-style keybindings and a pure router architecture.

## Architecture v4.1 (Current)

VoidB v4.1 uses a **completely decoupled, capability-first process plugin architecture**:

- **VoidB Shell & Connection Manager** (`voidb`): Dedicated connection information, credential vault, profile management, and JIT authorization gateway. It never embeds or links heavyweight database drivers directly.
- **Unified Command Dispatcher** (`voidb-cli`): The master dispatch desk. Discovers both bundled and user-installed process plugins and transparently routes subcommands, options, and flags.
- **Decoupled Process Plugins**: All 14 official plugins (`mysql`, `postgres`, `sqlite`, `redis`, `ssh`, `duckdb`, `docker`, `kubernetes`, `s3`, `elasticsearch`, `mongodb`, `jenkins`, `webdav`, `email`) live in independent repositories (`voidb-plugin-<name>`) with identical first-class status.
- **Tri-Modal Standard Contract**: Every plugin adheres to:
  1. `test`: Fast connectivity & configuration verification.
  2. `tui`: Standalone interactive full-screen terminal application (`voidb-cli <plugin> tui --profile <profile>`).
  3. `serve`: Headless `stdio-jsonrpc` protocol server for AI coding agents and machine automation.
  4. Domain commands: Full autonomous CLI subcommands (e.g., `mysql query`, `k8s pods`, `docker ps`).

Default database plugins are bundled in distribution packages and initialized with `voidb-cli plugin install-default`.

## Service Layer & Plugin SDK

All process plugins use `voidb-process-plugin-sdk` and maintain data operations in a dedicated `service/` layer.
- `voidb` core workspace contains zero database drivers (`mysql_async`, `tokio-postgres`, `rusqlite`, `redis`, `libduckdb-sys`, `russh`).
- Heavy drivers belong exclusively to their respective plugin crates.

## Connection Management

`ConnectionConfigRegistry` / `ProfileStore` **only stores connection metadata and encrypted credentials** (AES-256-GCM). Each plugin manages its own live connections via its service layer. No shared connection pool.

## Key Commands

```bash
cargo build    # Build all crates
cargo run      # Run VoidB TUI
cargo test     # Run tests
cargo clippy   # Lint
```

Binary name: `voidb`

Validation is tiered. Use [docs/ci-checks.md](docs/ci-checks.md) for the current
fast and full command sets. Focused changes should run the relevant fast crate
tests before commit; broad, release, cross-crate, capability, credential, or
validation-policy changes should also run `cargo test --workspace --no-fail-fast`
and `cargo clippy --workspace --all-targets --no-deps`.

## Important Notes for AI Assistants

1. **Plugin Isolation**: Plugins go in separate crates under `crates/plugins/`, never in `voidb-core`
2. **Security Critical**: Credential handling uses AES-256-GCM — extra care required
3. **Testing**: Run the relevant fast checks from `docs/ci-checks.md` after
   focused changes; run full workspace test and clippy tiers for broad,
   release, cross-crate, capability, credential, or validation-policy changes
4. **Language**: All new code, comments, and documentation must be in English
5. **Service Layer**: TUI plugins consume services; never call DB driver crates from TUI code

## Reference Docs

- [Architecture deep-dive](docs/architecture.md) — layers, abstractions, data flow, plugin registry
- [Tech stack](docs/tech-stack.md) — all dependencies, configuration files, build system
- [Conventions](docs/conventions.md) — naming, code style, error handling, derive patterns, anti-patterns
- [Service layer design](docs/service-layer-design.md) — design decisions, invariants, TUI/CLI patterns, anti-patterns
- [Plugin development guide](docs/plugin-development-guide.md) — service layer cookbook
- [Sync plugin + server](docs/sync-plugin.md) — E2E encrypted config sync (opt-in, client-side keys)
