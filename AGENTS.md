# VoidB - Terminal Database Manager

A terminal-based database management tool built with Rust + ratatui, replicating Navicat's core functionality with vim-style keybindings and a pure router architecture.

## Architecture v4.0 (Current)

VoidB v4.0 uses a **pure router architecture** where plugins are fully autonomous:

- **VoidB Shell** (`app_v4.rs`): Pure router (~1,025 lines) — manages tabs, routes events, renders 1-line tab bar and tab manager
- **Plugins**: Autonomous applications with full screen control
- **Communication**: Channel-based (non-blocking) + ShellCapabilities (DI)

**Key Event Routing** (two-layer):
1. **Hard globals** (always): `Ctrl+Q` (quit), `Ctrl+\` (shell escape menu)
2. Check `active_plugin.wants_raw_input()` — if `true`, skip soft globals
3. **Soft globals**: `q` (home), `Q` (close tab), `Ctrl+L` (tab manager)
4. Remaining events → active plugin

Shell does **not** render plugin UI, manage focus states, or show notifications.

## Plugin Trait

```rust
pub trait Plugin: Send + Sync {
    fn id(&self) -> &str;
    fn name(&self) -> &str;
    fn init(&mut self, caps: ShellCapabilities) -> Result<()>;
    fn update(&mut self, frame: &mut Frame, area: Rect, event: Option<Event>) -> Result<()>;
    fn wants_raw_input(&self) -> bool { false }
}
```

The shell registry currently contains only `ConnectionManagerPluginFactory`.
Protocol plugins are autonomous service, CLI, and capability crates. Built-in
and external plugins have identical first-class status under `voidb-cli`, which
dynamically discovers installed external process plugins and routes commands
transparently. Retained interactive apps (such as Docker, Kubernetes, Jenkins,
SSH, S3, WebDAV, Email) run as plugin-owned standalone TUIs through
`voidb-cli <plugin> tui --profile <profile>`. They are not embedded shell tabs.
All plugins follow the tri-modal contract: `test`, `tui`, and `serve` (stdio-jsonrpc).

## Service Layer (Critical)

Protocol, database, storage, and infrastructure plugins keep data operations in a `service/` submodule. The Sync plugin uses its dedicated `ops`/client/server modules for its command surface.
- `ServiceMode::Channel` — TUI mode: `send(cmd)` / `poll_event()` (non-blocking)
- `ServiceMode::Direct` — CLI mode: direct async method calls
- `SyncWorker<Cmd, Resp>` — for `!Send` types (SQLite, DuckDB)
- **TUI plugins never import database driver crates directly**

See [docs/plugin-development-guide.md](docs/plugin-development-guide.md) Section 11 for the full cookbook.

## Connection Management

`ConnectionConfigRegistry` (in `ShellCapabilities`) **only stores config metadata**. Each plugin manages its own live connection via its service layer. No shared connection pool.

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
