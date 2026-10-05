# Conventions

## Naming Patterns

### Files
- Use `snake_case.rs` for all Rust source files
- Plugin crates: `voidb-plugin-{name}` (hyphenated) in `crates/plugins/`
- Module files match their purpose: `connection.rs`, `config.rs`, `table_plugin.rs`, `db_browser.rs`
- Widget files: `snake_case.rs` in `crates/voidb-core/src/widgets/`
- Test files in `tests/` directory: `snake_case.rs` (e.g., `tui_test_simple.rs`, `e2e_simulation.rs`)

### Types
- Use `PascalCase` for all structs, enums, and traits
- Enum variants: `PascalCase` (e.g., `CellValue::DateTime`, `SortOrder::Ascending`)
- Plugin types follow `{Db}Plugin` pattern: `MySqlTablePlugin`, `PostgresTablePlugin`
- Factory types: `{Db}PluginFactory` (e.g., `MySqlPluginFactory`)
- Provider types: `{Db}ConnectionProvider` (e.g., `MySqlConnectionProvider`)
- Config structs: `{Plugin}Config` (e.g., `MySqlConfig`, `SshConfig`)
- Error enums: `VoidbError` (single error type in `crates/voidb-core/src/error.rs`)

### Functions
- Use `snake_case` for all functions and methods
- Builder-style: `fn new()` for constructors, `fn default()` via `Default` trait
- Async functions: plain `async fn` naming, no special suffix
- Getter style: `fn name(&self) -> &str` (no `get_` prefix)
- Boolean getters: `fn has_protocol()`, `fn is_encrypted()`, `fn wants_raw_input()`
- Display helpers: `fn display(&self) -> String`, `fn as_str(&self) -> &'static str`

### Constants & Modules
- Use `SCREAMING_SNAKE_CASE` for constants
- Examples: `ENCRYPTED_PREFIX_V1`, `SALT_LEN`, `NONCE_LEN`, `KEY_LEN`
- Static arrays: `static SQL_KEYWORDS: &[&str]`, `static SQL_FUNCTIONS: &[&str]`
- Use `snake_case` for module names
- Re-export key types from `mod.rs` using `pub use`
- Top-level `lib.rs` re-exports commonly used types for ergonomic imports

## Code Style

- No `.rustfmt.toml`; uses default `rustfmt` settings — run `cargo fmt` before committing
- Standard 4-space indentation
- Uses `cargo clippy` for linting (no custom `.clippy.toml`)
- `#[allow(dead_code)]` used on public API types not all consumed locally (43 occurrences across 20 files)
- `#[deprecated]` attribute used on legacy modules with migration guidance (e.g., `connection_registry.rs`)
- Edition 2024 (set in each crate's `Cargo.toml`)
- No path aliases configured; use relative crate paths
- Workspace crates referenced by name: `voidb-core`, `voidb-plugin-mysql`, etc.

## Error Handling

- Single enum `VoidbError` in `crates/voidb-core/src/error.rs` using `thiserror`
- Variants: `Connection`, `Query`, `Schema`, `Config`, `Plugin`, `Crypto`, `InvalidConfig`, `IncompatiblePlugin`, `Runtime`, `Timeout`, `Io`, `Other`
- Pattern: wrap errors with `.map_err(|e| VoidbError::Variant(e.to_string()))`
- Use `anyhow::Result` for application-level functions; `main()` and plugin `update()` return `anyhow::Result<()>`
- Chain `.map_err()` to convert external errors into `VoidbError` variants
- Use `?` operator pervasively; avoid manual `match` on `Result` when possible
- `unwrap_or_else` with `tracing::warn!` for non-critical config loading
- `panic!` used only for programming errors (e.g., duplicate plugin registration in `PluginRegistry::register`)

## Documentation

- All modules in `voidb-core`: `//!` at the top of the file with purpose, architecture notes, examples
- All public types, traits, functions: `///` doc comments with full sentences; `# Arguments`, `# Returns`, `# Examples`, `# Panics` where applicable
- The `Plugin` trait in `crates/voidb-core/src/plugin/plugin_trait.rs` is the gold-standard example
- Implementation notes: `//` comments — explain *why*, not *what*
- Section headers: `// === Section Name ===` or `// --- Section ---`
- All code, comments, and documentation: **English only**

## Derive Patterns

```rust
// Data types
#[derive(Debug, Clone, Serialize, Deserialize)]

// Enum types
#[derive(Debug, Clone, PartialEq, Eq)]  // add Serialize, Deserialize if stored

// State types
#[derive(Debug, Clone, Default)]

// Error types
#[derive(Debug, Error)]  // from thiserror

// Config types
#[derive(Debug, Clone, Serialize, Deserialize)]
// #[serde(default)] for optional fields with defaults
// #[serde(default = "default_fn")] with free-standing default functions
// #[serde(tag = "type")] for internally-tagged enum variants (e.g., SshAuthMethod)
```

## Import Organization

```rust
// External crates
use std::collections::HashMap;
use tokio::sync::Mutex;

// Workspace crates
use voidb_core::{DatabaseAdapter, VoidbError};

// Local modules
use crate::app::App;
use crate::components::Grid;
```

## Common Patterns

| Pattern | Example Location | Description |
|---|---|---|
| Plugin trait implementation | `crates/voidb-core/src/plugin/plugin_trait.rs` | All plugins implement `Plugin` trait with `id()`, `name()`, `init()`, `update()` |
| Factory pattern | `crates/voidb-core/src/plugin/registry.rs` | `PluginFactory` creates plugin instances; registered in `PluginRegistry` |
| Dependency injection | `crates/voidb-core/src/shell_capabilities.rs` | `ShellCapabilities` injected via `Plugin::init()` |
| Channel-based communication | `crates/voidb-tui/src/app_v4.rs` | `TabRequest` enum sent via `mpsc::channel` from plugins to shell |
| Adapter pattern | `crates/voidb-core/src/database/mod.rs` | `DatabaseAdapter` trait abstracts database operations |
| Config deserialization | `crates/plugins/voidb-plugin-ssh/src/config.rs` | Plugin-specific config structs deserialized from `plugin_config` JSON |
| Provider pattern | `crates/plugins/voidb-plugin-mysql/src/connection.rs` | `ConnectionDataProvider` + `ConnectionDisplayProvider` for UI metadata |
| Re-export pattern | `crates/voidb-core/src/lib.rs` | Top-level re-exports for ergonomic `use voidb_core::Type` imports |
| Theme centralization | `crates/voidb-tui/src/theme.rs` | All UI colors/styles defined as static methods on `Theme` struct |
| `Arc<RwLock<T>>` sharing | `crates/voidb-core/src/shell_capabilities.rs` | Shared state between shell and plugins uses `Arc<RwLock<T>>` |

## Anti-patterns to Avoid

| Pattern | Location | Severity | Notes |
|---|---|---|---|
| `#[allow(dead_code)]` overuse | 20 files, 43 occurrences | Low | Gate behind features or properly consume instead |
| Duplicated `UserSession` helper | `tests/e2e_simulation.rs`, `tests/test_query_editor.rs` | Medium | Should be in shared `test_helpers.rs` |
| Very large files | `db_browser.rs` (2779 lines), `table_plugin.rs` (2668 lines) | Medium | Split into submodules for rendering, event handling, data loading |
| Deprecated module still compiled | `crates/voidb-core/src/connection_registry.rs` | Low | Consider feature-gating behind `cli` feature |
