# Service Layer Design

This document captures the architectural decisions, design principles, and known pitfalls from the service-layer decoupling milestone (completed 2026-04-11). It is the reference for anyone adding a new plugin or extending an existing service.

## Core Decisions

These decisions were locked before any plugin extraction began and apply to all 14 plugins.

| Decision | Choice | Rationale |
|---|---|---|
| **D-01** | Per-plugin concrete service structs — no unified `PluginService` trait | Operations are too different across MySQL (SQL/rows), SSH (PTY I/O), Docker (container lifecycle), Redis (key scan). A unified trait becomes either stringly-typed or impossibly bloated. |
| **D-02** | Service code lives in `service/` submodule inside each plugin crate | Keeps driver deps (mysql_async, redis, bollard) inside the plugin crate. Moving services to `voidb-core` would pull all drivers into core. |
| **D-03** | Each plugin owns its own runtime (no shared runtime across plugins) | Per-plugin runtime creates at most 1 `Runtime` in init. Eliminates the per-operation `Runtime::new()` pattern. |
| **D-04** | `!Send` connections (rusqlite, duckdb) use a dedicated worker thread | Connection lives on the worker thread; commands/responses travel via channel. |
| **D-05** | Generic `SyncWorker<Cmd, Resp>` in `voidb-core` for all `!Send` types | SQLite and DuckDB both reuse the same generic wrapper — no duplication. |

## Service Layer Invariants

Rules that must hold for every service in the codebase:

1. **Zero TUI imports** — service modules must not depend on `ratatui`, `crossterm`, `Frame`, `Rect`, or `Widget`. If they do, the service cannot be used from CLI or MCP.
2. **`Send + Sync + 'static`** — services are wrapped in `Arc` and shared across async tasks. All driver handles (mysql_async::Pool, bollard::Docker, etc.) are already Send+Sync.
3. **Stateless re UI** — service methods take explicit parameters (`offset`, `limit`, `sort_column`) and return results. No "current page", "selected item", or cursor state lives in the service.
4. **Return domain types** — services return `voidb-core::database::types` (`CellValue`, `ColumnInfo`, `Row`, `QueryResult`) not raw driver types. Services return `Result<_, VoidbError>`, not `anyhow::Error`.
5. **Existing public API preserved** — `lib.rs` re-exports (`MySqlPluginFactory`, etc.) are unchanged. Decoupling is internal to the plugin crate.

## Service Architecture Per Plugin Category

### SQL Database Plugins (MySQL, PostgreSQL, SQLite, DuckDB)

Service sits above `DatabaseAdapter`. It wraps the adapter and adds higher-level operations:

```
{Db}Service
  |-- uses DatabaseAdapter for: list_databases, describe_table, query_rows, execute
  |-- adds: load_page (SELECT + COUNT), insert_row, update_cell, delete_rows,
  |         transaction management, DDL generation, export/import
```

Module layout:
```
crates/plugins/voidb-plugin-{db}/src/
    service/
        mod.rs          # {Db}Service facade
        commands.rs     # {Db}Command enum (inbound)
        events.rs       # {Db}Event enum (outbound to TUI)
        schema.rs       # Schema introspection (optional inner service)
        crud.rs         # Row CRUD operations (optional inner service)
```

### Ops-Wrapper Plugins (Redis, Docker, K8s, S3, WebDAV)

These already had `*_ops.rs` free functions. Service wraps them as methods:

```rust
// Before
pub async fn scan_keys(url: &str, db: u8, cursor: u64, ...) -> ScanResult { ... }

// After
impl RedisService {
    pub async fn scan_keys(&self, cursor: u64, ...) -> ScanResult {
        redis_ops::scan_keys(&self.url, self.db, cursor, ...).await
    }
}
```

`*_ops.rs` becomes private implementation detail. Service struct is the public interface.

### !Send Plugins (SQLite, DuckDB)

Connection lives on a dedicated thread; service communicates via `SyncWorker`:

```rust
pub struct SqliteService {
    worker: SyncWorker<SqliteCommand, SqliteResponse>,
}

impl SqliteService {
    pub async fn load_page(&self, ...) -> Result<PageResult, VoidbError> {
        self.worker.send(SqliteCommand::LoadPage { ... }).await?
    }
}
```

### Terminal/Session Plugins (SSH)

Bidirectional PTY requires channels both ways. SSH is the canonical model:

```
SshService
  |-- input channel:  SshInput  (Data, Resize, Exec, Disconnect)
  |-- output channel: SshSessionEvent (Data, HostKeyVerify, Disconnected)
  |-- SftpHandle: separate sub-service for SFTP
  |-- ForwardingManager: port-forward add/remove/status
```

For reusable lifecycle, lease, health, invalidation, and shutdown semantics
across SSH, database, Redis, storage, infrastructure, and Sync-style clients,
use [Plugin Session Capability](plugin-session-capability.md). The shared
capability records redacted descriptors only; live handles remain inside the
owning plugin service.
The SSH service is the reference implementation: it registers terminal, SFTP,
and forwarding descriptors from channel mode and maps descriptor close requests
back to existing service commands.

## TUI-to-Service Communication

Services expose `ServiceMode::Channel` (TUI) and `ServiceMode::Direct` (CLI) modes.

### TUI mode (non-blocking)

TUI plugins call `send(cmd)` / `poll_event()` — both non-blocking. The service runs an async worker loop on its tokio runtime.

```rust
// Spawn async work from synchronous update()
fn load_data(&mut self) {
    self.service.send(MySqlCommand::LoadPage { db, table, offset, limit });
    self.caps.tabs.request_render().ok();
}

// Poll in update() — check for results
fn poll_async(&mut self) {
    while let Some(event) = self.service.poll_event() {
        match event {
            MySqlEvent::PageLoaded(page) => { self.rows = page.rows; }
            MySqlEvent::Error(e) => { self.status = format!("Error: {e}"); }
        }
    }
}
```

### CLI mode (direct async)

CLI plugins call service methods directly in an async context:

```rust
let service = MySqlService::new_direct(&config).await?;
let result = service.execute_query(sql, db).await?;
print_table(&result);
```

## Anti-Patterns

### Unified PluginService trait

Do not create a `trait PluginService` that all plugins implement. The `DataPlugin` trait in `voidb-core/src/plugin/data.rs` is the cautionary example — it has `execute_custom_action(action, params) -> Value` as an escape hatch that proves the trait is too broad. Each plugin has its own concrete service struct.

### Service holding UI state

`GridState`, `FocusPane`, `MySqlMode`, `ListState` stay in the TUI plugin. Service methods accept raw data parameters (`offset: u64`, `limit: u64`, `pending_changes: HashMap<...>`) and return results. The TUI decides how to map results to display state.

### Service in voidb-core

Services need driver crates. voidb-core must not depend on mysql_async, redis, bollard, etc. Services stay in their plugin crates. Only shared types/traits go in voidb-core.

### ratatui types in service signatures

Service methods must not accept or return `ratatui::*` or `crossterm::*` types. Check any method extracted from a TUI plugin struct — it may still have `Frame`, `Rect`, or `Style` in its signature.

### Creating Runtime::new() per operation

After Phase 5 (Redis), `tokio::runtime::Runtime::new()` in plugin code should return 0 grep hits. One runtime per plugin, created in `init()` or service constructor.

## Validation Checks

Run these after touching any service module:

```bash
# No TUI imports in service code
grep -r "ratatui\|crossterm" crates/plugins/*/src/service* # must be empty

# No per-operation runtime creation
grep -r "Runtime::new()" crates/plugins/ # must be empty

# No blocking inside TUI update()
grep -r "\.join()" crates/plugins/ # std::thread::spawn joins in TUI plugins

# No raw driver types leaking through service API
grep -r "mysql_async::\|rusqlite::" crates/plugins/*/src/tui/ # must be empty
```

## Service Constructor Pattern

Every service provides consistent construction:

```rust
impl MySqlService {
    /// From ConnectionConfig (used by TUI via ShellCapabilities)
    pub async fn from_connection_config(config: &ConnectionConfig) -> Result<Self, VoidbError> {
        let mysql_config: MySqlConfig = serde_json::from_value(
            config.plugin_config.clone().unwrap_or_default()
        )?;
        Self::new(&mysql_config).await
    }

    /// From plugin-specific config (used by CLI, tests)
    pub async fn new(config: &MySqlConfig) -> Result<Self, VoidbError> { ... }
}
```

## What Belongs in the Service Layer vs TUI Layer

| Concern | Service | TUI plugin |
|---|---|---|
| Connect / disconnect | ✓ | |
| Schema introspection | ✓ | |
| Row CRUD, queries | ✓ | |
| File operations (SFTP/S3/WebDAV) | ✓ | |
| Streaming data (logs, terminal) | ✓ channel producer | channel consumer |
| Error types (`VoidbError`) | ✓ | converts to status string |
| Cursor position, scroll offset | | ✓ |
| Mode (Normal/Insert/Edit) | | ✓ |
| Pending edit buffer | | ✓ |
| Rendering, widgets | | ✓ |
| Key binding handling | | ✓ |
| Popups, dialogs | | ✓ |
| Clipboard operations | | ✓ |
| SQL syntax highlighting | shared utility (voidb-core) | |

---

*Architecture research: 2026-04-08 | Milestone complete: 2026-04-11*
