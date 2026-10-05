# VoidB Plugin Development Guide

This is the canonical reference for building plugins in VoidB v4.0. It covers architecture,
module responsibilities, the full plugin API, required patterns, the service layer convention,
and recommended UX practices.

For external process plugins that communicate over `stdio-jsonrpc`, start with
[Process Plugin SDK](process-plugin-sdk.md). This guide focuses on in-repo TUI
plugins and their service-layer boundaries.
Plugins that need durable connection/session reuse should also follow
[Plugin Session Capability](plugin-session-capability.md).

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Module Responsibilities](#2-module-responsibilities)
3. [Plugin Lifecycle](#3-plugin-lifecycle)
4. [The Plugin Trait](#4-the-plugin-trait)
5. [ShellCapabilities](#5-shellcapabilities)
6. [PluginFactory](#6-pluginfactory)
7. [Connection Configuration](#7-connection-configuration)
8. [Event System](#8-event-system)
9. [Tab Management](#9-tab-management)
10. [Registering Your Plugin](#10-registering-your-plugin)
11. [Service Layer Convention](#11-service-layer-convention)
12. [Required Patterns](#12-required-patterns)
13. [Recommended Patterns](#13-recommended-patterns)
14. [Constraints and Rules](#14-constraints-and-rules)
15. [Minimal Plugin Skeleton](#15-minimal-plugin-skeleton)
16. [Pre-ship Checklist](#16-pre-ship-checklist)

---

## 1. Architecture Overview

VoidB v4.0 uses a **pure router architecture**. The central insight is:

> **Plugins are autonomous applications. The shell is a dumb router.**

```
┌──────────────────────────────────────────────────┐
│                   VoidB Shell                    │
│  (tab bar rendering + event routing only)        │
├──────────┬──────────┬──────────┬─────────────────┤
│ Plugin A │ Plugin B │ Plugin C │   ...           │
│ (active) │          │          │                 │
└──────────┴──────────┴──────────┴─────────────────┘
         ↑
  Full screen control
  Own state, own connections
  Own keybindings, own UI
```

The shell (`app_v4.rs`) is about 1,025 lines. It:
- Maintains a `Vec<Tab>` with one plugin per tab
- Polls crossterm events at ~60fps (16ms timeout)
- Filters key events through a **two-layer global shortcut** system (see [Event System](#8-event-system))
- Routes remaining events to the active plugin via `plugin.update(frame, area, event)`
- Processes tab open/close requests that plugins send via channel

Everything else — layout, state machines, data loading, error display, keybindings — is entirely the plugin's responsibility.

---

## 2. Module Responsibilities

### Shell — `crates/voidb-tui/src/app_v4.rs`

| Does | Does NOT |
|------|----------|
| Render 1-line tab bar at top | Render any plugin UI |
| Route events to active plugin | Handle plugin-specific logic |
| Process global shortcuts (two-layer: hard + soft) | Manage plugin focus states |
| Create/destroy plugin instances via `PluginRegistry` | Show notifications |
| Receive tab requests over `mpsc` channel | Know what a plugin displays |

### voidb-core — `crates/voidb-core/`

Provides shared types and interfaces. Contains **no business logic**.

| Provides | Does NOT contain |
|----------|-----------------|
| `Plugin`, `PluginFactory` traits | Database drivers |
| `ShellCapabilities`, `TabManager` | Plugin implementations |
| `ConnectionConfig`, `ConnectionConfigRegistry` | UI rendering code |
| `Event` enum | Plugin-specific configuration |
| `ConnectionDialogComponent` trait | Application state |
| Widgets (`GridState`, etc.) | Connection pooling |
| `SyncWorker<Cmd, Resp>` generic | — |

### Plugins — `crates/plugins/<name>/`

Each plugin is a fully autonomous application:

| Owns | Shares (read-only via caps) |
|------|-----------------------------|
| Its own `tokio::Runtime` or async tasks | `ConnectionConfigRegistry` (connection metadata) |
| Its own database connection pool | `PluginRegistry` (plugin metadata) |
| All UI state (cursor, scroll, mode) | `VoidbClipboard` (cross-plugin clipboard) |
| Its own keybinding logic | — |
| Error handling and display | — |
| `service/` submodule for data operations | — |

### ConnectionManager — `crates/voidb-tui/src/plugins/connection_manager.rs`

The only plugin with **write access** to `ConnectionConfigRegistry`. It:
- Creates, edits, and deletes connection configurations
- Saves configurations to disk via `AppConfig`
- Opens other plugins in new tabs via `caps.tabs.open()`
- Delegates connection dialog UI to each plugin's `PluginFactory::create_connection_dialog()`

All other plugins treat `caps.connections` as **read-only**.

---

## 3. Plugin Lifecycle

```
App::new()
  └─ PluginRegistry::register(factory)     ← startup: register all factories

User opens connection
  └─ caps.tabs.open(title, plugin_id, ctx) ← trigger: ConnectionManager calls this
       └─ PluginRegistry::create(id, ctx)  ← factory.create(context) called
            └─ plugin.init(caps)           ← plugin receives ShellCapabilities
                 └─ [event loop begins]

Each key event
  └─ hard global? (Ctrl+Q, Ctrl+\)        ← always intercepted, even in raw mode
       ├─ yes: shell handles, event consumed
       └─ no:  plugin.wants_raw_input()?
            ├─ true:  plugin.update(frame, area, event)  ← soft globals skipped
            └─ false: soft global? (q, Q, Ctrl+L)
                 ├─ yes: shell handles, event consumed
                 └─ no:  plugin.update(frame, area, event)

User closes tab / app exits
  └─ drop(plugin)                          ← plugin cleans up connections, tasks
```

### Phase 1: Factory creates the plugin

`PluginFactory::create(context: Value)` receives a JSON context and returns a `Box<dyn Plugin>`.
The plugin at this point is **not yet connected** to anything — it should only parse the context
and initialize default state.

```rust
fn create(&self, context: Value) -> Result<Box<dyn Plugin>> {
    let connection_id = context["connection_id"]
        .as_str()
        .ok_or_else(|| anyhow!("Missing connection_id"))?
        .to_string();

    Ok(Box::new(MyPlugin {
        caps: None,
        connection_id,
        // ... default state ...
    }))
}
```

### Phase 2: Shell calls `init(caps)`

`Plugin::init()` is where the plugin:
1. Stores `ShellCapabilities` for later use
2. Reads connection configuration from `caps.connections`
3. Creates its service layer and kicks off connection
4. Kicks off initial data loading (ideally asynchronously)

```rust
fn init(&mut self, caps: ShellCapabilities) -> Result<()> {
    self.caps = Some(caps.clone());

    let config = caps.connections
        .blocking_read()
        .get(&self.connection_id)
        .ok_or_else(|| anyhow!("Connection '{}' not found", self.connection_id))?;

    let my_config: MyConfig = serde_json::from_value(
        config.plugin_config.clone().unwrap_or_default()
    )?;

    // Create service in channel mode for TUI
    self.service = Some(MyService::new(my_config, caps.tabs.clone(), runtime_handle));
    Ok(())
}
```

### Phase 3: update() loop

After `init()`, the shell calls `update(frame, area, event)` on every event that is not a
global shortcut. The plugin renders the full UI and handles the event in the same call.

### Phase 4: Drop

When a tab is closed or the app exits, the plugin is dropped. Implement `Drop` if you own
async resources (see [Required Patterns](#12-required-patterns)).

---

## 4. The Plugin Trait

```rust
pub trait Plugin: Send + Sync {
    fn id(&self) -> &str;
    fn name(&self) -> &str;

    fn init(&mut self, caps: ShellCapabilities) -> Result<()> { Ok(()) }

    fn update(
        &mut self,
        frame: &mut Frame,
        area: Rect,
        event: Option<Event>,
    ) -> Result<()>;

    fn wants_raw_input(&self) -> bool { false }
}
```

### `id() -> &str`

The plugin's unique identifier. Used for routing when `tabs.open()` is called.
- Must match `PluginFactory::plugin_id()`
- Convention: lowercase with hyphens (`"mysql"`, `"ssh-client"`, `"redis"`)
- Must be globally unique — duplicate IDs panic at startup

### `name() -> &str`

Human-readable name shown in the tab bar and UI (`"MySQL"`, `"SSH Client"`).

### `init(caps: ShellCapabilities) -> Result<()>`

Called once before the first `update()`. The plugin receives `ShellCapabilities` here.

**Do here:**
- Store `caps` in `self.caps = Some(caps)`
- Read connection config from `caps.connections`
- Create your service layer instance
- Kick off async initial data load
- Set initial tab title via `caps.tabs.set_title()`

**Do NOT:**
- Block for more than a few milliseconds — this freezes the UI
- Perform heavy computation synchronously

### `update(frame, area, event) -> Result<()>`

The core method. Called when an event is routed to this plugin.

**`event` can be `None`** when the shell forces a re-render (e.g., after a tab request resolves,
or after `caps.tabs.request_render()` is called from an async task).

**Do here:**
1. Poll service events (non-blocking `poll_event()`)
2. Handle the event if `event.is_some()`
3. Render your full UI to `frame` within `area`

```rust
fn update(&mut self, frame: &mut Frame, area: Rect, event: Option<Event>) -> Result<()> {
    // 1. Poll service events
    while let Some(evt) = self.service.poll_event() {
        self.handle_service_event(evt)?;
    }

    // 2. Handle user event
    if let Some(event) = event {
        self.handle_event(event)?;
    }

    // 3. Render
    self.render(frame, area)
}
```

### `wants_raw_input() -> bool`

Controls whether the shell intercepts soft global shortcuts (`q`, `Q`, `Ctrl+L`) before
forwarding key events to this plugin. Default: `false`.

When `true`, **only hard globals** (`Ctrl+Q` to quit, `Ctrl+\` to open shell escape menu)
are intercepted — all other key events reach the plugin directly. This is essential for
terminal-oriented plugins (SSH, Redis CLI) that need full keyboard control.

This method is called on every key event, so the return value can change dynamically:

```rust
fn wants_raw_input(&self) -> bool {
    // Raw mode only when actively connected to a terminal
    self.state == ConnectionState::Connected
        && self.view_mode == ViewMode::Terminal
}
```

**When to use:**
- Terminal emulators (SSH, serial console)
- Interactive CLI tools (Redis CLI, Python REPL)
- Any plugin where users type arbitrary text as the primary interaction

**When NOT to use (keep the default `false`):**
- Database browsers with tree/list navigation
- Configuration dialogs
- Plugins that mainly use vim-style single-key navigation

---

## 5. ShellCapabilities

```rust
#[derive(Clone)]
pub struct ShellCapabilities {
    pub connections: Arc<RwLock<ConnectionConfigRegistry>>,
    pub tabs: Arc<dyn TabManager>,
    pub clipboard: Arc<RwLock<Option<VoidbClipboard>>>,
    pub plugin_registry: Arc<PluginRegistry>,
    pub sessions: Arc<PluginSessionRegistry>,
    pub runtime: tokio::runtime::Handle,
}
```

Store it in your plugin struct as `caps: Option<ShellCapabilities>`, set in `init()`.

### `caps.connections`

Shared connection configuration registry. Contains only metadata (host, port, credentials),
not live database connections.
Reusable live sessions are plugin-owned service resources. Use the
[Plugin Session Capability](plugin-session-capability.md) descriptor lifecycle
when a plugin needs shared lease, health, invalidation, or shutdown semantics.

```rust
// Read (most plugins only ever read)
let registry = caps.connections.blocking_read();
let config = registry.get("my-connection-id")?;

// Write (ConnectionManager only)
caps.connections.blocking_write().upsert(new_config);
```

Key methods on `ConnectionConfigRegistry`:
- `get(id) -> Option<ConnectionConfig>` — fetch one config by name
- `list() -> Vec<ConnectionConfig>` — all configs
- `exists(id) -> bool` — check existence
- `upsert(config)` — add or update (ConnectionManager only)
- `delete(id)` — remove (ConnectionManager only)

### `caps.tabs`

Tab management. See [Tab Management](#9-tab-management) for the full API.

### `caps.clipboard`

Cross-plugin clipboard for database table data. Used to copy rows from one database plugin
and paste into another.

```rust
// Copy rows to clipboard
*caps.clipboard.blocking_write() = Some(VoidbClipboard::Rows(ClipboardRows {
    columns: vec!["id".into(), "name".into()],
    rows: selected_rows,
    source_dialect: DatabaseDialect::MySQL,
}));

// Read clipboard
if let Some(clipboard) = caps.clipboard.blocking_read().as_ref() {
    // use clipboard data
}
```

### `caps.plugin_registry`

Read-only access to registered plugin metadata. Rarely needed by plugins directly.

```rust
// Check if a plugin is available
if caps.plugin_registry.has_plugin("redis") {
    // show redis option
}

// List all plugins
let plugins = caps.plugin_registry.list_plugin_info();
```

### `caps.sessions`

Shared descriptor registry for plugin-owned runtime sessions. Use it only from
the owning plugin service or a thin service wrapper. The registry stores
redacted descriptors, health, leases, and close callbacks; it never stores
database pools, SSH handles, HTTP clients, SFTP workers, or decrypted
configuration.

The SSH plugin is the reference in-repo consumer:

- terminal PTY sessions use `interactive_terminal`;
- SFTP workers use `file_transfer`;
- port forwards use `port_forward`;
- descriptor close callbacks send existing service commands such as
  `Disconnect`, `Sftp(Close)`, or `Forward(Remove(id))`.

Keep descriptor metadata small and target-free. Do not include hostnames,
usernames, paths, SQL text, bucket names, object keys, tokens, private key
paths, or decrypted `plugin_config`.

---

## 6. PluginFactory

```rust
pub trait PluginFactory: Send + Sync {
    fn create(&self, context: Value) -> Result<Box<dyn Plugin>>;
    fn plugin_id(&self) -> &str;
    fn plugin_name(&self) -> &str;
    fn description(&self) -> &str { "" }
    fn create_connection_dialog(
        &self,
        existing_config: Option<&ConnectionConfig>,
    ) -> Option<Box<dyn ConnectionDialogComponent>> {
        None
    }
}
```

### `create(context: Value) -> Result<Box<dyn Plugin>>`

Creates a new plugin instance. The `context` is a JSON object, typically passed by
`ConnectionManager` when the user opens a connection.

**Standard context keys:**

```json
{
  "connection_id": "my-prod-server",   // REQUIRED: matches a key in ConnectionConfigRegistry
  "database": "analytics",            // optional: for DB plugins that navigate databases
  "table": "users"                    // optional: for plugins that open directly to a table
}
```

Your factory decides how to interpret the context — and can produce different plugin types
depending on what's present:

```rust
fn create(&self, context: Value) -> Result<Box<dyn Plugin>> {
    let connection_id = context["connection_id"].as_str()
        .ok_or_else(|| anyhow!("Missing connection_id"))?.to_string();

    let table = context["table"].as_str().unwrap_or("").to_string();

    if table.is_empty() {
        // Open browser (shows list of tables)
        Ok(Box::new(MyBrowserPlugin::new(connection_id)))
    } else {
        // Open directly to a specific table
        Ok(Box::new(MyTablePlugin::new(connection_id, table)))
    }
}
```

### `create_connection_dialog()`

Return `Some(dialog)` to provide a custom connection configuration form. Return `None` to use
the default dialog (which relies on `ConnectionDataProvider` custom fields — not yet stable).

Most plugins should implement a custom dialog — it gives full control over field layout,
authentication options, and validation logic.

```rust
fn create_connection_dialog(
    &self,
    existing_config: Option<&ConnectionConfig>,
) -> Option<Box<dyn ConnectionDialogComponent>> {
    let dialog = match existing_config {
        Some(cfg) => MyConnectionDialog::from_config(cfg),
        None => MyConnectionDialog::new(),
    };
    Some(Box::new(dialog))
}
```

See `crates/voidb-core/src/plugin/connection_dialog.rs` for the `ConnectionDialogComponent` trait.

---

## 7. Connection Configuration

```rust
pub struct ConnectionConfig {
    pub name: String,                          // user-visible name, also the key in registry
    pub db_type: DatabaseType,                 // MySQL | PostgreSQL | SQLite | Plugin
    pub plugin_id: Option<String>,             // required when db_type == Plugin
    pub plugin_config: Option<serde_json::Value>, // plugin-defined JSON blob, encrypted at rest
}
```

### Storing Plugin-Specific Config

All plugin-specific fields go into `plugin_config` as a JSON blob. Define your own config
struct and serialize/deserialize it:

```rust
// Define your config
#[derive(Serialize, Deserialize)]
struct MyConfig {
    host: String,
    port: u16,
    username: String,
    password: String,       // stored encrypted by Core
    database: String,
    use_ssl: bool,
}

// In init(): read and parse
fn init(&mut self, caps: ShellCapabilities) -> Result<()> {
    let registry = caps.connections.blocking_read();
    let conn = registry.get(&self.connection_id)
        .ok_or_else(|| anyhow!("Connection not found: {}", self.connection_id))?;

    let config: MyConfig = conn.plugin_config
        .as_ref()
        .ok_or_else(|| anyhow!("Missing plugin_config"))?
        .clone()
        .try_into()
        .map_err(|e| anyhow!("Invalid config: {}", e))?;
        // or: serde_json::from_value(pc.clone())?

    self.connect(config)?;
    Ok(())
}

// In ConnectionDialog::build_config(): serialize
fn build_config(&self) -> Result<ConnectionConfig, String> {
    let my_config = MyConfig {
        host: self.host_field.value().to_string(),
        port: self.port_field.value().parse().map_err(|_| "Invalid port")?,
        // ...
    };

    Ok(ConnectionConfig {
        name: self.name_field.value().to_string(),
        db_type: DatabaseType::Plugin,
        plugin_id: Some("my-plugin".to_string()),
        plugin_config: Some(serde_json::to_value(my_config).unwrap()),
    })
}
```

---

## 8. Event System

### The `Event` Enum

```rust
pub enum Event {
    Key(crossterm::event::KeyEvent),    // keyboard input
    Mouse(crossterm::event::MouseEvent),// mouse input
    FocusGained,                        // this tab became active
    FocusLost,                          // user switched to another tab
    Tick,                               // periodic tick (100ms)
    Resize { width: u16, height: u16 }, // terminal resized
}
```

### Dispatch Priority

Every key event follows this priority chain:

```
1. Tab Manager popup (if open)         → handles and consumes
2. Hard global shortcuts               → always intercepted (even in raw mode)
3. plugin.wants_raw_input() == true?   → if yes, skip step 4, forward to plugin
4. Soft global shortcuts               → intercepted only for non-raw plugins
5. plugin.update(frame, area, Some(event))
```

### Global Shortcuts (Two-Layer System)

VoidB uses a two-layer global shortcut system to balance shell control with plugin autonomy:

**Hard globals** — always intercepted, plugins can never receive these:

| Shortcut | Action |
|----------|--------|
| `Ctrl+Q` | Quit VoidB |
| `Ctrl+\` | Shell escape menu (Tab Manager) — the "emergency exit" for raw-mode plugins |

**Soft globals** — only intercepted when `wants_raw_input() == false` (the default):

| Shortcut | Action |
|----------|--------|
| `q` (no modifiers, not on tab 0) | Return to Connection Manager (tab 0) |
| `Q` (Shift+Q, not on tab 0) | Close the current tab |
| `Ctrl+L` | Open Tab Manager popup |

**For non-raw plugins (default):** Avoid using `q`, `Q`, or `Ctrl+L` as keybindings —
these keys are intercepted by the shell before reaching your plugin.

**For raw-mode plugins:** All keys except `Ctrl+Q` and `Ctrl+\` reach the plugin.
Users access shell-level operations (close tab, switch tab, go home) through the
shell escape menu (`Ctrl+\`).

### Tick Events

`Event::Tick` fires every ~100ms. It is **not** sent periodically on its own — VoidB only
emits events that crossterm produces. Tick is useful for:
- Auto-clearing status messages after N ticks
- Polling for async results at a fixed rate
- Animating loading spinners

Tick events are always routed directly to the active plugin (they never match a global shortcut).

### Focus Events

`FocusGained` fires when the user switches back to your tab. Use it to refresh stale data.
`FocusLost` fires when leaving your tab. Use it to pause background work.

---

## 9. Tab Management

All tab operations go through `caps.tabs` (a `Arc<dyn TabManager>`).

### Opening a New Tab

```rust
caps.tabs.open(
    "MySQL - production".to_string(),  // tab title
    "mysql".to_string(),               // plugin_id (must be registered)
    json!({
        "connection_id": "prod-mysql-01",
        "database": "analytics",
    }),
)?;
```

The shell processes this asynchronously (via `mpsc` channel). The new tab appears on the
**next render cycle**, not immediately.

### Closing the Current Tab

```rust
caps.tabs.close_current()?;
```

If this is the last tab, the application quits.

### Updating the Tab Title

```rust
// Good practice: update to show current context
caps.tabs.set_title(format!("MySQL - {}.{}", database, table))?;
```

Call this in `init()` once you know what you're displaying, and again if the user navigates.

### Triggering a Re-render from Async Code

When a background task completes and you want the UI to update without waiting for the next
user event, call `request_render()`:

```rust
let tabs_ref = caps.tabs.clone();
std::thread::spawn(move || {
    let result = fetch_data_from_db();
    tx.send(result).ok();
    tabs_ref.request_render().ok(); // wake up the event loop
});
```

### Listing and Switching Tabs

```rust
// Get all open tabs
let tabs = caps.tabs.list_tabs()?;
for tab in &tabs {
    println!("{}: {} (plugin: {})", tab.index, tab.title, tab.plugin_id);
}

// Switch to a specific tab
caps.tabs.switch_to(0)?; // go to tab 0 (Connection Manager)

// Close a specific tab
caps.tabs.close_tab(2)?;

// Get current tab index
let idx = caps.tabs.active_tab_index()?;
```

---

## 10. Registering Your Plugin

### Step 1: Implement `PluginFactory` in your crate

```rust
// crates/plugins/voidb-plugin-myplugin/src/lib.rs

pub use factory::MyPluginFactory;

mod factory {
    use voidb_core::{PluginFactory, Plugin, ConnectionConfig};
    use serde_json::Value;
    use anyhow::Result;

    pub struct MyPluginFactory;

    impl PluginFactory for MyPluginFactory {
        fn create(&self, context: Value) -> Result<Box<dyn Plugin>> {
            let connection_id = context["connection_id"]
                .as_str()
                .unwrap_or("")
                .to_string();
            Ok(Box::new(super::plugin::MyPlugin::new(connection_id)))
        }

        fn plugin_id(&self) -> &str { "my-plugin" }
        fn plugin_name(&self) -> &str { "My Plugin" }
        fn description(&self) -> &str { "Does something cool" }
    }
}
```

### Step 2: Add to workspace `Cargo.toml`

```toml
# Cargo.toml (workspace root)
[workspace]
members = [
    # ...existing entries...
    "crates/plugins/voidb-plugin-myplugin",
]
```

### Step 3: Add dependency to `voidb-tui`

```toml
# crates/voidb-tui/Cargo.toml
[dependencies]
# ...existing...
voidb-plugin-myplugin = { path = "../plugins/voidb-plugin-myplugin" }
```

### Step 4: Register in `app_v4.rs`

```rust
// crates/voidb-tui/src/app_v4.rs — in App::new()
plugin_registry.register(Box::new(voidb_plugin_myplugin::MyPluginFactory));
```

### Step 5: Add connection type to `conn_types()` in `connection_manager.rs`

**CRITICAL**: Without this step, users cannot create new connections of your plugin type from
the UI. The ConnectionManager uses a hardcoded list to show available connection types in the
"New Connection" dialog.

```rust
// crates/voidb-tui/src/plugins/connection_manager.rs — in conn_types()
fn conn_types(&self) -> Vec<ConnType> {
    vec![
        ConnType::builtin("MySQL", DatabaseType::MySQL, 3306, "root"),
        ConnType::builtin("PostgreSQL", DatabaseType::PostgreSQL, 5432, "postgres"),
        ConnType::builtin("SQLite", DatabaseType::SQLite, 0, ""),
        ConnType::plugin("Redis", "redis", 6379, "localhost", ""),
        ConnType::plugin("Email", "email", 993, "imap.gmail.com", ""),
        // Add your plugin here:
        ConnType::plugin("My Plugin", "my-plugin", 1234, "localhost", "user"),
    ]
}
```

For plugin types, use `ConnType::plugin(label, plugin_id, default_port, default_host, default_username)`.
The `plugin_id` must match your `PluginFactory::plugin_id()`.

For `DatabaseType::Plugin` connections, the `plugin_id` field in `ConnectionConfig` is used
automatically for routing — no additional code change needed as long as you set
`db_type: DatabaseType::Plugin` and `plugin_id: Some("my-plugin".to_string())` in your
`build_config()`.

### Step 6 (Optional): Add protocol icon

Add your plugin's icon to `protocol_icon()` in `connection_manager.rs`:

```rust
fn protocol_icon(protocol: &str) -> &'static str {
    match protocol.to_lowercase().as_str() {
        "mysql" | "mariadb" => "🐬",
        "postgres" | "postgresql" => "🐘",
        "sqlite" => "📦",
        "ssh" => "🔐",
        "redis" => "🔴",
        "email" => "📧",
        "my-plugin" => "🔧",  // Add your icon here
        _ => "🔌",
    }
}
```

---

## 11. Service Layer Convention

New database, protocol, storage, and infrastructure plugins must extract data operations into
a `service/` submodule. The service layer decouples data operations from the TUI, enabling CLI,
MCP, and future interfaces to share the same logic without any UI dependency. Specialized
plugins with a different command surface, such as Sync, may use dedicated `ops`/client modules
instead.
Sessionful services should own their live handles and expose only redacted
descriptors through [Plugin Session Capability](plugin-session-capability.md).

### 11.1 Why a Service Layer

Before decoupling, database queries, schema introspection, and CRUD operations were embedded
directly in the TUI plugin code. This meant:
- CLI had to duplicate data logic or import TUI-dependent code
- Testing required a terminal
- Adding new interfaces (MCP, REST) meant more duplication

The service layer provides a single source of truth for all data operations. The TUI and CLI
are both consumers of the service — neither contains business logic directly.

### 11.2 Service Module Structure

Each protocol/data plugin crate organizes its service code in a `service/` submodule:

```
crates/plugins/voidb-plugin-{name}/src/
  service/
    mod.rs           # {Name}Service struct, public API, background_task
    commands.rs      # {Name}Command enum (inbound from TUI/CLI)
    events.rs        # {Name}Event enum (outbound to TUI)
    schema.rs        # SchemaService (optional inner service)
    crud.rs          # CrudService (optional inner service)
    data_loader.rs   # DataLoaderService (optional inner service)
    browser.rs       # BrowserService (optional inner service)
  tui/
    mod.rs           # TUI plugin (consumes service via channels)
  cli.rs             # CLI plugin (consumes service via direct async)
  config.rs          # Plugin-specific configuration
```

The service module is the **only** place that imports database driver crates (e.g.,
`mysql_async`, `tokio-postgres`, `rusqlite`). TUI code never imports driver types directly.

### 11.3 Command/Event Enums

Commands flow **into** the service (from TUI or CLI). Events flow **out** (from service to TUI).

**Command enum** — from the MySQL reference implementation (`crates/plugins/voidb-plugin-mysql/src/service/commands.rs`):

```rust
/// Top-level command enum for the MySQL service.
pub enum MySqlCommand {
    // --- Connection lifecycle (oneshot reply for request-response) ---
    Connect {
        config: MySqlConfig,
        reply: oneshot::Sender<Result<(), String>>,
    },
    Ping {
        reply: oneshot::Sender<Result<(), String>>,
    },
    Disconnect,

    // --- Domain sub-commands (fire-and-forget, results come back as events) ---
    Schema(SchemaCommand),
    Crud(CrudCommand),
    Load(LoadCommand),
    Browser(BrowserCommand),
}

/// Schema introspection commands.
pub enum SchemaCommand {
    ListDatabases,
    ListTables { database: String },
    ListColumns { database: String, table: String },
    ListIndexes { database: String, table: String },
    // ...
}
```

Key patterns:
- **Oneshot reply channel** for request-response operations (Connect, Ping) where the caller
  needs the result immediately
- **Fire-and-forget** for async operations (Schema, Crud, Load) where results arrive as events
- **Domain sub-enums** group related operations (SchemaCommand, CrudCommand, LoadCommand, BrowserCommand)

**Event enum** — from the MySQL reference (`crates/plugins/voidb-plugin-mysql/src/service/events.rs`):

```rust
/// Top-level event enum for the MySQL service.
pub enum MySqlEvent {
    // --- Connection lifecycle ---
    Connected,
    Disconnected,

    // --- Domain events (grouped to match command domains) ---
    Schema(SchemaEvent),
    Crud(CrudEvent),
    Load(LoadEvent),
    Browser(BrowserEvent),

    // --- Error (per convention: every event enum must have this) ---
    Error(String),
}
```

The `Error(String)` variant is mandatory — it provides a uniform way for the TUI to display
operation failures regardless of which domain produced them.

### 11.4 ServiceMode Pattern

Each service struct supports two modes of operation through an internal `ServiceMode` enum:

```rust
/// Internal mode discriminator.
enum ServiceMode {
    /// TUI mode: commands sent via channel, results polled as events.
    Channel {
        cmd_tx: mpsc::UnboundedSender<MySqlCommand>,
        event_rx: mpsc::UnboundedReceiver<MySqlEvent>,
        _task: tokio::task::JoinHandle<()>,
    },
    /// CLI mode: inner services owned directly, async methods called directly.
    Direct {
        schema_svc: SchemaService,
        crud_svc: CrudService,
        loader_svc: DataLoaderService,
    },
}

pub struct MySqlService {
    mode: ServiceMode,
}
```

**Channel mode** (`new()`) — for TUI consumption:
- Creates an unbounded mpsc channel pair
- Spawns a background tokio task that processes commands
- TUI sends commands via `service.send(cmd)` (non-blocking)
- TUI polls results via `service.poll_event()` (non-blocking)
- Background task calls `tabs.request_render()` after every event emission

**Direct mode** (`new_direct()`) — for CLI consumption:
- Creates inner services directly (no channels, no background task)
- CLI calls async methods directly: `service.list_databases().await`
- No render notifications needed

```rust
impl MySqlService {
    /// Channel mode constructor (TUI).
    pub fn new(
        config: MySqlConfig,
        tabs: Arc<dyn TabManager>,
        runtime: tokio::runtime::Handle,
        clipboard: Arc<tokio::sync::RwLock<Option<VoidbClipboard>>>,
    ) -> Self {
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let task = runtime.spawn(Self::background_task(cmd_rx, event_tx, tabs, clipboard));
        Self { mode: ServiceMode::Channel { cmd_tx, event_rx, _task: task } }
    }

    /// Direct mode constructor (CLI).
    pub async fn new_direct(config: &MySqlConfig) -> Result<Self, String> {
        let pool = create_pool(config)?;
        Ok(Self {
            mode: ServiceMode::Direct {
                schema_svc: SchemaService::new(pool.clone()),
                crud_svc: CrudService::new(pool.clone()),
                loader_svc: DataLoaderService::new(pool),
            },
        })
    }
}
```

### 11.5 TUI Consumption

The TUI plugin interacts with the service through two non-blocking methods:

```rust
// Sending commands (in event handlers):
service.send(MySqlCommand::Schema(SchemaCommand::ListDatabases));
service.send(MySqlCommand::Load(LoadCommand::LoadTableData {
    database: "mydb".into(),
    table: "users".into(),
    page_size: 100,
    offset: 0,
}));

// Polling events (in update() loop):
fn update(&mut self, frame: &mut Frame, area: Rect, event: Option<Event>) -> Result<()> {
    // Drain all pending service events
    let svc = self.service.lock().unwrap();
    while let Some(evt) = svc.poll_event() {
        match evt {
            MySqlEvent::Schema(SchemaEvent::DatabasesLoaded(dbs)) => {
                self.databases = dbs;
            }
            MySqlEvent::Load(LoadEvent::TableDataLoaded { columns, rows, .. }) => {
                self.columns = columns;
                self.rows = rows;
            }
            MySqlEvent::Error(msg) => {
                self.show_error(&msg);
            }
            _ => {}
        }
    }
    drop(svc);

    // Handle user input, render UI...
}
```

The service's background task calls `tabs.request_render()` after emitting every event,
which wakes the TUI event loop and triggers an `update()` call where `poll_event()` picks
up the result.

### 11.6 CLI Consumption

The CLI uses direct async method calls — no channels, no background task:

```rust
// In a CliPlugin implementation:
async fn execute(&self, ctx: &CliContext, matches: &ArgMatches) -> Result<(), String> {
    let config = self.load_config(ctx, matches)?;
    let service = MySqlService::new_direct(&config).await?;

    let databases = service.list_databases().await
        .map_err(|e| e.to_string())?;

    for db in databases {
        println!("{}", db);
    }
    Ok(())
}
```

The CLI binary (`crates/voidb-cli/src/main.rs`) uses `CliPluginManager` to register and
dispatch plugin CLI commands. Each plugin provides a `create_{name}_cli_plugin()` factory
function.

### 11.7 Session Capability Cookbook

Use `caps.sessions` when a service keeps authenticated or stateful runtime
resources alive across operations. The service remains the owner of all live
handles; the session registry is only a descriptor, lease, health, and shutdown
coordinator.

Use sessions for:

- interactive terminals, SFTP workers, port forwards, log streams, watch
  streams, long-running sync clients, and reusable database or protocol clients;
- service-owned state that needs explicit close, owner close, health reporting,
  or support-bundle visibility;
- cases where multiple service subdomains reuse one authenticated transport,
  such as SSH terminal, SFTP, and forwarding over one SSH connection.

Do not use sessions for:

- one-shot stateless operations that do not keep a live target resource;
- persisted UI restore state such as the last SFTP path;
- exposing driver handles to the shell, another plugin, or agent-facing output.

Agent-facing stream or cursor families attach an `AgentLiveSessionContract` to
their `CapabilitySessionHandoff`. Keep driver cursors and clients in the
service; expose only schema-checked events and bounded opaque cursors. Choose
`bounded_buffer` when a producer must run in the background and report every
drop/coalesce through truncation counters. Choose `source_paced` only when the
target advances during a bounded pull and no buffered loss is possible.
Resumable data/search cursors should require a one-way resource-scope
fingerprint and emit sequence-bound checkpoints. Heartbeat events are
content-free and require declared interval/idle bounds; read waits are capped
by both the live descriptor and the generic session call timeout. The normative
mapping is [Data and Search Agent Live-Session Contract](data-search-agent-live-session-contract.md).

Long storage transfers use `AgentTransferContract` and `AgentTransferEvent`
from `voidb_core::transfer`. The backend descriptor is descriptive only: do not
attach a transfer session handoff until the plugin service owns cancellation,
bounded retry, resume binding, conflict revalidation, and cleanup. S3/WebDAV
mapping and local-path rules are defined in
[Storage Agent Transfer Contract](storage-agent-transfer-contract.md).

Recommended integration pattern:

1. Generate a runtime `owner_id` that does not contain hostnames, usernames, or
   connection labels.
2. Pass `caps.sessions.clone()` into the service constructor. Prefer an
   explicit constructor such as `new_with_sessions(...)` and keep `new(...)` as
   a standalone/testing fallback if needed.
3. Register descriptors from the service layer when a live resource starts.
   Use standardized purposes such as `interactive_terminal`, `file_transfer`,
   and `port_forward`.
4. Store only redacted metadata. Safe examples are local descriptor kind,
   terminal dimensions, or an internal forwarding rule id. Unsafe examples are
   hosts, remote paths, usernames, SQL text, bucket names, tokens, and private
   key paths.
5. Attach close callbacks that send existing service commands over the service
   channel. The callback must not block the render loop.
6. Update health on service events and mark sessions closed in the same order
   the service tears down live resources.
7. In `Drop`, save UI-only state separately, then request owner close through
   `caps.sessions.close_owner(owner_id, "plugin_dropped")`.

Tests for sessionful services should cover descriptor registration without
secret metadata, close callbacks mapping to service commands, health
transitions, and owner shutdown. For release-candidate changes touching session
integration, run the plugin's service/capability gate plus `cargo test -p
voidb-core session`, `cargo test -p voidb-tui`, `git diff --check`, and the
workspace tiers when the shared boundary changes.

### 11.8 !Send Worker Pattern (SyncWorker)

Some database drivers produce `!Send` connection types (rusqlite, duckdb). These connections
cannot be moved across thread boundaries, which means they cannot be used with
`tokio::spawn()`. The `SyncWorker<Cmd, Resp>` generic in `crates/voidb-core/src/sync_worker.rs`
solves this.

**Architecture:**

```
TUI thread                    Worker thread (OS thread)
----------                    -------------------------
SyncWorker.send(cmd) ------> std::sync::mpsc::Receiver
                                  |
                               handler_fn(&mut conn, cmd)
                                  |
SyncWorker.try_recv() <----- tokio::sync::mpsc::UnboundedSender
SyncWorker.recv().await <---'
```

**When to use:** Any plugin whose database driver produces a `!Send` connection type.
Currently used by SQLite (`rusqlite::Connection`) and DuckDB (`duckdb::Connection`).

**Usage** — from `SqliteService`:

```rust
use voidb_core::sync_worker::SyncWorker;

let worker = SyncWorker::spawn(
    || {
        // init_fn: create the !Send connection on the worker thread
        let conn = rusqlite::Connection::open(&config.path)?;
        Ok(conn)
    },
    |conn, cmd| {
        // handler_fn: process each command using the connection
        match cmd {
            InternalCmd::Schema(schema_cmd) => {
                let result = handle_schema(conn, schema_cmd);
                Some(InternalResp::Schema(result))
            }
            InternalCmd::Crud(crud_cmd) => {
                let result = handle_crud(conn, crud_cmd);
                Some(InternalResp::Crud(result))
            }
            // ...
        }
    },
)?;
```

Key design points:
- `SyncWorker::spawn()` takes an `init_fn` and `handler_fn`
- The connection type `C` has no `Send` bound — this is the entire point
- `init_fn` runs on the worker thread and creates the connection
- An init barrier (`std::sync::mpsc` oneshot) propagates init errors synchronously back to
  the caller
- `handler_fn` processes commands sequentially on the worker thread
- Commands go in via `std::sync::mpsc` (the worker thread has no tokio context)
- Responses come back via `tokio::sync::mpsc::UnboundedSender` (sync send, async recv)

### 11.9 Inner Services

For plugins with many operations, decompose the service into inner services:

- **SchemaService** — database/table/column/index introspection
- **CrudService** — query execution, save changes, insert rows
- **DataLoaderService** — paginated data loading, row counts, primary keys
- **BrowserService** — DDL management (create/drop/rename tables)

Each inner service takes a pool/connection clone and implements domain-specific operations.
The background task delegates to them based on the command variant:

```rust
async fn background_task(mut cmd_rx: Receiver<MySqlCommand>, event_tx: Sender<MySqlEvent>, ...) {
    // Inner services created after Connect command succeeds
    let mut schema_svc: Option<SchemaService> = None;
    // ...

    while let Some(cmd) = cmd_rx.recv().await {
        match cmd {
            MySqlCommand::Schema(schema_cmd) => {
                if let Some(ref svc) = schema_svc {
                    Self::handle_schema(svc, schema_cmd, &event_tx, &tabs).await;
                }
            }
            MySqlCommand::Crud(crud_cmd) => { /* delegate to crud_svc */ }
            MySqlCommand::Load(load_cmd) => { /* delegate to loader_svc */ }
            // ...
        }
    }
}
```

This decomposition is optional — simpler plugins can handle all commands directly in the
background task without separate inner service structs.

---

## 12. Required Patterns

These patterns are mandatory. Ignoring them causes bugs or bad UX.

### Service Layer

All new protocol/data plugins must implement a service layer in a `service/` submodule. The
TUI plugin must not import database driver crates directly. Use `_` prefix for intentionally
unused fields instead of `#[allow(dead_code)]`.

### Async Data Loading

**Never block the render thread.** Database queries, network requests, and file I/O must
happen in the service layer's background task or via `SyncWorker`. The TUI plugin only sends
commands and polls events — both non-blocking.

```rust
// In event handler: send command (non-blocking)
self.service.send(MySqlCommand::Schema(SchemaCommand::ListDatabases));

// In update(): poll results (non-blocking)
while let Some(evt) = self.service.poll_event() {
    self.handle_service_event(evt)?;
}
```

### Capability Risk and Policy

Every invokable operation must expose conservative capability metadata before
it reaches CLI, TUI, or process-plugin invocation paths:

- `risk = read_only` only for operations that cannot change target-visible
  state.
- `risk = mutating` for creates or updates that are not destructive.
- `risk = destructive` for deletes, drops, overwrites, irreversible changes, or
  any operation that needs explicit confirmation.
- `risk = external_side_effect` for sending email, triggering jobs, executing
  commands, or changing infrastructure outside the local VoidB process.

Do not use confirmation dialogs as the permission model. UI confirmation,
`--yes`, and `InvocationAcknowledgement` only prove caller intent for one
invocation. Core policy still evaluates profile rules, scoped approvals,
dry-run support, and credential grants.

Capability authors are responsible for these invariants:

- Destructive compatibility flags cannot downgrade risk. If
  `destructive = true`, Core treats `risk = read_only` as destructive and
  process-plugin discovery reports a warning.
- Non-read-only capabilities must declare stable permission strings for policy
  and audit.
- Dry-run support must be real. When `dry_run = true`, service code must avoid
  target mutation and must describe any checks it could not perform safely.
- Policy reasons, audit metadata, warnings, and target errors must not include
  plaintext credentials, raw SQL, object contents, command output, or
  unredacted endpoint diagnostics.

Agent authorization metadata is declaration-only. Set
`CapabilityDefinition.authorization` after reviewing the operation:

```rust
authorization: CapabilityAuthorizationMetadata::declared()
    .with_interactive_execute()
    .with_session_purposes(vec![PluginSessionPurpose::InteractiveTerminal])
    .with_approval_schema(CapabilityApprovalSchema::v1(vec![
        CapabilityApprovalField::new(
            "/command",
            "Remote command",
            CapabilityApprovalValueType::String,
        )
        .required()
        .with_risk_emphasis(CapabilityApprovalRiskEmphasis::Destructive),
    ])),
```

- `declared=true` opts the definition into centrally generated recommended
  presets. Missing metadata fails closed to Custom-only.
- `interactive_execute=true` is only for the smallest real interactive or
  execute workflow. It must not mean every mutating capability.
- `session_purposes` describes semantic state; it does not create a live handle
  or bypass the plugin session factory.
- Use `note` for a coarse/deferred boundary. Keep mixed read/write operations
  such as raw command endpoints Custom-only until policy can distinguish them.
- `approval_schema` fields must point into the normalized invocation input and
  must describe enforcement that really occurs. Use `Exact` for identity or a
  command, `Prefix` for a path/key namespace, `Subset` for bounded lists, and
  `Maximum` for limits such as replica count. Mark fields required only when a
  constrained approval is meaningless without them.
- Never declare passwords, tokens, private keys, message/object bodies, or any
  other secret as a review field. `Secret`, unknown schema versions, duplicate
  paths, and malformed pointers fail closed.
- Capability-wide approval remains valid only when
  `capability_wide_allowed=true`. Exact-invocation approval fingerprints the
  complete normalized input even when only a subset is reusable as structured
  constraints.

Process plugins declare the same optional object in `plugin.toml` or use
`CapabilityBuilder::authorization(...)`. Older manifests deserialize as
undeclared and therefore cannot silently enter Read-only or
Interactive/Execute. Plugins never own grants, central policy decisions,
broker recovery, or authorization UI.

Run `cargo test -p voidb-cli bundled_plugin_approval_fields_are_real_normalized_input_paths`
for bundled changes. Process-plugin conformance must prove the same input-path
and schema-version rules before enabling constrained or exact JIT requests.

See [Plugin Conformance And Certification](plugin-conformance.md) for the
static checks and maturity criteria used to promote plugins.

### External-Agent Interaction

Choose the smallest external-agent surface justified by plugin-local state:

- Prefer ordinary capability discovery and invocation. Data, search, storage,
  and messaging plugins must remain capability-only and must not add a TUI
  session-share shortcut or frontend.
- A bounded current-view context share is permitted only when a retained TUI
  owns material state that an external agent cannot cheaply rediscover. Docker,
  Kubernetes, and Jenkins are the current examples.
- Live PTY view and input sharing is SSH-specific. Do not generalize current-PTY
  permission, writers, or takeover state to other plugins.

The TUI must not collect an agent prompt or render a conversation transcript.
A share uses a short label, bounded redacted context, generation binding,
expiry, and a plugin-owned store. Structured operation requests remain inert
until the plugin validates them and stages them into its existing plan or
capability gate. Denial must be recordable without staging. Readonly,
dry-run, destructive acknowledgement, authorization, confirmation, redaction,
and audit checks are never inherited from a share envelope.
Treat each operation request ID and action index as a one-shot decision. The
owning store must serialize decisions and reject approval or denial replays.

External handoff uses protocol-v1 `voidb-cli context
list/show/operation/deny/status/wait`. A plugin that opts into this surface must
expose a deterministic store-root resolver, write records as private regular
files below a private non-symlink directory, and retain the Core v1 record
shape. Every read or write is principal-aware and requires the exact
`(plugin_id, context_id, generation)` tuple. The first operation atomically
binds an unbound record, cooperating processes serialize through the per-record
lock, exact retries are idempotent, and changed replays fail closed. Non-PTY v1
requests contain exactly one operation so a TUI cannot approve only the first
member of a larger request. Status/wait project indexed decisions without
blocking the owning TUI. Retained non-PTY TUIs publish new records with
`share_with_owner_lease` and keep the returned lease alive until shutdown. The
lease is an OS file lock, not a PID or live handle in protocol output; an
unlocked or missing required lease makes a non-terminal context stale after a
hard owner crash. See the contract for stable errors and exit codes.

Live handles stay inside the plugin service. `ShellCapabilities` and
`ConnectionConfigRegistry` must not become a runtime pool or operation broker.
For the complete plugin matrix and compatibility rules, see
[External-Agent Interaction Contract](assist-handoff.md).

### Avoid Reserved Keys

For non-raw plugins (the default), soft global shortcuts (`q`, `Q`, `Ctrl+L`) are consumed
by the shell before reaching your plugin. Do not use these as keybindings — they will
silently do nothing. Use `Esc` to go back, `d` to delete, etc.

Hard global shortcuts (`Ctrl+Q`, `Ctrl+\`) are **always** consumed by the shell, even for
raw-mode plugins. Never rely on these keys in any plugin.

If your plugin needs full keyboard control, implement `wants_raw_input()` to return `true`
— this bypasses the soft globals and lets your plugin receive `q`, `Q`, `Ctrl+L`, etc.

### Runtime Cleanup (`Drop` implementation)

If your plugin owns a `tokio::Runtime`, you must drop it in a separate thread to avoid
panicking inside an async context:

```rust
pub struct MyPlugin {
    rt: Option<Arc<tokio::runtime::Runtime>>,
    // ...
}

impl Drop for MyPlugin {
    fn drop(&mut self) {
        if let Some(rt) = self.rt.take() {
            std::thread::spawn(move || drop(rt));
        }
    }
}
```

---

## 13. Recommended Patterns

These patterns are not enforced but are strongly recommended for a consistent user experience.

### Status Bar

Reserve the last row of `area` for a hint/status line. Every existing plugin does this.

```rust
fn render(&self, frame: &mut Frame, area: Rect) {
    let chunks = Layout::vertical([
        Constraint::Min(0),      // main content
        Constraint::Length(1),   // status bar
    ]).split(area);

    self.render_main(frame, chunks[0]);
    self.render_status_bar(frame, chunks[1]);
}

fn render_status_bar(&self, frame: &mut Frame, area: Rect) {
    let hints = match self.mode {
        Mode::Browse => "j/k: move  Enter: open  /: search  ?: help  q: back",
        Mode::Search => "Type to search  Enter: confirm  Esc: cancel",
        Mode::Edit   => "Enter: save  Esc: cancel",
    };
    let bar = Paragraph::new(hints)
        .style(Style::default().fg(Color::DarkGray));
    frame.render_widget(bar, area);
}
```

### Mode State Machine

Almost every non-trivial plugin needs multiple interaction modes. Use an enum and dispatch:

```rust
#[derive(Default)]
enum Mode { #[default] Browse, Edit, Search, Confirm, Help }

fn update(&mut self, frame: &mut Frame, area: Rect, event: Option<Event>) -> Result<()> {
    if let Some(event) = event {
        match self.mode {
            Mode::Browse  => self.handle_browse(event)?,
            Mode::Edit    => self.handle_edit(event)?,
            Mode::Search  => self.handle_search(event)?,
            Mode::Confirm => self.handle_confirm(event)?,
            Mode::Help    => self.handle_help(event)?,
        }
    }
    match self.mode {
        Mode::Browse  => self.render_browse(frame, area),
        Mode::Edit    => self.render_edit(frame, area),
        // for overlays: render background first, then popup on top
        Mode::Confirm => { self.render_browse(frame, area); self.render_confirm(frame, area); }
        Mode::Help    => { self.render_browse(frame, area); self.render_help_popup(frame, area); }
        _ => Ok(()),
    }
}
```

### Empty State / Onboarding

When there is no data to show (first launch, no connections, empty table), render a helpful
message instead of a blank screen.

### Loading Indicator

While async data is in-flight, show a loading message.

### Status Messages with Auto-Clear

Use a timed status message at the bottom for feedback on actions.

### Confirmation Dialogs for Destructive Operations

Before deleting rows, dropping tables, or any irreversible action, show a confirmation.

### Modal Popups

For help screens, link pickers, file browsers, etc., overlay a popup on the current render.
Always handle the popup's events **before** normal event handling.

---

## 14. Constraints and Rules

| Rule | Reason |
|------|--------|
| **Plugin crates go in `crates/plugins/`**, never in `voidb-core` | Core must remain business-logic free |
| **Do not modify `app_v4.rs` for plugin-specific features** | Shell must stay as a pure router |
| **Do not add fields to `ShellCapabilities`** without core team discussion | Breaks plugin API stability |
| **Do not write to `ConnectionConfigRegistry`** from non-ConnectionManager plugins | Single source of truth |
| **Do not block the render thread** (no synchronous DB queries, no `thread::sleep`) | Freezes entire UI |
| **Duplicate `plugin_id` panics at startup** | Intentional — catch config errors early |
| **Plugin ID in `PluginFactory` must match `Plugin::id()`** | Routing breaks otherwise |
| **Service layer is mandatory** for all new plugins | Enables TUI/CLI/MCP interface parity |
| **TUI plugins must not import database driver crates** | Service layer owns all driver dependencies |
| **Capability risk metadata must be conservative** | Core policy and audit rely on declared risk and permissions |

---

## 15. Minimal Plugin Skeleton

A complete, working plugin that shows a list and opens a detail tab:

```rust
// crates/plugins/voidb-plugin-example/src/lib.rs

use anyhow::Result;
use crossterm::event::KeyCode;
use ratatui::{
    layout::{Constraint, Layout},
    style::{Color, Style},
    text::Line,
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame,
};
use ratatui::layout::Rect;
use serde_json::json;
use voidb_core::{Event, Plugin, PluginFactory, ShellCapabilities, ConnectionConfig};

// ── Factory ──────────────────────────────────────────────────────────────────

pub struct ExamplePluginFactory;

impl PluginFactory for ExamplePluginFactory {
    fn create(&self, context: serde_json::Value) -> Result<Box<dyn Plugin>> {
        let connection_id = context["connection_id"]
            .as_str()
            .unwrap_or("unknown")
            .to_string();
        Ok(Box::new(ExamplePlugin::new(connection_id)))
    }

    fn plugin_id(&self) -> &str { "example" }
    fn plugin_name(&self) -> &str { "Example" }
    fn description(&self) -> &str { "Example plugin for VoidB" }
}

// ── Plugin ────────────────────────────────────────────────────────────────────

struct ExamplePlugin {
    caps: Option<ShellCapabilities>,
    connection_id: String,
    items: Vec<String>,
    selected: usize,
    status: Option<String>,
}

impl ExamplePlugin {
    fn new(connection_id: String) -> Self {
        Self {
            caps: None,
            connection_id,
            items: vec![],
            selected: 0,
            status: None,
        }
    }
}

impl Plugin for ExamplePlugin {
    fn id(&self) -> &str { "example" }
    fn name(&self) -> &str { "Example" }

    fn init(&mut self, caps: ShellCapabilities) -> Result<()> {
        self.caps = Some(caps.clone());

        // Read config from registry
        let registry = caps.connections.blocking_read();
        if let Some(_config) = registry.get(&self.connection_id) {
            // In a real plugin: create service layer here
        }

        // Simulate loaded items (in real plugin: load via service)
        self.items = vec!["Item A".into(), "Item B".into(), "Item C".into()];
        caps.tabs.set_title(format!("Example - {}", self.connection_id))?;
        Ok(())
    }

    fn update(&mut self, frame: &mut Frame, area: Rect, event: Option<Event>) -> Result<()> {
        // Handle event
        if let Some(Event::Key(key)) = event {
            if key.modifiers.is_empty() {
                match key.code {
                    KeyCode::Char('j') | KeyCode::Down => {
                        if self.selected + 1 < self.items.len() {
                            self.selected += 1;
                        }
                    }
                    KeyCode::Char('k') | KeyCode::Up => {
                        self.selected = self.selected.saturating_sub(1);
                    }
                    KeyCode::Enter => {
                        if let Some(item) = self.items.get(self.selected) {
                            if let Some(caps) = &self.caps {
                                caps.tabs.open(
                                    format!("Detail: {}", item),
                                    "example-detail".to_string(),
                                    json!({ "connection_id": self.connection_id, "item": item }),
                                )?;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        // Layout: main content + status bar
        let chunks = Layout::vertical([
            Constraint::Min(0),
            Constraint::Length(1),
        ]).split(area);

        // Render list
        let items: Vec<ListItem> = self.items
            .iter()
            .enumerate()
            .map(|(i, item)| {
                let style = if i == self.selected {
                    Style::default().fg(Color::Yellow)
                } else {
                    Style::default()
                };
                ListItem::new(item.as_str()).style(style)
            })
            .collect();

        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title("Items"));
        frame.render_widget(list, chunks[0]);

        // Status bar
        let hint = self.status.as_deref()
            .unwrap_or("j/k: move  Enter: open  q: back");
        let bar = Paragraph::new(hint)
            .style(Style::default().fg(Color::DarkGray));
        frame.render_widget(bar, chunks[1]);

        Ok(())
    }
}
```

Register in `app_v4.rs`:
```rust
plugin_registry.register(Box::new(voidb_plugin_example::ExamplePluginFactory));
```

---

## 16. Pre-ship Checklist

Before merging a new plugin, verify:

**Correctness**
- [ ] `Plugin::id()` matches `PluginFactory::plugin_id()`
- [ ] `plugin_id` is unique (not already used by another plugin)
- [ ] Plugin respects reserved keys: hard globals (`Ctrl+Q`, `Ctrl+\`) are never available; soft globals (`q`, `Q`, `Ctrl+L`) are unavailable unless `wants_raw_input()` returns `true`
- [ ] No blocking operations in `update()` or `render()`
- [ ] `init()` stores caps: `self.caps = Some(caps)`
- [ ] Capabilities declare conservative `risk`, `destructive`, `supports_dry_run`, permissions, and required secret classes
- [ ] Dry-run paths never mutate target state and report limitations clearly

**Service Layer (protocol/data plugins)**
- [ ] `service/` submodule exists with mod.rs, commands.rs, events.rs
- [ ] Service struct has both `new()` (TUI) and `new_direct()` (CLI) constructors
- [ ] TUI plugin contains zero direct driver imports (e.g., no `mysql_async` in table_plugin.rs)
- [ ] CLI plugin uses direct async methods, not channels
- [ ] Command enum covers all data operations the plugin performs
- [ ] Event enum includes an Error variant for operation failures

**Stability**
- [ ] Async tasks send results via channel; `update()` polls non-blocking
- [ ] `Drop` implemented if plugin owns a `tokio::Runtime`
- [ ] Plugin handles empty/no-data state without panicking
- [ ] Plugin handles terminal resize gracefully

**UX**
- [ ] Status bar shows relevant hints for current mode
- [ ] Loading state is communicated (spinner, "Loading...", or similar)
- [ ] Errors are shown to the user (not just `eprintln!`)
- [ ] Destructive operations have a confirmation step
- [ ] Tab title is updated to reflect the current view
- [ ] External-agent access follows the documented plugin matrix
- [ ] Capability-only plugins expose no TUI or live-session share
- [ ] Any approved context share is bounded, redacted, plugin-owned, and routes operations through existing local gates
- [ ] Operation decisions are one-shot and the owning store rejects replay
- [ ] Non-PTY operation requests contain exactly one operation; partial or reordered multi-action review fails closed
- [ ] Context polling never sleeps in the TUI event loop and clears expired, stale, terminal, or externally decided work

**Integration**
- [ ] `PluginFactory::create_connection_dialog()` returns a working dialog
- [ ] `ConnectionConfig` uses `db_type: DatabaseType::Plugin` and sets `plugin_id`
- [ ] Crate added to workspace `Cargo.toml` members
- [ ] Crate added as dependency to `voidb-tui/Cargo.toml`
- [ ] Factory registered in `app_v4.rs`
- [ ] **Connection type added to `conn_types()` in `connection_manager.rs`** (without this, users cannot create new connections from UI!)
- [ ] `cargo build` passes, `cargo clippy` passes

---

*Last updated: 2026-07-13*
