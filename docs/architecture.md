# Architecture

## High-Level Pattern

- Shell has zero knowledge of plugin internals
- Plugins receive full screen area (minus 1-line tab bar) and render autonomously
- Communication is channel-based and non-blocking (mpsc for tab operations, render requests)
- Dependency injection via `ShellCapabilities` provides plugins with shared services
- Two-layer global shortcut system prevents key conflicts between shell and plugins

## Component Diagram

```
+-------------------------------------------------------------------------------+
|                            VoidB Architecture v4.0                            |
+-------------------------------------------------------------------------------+
|                                                                               |
|   [Human Interaction]                                 [Machine Communication] |
|                                                                               |
|   +-----------------------+   +-------------------+   +-------------------+   |
|   |   voidb (Main TUI)    |   | voidb-cli <cmd>   |   | AI Agents / Core  |   |
|   |  Connection & Profile |   | Unified Command   |   | Capability Broker |   |
|   |       Manager         |   |    Dispatcher     |   |                   |   |
|   +-----------------------+   +-------------------+   +-------------------+   |
|               |                         |                       |             |
|               | saves metadata          | transparent dispatch  | JSON-RPC    |
|               v                         v                       v             |
|     ~/.config/voidb/config.toml   +---------------------------------------+   |
|     (AES-256-GCM encrypted)       |    Plugins (Builtin & External)       |   |
|                                   |  - test  : Connectivity check         |   |
|                                   |  - tui   : Fullscreen interactive TUI |   |
|                                   |  - serve : stdio-jsonrpc protocol     |   |
|                                   |  - <cmd> : Domain-specific operations |   |
|                                   +---------------------------------------+   |
+-------------------------------------------------------------------------------+
```

## Layers & Division of Responsibility

### 1. VoidB Shell (`crates/voidb-tui/src/app_v4.rs`)
- Pure connection information & profile management UI.
- Never embeds, hosts, or summons heavyweight external child processes.
- Contains only the `ConnectionManagerPluginFactory`.

### 2. Unified Command Dispatcher (`voidb-cli`)
- Serves as the first-class dispatch desk.
- First-class equality for built-in and external process plugins.
- Dynamically discovers external plugins installed under `~/Library/Application Support/voidb/plugins/<plugin>/bin/`.
- Transparently routes arguments, subcommands, flags, and help requests to plugin binaries.

### 3. Plugins (Built-in & External)
- Fully autonomous domain operators.
- Support the tri-modal operational contract:
  - `test`: Automated connectivity verification.
  - `tui`: Standalone full-screen interactive terminal interface (invoked via `voidb-cli <plugin> tui --profile <profile>`).
  - `serve`: `stdio-jsonrpc` protocol server for AI Agents and automated orchestration.
  - Domain commands: Full autonomous command surface (e.g., `k8s pods`, `docker ps`, `s3 buckets`).

## Data Flow

- **Shell state**: Minimal — `Vec<Tab>`, `active_tab: usize`, `should_quit: bool`, `tab_manager_popup: Option`
- **Plugin state**: Each plugin owns all its state (data, UI mode, cursor position, async receivers, etc.)
- **Shared state**: `ConnectionConfigRegistry` (read/write via `Arc<RwLock<>>`), `VoidbClipboard` (`Arc<RwLock<>>`)
- **Persistence**: `AppConfig` saved to `~/.config/voidb/config.toml` with AES-256-GCM encryption for credentials

## External-Agent Interaction

Conversation stays in the external agent; VoidB provides target access and
local policy gates, not an embedded chat client. The interaction surface is
plugin-specific:

- SSH may explicitly share a bounded, redacted live PTY view and review
  structured PTY or capability operation requests. The SSH service retains the
  live handle and enforces generation, single-writer, TTL, readonly, prompt,
  output-bound, one-shot approval, replay rejection, and immediate-revoke
  checks. Alternate-screen and application-key states remain visible warnings
  that the local operator may accept after inspecting the current terminal.
- Docker, Kubernetes, and Jenkins may explicitly share bounded current-view
  context when it cannot be cheaply rediscovered. A structured operation
  request is staged into the plugin's existing plan and human confirmation
  path; it never executes directly from the share store.
- Data, search, storage, and messaging plugins expose capabilities only. Their
  human TUIs do not publish session state. Plugin-owned persistent agent
  sessions may retain database state, but never attach to a human TUI session.
- The shell never owns shares, plugin sessions, target clients, or operation
  dispatch. Core owns only transport-neutral binding, redaction, expiry,
  identity, confirmation, denial, and audit value types.

The normative matrix and compatibility boundary are in
[External-Agent Interaction Contract](assist-handoff.md).

## Key Abstractions

### `Plugin` trait (`crates/voidb-core/src/plugin/plugin_trait.rs`)
- Core abstraction for autonomous applications within VoidB
- Methods: `id()`, `name()`, `init(caps)`, `update(frame, area, event)`, `wants_raw_input()`
- Pattern: Trait object (`Box<dyn Plugin>`) stored in `Tab` struct

### `PluginFactory` (`crates/voidb-core/src/plugin/registry.rs`)
- Factory for creating Plugin instances from JSON context
- Methods: `create(context) -> Box<dyn Plugin>`, `plugin_id()`, `plugin_name()`, `create_connection_dialog()`
- Pattern: Registry pattern — factories stored in `HashMap<String, Box<dyn PluginFactory>>`

### `DatabaseAdapter` (`crates/voidb-core/src/database/mod.rs`)
- Async database operations abstraction (schema introspection, queries, DDL)
- Methods: `connect()`, `list_databases()`, `describe_table()`, `query_rows()`, `execute()`, etc.
- Pattern: Async trait via `#[async_trait]`, implemented by each DB plugin's adapter

### `ShellCapabilities` (`crates/voidb-core/src/shell_capabilities.rs`)
- Dependency injection container passed to plugins at init
- Fields: `connections`, `tabs`, `clipboard`, `plugin_registry`
- Pattern: Clone-friendly struct with Arc-wrapped fields

### `TabManager` trait (`crates/voidb-core/src/shell_capabilities.rs`)
- Interface for plugins to manage tabs without direct shell access
- Methods: `open()`, `close_current()`, `set_title()`, `request_render()`, `list_tabs()`, `switch_to()`, `quit()`
- Pattern: Trait object (`Arc<dyn TabManager>`), implemented by `AppTabManager` in shell

### `NativePlugin` trait (`crates/voidb-core/src/plugin/native.rs`)
- Legacy interface for registering database protocol handlers
- Methods: `plugin_id()`, `protocols()`, `default_port()`, `create_adapter()`

### `ConnectionDialogComponent` (`crates/voidb-core/src/plugin/connection_dialog.rs`)
- Plugin-provided custom connection configuration dialog
- Methods: `render()`, `handle_event() -> DialogAction`, `build_config()`

### `Event` enum (`crates/voidb-core/src/event.rs`)
- Unified event type passed from shell to plugins
- Variants: `Key(KeyEvent)`, `Mouse(MouseEvent)`, `Paste(String)`, `Tick`, `FocusGained`, `FocusLost`, `Resize { width, height }`

## Entry Points

| Entry | Location | Trigger |
|---|---|---|
| TUI app | `crates/voidb-tui/src/main.rs` | User runs `voidb` |
| CLI | `crates/voidb-cli/src/main.rs` | User runs `voidb-cli <plugin> <command>` |
| Plugin registration | `crates/voidb-tui/src/app_v4.rs` lines 151-193 | `App::new()` during startup |

## Error Handling

- `VoidbError` (thiserror): Typed error enum in `crates/voidb-core/src/error.rs`
  - Variants: `Connection`, `Query`, `Schema`, `Config`, `Plugin`, `Crypto`, `InvalidConfig`, `IncompatiblePlugin`, `Runtime`, `Timeout`, `Io`, `Other`
- `anyhow::Result`: Used at application boundaries (main, plugin update methods)
- Plugin `update()` returns `Result<()>` (anyhow) — shell logs errors via `eprintln!` but does not crash
- Shell catches render errors per-frame: `if let Err(e) = self.render_frame(frame, event) { eprintln!(...) }`

## Event System

- `Key(KeyEvent)`: Keyboard input with code, modifiers, kind (Press/Release/Repeat)
- `Mouse(MouseEvent)`: Click, drag, scroll with position
- `Paste(String)`: Bracketed paste (full text as single event)
- `Tick`: Plugin-requested render (via `request_render()` channel)
- `Resize { width, height }`: Terminal resize notification
- `FocusGained` / `FocusLost`: Tab focus changes (defined but not actively dispatched)

## Plugin Registry

The shell registry currently contains only the built-in Connection Manager:

| Plugin ID | Factory | Crate | Type |
|---|---|---|---|
| `connection-manager` | `ConnectionManagerPluginFactory` | `voidb-tui` | Home screen |

Protocol plugins are registered with `voidb-cli` for commands and capability
invocation. Retained interactive plugins such as Docker, Kubernetes, Jenkins,
and SSH own standalone terminal apps launched with
`voidb-cli <plugin> tui --profile <profile>`; they are intentionally not
registered as embedded shell tabs. Connection Manager presents profile,
capability, and standalone-TUI launch guidance without owning a plugin runtime.

## Cross-Cutting Concerns

### Logging
- Framework: `tracing` + `tracing-subscriber` with env-filter
- Output: File-based (`~/.local/share/voidb/logs/voidb.log`), never to terminal
- Level: Default `info`, configurable via `RUST_LOG` env var

### Security
- Connection credentials stored in `plugin_config` JSON field of `ConnectionConfig`
- Encrypted at rest using AES-256-GCM via `crates/voidb-core/src/crypto.rs`
- Key derivation: Argon2 from optional master password. Current TUI saves without prompting for a master password, so config encryption falls back to a compiled default passphrase; see [Security Notes](security.md).
- Config file: `~/.config/voidb/config.toml` with encrypted `plugin_config` blobs

### Clipboard
- System clipboard: `arboard` crate via `crates/voidb-core/src/clipboard.rs`
- Internal clipboard: `VoidbClipboard` in `ShellCapabilities` for cross-plugin row copy/paste
- Format: TSV for external paste + JSON magic line for VoidB-to-VoidB structured paste

### Input Validation
- Connection configs: Plugin-specific validation in `ConnectionDialogComponent::build_config()`
- JSON schema: `jsonschema` crate available in voidb-core (for plugin_config validation)
- No centralized validation layer — each plugin validates its own inputs
