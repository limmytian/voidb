# Changelog

All notable changes to VoidB will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.2] - 2026-10-08

### Added

- **100% Decoupled Process Plugin Architecture**: Completely externalized 6 database and protocol drivers (`mysql`, `postgres`, `sqlite`, `redis`, `ssh`, `duckdb`) into independent repositories, removing all heavy driver crates (`libduckdb-sys`, `tokio-postgres`, `mysql_async`, `rusqlite`, `redis`, `russh`) from the core voidb workspace.
- **Unified Command Dispatcher & Complete Plugin Equality**: `voidb-cli` now dynamically discovers all 14 official plugins and transparently routes subcommands, arguments, options, and help messages.
- **Standard Tri-Modal Contract for All 14 Plugins**: Every official plugin provides `test` (fast connectivity check), `tui` (standalone interactive full-screen terminal), and `serve` (headless stdio-jsonrpc for AI coding agents) alongside domain commands.
- **Bundled Default Plugins & One-Click Init**: Built-in discovery checks sibling and installation prefix paths (`<exe_dir>/plugins`, `<prefix>/share/voidb/plugins`). Added `voidb-cli plugin install-default` for one-command initialization of core database plugins.
- **Release Packaging & Distribution**: Updated GitHub release workflow and Homebrew formula to build and package both `voidb` and `voidb-cli` binaries together.

### Changed

- Updated all architectural documentation and AGENTS.md guide to reflect the decoupled v4.1 architecture.
- Cleaned up obsolete in-tree migration documentation.

## [0.3.0] - 2026-10-08

### Added

- Visual Plugin Manager & Online Marketplace in TUI shell (`p` shortcut) with dual-tab (Installed vs Marketplace) navigation, category filtering, search, and async install/update/uninstall operations.
- Hosted Official Plugin Registry on GitHub (`registry/index.json`) and automated CI dispatch workflow (`update-registry.yml`) linking standalone plugin releases.
- Online `voidb plugin install <name>` with remote GitHub release download, SHA256 checksum verification, and Ed25519 signature validation.
- Gzip decompression (`.tar.gz` / `.tgz`) support across plugin archive installation and extraction engine.
- Complete standalone packaging and GitHub Releases for all 8 external plugins: `s3`, `email`, `docker`, `kubernetes`, `elasticsearch`, `mongodb`, `jenkins`, `webdav`.
- Central Connection Manager authorization workflow with Read-only,
  Interactive/Execute, and Custom presets; reviewed TTL/use limits; explicit
  destructive consent; inspect, renew, replace, scoped revoke, and revoke-all.
- Frontend-safe per-profile grant state covering expiry/use exhaustion, broker
  health, exact capability scope, and active persistent session counts.
- Shared authorization metadata and centrally generated exact presets for all
  bundled capability plugins and process-plugin manifests/SDK.

### Security

- Agent grants now reject empty/wildcard or preset-mismatched scopes, preserve
  immutable Profile ID/plugin binding, recover stale brokers without persisted
  credentials, and keep broker tokens/sockets/passwords out of frontend state.
- Interactive SSH authorization requires explicit grant consent and per-call
  destructive acknowledgement. Disposable OpenSSH acceptance verified separate
  persistent `cd` and `ls` calls, SFTP/forwarding lifecycle, and secret scans.
- Plugin packaging and registry verification gates supply-chain security via SHA-256 and Ed25519 signatures.

### Fixed

- TUI quality evidence now runs under an isolated HOME/config and accepts both
  configured and empty-profile first frames without reading user credentials.

## [0.3.0-rc.1] - 2026-07-05

### Changed

- **BREAKING**: Removed `intercepts_event()` from Plugin trait — global shortcuts are now unconditional and cannot be overridden by plugins
- Global shortcuts (`q`, `Q`, `Ctrl+Q`, `Ctrl+L`) are always handled by the shell before events reach plugins

### Added

- `Q` (Shift+Q) global shortcut to close the current tab

### Documentation

- Published release-candidate baseline, release blocker inventory, all-plugin
  RC readiness matrix/report, package smoke, and final tag-readiness workflow
  records for the 2026-07-05 release-candidate cut.
- Recorded plugin release dispositions, skipped live fixture smoke, residual
  risks, package artifact expectations, and release-note waiver requirements.
- Recorded the 2026-07-04 release stabilization rehearsal, including refreshed
  automated gates, package artifact smoke, skipped live-fixture smoke, and a
  no-go tagging decision until required real-terminal TUI smoke and
  version/tag consistency are resolved.

## [0.2.0] - 2026-03-19

### Changed

- **BREAKING**: Complete architecture redesign to v4.0 Pure Router Architecture
- Plugins are now fully autonomous applications with full screen control
- Replaced Component trait with Plugin trait
- Removed Message enum in favor of ShellCapabilities (dependency injection)
- Simplified VoidB toward a pure-router shell architecture
- Channel-based communication for non-blocking tab operations
- Global shortcuts simplified (Ctrl+Q for quit, plugins handle their own keys)

### Added

- **ShellCapabilities** - Dependency injection for plugins
  - `tabs` - Tab operations (open, close, set_title)
  - `connections` - Shared connection registry
- **PluginRegistry** - Factory-based plugin registration system
- **Plugin trait** - Clean lifecycle (init, update)
- **MySQL Plugin** - Fully autonomous table viewer/editor
  - Tree navigation, data grid, SQL editor
  - Vim-style keybindings
  - Multiple editing modes
- **PostgreSQL Plugin** - Full PostgreSQL support
- **SQLite Plugin** - File-based database management
- **Email Plugin** - IMAP/POP3 email client
  - Mailbox browsing, email reading
  - HTML email rendering to text
  - Attachment handling
- **SQL Features**
  - Syntax highlighting (`sql_highlight.rs`)
  - Autocomplete (`autocomplete.rs`)
  - Statement parsing (`sql_split.rs`)
- **Security**
  - AES-256-GCM credential encryption (`crypto.rs`)
- **Import/Export**
  - CSV, JSON, SQL export (`export.rs`)
  - CSV import (`import.rs`)
- **UI Widgets** (in voidb-core/widgets/)
  - Reusable tree, grid, editor components
  - Shared across plugins
- Documentation: `docs/plugin-development-guide.md` with v4.0 guide

### Removed

- **BREAKING**: Component trait and component-based architecture
- **BREAKING**: Action enum (100+ variants)
- **BREAKING**: Message enum (7 variants, replaced by ShellCapabilities)
- **BREAKING**: InputMode enum (moved to plugins)
- **BREAKING**: Old shell-level UI components:
  - DataGrid component
  - QueryEditor component
  - Structure Designer component
  - Dialog components
  - Command Palette
  - Status Bar (minimal version in shell)
  - Tab Bar (replaced with simple top bar)
  - Context Menu
  - Help Overlay
  - Welcome Screen
- **BREAKING**: Centralized state management (TabManager, UndoStack)
  - Plugins now manage their own state
- **BREAKING**: Legacy event/mode/keymap/focus systems
- **Total**: ~16,000 lines of legacy component-based architecture removed

### Fixed

- Event routing now correctly routed to active plugin
- Tab operations are non-blocking via channels
- Clipboard integration works across all platforms
- Email HTML rendering properly converts to text for TUI display

### Migration

**For Plugin Developers**:

Old plugins using the Component trait must be migrated to the new Plugin trait. See [docs/plugin-development-guide.md](docs/plugin-development-guide.md) for complete v4.0 migration guide.

**Key Changes**:
- Replace `Component` trait with `Plugin` trait
- Store `ShellCapabilities` from `init()` instead of returning `Message`s
- Use `caps.tabs.open/close()` for tab operations
- Implement full-screen rendering in `update(frame, area, event)`
- Handle events directly instead of returning `Action`s

---

## [0.1.0] - 2026-03-18

### Added

- Initial release
- Core foundation (event loop, vim modes, components)
- Database adapters (MySQL, PostgreSQL, SQLite)
- Object tree browser
- Data grid with pagination and editing
- SQL query editor with syntax highlighting
- Table structure designer
- Import/Export (CSV, JSON, SQL)
- Connection management with encryption

---

**Legend**:
- **BREAKING**: Breaking change requiring migration
