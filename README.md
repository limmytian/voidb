<div align="center">

# VoidB

### Keyboard-First TUI + Safe Gateway for AI Agents

[![CI](https://github.com/limmytian/voidb/actions/workflows/ci.yml/badge.svg)](https://github.com/limmytian/voidb/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-edition%202024-orange.svg)](https://www.rust-lang.org/)

A modern, capability-first database & infrastructure management platform designed for developers and autonomous AI coding agents alike.
Replicating Navicat-class multi-protocol power in your terminal with Vim-style navigation, encrypted credential vaults, and fine-grained JIT agent authorization.

</div>

---

## ⚡ Why VoidB?

- ⌨️ **Keyboard-First Terminal Experience** — Native Ratatui TUI with full Vim keybindings, fuzzy profile search, schema-driven connection forms, and instant interactive diagnostics.
- 🤖 **Secure Gateway for AI Agents** — Purpose-built CLI & broker architecture that lets AI agents (Cursor, Claude Code, Goose, Antigravity) query databases, inspect containers, and manage infrastructure without handing over raw passwords or permanent privileges.
- 🛡️ **Defensive Security & JIT Authorization** — Master passwords and credentials stored in AES-256-GCM encrypted vaults; agents request 15-minute time-bounded, read-only or explicit JIT authorization with mandatory human review for destructive calls.
- 🔌 **Unified Multi-Protocol Ecosystem** — One tool across relational databases (MySQL, PostgreSQL, SQLite, DuckDB), in-memory stores (Redis), document/search engines (MongoDB, Elasticsearch), DevOps infrastructure (SSH, Docker, Kubernetes), and external process plugins (S3, WebDAV, Email, Jenkins).
- 🚀 **Modular & Blazing Fast** — Zero-cost abstraction plugin architecture with tiered feature compilation (`mysql`, `postgres`, `sqlite`, `redis`, `ssh` by default) so you don't wait for heavy C++ or Kubernetes drivers unless you want them.

---

## Current Architecture

VoidB uses a capability-first core with independent terminal frontends:

- **Connection Manager**: the default standalone application. It owns its event
  loop and native profile state and does not implement the router `Plugin` trait.
- **VoidB Shell**: an optional compatibility/development surface launched with
  `voidb --shell`; it is not the default profile workflow.
- **Plugin crates**: own protocol, service, CLI, and capability code. They no longer ship legacy router-hosted UI factories.

See [Plugin Development Guide](docs/plugin-development-guide.md) for plugin
architecture and service-layer patterns, and
[Plugin-Owned TUI Development Guide](docs/plugin-owned-tui-development-guide.md)
for the requirements any future plugin-owned terminal app must meet.

---

## 🎬 Quick Start

### Installation

```bash
# Install via cargo
cargo install voidb

# Or build from source
git clone https://github.com/limmytian/voidb.git
cd voidb
cargo build --release
sudo cp target/release/voidb /usr/local/bin/
```

### First Run

```bash
# Launch VoidB
voidb

# Equivalent explicit Connection Manager entrypoints
voidb --connection-manager
voidb-cli connections tui

# Optional shell compatibility/development surface
voidb --shell

# In VoidB:
# 1. Use the Connection Manager to create or edit profiles
# 2. Press Enter on a profile for CLI/capability guidance
# 3. Use voidb-cli or voidb invoke for plugin operations
```

When creating a profile, enter `Connection type`, `Name`, then optional
`Display name`. The name is the stable CLI reference and must be unique within
its connection type (case-insensitive). Display names may be repeated. Each
profile also receives a globally unique, immutable Profile ID.

For agent access, select a profile in the Connection Manager, press `a`, and
confirm the recommended 15-minute read-only access. Agents can then use the
short facade command without handling grant IDs, plugin IDs, or immutable
Profile IDs:

```bash
voidb-cli agent exec jenkins.jobs --profile prod-jenkins --input-json '{}'
```

If no current grant permits an operation, an identified interactive agent
creates one exact JIT request and waits briefly for review in the Connection
Manager (`p`). Destructive calls still require specific approval and `--yes`.
Use `agent list` and `agent revoke --all` to inspect or immediately block
access. The lower-level `agent authorize`, `agent run`, and `agent request`
commands remain available for automation and advanced policy control.

### Keybindings Cheatsheet

| Key | Action |
|-----|--------|
| `j` / `k`, arrows | Select profile |
| `n` / `e` / `d` | Create, edit, or delete a native profile |
| `Tab` / `Shift+Tab` | Navigate interactive profile fields |
| `Left` / `Right` | Change authentication, transport, enum, or boolean values |
| `Ctrl+U` | Clear the active editor field |
| `F2` | Toggle interactive form and advanced JSON |
| `Ctrl+S` | Validate and save a profile |
| `t` | Test selected profile |
| `c` | Browse plugin capabilities |
| `a` | Review quick read-only agent access; press `a` again for advanced controls |
| `p` | Review pending operation-specific agent requests |
| `/` | Search profiles |
| `m` | Unlock or protect credentials |
| `?` | Show help |
| `Ctrl+Q` | Quit |

Press `?` in the app for the current keybinding reference.

---

## 📚 Documentation

- **Plugin Developers**
  - [Plugin Development Guide](docs/plugin-development-guide.md) ⭐ Start here for v4.0 architecture
  - [Plugin-Owned TUI Development Guide](docs/plugin-owned-tui-development-guide.md) - Standalone TUI command, terminal lifecycle, tests, and release gates
  - Example plugins in `crates/plugins/` directory

- **Core Contributors**
  - [CHANGELOG.md](CHANGELOG.md) - Version history and breaking changes
  - [Readiness Documentation Map](docs/readiness.md) - Canonical current architecture, Agent, TUI, security, and release sources
  - [Agent Capability and Experience Matrix](docs/agent-capability-matrix.md) - Generated capability, session, TUI, handoff, and validation inventory
  - [Agent Operator, Migration, and Troubleshooting Guide](docs/agent-operator-guide.md) - Copyable upgrade, authorization, session, cleanup, troubleshooting, and rollback workflows
  - [Agent and TUI Aggregate Release Gate](docs/agent-tui-release-gate.md) - One layered command for focused through full release evidence
  - Source code in `crates/voidb-core/` and `crates/voidb-tui/`

- **Users**
  - Quick Start: See [Quick Start](#-quick-start) section above
  - Keybindings: Press `:help` in the app
  - Native profiles: the platform config directory's `voidb/profiles.json`
  - Encrypted plugin configuration: `voidb/credentials.json`

---

## 🔌 Plugin Ecosystem

VoidB's plugin system allows support for any protocol or data source:

### Official Plugins

| Plugin | Protocol / Role | Workspace Status | Location |
|--------|------------------|------------------|----------|
| Connection Manager | Native profile and credential configuration | Default standalone TUI | `crates/voidb-tui/src/connection_manager_app.rs` |
| MySQL | MySQL/MariaDB | Service, CLI, and capability crate | `crates/plugins/voidb-plugin-mysql` |
| PostgreSQL | PostgreSQL | Service, CLI, and capability crate | `crates/plugins/voidb-plugin-postgres` |
| SQLite | SQLite | Service, CLI, and capability crate | `crates/plugins/voidb-plugin-sqlite` |
| Redis | Redis | Service, CLI, and capability crate | `crates/plugins/voidb-plugin-redis` |
| MongoDB | MongoDB | Service, CLI, and capability crate | `crates/plugins/voidb-plugin-mongodb` |
| DuckDB | DuckDB | Service, CLI, and capability crate | `crates/plugins/voidb-plugin-duckdb` |
| Elasticsearch | Elasticsearch | Service, CLI, and capability crate | `crates/plugins/voidb-plugin-elasticsearch` |
| SSH | SSH/SFTP | Service, CLI, and capability crate | `crates/plugins/voidb-plugin-ssh` |
| Docker | Docker Engine | External process plugin (stdio-jsonrpc) | [limmytian/voidb-plugin-docker](https://github.com/limmytian/voidb-plugin-docker) |
| Kubernetes | Kubernetes API | External process plugin (stdio-jsonrpc) | [limmytian/voidb-plugin-kubernetes](https://github.com/limmytian/voidb-plugin-kubernetes) |
| S3 | S3-compatible object storage | External process plugin (stdio-jsonrpc) | [limmytian/voidb-plugin-s3](https://github.com/limmytian/voidb-plugin-s3) |
| WebDAV | WebDAV storage | External process plugin (stdio-jsonrpc) | [limmytian/voidb-plugin-webdav](https://github.com/limmytian/voidb-plugin-webdav) |
| Email | IMAP/POP3 + SMTP | External process plugin (stdio-jsonrpc) | [limmytian/voidb-plugin-email](https://github.com/limmytian/voidb-plugin-email) |
| Jenkins | Jenkins CI | External process plugin (stdio-jsonrpc) | [limmytian/voidb-plugin-jenkins](https://github.com/limmytian/voidb-plugin-jenkins) |
| Sync | Encrypted config sync client | CLI client/server library surface | `crates/plugins/voidb-plugin-sync` |

### Create Your Own Plugin

See the [Plugin Development Guide](docs/plugin-development-guide.md) for
service-layer and plugin structure rules. Future interactive terminal apps must
use the
[Plugin-Owned TUI Development Guide](docs/plugin-owned-tui-development-guide.md).

Example plugin structure:
```
crates/plugins/voidb-plugin-yourname/
├── Cargo.toml
├── src/
│   ├── lib.rs          # Plugin factory
│   └── plugin.rs       # Plugin implementation
```

Reference existing plugins in `crates/plugins/` for complete examples.

---

## 🏗️ Architecture

VoidB uses independent frontend boundaries over a shared capability core:

- **Native Connection Manager**: owns profile CRUD, encrypted configuration,
  credential unlock, schema-driven interactive forms, diagnostics, and
  capability guidance. Authentication choices dynamically reveal their fields;
  advanced JSON is available with `F2`.
- **Optional VoidB Shell**: retained behind `voidb --shell` for compatibility and
  development; it is not used by the native Connection Manager.

- **Plugins**: Fully autonomous applications that:
  - Own their full-screen UI rendering
  - Handle their own events
  - Manage their own state
  - Use ShellCapabilities for tab/connection operations

- **Communication**: profile IDs and CLI/capability contracts connect the
  manager to plugin services. Plugin TUIs run only through their own CLI command.

```
┌─────────────────────────────────────────────────┐
│       Native Connection Manager                 │
│  • profiles.json                                │
│  • encrypted credentials.json                   │
│  • profile test + capability guidance           │
└─────────────────────┬───────────────────────────┘
                      │
        ┌─────────────┴─────────────┐
        │  profile/capability CLI   │
        └─────────────┬─────────────┘
                      │
          ┌───────────┴───────────┐
          │ Plugin services/TUIs  │
          └───────────────────────┘
```

### Example Plugins

See these for complete examples of autonomous plugins:
- `crates/plugins/voidb-plugin-mysql/src/table_plugin.rs` - MySQL legacy table viewer/editor
- `crates/plugins/voidb-plugin-postgres/src/table_plugin.rs` - PostgreSQL legacy table viewer/editor
- `crates/plugins/voidb-plugin-redis/src/cli_plugin.rs` - Redis standalone TUI and CLI registration

See [Plugin Development Guide](docs/plugin-development-guide.md) and
[Plugin-Owned TUI Development Guide](docs/plugin-owned-tui-development-guide.md)
for full details.

---

## 🛣️ Roadmap

See the [Readiness Documentation Map](docs/readiness.md) for current sources
and the generated [Agent Capability and Experience Matrix](docs/agent-capability-matrix.md)
for built-in plugin posture and coverage.

---

## 🤝 Contributing

Contributions should follow the conventions in [docs/conventions.md](docs/conventions.md) and the validation tiers in [docs/ci-checks.md](docs/ci-checks.md).

### Development Setup

```bash
# Clone repository
git clone https://github.com/limmytian/voidb.git
cd voidb

# Install dependencies
rustup update stable

# Run tests
cargo test

# Run in development mode
cargo run
```

---

## 🐛 Reporting Issues

Found a bug or have a feature request? Use the repository issue tracker on GitHub.

---

## 📄 License

VoidB is released under the Apache License 2.0. See [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgments

- [ratatui](https://github.com/ratatui-org/ratatui) - Terminal UI framework
- [crossterm](https://github.com/crossterm-rs/crossterm) - Cross-platform terminal manipulation

---

**Built with ❤️ by the VoidB community**
