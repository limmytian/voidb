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
- 🔌 **Unified Multi-Protocol Ecosystem** — One tool across relational databases (MySQL, PostgreSQL, SQLite, DuckDB), in-memory stores (Redis), document/search engines (MongoDB, Elasticsearch), DevOps infrastructure (SSH, Docker, Kubernetes), and storage/collaboration plugins (S3, WebDAV, Email, Jenkins).
- 🚀 **100% Decoupled & Blazing Fast** — Clean, lightweight core with zero heavy C++ or driver bloat. All 14 official protocol plugins run as first-class, independent process plugins with identical standing under `voidb-cli`; the Connection Manager is native, and only the optional Sync client plugin remains in this repository.

---

## Current Architecture

VoidB uses a capability-first core with completely decoupled process plugins:

- **Connection Manager (`voidb`)**: the default standalone application. It owns its event loop, encrypted credentials vault, profile state, and JIT authorization gateway. It never directly embeds heavy protocol drivers.
- **Unified Command Dispatcher (`voidb-cli`)**: the master CLI dispatch desk. Discovers user-installed process plugins and explicitly configured development plugins and transparently routes commands, arguments, and flags.
- **Decoupled Process Plugins (`voidb-plugin-<name>`)**: All 14 official plugins live in separate repositories and adhere to the tri-modal contract: `test` (connectivity check), `tui` (interactive terminal app), and `serve` (`stdio-jsonrpc` for agents).
- **Optional Plugins**: Core distributions contain no plugins. On first interactive launch, choose whether to install the recommended set, or run `voidb-cli plugin install-default` later. All official plugins use the same user installation and uninstall lifecycle.

Install only what you need:

```bash
voidb-cli plugin install mysql
# Or install the six recommended plugins:
voidb-cli plugin install-default
voidb-cli plugin uninstall mysql
```

In the Connection Manager, a profile with a missing plugin shows `NOT INSTALLED`.
Select it and press `i`, then confirm to download only that official plugin.
Installation runs in the background; the UI refreshes when it finishes.
Disabled or incompatible plugins have separate statuses and are not overwritten.

All managed installations use the user plugin directory (on macOS,
`~/Library/Application Support/voidb/plugins`). Core installation and upgrades
never install plugins automatically. Legacy plugins under a Homebrew or system
installation prefix are no longer discovered implicitly; install the needed
plugins through the registry instead. Connection profiles and credentials are
preserved. Explicit development and offline roots remain available through
`VOIDB_PLUGIN_PATH` and `VOIDB_BUNDLED_PLUGIN_ROOT`; `install-default` uses the
registry unless `--from-bundled` is explicitly selected.

See [docs/architecture.md](docs/architecture.md) for full architecture details.

---

## 🎬 Quick Start

### Installation

#### 1. Official One-Line Script (Linux & macOS)

```bash
curl -fsSL https://raw.githubusercontent.com/limmytian/voidb/main/scripts/install.sh | bash
```

#### 2. Homebrew (macOS / Linux)

```bash
brew install limmytian/tap/voidb
```
*(Or install manually via `packaging/homebrew/voidb.rb`)*

#### 3. From Source / Cargo

```bash
# Install via cargo
cargo install --locked voidb voidb-cli

# Or clone and build
git clone https://github.com/limmytian/voidb.git
cd voidb
cargo build --release
sudo cp target/release/voidb target/release/voidb-cli /usr/local/bin/
```

### First Run

```bash
# Launch VoidB
voidb

# Equivalent explicit Connection Manager entrypoints
voidb --connection-manager
voidb-cli connections tui

# Deprecated compatibility alias: --shell prints a warning and then
# launches the native Connection Manager (the embedded shell was removed)
voidb --shell

# In VoidB:
# 1. Use the Connection Manager to create or edit profiles
# 2. Press Enter on a profile for CLI/capability guidance
# 3. Use voidb-cli or voidb invoke for plugin operations
```

`voidb-cli` itself ships only the built-in command groups (`audit`,
`connections`, `context`, `credential`, `invoke`, `plugin`, `profile`, plus the
feature-gated `sync`). Plugin domain commands such as `voidb-cli mysql query`
require that plugin to be installed first, for example with
`voidb-cli plugin install-default` or `voidb-cli plugin install <plugin>`.

CLI ergonomics:

- **Shorter aliases**: `conn` (connections), `cred` (credential), `profiles`
  (profile), and `re-encrypt` (`credential master reencrypt`) are visible
  aliases shown in `--help`.
- **Shell completions**: generate a completion script for your shell, for
  example `voidb-cli completions fish >
  ~/.config/fish/completions/voidb-cli.fish` (also supports `bash`, `zsh`,
  `powershell`, and `elvish`).
- **Interactive unlock**: in a terminal, commands that need credential
  decryption prompt once for the master password (echo disabled, prompt on
  stderr) instead of requiring `VOIDB_MASTER_PASSWORD` up front. Agents and
  scripts without a terminal stay fail-closed and must set
  `VOIDB_MASTER_PASSWORD`.

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
  - [Process Plugin Development and Certification Guide](docs/process-plugin-development-guide.md) ⭐ Start here for the current process-plugin architecture
  - [Process Plugin SDK](docs/process-plugin-sdk.md) - Rust SDK primitives over the stable stdio-jsonrpc protocol
  - [Plugin-Owned TUI Development Guide](docs/plugin-owned-tui-development-guide.md) - Standalone TUI command, terminal lifecycle, tests, and release gates
  - Minimal protocol examples in `examples/process-plugins/` and the cargo-generate template in `templates/process-plugin-template/`

- **Core Contributors**
  - [CHANGELOG.md](CHANGELOG.md) - Version history and breaking changes
  - [Readiness Documentation Map](docs/readiness.md) - Canonical current architecture, Agent, TUI, security, and release sources
  - [Agent Capability and Experience Matrix](docs/agent-capability-matrix.md) - Generated capability, session, TUI, handoff, and validation inventory
  - [Agent Operator, Migration, and Troubleshooting Guide](docs/agent-operator-guide.md) - Copyable upgrade, authorization, session, cleanup, troubleshooting, and rollback workflows
  - [Agent and TUI Aggregate Release Gate](docs/agent-tui-release-gate.md) - One layered command for focused through full release evidence
  - Source code in `crates/voidb-core/` and `crates/voidb-tui/`

- **Users**
  - Quick Start: See [Quick Start](#-quick-start) section above
  - Keybindings: Press `?` in the app
  - Native profiles: the platform config directory's `voidb/profiles.json`
  - Encrypted plugin configuration: `voidb/credentials.json`

---

## 🔌 Plugin Ecosystem

VoidB's plugin system allows support for any protocol or data source:

### Official Plugins

All 14 official protocol plugins are developed and released in independent
`voidb-plugin-<name>` repositories outside this workspace and are distributed as
signed packages through the plugin registry (`registry/index.json`). Only the
optional Sync client plugin remains in this repository.

| Plugin | Protocol / Role | Status | Location |
|--------|------------------|--------|----------|
| Connection Manager | Native profile and credential configuration | Default standalone TUI | `crates/voidb-tui/src/connection_manager_app.rs` |
| MySQL | MySQL/MariaDB | Official process plugin (stdio-jsonrpc) | [limmytian/voidb-plugin-mysql](https://github.com/limmytian/voidb-plugin-mysql) |
| PostgreSQL | PostgreSQL | Official process plugin (stdio-jsonrpc) | [limmytian/voidb-plugin-postgres](https://github.com/limmytian/voidb-plugin-postgres) |
| SQLite | SQLite | Official process plugin (stdio-jsonrpc) | [limmytian/voidb-plugin-sqlite](https://github.com/limmytian/voidb-plugin-sqlite) |
| Redis | Redis | Official process plugin (stdio-jsonrpc) | [limmytian/voidb-plugin-redis](https://github.com/limmytian/voidb-plugin-redis) |
| DuckDB | DuckDB | Official process plugin (stdio-jsonrpc) | [limmytian/voidb-plugin-duckdb](https://github.com/limmytian/voidb-plugin-duckdb) |
| SSH | SSH/SFTP | Official process plugin (stdio-jsonrpc) | [limmytian/voidb-plugin-ssh](https://github.com/limmytian/voidb-plugin-ssh) |
| Elasticsearch | Elasticsearch | Official process plugin (stdio-jsonrpc) | [limmytian/voidb-plugin-elasticsearch](https://github.com/limmytian/voidb-plugin-elasticsearch) |
| MongoDB | MongoDB | Official process plugin (stdio-jsonrpc) | [limmytian/voidb-plugin-mongodb](https://github.com/limmytian/voidb-plugin-mongodb) |
| Docker | Docker Engine | Official process plugin (stdio-jsonrpc) | [limmytian/voidb-plugin-docker](https://github.com/limmytian/voidb-plugin-docker) |
| Kubernetes | Kubernetes API | Official process plugin (stdio-jsonrpc) | [limmytian/voidb-plugin-kubernetes](https://github.com/limmytian/voidb-plugin-kubernetes) |
| S3 | S3-compatible object storage | Official process plugin (stdio-jsonrpc) | [limmytian/voidb-plugin-s3](https://github.com/limmytian/voidb-plugin-s3) |
| WebDAV | WebDAV storage | Official process plugin (stdio-jsonrpc) | [limmytian/voidb-plugin-webdav](https://github.com/limmytian/voidb-plugin-webdav) |
| Email | IMAP/POP3 + SMTP | Official process plugin (stdio-jsonrpc) | [limmytian/voidb-plugin-email](https://github.com/limmytian/voidb-plugin-email) |
| Jenkins | Jenkins CI | Official process plugin (stdio-jsonrpc) | [limmytian/voidb-plugin-jenkins](https://github.com/limmytian/voidb-plugin-jenkins) |
| Sync | Encrypted config sync client | In-repo CLI plugin (feature-gated) | `crates/plugins/voidb-plugin-sync` |

### Create Your Own Plugin

See the [Process Plugin Development and Certification Guide](docs/process-plugin-development-guide.md)
and the [Process Plugin SDK](docs/process-plugin-sdk.md) for the stdio-jsonrpc
contract, packaging, and certification rules. Start new plugins from the
cargo-generate template in `templates/process-plugin-template/`. Future
interactive terminal apps must use the
[Plugin-Owned TUI Development Guide](docs/plugin-owned-tui-development-guide.md).

Template structure:
```
templates/process-plugin-template/
├── Cargo.toml
├── plugin.toml      # Plugin manifest: identity, capabilities, runtime transport
└── src/
    └── main.rs      # stdio-jsonrpc entrypoint
```

---

## 🏗️ Architecture

VoidB uses independent frontend boundaries over a shared capability core:

- **Native Connection Manager**: owns profile CRUD, encrypted configuration,
  credential unlock, schema-driven interactive forms, diagnostics, and
  capability guidance. Authentication choices dynamically reveal their fields;
  advanced JSON is available with `F2`.
- **Deprecated `--shell` alias**: the embedded shell was removed in v0.3.6.
  `voidb --shell` is accepted only as a deprecated alias that prints a warning
  and then launches the native Connection Manager.

- **Plugins**: Fully autonomous applications that:
  - Own their full-screen UI rendering
  - Handle their own events
  - Manage their own state
  - Run as separate processes communicating over stdio-jsonrpc

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

The official plugins no longer live in this repository. Complete plugin sources
are in their independent repositories (for example
[limmytian/voidb-plugin-mysql](https://github.com/limmytian/voidb-plugin-mysql)
and [limmytian/voidb-plugin-redis](https://github.com/limmytian/voidb-plugin-redis)).
In-repo starting points:

- `templates/process-plugin-template/` - cargo-generate template for a new process plugin
- `examples/process-plugins/` - minimal Go, Python, and Rust protocol examples
- `crates/plugins/voidb-plugin-sync/` - the in-tree Sync client plugin

See the [Process Plugin Development and Certification Guide](docs/process-plugin-development-guide.md)
and the [Plugin-Owned TUI Development Guide](docs/plugin-owned-tui-development-guide.md)
for full details.

---

## 🔄 Sync Server

The optional Sync client plugin (`crates/plugins/voidb-plugin-sync`) pairs with
a standalone backend shipped in this repository under
[voidb-sync-server/](voidb-sync-server/). The server stores only opaque,
end-to-end encrypted sync objects and password verifiers; plaintext
configuration and credentials never leave the client. Deployment files include
a Dockerfile and a Kubernetes manifest. See
[voidb-sync-server/README.md](voidb-sync-server/README.md) for setup and
configuration.

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

### Plugin trust and legacy recovery

VoidB v0.3.5 verifies managed plugin signatures against a compiled official public
key before CLI, TUI or agent execution. Installation records are inventory caches;
deleting them or rewriting their hashes never authorizes a replacement binary.
Install the new signed official plugin v0.3.4 packages explicitly. Recover an old
unsigned installation with `voidb-cli plugin update <plugin>`; profiles and
credentials are preserved. The public registry advances only after signed release
assets are published, so candidate verification uses the candidate registry.

Unsigned development requires `VOIDB_PLUGIN_PATH` plus
`VOIDB_ALLOW_UNSIGNED_PLUGINS=1` and cannot target standard managed user directories.
This opt-in permits arbitrary developer code and access to credentials deliberately
provided to it. Offline managed packages still require authenticated provenance;
`--verify-key` only adds an archive signature check and does not add a runtime
trust root. Replacing the trusted core or a privileged host remains outside this
protection.

Candidate validation can select a registry with `VOIDB_PLUGIN_REGISTRY_URL` or
`--registry-url`. This changes the download location only; it never changes the
compiled trusted signing keys. Release signing/verification scripts require
Python 3.11+ and OpenSSL 3. Use `scripts/update-homebrew-formula.py` after all four
verified Unix core archives are available; published v0.3.4 formula hashes remain
unchanged until that evidence exists.
