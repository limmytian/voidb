# Technology Stack

## Languages
- Rust (edition 2024) - All application code, plugins, core library
- TOML - Configuration files (`Cargo.toml`, `~/.config/voidb/config.toml`)
- JSON - Plugin config blobs, saved queries, clipboard interchange format
- SQL - Built-in syntax highlighting, autocomplete, statement splitting

## Runtime
- Rust stable toolchain (rustc 1.94.0 on dev machine, no `rust-toolchain.toml` pinned)
- Tokio 1.x async runtime (full features) - all async I/O including database drivers and network
- No `rust-toolchain.toml` present; relies on system-installed toolchain
- Cargo (Cargo workspace with `resolver = "2"`)
- Lockfile: `Cargo.lock` present and committed
- Root: `Cargo.toml` (workspace root)
- Default member: `crates/voidb-tui` (binary crate)
- 18 total workspace members (3 core crates + 15 plugin crates)

## Frameworks
- ratatui 0.29 (features: `crossterm`, `all-widgets`) - Terminal UI rendering
- crossterm 0.28 (features: `event-stream`) - Terminal backend, input handling, Kitty keyboard protocol
- tui-textarea 0.7 - Multi-line text editor widget (used in `voidb-tui`)
- tui-input 0.11 - Single-line text input widget (used in Redis plugin)
- tokio 1.x (features: `full`) - Async runtime, channels, timers
- async-trait 0.1 - Async trait support for DatabaseAdapter, NativePlugin
- futures 0.3 - Stream combinators (used in TUI, Kubernetes, MongoDB plugins)
- tokio-util 0.7 - Codec/framing utilities (used in TUI, Kubernetes)
- serde 1.0 (features: `derive`) - Core serialization framework
- serde_json 1.0 - JSON serialization for plugin configs, clipboard, RPC
- toml 0.8 - Config file parsing (`config.toml`)
- serde_yaml 0.9 - YAML parsing (Kubernetes plugin only)
- csv 1.3 - CSV import/export
- aes-gcm 0.10 - AES-256-GCM authenticated encryption for credential storage
- argon2 0.5 - Argon2id key derivation (V1 heavy + V2 light params)
- base64 0.22 - Base64 encoding for encrypted envelope format
- thiserror 2.0 - Structured error types (`VoidbError` in `crates/voidb-core/src/error.rs`)
- anyhow 1.0 - Application-level error handling
- clap 4.5 (features: `derive`) - CLI argument parsing (used in `voidb-cli` and plugins)
- tracing 0.1 - Structured logging
- tracing-subscriber 0.3 (features: `env-filter`) - Log subscriber with env-based filtering
- jsonschema 0.26 - JSON Schema validation for plugin configs

## Key Dependencies

### Core
| Crate | Version | Purpose | Used In |
|---|---|---|---|
| ratatui | 0.29 | TUI rendering framework | `voidb-core`, `voidb-tui`, all plugins |
| crossterm | 0.28 | Terminal backend, input events, mouse/paste | `voidb-core`, `voidb-tui`, all plugins |
| tokio | 1.x | Async runtime (full features) | All crates |
| serde / serde_json | 1.0 | Serialization for configs, clipboard, IPC | All crates |
| aes-gcm / argon2 | 0.10 / 0.5 | Credential encryption at rest | `voidb-core` |

### Database Drivers
| Crate | Version | Purpose | Used In |
|---|---|---|---|
| mysql_async | 0.34 | MySQL/MariaDB async driver | `voidb-plugin-mysql` |
| tokio-postgres | 0.7 | PostgreSQL async driver (with chrono, serde_json, uuid features) | `voidb-plugin-postgres` |
| rusqlite | 0.32 | SQLite driver (bundled, with chrono, serde_json, uuid features) | `voidb-plugin-sqlite`, `voidb-core` |
| redis | 0.27 | Redis async driver (tokio-comp, aio features) | `voidb-plugin-redis` |
| mongodb | 3.x | MongoDB official driver | `voidb-plugin-mongodb` |
| duckdb | 1.4 | DuckDB embedded analytics (bundled) | `voidb-plugin-duckdb` |

### Infrastructure / Protocol
| Crate | Version | Purpose | Used In |
|---|---|---|---|
| russh | 0.48 | SSH2 protocol client | `voidb-plugin-ssh` |
| russh-keys | 0.48 | SSH key handling | `voidb-plugin-ssh` |
| russh-sftp | 2.1 | SFTP subsystem over SSH | `voidb-plugin-ssh` |
| ssh-key | 0.6 | SSH key parsing | `voidb-plugin-ssh` |
| bollard | 0.18 | Docker Engine API client | `voidb-plugin-docker` |
| kube | 0.99 | Kubernetes API client (rustls-tls, ws features) | `voidb-plugin-kubernetes` |
| k8s-openapi | 0.24 | Kubernetes API types (v1.32) | `voidb-plugin-kubernetes`, `voidb-tui`, `voidb-cli` |
| rust-s3 | 0.37 | S3-compatible object storage client | `voidb-plugin-s3` |
| reqwest | 0.12 | HTTP client (json, native-tls features) | `voidb-plugin-elasticsearch` |

### Utilities
| Crate | Version | Purpose | Used In |
|---|---|---|---|
| chrono | 0.4 | Date/time handling (serde feature) | Core + most plugins |
| uuid | 1.0 | UUID generation/parsing (serde feature) | Core + database plugins |
| unicode-width | 0.2 | CJK/emoji text width calculation for TUI | Core + plugins |
| dirs | 6.0 | Platform config/data directory resolution | `voidb-core`, `voidb-tui` |
| arboard | 3.x | System clipboard access | `voidb-core`, `voidb-tui` |
| vt100 | 0.15 | VT100 terminal emulation (SSH plugin terminal, Kubernetes exec) | `voidb-core`, `voidb-plugin-kubernetes` |
| shellexpand | 3.1.2 | Shell tilde/env expansion in file paths | `voidb-core` |
| once_cell | 1.19 | Lazy static initialization | `voidb-core` |
| hex | 0.4 | Hex encoding for BLOB display | MySQL, Postgres, SQLite, DuckDB plugins |
| bson | 2.x | BSON types for MongoDB | `voidb-plugin-mongodb` |
| http | 1.x | HTTP types | `voidb-plugin-kubernetes` |
| futures-util | 0.3 | Stream extension traits | `voidb-plugin-docker` |

## Configuration Files

| File | Format | Purpose |
|---|---|---|
| Platform config `voidb/config.toml` | TOML | App settings, master-password verifier, optional migration backup |
| Platform config `voidb/profiles.json` | JSON | Native profile identity, metadata, policy, credential references |
| Platform config `voidb/credentials.json` | JSON | AES-256-GCM encrypted local plugin configuration records |
| `~/.config/voidb/saved_queries.json` | JSON | Saved queries array |
| `~/.config/voidb/query_history.txt` | Plain text | Query history, max 500 entries, newlines escaped as `\n` |
| `~/.local/share/voidb/logs/voidb.log` | Text | Log output, level via `RUST_LOG` (default: `info`) |

- Config schema: `crates/voidb-core/src/config.rs` (`AppConfig` struct)
- Auto-creates config directory if missing

## Build System

- Binaries: `voidb` (TUI, `crates/voidb-tui/src/main.rs`), `voidb-cli` (`crates/voidb-cli/src/main.rs`)
- SQLite (`rusqlite`) and DuckDB (`duckdb`) use `bundled` feature — compile C libraries from source
- Release profile: LTO enabled, single codegen unit, `opt-level = "z"` (size-optimized), strip symbols
- Feature flags: `voidb-core` has `default = ["mysql"]` feature gate
- No Dockerfile, no committed CI/CD runner config, no `rust-toolchain.toml`
- Cross-platform package jobs are documented in Package CI Matrix

## Platform Requirements

- Rust stable toolchain (edition 2024 requires rustc >= 1.85.0)
- C compiler (for `rusqlite` and `duckdb` bundled builds)
- macOS / Linux (TUI + SSH + clipboard support)
- Terminal with UTF-8 support; Kitty keyboard protocol optional
