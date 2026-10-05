# Contributing to VoidB

Thank you for your interest in contributing to VoidB! We welcome contributions from the community.

## Code of Conduct

By participating in this project, you agree to abide by respectful and constructive community standards.

## Getting Started

### Prerequisites

- **Rust**: Latest stable Rust toolchain (edition 2024 support required).
- **Cargo**: Bundled with Rust.
- Optional for full builds: C/C++ compiler toolchain (for native DuckDB support) and Docker (for live fixture smoke tests).

### Building

VoidB uses Cargo workspaces and feature tiering to keep builds fast:

```bash
# Build core packages with Tier 1 default features (MySQL, Postgres, SQLite, Redis, SSH)
cargo build

# Run the VoidB TUI
cargo run -p voidb-tui

# Run the VoidB CLI
cargo run -p voidb-cli -- --help

# Build with all optional features and plugins enabled
cargo build --workspace --features full
```

## Development Workflow

### 1. Branching & Commits

- Fork the repository and create a branch for your feature or bug fix from `main`.
- Keep commits focused and logically grouped. Write clear commit messages.
- Ensure all comments, code, and documentation are written in **English**.

### 2. Testing & Quality Checks

Run the fast checks before committing:

```bash
# Format check
cargo fmt --all -- --check

# Test core and CLI
cargo test -p voidb-core
cargo test -p voidb-cli

# Run Clippy
cargo clippy -p voidb-core --all-targets --no-deps
cargo clippy -p voidb-cli --all-targets --no-deps
```

For broader changes across plugins or shared contracts, consult [docs/ci-checks.md](docs/ci-checks.md) for tiered test commands.

### 3. Architecture Guidelines

- **Plugin Isolation**: Database/protocol plugins live in `crates/plugins/`, never inside `voidb-core`.
- **Pure Router Shell**: The TUI shell (`voidb-tui`) acts as an autonomous router; plugins manage their own internal views.
- **Service Layer**: TUI and CLI code consume service modules (`service/`); never import database driver crates directly into TUI components.
- **Security & Secrets**: Never log or print plaintext passwords, connection strings, or authorization tokens. Profile data must adhere to AES-256-GCM encryption.

## Pull Requests

1. Ensure all tests and lints pass.
2. If your change affects capability metadata or agent interfaces, run `bash scripts/check-agent-capability-matrix.sh` to make sure documentation remains in sync.
3. Open a Pull Request against the `main` branch with a clear description of the problem solved and the changes introduced.
