# voidb-process-plugin-sdk

Official Rust SDK for developing standalone external process plugins for [VoidB](https://github.com/limmytian/voidb).

## Overview

VoidB uses an out-of-process architecture for third-party protocols, storage engines, and infrastructure plugins. Process plugins run as independent executables communicating with VoidB via standard I/O (`stdio-jsonrpc` 2.0).

This crate provides:
- **`CapabilityRouter`**: Declarative routing for capability invocations and lifecycle events.
- **`ManifestBuilder`**: Structured generator for `plugin.toml` manifests.
- **`serve_stdio`**: Robust stdio event loop handling `voidb.initialize`, `voidb.health`, and `voidb.invoke` requests.
- **Generic SQL Helpers**: Optional `GenericSqlBackend` router for relational database plugins.

## Getting Started

### 1. Add Dependency

```toml
[dependencies]
voidb-process-plugin-sdk = "0.3.0-rc.1"
voidb-core = "0.3.0-rc.1"
```

### 2. Implement Your Plugin

```rust,no_run
use anyhow::Result;
use voidb_process_plugin_sdk::{CapabilityRouter, serve_stdio};
use voidb_core::{CapabilityInvocationResult, InvocationStatus};

fn main() -> Result<()> {
    let router = CapabilityRouter::new("myplugin")
        .capability("ping", |_invocation, _grants| {
            Ok(CapabilityInvocationResult {
                invocation_id: _invocation.id,
                status: InvocationStatus::Succeeded,
                output: serde_json::json!({ "pong": true }),
                output_summary: serde_json::json!({ "pong": true }),
                target: None,
                page: None,
                duration_ms: 1,
            })
        });

    serve_stdio(&router)?;
    Ok(())
}
```

### 3. Generate Manifest and Schemas

Run your plugin with schema export or provide `plugin.toml` and corresponding JSON Schemas in `schemas/`:

```toml
id = "myplugin"
name = "My Plugin"
version = "0.1.0"
protocol_version = "1"

[runtime]
command = "myplugin"
args = ["serve"]
transport = "stdio-jsonrpc"

[connections]
profile_schema = "schemas/profile.schema.json"
secret_classes = ["password"]

[[capabilities]]
id = "ping"
description = "Ping capability"
input_schema = "schemas/ping-input.schema.json"
output_schema = "schemas/ping-output.schema.json"
permissions = ["connection.read"]
risk = "read_only"
destructive = false
streaming = false
connection_required = false
required_secret_classes = []
supports_dry_run = false
default_timeout_ms = 5000
```

## Scaffolding New Plugins

To scaffold a new plugin quickly using `cargo-generate`:

```bash
cargo generate --path templates/process-plugin-template --name voidb-plugin-myengine
```

## License

Apache-2.0
