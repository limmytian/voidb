# Third-Party Process Plugin Development and Certification Guide

VoidB features a decoupled, language-agnostic process-plugin architecture communicating over standard input and output via `stdio-jsonrpc` (JSON-RPC 2.0).

Whether built in Rust with `voidb-process-plugin-sdk`, Go, Python, Node.js, or Shell, any external executable conforming to the specification can register connection profiles, capabilities, and agent execution paths in VoidB.

---

## 1. Architecture Overview

```text
┌────────────────────────────────────────────────────────┐
│                      VoidB Shell                       │
│      (Connection Manager TUI / CLI / Agent Router)     │
└───────────────▲────────────────────────▲───────────────┘
                │                        │
       Discovery & Metadata     Line-delimited JSON-RPC 2.0
      (plugin.toml + schemas)     (stdin / stdout streams)
                │                        │
┌───────────────▼────────────────────────▼───────────────┐
│               External Process Plugin                  │
│       bin/voidb-plugin-<name> (Rust, Go, Python, ...)  │
└────────────────────────────────────────────────────────┘
```

### Core Invariants
1. **Isolation**: Process plugins run in isolated OS processes. A plugin crash never crashes the VoidB host.
2. **Deterministic Contract**: Communication strictly adheres to line-delimited JSON-RPC 2.0 on standard I/O. Standard error (`stderr`) is strictly reserved for diagnostic logs.
3. **Zero Plaintext Secrets**: The host brokers credentials using capability grants. Plugins never receive plaintext passwords or private keys directly from the host invocation envelope.
4. **Offline Packaging**: Plugins can be distributed as offline `.tar.zst` or `.tar` archives, installable with checksum verification and atomic directory staging.

---

## 2. Directory Layout and Packaging Specification

A standard VoidB process plugin package adheres to this file layout:

```text
<plugin-id>/
├── plugin.toml                 # Required: Process plugin manifest
├── bin/
│   └── voidb-plugin-<name>     # Required: Executable binary or entrypoint script
├── schemas/
│   ├── profile.schema.json     # Required: JSON schema for connection profile
│   ├── <cap>-input.schema.json # Required for each capability: Input JSON Schema
│   └── <cap>-output.schema.json# Required for each capability: Output JSON Schema
├── README.md                   # Plugin documentation
└── LICENSE                     # Open source license (e.g., Apache-2.0, MIT)
```

### Manifest Format (`plugin.toml`)

```toml
id = "my-service"
name = "My Service Plugin"
version = "0.1.0"
protocol_version = "1"
description = "Community process plugin for My Service integration"
license = "Apache-2.0"

[runtime]
command = "voidb-plugin-my-service"
args = ["serve"]
transport = "stdio-jsonrpc"

[connections]
profile_schema = "schemas/profile.schema.json"
secret_classes = ["password", "token"]

[[capabilities]]
id = "ping"
description = "Verify endpoint connectivity and health."
input_schema = "schemas/ping-input.schema.json"
output_schema = "schemas/ping-output.schema.json"
permissions = ["connection.read"]
risk = "read_only"
destructive = false
streaming = false
connection_required = true
supports_dry_run = false
default_timeout_ms = 5000
```

---

## 3. Protocol Specification (`stdio-jsonrpc`)

Plugins read line-delimited JSON-RPC 2.0 requests from `stdin` and write responses to `stdout`. Every response must terminate with a newline `\n`.

### Reserved Environment Variables
VoidB automatically injects the following runtime environment variables into the plugin process:

| Environment Variable | Description |
|---|---|
| `VOIDB_PLUGIN_ID` | The registered identifier of the plugin |
| `VOIDB_PLUGIN_DIR` | Absolute path to the plugin package directory |
| `VOIDB_PROTOCOL_VERSION` | Negotiated protocol version (e.g. `1`) |
| `VOIDB_LOG_FORMAT` | Log format mode (`json` or `text`) |

### Mandatory JSON-RPC Methods

#### 1. `voidb.initialize`
Negotiates protocol version and readiness.
- **Request**:
  ```json
  {"jsonrpc":"2.0","id":"init-1","method":"voidb.initialize","params":{"protocol_version":"1","plugin_id":"my-service"}}
  ```
- **Response**:
  ```json
  {"jsonrpc":"2.0","id":"init-1","result":{"plugin_id":"my-service","protocol_version":"1","status":"ready"}}
  ```

#### 2. `voidb.health`
Heartbeat check to verify the process is alive.
- **Request**:
  ```json
  {"jsonrpc":"2.0","id":"health-1","method":"voidb.health","params":{"include_runtime":true}}
  ```
- **Response**:
  ```json
  {"jsonrpc":"2.0","id":"health-1","result":{"status":"ready","active_invocations":0}}
  ```

#### 3. `voidb.invoke`
Executes a specific capability.
- **Request**:
  ```json
  {
    "jsonrpc": "2.0",
    "id": "inv-1",
    "method": "voidb.invoke",
    "params": {
      "invocation": {
        "id": "invoke-uuid-1234",
        "capability_id": "ping",
        "input": { "verbose": true },
        "timeout_ms": 5000,
        "dry_run": false
      },
      "grants": []
    }
  }
  ```
- **Response**:
  ```json
  {
    "jsonrpc": "2.0",
    "id": "inv-1",
    "result": {
      "invocation_id": "invoke-uuid-1234",
      "status": "succeeded",
      "output": { "healthy": true, "latency_ms": 12 },
      "output_summary": { "status": "ok", "redaction": "not_required" }
    }
  }
  ```

#### Structured Errors
If an invocation fails, return structured errors in `error.data`:
```json
{
  "jsonrpc": "2.0",
  "id": "inv-1",
  "error": {
    "code": -32000,
    "message": "Capability execution failed",
    "data": {
      "category": "Target",
      "code": "connection.refused",
      "message": "Unable to connect to remote service host",
      "details": { "host": "10.0.0.1" },
      "retryable": true
    }
  }
}
```

---

## 4. Quickstart Scaffolding with `cargo-generate`

VoidB provides an official project scaffolding template in `templates/process-plugin-template`.

### Creating a New Plugin
```bash
cargo generate --path /path/to/voidb/templates/process-plugin-template \
  --name voidb-plugin-redis-extra
```

### Developing with `voidb-process-plugin-sdk`
In `src/main.rs`:
```rust
use serde_json::json;
use voidb_process_plugin_sdk::{
    CapabilityRouter, redacted_output_summary, serve_stdio, succeeded,
};

fn main() -> anyhow::Result<()> {
    let router = CapabilityRouter::new("my-service")
        .capability("ping", |invocation, _grants| {
            Ok(succeeded(
                invocation.id,
                json!({ "status": "pong" }),
                redacted_output_summary(json!({ "healthy": true })),
            ))
        });

    serve_stdio(router)?;
    Ok(())
}
```

---

## 5. Offline Packaging & Distribution Tooling

VoidB CLI includes built-in commands for validating, packaging, and installing plugin packages:

### Packaging an Offline Bundle
```bash
voidb-cli plugin package ./my-service-plugin --archive-format tar.zst
# Output: dist/my-service-0.1.0.tar.zst
```

### Inspecting and Validating a Package
```bash
voidb-cli plugin describe my-service --state-any --include runtime,connections,capabilities,schemas,diagnostics
```

### Installing an Offline Package
```bash
voidb-cli plugin install dist/my-service-0.1.0.tar.zst
```

### Updating or Downgrading an Installed Plugin
```bash
voidb-cli plugin update my-service --from dist/my-service-0.2.0.tar.zst
# For rollback or downgrade:
voidb-cli plugin update my-service --from dist/my-service-0.1.0.tar.zst --allow-downgrade
```

---

## 6. Conformance & Certification Checklist

Before publishing your plugin or submitting it for community inclusion, run the conformance checklist:

- [ ] **Manifest & Identity**:
  - `plugin.toml` matches directory name outside development roots.
  - `protocol_version = "1"` and `transport = "stdio-jsonrpc"`.
  - Version conforms to semver.
- [ ] **Schemas**:
  - `profile.schema.json` valid JSON Schema.
  - All declared capabilities provide valid input and output schema JSON documents.
- [ ] **Risk & Safety**:
  - Side-effecting capabilities declare permissions.
  - Destructive capabilities set `destructive = true` and `risk = "destructive"`.
  - Read-only queries and inspection set `risk = "read_only"` with `supports_dry_run = false`.
- [ ] **Protocol Handshake**:
  - Direct smoke-test verifies `voidb.initialize`, `voidb.health`, and `voidb.invoke`.
- [ ] **Clean Diagnostics**:
  - Running `voidb-cli plugin describe <id> --state-any` reports `state = "available"` with zero diagnostic errors.
- [ ] **Offline Packaging**:
  - Package builds cleanly via `voidb-cli plugin package` and successfully installs in a fresh install root.
