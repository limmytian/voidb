# Quickstart: Build a VoidB Plugin in 5 Minutes

VoidB uses an external process plugin architecture based on **stdio-jsonrpc**.
This lets you write plugins for VoidB in **any programming language** (Rust,
Go, Python, Node.js, Shell, etc.) and seamlessly plug into VoidB's Connection
Manager, CLI, and agent capability system.

---

## Basic Plugin Directory Structure

A standard VoidB plugin directory looks like this:

```text
my-plugin/
  plugin.toml                    # Plugin metadata manifest
  bin/
    my-plugin                    # Executable (script or binary)
  schemas/
    profile.schema.json          # JSON Schema for the connection profile (form rendering and validation)
    my-capability-input.json     # Capability input parameter schema
    my-capability-output.json    # Capability output result schema
```

---

## Step 1: Write `plugin.toml`

Create `plugin.toml` in the plugin root directory:

```toml
id = "my-plugin"
name = "My Plugin"
version = "0.1.0"
protocol_version = "1"
description = "My custom VoidB plugin"
license = "MIT"

[runtime]
command = "my-plugin"
args = []
transport = "stdio-jsonrpc"

[connections]
profile_schema = "schemas/profile.schema.json"
secret_classes = []

[[capabilities]]
id = "hello"
description = "Greet the caller"
input_schema = "schemas/my-capability-input.json"
output_schema = "schemas/my-capability-output.json"
permissions = ["connection.read"]
risk = "read_only"
destructive = false
streaming = false
connection_required = false
```

---

## Step 2: Define Schemas

Place the JSON Schema files in the `schemas/` directory:

- `schemas/profile.schema.json`:
  ```json
  {
    "type": "object",
    "properties": {
      "host": { "type": "string" },
      "port": { "type": "integer" }
    }
  }
  ```

- `schemas/my-capability-input.json`:
  ```json
  {
    "type": "object",
    "properties": {
      "name": { "type": "string" }
    }
  }
  ```

- `schemas/my-capability-output.json`:
  ```json
  {
    "type": "object",
    "required": ["greeting"],
    "properties": {
      "greeting": { "type": "string" }
    }
  }
  ```

---

## Step 3: Write the Plugin Runtime

The plugin receives JSON-RPC 2.0 requests line by line on stdin and writes
responses to stdout (one JSON object per line).

The base methods it must handle are:
1. `voidb.initialize`
2. `voidb.health`
3. `voidb.invoke`

### Method A: Using Rust (`voidb-process-plugin-sdk`)

```rust
use serde_json::json;
use voidb_process_plugin_sdk::{
    CapabilityRouter, redacted_output_summary, serve_stdio, succeeded,
};

fn main() -> anyhow::Result<()> {
    let router = CapabilityRouter::new("my-plugin")
        .capability("hello", |invocation, _grants| {
            let name = invocation.input["name"].as_str().unwrap_or("World");
            Ok(succeeded(
                invocation.id,
                json!({ "greeting": format!("Hello, {}!", name) }),
                redacted_output_summary(json!({ "status": "ok" })),
            ))
        });

    serve_stdio(router)?;
    Ok(())
}
```

### Method B: Using Python 3

Create the executable script `bin/my-plugin` and make it executable
(`chmod +x bin/my-plugin`):

```python
#!/usr/bin/env python3
import sys, json

for line in sys.stdin:
    if not line.strip():
        continue
    req = json.loads(line)
    method = req.get("method")
    msg_id = req.get("id")

    if method == "voidb.initialize":
        resp = {"jsonrpc": "2.0", "id": msg_id, "result": {"plugin_id": "my-plugin", "protocol_version": "1", "status": "ready"}}
    elif method == "voidb.health":
        resp = {"jsonrpc": "2.0", "id": msg_id, "result": {"status": "ready", "active_invocations": 0}}
    elif method == "voidb.invoke":
        inv = req.get("params", {}).get("invocation", {})
        name = inv.get("input", {}).get("name", "World")
        resp = {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "invocation_id": inv.get("id", "inv-1"),
                "status": "succeeded",
                "output": {"greeting": f"Hello, {name}!"},
                "output_summary": {"status": "ok", "redaction": "not_required"}
            }
        }
    else:
        resp = {"jsonrpc": "2.0", "id": msg_id, "error": {"code": -32601, "message": "Method not found"}}

    sys.stdout.write(json.dumps(resp) + "\n")
    sys.stdout.flush()
```

### Method C: Using Go

See
[`examples/process-plugins/example-go/main.go`](../examples/process-plugins/example-go/main.go);
compile it into a binary and place it at `bin/my-plugin`.

---

## Step 4: Test and Run

### Method 1: Local development debugging

Use the `VOIDB_PLUGIN_PATH` environment variable to point VoidB at the
development directory to scan (the directory that CONTAINS your plugin's
folder, not the plugin folder itself):

```bash
VOIDB_PLUGIN_PATH=/path/to/parent_of_my_plugin vb plugin list
VOIDB_PLUGIN_PATH=/path/to/parent_of_my_plugin vb plugin describe my-plugin
```

Invoking an unsigned development plugin additionally requires
`VOIDB_ALLOW_UNSIGNED_PLUGINS=1` (see Method 2).

### Method 2: Production installation

Do not copy or symlink a plugin directory into a managed plugin directory
(`voidb/plugins` under the platform config or data directory): managed installs
verify package signatures and install provenance, and a hand-copied directory
fails that integrity gate.

Unsigned development plugins are only discovered from an explicit development
root, with unsigned execution explicitly enabled:

```bash
# VOIDB_PLUGIN_PATH must point at the directory that CONTAINS my-plugin/
VOIDB_PLUGIN_PATH=$(pwd) VOIDB_ALLOW_UNSIGNED_PLUGINS=1 vb plugin list
VOIDB_PLUGIN_PATH=$(pwd) VOIDB_ALLOW_UNSIGNED_PLUGINS=1 vb plugin describe my-plugin
```

`VOIDB_PLUGIN_PATH` and `VOIDB_ALLOW_UNSIGNED_PLUGINS=1` only apply to explicit
development roots; they never apply to managed install directories. Production
installs must go through packaging and the signed registry:

```bash
vb plugin install my-plugin
```

VoidB then discovers and loads the plugin automatically and registers its
optional connection type in the Connection Manager!
