# 5 分钟开发一个 VoidB 插件 (Quickstart: Build a VoidB Plugin in 5 Minutes)

VoidB 采用了基于 **stdio-jsonrpc** 的外部进程插件架构。这使得你可以用**任何编程语言**（Rust、Go、Python、Node.js、Shell 等）为 VoidB 编写插件，无缝接入 VoidB 的 Connection Manager、CLI 以及 Agent 能力体系。

---

## 插件基本目录结构

一个标准的 VoidB 插件目录结构如下：

```text
my-plugin/
  plugin.toml                    # 插件元数据清单
  bin/
    my-plugin                    # 可执行文件 (脚本或二进制文件)
  schemas/
    profile.schema.json          # 连接配置的 JSON Schema (供表单渲染与校验)
    my-capability-input.json     # Capability 输入参数 Schema
    my-capability-output.json    # Capability 输出结果 Schema
```

---

## 第 1 步：编写 `plugin.toml`

在插件根目录下创建 `plugin.toml`：

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

## 第 2 步：定义 Schemas

在 `schemas/` 目录下放置 JSON Schema 文件：

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

## 第 3 步：编写插件运行体

插件通过 stdin 逐行接收 JSON-RPC 2.0 请求，并将响应输出到 stdout（每行一个 JSON 对象）。

必须响应的基础方法包括：
1. `voidb.initialize`
2. `voidb.health`
3. `voidb.invoke`

### 方式 A：使用 Rust (`voidb-process-plugin-sdk`)

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

### 方式 B：使用 Python 3

创建可执行脚本 `bin/my-plugin` 并赋予执行权限 (`chmod +x bin/my-plugin`)：

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

### 方式 C：使用 Go

参见 [`examples/process-plugins/example-go/main.go`](../examples/process-plugins/example-go/main.go)，编译为二进制放至 `bin/my-plugin` 即可。

---

## 第 4 步：测试与运行

### 方式 1：本地开发调试

使用 `VOIDB_PLUGIN_PATH` 环境变量指定开发目录进行扫描：

```bash
VOIDB_PLUGIN_PATH=/path/to/parent_of_my_plugin voidb-cli plugin list
VOIDB_PLUGIN_PATH=/path/to/parent_of_my_plugin voidb-cli plugin describe my-plugin
```

### 方式 2：正式安装使用

将插件目录直接拷贝或软链接至用户配置目录：

```bash
mkdir -p ~/.config/voidb/plugins
cp -r my-plugin ~/.config/voidb/plugins/
```

打开 VoidB 或运行 `voidb-cli plugin list`，VoidB 将会自动发现并加载该插件，并在 Connection Manager 中注册可选连接类型！
