# Process Plugin SDK

VoidB process plugins are local executables that speak the stable
`stdio-jsonrpc` protocol. The Rust SDK crate
`voidb-process-plugin-sdk` is the first authoring layer over that protocol.
For the full authoring path, see
[External Process Plugin Workflow](external-plugin-workflow.md).

It is intentionally small:

- manifest and capability builders for `plugin.toml` generation tools;
- schema helper constructors for simple JSON Schema files;
- a synchronous stdio JSON-RPC dispatcher for `voidb.initialize`,
  `voidb.health`, `voidb.invoke`, and `voidb.cancel`;
- a capability router keyed by manifest capability ID;
- structured error, target-error, redaction, and result helpers;
- re-exports of the stable protocol constants from `voidb-core`.

The SDK does not own target clients, connection pools, async runtimes, profile
storage, credential lookup, or TUI state. Plugins keep those behind their
handlers. VoidB continues to broker credential grants; SDK handlers receive
grant descriptors only, not plaintext secrets.

## Minimal Rust Shape

```rust
use serde_json::json;
use voidb_process_plugin_sdk::{
    CapabilityRouter, redacted_output_summary, serve_stdio, succeeded,
};

fn main() -> anyhow::Result<()> {
    let router = CapabilityRouter::new("hello-sql").capability("query", |invocation, _grants| {
        Ok(succeeded(
            invocation.id,
            json!({ "columns": ["answer"], "rows": [[42]] }),
            redacted_output_summary(json!({ "row_count": 1 })),
        ))
    });

    serve_stdio(router)?;
    Ok(())
}
```

Plugins with async target clients can create their own runtime inside the
handler closure or delegate to a worker thread. The SDK stays synchronous so it
can run in tiny examples and in non-Tokio plugin binaries.

## Manifest Builder Shape

```rust
use voidb_core::CapabilityRiskLevel;
use voidb_process_plugin_sdk::{CapabilityBuilder, ManifestBuilder};

let manifest = ManifestBuilder::new("hello-sql", "Hello SQL", "0.1.0", "hello-sql")
    .capability(
        CapabilityBuilder::new(
            "query",
            "Run a bounded read-only query.",
            "schemas/query-input.schema.json",
            "schemas/query-output.schema.json",
        )
        .permission("connection.read")
        .permission("sql.query")
        .risk(CapabilityRiskLevel::ReadOnly)
        .default_timeout_ms(1000)
        .build(),
    )
    .build();
```

The builder is for tooling and examples; installed plugins still ship a plain
`plugin.toml` plus schemas and runtime files. Discovery remains the source of
truth.

## Example Packages

Two local fixture packages live under `examples/process-plugins/`:

- `hello-sql`: read-only `query` and mutating `exec` with dry-run support.
- `hello-storage`: read-only `list`, mutating `put`, destructive `delete`, and
  external-side-effect `notify`, all backed by safe synthetic responses.

They are intentionally shell-based so they can be discovered and health-checked
without building anything:

```bash
VOIDB_PLUGIN_PATH=examples/process-plugins cargo run -p voidb-cli -- plugin list --format json
VOIDB_PLUGIN_PATH=examples/process-plugins cargo run -p voidb-cli -- plugin describe hello-sql --include capabilities,schemas --format json
```

The examples are not live database or cloud clients. They exist to show package
shape, manifest risk declarations, schema layout, and the request/response
contract with no secrets and no external services.

## Persistent Session Protocol

Protocol `1.1` adds optional `voidb.session.open`, `call`, `health`, `renew`,
`cancel`, and `close` methods. A plugin advertises support by returning
`session_protocol: "1"` from `voidb.initialize`. Protocol `1.0` plugins remain
available for stateless `voidb.invoke`; the host returns an explicit
`compatibility_fallback: "stateless"` error if a caller asks them for a session.

External plugins own every live driver, stream, child task, and remote handle.
The host supplies an opaque session ID, generation, grant/profile binding,
capability scope, and lease deadline. Returned `handle_id` values are opaque and
descriptors must be no larger than 4 KiB and contain no password-, token-,
secret-, or credential-shaped fields. Call output remains bounded and must
report redaction. The host serializes requests unless a future negotiated
extension explicitly permits multiplexing.

Plugins must cancel child work and close remote handles on `session.cancel` or
`session.close`. The runtime child is kill-on-drop, so host crashes do not leave
an external plugin process orphaned; plugins should additionally apply their
own lease deadline so an isolated child cannot retain target state indefinitely.
The SDK's default session methods fail closed with `plugin.session_unsupported`.

## Non-Rust SDK Feasibility

The process-plugin boundary is language-neutral because the runtime contract is
newline-delimited JSON-RPC over stdin/stdout. A minimal Python or TypeScript SDK
is feasible without weakening VoidB security if it follows the same constraints:

- use the same `plugin.toml` and JSON Schema package layout;
- read one UTF-8 JSON object per line from stdin and write one JSON-RPC response
  per line to stdout;
- keep stderr diagnostic-only and assume VoidB will redact it;
- implement `voidb.initialize`, `voidb.health`, `voidb.invoke`, and reserve
  `voidb.cancel`, plus the optional protocol `1.1` session lifecycle methods;
- receive credential grant descriptors only, never plaintext secrets in env,
  manifest files, or JSON-RPC params;
- return `CapabilityError` under `error.data` for structured failures;
- keep dry-run behavior local and deterministic for side-effecting
  capabilities.

The first recommended non-Rust prototype is Python because the standard library
already has line-oriented stdin/stdout, JSON parsing, and subprocess-friendly
packaging. TypeScript is also viable, but package-local Node runtime resolution
and cross-platform executable wrappers need more installation rules before it
should be promoted as the default external SDK.

## Validation Gate

For SDK or example changes, run:

```bash
cargo test -p voidb-process-plugin-sdk
cargo test -p voidb-core process_plugin
VOIDB_PLUGIN_PATH=examples/process-plugins cargo run -p voidb-cli -- plugin list --format json
git diff --check
```
