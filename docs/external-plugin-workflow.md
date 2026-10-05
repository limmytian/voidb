# External Process Plugin Workflow

This workflow is for authors building a process plugin outside the VoidB TUI
plugin crates. It builds on:

- [Process Plugin SDK](process-plugin-sdk.md)
- [Plugin Manifest Schema](plugin-manifest-schema.md)
- [Plugin Invocation Transport](plugin-invocation-transport.md)
- [Runtime Plugin Discovery](runtime-plugin-discovery.md)
- [Plugin Conformance And Certification](plugin-conformance.md)

The goal is a local package directory that VoidB can discover, validate,
health-check, certify, and invoke through the same capability path as bundled
plugins.

## 1. Pick The Package Shape

Start with one plugin directory:

```text
hello-sql/
  plugin.toml
  bin/
    hello-sql
  schemas/
    profile.schema.json
    query-input.schema.json
    query-output.schema.json
```

The directory name should match `plugin.toml` `id` outside explicit
development roots. Use lowercase IDs with hyphens for plugin IDs and stable,
short capability IDs.

Keep package files non-secret:

- no plaintext credentials in `plugin.toml`;
- no plaintext credentials in schemas, README files, examples, or installer
  metadata;
- no generated local state or synced profile data in the plugin package.

## 2. Declare Capabilities Conservatively

Every capability needs:

- `input_schema` and `output_schema`;
- explicit `permissions`;
- `risk`;
- legacy `destructive` compatibility flag;
- `supports_dry_run` when the capability can plan without changing target
  state.

Risk guidance:

| Risk | Use For | Notes |
|---|---|---|
| `read_only` | Queries, list operations, diagnostics. | Do not mutate target state. |
| `mutating` | Creates or updates target state. | Prefer dry-run support. |
| `destructive` | Deletes, drops, overwrites, or irreversible changes. | Requires acknowledgement unless policy allows dry-run only. |
| `external_side_effect` | Email, CI triggers, SSH commands, webhooks, Docker/K8s actions. | Treat as externally visible even if no local data changes. |

When unsure, choose the higher risk. Policy and audit are only useful when the
manifest does not understate behavior.

## 3. Implement The Runtime

Rust plugins can use `voidb-process-plugin-sdk`:

```rust
use serde_json::json;
use voidb_process_plugin_sdk::{CapabilityRouter, serve_stdio, succeeded};

fn main() -> anyhow::Result<()> {
    let router = CapabilityRouter::new("hello-sql").capability("query", |invocation, _grants| {
        Ok(succeeded(
            invocation.id,
            json!({ "columns": ["answer"], "rows": [[42]] }),
            json!({ "row_count": 1 }),
        ))
    });

    serve_stdio(router)?;
    Ok(())
}
```

Non-Rust runtimes are valid when they implement the same line-delimited
JSON-RPC contract:

1. read one UTF-8 JSON object per line from stdin;
2. write exactly one JSON-RPC response per Core request to stdout;
3. keep stderr diagnostic-only;
4. implement `voidb.initialize`, `voidb.health`, and `voidb.invoke`;
5. reserve `voidb.cancel`;
6. return `CapabilityError` under `error.data` for failures.

Never receive or print plaintext secrets. VoidB passes credential grant
descriptors, not credential material.

## 4. Run Local Protocol Smoke

Before using VoidB discovery, smoke-test the executable directly:

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":"initialize","method":"voidb.initialize","params":{"protocol_version":"1","plugin_id":"hello-sql"}}' \
  '{"jsonrpc":"2.0","id":"health","method":"voidb.health","params":{"include_runtime":true}}' \
  | env -i \
      VOIDB_PLUGIN_ID=hello-sql \
      VOIDB_PLUGIN_DIR="$PWD/hello-sql" \
      VOIDB_PROTOCOL_VERSION=1 \
      VOIDB_LOG_FORMAT=json \
      ./hello-sql/bin/hello-sql
```

Expected responses use `jsonrpc = "2.0"`, echo each request `id`, and report
`status = "ready"` for initialization and health.

## 5. Discover Locally

Use `VOIDB_PLUGIN_PATH` for development. The variable points at a root that
contains one or more plugin directories:

```bash
VOIDB_PLUGIN_PATH=examples/process-plugins \
  cargo run -p voidb-cli -- plugin list --format json

VOIDB_PLUGIN_PATH=examples/process-plugins \
  cargo run -p voidb-cli -- plugin describe hello-sql \
    --include runtime,connections,capabilities,schemas,diagnostics \
    --format json
```

The candidate should be `available`. If it is `invalid` or `incompatible`, fix
the manifest, schemas, platform requirements, runtime command, or protocol
version before continuing.

## 6. Invoke Through VoidB

Generic invocation uses `voidb invoke run <plugin>.<capability>`.

```bash
VOIDB_PLUGIN_PATH=examples/process-plugins \
  cargo run -p voidb-cli -- invoke run hello-sql.query \
    --profile name:hello-dev \
    --input-json '{"sql":"select 42","limit":1}' \
    --format json
```

Current CLI invocation still requires a profile reference even for stateless
process-plugin examples. For local development, create or migrate a development
profile for the plugin before using `invoke run`, or use the direct protocol
smoke in step 4 while iterating on handler logic.

Side-effecting capabilities should be exercised in both dry-run and confirmed
forms:

```bash
voidb invoke run hello-storage.delete \
  --profile name:hello-dev \
  --input-json '{"key":"hello.txt"}' \
  --dry-run \
  --format json

voidb invoke run hello-storage.delete \
  --profile name:hello-dev \
  --input-json '{"key":"hello.txt"}' \
  --yes \
  --format json
```

Do not use live destructive targets for initial SDK validation. Use disposable
fixtures with deterministic outputs.

## 7. Add Conformance Evidence

Static conformance starts from discovery output:

```rust
use voidb_core::{
    PluginMaturityLevel, certify_process_plugin_candidate,
    discover_process_plugins_from_roots,
};
```

For experimental readiness, the candidate should pass static checks for:

- available state;
- manifest identity and semver;
- supported protocol and transport;
- resolvable runtime command;
- valid profile/input/output schemas;
- explicit risk and permissions;
- dry-run declarations that match side-effecting behavior.

For beta or stable readiness, add deterministic runtime evidence for:

- structured errors;
- redaction;
- timeout behavior;
- cancellation behavior;
- health checks;
- invocation audit events.

Use [Plugin Conformance And Certification](plugin-conformance.md) for report
shape, maturity levels, and promotion decisions. Missing live credentials should
be recorded as skipped live checks with a clear opt-in fixture, not hidden.

## 8. Package For Installation

Until `voidb plugin install` lands, installation is a local copy into a
documented plugin root or an explicit `VOIDB_PLUGIN_PATH` development root.

Package checklist:

- `plugin.toml` at the plugin directory root;
- package-local executable under `bin/`;
- every referenced JSON Schema under `schemas/` or a documented URI;
- README and LICENSE;
- no plaintext secrets, profile data, device state, or generated audit logs;
- executable bits set for runtime files on Unix-like systems.

Future installers will validate the same shape before atomically activating the
directory.

## 9. Release Checklist

Before asking VoidB to promote a plugin:

- `cargo test -p voidb-process-plugin-sdk` passes if using the Rust SDK;
- `VOIDB_PLUGIN_PATH=<root> voidb plugin list --format json` reports
  `available`;
- `voidb plugin describe <id> --include capabilities,schemas,diagnostics`
  shows no blocking diagnostics;
- direct protocol smoke covers initialize, health, success, structured error,
  and timeout paths;
- dry-run fixtures prove side-effecting capabilities can plan safely;
- conformance report has no blocking failures for the target maturity;
- documentation names unsupported operations and live-test opt-in requirements.

External plugins are trusted local code. Treat authoring, installation, and
updates like package management, not like loading untrusted data.
