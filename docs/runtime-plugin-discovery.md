# Runtime Plugin Discovery

This document designs the first runtime discovery and process lifecycle model
for capability-first VoidB plugins. It complements:

- [Plugin Manifest Schema](plugin-manifest-schema.md), which defines
  `plugin.toml`.
- [Plugin Invocation Transport](plugin-invocation-transport.md), which defines
  `stdio-jsonrpc` messages after a process is started.
- [Secret Brokering and Redaction Policy](secret-brokering-redaction-policy.md),
  which defines what may cross process and agent boundaries.
- [Future Plugin Installation Model](plugin-installation-model.md), which
  defines how plugin directories are installed, updated, disabled, and removed.

## Scope

This slice defines installed plugin search paths, manifest validation,
on-demand process startup, crash handling, and version compatibility checks. The
current implementation includes manifest discovery, CLI reporting, and a
focused stdio JSON-RPC runtime host used by generic process-plugin invocation.
It does not implement installation commands, marketplace behavior, long-lived
process pooling, or a hosted plugin catalog. Installation lifecycle rules are
documented separately in
[Future Plugin Installation Model](plugin-installation-model.md).

The current in-workspace Rust plugin factories remain the v4 TUI mechanism
during migration. Process plugin discovery is the target contract for the new
capability-first CLI and protocol.

## Installed Plugin Layout

An installed process plugin is a directory containing a manifest and any files
referenced by that manifest:

```text
mysql/
  plugin.toml
  bin/
    voidb-plugin-mysql
  schemas/
    mysql-profile.schema.json
    query-input.schema.json
    query-output.schema.json
    exec-input.schema.json
    exec-output.schema.json
```

The directory name should match the manifest `id`. Core treats a mismatch as a
manifest validation error unless the root is an explicit development path.

Manifest-relative paths are resolved from the directory containing
`plugin.toml`. This includes:

- `runtime.command` when it contains a path separator.
- `connections.profile_schema`.
- every capability `input_schema`.
- every capability `output_schema`.

Bare runtime commands such as `voidb-plugin-mysql` are resolved in this order:

1. `<plugin-dir>/bin/<command>`
2. the operating system `PATH`, but only when the plugin came from
   `VOIDB_PLUGIN_PATH`

Production installers should prefer package-local executables under `bin/`.
User, system, and bundled roots must not rely on `PATH`; otherwise a manifest
could execute a different binary than the reviewed package-local runtime.
Development roots may rely on `PATH` for local iteration because the user opted
into that root explicitly.

## Search Paths

Core discovers installed process plugins from ordered roots. Higher-precedence
roots override lower-precedence roots only when the candidate is `available`.
Invalid or incompatible higher-precedence candidates remain visible for
diagnostics, but they do not block a lower-precedence available candidate with
the same plugin ID.

1. `VOIDB_PLUGIN_PATH`: explicit development override. It is a platform path
   list (`:` on Unix-like systems, `;` on Windows). Each entry is a plugin root
   that may contain one or more plugin directories. Trust level:
   `explicit_development`.
2. User install root:
   - macOS: `~/Library/Application Support/voidb/plugins`
   - Linux: `${XDG_DATA_HOME:-~/.local/share}/voidb/plugins`
   - Windows: `%APPDATA%\voidb\plugins`
   Trust level: `user_installed`.
3. System install root:
   - macOS: `/Library/Application Support/voidb/plugins`
   - Linux: `/usr/local/share/voidb/plugins`, then `/usr/share/voidb/plugins`
   - Windows: `%ProgramData%\voidb\plugins`
   Trust level: `administrator_managed`.
4. Bundled app resource root, when a packaged VoidB distribution ships process
   plugins.
   Trust level: `bundled`.

Core must not scan the current working directory by default. Opening a project
or repository should not implicitly execute process plugins from that
repository. Development roots must be explicit through `VOIDB_PLUGIN_PATH` or a
future trusted dev-mode config.

## Discovery Algorithm

Discovery builds a read-only registry of candidates:

1. Collect roots in precedence order.
2. For each root, list immediate child directories, ignoring dot-prefixed
   install-manager metadata directories.
3. For each child directory, look for `plugin.toml`.
4. Parse `plugin.toml` as TOML.
5. Convert the parsed value to JSON-compatible data.
6. Validate it against
   [`schemas/plugin-manifest.schema.json`](../schemas/plugin-manifest.schema.json).
7. Run semantic validation checks that JSON Schema cannot express.
8. Resolve manifest-relative paths.
9. Record a candidate as `available`, `invalid`, `incompatible`, or
   `disabled`.
10. Build the effective registry by plugin ID, keeping the highest-precedence
    available candidate and recording lower-precedence available candidates as
    `shadowed` for diagnostics.

Discovery should be deterministic. CLI output should sort plugin IDs and
capability IDs lexicographically unless a user-facing command explicitly asks
for discovery order.

## Manifest Validation

JSON Schema validation checks field shape. Semantic validation checks project
rules:

- `$schema`, when present, references the supported VoidB process-plugin
  manifest schema URI.
- directory name matches `id`, except explicit development paths may opt out.
- `id` is unique in the effective registry.
- `protocol_version` is supported by Core.
- `runtime.transport` is supported by Core.
- `runtime.command` resolves to an executable file or a command that can be
  found in `PATH` from an explicit development root.
- referenced profile, input, and output schemas exist and parse as JSON.
- remote schema references may use `http` or `https`; local discovery records a
  warning and never fetches them.
- capability IDs are unique within the plugin.
- `ui.entrypoint_capability`, when present, references an existing capability.
- every capability `required_secret_classes` value appears in
  `connections.secret_classes`.
- stateless capabilities cannot request profile secret classes.
- destructive capabilities declare at least one permission string.
- destructive operations are explicitly marked with `destructive = true`.
- streaming capabilities use a transport that supports stream notifications.
- `requirements.platforms`, when present, includes the current platform.
- `requirements.voidb_core`, when present, is compatible with the current Core
  version.

Invalid manifests must not be partially loaded. Core may display validation
errors in `voidb plugin list --format json`, but errors must not include
plaintext secrets, environment values, plugin stderr, or unredacted filesystem
content.

## Candidate States

Discovery records these candidate states:

| State | Meaning |
|---|---|
| `available` | Manifest is valid, compatible, and can be launched on demand. |
| `invalid` | Manifest or referenced schemas failed validation. |
| `incompatible` | Manifest is valid but requires an unsupported Core, protocol, transport, or platform. |
| `shadowed` | A lower-precedence candidate uses an ID already provided by a valid higher-precedence candidate. |
| `disabled` | Candidate is valid but disabled by user or policy. |
| `failed` | Candidate was available, but the most recent process lifecycle failed. |

Candidate state is discovery metadata. It does not modify the manifest file.
The current discovery MVP can parse and report `disabled`, but disabled state
is expected to come from the VoidB-owned install record or policy layer rather
than from `plugin.toml`.

Disabled candidates are never effective invocation targets. They also do not
shadow lower-precedence available candidates with the same plugin ID; only an
available higher-precedence candidate wins shadowing. Runtime hosts reject
disabled candidates with `unavailable.process_plugin_candidate_not_available`.

## On-Demand Process Startup

Process plugins are started lazily:

1. CLI or Core needs plugin metadata, a health check, or an invocation.
2. Core resolves the effective candidate by plugin ID.
3. The current runtime host rejects every candidate not in `available` state.
   A future long-lived supervisor may treat `failed` as recoverable after the
   restart backoff window.
4. Core starts `runtime.command` with `runtime.args`.
5. Core clears inherited environment, applies non-secret manifest
   `runtime.env`, and then overwrites Core-owned runtime variables:
   - `VOIDB_PLUGIN_ID`
   - `VOIDB_PLUGIN_DIR`
   - `VOIDB_PROTOCOL_VERSION`
   - `VOIDB_LOG_FORMAT=json`
6. Core connects stdin, stdout, and stderr pipes.
7. Core sends `voidb.initialize` and waits for a ready response.
8. Core sends `voidb.health` before first invocation when the plugin did not
   return ready state from initialization.
9. Core marks the process `ready` and dispatches queued invocation work.

Core owns process lifecycle. Plugins own protocol-specific runtime state,
target connections, workers, and cleanup behind the process boundary.

## Process Pooling And Idle Shutdown

The first runtime model should use one process per plugin ID per VoidB Core
process. It may be extended later to support pool members, isolation classes,
or per-profile processes.

Suggested defaults:

- Start on demand.
- Reuse one ready process for concurrent invocations when the plugin declares
  the capability safe for concurrency in a future manifest field.
- Otherwise serialize invocations per plugin process.
- Send `voidb.health` before dispatch after long idle periods.
- Shut down idle processes after a configurable timeout, such as five minutes.

Shutdown should be graceful first. A future transport method may add
`voidb.shutdown`; until then, Core can close stdin and wait for process exit,
then terminate if the grace period expires.

## Crash Handling

When a plugin process exits unexpectedly or violates the transport contract:

1. Mark the process as failed.
2. Fail active invocations with `category = "plugin"` and a stable code such as
   `plugin.crashed` or `plugin.protocol_violation`.
3. End active streams with a terminal failed status when possible.
4. Redact stderr and include only a safe diagnostic summary in logs, CLI
   output, and audit metadata. The summary may include byte count, configured
   byte limit, truncation status, and a fixed redacted-content placeholder, but
   never raw stderr text.
5. Release credential grants associated with active invocations or instances.
6. Apply restart backoff before launching the plugin again.

Suggested restart policy:

- first failure: restart allowed immediately for the next invocation
- repeated failures: exponential backoff with jitter
- repeated failures inside a short window: mark candidate `failed` and require
  explicit user action or a later health retry

The current focused runtime host starts a fresh short-lived process for each
health check or invocation, so there is no pooled process to restart. Crash
handling is still structured and redacted; the full `failed` state and restart
backoff policy belong to the future pooled supervisor.

Core should distinguish target-system failures from plugin process failures.
If a database rejects a query, the error is `target_system`. If the plugin
crashes while handling the query, the error is `plugin`.

## Version Compatibility

Compatibility has three layers:

1. Manifest schema version: the structure of `plugin.toml`.
2. Process protocol version: the JSON-RPC methods and message shapes.
3. Plugin package version: the plugin's own semantic version.

The current draft uses:

- `plugin.toml` validated by
  [`schemas/plugin-manifest.schema.json`](../schemas/plugin-manifest.schema.json).
- `protocol_version = "1"` for `stdio-jsonrpc`.
- semantic `version` for plugin package identity and updates.

Core compatibility rules:

- Reject unknown major protocol versions.
- Allow compatible minor protocol versions only when Core has explicit support.
- Reject manifests whose `requirements.voidb_core` excludes the current Core
  version.
- Reject manifests whose `requirements.platforms` excludes the current
  platform.
- During `voidb.initialize`, the plugin must echo the selected
  `protocol_version`.
- If a plugin selects a different version than Core requested, Core rejects the
  process unless the version was explicitly offered by Core.

Version errors use `category = "plugin"` or `category = "unavailable"` with
stable codes such as `plugin.protocol_unsupported` or
`plugin.core_incompatible`.

## Security Boundaries

Discovery and startup must preserve the existing local trust boundary:

- Manifest files are metadata and must not contain plaintext credentials.
- Core does not pass plaintext secrets in environment variables.
- Core does not pass plaintext secrets in JSON-RPC messages.
- Plugin stderr is untrusted diagnostics and must be redacted before display or
  persistence.
- Core must not execute plugins from the current working directory by default.
- Manifest-relative paths must stay within the plugin directory unless a field
  explicitly allows URI or absolute path behavior.
- User-installed plugins are local code execution. VoidB should present them as
  trusted local extensions, not as a sandbox boundary.
- Discovery output includes a root trust level so agents can distinguish
  explicit development overrides from user-installed, administrator-managed,
  and bundled process plugins.

## Invariants

- Discovery is deterministic and produces machine-readable candidate state.
- Only validated, compatible candidates are launchable.
- Higher-precedence available roots shadow lower-precedence available roots by
  plugin ID; invalid or incompatible candidates stay diagnostic-only.
- Process startup is lazy and begins with `voidb.initialize`.
- `voidb.health` is the first recovery probe for questionable process state.
- Crashes fail active invocations with structured `plugin` errors.
- Credential grants are scoped to invocation or runtime instance lifetime and
  are released on crash.
- Version compatibility is checked before dispatching invocation work.

## Focused Regression Gate

Run this gate for changes to discovery roots, manifest compatibility, runtime
command resolution, stdio process lifecycle, timeout/cancellation behavior,
crash diagnostics, stderr redaction, or generic process-plugin invocation:

```bash
cargo test -p voidb-core process_plugin
cargo test -p voidb-core process_plugin_runtime
cargo test -p voidb-cli plugin
cargo test -p voidb-cli invoke
git diff --check
```

The gate is deterministic and uses in-test fixture plugins. It does not require
installing external plugin packages or connecting to external services. Broader
release-candidate gates are listed in [CI Check Tiers](ci-checks.md) and the
[Security Release Checklist](security-release-checklist.md).
