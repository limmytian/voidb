# Migration Compatibility Notes

This document lists the compatibility risks that must be preserved or handled
while VoidB migrates from the v4 TUI-centered plugin model toward the
capability-first CLI and process-plugin architecture.

The migration must be additive until the new profile, credential, policy,
audit, plugin discovery, and invocation contracts can round-trip existing
behavior. Existing users should not need to rewrite configuration files,
install process plugins, or depend on removed router-hosted TUI factories. The
replacement contract is CLI/capability/service first; future plugin-owned TUIs
must be introduced as new surfaces with their own evidence.

## Compatibility Baseline

The current v4 system has these user-visible compatibility anchors:

- saved connections are persisted as `ConnectionConfig` values in the app
  config;
- plugin-specific connection details live in encrypted
  `ConnectionConfig.plugin_config`;
- `ConnectionConfig.effective_plugin_id()` falls back from `plugin_id` to the
  legacy `DatabaseType` protocol name;
- connection identity uses `"{effective_plugin_id}::{name}"`, so different
  plugins may have the same display name;
- the default TUI registers shell-owned built-ins such as the Connection
  Manager at startup;
- old database browser/table/query-editor factories and old non-database
  router-hosted plugin factories have been removed;
- the CLI registers built-in CLI plugins at startup and dispatches through
  per-plugin command handlers;
- protocol plugins keep driver access inside plugin-owned service layers, with
  channel mode for the TUI and direct mode for the CLI.

These anchors remain the rollback target until the capability-first model has
production migration code and tests.

## Existing Config Compatibility

`ConnectionConfig` remains the storage-backed compatibility adapter during the
transition. New public surfaces may expose `ConnectionProfile`, but they must
load existing config files without requiring a one-way rewrite.

Compatibility risks:

| Risk | Impact | Mitigation | Exit criteria |
|---|---|---|---|
| Config rewrite changes encrypted `plugin_config` shape. | Users can lose credentials or protocol-specific settings. | Read existing values through an adapter and only write after explicit user edits or a tested migration command. | Existing `config.toml` fixtures load, inspect, test, and save without losing plugin fields. |
| Profile migration treats `plugin_config` as agent-safe metadata. | Secrets or sensitive target-system data can appear in CLI, logs, sync, or audit. | Keep decrypted plugin config behind credential brokering and redaction; expose only schema-classified non-secret fields. | Profile inspect, capability discovery, audit, and sync outputs pass redaction tests. |
| `plugin_id` aliases drift from legacy database protocol names. | Existing PostgreSQL configs may route differently from new process plugin IDs. | Preserve alias mapping for legacy IDs such as `postgresql` and plugin IDs such as `postgres`; avoid normalizing in persisted storage until migration is explicit. | Old configs and new profiles resolve to the same plugin across TUI and CLI tests. |
| `connection_key()` semantics change. | Tabs, saved UI context, duplicate names, and plugin-specific profile lookup can collide. | Keep composite identity during the adapter phase and map profile IDs separately from display names. | Duplicate names across plugins remain valid and tab reopen behavior is stable. |
| Default encryption behavior is mistaken for the future credential broker. | Sync or agent features may overstate secret isolation. | Document current encryption as a storage compatibility layer; do not treat it as a cross-device credential record format. | Credential broker work owns all plaintext grant, redaction, and syncable encrypted record semantics. |
| A failed migration has no rollback path. | Users cannot recover working local config. | Make migrations backup-first, versioned, and reversible where practical. | Migration commands produce a backup and can report which profiles changed. |

Config migration rules:

1. Load legacy `ConnectionConfig` values first and adapt them to profile views.
2. Do not delete unknown plugin-specific JSON fields.
3. Do not print decrypted `plugin_config` by default.
4. Do not require installed process plugins before existing built-in configs can
   appear in the TUI or CLI.
5. Treat destructive policy defaults as deny-by-default until a migrated
   profile explicitly carries policy.

### Legacy Profile Adapter Identity Contract

The adapter from `ConnectionConfig` to `ConnectionProfile` has two identities to
preserve during the migration:

- Legacy connection identity remains `ConnectionConfig.connection_key()`, which
  is `"{effective_plugin_id}::{name}"`. TUI tabs, config replacement, duplicate
  display names, and old CLI lookup behavior continue to depend on this key.
- Capability-facing profile identity is a separate generated profile ID. It is
  derived from the legacy connection key for stability, but it is not equal to
  the key and must not require rewriting existing config files.

Adapter rules:

1. `ConnectionConfig.name` becomes the plugin-scoped profile name for the
   legacy view. Duplicate aliases across plugins are allowed during migration;
   profile commands must treat ambiguous bare aliases as a resolution error.
2. `ConnectionConfig.effective_plugin_id()` remains the source for legacy
   routing metadata and the connection key.
3. The legacy PostgreSQL fallback ID `postgresql` maps to capability-facing
   plugin ID `postgres` at the profile boundary only. Stored configs and
   `connection_key()` are not normalized by the adapter.
4. Explicit plugin IDs such as `postgres`, `mysql`, `sqlite`, or `redis` remain
   unchanged in both the legacy key and the capability-facing plugin ID unless a
   documented alias rule applies.
5. Adapter metadata may include legacy routing fields such as connection key,
   legacy plugin ID, database type, and whether plugin config exists. It must
   not include decrypted `plugin_config` values.

## TUI User Compatibility

The default TUI remains a supported application surface during the migration,
but it is now a shell-owned profile catalog, handoff surface, and compatibility
launcher. The pure router shell continues to own tabs, hard globals, soft
globals, and event routing. Retained plugin TUIs launch from plugin CLI
commands; router-hosted plugin factories are opt-in compatibility only.

Compatibility risks:

| Risk | Impact | Mitigation | Exit criteria |
|---|---|---|---|
| Capability-first work bypasses the Connection Manager. | Existing users cannot create, edit, test, or open connections in the TUI. | Keep Connection Manager wired to the legacy config adapter until a profile-native UI exists. | Existing connection CRUD and open-tab flows still work in smoke tests. |
| Shell key routing changes while plugins migrate. | `Ctrl+Q`, `Ctrl+\`, `q`, `Q`, `Ctrl+L`, and raw-input plugins regress. | Keep router-level key behavior independent from capability invocation work. | TUI event-routing tests or manual checklist cover raw and non-raw plugins. |
| Table/browser UI is downscoped before CLI capabilities replace it. | Users lose database inspection and editing workflows. | Apply the downscoping plan only after profile and capability contracts can serve equivalent read/query paths. | SQL browser deprecations name a replacement command or adapter. |
| Users expect old non-database plugin tabs in the default shell. | Old interactive plugin tabs are no longer available. | Document CLI/capability replacements and require any future TUI to pass the plugin-owned rebuild gate. | README, roadmap, and migration docs describe CLI/capability as the stable surface. |
| Tab context expects legacy connection IDs. | Existing plugin tabs cannot reopen or route requests after profile IDs appear. | Keep legacy connection IDs in tab context during adapter phase and add profile IDs as optional metadata. | Opening browser/table tabs works from both legacy config and profile views. |
| Errors from process plugins use a different display model. | TUI status lines become inconsistent or leak implementation details. | Convert structured errors to concise TUI-safe status text, with details available through logs or inspect commands. | TUI displays stable, redacted target and plugin errors. |

TUI compatibility rules:

1. Do not make process-plugin discovery a prerequisite for running the default
   TUI shell.
2. Keep the TUI service path non-blocking by preserving channel mode.
3. Keep plugin-owned UI state out of Core profile and capability types.
4. Add profile/capability adapters beside existing dialogs before removing
   legacy config forms.
5. Treat future plugin TUIs as new plugin-owned work; do not restore old
   router-hosted compatibility features.

## Built-In Plugin Factory Compatibility

Runtime process-plugin discovery is the target for capability-first plugins,
but the current built-in Rust plugin crates remain part of the packaged
workspace. The default TUI registers only shell-owned built-ins. Protocol,
infrastructure, storage, and sync crates remain built-in service, CLI, and
capability providers; router-hosted factories have been removed.

Compatibility risks:

| Risk | Impact | Mitigation | Exit criteria |
|---|---|---|---|
| Built-in plugins are treated as user-installed process plugins. | Packaged TUI builds can fail unless users install duplicate plugin directories. | Model built-ins as a separate provider during migration. Process discovery is additive. | A clean build can run the TUI with no user plugin root. |
| Built-in and process plugins share an ID. | Discovery or invocation can silently choose the wrong implementation. | Define deterministic precedence and shadowing diagnostics before enabling process plugins for IDs that also exist as built-ins. | `voidb plugin list --format json` can explain active and shadowed providers. |
| Built-in connection dialogs diverge from process plugin profile schemas. | Users edit one shape in the TUI and invoke another shape in the CLI. | Keep schema adapters close to each plugin and test legacy config to profile conversion per plugin. | SQLite and Redis migration pair can round-trip legacy config and capability profile metadata. |
| Built-in factory APIs are removed before replacements exist. | Default shell startup or Connection Manager behavior can regress. | Keep only shell-owned factories in the TUI and prove protocol work through CLI/capability tests. | The default TUI starts without protocol plugin UI crates and plugin CLI/capability tests pass. |
| Optional or experimental plugins block app startup. | One broken plugin prevents unrelated built-ins from loading. | Keep factory registration deterministic and make future discovery failures per-candidate, not global. | Invalid process plugins do not prevent built-in factories from registering. |

Built-in plugin migration rules:

1. Migrate one protocol pair at a time instead of moving every built-in plugin
   to process execution in one step.
2. Keep plugin IDs stable and document any alias mapping.
3. Keep connection test and display providers working until profile schemas own
   that metadata.
4. Treat process-plugin manifests as the future public contract, not as a
   replacement for existing Rust factories in the same slice.
5. Keep router-hosted plugin factories out of builds; future UI work must be
   plugin-owned and independently gated.

## Service-Layer Direct Mode Compatibility

Current CLI commands call plugin services directly from async command handlers.
The TUI uses channel mode so plugin work does not block rendering. This split
is a compatibility strength and should survive the capability-first migration.

Compatibility risks:

| Risk | Impact | Mitigation | Exit criteria |
|---|---|---|---|
| `voidb invoke` calls TUI channel APIs. | CLI invocations become stateful, hard to test, or block on UI lifecycles. | Route capabilities into direct service methods or process-plugin transport, never through TUI widgets. | Capability tests can run headless without ratatui or crossterm imports. |
| Direct mode is removed while existing CLI subcommands still use it. | Current scriptable commands regress. | Keep existing CLI plugin commands and add generic invocation beside them. | Existing CLI command tests pass while `voidb invoke` tests are added. |
| Service modules start depending on profile or transport UI types. | Driver code leaks into Core or TUI concerns leak into services. | Preserve service-layer invariants: no TUI imports, domain return types, explicit parameters. | Service validation checks remain clean after capability adapters are added. |
| `!Send` drivers are invoked from the wrong thread. | SQLite and DuckDB can panic or corrupt service behavior. | Continue using `SyncWorker` for SQLite and DuckDB; direct capability handlers must respect their worker model. | SQLite and DuckDB direct-mode tests cover query and mutation paths. |
| Sync plugin is forced into the standard service folder pattern. | Existing sync command surface becomes awkward or regresses. | Keep Sync on its dedicated `ops`, client, and server modules while applying the same CLI safety rules. | Sync CLI commands continue to pass tests and remain opt-in. |

Direct-mode migration rules:

1. Capability handlers should reuse existing service methods before adding new
   driver access paths.
2. TUI plugins must not import database driver crates directly as part of
   capability migration.
3. New process-plugin transport code should preserve structured errors and
   execution controls without weakening existing direct CLI behavior.
4. Existing per-plugin CLI subcommands remain compatibility commands until the
   generic invocation surface is stable.

## Sync And Installation Compatibility

Sync and plugin distribution must stay behind the local profile, credential,
policy, audit, discovery, and invocation contracts.

Compatibility risks:

| Risk | Impact | Mitigation | Exit criteria |
|---|---|---|---|
| Sync copies plugin binaries or treats install roots as portable state. | Devices can execute unreviewed code or receive unusable binaries. | Sync only plugin identity and compatibility metadata; install code locally. | Synced profiles can report `plugin_missing` without modifying install roots. |
| A synced profile requires a plugin that is not present locally. | Users may think profile data is corrupt. | Keep the profile visible but unavailable, with a clear missing or incompatible plugin status. | Listing and inspecting unavailable profiles is safe and redacted. |
| Plugin updates change profile schema without a migration model. | Saved profiles may become unreadable. | Treat profile schema changes as compatibility-sensitive until explicit migration machinery exists. | Install/update commands can block, warn, or require confirmation for schema changes. |
| Current full-directory sync becomes the public profile contract. | Local file layout freezes and future object-level sync gets harder. | Keep current sync opt-in and document it as compatibility backup behavior. | Default sync waits for object-level profile and credential records. |

## Review Checklist

Use this checklist before landing any slice that changes profile, plugin,
capability, sync, or service boundaries:

- Existing `ConnectionConfig` files load without a forced rewrite.
- Decrypted `plugin_config` is not printed, logged, synced, or audited by
  default.
- Duplicate connection display names across plugins still resolve correctly.
- Legacy plugin IDs and aliases route consistently in TUI and CLI paths.
- The default TUI starts with shell-owned built-ins and no user plugin install
  root.
- Connection Manager can still list, edit, test, and open existing
  connections.
- Shell key routing stays intact for shell-owned surfaces.
- Future standalone plugin TUI commands must pass PTY startup, resize, quit,
  cleanup, and transcript redaction gates before shipping.
- Existing CLI subcommands still dispatch through direct service mode.
- New capability handlers reuse plugin services or process transport instead
  of importing driver crates into TUI or Core.
- SQLite and DuckDB continue to respect their worker-thread model.
- Sync remains opt-in and does not sync plugin binaries.
- Missing or incompatible plugins make profiles unavailable, not corrupt.
- Rollback and backup behavior is documented for any persistent migration.

## Non-Goals

- Implementing profile migration code in this slice.
- Removing built-in Rust plugin crates or compatibility factory APIs
  immediately.
- Replacing existing CLI subcommands with `voidb invoke`.
- Defining marketplace, hosted catalog, or remote trust behavior.
- Making current encrypted `plugin_config` a cross-device credential record
  format.
