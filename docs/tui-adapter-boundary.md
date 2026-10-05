# TUI Adapter Boundary

This document defines how VoidB TUI surfaces consume core profiles,
capabilities, and plugin services after the capability-first migration. It is
part of Requirement 05 and follows
[TUI Workflow Classification](tui-workflow-classification.md).

The purpose is narrow: keep the TUI valuable for human interaction without
letting it become the authoritative plugin contract again.

## Decision

The TUI is an optional frontend. It is not the core plugin API, the agent
interface, or the source of truth for protocol behavior.

Core profiles, capability definitions, capability invocations, structured
errors, redaction policy, and audit records are the authoritative contract for
agents and automation. TUI plugins adapt that contract to keyboard-driven
human workflows.

TUI plugins may own presentation, local interaction state, and long-lived human
sessions. They must not own profile persistence, credential brokering,
capability schemas, destructive-operation policy, audit semantics, or target
protocol behavior.

## Ownership Model

| Layer | Owns | Must not own |
|---|---|---|
| Core capability model | `ConnectionProfile`, `ConnectionInstanceDescriptor`, `CapabilityDefinition`, `CapabilityInvocation`, invocation controls, structured results, audit model. | Live database, SSH, storage, or service handles. |
| Profile and secret layer | Profile CRUD, profile validation, credential references, secret brokering, redaction rules. | TUI rendering or plugin-specific live connection state. |
| Plugin service layer | Driver/client integration, connection lifecycle, workers, pools, direct/channel modes, typed commands, typed events, target error mapping. | Shell tabs, global shortcuts, core profile persistence, credential plaintext exposure. |
| TUI adapter | Rendering, local UI state, key/mouse handling after shell routing, cursor/selection state, dialogs, progress display, tab titles, render requests. | Protocol schemas, persistence formats, secret handling, audit policy, CLI/agent output contracts. |
| Shell | Tab lifecycle, hard/soft global shortcuts, plugin factory routing, dependency injection through `ShellCapabilities`. | Plugin layout, plugin focus model, target protocol execution, plugin service logic. |

This preserves the v4 shell architecture while moving public protocol contracts
out of TUI-only state.

## Boundary Invariants

- A saved profile is configuration, not a live connection and not a singleton.
- A runtime instance belongs to a plugin service. Core may describe it, but it
  does not hold the live driver handle.
- A capability invocation is the unit of agent-facing execution, timeout,
  cancellation, pagination, structured error reporting, redaction, and audit.
- TUI code renders and steers workflows; it does not define capability
  semantics.
- TUI actions that are also useful to agents must be backed by a service
  command or capability handler before they become a polished UI feature.
- TUI mutations must follow the same validation, policy, destructive-operation,
  and credential paths as CLI/capability execution.
- `ShellCapabilities` remains the only shell-to-plugin dependency injection
  surface.
- TUI plugins must not import database, storage, or protocol driver crates
  directly when a service layer exists for that protocol.

## Allowed TUI Dependencies

A TUI plugin may depend on:

- `voidb-core` types needed for plugin registration, shell capabilities,
  profile references, capability metadata, and clipboard/tab integration.
- Its own crate's service commands, service events, connection config adapter,
  and UI-local state types.
- `ShellCapabilities` for tabs, render requests, clipboard, plugin registry,
  and the shared runtime handle.
- `ConnectionConfigRegistry` during the transition, treating
  `ConnectionConfig` as a storage adapter for future `ConnectionProfile`
  behavior.

A TUI plugin must not depend on:

- target driver crates directly, such as SQL, Redis, SSH, storage, or cloud SDK
  crates, when those calls belong in the plugin service layer;
- plaintext credential material or decryption internals;
- ad hoc JSON formats that duplicate capability schemas;
- CLI output formatting or agent response contracts;
- shell internals outside `ShellCapabilities`.

## Consumption Flow

TUI surfaces should consume profiles and capabilities through this flow:

1. The user selects or creates a profile through the Connection Manager or a
   future profile service.
2. The TUI resolves display-safe profile metadata from core/profile APIs. It
   may show aliases, labels, plugin IDs, endpoint summaries, and validation
   status, but not plaintext secrets.
3. The TUI starts a plugin service in channel mode for interactive sessions, or
   routes a finite operation through the same service/capability handler used
   by CLI execution.
4. The service owns target clients, runtime instances, workers, reconnection,
   pooling, and protocol errors.
5. The service emits typed events or returns structured results.
6. The TUI renders those events/results and requests repaint through
   `caps.tabs.request_render()` when asynchronous work changes visible state.
7. Any mutation or destructive operation uses the shared validation,
   confirmation, policy, redaction, and audit path.

This flow permits rich terminal UI behavior without making TUI state the only
way to execute a protocol operation.

## Current Transition Rule

The existing `ConnectionConfig` remains the persistence shape during the
transition. New TUI work should treat it as a storage-backed profile adapter,
not as the final public model.

When adding or changing a TUI workflow:

1. Identify the profile reference and capability/service command behind the
   action.
2. Put target protocol work in the service layer.
3. Add service or capability tests for behavior that agents and CLI users will
   rely on.
4. Keep TUI tests focused on interaction wiring, rendering state, and key
   routing.
5. Avoid broad UI expansion until the underlying command contract is stable.

## Workflow Examples

### SQL Query Editor

The TUI may provide a human query editor, schema picker, and result grid. Query
execution still belongs to a SQL service command or `query` capability. The TUI
passes SQL text, profile reference, pagination controls, and timeout controls
into that command, then renders rows and errors from the structured response.

The TUI must not own SQL driver clients, invent a separate row format, or make
schema discovery available only through widget state.

### Redis Key Browser

The TUI may provide key navigation, value preview, and an editor for large
values. Reads and writes still map to service commands or capabilities such as
`keys`, `get`, `set`, `del`, `ttl`, `info`, and `exec`.

Destructive operations such as `del` must use the same destructive-operation
metadata, confirmation behavior, and audit categories as CLI invocation.

### SSH Terminal And SFTP

The TUI owns raw keyboard input, terminal screen state, scrollback, SFTP panel
selection, and transfer progress display. The SSH service owns host-key
handling, sessions, channels, SFTP handles, tunnels, and target errors.

One SSH profile may create several runtime instances at once, such as a
terminal, an SFTP browser, and a tunnel. Closing one TUI tab must not imply that
every instance from that profile is closed unless the service explicitly
models that lifecycle.

### Live Logs And Attach

The TUI may provide streaming log views, search, pause, resume, follow mode,
and attach/exec panes. Fetching logs, starting streams, cancellation, exec
commands, and target errors belong to the plugin service or capability
handler.

Streaming output should remain usable by agents through NDJSON or another
capability transport instead of being visible only in the ratatui widget.

### Connection Manager

The Connection Manager may remain a retained TUI surface for manual profile
catalog, edit dialogs, connection testing, and tab launch. Long-term profile
CRUD and validation belong to profile APIs shared with CLI commands.

The TUI may update profile data through that API. It should not become the only
writer of profile persistence or the only place where validation rules exist.

## Anti-Patterns

Avoid these patterns:

- adding a TUI button or keybinding whose action has no service command or
  capability equivalent;
- importing target driver crates in TUI modules for convenience;
- parsing encrypted connection configuration in widgets;
- storing plaintext credentials in widget state, logs, tab contexts, or
  clipboard data;
- encoding destructive-operation policy as a local confirmation dialog only;
- emitting human-only error strings when a structured capability error is
  required;
- making shell globals aware of protocol-specific plugin modes;
- using tab context JSON as an undocumented protocol contract.

## Acceptable Exceptions

Some behavior is naturally TUI-only:

- cursor position, scroll position, pane split sizes, sort columns, and
  transient filters;
- terminal screen buffers and raw input state;
- selected rows, selected keys, selected files, and unsaved local editor text;
- preview formatting that does not alter protocol results;
- local keyboard shortcuts and focus modes inside a plugin.

These states may stay local to TUI components as long as they do not become the
only representation of protocol behavior or persisted user data.

## Review Checklist

Use this checklist when reviewing new or changed TUI work:

- Does every protocol operation route through a service command or capability
  handler?
- Are saved profiles referenced by ID or alias instead of copied into widget
  state?
- Are secrets represented only by credential references or brokered access?
- Are destructive actions covered by shared validation and policy?
- Are structured errors preserved before they are rendered for humans?
- Are tests placed at the service/capability layer for reusable behavior?
- Does the TUI depend only on `ShellCapabilities` for shell interaction?
- Can an agent or script perform the same non-interactive operation without
  opening the TUI?

## Follow-Up Impact

The database TUI downscoping slice should use this boundary to decide which SQL
browser/table editor paths are retained as thin adapters, paused, or moved
behind CLI-first capability work. That concrete guidance is defined in
Database TUI Downscoping Plan.
