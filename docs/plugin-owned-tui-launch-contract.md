# Plugin-Owned TUI Launch Contract

This document defines how future accepted VoidB plugin TUIs advertise and
launch as standalone terminal apps. It follows
[ADR: Plugin-Owned CLI-Launched TUI Apps](adr-plugin-owned-cli-launched-tui.md).

## Scope

This is the target contract for new plugin-owned TUIs. Requirement 77 removed
the old router-hosted plugin factories and compatibility feature gates, so no
current in-repo plugin TUI command is retained by default. A plugin TUI must be
rebuilt and accepted against this contract before it ships again.

The contract covers:

- TUI advertisement and command discovery;
- profile selection and credential handoff;
- terminal lifecycle responsibilities;
- exit codes and structured errors;
- forbidden shared UI dependencies;
- validation required before a plugin TUI is considered shipped.

## Advertising A TUI

A future in-repo plugin advertises a standalone TUI by registering a
plugin-specific CLI subcommand:

```bash
voidb <plugin-id> tui --profile <profile-ref>
```

Examples:

```bash
voidb ssh tui --profile prod-shell
voidb email tui --profile work-mail
voidb s3 tui --profile object-store
```

A process plugin may also advertise TUI availability in `plugin.toml`:

```toml
[ui]
tui = true
entrypoint_capability = "terminal"
raw_input = true
```

The current manifest fields are discovery metadata only:

- `tui` tells launchers that a human TUI exists.
- `entrypoint_capability` names the closest capability that describes the
  workflow or required permission.
- `raw_input` tells launchers and policy tools that the app may need full
  terminal input control.

Future manifest revisions may add explicit launch fields. Until then, in-repo
plugins should expose the plugin-owned command directly, and process-plugin
launchers must treat the runtime command and TUI command shape as an
implementation-specific package contract.

## Command Shape

The minimum standalone command shape is:

```bash
voidb <plugin-id> tui --profile <profile-ref>
```

Recommended common flags:

| Flag | Required | Meaning |
|---|---:|---|
| `--profile <ref>` | yes, for target-backed TUIs | Profile ref accepted by profile CLI commands: name, `id:<uuid>`, or `name:<name>`. |
| `--purpose <name>` | no | Plugin-defined launch purpose such as `terminal`, `sftp`, `mailbox`, `logs`, or `browser`. |
| `--readonly` | no | Request read-only policy where the plugin can enforce it. |
| `--format json` | no, preflight only | Emit machine-readable preflight or launch failure output before entering the TUI. |
| `--no-restore` | no | Start without plugin-owned UI restoration state. |

Profile refs are allowed in arguments because they are not secrets. Plaintext
passwords, tokens, private keys, decrypted config, credential grants, and
session handles are never allowed in arguments.

## Profile And Credential Handoff

Launch follows this flow:

1. CLI parses the plugin TUI command.
2. Core resolves the profile ref to a saved profile and display-safe metadata.
3. Core evaluates policy for the requested TUI purpose and requested
   permissions.
4. Core creates a scoped credential grant or grant descriptor with a short TTL.
5. The plugin TUI starts with profile identity plus grant references, not
   plaintext secrets.
6. The plugin service resolves credential material through the approved broker
   path and keeps it out of UI state, logs, panic output, audit records, and
   shell history.

Allowed launch inputs:

- plugin ID;
- profile ID or name;
- display-safe profile labels and endpoint summaries;
- purpose, read-only preference, restore preference, and terminal size;
- opaque credential grant ID or file descriptor when the broker supports it.

Forbidden launch inputs:

- plaintext passwords, tokens, API keys, private keys, client certificates, or
  decrypted `plugin_config`;
- full connection strings containing secrets;
- credential grants in command arguments;
- target-specific data without redaction rules, such as raw SQL, object keys,
  message bodies, private file paths, or hostnames if a policy marks them
  sensitive.

## Terminal Lifecycle

The launched plugin TUI owns the terminal lifecycle. The default shell must not
wrap its render loop or recover its local state.

Every standalone TUI must:

- enter raw mode only after preflight succeeds;
- enable alternate screen only when it can restore it on all exits;
- install panic/error cleanup that restores raw mode, cursor visibility, mouse
  mode, bracketed paste, and alternate screen;
- handle resize events without layout corruption or panic;
- handle `Ctrl+C`, EOF, and normal quit paths consistently;
- avoid blocking the render/input loop on network or driver calls;
- keep async work behind service commands, workers, or cancellation-aware tasks;
- write diagnostics to stderr only after redaction;
- avoid periodic busy repaint loops when no state changes.

Plugin TUIs that embed remote terminals or attach sessions must also:

- preserve raw input correctness for printable characters and control keys;
- provide an escape path that does not conflict with the remote application;
- close PTY, SFTP, log, watch, and forwarding sessions through plugin service
  teardown, not by dropping UI state only;
- keep terminal scrollback and replay state plugin-local unless explicitly
  exported by a user action.

## Exit Codes And Errors

Standalone TUI commands should use stable exit codes:

| Code | Meaning |
|---:|---|
| `0` | Normal user exit. |
| `2` | Usage error or invalid command arguments. |
| `3` | Profile, credential, or policy failure before launch. |
| `4` | Target connection, authentication, or health failure before first usable frame. |
| `5` | Terminal setup or cleanup failure. |
| `6` | Plugin internal error or unrecovered panic after cleanup. |
| `7` | Unsupported terminal, platform, or required local dependency. |
| `124` | Timeout or cancellation. |

When `--format json` is provided for preflight or failed launch, output should
follow the same structured category vocabulary as capability errors:
validation, auth, permission, transport, timeout, plugin, target, and terminal.

Runtime errors that occur after the TUI is active may be rendered in the app,
but they must still be redacted and recoverable. Destructive or externally
side-effecting failures should also write audit events when the operation was
attempted.

## Forbidden Shared UI Dependencies

New standalone plugin TUIs must not depend on:

- `voidb-tui` internals;
- `Plugin`, `PluginFactory`, `Plugin::update()`, or shell tab routing for their
  primary render loop;
- `ShellCapabilities.tabs` as the way to model plugin-local windows or panes;
- another plugin's UI modules, widgets, keymaps, layouts, state machines, or
  adapters;
- `crates/voidb-core/src/widgets/*` for new shared UI behavior unless the
  dependency is explicitly promoted as a stable non-legacy API;
- undocumented JSON tab contexts as a protocol contract;
- target driver crates directly from UI modules when a service layer exists.

Allowed dependencies:

- `voidb-core` profile, credential, capability, audit, process-plugin,
  session-descriptor, redaction, and structured error contracts;
- the owning plugin's service commands, events, config adapters, and local UI
  modules;
- terminal libraries such as `ratatui` and `crossterm`;
- plugin-local reusable components that are tested with that plugin.

## Shell Launch Affordance

After Requirement 77, `voidb-tui` is not a compatibility bridge for old plugin
rendering. If a future plugin-owned TUI is accepted, the shell may offer launch
affordances only after the plugin exposes a documented CLI command:

- show which plugins have standalone TUI commands;
- launch a standalone command from a profile row after preflight;
- show profile-scoped CLI or capability guidance when no TUI exists.

The shell must not pass plaintext secrets, host plugin rendering, preserve old
router-hosted factories behind feature flags, or translate plugin-specific UI
state. It is a launcher and profile catalog, not a TUI platform.

## Validation Gate

A standalone TUI is shipped only when it has:

- a documented `voidb <plugin> tui` command;
- profile and credential handoff without plaintext secrets in args, env, logs,
  panic output, or audit records;
- service-layer execution for target operations;
- for data inspectors, a completed Requirement 83 decision record in
  [Data Inspector CLI-First Decisions](data-inspector-cli-first-decisions.md)
  before any pilot implementation starts;
- terminal lifecycle tests for startup, quit, cleanup, resize, and crash
  recovery;
- raw input tests if it embeds a terminal or attach session;
- UX acceptance evidence from
  [Standalone TUI UX Acceptance Criteria](standalone-tui-ux-acceptance.md);
- release notes that make clear the TUI is a new plugin-owned surface, not a
  restored router-hosted compatibility path.
