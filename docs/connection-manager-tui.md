# Connection Manager TUI

The Connection Manager is VoidB's human configuration surface for saved
profiles, credential state, connection diagnostics, plugin metadata, and
copyable CLI guidance. It is a native standalone application, not a router
plugin or product-wide plugin TUI launcher.

## Command

The canonical workspace command is:

```bash
voidb-cli connections tui
```

That command launches the `voidb` TUI binary in standalone Connection Manager
mode:

```bash
voidb --connection-manager
```

`voidb` without arguments opens this native Connection Manager. The explicit
`voidb --connection-manager` form remains supported. The old shell is available
only through `voidb --shell`. `voidb-cli connections tui --print-command` prints
the resolved standalone command for scripts and tests.

## Native storage

- `profiles.json` stores profile identity, plugin metadata, policy, and
  credential references.
- `credentials.json` stores the complete plugin configuration as an encrypted
  local record.
- New manager CRUD never writes `AppConfig.connections` and never labels newly
  created profiles as legacy.
- Existing `config.toml` connections can be imported explicitly with
  `voidb-cli profile migrate apply`; migration creates self-contained native
  profiles while leaving the old file only as a rollback backup.

## Boundary

Connection Manager may:

- list, create, edit, and delete native profiles and encrypted configurations;
- show profile catalog and credential-protection state;
- guide users toward profile tests, capability discovery, and plugin-owned TUI
  commands;
- refresh directly from the native profile and credential stores.

Connection Manager must not:

- launch or host plugin-owned TUI render loops;
- open central plugin tabs for protocol workflows;
- forward credential grants from the manager into plugin TUIs;
- depend on another plugin's UI state machine, layout, or keymap.

Plugin TUIs remain plugin-owned commands such as:

```bash
voidb-cli ssh tui --profile prod-shell
voidb-cli email tui --profile work-mail
```

## Schema-driven profile forms

Create and edit open an interactive form by default. The form contract declares
field labels, required state, scalar types, numeric ranges, valid enum values,
secret handling, and conditional visibility. Authentication and transport
choices are tagged unions: selecting one choice immediately replaces the
inactive branch and reveals only the fields accepted by that plugin.

New profiles begin with connection type, then name, then optional display name.
Name is the stable CLI reference used by commands such as
`voidb-cli profile test prod-bastion --plugin ssh`. It is required and unique
within the selected plugin, ignoring case. Display name is a human-facing label
and may be repeated. A globally unique Profile ID is generated on creation and
is preserved when either name is edited.

SSH, for example, exposes `Password`, `PublicKey`, and `Agent`. Password mode
shows a masked password field; public-key mode shows the private-key path and
optional passphrase; agent mode shows neither. The same renderer handles Docker
transports, Kubernetes direct authentication, WebDAV authentication, S3
providers and credentials, Elasticsearch and MongoDB authentication, and
Jenkins authentication.

`F2` opens advanced JSON for uncommon or future plugin fields. Returning with
`F2` parses the document back into the form, and save validates visible fields
against the form schema. Advanced JSON is an escape hatch, not the primary
configuration workflow.

## UX Brief

Target users are local humans configuring VoidB profiles before using
agent-facing CLI/capability commands or accepted plugin-owned TUIs.

Top workflows:

| Workflow | Success state | Budget |
|---|---|---:|
| Review profiles | Saved profiles are visible with protocol identity and credential state. | 1 action after launch. |
| Create or edit profile | Config is validated and saved without printing plaintext secrets. | 6 actions after selecting protocol. |
| Protect credentials | User can set or unlock a master password in a local raw-input dialog. | 4 actions. |
| Test profile connectivity | A background service-backed profile test completes without freezing input. | 1 action from selected profile. |
| Find next CLI action | Selected profile shows copyable profile/capability guidance instead of launching another TUI. | 1 action. |

First viewport:

- title and counts for saved connections and profile views;
- credential-protection summary with a local master-password action;
- dense connection list grouped by protocol and name;
- status line for save, delete, refresh, and guidance messages;
- compact command strip for navigation, search, profile edit, delete, refresh,
  and help.

Keyboard vocabulary:

| Key | Behavior |
|---|---|
| `j` / `k` or arrows | Move through profiles. |
| `/` | Filter profiles. |
| `Enter` | Show CLI/capability guidance for the selected profile. |
| `c` | Open the capability browser for the selected profile's plugin. |
| `n` | Create a profile. |
| `e` | Edit the selected profile. |
| `Tab` / `Shift+Tab` | Move through identity and plugin form fields. |
| `Left` / `Right` | Change enum, boolean, authentication, or transport choices. |
| `Ctrl+U` | Clear the active text, secret, list, or numeric field. |
| `F2` | Toggle interactive form and advanced JSON. |
| `Ctrl+S` | Validate and save the active profile editor. |
| `d` | Confirm delete for the selected profile. |
| `t` | Run a background profile connectivity test. |
| `m` | Unlock or set a master password. |
| `a` | Open the centralized authorization manager for presets, exact Custom scope, TTL/uses, grant review, renew/replace, and profile revoke. |
| `p` | Open the canonical JIT request inbox, principal/profile grouping, plugin-aware review, and immutable revision history. |
| `x` | Open a separate review step for the explicit secondary revoke-all action. |
| `r` | Refresh from the native profile store. |
| `?` | Show local help. |
| `:q` or `Ctrl+Q` | Quit the standalone app. |

States:

- empty: no saved profiles, with `n` as the primary action;
- search-empty: no matching profiles, with `Esc` to clear;
- credential-locked: profile list may be unavailable until unlock succeeds;
- save success/failure: redacted status message;
- test running/result: status line updates from the structured `profile test`
  JSON envelope, without printing stderr or decrypted config;
- capability browser: modal lists `invoke list` metadata and emits command
  guidance only; capability execution stays in `voidb-cli invoke run`;
- authorization manager: Read-only is the recommended preset;
  Interactive/Execute selects only a centrally recommended semantic capability;
  Full access captures every capability in the current catalog as an exact
  snapshot; Custom requires exact capability selection. Destructive scope
  requires an explicit acknowledgement and a second review/confirm step;
- JIT approval inbox: a background service boundary refreshes canonical broker
  state without blocking input, distinguishes fresh from stale snapshots, and
  groups requests by agent principal and immutable profile. `Enter` reviews
  once/bounded/add-to-grant/deny, `c` adds only declared non-secret narrowing
  constraints, and a second `Enter` confirms. Approval passes the already
  unlocked master password only through a private local stdin pipe;
- grant status: profile rows and details distinguish off, read-only,
  execute-enabled, expiring, exhausted, stale, and broker-offline states, plus
  remaining uses and active session count. A background worker refreshes the
  password-free projection without blocking terminal input;
- lifecycle actions: renewal preserves immutable scope; replacement closes the
  displaced grant's sessions; profile revoke and global revoke-all have separate
  review steps;
- delete pending: explicit confirmation;
- unsupported launch: guidance explains that plugin TUIs are entered through
  plugin-owned CLI commands.

Promotion evidence:

- focused `voidb-tui` tests for the standalone runtime boundary;
- CLI preflight test for `voidb-cli connections tui --print-command`;
- PTY startup, first-frame, quit, and cleanup transcript evidence;
- secret-leak checks for rendered status, stderr, and captured transcripts.

Current evidence is recorded in
Connection Manager TUI Evidence - 2026-07-07.
