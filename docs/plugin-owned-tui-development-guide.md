# Plugin-Owned TUI Development Guide

This guide is the implementation cookbook for future standalone plugin TUIs.
Use it when adding a new human terminal app after the CLI/capability contract
has already proven the workflow.

It complements:

- [Plugin Development Guide](plugin-development-guide.md) for service-layer
  conventions;
- [ADR: Plugin-Owned CLI-Launched TUI Apps](adr-plugin-owned-cli-launched-tui.md);
- [Plugin-Owned TUI Launch Contract](plugin-owned-tui-launch-contract.md);
- [Standalone TUI UX Acceptance Criteria](standalone-tui-ux-acceptance.md);
- [Plugin-Owned TUI UX Briefs](plugin-owned-tui-ux-briefs.md).

The current in-repo CLI binary is `voidb-cli`. Some architecture docs use the
packaged shorthand `voidb <plugin> tui`; for workspace commands, implement and
test `voidb-cli <plugin> tui` only after a new plugin-owned TUI is accepted.

## Target Shape

A standalone TUI is owned by its plugin crate:

| Concern | Owner |
|---|---|
| CLI subcommand and preflight output | owning plugin `cli_plugin.rs` |
| Terminal init, render loop, input, resize, cleanup | owning plugin TUI runtime |
| Target operations, sessions, workers, reconnect, retries | owning plugin service layer |
| Profile resolution, credential grants, redaction, launch plan | `voidb-core` and `voidb-cli` contracts |
| Router-hosted shell tabs and old factories | removed; do not depend on them |

Do not build new UX by adding another factory to `voidb-tui`. Old router-hosted
factories and legacy database adapters are not compatibility targets.

## Command Shape

Every accepted TUI exposes a plugin-local command:

```bash
voidb-cli <plugin-id> tui --profile <profile-ref>
```

Common flags:

| Flag | Meaning |
|---|---|
| `--profile <ref>` | Required for target-backed TUIs. Accepts names, `id:<id>`, and `name:<name>` where supported by the profile resolver. |
| `--purpose <name>` | Plugin-defined launch purpose, for example `terminal`, `sftp`, `mailbox`, `browser`, `logs`, or `builds`. |
| `--readonly` | Request read-only behavior when the plugin can enforce it. |
| `--format json` | Preflight mode. Print the launch envelope and exit before entering raw mode. |
| `--no-restore` | Start without plugin-owned UI restoration state. |

Preflight mode must be secret-free and deterministic enough for tests:

```bash
voidb-cli ssh tui --profile prod --format json
voidb-cli s3 tui --profile objects --purpose browser --format json
```

The JSON envelope should include the command name, plugin id, profile summary,
purpose, redaction status, and credential reference count. It must not include
plaintext passwords, tokens, access keys, private keys, connection strings, or
decrypted plugin config.

## Profile And Credential Handoff

Use `build_tui_launch_plan` from `voidb-core`:

1. Resolve the saved profile from the CLI `--profile` ref.
2. Build a `TuiLaunchRequest` with plugin id, profile ref, purpose, and policy
   flags.
3. Call `build_tui_launch_plan(&profile, request, "voidb", Utc::now())`.
4. Print the plan for `--format json`, or enter the terminal app.
5. Pass only profile identity and credential grant references into runtime
   state.

Allowed in launch args and env:

- plugin id;
- profile ID or name;
- purpose and policy flags;
- opaque credential grant id;
- display-safe labels.

Forbidden in launch args, env, logs, panic output, audit summaries, and test
fixtures:

- passwords, tokens, access keys, secret keys, private keys, certificates;
- decrypted `plugin_config`;
- full connection strings containing credentials;
- credential material embedded in profile display labels;
- target data that the profile policy marks sensitive.

The TUI may render display-safe endpoint labels, but credential material must
stay behind the plugin service or credential broker boundary.

## Service Layer Boundary

Standalone TUI modules consume plugin services; they do not talk to target
drivers directly.

Use the same service rules as router-hosted plugins:

- keep protocol clients and driver crates in `service/`, `ops/`, or
  plugin-specific client modules;
- use `ServiceMode::Channel` or plugin-specific channel workers for TUI loops;
- use `ServiceMode::Direct` only for CLI commands that do not run an
  interactive terminal loop;
- use `SyncWorker<Cmd, Resp>` or equivalent worker boundaries for `!Send`
  drivers;
- make long-running target operations cancellation-aware;
- convert target failures into structured categories before rendering a human
  message.

The render loop must remain responsive while target operations run. Do not block
`terminal.draw`, input polling, or resize handling on a network call, database
driver call, filesystem transfer, or log stream.

## Terminal Runtime

Each standalone TUI owns terminal lifecycle:

1. Complete profile and preflight validation before entering raw mode.
2. Initialize the terminal with `ratatui::init()` or an equivalent plugin-local
   wrapper.
3. Install cleanup for normal quit, `Ctrl+C`, terminal errors, and panics where
   practical.
4. Poll crossterm events with a bounded timeout.
5. Convert terminal events into plugin-local events.
6. Draw on ticks, input, service events, and resize.
7. On quit, close plugin-owned sessions through service commands, then restore
   the terminal.

The loop should explicitly handle:

- normal quit;
- escape layer for raw-input apps;
- `Ctrl+C` and EOF;
- resize events;
- service event drain;
- render errors;
- plugin-requested quit through a local tab-manager shim when reusing an
  existing router-hosted plugin type.

If reusing an existing `Plugin::update()` implementation temporarily, provide
standalone `ShellCapabilities` with a plugin-local `TabManager`. The tab manager
may request quit, title changes, or render wakeups, but it must not model real
shell tabs as the plugin's window system.

## Input And Escape Model

Standalone TUIs should use familiar keys only when they fit the domain:

| Key | Default recommendation |
|---|---|
| `?` | Plugin-local help. |
| `/` | Search or filter in the active region. |
| `Tab` / `Shift+Tab` | Move between major non-raw regions. |
| `Esc` | Back, close modal, cancel local mode, or arm an escape layer. |
| `q` | Quit only when no destructive operation or unsaved local work is pending. |

Raw-input apps, such as SSH terminal or attach sessions, must reserve an escape
path that does not conflict with routine remote input. The escape layer belongs
to the plugin, not to the default shell.

## UX Scorecard

Before marking a standalone TUI retained, write or update its brief with:

- target users and operating context;
- top workflows and success states;
- keystroke budgets for common paths;
- first viewport information architecture;
- keyboard vocabulary and escape behavior;
- destructive-operation confirmation flows;
- empty, loading, success, disconnected, permission, and error states;
- non-goals;
- evidence required before promotion.

Use [Plugin-Owned TUI UX Briefs](plugin-owned-tui-ux-briefs.md) as the template.
Do not copy another plugin's layout unless the workflow actually matches.

## Required Tests

For a retained standalone TUI, add or update these checks:

```bash
cargo test -p voidb-core tui_launch
cargo test -p voidb-plugin-<name> <plugin-owned-pty-gate>
cargo test -p voidb-plugin-<name>
/usr/bin/git diff --check
```

The plugin-owned PTY gate must include:

- JSON preflight redaction checks;
- PTY startup and first-frame checks;
- resize repaint checks;
- normal quit and terminal restore checks;
- alternate-screen and cursor restore transcript checks;
- credential leak checks in captured ANSI transcripts;
- evidence output under `target/tmp/standalone-tui-ux/`.

Add plugin-specific service tests for target behavior. Examples:

- SSH: host-key policy, auth failures, PTY input/output, SFTP, forwarding,
  disconnect and reconnect.
- Email: mailbox listing, search, read, compose validation, provider errors.
- Docker/Kubernetes: resource listing, logs, exec or attach, lifecycle
  confirmations, disconnected targets.
- S3/WebDAV: browse, upload/download plan, transfer progress, delete
  confirmation and retry.
- Jenkins: job/build list, console streaming, trigger/stop confirmation,
  unreachable server.

Live fixtures remain opt-in unless the plugin readiness doc requires them for a
release-candidate gate.

## Release Gate

A standalone TUI may be shipped only when release notes or readiness evidence
list:

- command used to launch the TUI;
- profile and credential handoff behavior;
- service-layer operations covered;
- UX scorecard or plugin brief;
- automated validation commands and results;
- transcript, screenshot, or fixture evidence;
- known skipped live checks;
- rollback or feature-gate strategy;
- explicit confirmation that the feature is new plugin-owned UI work and does
  not depend on removed router-hosted factories or shared legacy widgets.

## Prohibited Coupling

Do not introduce these dependencies for new standalone TUI work:

- `voidb-tui` internals;
- shell tab routing as the primary window model;
- another plugin's UI module, layout, keymap, state machine, or adapter;
- target driver crates in TUI modules when a service layer exists;
- plaintext secrets in args, env, logs, panic output, audit events, or tests;
- shared widgets as a new product-wide design system without an explicit
  extraction decision.

Plugin-local helpers are fine when they are owned and tested by that plugin.
Shared contracts should live in `voidb-core` only when they are non-UI protocol,
profile, credential, launch, audit, or capability contracts.

## Minimal Checklist

Before opening a standalone TUI change:

- [ ] `voidb-cli <plugin> tui --profile <profile>` exists.
- [ ] `--format json` preflight is secret-free.
- [ ] Terminal startup, resize, quit, and cleanup are covered by PTY tests.
- [ ] Target operations use the plugin service layer.
- [ ] No UI module imports target driver crates directly.
- [ ] Credential material stays out of UI state and diagnostics.
- [ ] The plugin UX brief or readiness doc describes top workflows.
- [ ] CI docs list the focused test command.
- [ ] The feature does not depend on old router-hosted behavior or legacy
      database/browser widgets.
