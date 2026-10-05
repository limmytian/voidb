# ADR: Plugin-Owned CLI-Launched TUI Apps

## Status

Accepted for planning.

## Date

2026-07-06

## Context

VoidB v4 currently uses a pure-router TUI shell. The shell owns tabs, global
shortcut routing, and `ShellCapabilities`; plugin crates render full-screen
surfaces through `PluginFactory` and `Plugin::update()`.

That model is cleaner than a shell-owned layout, but it still makes the default
VoidB TUI the host for plugin human experiences. As VoidB moves toward a
capability-first product, this creates three problems:

- Plugin UI delivery is coupled to `voidb-tui` dependencies and registration.
- Human TUI workflows inherit shared shell behavior even when they need their
  own terminal lifecycle, raw input, test harness, and release gate.
- UI code can keep growing as a router-hosted compatibility layer instead of
  becoming a deliberate plugin-owned application.

Earlier decisions remain valid:

- [Capability-First CLI Architecture](adr-capability-first-cli-architecture.md)
  makes CLI and structured capabilities the core agent interface.
- [TUI Workflow Classification](tui-workflow-classification.md) keeps TUI for
  human workflows where it is materially better than repeated commands.
- [TUI Adapter Boundary](tui-adapter-boundary.md) prevents TUI state from
  becoming the protocol boundary.
- Database TUI Downscoping Plan moves legacy
  database browser/editor surfaces behind explicit compatibility gates.

This ADR narrows the next architecture target: retained plugin TUIs should be
owned, launched, tested, and released by their plugin CLI entrypoint rather than
hosted inside the default shell router.

## Decision

VoidB will rebuild retained plugin TUI workflows as standalone terminal apps
launched from plugin CLI commands.

The default VoidB surface becomes capability-first and CLI-driven. Human TUI
apps are opt-in commands such as:

```bash
voidb ssh tui --profile prod
voidb email tui --profile work
voidb kubernetes tui --profile dev-cluster
```

For process plugins, discovery may still advertise that a plugin has a TUI, but
the launched process is the plugin's own terminal app. Core may resolve plugin
metadata, profile references, credential grants, policy, audit, and launch
preflight. Core must not host plugin rendering, own plugin UI state, or provide
cross-plugin UI adapters for new standalone TUIs.

The existing `voidb-tui` shell remains a compatibility and profile-management
surface during migration. It may keep:

- the Connection Manager as a shell-owned profile catalog and launcher;
- database handoff tabs that point users to CLI/capability workflows;
- gated legacy database UI factories while compatibility support is shipped;
- bridge affordances that launch standalone plugin TUI commands.

It must not be the destination architecture for retained plugin TUIs.

## Ownership Boundary

| Concern | Owner |
|---|---|
| Profile CRUD, credential references, redaction, policy, audit | Core and CLI |
| Capability discovery and structured invocation | Core, CLI, plugin services |
| Standalone TUI command shape | Owning plugin CLI |
| Terminal initialization, raw mode, alternate screen, resize, cleanup | Owning plugin TUI app |
| Plugin service clients, sessions, workers, reconnect, protocol errors | Owning plugin service layer |
| Shell tabs, legacy routing, compatibility launch affordances | `voidb-tui` shell only |

The standalone TUI can use the plugin's service layer in channel mode, direct
mode, or a plugin-specific runtime boundary. It must not import target drivers
from UI code when a service layer exists.

## Required Contracts

The detailed launch contract is defined in
[Plugin-Owned TUI Launch Contract](plugin-owned-tui-launch-contract.md).

The current migration inventory and blockers are tracked in
Router-Hosted TUI Migration Audit.

The quality bar for rebuilt terminal apps is defined in
[Standalone TUI UX Acceptance Criteria](standalone-tui-ux-acceptance.md).

## Consequences

Positive:

- Plugin TUI work can be planned, tested, and released per workflow rather than
  through one shared shell.
- Plugins can choose the terminal architecture that fits the workflow, including
  raw input, PTY handling, streaming, and domain-specific layout.
- The default VoidB binary can stay smaller and more predictable for agents.
- Capability and CLI contracts remain the reusable automation surface.

Negative:

- Existing router-hosted UI code needs migration, explicit compatibility gates,
  or deletion decisions.
- Profile and credential handoff into launched TUI processes needs a safe
  grant contract before broad implementation.
- Some reusable widgets in `voidb-core` become legacy dependencies unless they
  are moved into plugin-local code or retired.
- Release validation must include terminal lifecycle tests that do not exist
  for every plugin today.

## Non-Goals

- Remove `voidb-tui` immediately.
- Rewrite every plugin TUI in one requirement.
- Create a universal design system that makes plugin TUIs identical.
- Preserve database legacy TUI behavior except through explicit compatibility
  gates until replacements or CLI-only decisions are accepted.
- Put plaintext credentials in command arguments, environment variables, logs,
  panic output, audit records, or shell history.

## Open Questions

- Whether process-plugin manifests should add explicit TUI launch fields beyond
  the current `ui.tui`, `entrypoint_capability`, and `raw_input` metadata.
- Whether the first implementation should add a generic `voidb plugin tui`
  launcher, rely only on plugin-specific `voidb <plugin> tui` commands, or
  support both.
- Which plugin provides the first complete standalone TUI reference after the
  launch runtime exists. SSH is the best candidate because it exercises raw
  input, SFTP, forwarding, sessions, and terminal cleanup.
