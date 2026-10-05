# Standalone TUI UX Acceptance Criteria

This document makes the quality bar for plugin-owned terminal apps measurable.
It applies to retained standalone TUIs launched through plugin CLI commands.

It supports [ADR: Plugin-Owned CLI-Launched TUI Apps](adr-plugin-owned-cli-launched-tui.md),
[Plugin-Owned TUI Launch Contract](plugin-owned-tui-launch-contract.md), and
[Plugin-Owned TUI UX Briefs](plugin-owned-tui-ux-briefs.md).

## Release Classification

Every standalone TUI must declare one of these states in its plugin readiness
document:

| State | Meaning |
|---|---|
| Reference | Complete enough to guide other plugin TUIs. |
| Retained | Supported human workflow with required tests and evidence. |
| Pilot | Useful but still proving architecture or workflow quality. |
| Compatibility | Old router-hosted or transitional behavior, not the target model. |
| CLI-only | No retained TUI; CLI/capabilities are the supported path. |

## Performance Budgets

Measured on a local development machine unless a plugin-specific readiness doc
states a stricter environment. The measurement points, cold/warm sampling,
percentile method, CI variance policy, and artifact schema are defined in
[TUI Interaction Performance Contract](tui-interaction-performance.md).

| Budget | Target |
|---|---:|
| Preflight without target network calls | p95 under 500 ms |
| First rendered frame after process start | p95 under 750 ms |
| Key event to visible local repaint | p95 under 50 ms |
| Raw terminal key echo or forwarding path | p95 under 35 ms, excluding remote latency |
| Resize event to stable layout | p95 under 100 ms |
| Quit to terminal restoration | p95 under 250 ms |
| Idle CPU after steady state | no busy repaint loop; no continuous polling without work |

If a remote target blocks startup, the app must render a connecting state before
the target operation exceeds the first-frame budget.

## Keyboard Journey Scorecard

Each retained TUI must define the top workflows for its domain and score them.

Required scorecard fields:

- workflow name;
- initial state and required profile;
- success state;
- maximum expected keystrokes for the common path;
- escape/back behavior from each modal state;
- destructive-operation confirmation path, if any;
- whether mouse is optional, required, or unsupported;
- raw-input conflicts and the plugin escape sequence.

Acceptance:

- top workflows are possible without a mouse;
- common actions are visible through labels, menus, command palette, or help;
- no retained workflow depends on an undocumented shell global;
- raw-input plugins reserve an escape path that cannot be confused with routine
  remote typing;
- dialogs and modes can be exited without losing unsaved local work unless the
  user confirms discard.

## Information Architecture Checks

The first viewport must show:

- plugin name and current mode;
- selected profile or safe target label;
- connection or session health;
- primary navigation region;
- primary content region;
- current selection or cursor context;
- pending background work, if any;
- error or warning state, if any;
- discoverable next actions.

The app must provide explicit empty, loading, error, permission-denied,
disconnected, reconnecting, and success states. Blank screens are not accepted
outside a remote terminal pane after a successful connection.

## Accessibility And Visual Criteria

Acceptance:

- normal foreground/background contrast is at least 4.5:1;
- selected, focused, warning, and destructive states are not communicated by
  color alone;
- text fits in supported terminal widths without overlapping adjacent regions;
- minimum supported viewport is documented per plugin;
- resize below the supported minimum shows a controlled compact or unsupported
  state instead of corrupt layout;
- focus is always visible;
- spinners, progress, and streaming output do not hide errors or prompts.

## Error Recovery

Every retained TUI must preserve structured error categories before rendering a
human message:

- validation;
- auth;
- permission;
- transport;
- timeout;
- plugin;
- target;
- terminal.

Acceptance:

- errors include a safe summary, category, and next action;
- target errors can be retried when retry is meaningful;
- auth and permission errors route to profile or credential guidance without
  printing secrets;
- transient stream failures do not crash unrelated panes;
- crash recovery restores the terminal and writes redacted diagnostics only.

## Destructive Action Safety

Destructive or external-side-effect operations require:

- clear object summary before execution;
- non-default affirmative confirmation;
- typed confirmation for bulk, irreversible, or high-blast-radius operations;
- dry-run or preview when the capability supports it;
- audit event with profile ref, plugin id, operation, risk, acknowledgement,
  result, timing, and redacted input summary;
- cancellation or rollback guidance when the target supports it.

Examples include deleting files or objects, dropping collections or tables,
stopping containers, deleting Kubernetes resources, aborting Jenkins builds,
sending email, and applying sync conflict resolutions.

## Evidence Required

A retained standalone TUI must include:

- PTY or terminal integration tests for startup, first frame, normal quit,
  resize, and cleanup;
- crash or panic cleanup test that verifies raw mode and alternate screen are
  restored;
- snapshot, ANSI transcript, or screenshot evidence for at least one normal,
  empty, loading, error, and destructive-confirmation state;
- secret-leak checks for args, env, stderr, logs, panic output, and audit
  summaries;
- service or capability tests for target operations;
- a plugin readiness note listing skipped live fixtures or manual checks.

The shared automated release gate is:

```bash
scripts/tui-quality-gate.sh
```

It launches every retained standalone TUI and Connection Manager in real PTYs,
checks first-frame, key-to-repaint, resize, stream cancellation, idle CPU and
repaint, quit/restore, cleanup, and credential leak markers, then writes ANSI
transcripts and metrics to `target/tmp/tui-quality-gate/`. The CI retention
contract and manual emulator matrix are in
[TUI CI And Real-Terminal Coverage](tui-terminal-coverage.md).

Fixture evidence-generation duration is a build/test throughput signal only.
It must not be reported as first-frame or interaction latency.

## Per-Plugin Minimums

| Plugin family | Additional minimum evidence |
|---|---|
| SSH | Raw input, terminal resize, disconnect/reconnect, host-key prompt, SFTP, forwarding, session shutdown. |
| Email | Mailbox list, message read, search, compose draft/discard/send confirmation, attachment metadata, provider auth error. |
| Docker/Kubernetes | Resource triage, logs, exec or attach, lifecycle confirmation, stream cancellation, disconnected target recovery; follow [Live Operations TUI Safety](live-operations-tui-safety.md). |
| S3/WebDAV | Browse, preview metadata, upload/download plan, transfer progress, failure retry, delete confirmation; follow [Storage TUI UX Decisions](storage-tui-ux-decisions.md). |
| SQL/data inspectors | Query/read path through shared capabilities, bounded result paging, read-only mode, mutation preview or explicit CLI-only decision. |
| Jenkins | Job/build list, console streaming, trigger/stop confirmation, queued/running/failed state, unreachable server handling; follow [Live Operations TUI Safety](live-operations-tui-safety.md). |
| Sync | CLI-first status, conflict summary, explicit force/revision acknowledgement, credential and server-unavailable states. |

## Acceptance Review

Before marking a standalone TUI retained:

- attach the command used to launch it;
- attach validation commands and results;
- record performance measurements or explain why the budget was not applicable;
- link screenshots/transcripts or test fixtures;
- record known gaps and whether they block release.
