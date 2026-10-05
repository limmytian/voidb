# Plugin-Owned TUI UX Briefs

These briefs define the first product shape for retained plugin-owned terminal
apps. They support the
[Plugin-Owned CLI-Launched TUI ADR](adr-plugin-owned-cli-launched-tui.md),
[Plugin-Owned TUI Launch Contract](plugin-owned-tui-launch-contract.md), and
[Standalone TUI UX Acceptance Criteria](standalone-tui-ux-acceptance.md).

Each retained TUI must own its own interaction model. Shared commands such as
quit, help, search, filter, and command palette may feel familiar, but no plugin
may inherit another plugin's layout, state machine, or workflow assumptions by
default.

## Shared Brief Template

Every retained plugin TUI readiness note must include:

- target users and operating context;
- top workflows, with success states and expected keystroke budgets;
- interaction model and primary modes;
- information architecture for the first viewport;
- keyboard vocabulary, including escape/back behavior;
- destructive or external-side-effect handling;
- empty, loading, error, disconnected, permission, and success states;
- explicit non-goals;
- evidence required before promotion from pilot to retained.

Shared default keys are recommendations, not a design system:

| Key | Meaning |
|---|---|
| `?` | Plugin-local help. |
| `/` | Search or filter inside the active region. |
| `:` | Command palette or command prompt, if the domain benefits from named actions. |
| `Tab` / `Shift+Tab` | Move between major regions when raw input is not active. |
| `Esc` | Back, close modal, cancel pending local mode, or open the plugin escape layer for raw-input apps. |
| `q` | Quit current plugin app only when no destructive operation or unsaved local work is pending. |

Raw-input apps must document their own escape layer because printable keys may
belong to the remote program rather than VoidB.

## Retention Matrix

| Plugin or family | TUI state | Brief |
|---|---|---|
| Connection Manager | Built-in configuration TUI | Retained as the profile/configuration surface. It does not host plugin TUIs; see [Connection Manager TUI](connection-manager-tui.md). |
| SSH | Reference pilot | Retained. First full standalone reference because it exercises raw input, PTY resize, SFTP, forwarding, reconnect, and session teardown. |
| Email | Pilot | Retained if mailbox triage and compose flows beat repeated CLI commands. |
| Docker | Pilot candidate | Retained for local live-operations triage if logs, exec, and lifecycle safety are strong. |
| Kubernetes | Pilot candidate | Retained for cluster triage if watch/log/exec workflows are safe and recoverable. |
| S3 | Conditional retained | Retain only if object navigation and transfer planning are materially better than CLI/capability flows. |
| WebDAV | Conditional retained | Retain only if two-panel remote file workflows justify a TUI. |
| Jenkins | Conditional retained | Retain if build/log triage and stop/retry workflows need an interactive app. |
| Sync | Minimal or CLI-only | Prefer CLI-first; retain only a small status/setup/conflict app if policy workflows need guided human review. |
| SQL/data inspectors | Conditional or CLI-only | Retain per plugin only with bounded paging and clear evidence that human browsing beats shared SQL capabilities. |

## SSH Reference Pilot

Target users:

- operators who need an interactive shell, SFTP navigation, forwarding, and
  session diagnostics from one saved profile;
- engineers recovering from intermittent target failures while preserving a
  usable local terminal;
- security-conscious users who need host-key and credential prompts without
  leaking secrets.

Top workflows:

| Workflow | Success state | Budget |
|---|---|---:|
| Open terminal session | Remote shell is active, raw input is owned by the terminal pane, and the escape layer is visible before first input. | 2 actions after launch. |
| Accept or reject host key | Host fingerprint is shown with safe labels and the decision is persisted or cancelled explicitly. | 3 actions. |
| Browse SFTP | Directory listing loads, selection is visible, preview metadata is safe, and transfer commands are available. | 4 actions from launcher. |
| Create local or remote forward | Forward appears in monitor with bind/target labels, byte counters, and stop action. | 6 actions. |
| Recover disconnect | Session health changes to disconnected, reconnect is offered, and terminal state is not corrupted. | 2 actions after failure. |

Interaction model:

- primary modes: Terminal, SFTP, Forwarding, Monitor, Diagnostics;
- terminal mode owns printable keys and most control keys;
- a plugin escape layer, such as `Ctrl+]` followed by a command key, opens the
  local command bar without sending the sequence to the remote host;
- background service events update health, transfer progress, and forward
  counters without blocking input.

First viewport:

- top status line: profile alias, purpose, connection health, host-key state,
  active mode, and credential-grant age;
- main pane: terminal PTY, SFTP table, forwarding table, monitor, or
  diagnostics;
- side or bottom command strip: local escape key, active mode keys, pending
  background work, and last safe error;
- no remote hostname, username, file path, or command output is shown in logs
  unless redaction policy allows it.

Keyboard vocabulary:

| Key | Behavior |
|---|---|
| plugin escape then `h` | Open help/command palette. |
| plugin escape then `s` | Switch to SFTP. |
| plugin escape then `f` | Switch to forwarding. |
| plugin escape then `m` | Switch to monitor. |
| plugin escape then `r` | Reconnect current session. |
| plugin escape then `q` | Quit after closing sessions gracefully. |

Destructive and side-effect handling:

- host-key trust requires explicit accept/reject;
- stopping forwards, deleting remote files, overwriting transfers, and killing
  sessions require confirmation with target summary;
- reconnect never discards local unsent compose/input buffers without a prompt;
- all teardown paths close PTY, SFTP, metrics, and forwarding resources through
  the SSH service layer.

States:

- empty: profile resolved, no session started, available modes listed;
- loading: connecting, host-key check, auth, SFTP list, or forward bind;
- error: categorized auth, permission, transport, timeout, target, terminal, or
  plugin error with retry guidance;
- disconnected: local UI remains responsive and offers reconnect or exit;
- success: terminal active, transfer complete, forward bound, or reconnect
  restored.

Non-goals:

- universal terminal emulator abstraction for other plugins;
- importing SSH driver crates from TUI-only modules;
- reusing another plugin file browser or forwarding UI as the SSH architecture;
- making the default shell host SSH tabs.

Promotion evidence:

- PTY tests for startup, quit, resize, raw input escape, and cleanup;
- fixture-backed SSH tests for host-key, auth failure, terminal, SFTP, and
  forwarding;
- ANSI transcript or screenshot for each mode and at least one error state;
- secret-leak checks for args, env, stderr, panic output, and audit summaries.

## Email Pilot

Target users:

- people triaging high-volume mailboxes from saved IMAP/SMTP profiles;
- users who need fast search, message reading, attachment review, and compose
  without exposing credentials or message bodies outside the plugin.

Top workflows:

| Workflow | Success state | Budget |
|---|---|---:|
| Triage inbox | Message list is filtered, selected, read, archived, flagged, or moved. | 5 actions from launch. |
| Search mail | Results show sender, subject, date, mailbox, and safe snippets. | 3 actions. |
| Read message | Message body, headers, attachments, and thread context are readable. | 2 actions from selected row. |
| Compose and send | Draft is validated, recipients are confirmed, send result is shown. | Domain-dependent; no hidden send. |
| Diagnose provider error | Auth, TLS, quota, or folder errors show safe next action. | 1 action from error banner. |

Interaction model:

- three-column mailbox view on wide terminals: folders, message list, reader;
- compact two-region layout on narrow terminals: list/reader toggled by mode;
- compose is a dedicated modal or full-screen mode with draft preservation;
- search and filters are local-first, with service requests cancellable.
- generic invoke remains read-only for Email; send/delete side effects belong
  only to the plugin-owned TUI or explicit CLI commands with confirmation.

First viewport:

- profile alias, provider type, mailbox, sync state, unread count, and last
  error;
- folder list or compact folder selector;
- message list with sender/subject/date/status;
- reader preview or empty-state guidance;
- command strip for search, compose, reply, move, archive, and help.

Keyboard vocabulary:

| Key | Behavior |
|---|---|
| `/` | Search current mailbox. |
| `f` | Folder selector. |
| `Enter` | Open selected message. |
| `c` | Compose. |
| `r` | Reply. |
| `m` | Move. |
| `a` | Archive, where supported. |
| `!` | Provider diagnostics. |
| `Esc` | Leave search, reader, compose, diagnostics, or attachment plan without losing confirmed state. |

Destructive and side-effect handling:

- sending mail requires a final confirmation showing recipient count and safe
  subject;
- deleting, moving, and marking bulk selections require explicit confirmation;
- discard draft requires confirmation when the draft is non-empty;
- attachments show metadata before open/download and never auto-execute.

Privacy and evidence rules:

- message bodies and attachment bytes must not be written to stderr, logs,
  panic output, audit summaries, fixture reports, or transcript evidence;
- transcripts may show synthetic fixture sender, subject, folder, counts,
  attachment filename, MIME type, and byte size, but not fixture body text;
- diagnostics show protocol, TLS mode, ports, `verify_tls`, deferred
  send/delete state, and provider error category only;
- provider errors redact email address, password, receive host, SMTP host,
  bearer/API tokens, and raw server greetings that contain account material;
- compose drafts stay in process memory until sent or discarded. A draft crash
  recovery note may record field presence and recipient count, not body text.

Attachment model:

- first pilot shows attachment metadata only: filename, MIME type, byte size,
  and whether download/open is planned;
- open/download actions require a local destination plan and explicit
  confirmation before any file is written or external viewer is launched;
- unsupported inline, encrypted, or malformed attachments render as safe
  metadata plus a provider/parser error, not raw MIME.

Compose model:

- compose, reply, and forward start in draft mode with fields for to, cc,
  subject, and body;
- send is disabled until at least one recipient and a subject/body review state
  are present;
- final send confirmation names recipient count, safe subject, attachment count,
  and SMTP profile label;
- failed send preserves the draft and shows a retry/discard choice.

States:

- empty mailbox, empty search results, folder unavailable, provider auth error,
  quota error, SMTP failure, offline/disconnected, and send success.

Non-goals:

- full rich-text editor parity;
- cross-account universal inbox in the first pilot;
- exposing raw message bodies in diagnostics or audit logs;
- sharing the SSH or storage layout.

Promotion evidence:

- service tests for list, search, fetch, compose validation, and provider
  errors;
- PTY transcript coverage for inbox, reader, search, attachment plan, compose,
  empty search, auth error, SMTP failure, and send confirmation;
- secret and message-body leak checks for diagnostics, stderr, panic output,
  audit summaries, fixture reports, and transcript artifacts.

## Docker Pilot

Target users:

- local developers and operators inspecting containers, images, compose-style
  stacks, logs, and exec sessions;
- users who need safe lifecycle actions without memorizing container IDs.

Top workflows:

| Workflow | Success state | Budget |
|---|---|---:|
| Triage containers | Running, unhealthy, exited, and selected container details are visible. | 2 actions. |
| Stream logs | Log stream starts, can pause/filter/search, and can be stopped. | 4 actions. |
| Exec into container | Command prompt validates target and opens an attach/exec stream. | 5 actions. |
| Restart or stop | Confirmation names container, image, and risk; result is shown. | 4 actions. |
| Recover daemon error | UI shows Docker unavailable or permission error with next action. | 1 action. |

Interaction model:

- dashboard with resource list, detail pane, and log/action pane;
- logs and exec are cancellable stream modes, not blocking list refresh;
- destructive actions use typed confirmation for multiple containers.

First viewport:

- profile alias or local context, daemon health, resource counts, active filter;
- container table with health/status/image/age;
- selected detail with ports, mounts, labels, recent errors;
- command strip for logs, exec, inspect, restart, stop, remove, refresh.

Keyboard vocabulary:

| Key | Behavior |
|---|---|
| `/` | Filter containers/logs. |
| `l` | Logs. |
| `x` | Exec or attach prompt. |
| `i` | Inspect details. |
| `r` | Restart confirmation. |
| `s` | Stop confirmation. |
| `D` | Remove confirmation. |

Non-goals:

- replacing Compose or Kubernetes orchestration tools;
- building a generic live-operations layout for every plugin;
- auto-running destructive lifecycle operations.

Promotion evidence:

- local Docker fixture tests for unavailable daemon, container list, logs, exec
  command validation, stop/restart confirmations, and stream cancellation;
- transcript coverage for running, empty, loading, error, and destructive
  confirmation states.

## Kubernetes Pilot

Target users:

- operators triaging namespace resources, pod status, events, logs, and exec
  sessions;
- engineers who need a guided terminal view over a known kubeconfig profile.

Top workflows:

| Workflow | Success state | Budget |
|---|---|---:|
| Triage namespace | Pods, deployments, services, events, and warnings are visible. | 3 actions. |
| Follow pod logs | Stream starts with container selector, filter, pause, and stop. | 5 actions. |
| Exec into pod | Pod/container are confirmed before raw session opens. | 6 actions. |
| Explain failure | Image pull, crash loop, scheduling, and permission errors are summarized. | 2 actions. |
| Delete or restart workload | Explicit typed confirmation and audit-safe summary. | 6 actions. |

Interaction model:

- resource navigator by namespace/kind with detail and events panes;
- log/exec are dedicated modes with cancellation and escape paths;
- watch updates are throttled and never block input.

First viewport:

- profile alias, context, namespace, cluster health, watch state;
- resource kind tabs or selector;
- table of resources with readiness, restarts, age, and warnings;
- details/events/log preview for selected resource.

Keyboard vocabulary:

| Key | Behavior |
|---|---|
| `n` | Namespace selector. |
| `k` | Resource kind selector. |
| `/` | Filter resources or logs. |
| `l` | Logs. |
| `x` | Exec prompt. |
| `e` | Events. |
| `d` | Describe. |
| `D` | Delete confirmation. |

Non-goals:

- replacing kubectl for arbitrary commands;
- hiding RBAC failures behind generic target errors;
- router-hosted cluster browser tabs.

Promotion evidence:

- kind fixture or deterministic unavailable-target tests for list, logs, exec
  prompt validation, RBAC error, watch cancellation, and destructive
  confirmation.

## S3 And WebDAV Storage Pilots

Target users:

- users browsing remote buckets/directories, previewing metadata, and planning
  upload/download/delete operations;
- operators who need transfer progress and retry guidance.

Top workflows:

| Workflow | Success state | Budget |
|---|---|---:|
| Browse remote path | Listing is paged, sortable, and selection is visible. | 3 actions. |
| Preview metadata | Safe object/path metadata is shown without downloading content. | 2 actions. |
| Download or upload | Plan is reviewed, transfer progress is shown, result is recoverable. | 5 actions after selection. |
| Delete | Typed confirmation names object count and prefix/path risk. | 5 actions. |
| Recover transfer failure | Failed item, reason, and retry/skip options are visible. | 2 actions. |

Interaction model:

- two-panel local/remote only if both sides are first-class; otherwise use a
  remote browser plus transfer queue;
- transfer queue is a persistent region with pause/cancel/retry;
- large prefixes/directories require bounded paging, never unbounded scans.

First viewport:

- profile alias, endpoint type, bucket/root path, permission/read-only state;
- remote listing with object/file name, size, modified time, type, status;
- selected metadata and transfer queue;
- command strip for open, parent, search, upload, download, delete, refresh.

Keyboard vocabulary:

| Key | Behavior |
|---|---|
| `/` | Filter listing. |
| `Enter` | Open prefix/directory. |
| `Backspace` | Parent. |
| `u` | Upload plan. |
| `d` | Download plan. |
| `D` | Delete confirmation. |
| `p` | Preview metadata. |
| `t` | Transfer queue. |

Non-goals:

- generic file manager reused across plugins without ownership;
- sync conflict resolution inside the first browser pilot;
- automatic recursive operations without plan and confirmation.

Promotion evidence:

- S3 MinIO or WebDAV fixture tests for browse, metadata, transfer planning,
  progress, retryable failure, permission error, and delete confirmation.

## Jenkins Pilot

Target users:

- developers and release operators inspecting jobs, queued/running builds,
  console logs, parameters, and stop/retry decisions.

Top workflows:

| Workflow | Success state | Budget |
|---|---|---:|
| Find job/build | Job list and selected build status are visible. | 3 actions. |
| Stream console | Console stream starts, can pause/search, and highlights failure clues. | 4 actions. |
| Trigger build | Parameters are reviewed and explicit confirmation starts build. | Domain-dependent. |
| Stop build | Confirmation names job/build/user-visible risk. | 4 actions. |
| Recover server error | Auth, crumb, unavailable, and permission errors show next action. | 1 action. |

Interaction model:

- job/build navigator with detail pane and console stream mode;
- queued/running/failed states are visible without opening logs;
- trigger and stop are modal flows with audit-safe summaries.

First viewport:

- profile alias, server label, auth/crumb state, queue health;
- job list with health, last build, branch/folder context;
- selected build detail and latest console/error preview.

Keyboard vocabulary:

| Key | Behavior |
|---|---|
| `/` | Search jobs/logs. |
| `Enter` | Open job/build. |
| `l` | Console log. |
| `b` | Trigger build. |
| `s` | Stop build confirmation. |
| `r` | Retry/rebuild confirmation. |
| `p` | Parameters. |

Non-goals:

- complete Jenkins administration;
- editing job definitions in the first pilot;
- exposing tokens, crumb values, or raw server responses in diagnostics.

Promotion evidence:

- fixture or mocked-service tests for job list, console stream, trigger
  validation, stop confirmation, auth/permission errors, and unavailable server.

## Sync Minimal TUI Or CLI-Only

Target users:

- users reviewing sync status, enrollment, conflicts, and server reachability;
- operators who need a guided view only when CLI status is insufficient.

Retained TUI threshold:

- keep a TUI only if conflict review or device enrollment has a human decision
  path that is safer in an interactive app than in `voidb sync` commands;
- otherwise classify Sync as CLI-only and invest in structured status,
  diagnostics, and conflict commands.

Minimum retained workflows:

- status dashboard with local device, server, last sync, pending objects;
- conflict list with explicit force/revision acknowledgement;
- server-unavailable and credential-unavailable states;
- no automatic force resolution from the first viewport.

Non-goals:

- replacing scripted sync automation;
- hiding cryptographic or credential failures behind generic messages;
- syncing plugin-local TUI state before each plugin defines its schema.

## SQL And Data Inspector Decisions

This family includes MySQL, PostgreSQL, SQLite, DuckDB, Redis, MongoDB, and
Elasticsearch.

Default position:

- CLI/capability-first unless a plugin-specific human inspection workflow has
  evidence that a TUI is materially better;
- old database and Redis router-hosted UIs were removed by Requirement 77;
  future inspectors require a new plugin-owned design and PTY evidence;
- MongoDB and Elasticsearch must prove bounded document/index inspection,
  safe mutation handling, and fixture-backed errors before becoming retained
  TUIs.

Retained inspector minimums:

- passing the Requirement 83 data inspector gate in
  [Data Inspector CLI-First Decisions](data-inspector-cli-first-decisions.md);
- bounded paging and explicit query/filter controls;
- read-only mode at launch;
- mutation preview or dry-run where supported;
- visible schema/document/index context;
- large-result and target-error states that remain responsive;
- no shared SQL browser copied into non-SQL plugins.

CLI-only evidence:

- documented commands and capabilities cover the top read/query workflows;
- examples exist for list, describe, query/search, bounded pagination, and
  target errors;
- release notes explain that legacy router-hosted UI is not the default path.

Requirement 83 current decision:

- MySQL, PostgreSQL, and DuckDB are `CLI-only`;
- SQLite, Redis, MongoDB, and Elasticsearch are `Later candidate` surfaces that
  still ship as CLI-only;
- no data inspector has an accepted or retained TUI pilot.

## Pilot Selection Rule

When more than one pilot is available, prioritize the plugin that exercises the
highest number of unique risks while still being testable locally:

1. SSH for raw input, host-key, reconnect, SFTP, forwarding, and PTY cleanup.
2. Email for triage, compose, provider errors, and safe message handling.
3. Kubernetes or Docker for live logs, exec/attach, watches, and destructive
   lifecycle actions.
4. S3 or WebDAV for transfer planning and retryable file/object operations.
5. Jenkins for build/log triage and stop/retry safety.
6. Sync only if conflict review needs guided human interaction.

Each pilot must update its plugin readiness document with the chosen brief,
skipped workflows, validation commands, and remaining gaps before it can be
classified as retained.
