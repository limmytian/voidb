# Live Operations TUI Safety

This note records the Task Weaver requirement 81 slice 1 safety contract for
Docker, Kubernetes, and Jenkins standalone TUIs. It defines shared constraints
without creating shared UI state, shared keymaps, or a generic operations
layout.

## Scope

Each live-operations plugin owns its standalone command and terminal lifecycle:

```bash
voidb-cli docker tui --profile <profile>
voidb-cli kubernetes tui --profile <profile>
voidb-cli jenkins tui --profile <profile>
```

The TUIs may reuse non-UI contracts such as profile resolution, credential
grants, redaction, capability policies, audit schema, and plugin service
commands. They must not share widgets, state machines, focus models, stream
buffers, or confirmation dialogs.

## Stream Bounds

Live streams must be bounded before they reach UI state:

- log buffers keep a fixed maximum line count per stream;
- console and event streams track byte counts, dropped-line counts, and latest
  cursor or timestamp when available;
- stream panes render the newest data by default but preserve a paused scroll
  position when the operator scrolls back;
- target stream errors are rendered as redacted state, not panic output;
- background streams stop when the view closes, the profile changes, or the TUI
  exits.

Default retained buffers:

| Plugin | Stream | Default retained data |
|---|---|---:|
| Docker | container logs | 2,000 lines or 2 MiB |
| Docker | exec/attach transcript | 1,000 lines or 1 MiB |
| Kubernetes | pod logs/events/watch | 2,000 lines or 2 MiB per selected target |
| Kubernetes | exec transcript | 1,000 lines or 1 MiB |
| Jenkins | console log | 5,000 lines or 5 MiB |

The TUI must disclose truncation in status or metadata panels.

## Cancellation

Every long-running operation needs a visible cancellation path:

- log follow and watch streams use `c` or an explicit cancel action;
- exec/attach sessions reserve an escape sequence before raw input begins;
- target operations keep cancellation tokens in service state, not UI widgets;
- cancellation is best effort and must report whether the target acknowledged,
  timed out, or left an unknown state;
- quitting the TUI sends cancellation to active streams before terminal restore.

Plugin-specific requirements:

- Docker attach and exec must close stdin/stdout bridges and report exit state
  when known.
- Kubernetes watches and exec must close watch handles or remote command
  streams and report namespace/resource context.
- Jenkins console follow must stop polling without aborting the build unless a
  separate destructive stop plan is confirmed.

## Exec And Attach Escape Paths

Raw input is allowed only inside explicit exec/attach modes. Before entering raw
input, the TUI must show:

- target summary;
- command or attach mode;
- requested TTY/stdin behavior;
- escape sequence;
- whether keystrokes are forwarded to the target.

Default escape sequences:

| Plugin | Raw mode | Escape |
|---|---|---|
| Docker | exec/attach | `Ctrl+]` then `q` |
| Kubernetes | exec | `Ctrl+]` then `q` |
| Jenkins | none by default | not applicable |

Shell global shortcuts must not be assumed while raw input is active.

## Watch Throttling

Watch and polling views must avoid busy repaint loops:

- redraw only after a service event, explicit key event, resize, or bounded tick;
- coalesce rapid watch updates into a single UI frame;
- record dropped/coalesced event counts in diagnostics;
- use exponential backoff after target transport errors;
- keep reconnect attempts explicit after auth or permission failures.

Suggested minimum intervals:

| Source | Interval |
|---|---:|
| Docker list refresh | 2 seconds |
| Docker log follow repaint | 100 ms coalesced |
| Kubernetes resource watch repaint | 100 ms coalesced |
| Kubernetes fallback poll | 2 seconds |
| Jenkins console follow poll | 1 second |

## Destructive Action Safety

Destructive or externally side-effecting actions must enter a plan state before
execution.

Docker destructive or side-effecting actions:

- stop, restart, kill, remove container;
- remove image, network, or volume;
- exec/attach when stdin is forwarded;
- prune operations.

Kubernetes destructive or side-effecting actions:

- delete resource;
- rollout restart;
- scale workload;
- apply patch;
- exec into pod;
- port-forward or log follow that may expose sensitive output.

Jenkins destructive or side-effecting actions:

- trigger build;
- stop or abort build;
- replay/retry build;
- submit build parameters;
- mutate queue item when supported.

Confirmation rules:

- low-blast-radius plans require `y`;
- destructive plans require a second `y` after the summary is visible;
- bulk, namespace-wide, prune, or irreversible plans require typed target text;
- read-only launches may stage plans but must not send mutating service
  commands;
- every executed plan emits an audit summary with profile ref, plugin id,
  target summary, acknowledgement state, result, timing, and redaction status.

External-agent interaction for Docker, Kubernetes, and Jenkins is non-PTY and
external-first:

- `a` explicitly shares or refreshes bounded, redacted current-view context;
- `A` is not an operation shortcut and the TUI has no conversation surface;
- the plugin automatically notices a new structured operation request without
  blocking its service channel or terminal event loop;
- `y` stages the request into the plugin's existing operation plan, while `n`
  (or `d` in Kubernetes) records denial without staging;
- current-PTY targets are rejected for all three infrastructure TUIs;
- service execution still requires the existing human confirmation path, with
  destructive plans retaining their second confirmation.

SSH current-PTY control is the only live-input sharing case:

- agent guidance and agent-side inspection never write the human PTY;
- proposed current-PTY commands require a visible operation panel and one
  explicit `y` decision; `A` also scopes later automatic commands to the exact
  agent principal and current share lifetime;
- a successful approval or denial closes the review, and the store atomically
  rejects another confirmation for the same operation request and action index;
- only one writer may own current PTY input at a time;
- the status line must show the owner state and dropped-input count;
- the human revoke path is `Ctrl+]` then `v` and must work from raw terminal
  mode;
- stale session generations, host-key prompts, disconnected/error states,
  password-like prompts, pending local input, readonly launch, and oversized
  retained output block takeover;
- alternate-screen/application-key modes produce a visible warning that the
  local operator may accept after inspecting the exact command and current
  terminal; approval acquires the single-writer lease before sending input;
- action confirmations and control/revoke/expire outcomes are audited with
  redaction status and without raw screen, transcript, stdin, credentials, or
  live handle details.

## Error And Privacy Boundaries

Error panels must preserve categories before rendering human text:

- validation;
- auth;
- permission or RBAC;
- target unavailable;
- timeout;
- stream closed;
- conflict or locked state;
- plugin/service error;
- terminal error.

Secrets and private output must not appear in diagnostics:

- Docker: registry tokens, env vars, bind-mount private paths, secret names when
  policy marks them sensitive, raw exec input, and unredacted container env.
- Kubernetes: kubeconfig tokens/certs, secret data, service-account tokens,
  private image pull credentials, raw exec input, and unredacted RBAC
  diagnostics.
- Jenkins: API tokens, crumb values, cookies, build parameters marked secret,
  credentials IDs when policy marks them sensitive, and raw console lines
  classified as secret-bearing.

Evidence fixtures may use deterministic names and log lines, but not production
target names, credentials, raw env dumps, or private file paths.

## Audit Summaries

Each executed side-effecting plan records a bounded audit summary:

- plugin id and profile ref;
- operation kind and risk level;
- target identity and safe display label;
- dry-run or readonly state;
- confirmation method;
- cancellation token or stream id when applicable;
- result state and elapsed time;
- byte/line counts for streamed output;
- redaction status and any dropped diagnostics.

Audit summaries must not include raw logs, console bodies, command stdin,
secret-bearing parameters, decrypted config, or target credential material.

## Plugin-Owned UX Notes

Docker should feel like a container triage console: container list, details,
logs, lifecycle plan, and explicit exec/attach prompt.

Kubernetes should feel like a resource triage console: namespace/resource list,
workload/pod details, events, logs, watch state, and explicit exec or rollout
plans.

Jenkins should feel like a build and console triage console: job/build list,
queue/running/failed states, console follow, search, trigger parameter preview,
and stop/retry plans.

The only shared contract is safety. Rendering, navigation, and local state stay
inside each plugin crate.
