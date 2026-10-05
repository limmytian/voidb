# Storage TUI UX Decisions

This note records the Requirement 80 slice 1 decisions for plugin-owned S3 and
WebDAV storage browsers. It is a design and safety contract for later
implementation slices; it does not reintroduce a shared router-hosted file
manager.

## Scope

S3 and WebDAV should each own an independent standalone command:

```bash
voidb-cli s3 tui --profile <profile>
voidb-cli webdav tui --profile <profile>
```

Both TUIs may reuse non-UI contracts such as profile resolution, redaction,
capability policy, service commands, pagination limits, and fixture smoke
patterns. They must not share widgets, focus state, keymaps, transfer queues, or
UI state machines. Storage behavior that is common in concept is expressed here
as a contract; rendering and runtime state stay inside each plugin crate.

## S3 Browser Brief

S3 is an object and prefix browser, not a local/remote two-panel file manager.
The first viewport should show the selected bucket, current prefix, object
count/page status, and a right-side metadata/operation panel for the selected
object or prefix. Bucket switching is explicit because changing buckets changes
the policy and error boundary.

Primary S3 workflows:

- browse buckets and prefixes with bounded pages
- filter the current page by key fragment, suffix, size range, or storage class
- preview object metadata: key, size, ETag, last modified, storage class, and
  content type when available
- stage download, upload, delete, and virtual-directory creation plans
- compute or display sync-plan summaries through the existing S3 sync plan
  capability path
- show permission, missing-object, region, endpoint, and authentication errors
  as redacted target-state panels

S3 key vocabulary:

| Key | Action |
|---|---|
| `j` / `k`, Up / Down | Move selection within the loaded page. |
| `Enter` | Open a prefix; object selection only updates the metadata panel. |
| `Backspace` | Move to parent prefix. |
| `/` | Filter the loaded page locally. |
| `n` / `p` | Load next or previous bounded page. |
| `m` | Open metadata panel for the selected object. |
| `d` | Stage a download plan for the selected object. |
| `u` | Stage an upload plan; execution requires an explicit local path. |
| `x` | Stage a delete plan for the selected object or prefix marker. |
| `y` | Confirm the staged plan; destructive plans require a second `y`. |
| `c` | Cancel the staged plan or active transfer. |
| `r` | Retry the last failed page load or transfer. |
| `q` | Quit after terminal cleanup. |

S3 transfer UI should be a queue panel, not direct execution from selection.
Each queue item records source, target bucket/key, expected size when known,
overwrite policy, dry-run/preview state, and latest service event. Recursive
prefix delete and sync must start as a preview-only plan and show the number of
affected objects before confirmation.

## WebDAV Browser Brief

WebDAV is a remote path browser over hierarchical collections. It should feel
closer to SFTP than S3 because directories are first-class resources, but it
still stays plugin-owned and service-backed.

The first viewport should show the current remote path, a sortable entry list,
and a right-side metadata/operation panel. A local panel is not part of the
initial design; local paths are explicit operation inputs so the TUI does not
become a general file manager.

Primary WebDAV workflows:

- browse remote collections with bounded page windows
- filter the current collection by name, kind, size, or modified date
- preview metadata: path, item kind, size, modified date, ETag, content type,
  and server capability hints when available
- stage download, upload, delete, mkdir, copy, move, and sync-plan operations
- show auth, TLS, permission, conflict, locked-resource, and missing-path errors
  as redacted target-state panels

WebDAV key vocabulary:

| Key | Action |
|---|---|
| `j` / `k`, Up / Down | Move selection within the loaded collection. |
| `Enter` | Open a collection; file selection updates metadata. |
| `Backspace` | Move to parent collection. |
| `/` | Filter the loaded collection locally. |
| `n` / `p` | Load next or previous bounded page when the service paginates. |
| `m` | Stage mkdir under the current collection. |
| `d` | Stage a download plan for the selected file. |
| `u` | Stage an upload plan; execution requires an explicit local path. |
| `v` | Stage move or rename for the selected item. |
| `o` | Stage copy for the selected item. |
| `x` | Stage delete for the selected item. |
| `y` | Confirm the staged plan; destructive plans require a second `y`. |
| `c` | Cancel the staged plan or active transfer. |
| `r` | Retry the last failed list or transfer operation. |
| `q` | Quit after terminal cleanup. |

WebDAV transfer UI should show one active operation plus a small queued list.
Directory deletes, moves, and copies must be previewed as recursive plans when
the service can enumerate descendants; otherwise the TUI must label the plan as
server-side recursive and require a second confirmation.

## Shared Safety Contract

The storage TUIs share operation rules but not UI code.
Transfer queue items and service events use the driver-free lifecycle in
[Storage Agent Transfer Contract](storage-agent-transfer-contract.md), so Agent,
CLI JSON/stream, and TUI progress cannot diverge on phase, counters, retry,
conflict, resume, cancellation, cleanup, or redaction semantics.

Listing:

- Always bound list calls by the plugin capability or service page limit.
- Persist cursor/page state only in plugin-local memory.
- Show partial results and retry affordances when a page fails.
- Do not log object keys, paths, URLs, or response bodies outside the TUI
  unless they have been classified as safe metadata for the evidence artifact.

Planning:

- Mutating operations enter the transfer queue as plans before execution.
- Uploads and downloads must display source, destination, size if known, and
  overwrite behavior before confirmation.
- Delete, recursive overwrite, move, copy, mkdir collision, and sync apply are
  destructive or externally side-effecting and require explicit confirmation.
- Destructive plans require a second confirmation key after the summary is
  visible.
- Read-only launches may browse and stage plans but must not send mutating
  service commands.

Progress and retry:

- Transfers render byte progress when the service provides totals; otherwise
  render transferred bytes and an indeterminate state.
- Retry reuses the same plan after refreshing target metadata.
- Skip is available for multi-item plans and must record skipped item counts.
- Cancel signals the plugin service or worker and marks any partial local or
  remote cleanup result in the queue.

Errors and redaction:

- Target errors are rendered with plugin-specific stable codes and redacted
  target messages.
- S3 must redact endpoints, regions/accounts when policy marks them sensitive,
  access keys, secret keys, session tokens, signed URLs, and raw provider
  diagnostics.
- WebDAV must redact URLs, usernames, passwords, bearer tokens, cookies, auth
  headers, and raw server diagnostics.
- Evidence transcripts may include deterministic fixture object names or paths,
  but not configured production keys, URLs, credentials, response bodies, or
  local private file paths.

Audit summaries:

- Every executed mutating plan should have a bounded summary: operation kind,
  item count, byte count if known, destination class, dry-run flag, confirmation
  state, completion state, and redaction status.
- Audit output must not contain file contents, object bodies, credentials,
  signed URLs, raw plugin config, or unredacted target errors.

## Fixture And Evidence Direction

S3 evidence should use the local MinIO fixture or deterministic fixture JSON to
cover startup, bucket/prefix listing, metadata preview, transfer planning,
permission failure, delete confirmation, resize, quit/restore, and leak checks.

WebDAV evidence should use the local rclone WebDAV fixture or deterministic
fixture JSON to cover startup, directory listing, metadata preview, transfer
planning, permission failure, delete confirmation, resize, quit/restore, and
leak checks.

Both evidence paths should emit a secret-free `--format json` preflight and a
fixture evidence artifact under `target/tmp`. The committed documentation should
record the exact command, observed coverage, and any skipped live fixture
conditions.

Launch, rollback, unsupported-terminal, and scripted-equivalent details are
recorded in [Storage TUI Launch And Rollback](storage-tui-launch-and-rollback.md).
