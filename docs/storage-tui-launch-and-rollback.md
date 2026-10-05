# Storage TUI Launch And Rollback

This runbook records Task Weaver requirement 80 storage TUI launch, evidence,
known gaps, rollback behavior, and scripted equivalents for S3 and WebDAV.

## Launch Commands

S3:

```bash
voidb-cli s3 tui --profile <profile>
voidb-cli s3 tui --profile <profile> --readonly
voidb-cli s3 tui --profile <profile> --format json
voidb-cli s3 tui --fixture crates/plugins/voidb-plugin-s3/fixtures/s3_tui_browser.json \
  --evidence target/tmp/s3-tui-fixture-evidence.json
```

WebDAV:

```bash
voidb-cli webdav tui --profile <profile>
voidb-cli webdav tui --profile <profile> --readonly
voidb-cli webdav tui --profile <profile> --format json
voidb-cli webdav tui --fixture crates/plugins/voidb-plugin-webdav/fixtures/webdav_tui_browser.json \
  --evidence target/tmp/webdav-tui-fixture-evidence.json
```

`--profile` is the preferred launch path because it goes through the connection
profile and credential grant flow. `--connection` remains available for legacy
local connection names. `--fixture` is deterministic and must not open the
network.

## Terminal Contract

The storage TUIs are standalone plugin-owned terminal applications. They do not
run inside the old router shell and do not host other plugin tabs. The service
boundary is channel mode:

- S3 uses `S3Service::Channel`.
- WebDAV uses `WebDavService::Channel`.

The launch preflight reports `raw_input: false`; storage browsers keep shell
keyboard semantics rather than forwarding all keys to a remote process. Quit
must restore terminal state through the TUI runtime cleanup path.

Unsupported or partial terminal environments:

- non-interactive stdin/stdout without a TTY;
- terminals that cannot enter alternate-screen/raw-mode through crossterm;
- widths too narrow for a browser and metadata panel, where operators should
  use CLI or capability commands instead;
- sessions where target network calls block before the first remote listing,
  which should still use preflight or fixtures for diagnostics.

## Fixture Evidence

S3 fixture evidence is recorded in
S3 Standalone TUI Evidence - 2026-07-07.
The deterministic artifact covers startup, bucket/prefix browsing, metadata
preview, local filtering, transfer planning, delete confirmation, permission
failure, resize, quit/restore, and marker-based secret leak scanning.

WebDAV fixture evidence is recorded in
WebDAV Standalone TUI Evidence - 2026-07-07.
The deterministic artifact covers startup, directory browsing, metadata
preview, local filtering, transfer planning, delete confirmation, permission
failure, resize, quit/restore, and marker-based secret leak scanning.

Evidence JSON files stay under `target/tmp` and are not committed. The
committed fixtures and commands above make them reproducible.

## External-Agent Access

S3 and WebDAV are capability-only for external agents. Their standalone TUIs
do not publish browser state, open a session share, or host an agent
conversation. Agents discover and invoke the existing object and sync-plan
capabilities; the plugin service retains every live storage client.

Capability results withhold credentials, local paths, object content, raw
diagnostics, and live clients. `put`, `delete`, and `mkdir` remain destructive,
dry-run-only before acknowledgement, and subject to the ordinary capability
policy. `list`, `stat`, `get`, and `sync_plan` remain read-only.

Copy and move exist in plugin services but are not current generic
capabilities. External copy/move proposals therefore fail closed instead of
bypassing capability policy. See the
[External-Agent Interaction Contract](assist-handoff.md).

## Rollback Behavior

The rollback path is operational, not a reintroduction of legacy router-hosted
storage UI code.

- Stop using `voidb-cli s3 tui` or `voidb-cli webdav tui` for the affected
  plugin.
- Use the plugin CLI commands listed below for the same operation.
- Use `voidb-cli invoke describe <capability>` and
  `voidb-cli invoke run <capability>` for machine-readable scripted flows.
- Keep profile and credential configuration unchanged; rollback does not
  require profile migration.
- Do not restore the old router-hosted file manager or shared TUI widgets.

Read-only launches are a partial rollback mode for human operators: browsing
and planning remain available, while mutating plans stay non-executing.

## Scripted Equivalents

S3 CLI equivalents:

```bash
voidb-cli s3 ls --connection <connection> [s3://bucket/prefix]
voidb-cli s3 info --connection <connection> s3://bucket/key
voidb-cli s3 get --connection <connection> s3://bucket/key ./local-file
voidb-cli s3 put --connection <connection> ./local-file s3://bucket/key
voidb-cli s3 rm --connection <connection> s3://bucket/key
voidb-cli s3 pull --connection <connection> s3://bucket/prefix ./local-dir --dry-run
voidb-cli s3 push --connection <connection> ./local-dir s3://bucket/prefix --dry-run
```

S3 capability equivalents:

```bash
voidb-cli invoke run s3.list --profile <profile> --input-json '{"bucket":"bucket","prefix":"prefix/"}' --format json
voidb-cli invoke run s3.stat --profile <profile> --input-json '{"bucket":"bucket","key":"prefix/file.txt"}' --format json
voidb-cli invoke run s3.get --profile <profile> --input-json '{"bucket":"bucket","key":"prefix/file.txt"}' --format json
voidb-cli invoke run s3.put --profile <profile> --input-json '{"bucket":"bucket","key":"prefix/file.txt","content_base64":"..."}' --dry-run --format json
voidb-cli invoke run s3.delete --profile <profile> --input-json '{"bucket":"bucket","key":"prefix/file.txt"}' --dry-run --format json
voidb-cli invoke run s3.sync_plan --profile <profile> --input-json '{"bucket":"bucket","remote_prefix":"prefix/","local_root":"/approved/root","local_path":"local-dir","mode":"pull"}' --format json
```

WebDAV CLI equivalents:

```bash
voidb-cli webdav ls --connection <connection> /remote/path/
voidb-cli webdav info --connection <connection> /remote/path/file.txt
voidb-cli webdav get --connection <connection> /remote/path/file.txt ./local-file
voidb-cli webdav put --connection <connection> ./local-file /remote/path/file.txt
voidb-cli webdav rm --connection <connection> /remote/path/file.txt
voidb-cli webdav pull --connection <connection> /remote/path/ ./local-dir --dry-run
voidb-cli webdav push --connection <connection> ./local-dir /remote/path/ --dry-run
```

WebDAV capability equivalents:

```bash
voidb-cli invoke run webdav.list --profile <profile> --input-json '{"path":"/remote/path/"}' --format json
voidb-cli invoke run webdav.stat --profile <profile> --input-json '{"path":"/remote/path/file.txt"}' --format json
voidb-cli invoke run webdav.get --profile <profile> --input-json '{"path":"/remote/path/file.txt"}' --format json
voidb-cli invoke run webdav.put --profile <profile> --input-json '{"path":"/remote/path/file.txt","content_base64":"..."}' --dry-run --format json
voidb-cli invoke run webdav.delete --profile <profile> --input-json '{"path":"/remote/path/file.txt"}' --dry-run --format json
voidb-cli invoke run webdav.sync_plan --profile <profile> --input-json '{"remote_path":"/remote/path/","local_root":"/approved/root","local_path":"local-dir","mode":"pull"}' --format json
```

## Known Gaps

- The TUI operation panels stage upload paths but do not provide an interactive
  local path picker.
- Recursive deletes, copies, moves, and sync apply remain preview-oriented until
  the service can present bounded descendant counts in the TUI.
- Live provider compatibility is covered by the existing S3/WebDAV fixture
  smoke gates, not by the deterministic TUI fixtures.
- PTY timing metrics for first-frame and quit-restore budgets remain part of
  the broader standalone TUI release gate.

These gaps do not block the requirement 80 storage browser implementation
because the retained scope is standalone browsing, metadata inspection,
transfer/delete planning, safe preflight, and deterministic evidence.
