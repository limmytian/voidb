# Email TUI

Requirement 82 rebuilds Email as a plugin-owned standalone TUI for mailbox
triage, reader, search, attachment planning, compose, send confirmation, and
provider diagnostics.

## Launch

Use a migrated profile:

```bash
voidb-cli email tui --profile <profile>
```

Use a legacy connection during migration:

```bash
voidb-cli email tui --connection <connection>
```

Secret-free preflight:

```bash
voidb-cli email tui --profile <profile> --format json
```

Deterministic fixture mode for PTY evidence:

```bash
voidb-cli email tui \
  --fixture crates/plugins/voidb-plugin-email/fixtures/email_tui_smoke.json
```

## Retained Workflows

- mailbox and folder overview with bounded first-page message listing;
- local sender/subject search over the loaded page;
- reader view using read-only body fetch or fixture bodies;
- attachment metadata plan showing filename, MIME type, and byte size only;
- compose and reply draft mode with recipient, subject, and body validation;
- final send confirmation before SMTP is contacted;
- dirty-draft discard confirmation;
- provider diagnostics for auth, TLS, quota, folder, and transport failures.

The TUI does not auto-open attachments or auto-write downloaded files. Fixture
mode never opens SMTP, even when a send confirmation is accepted. The generic
Agent surface is separate and applies its own scoped approval, preview,
acknowledgement, stable-identity, and local-path gates.

## External-Agent Access

Email uses capabilities plus a mailbox-scoped `email.idle` Agent Session for
external agents. The standalone TUI does not publish its human UI state, share
its client, or host an agent conversation. The plugin service owns every live
IMAP, POP3, and SMTP client.

Full attachment bytes, draft bodies, credentials, provider greetings, and live
protocol clients are never exposed in audit or discovery output. Bounded fetch
may return explicitly requested message text. Send/delete/move/flag and
attachment materialization are invokable only with their declared scoped
approval, dry-run support, and acknowledgement gates. See the
[Email Agent policy](email-agent-policy.md) and
[External-Agent Interaction Contract](assist-handoff.md).

## CLI And Capability Fallback

Human CLI:

```bash
voidb-cli email folders --connection <connection>
voidb-cli email list --connection <connection> INBOX --limit 20
voidb-cli email read --connection <connection> INBOX <uid>
voidb-cli email delete --connection <connection> INBOX <uid>
```

Agent invocation exposes bounded reads and guarded writes:

```bash
voidb-cli invoke list email --format json
voidb-cli invoke describe email.list --format json
voidb-cli invoke run email.search --profile <profile> \
  --input-json '{"folder":"INBOX","query":"subject","limit":10}'
voidb-cli invoke run email.fetch --profile <profile> \
  --input-json '{"folder":"INBOX","uid":1,"max_text_bytes":4096}'
voidb-cli invoke run email.send --profile <profile> --dry-run \
  --input-json '{"to":["recipient@example.test"],"subject":"Status","text_body":"Ready","idempotency_key":"status-send-0001"}'
```

`email.idle` is session-only; discovery returns its live-session handoff
contract instead of treating it as a one-shot invocation.

## Evidence 2026-07-07

Focused validation:

```bash
rustfmt --edition 2024 --check crates/plugins/voidb-plugin-email/src/tui.rs
cargo test -p voidb-plugin-email --quiet
cargo test -p voidb-cli email --quiet
cargo run -p voidb-cli -- email tui \
  --fixture crates/plugins/voidb-plugin-email/fixtures/email_tui_smoke.json \
  --format json
/usr/bin/git diff --check
```

PTY smoke:

```text
command: target/debug/voidb-cli email tui --fixture crates/plugins/voidb-plugin-email/fixtures/email_tui_smoke.json
exit_code: 0
transcript: target/tmp/email-tui-pty/email-tui.ansi
missing_markers: []
leak_markers: []
```

The PTY smoke covers first frame, reader, attachment plan, search, diagnostics,
compose, send confirmation, and quit. It scans for the fixture body marker
`PRIVATE_BODY_SHOULD_NOT_APPEAR` and the synthetic draft body marker used by the
smoke; neither appears in the transcript. The fixture uses `redact_bodies` so
reader and compose evidence can prove the states without preserving message
body text in transcript artifacts.

Skipped or deferred checks:

- real-provider IMAP/POP3/SMTP compatibility smoke remains optional and must
  use non-production mailboxes;
- auth, TLS, quota, and provider-specific SMTP failures are classified in the
  TUI, but live provider failure fixtures were not run in this slice;
- attachment open/download still stops at safe planning and requires future
  destination/confirmation implementation before writing files.
