# Email Agent Mutation and Transfer Policy

This document defines the safety contract for the guarded Email Agent
capabilities. The executable policy lives in
`crates/plugins/voidb-plugin-email/src/policy.rs`.

## Operation classification

| Operation | Risk | Permission | Dry-run | Apply acknowledgement |
| --- | --- | --- | --- | --- |
| send | external side effect | `email.send` | required preview support | required |
| move | external side effect | `email.move` | required preview support | required |
| delete | destructive | `email.delete` | required preview support | required |
| set flags | external side effect | `email.set_flags` | required preview support | required |
| download attachment | external side effect | `email.download_attachment` | required preview support | required |

Read-only grants and presets contain none of these write permissions. Discovery,
folder listing, message listing/search, message fetch, attachment metadata, and
mailbox event observation remain separately scoped read operations.

## Preview and audit boundary

Every write supports a no-network dry-run. Send previews expose only recipient,
domain, subject/body byte, and attachment byte counts. They never echo
addresses, subject text, bodies, attachment source paths, credentials, or
attachment bytes. Mailbox mutation previews expose message/mailbox counts and
whether a destination or flags are present, but not message bodies or headers.

Apply requires both a scoped approval evaluated by the shared capability
policy and a per-invocation acknowledgement. The plugin repeats the
acknowledgement check before any SMTP, IMAP, or local-file side effect.

All write requests carry a caller-owned idempotency key of 16–128 ASCII token
characters. Implementations retain bounded outcomes so retries can return the
prior result instead of repeating a send or mailbox mutation.

## Message identity and stale-target protection

Mailbox mutations and attachment downloads address a message with:

- mailbox name;
- server `UIDVALIDITY`;
- message UID;
- optional expected modification sequence (`MODSEQ`).

Sequence numbers are never accepted as Agent mutation identities. Before an
apply, the service re-selects the mailbox, compares `UIDVALIDITY`, resolves the
UID, and checks `MODSEQ` when supplied. Any mismatch fails closed before
changing the mailbox or materializing an attachment.

## Recipient guardrails

Structured mailbox addresses are required. Header injection, display-name
syntax in address fields, empty recipients, invalid domains, and more than 50
combined To/Cc/Bcc recipients are rejected. A request may narrow the default
with a lower recipient limit, a domain allowlist, or a domain blocklist.
Previews report only counts, including the number of recipients outside the
sender domain.

## Content and attachment limits

- subject: single-line, at most 998 bytes;
- text body: at most 1 MiB;
- HTML body: at most 2 MiB;
- attachments: at most 20 files;
- one attachment: at most 25 MiB;
- combined attachments: at most 50 MiB.

Attachment upload reads only approved local sources through the shared local
filesystem boundary. Attachment download writes only to approved destinations,
uses atomic no-replace creation, and never trusts a MIME filename as a path.
Empty names, control characters, path separators, traversal aliases, and names
over 255 bytes are rejected.

## Protocol and cancellation rules

Send uses SMTP and never shares a live SMTP handle. Move, delete, flags,
attachment fetch, and IDLE require IMAP; POP3 reports those operations as
unsupported instead of approximating weaker semantics. Long reads, local
transfers, SMTP send, and IMAP IDLE observe the shared cancellation token and
return bounded, redacted outcomes.

`email.idle` is a session-only watch stream for one mailbox. Its discovery
contract caps the buffer at 512 events / 512 KiB, drops the oldest event with
observable loss accounting, binds every resume cursor to the mailbox resource,
emits 15-second heartbeats, retries transient failures with bounded backoff,
supports per-call cancellation, and stops observation on idempotent close.
Events contain only UIDVALIDITY, highest UID, message count, optional highest
MODSEQ, and a change classification.

## Deterministic evidence

The default unit and CLI gates verify catalog risk/permission declarations,
approval schemas, acknowledgement denial, no-network redacted previews,
recipient-domain denial, unsafe attachment-name rejection, stable message
identity previews, audit-summary redaction, IDLE cursor scoping, cancellation,
and close cleanup.

The opt-in GreenMail smoke additionally exercises acknowledged structured SMTP
send with an approved attachment source, idempotent replay, stable-UID flag
partial failure, attachment metadata/download and traversal denial, mailbox
move, UID expunge, and content-free IDLE arrival/cancellation. The checked-in
Email PTY journey remains the standalone-TUI latency, idle, resize, terminal
restoration, and transcript leak gate.
