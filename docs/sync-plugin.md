# VoidB Sync — architecture

End-to-end encrypted synchronization of `~/.config/voidb/` (and any future
plugin data that lives under it) across devices.

This document describes the current beta-certified, opt-in sync plugin and
server. The capability-first boundary for when sync may become a stable product
contract is defined in
[Sync Boundary Under The Capability Model](sync-boundary.md), with the concrete
target object contract in [Object-Level Sync Model](object-level-sync-model.md).
Beta evidence is recorded in Sync Beta Readiness, and
release smoke gates are defined in Release Sync Smoke.

- **Client**: `crates/plugins/voidb-plugin-sync/` (`voidb-plugin-sync` in the
  plugin registry, id `sync`)
- **Server**: `voidb-sync-server/` — a standalone crate (its own
  `[workspace]`, not part of the main voidb workspace)

---

## Why it's a plugin, not a core feature

Only users who opt in run the sync plugin. Other plugins do not implement a
sync API directly; they expose safe local records and let the sync plugin decide
what can be serialized.

VoidB now has two opt-in sync paths:

- `--kind objects` pushes/pulls encrypted object records for profiles, profile
  policy, credential references, broker-owned encrypted credential records,
  plugin compatibility metadata, and app preferences. Server-visible IDs are
  opaque and mappings stay in device-local `sync.toml`.
- `--kind full`, `--kind global`, and `--kind plugin:<id>` keep the original
  encrypted bundle behavior as an explicit compatibility backup/manual recovery
  path. Bundle sync is not used as automatic fallback for object conflicts.

The object-level target uses opaque server-visible object IDs, encrypted
payloads, redacted manifests, and device-local `sync.toml` state as described
in [Object-Level Sync Model](object-level-sync-model.md).

## Security model

Encryption keys never leave the client. The server stores only
ciphertext + password verifiers, so a full DB dump cannot decrypt user data.

```
password + kdf_salt_auth --Argon2id--> auth_hash_client  → sent to server
password + kdf_salt_kek  --Argon2id--> KEK
KEK + nonce              --AES-GCM---> wrapped_dek (stored server-side, opaque)
DEK = random 32 bytes                  (generated at signup)
```

The server re-hashes `auth_hash_client` with a per-user server salt and
stores only `Argon2id(auth_hash_client, srv_salt)`, so even the DB-side
verifier cannot be replayed against the API.

The server cannot unwrap the DEK. Registration generates a one-time recovery
code that wraps the DEK with a secondary client-derived key; the user must
store that code outside VoidB. Neither the recovery code nor an unwrapped DEK
is persisted in `sync.toml`.

## Data flow

```
┌───────────────────────────────────────┐
│ voidb-plugin-sync (client)            │
│                                       │
│  ┌──────────┐  tar.zst  ┌─────────┐   │
│  │ ~/.config/voidb/ ──▶ │ bundle  │   │
│  └──────────┘           │ (plain) │   │
│                         └────┬────┘   │
│                              │        │
│                    AES-256-GCM(DEK)   │
│                              ▼        │
│                       ┌──────────┐    │
│                       │ciphertext│    │
│                       └────┬─────┘    │
└────────────────────────────┼──────────┘
                             │ HTTP PUT
                             ▼
┌───────────────────────────────────────┐
│ voidb-sync-server                     │
│                                       │
│   POST / PUT / GET /v1/...            │
│                                       │
│   ┌──────────────────┐ ┌───────────┐  │
│   │ metadata.db (SQL)│ │ blobs/    │  │
│   │  users/devices/  │ │ <uid>/    │  │
│   │  blob index      │ │ <kind>/   │  │
│   └──────────────────┘ │ <rev>.bin │  │
│                        └───────────┘  │
└───────────────────────────────────────┘
```

## Storage conventions

Everything the user owns lives under `~/.config/voidb/` (override with
`VOIDB_CONFIG_DIR=<path>`):

```
~/.config/voidb/
├── config.toml                   # global
├── saved_queries.json            # global
├── query_history.txt             # global
├── sync.toml                     # sync bookkeeping (NOT synced)
└── plugins/
    └── <plugin_id>/              # owned by each plugin
        └── ...
```

- `sync.toml` is the only file inside `~/.config/voidb/` that is *never*
  uploaded — it contains per-device state that would otherwise clobber other
  devices on pull.
- Anything else is automatically included. Plugins can add files freely.

Server-side:

```
<data_dir>/                       # typically an NFS mount
├── metadata.db
└── blobs/<user_id>/<kind>/<revision>.bin
```

## API surface (summary)

See [`voidb-sync-server/README.md`](../voidb-sync-server/README.md) for the
full spec.

| Endpoint                                | Purpose                           |
|-----------------------------------------|-----------------------------------|
| `POST /v1/auth/register`                | First-time signup                 |
| `POST /v1/auth/challenge`               | Fetch KDF params for login        |
| `POST /v1/auth/login`                   | Exchange auth hash for a token    |
| `POST /v1/auth/logout`                  | Revoke current device token       |
| `GET  /v1/me`                           | User + device summary             |
| `GET  /v1/devices`                      | List devices                      |
| `DELETE /v1/devices/{id}`               | Revoke another device             |
| `PUT  /v1/blobs/{kind}`                 | Push ciphertext (optimistic lock) |
| `GET  /v1/blobs/{kind}/latest`          | Pull newest revision              |
| `GET  /v1/blobs/{kind}/history`         | Revision list                     |
| `GET  /v1/blobs/{kind}/revisions/{r}`   | Fetch a specific revision         |
| `PUT  /v1/objects/{object_id}`          | Push one encrypted object         |
| `GET  /v1/objects`                      | List latest object manifests      |
| `GET  /v1/objects/{object_id}/latest`   | Pull newest object ciphertext     |
| `GET  /v1/objects/{object_id}/history`  | Object revision list              |
| `GET  /v1/objects/{object_id}/revisions/{r}` | Fetch a specific object revision |

Bundle optimistic locking: `PUT /v1/blobs/{kind}` carries
`expected_revision`. If it doesn't match the server's current revision, the
server returns 409 with `{ current_revision: N }`.

Object optimistic locking: `PUT /v1/objects/{object_id}` carries
`base_server_revision`. A stale write returns
`sync.conflict.object_revision_mismatch` with only opaque object ID, object
kind, revisions, redacted actor, timestamp, and redaction status. The client
does not fall back to a bundle pull after this conflict.

## UI (client) — current MVP

One tab managed by the `sync` plugin, with plugin-owned screens:

1. **Form** (login / register toggle via `Ctrl-R`): server URL, email,
   password, device name (+ optional invite token in register mode).
2. **LoggedIn**: shows server URL, account, device, last-synced revision.
   - `p` — push
   - `l` — pull (overwrites local config dir with server state)
   - `c` — review local object conflict markers when present
   - `L` — switch account (returns to the form)
   - `q` — return to home (standard VoidB shortcut)
3. **Object conflict review**: groups conflicts by object kind, shows opaque
   object IDs, redacted revision details, local labels only from local profile
   store access, and never prints server-derived labels, ciphertext, decrypted
   payloads, credential material, or local mapping IDs.
   - `r` — keep remote after explicit Enter confirmation
   - `f` — keep local with force for non-credential objects after confirmation
   - `m` — safe merge for profile/profile_policy/app_preference after
     confirmation
   - `d` — tombstone delete after destructive confirmation
   - `e` — credential re-enrollment handoff prompt for credential_record
     conflicts
   - `Esc` — cancel confirmation or leave conflict review

The DEK is kept in memory only; logging out or restarting VoidB requires
logging in again.

## Agent control surface

Sync exposes six stateless, connection-independent capabilities. Core represents
their authorization and audit scope with the stable `system:sync` identity,
selected as `--profile local`. This is not a saved connection profile and does
not create a connection pool, generic live session, shared client, or reusable
decryption handle.

| Capability | Risk | Behavior |
|---|---|---|
| `sync.status` | Read-only | Reads local readiness, last-sync state, bounded pending-work counts, and local compatibility versions without a network call. |
| `sync.diagnostics` | Read-only | Optionally calls only the unauthenticated health endpoint and returns a redacted connectivity code. |
| `sync.plan` | Read-only | Uses the enrolled device token to compare local mappings with remote object summaries and returns stable, paginated upload/download/no-op/conflict decisions. |
| `sync.diff` | Read-only | Returns only the non-no-op page of the same metadata-only plan. |
| `sync.conflict_resolve` | Destructive | Resolves one opaque object conflict after dry-run preview, typed confirmation, acknowledgement, and persistent idempotency checks. |
| `sync.recovery` | Destructive | Retries object push/pull or performs explicit bookkeeping reset, rebootstrap, or recovery-code password reset under the same guards. |

Discover the exact schemas and centrally generated presets without unlocking
profiles:

```bash
voidb-cli agent catalog --plugin sync
voidb-cli invoke describe sync.conflict_resolve
```

The recommended Read-only preset contains exactly `sync.status`,
`sync.diagnostics`, `sync.plan`, and `sync.diff`:

```bash
voidb-cli agent authorize \
  --profile local \
  --plugin sync \
  --preset read_only
```

The Interactive/Execute preset contains exactly `sync.conflict_resolve` and
`sync.recovery`. It must be explicitly authorized with destructive access:

```bash
voidb-cli agent authorize \
  --profile local \
  --plugin sync \
  --preset interactive_execute \
  --allow-destructive \
  --yes
```

Status is offline. Diagnostics can also be forced offline. Plan and diff make
an authenticated metadata request but never fetch or decrypt ciphertext:

```bash
voidb-cli invoke run sync.status \
  --profile local \
  --input-json '{}'

voidb-cli invoke run sync.diagnostics \
  --profile local \
  --input-json '{"check_connectivity":false}'

voidb-cli invoke run sync.plan \
  --profile local \
  --input-json '{"direction":"bidirectional","object_kind":"profile"}' \
  --page-limit 100
```

Plan and diff output contains opaque object IDs, object kinds, schema/object
versions, server revisions, decisions, compatibility state, and redacted
reason codes only. It does not copy remote manifests, payload hashes,
ciphertext, aliases, hosts, credential labels, local IDs, or local paths into
Agent output. A cursor is bound to the stable plan ID and fails with
`conflict.sync_plan_changed` if the compared metadata changes.

### Mutation preview and credential handoff

Every mutation is previewed first. Put the non-secret request in a private
temporary JSON file:

```json
{
  "mode": "keep_remote",
  "object_kind": "profile",
  "object_id": "sync_profile_opaque"
}
```

```bash
voidb-cli invoke run sync.conflict_resolve \
  --profile local \
  --dry-run \
  --input-file target/tmp/sync-conflict-preview.json
```

Copy the returned `plan_id` and `required_confirmation` into a separate
execution request together with a fresh public idempotency key. No password,
token, recovery code, key, or decrypted material belongs in that file. When
the selected operation needs the DEK, hand the password to the plugin by
environment variable and name that variable in the request; the value is
never part of capability input:

```bash
read -rs VOIDB_SYNC_PASSWORD
export VOIDB_SYNC_PASSWORD
voidb-cli invoke run sync.conflict_resolve \
  --profile local \
  --yes \
  --input-file target/tmp/sync-conflict-execute.json
unset VOIDB_SYNC_PASSWORD
```

The default handoff names are `VOIDB_SYNC_PASSWORD`,
`VOIDB_SYNC_RECOVERY_CODE`, and `VOIDB_SYNC_NEW_PASSWORD`. A request may select
another environment variable name using `password_env`,
`recovery_code_env`, or `new_password_env`, but only uppercase ASCII names are
accepted. Never place the corresponding values in `--input-json`, command
arguments, files, logs, or audit metadata. Broker children inherit the
operator-provided environment only for the bounded invocation and never turn
it into a generic Sync session.

Completed mutations record a bounded, device-local replay entry in
`sync.toml`. The entry contains only the capability ID, input fingerprint,
completion time, and redacted result summary. Reusing the same idempotency key
with identical input returns the saved outcome; different input fails with
`conflict.sync_idempotency_key_reused`. `sync.toml`, including this ledger,
remains excluded from every Sync payload.

### Recovery runbook

1. Run `sync.recovery` with `--dry-run` and one of `retry`, `reset`,
   `rebootstrap`, or `recover_access`.
2. Review the returned effects, plan ID, mapping/conflict counts, and exact
   confirmation string.
3. Add the plan ID, confirmation, and a new idempotency key to the execution
   request; execute with `--yes` under the mutation preset.
4. For `retry`, choose `push_objects` or `pull_objects` and provide the
   password environment handoff.
5. `reset` clears revisions and conflict markers but retains opaque mappings.
   `rebootstrap` additionally clears mappings and disables periodic Sync; it
   does not delete local profile or credential files.
6. `recover_access` uses the one-time recovery-code and new-password
   environment handoffs, rewraps the same DEK client-side, rotates the account
   password, and stores only the fresh device token through the configured
   token backend.

Common safe error codes include `credential.sync_token_missing`,
`credential.sync_handoff_missing`, `conflict.sync_preview_changed`,
`conflict.sync_idempotency_key_reused`,
`conflict.sync_plan_changed`, and redacted `sync.*_failed` codes. Raw server
messages, endpoints, credentials, keys, ciphertext, and decrypted values are
not returned. Timeouts and caller cancellation use the generic invocation
controls and are effective for all six capabilities.

## CLI and release smoke

The current CLI exposes `sync login`, `sync logout`, `sync push`, `sync pull`,
and `sync status`. Use `sync push --kind objects` and
`sync pull --kind objects` for the object MVP. Use `--kind full`,
`--kind global`, or `--kind plugin:<id>` only for compatibility-bundle backup
or manual recovery. `sync status` reports object counts, latest revisions,
unavailable imported records, and object conflict counts by kind without
printing aliases, hosts, usernames, credential labels, or local IDs.
`sync status --format json` adds scriptable `objects.conflicts` entries with
opaque object IDs, revisions, redaction status, timestamps, and unavailable
reasons. JSON output uses the agent-facing CLI envelope:

```json
{
  "ok": true,
  "schema_version": 1,
  "command": "sync",
  "data": {
    "objects": {
      "conflict_count": 1,
      "conflicts": [
        {
          "object_kind": "credential_record",
          "object_id": "sync_credrec_abc",
          "current_server_revision": 4,
          "redaction": "withheld",
          "unavailable_reason": "object_revision_conflict"
        }
      ]
    }
  }
}
```

Object conflict resolution has scriptable CLI helpers:

- `sync conflict list [--format json]` prints local redacted conflict markers.
  JSON output uses the same top-level sync envelope and keeps entries under
  `data.conflicts`.
- `sync conflict resolve --mode keep-remote --object-kind <kind> --object-id <id>`
  applies the latest encrypted remote object after local compatibility checks.
- `sync conflict resolve --mode keep-local-force --object-kind <kind>
  --object-id <id> --current-server-revision <rev>` force-pushes one named
  non-credential object and records a redacted `sync_object_force_push` audit
  event. Bulk force is not available.
- `sync conflict resolve --mode merge --object-kind <kind> --object-id <id>
  --current-server-revision <rev>` performs only safe profile metadata,
  profile-policy, or app-preference merges. Policy merges preserve denies and
  keep destructive defaults disabled unless both sides enabled them.
- `sync conflict resolve --mode delete-tombstone --object-kind <kind>
  --object-id <id> --current-server-revision <rev> --acknowledge-delete`
  creates a tombstone object version and removes the local object.
- `sync conflict credential-handoff --object-id <id> [--format json]` maps a
  credential-record conflict to the explicit re-enrollment command without
  printing credential material. JSON output uses the same sync envelope and
  keeps the suggested command under `data.command`.

Credential object recovery has two narrow CLI helpers:

- `sync credential migrate-mappings` creates device-local object mappings for
  stored credential records without uploading plaintext or server-visible local
  IDs.
- `sync credential re-enroll --profile <id> --credential <id>` re-encrypts and
  pushes one `credential_record` from `--secret-env`, `--json-env`, or
  `--from-legacy`. The command never prints the supplied material or plaintext
  diffs.

Account registration remains a TUI/ops flow rather than a CLI command. Release
smoke should therefore use automated ops tests for registration and the CLI only
after a disposable account already exists.

Run the secret-free sync smoke helper before release-candidate validation:

```bash
scripts/release-sync-smoke.sh
```

This runs the sync plugin e2e test and the standalone sync server smoke suite
with disposable local state. Hosted or manually launched server smoke remains
opt-in and is documented in Release Sync Smoke.

## Roadmap

Implemented in the object MVP:

- [x] Server-side object revision storage, latest pointers, history, tombstones,
      and redacted optimistic-conflict responses
- [x] Client object push/pull for profiles, profile policies, credential refs,
      encrypted credential records, plugin compatibility metadata, and app
      preferences
- [x] Device-local sync object mappings in `sync.toml`; legacy local IDs remain
      encrypted/local and are never server-visible object IDs
- [x] Credential-record import stores encrypted broker-owned envelopes locally,
      keeps plaintext material in memory only during decrypt, and marks
      failed-decrypt objects unavailable without destructive profile rewrites
- [x] Credential-record mapping migration and re-enrollment helpers for
      confirming legacy material or supplying replacement material locally
- [x] Redacted audit events for credential-record push, pull, unavailable
      import/decrypt failures, mapping migration, and re-enrollment
- [x] Local object conflict markers in `sync.toml`, `sync status --format json`
      conflict arrays, and redacted `sync_object_conflict` audit events for
      object push/re-enrollment conflict detection
- [x] CLI conflict resolution commands for keep-remote, per-object
      keep-local-force, safe merge, tombstone delete acknowledgement, and
      credential re-enrollment handoff, with redacted per-object audit events
- [x] TUI object conflict review with kind grouping, redacted detail view,
      explicit resolution confirmations, and credential re-enrollment handoff
- [x] CLI `--kind objects` path and `sync status` object-count summary
- [x] Compatibility bundle path remains available through explicit `--kind`
      values and is not an object-conflict fallback

Still not implemented:

- [ ] Recovery code at signup (bip39-style) that wraps the DEK with a
      secondary key, so users can reset password without data loss
- [ ] Interactive failed-decrypt repair UX beyond CLI credential re-enrollment
      handoff
- [ ] Pull-time conflict marker import beyond push/re-enrollment detection
- [ ] Tombstone delete import UX beyond preserving unavailable local mappings
- [ ] Schema-aware plugin compatibility checks that can disable profiles when a
      local plugin is missing or incompatible
- [ ] Automatic periodic sync (pull on launch, push on exit)
- [ ] OAuth (GitHub / Google) as an alternative to email + password
- [ ] Keyring-backed token persistence (optional, off by default)
