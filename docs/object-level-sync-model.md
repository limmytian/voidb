# Object-Level Sync Model

This document defines the first target contract for object-level VoidB sync.
It refines [Sync Boundary Under The Capability Model](sync-boundary.md) into
concrete object identity, versioning, redacted manifest, and device enrollment
rules.

The current sync plugin is beta-certified but still opt-in. It has an
object-level MVP for profile and encrypted credential records, while the older
encrypted full-directory bundle remains a recovery and compatibility path. The
bundle is not the stable object sync API. See
Sync Beta Readiness for the release-facing decision.

## Goals

Object-level sync must let devices exchange capability-first records without
turning local files into public API.

Governed team/profile sharing adds a stricter collection boundary over these
objects. See [Governed Team Profile Sharing](team-profile-sharing.md) for the
rules that turn credential refs into local re-enrollment requirements and keep
team-share server metadata opaque.

Initial objects:

- connection profiles;
- credential reference metadata;
- profile policy;
- plugin compatibility metadata;
- non-secret app preferences;
- encrypted credential records.

Non-goals for this slice:

- syncing plaintext secrets;
- syncing `sync.toml`;
- replacing the current full-directory bundle implementation;
- defining conflict merge UI in detail;
- requiring plugins to implement sync APIs before profile and credential
  objects stabilize.

## Non-Negotiable Invariants

1. Plaintext passwords, tokens, API keys, private keys, passphrases, client
   certificates, decrypted `plugin_config`, and credential-bearing URLs never
   enter object payloads, manifests, audit details, or server-visible fields.
2. `sync.toml` stays device-local. It may contain server URL, email, device ID,
   device name, last revisions, timestamps, and local tokens, but it is never a
   synced object.
3. Server-visible object IDs are opaque. They must not be reversible encodings
   of aliases, hostnames, usernames, bucket names, local paths, legacy
   connection keys, or credential paths.
4. Profile policy travels with the profile. A synced profile must not become
   more permissive on another device.
5. Missing plugins or credentials make an imported object unavailable, not
   silently downgraded or rewritten.
6. Every object mutation has version, actor, and device attribution suitable for
   redacted audit records.

## Object Envelope

Every object uses one outer envelope. The server may index only the fields
listed in [Server-Visible Manifest](#server-visible-manifest). Payload content
is encrypted before upload unless a later object kind is explicitly classified
as public.

```json
{
  "schema_version": 1,
  "object_id": "sync_profile_01JZ8N2E9F6Q0Z2P2W3Q4R5T6V",
  "object_kind": "profile",
  "object_version": 7,
  "base_server_revision": 12,
  "payload_hash": "sha256:...",
  "payload_size": 942,
  "updated_at": "2026-07-04T15:00:00Z",
  "updated_by": {
    "actor_type": "human",
    "actor_id": "local-user",
    "device_id": "device_01JZ8N1..."
  },
  "deleted": false,
  "redaction": "withheld",
  "ciphertext": "base64..."
}
```

Field rules:

| Field | Rule |
|---|---|
| `schema_version` | Version of the envelope schema, not the plugin profile schema. |
| `object_id` | Opaque, server-visible, stable for the logical object. |
| `object_kind` | Stable kind such as `profile`, `credential_ref`, `profile_policy`, `plugin_compatibility`, or `credential_record`. |
| `object_version` | Monotonic per-object version assigned by the client before push. |
| `base_server_revision` | Last server revision the mutating client observed; used for optimistic conflict checks. |
| `payload_hash` | Hash of the canonical encrypted payload or ciphertext, never a hash over plaintext that could be used as a dictionary oracle for low-entropy secrets. |
| `payload_size` | Ciphertext size or encrypted payload size. |
| `updated_at` | Client timestamp for display and audit; server still assigns authoritative receive time. |
| `updated_by` | Actor and device attribution. Actor IDs must follow audit redaction rules. |
| `deleted` | Tombstone marker. Deletions keep the object ID and advance `object_version`. |
| `redaction` | Redaction status for the server-visible envelope and manifest. |
| `ciphertext` | Encrypted payload bytes. The server stores but cannot decrypt this field. |

## Object IDs

Object IDs are sync IDs, not necessarily local profile IDs.

Required properties:

- generated with random or time-sortable opaque entropy, for example ULID/UUIDv7;
- namespaced by object kind for operator diagnostics;
- stable across devices after first sync;
- stored in the encrypted local object payload or local mapping;
- never derived from aliases, profile names, hostnames, usernames, bucket names,
  database names, local paths, credential reference labels, or legacy
  `ConnectionConfig.connection_key()`.

Recommended prefixes:

| Object kind | Prefix |
|---|---|
| profile | `sync_profile_` |
| credential reference | `sync_credref_` |
| profile policy | `sync_policy_` |
| plugin compatibility | `sync_plugin_` |
| encrypted credential record | `sync_credrec_` |
| app preference | `sync_pref_` |

Local IDs such as `profile:<base64url(legacy_connection_key)>` and
`credential:<base64url(...path...)>` may continue to exist for migration and
local compatibility. They must not become server-visible object IDs because the
encoded source can reveal aliases, plugins, or credential paths.

## Versioning

Object sync uses two counters:

- `object_version`: client-owned monotonic version for one logical object;
- `server_revision`: server-owned monotonic revision for the accepted object
  write.

Update rules:

1. A client pulls object `A` at server revision `12` and object version `7`.
2. The client edits `A`, increments `object_version` to `8`, and pushes with
   `base_server_revision: 12`.
3. The server accepts only if the current server revision for `A` is still `12`.
4. The server stores the new ciphertext and returns server revision `13`.
5. If the current server revision is different, the server returns conflict
   details containing only object kind, opaque object ID, current revision, and
   redacted timestamps.

Deletion is a tombstone update. It increments `object_version`, records
`deleted: true`, and keeps enough encrypted payload metadata to let other
devices remove or disable the local object without exposing its previous
plaintext shape.

Schema migration rules:

- New readers must reject unknown required envelope fields.
- Object payload schemas carry their own payload version inside ciphertext.
- A migration may write a new object version without changing user-facing
  profile data.
- Downgraded clients must leave unsupported object kinds untouched and report
  `unavailable.sync_object_schema_unsupported`.

## Initial Payload Shapes

Payloads are encrypted. The shapes below describe decrypted client-side content.

### `profile`

```json
{
  "payload_version": 1,
  "profile": {
    "id": "profile-local-or-sync-mapped-id",
    "name": "prod-db",
    "plugin_id": "mysql",
    "display_name": "Production DB",
    "metadata": {},
    "default_options": {},
    "credential_refs": [],
    "policy_ref": "sync_policy_..."
  },
  "compatibility_ref": "sync_plugin_..."
}
```

Rules:

- `metadata` is plugin-schema validated before import.
- Sensitive metadata may exist only inside encrypted payloads and still follows
  CLI/TUI redaction rules after import.
- `credential_refs` contain references, classes, labels, and non-secret
  fingerprints only.
- The payload must not include legacy decrypted `plugin_config`.

### `credential_ref`

```json
{
  "payload_version": 1,
  "profile_object_id": "sync_profile_...",
  "credential_ref": {
    "id": "credref-local-or-sync-mapped-id",
    "class": { "kind": "password" },
    "label": "primary",
    "fingerprint": "sha256:optional-non-secret-fingerprint"
  }
}
```

Rules:

- Credential refs can sync without credential material.
- A receiving device with no matching encrypted credential record imports the
  profile as missing credentials and prompts the user to enroll secrets locally.

### `credential_record`

Credential records are broker-owned encrypted records. The server-visible
object stores only opaque object IDs, ciphertext hash/size, algorithm metadata,
and redaction status. The decrypted client-side payload is:

```json
{
  "payload_version": 1,
  "profile_object_id": "sync_profile_...",
  "credential_ref_object_id": "sync_credref_...",
  "credential": {
    "profile_id": "profile-local-or-sync-mapped-id",
    "credential_ref_id": "credential-local-or-sync-mapped-id",
    "plugin_id": "mysql",
    "class": { "kind": "password" },
    "label": "primary",
    "created_at": "2026-07-04T14:00:00Z",
    "material": {
      "kind": "utf8",
      "value": "secret material after local decrypt"
    }
  },
  "migration": {
    "source_kind": "legacy_plugin_config",
    "local_source_redacted": true
  },
  "redaction": "withheld"
}
```

Encryption rules:

- Credential record payloads are encrypted locally with AES-256-GCM under the
  sync DEK after the sync password-derived KEK has unwrapped that DEK.
- Associated data binds the credential record object ID, object version,
  profile object ID, credential-ref object ID, schema version, payload version,
  and `credential_record` object kind.
- The encrypted envelope stores the nonce, associated data, ciphertext hash,
  ciphertext size, key-wrap label `sync-dek.v1`, migration source kind, and
  redaction status. It does not store plaintext material, labels, legacy
  connection keys, local credential paths, master passwords, sync passwords,
  KEK, or DEK bytes.
- Decryption must fail closed if the DEK is unavailable, the associated data no
  longer matches the envelope, the ciphertext hash does not match, or the
  decrypted payload references a different profile or credential-ref object.

### `profile_policy`

```json
{
  "payload_version": 1,
  "profile_object_id": "sync_profile_...",
  "policy": {
    "allowed_capabilities": ["query"],
    "denied_capabilities": ["exec"],
    "allow_destructive_by_default": false
  }
}
```

Rules:

- Policy is part of the effective profile state.
- Missing policy defaults to deny destructive operations by default.
- Policy conflicts are object conflicts, not silent last-writer-wins changes.

### `plugin_compatibility`

```json
{
  "payload_version": 1,
  "plugin_id": "mysql",
  "profile_schema_id": "voidb.mysql.profile.v1",
  "profile_schema_version": 1,
  "minimum_plugin_version": "0.1.0",
  "capability_contracts": ["sql.v1"]
}
```

Rules:

- Import checks local plugin availability and schema compatibility.
- Missing or incompatible plugins mark dependent profiles unavailable while
  preserving encrypted payloads for future retry.

## Server-Visible Manifest

The object manifest is the only server-visible metadata beyond ciphertext and
server auth state. It exists for conflict detection, storage accounting, and
operator-safe diagnostics.

Allowed fields:

```json
{
  "manifest_version": 1,
  "batch_id": "sync_batch_01JZ8...",
  "created_at": "2026-07-04T15:00:00Z",
  "device_id": "device_01JZ8...",
  "objects": [
    {
      "object_id": "sync_profile_01JZ8...",
      "object_kind": "profile",
      "schema_version": 1,
      "object_version": 8,
      "base_server_revision": 12,
      "deleted": false,
      "payload_hash": "sha256:...",
      "payload_size": 942,
      "redaction": "withheld"
    }
  ],
  "counts": {
    "profile": 1,
    "credential_ref": 2,
    "profile_policy": 1
  }
}
```

Forbidden manifest fields:

- profile name or display name;
- hostnames, usernames, database names, bucket names, regions, account IDs,
  tenant IDs, object paths, local filesystem paths, or target-system labels;
- credential reference labels when user-chosen;
- credential classes when not required for conflict behavior;
- legacy connection keys or base64 encodings of them;
- plaintext query text, Redis keys, object names, email addresses, URLs, or
  command output;
- decrypted plugin config or any secret-shaped field.

If a field is useful for local UI but would reveal target-system data
server-side, put it inside encrypted payloads and redact it before CLI/TUI
display. If redaction cannot be guaranteed, omit the field and set redaction to
`withheld` or fail closed before upload.

## Redaction Policy

Object sync uses the same data classes as
[Secret Brokering and Redaction Policy](secret-brokering-redaction-policy.md).

Manifest redaction statuses:

| Status | Meaning |
|---|---|
| `not_required` | The server-visible field set contains no sensitive data classes. |
| `applied` | Sensitive source data was transformed into an allowed placeholder or count. |
| `withheld` | Sensitive source data exists but was intentionally omitted. |
| `failed_closed` | Sync refused to upload because it could not prove the manifest was safe. |

Default policy for object-level sync is `withheld`: prefer opaque IDs and
counts over redacted human labels.

## Conflict Resolution

Object sync is optimistic and object-scoped. The server accepts an object write
only when `base_server_revision` matches the current server revision for the
same `object_id`. A stale write returns a structured conflict; it never returns
decrypted payload, aliases, credential labels, hostnames, usernames, bucket
names, local paths, or legacy connection keys.

Server conflict shape:

```json
{
  "code": "sync.conflict.object_revision_mismatch",
  "object_id": "sync_profile_01JZ8...",
  "object_kind": "profile",
  "attempted_base_server_revision": 12,
  "current_server_revision": 13,
  "attempted_object_version": 8,
  "current_object_version": 9,
  "server_updated_at": "2026-07-04T15:05:00Z",
  "server_updated_by": {
    "actor_type": "human",
    "actor_id": "<redacted:actor>",
    "device_id": "device_01JZ8..."
  },
  "redaction": "withheld"
}
```

Client behavior:

1. `push` stops at the first conflict by default and reports only the object
   kind, opaque ID, revisions, redacted timestamp, and redaction status.
2. Push/re-enrollment conflict detection stores a local conflict marker and
   keeps the existing local object active until the user or agent resolves the
   conflict. Pull and later resolution flows must not silently overwrite
   credential records, profile policy, or `sync.toml`.
3. `sync status --format json` includes an `objects.conflicts` array with the
   same redacted fields as the server conflict shape.
4. TUI presentation should group conflicts by object kind and show local labels
   only after decrypting local payloads and applying normal CLI/TUI redaction.
   The server-provided conflict summary remains opaque.
5. Conflict details in audit records use the same redacted shape and must not
   include ciphertext, decrypted payloads, credential material, or file paths.

Resolution modes:

| Mode | Allowed for | Rule |
|---|---|---|
| Keep local and push | Profile, credential ref, profile policy, plugin compatibility, app preference | Requires an explicit force action with the current server revision. The client writes a new object version and records `sync.object_force_push`. |
| Keep remote | All object kinds | Replaces or disables the local object from the encrypted remote payload after compatibility checks. Credential records remain unavailable if they cannot be decrypted locally. |
| Merge | Profile metadata, profile policy, app preference | Allowed only when the merge is schema-aware and cannot loosen policy. Policy merges must preserve all denies and keep `allow_destructive_by_default` false unless both sides set it true. |
| Re-enroll credential | Credential record | Preferred when devices have divergent encrypted credential records. The user supplies or confirms local credential material; no plaintext diff is shown. |
| Delete tombstone | All object kinds | Requires an explicit destructive acknowledgement and creates a tombstone object version. |

Credential record conflicts are never auto-merged because the client cannot
prove two ciphertexts represent the same secret without decrypting locally.
If decryption fails, the only safe actions are keep remote as unavailable,
delete, or re-enroll the credential. Credential-record force push is routed to
the re-enrollment flow instead of a plaintext diff or blind overwrite.

Force and merge guardrails:

- Force push must name the object ID and the server revision being overwritten.
- Bulk force is disallowed until a later design adds a per-object preview and
  audit trail.
- Merge output must be validated against the payload schema before upload.
- A merge that would remove a denied capability, add a destructive default, or
  drop a credential reference must become an explicit conflict, not an
  automatic merge.
- Every resolution emits one audit event per object with actor, device, object
  kind, object ID, previous revision, new revision, mode, and redaction status.

## Device Enrollment Boundary

Registering the first device creates the sync account, derives auth and wrapping
keys from the sync password, creates a DEK, wraps the DEK, and stores only
server-safe auth data plus wrapped DEK server-side.

Adding a device:

1. The user logs in with the sync account password from the new device.
2. The server returns KDF parameters and wrapped DEK.
3. The client derives the KEK locally, unwraps the DEK, and stores the bearer
   token only in the local `sync.toml` if CLI login is used.
4. The client pulls object manifests and ciphertext.
5. The client imports compatible objects into local profile/credential stores.
6. Missing plugins or missing local credential material leave profiles disabled
   or needing attention; they do not expose secrets or downgrade policy.

`sync.toml` is not copied from another device. Device ID, token, last revisions,
and local timestamps are created or updated only by the current device.

Device revocation invalidates server tokens for that device. It does not
decrypt, rewrite, or delete already encrypted user object payloads.

## Recovery Boundary

Password loss remains data loss unless a future recovery code or another
already-enrolled device can rewrap the DEK. The server cannot recover the DEK.

Recovery rules:

- Do not export plaintext credentials as a recovery mechanism.
- Do not sync the master password, sync password, KEK, DEK, unwrapped recovery
  material, bearer token, or `sync.toml`.
- A future recovery code may wrap the DEK with a secondary key, but the code
  must be generated client-side, shown once, and never stored plaintext
  server-side.
- If credential records cannot be decrypted on a recovered device, profiles may
  import with missing credential state and require local secret re-entry.
- The current full-directory bundle can remain an explicit manual recovery
  path, but UI and docs must label it experimental and compatibility-oriented.

## Compatibility Bundle Migration

The current full-directory bundle stays available as an explicit compatibility
backup and manual recovery path while object sync is built. It must not become
the stable object sync API.

Rules for the bundle path:

- Keep `sync push --kind full`, `sync pull --kind full`, and `plugin:<id>`
  bundle kinds opt-in.
- Label the path as "compatibility backup" or "manual recovery" in CLI, TUI,
  docs, and release notes. Do not call it stable object-level sync.
- Continue excluding `sync.toml` and preserving the receiving device's local
  identity, token, and revision state.
- Warn before a full-bundle pull overwrites local files. Future TUI flows should
  require an explicit destructive acknowledgement.
- Do not use bundle manifests as the model for object manifests. Bundle
  manifests may expose local file paths; object manifests may not.
- Do not automatically fall back from object sync to a full-bundle pull after an
  object conflict. That would turn a precise conflict into a broad overwrite.

Migration sequence:

1. Keep the existing bundle implementation and smoke tests unchanged for users
   who rely on backup-style sync.
2. Store local mappings between opaque sync object IDs and local profile or
   credential IDs when object sync is first enabled. Legacy local IDs such as
   `profile:<base64url(...)>` remain local and never become server-visible IDs.
3. Upload object manifests and ciphertext per object kind. Full bundles can be
   uploaded separately for recovery, but they are not part of object conflict
   resolution.
4. Pull object manifests first. Import compatible objects into profile,
   credential, and policy stores; mark missing plugins or credentials
   unavailable instead of rewriting data into legacy config fields.
5. Keep rollback simple: a user may disable object sync and perform a manual
   compatibility-bundle restore, but VoidB must describe that as a recovery
   operation with overwrite risk.

## Implemented MVP Status

As of the current MVP, VoidB implements the first object path:

- sync server object tables and `/v1/objects` endpoints for upload, latest
  listing, fetch, history, tombstone storage, and redacted revision conflicts;
- sync client `--kind objects` push/pull for profile, profile policy,
  credential-ref, encrypted credential-record, plugin-compatibility, and
  app-preference objects;
- device-local object mappings in `sync.toml`, so local profile IDs, credential
  IDs, aliases, labels, hosts, usernames, bucket names, and paths are not
  server-visible object IDs or manifest fields;
- profile import from decrypted object payloads, with missing credential
  material marked unavailable instead of converted into plaintext or legacy
  config fields;
- credential-record import stores broker-owned encrypted envelopes in
  `credentials.json`, keeps plaintext material in memory only during decrypt,
  and caches unavailable encrypted object payloads for future retry without
  rewriting local profiles destructively;
- credential-record mapping migration and CLI re-enrollment can confirm legacy
  material or accept replacement material locally, then re-encrypt and push a
  new broker-owned `credential_record` without plaintext diffs;
- redacted audit events cover credential-record push, pull, unavailable
  import/decrypt failure, mapping migration, and re-enrollment paths;
- local object conflict markers in `sync.toml`, `sync status --format json`
  conflict arrays, and redacted `sync_object_conflict` audit events cover
  object push/re-enrollment conflict detection;
- CLI conflict resolution commands cover keep-remote, per-object
  keep-local-force for non-credential objects, safe profile/policy/preference
  merge, destructive tombstone acknowledgement, and credential re-enrollment
  handoff; each successful resolution emits a redacted per-object audit event;
- TUI conflict review groups local conflict markers by object kind, shows
  redacted detail fields and locally loaded labels without local mapping IDs,
  and requires explicit confirmation before keep-remote, force, merge, or
  tombstone actions;
- `sync status` object counts by kind, latest revisions, unavailable counts,
  and conflict counts without server-derived human labels.

Known MVP limits:

- pull-time conflict marker import and interactive failed-decrypt repair are
  still later work;
- plugin compatibility is recorded as metadata but not yet enforced against a
  live plugin/schema registry during import;
- the compatibility bundle remains available only as explicit manual
  backup/recovery and is not used as fallback after object conflicts.

## Migration Gates For Later Slices

Before object sync can be presented as stable:

1. Complete interactive credential-record recovery UX, including
   failed-decrypt repair and explicit keep-local/keep-remote behavior.
2. Keep `cargo test -p voidb-core object_sync` green. These tests prove profile,
   credential-ref, credential-record envelope, and manifest serialization
   contain no plaintext secrets or target-system metadata.
3. Implement pull-time conflict marker import, TUI conflict presentation, and
   interactive failed-decrypt repair using the conflict shape above.
4. Keep the current full-directory bundle available only as opt-in
   compatibility backup and manual recovery.
5. Update release gates so "stable Sync" means object-level sync gates pass,
   including core object serialization, sync client object push/pull, server
   object conflict tests, and compatibility-bundle smoke.
