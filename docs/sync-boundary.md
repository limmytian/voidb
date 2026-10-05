# Sync Boundary Under The Capability Model

This document defines the sync boundary for the capability-first VoidB model.
It belongs to Requirement 06 and clarifies which profile metadata can sync,
how encrypted credential state is treated, and why sync must not move ahead of
the local capability, profile, policy, plugin, and audit model.

It builds on:

- [Capability Core Model](capability-core-model.md)
- [Connection Profile CLI Contract](connection-profile-cli.md)
- [Secret Brokering and Redaction Policy](secret-brokering-redaction-policy.md)
- [Audit and Structured Error Schema](audit-and-error-schema.md)
- [Plugin Manifest Schema](plugin-manifest-schema.md)
- [Future Plugin Installation Model](plugin-installation-model.md)
- [Migration Compatibility Notes](migration-compatibility-notes.md)
- [VoidB Sync Architecture](sync-plugin.md)
- [Object-Level Sync Model](object-level-sync-model.md)

## Decision

Cloud sync is a deferred extension over the local model, not a prerequisite for
the architecture shift.

The local capability-first model must define profile identity, credential
references, secret brokering, policy, plugin compatibility, audit records, and
structured errors before sync becomes a default or product-contract surface.

The current sync plugin is beta-certified but remains opt-in. Req49 records the
release-facing beta decision, and Req60 records local object-level
stable-readiness evidence, in
Sync Beta Readiness. The compatibility bundle path
snapshots local configuration into an end-to-end encrypted bundle for
backup/manual recovery. That bundle behavior is not the public sync contract
and must not be used to define profile, credential, policy, plugin, or audit
semantics.

## Agent Threat Model

The Sync Agent surface is a local control plane over the existing encrypted
protocol. It is not a connection profile, a generic live session, or a way to
delegate decrypted Sync state. Generic invocation represents it with the
stable `system:sync` authorization identity (`--profile local`) so Core can
apply grants, policy, cancellation, deadlines, and audit without creating a
driver handle, pool, socket, or reusable in-memory session.

### Assets and trust boundaries

| Boundary | Trusted responsibility | Data that may cross |
|---|---|---|
| Agent caller to VoidB Core | Core validates capability schemas, exact authorization scope, acknowledgement, deadlines, output bounds, and audit metadata. | Schema-shaped inputs, opaque object IDs, counts, versions, hashes, redacted failure codes, and explicit confirmation material. |
| Core to Sync plugin | The plugin owns Sync config, token-store access, client-side keys, encryption, bundle packaging, conflict state, and protocol calls. | A single bounded operation; never a generic client, driver, or live session handle. |
| Sync plugin to server | The client encrypts content and authenticates the device. The server stores ciphertext and optimistic-concurrency metadata without a decryption path. | Ciphertext, opaque IDs, object kinds, revisions, required hashes, and deliberately exposed protocol metadata. |
| Local operator to recovery flow | The operator supplies passwords, recovery codes, or credential material through protected prompts or brokers and confirms destructive recovery. | Only derived proofs, wrapped keys, encrypted credential records, and redacted outcome metadata leave the local boundary. |

Protected assets include the DEK and KEK, user and recovery secrets, bearer
tokens, unwrapped recovery material, decrypted bundles and object payloads,
credential plaintext, local profile IDs and aliases, target hostnames, local
paths, and credential-bearing configuration. These values must not appear in
capability schemas, previews, results, errors, pagination cursors, audit
metadata, command arguments, or logs.

The server and network are treated as untrusted for confidentiality. A
compromised server may withhold, replay, reorder, or corrupt ciphertext and
metadata, so clients validate authenticated encryption, object versions,
optimistic revisions, and replay/idempotency identifiers before changing local
state. The server can still observe deliberately exposed timing, sizes, object
kinds, opaque identifiers, and revision metadata; the surface does not claim
traffic-analysis resistance.

### Agent non-goals and forbidden exports

- No capability returns or accepts a bearer token, password, recovery code,
  DEK, KEK, private key, decrypted payload, raw bundle, or live protocol
  object.
- No capability exposes local aliases, credential labels, target endpoints,
  local paths, or raw server error text when an opaque ID, count, or redacted
  code is sufficient.
- No generic Agent session owns Sync authentication state. Operations derive
  the minimum state they need inside the plugin and drop it on completion.
- Read-only status, diagnostics, plan, and diff never push, pull, enroll,
  resolve, reset, or enable periodic Sync.
- A preview is not authorization. Mutations require the narrow capability,
  matching typed confirmation, acknowledgement where applicable, and replay
  protection.
- Compatibility bundles remain explicit backup/manual recovery and never
  become an automatic object-conflict fallback.

Audit records identify the capability, actor, `system:sync` scope, operation
mode, opaque object identity when needed, counts, result status, and redaction
state. They intentionally omit raw invocation secrets, ciphertext, decrypted
content, target metadata, tokens, keys, and recovery material.

## Current MVP Boundary

The current sync plugin keeps the compatibility bundle path:

- bundles `~/.config/voidb/` as deterministic `tar.zst`;
- supports `full`, `global`, and `plugin:<id>` bundle kinds;
- excludes `sync.toml` from bundles and preserves it on pull;
- encrypts bundle payloads client-side with a DEK before upload;
- uploads a plaintext manifest containing file paths, sizes, and hashes;
- stores only ciphertext and sync metadata server-side;
- uses optimistic server revisions for blob updates;
- can overwrite local config on pull.

This is acceptable only as opt-in compatibility behavior. It gives users a
working backup/sync path, but it is too coarse to be the capability-first sync
model because it treats storage files as the contract.

Req60 adds a local object-level readiness gate for the target contract. The
plugin can push and pull object records for profiles, profile policy,
credential references, encrypted credential records, plugin compatibility, and
app preferences; it records object conflicts instead of falling back to a
bundle resolver; and the hosted smoke starts a real local `voidb-sync-server`
process with disposable state. That evidence supports a stable/default
acceptance decision, but it does not by itself enable Sync by default.

## Target Sync Unit

The target sync unit is a versioned, schema-shaped object owned by VoidB Core
or a plugin manifest, not an arbitrary local file. The concrete envelope, ID,
version, manifest, and device-enrollment contract is defined in
[Object-Level Sync Model](object-level-sync-model.md).

Governed team sharing is a stricter layer over profile objects, not a broader
form of personal sync. Its collection, role, field-policy, and local
credential re-enrollment rules are defined in
[Governed Team Profile Sharing](team-profile-sharing.md).

Initial sync units should be:

- connection profiles;
- credential reference metadata;
- encrypted credential records, only through the credential broker;
- profile policy;
- non-secret app preferences;
- saved query metadata and query text when policy permits;
- installed plugin identity and compatibility metadata;
- sync bookkeeping that is explicitly cross-device.

These units need stable IDs, versions, conflict behavior, redaction rules, and
migration paths before they are enabled by default.

## Profile Metadata Sync Rules

Connection profiles can sync only as profile records, not as decrypted
`ConnectionConfig.plugin_config` blobs.

| Field or data class | Sync decision | Notes |
|---|---|---|
| Profile ID | Sync | Stable identity is required for cross-device references. |
| Name | Sync | Conflicts must be detected when another profile in the same plugin uses the name, ignoring case. |
| Plugin ID | Sync | The receiving device must verify that a compatible plugin is installed or mark the profile unavailable. |
| Display name | Sync | User-facing metadata, not secret by itself. |
| Non-secret metadata | Sync | Examples include host, port, database name, bucket, region, namespace, and file path when policy allows. |
| Sensitive metadata | Conditional | Usernames, internal hostnames, account IDs, and tenant IDs may sync inside encrypted profile state, but agent-facing output still follows redaction policy. |
| Default invocation options | Sync | Only if schema-validated and free of plaintext secrets. |
| Credential references | Sync | IDs, classes, labels, and non-secret fingerprints may sync. Plaintext material may not. |
| Policy | Sync | Capability allow/deny lists and destructive defaults must follow the profile across devices. |
| Runtime instance descriptors | Do not sync | Instances are local, live state owned by plugin services. |
| Session state, pools, sockets, tunnels | Do not sync | These are runtime artifacts, not profile configuration. |

The receiving device must be able to list, inspect, validate, and test synced
profiles without printing plaintext secrets.

## Credential State

Plaintext credential material must never sync.

Never sync:

- plaintext passwords, tokens, API keys, private keys, passphrases, or client
  certificates;
- decrypted `plugin_config`;
- credential-bearing connection URLs;
- bearer tokens from `sync.toml`;
- the DEK, KEK, user password, or unwrapped recovery material;
- runtime session tokens or temporary target credentials unless a future
  credential broker explicitly classifies them as syncable encrypted records.

Credential references may sync because they identify what kind of credential a
profile needs. A reference is not enough to connect unless the receiving device
also has a compatible encrypted credential record or the user supplies the
secret locally.

Encrypted credential records may sync only after the credential broker owns
their format. The required properties are:

- client-side encryption before upload;
- no server-side decryption path;
- key wrapping separate from server authentication;
- per-record metadata that does not reveal plaintext material;
- versioned encryption metadata for migrations;
- a recovery and device-enrollment story that does not weaken local policy;
- audit records that mention credential reference IDs and classes, not secret
  values.

The existing `ConnectionConfig.plugin_config` encryption is a storage-internal
compatibility layer. It may be carried inside the current opt-in encrypted
bundle, but it is not a cross-device credential record format.

## Sync Config And Device State

`sync.toml` is device-local and must not sync.

It may contain:

- server URL;
- account email;
- device ID and device name;
- per-kind last revisions;
- last sync timestamp;
- a local CLI bearer token if CLI login is enabled.

This file is excluded from current bundles because copying it across devices
would clobber local device identity, revision tracking, and login state. A
future account/device model can sync a device list from the server, but the
local device's token and bookkeeping remain local.

## Manifest Visibility

Current sync uploads a plaintext bundle manifest with file paths, sizes, and
hashes. The server cannot decrypt bundle contents, but the manifest still
reveals shape metadata.

For the current opt-in MVP, this is acceptable if documented. For the target
model, manifests should be redacted or schema-shaped:

- use opaque server-visible object IDs that are not derived from aliases,
  hostnames, usernames, bucket names, local paths, or legacy connection keys;
- avoid exposing profile aliases in paths or object labels;
- avoid file names that contain hostnames, usernames, project names, bucket
  names, or credential labels;
- expose counts, kinds, versions, and hashes only when needed for conflict
  detection;
- redact or omit plugin-specific paths if they may reveal target-system data.

## Why Sync Must Not Lead

Sync must wait behind the local capability model for these reasons:

1. Profile identity is not yet the stable public contract while
   `ConnectionConfig` remains the transition storage shape.
2. Credential references and credential broker records need a stable schema
   before cross-device copies can be safe.
3. Policy must travel with profiles so a synced profile does not become more
   permissive on another device.
4. Audit semantics must exist before sync can record push, pull, conflict,
   recovery, and credential-enrollment actions safely.
5. Plugin manifests and compatibility rules must exist so a receiving device
   can distinguish "plugin missing" from "profile corrupt".
6. Structured errors must exist so sync failures are scriptable and safe for
   agents.
7. Conflict behavior must be object-level, not only whole-bundle revision
   replacement.
8. The current full-directory bundle can preserve legacy behavior, but it
   cannot tell Core which profile, policy, or credential object actually
   changed.

Moving sync first would freeze local file formats as public API and make later
profile/credential migrations harder.

## Conflict Model Direction

The current server revision protects one blob kind at a time. The target model
uses the object-scoped conflict contract in
[Object-Level Sync Model](object-level-sync-model.md#conflict-resolution).
Conflicts name only object kind, opaque object ID, versions, revisions, redacted
timestamps, and redaction status. Force and merge actions require explicit
per-object audit events.

Whole-bundle pull can remain a manual recovery operation, but it should not be
the default sync behavior for capability-first profiles.

## Syncable Data Matrix

| Data | Sync now in MVP bundle | Target default | Notes |
|---|---:|---:|---|
| `config.toml` as a file | Yes, opt-in | No | Replace with schema-shaped profiles, preferences, and policy records. |
| `sync.toml` | No | No | Device-local state. |
| Connection profile ID, alias, plugin ID | Indirect | Yes | Must become first-class sync records. |
| Non-secret profile metadata | Indirect | Yes | Schema-validated per plugin. |
| Sensitive profile metadata | Indirect | Conditional | Encrypted at rest and redacted in outputs. |
| Credential reference IDs/classes | Indirect | Yes | Safe as references, not as secrets. |
| Plaintext credential material | No | No | Never sync. |
| Encrypted credential records | Indirect | Conditional | Only after credential broker owns the format. |
| Profile policy | Indirect | Yes | Must travel with profiles. |
| Runtime instances and sessions | No | No | Local live state. |
| Saved query text | Yes, opt-in | Conditional | Policy may classify query text as target-system data. |
| Plugin local state under `plugins/<id>/` | Yes, opt-in | Conditional | Requires plugin-owned sync schema before default enablement. |
| Installed plugin binaries | No | No | See [Future Plugin Installation Model](plugin-installation-model.md). |
| Plugin manifests and compatibility metadata | Indirect | Yes | Enough to detect missing or incompatible plugins. |
| Audit records | No explicit contract | Deferred | Needs retention and redaction policy before sync. |

## Rebuild Gates

Do not enable sync by default until these gates are true:

1. `ConnectionProfile` is the public profile shape for CLI and agents.
2. Credential references are separate from plaintext credential material.
3. Encrypted credential records have a broker-owned, versioned format.
4. Profile policy and destructive-operation defaults are part of synced
   profile records.
5. Plugin manifests declare profile schemas and compatibility requirements.
6. Structured errors and audit records cover sync push, pull, login, conflict,
   recovery, and device enrollment.
7. Object-level conflict behavior exists for profiles and credential records.
8. Legacy `ConnectionConfig` migration can round-trip without losing user data.
9. Sync payload manifests are redacted or schema-shaped enough for server-side
   storage.
10. Recovery and device enrollment are documented without requiring plaintext
    secret export.

## Near-Term Rules

- Keep sync opt-in until the release owner explicitly accepts the stable/default
  claim.
- Keep `sync.toml` excluded from bundles.
- Do not advertise full-directory sync as the capability-first data model.
- Do not add marketplace, hosted catalog, or plugin distribution requirements
  to the sync boundary.
- Do not make plugins implement sync APIs while the local manifest and profile
  contracts are still moving.
- Prefer local profile, credential, policy, and audit work over sync feature
  expansion.
- When sync changes are necessary, test the sync plugin directly with
  `cargo test -p voidb-plugin-sync`.
- For release-candidate prep, run the local sync smoke helper documented in
  Release Sync Smoke. The stable/default claim also
  requires recording the object-level gate and local hosted process evidence,
  not only the compatibility-bundle smoke.
- Treat the full-directory bundle as compatibility backup or manual recovery,
  not as a fallback resolver for object-level conflicts.

## Non-Goals

- Removing the current sync plugin.
- Rewriting the sync server in this slice.
- Designing the future plugin marketplace.
- Replacing the opt-in stable-readiness gate with automatic/default Sync.
- Claiming absolute protection from a local agent with arbitrary filesystem or
  process access.
