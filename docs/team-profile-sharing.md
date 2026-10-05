# Governed Team Profile Sharing

This document defines the first governed sharing boundary for capability
profiles. It extends the object-level sync model from personal multi-device
recovery into team-scoped profile collections without sharing plaintext secrets,
master passwords, unwrapped keys, or device-local sync state.

The core model lives in `crates/voidb-core/src/team_sharing.rs`.

## Goals

- Share approved profile object collections with team members.
- Preserve profile policy and plugin compatibility requirements across import.
- Let receiving devices import profile metadata while requiring local credential
  re-enrollment for secret material.
- Keep server-visible collection metadata opaque and redacted.
- Leave room for revoke and audit flows without weakening the credential model.

Non-goals for this slice:

- implementing the share server API;
- implementing invite, revoke, or audit storage;
- sharing encrypted credential records across team boundaries;
- sharing `sync.toml`, master passwords, sync passwords, KEK/DEK bytes, or
  runtime session state.

## Collection Model

A team share is a `TeamShareCollection` encrypted client-side before storage or
transport. Server-visible metadata uses `TeamShareCollectionManifest`, which
contains only:

- `collection_id`, using the opaque `share_collection_` prefix;
- update actor and timestamp;
- member and object counts;
- object kinds;
- redaction status.

The manifest must not include collection display names, profile names,
plugin-specific target metadata, hostnames, usernames, bucket names, database
names, credential labels, ciphertext, local paths, or legacy connection keys.

Collection membership is represented by `TeamShareMember`:

| Role | Can import profiles | Can modify collection | Can revoke access |
|---|---:|---:|---:|
| `owner` | Yes | Yes | Yes |
| `maintainer` | Yes | Yes | Yes |
| `consumer` | Yes | No | No |
| `auditor` | No | No | No |

Principals use opaque IDs such as `principal_...`; user emails, display names,
and directory group names are not part of the server-visible collection
manifest.

## Shareable Objects

Team sharing reuses object sync payloads for profile-shaped data:

| Object kind | Team share decision | Notes |
|---|---|---|
| `profile` | Share | Profile payload is already redacted by object sync helpers. |
| `credential_ref` | Share | Carries ID, class, redacted label, and optional non-secret fingerprint only. |
| `profile_policy` | Share | Must travel with the profile so imports do not become more permissive. |
| `plugin_compatibility` | Share | Used to detect missing or incompatible local plugins. |
| `credential_record` | Require local re-enrollment | Team sharing must not move encrypted credential material between people. |
| `app_preference` | Reject as device-local | Not part of governed profile sharing. |

`TeamShareProfileObject` bundles one profile payload with its policy,
plugin-compatibility record, credential refs, and generated credential
requirements. It fails closed when object IDs or references disagree, for
example when a profile points to one policy object but the bundle includes a
different policy object.

## Field Policy

The default `TeamSharePolicy` classifies profile fields as follows:

| Field class | Decision |
|---|---|
| Profile ID, alias, plugin ID, display name | Share |
| Profile metadata and default options | Share after object-sync redaction |
| Credential reference ID and class | Share |
| Credential reference label | Share after redaction |
| Profile policy | Share |
| Plugin compatibility metadata | Share |
| Credential material | Require local re-enrollment |
| Master password | Reject |
| Unwrapped key material | Reject |
| Device-local `sync.toml` state | Reject |
| Runtime session state | Reject |

The policy is intentionally conservative. If a future field cannot be classified
confidently, import should fail closed or mark the profile unavailable until the
field has an explicit share rule.

## Import Restrictions

`plan_team_share_import` produces a redacted `TeamShareImportPlan` instead of
silently applying a collection. The plan can contain these actions:

- `import_profile` for accepted profile metadata;
- `apply_profile_policy` when policy is present;
- `check_plugin_compatibility` for each shared profile;
- `mark_profile_unavailable` when the required plugin is missing locally or
  below the shared profile's minimum plugin version;
- `bind_local_credential` when a compatible local credential reference already
  exists;
- `require_credential_reenrollment` when a credential ref has no local material.

Import never accepts credential records from a team share. Credential refs are
treated as requirements, not grants. A receiving user must enroll or bind secret
material locally through the credential broker before the imported profile can
connect to a target system.

Import action reasons are intentionally narrow and redacted:

- `missing_plugin`;
- `incompatible_plugin_version`;
- `credential_reenrollment_required`;
- `local_credential_available`.

The current version check compares numeric semantic-version segments before
pre-release/build metadata. Unknown or non-numeric versions fail closed as
incompatible when a minimum version is declared.

## Device-Local State

These values remain local and must not appear in a collection, manifest, audit
detail, or import plan:

- `sync.toml`, device IDs, local bearer tokens, and revision cursors;
- master passwords and sync passwords;
- unwrapped KEK/DEK bytes or recovery material;
- plaintext passwords, tokens, API keys, private keys, passphrases, and client
  certificates;
- decrypted `plugin_config`;
- runtime sessions, tunnels, sockets, pools, temporary target credentials, and
  other plugin live state.

## Supported Boundaries

Team sharing is not personal sync with a bigger audience.

| Area | Supported now | Not supported |
|---|---|---|
| Personal object sync | Device-to-device profile, policy, plugin compatibility, credential ref, and encrypted credential record sync under one user's sync enrollment. | Treating personal sync credentials or `sync.toml` as team material. |
| Team profile sharing | Sharing approved profile collections with opaque collection, invite, member, and profile object IDs. | Sharing arbitrary config directories, plugin local state, runtime sessions, or app preferences. |
| Credentials | Credential references become local re-enrollment requirements or local binding actions. | Sharing plaintext secrets, encrypted credential records between people, master passwords, sync passwords, KEK/DEK bytes, or unwrapped recovery material. |
| Plugins | Import plans check local plugin presence and declared minimum plugin version. | Installing plugins automatically, trusting remote plugin binaries, or downgrading profile policy when a plugin is missing. |
| Policy | Profile policy travels with the profile and mismatched object references fail closed. | Silent policy rewrites, ownership transfer by invite, or making imported profiles more permissive. |
| Revoke | Owners and maintainers can revoke pending invites or non-owner members. | Guaranteed target-system credential revocation, owner removal, history erasure, or revoking already copied local secrets. |
| Audit | Redacted activity/audit records with opaque IDs and counts. | Audit payloads containing aliases, hostnames, plugin IDs, credential labels, target diagnostics, or secrets. |

## Invite, Import, And Revoke Flows

`create_team_share_invite` creates a pending invite only when the inviter is an
`owner` or `maintainer` member of the collection. Invites can grant
`maintainer`, `consumer`, or `auditor`; ownership transfer is intentionally not
an invite operation.

`accept_team_share_invite` checks that:

- the invite is still pending;
- the invite belongs to the collection being imported;
- the invite has not expired;
- the accepting actor matches the invite recipient principal.

Acceptance returns a `TeamShareInviteAcceptance` containing the
`TeamShareImportPlan`, imported profile count, unavailable profile count,
credential re-enrollment count, blocked count, and redaction status. Import can
plan profile metadata while still marking a profile unavailable when a plugin is
missing or secret material needs local re-enrollment.

`revoke_team_share_access` lets an `owner` or `maintainer` revoke a member or
pending invite. The owner role cannot be revoked through this flow; ownership
transfer or collection shutdown needs a separate policy surface.

## Activity And Audit

Team sharing exposes redacted `TeamShareActivityRecord` values for:

- `invite_created`;
- `invite_accepted`;
- `import_planned`;
- `import_blocked`;
- `access_revoked`;
- `credential_reenrollment_required`.

`team_share_activity_audit_event` maps those records into the shared
`AuditEvent` shape using these stable operation names:

- `team_share_invite_created`;
- `team_share_invite_accepted`;
- `team_share_import_planned`;
- `team_share_import_blocked`;
- `team_share_access_revoked`;
- `team_share_credential_reenrollment_required`.

Activity metadata contains opaque collection, invite, and member IDs plus
counts for profiles, unavailable profiles, credential re-enrollments, and
blocked imports. It must not contain profile names, plugin IDs, hostnames,
usernames, bucket names, database names, target-system diagnostics, credential
labels, or credential values.

## Validation

Focused model changes should run:

```bash
cargo test -p voidb-core team_sharing
```

Changes that alter object-sync payloads, credential references, or policy
evaluation should also run the relevant sync and capability checks listed in
[CI Check Tiers](ci-checks.md).
