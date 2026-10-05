# Security Notes

VoidB encrypts connection `plugin_config` blobs before writing
`~/.config/voidb/config.toml`, but the protection level depends on whether a
master password is used.

## Credential Storage

- Connection credentials are serialized into `ConnectionConfig.plugin_config`.
- `AppConfig::save_with_password(Some(...))` encrypts those blobs with
  AES-256-GCM and an Argon2id-derived key from the supplied master password.
- The Connection Manager can now set, unlock, and re-encrypt with a user
  master password from the TUI. Until the user completes that flow, legacy
  saves can still use the compiled default passphrase in
  `crates/voidb-core/src/crypto.rs`.

The default passphrase prevents casual plaintext reading of config files, but it
is not strong protection against anyone who has access to the source code,
binary, or this documentation. Treat credentials saved without a master password
as weakly protected.

## File Permissions

On Unix-like systems, VoidB writes local security-sensitive files with `0600`
permissions. This includes `config.toml`, sync plugin `sync.toml`, migrated
profile files, credential grant stores, and audit event logs. Private file modes
reduce accidental disclosure to other local users, but they do not replace
strong credential encryption.

## Recommended UX Surface

The Connection Manager surfaces the master-password warning because that is
where users create and edit credentials. The current flow is:

1. Show a concise, count-based warning when saved credential material is still
   protected by the default passphrase.
2. Offer a master-password prompt with the `m` key.
3. Re-encrypt existing connection configs with the user-provided master password.
4. Avoid storing the master password; keep it in process memory only after entry.
5. Prompt to unlock when the config is protected but the TUI session is locked.

Documentation and release notes should still avoid claiming that default
credential storage is strong security for users who have not completed
re-encryption.

The detailed setup, unlock, forget, recovery, and state-transition rules are in
[Master Password UX and Credential Protection State](master-password-ux.md).
The current CLI re-encryption flow is
`voidb-cli credential master reencrypt --new-password-env VOIDB_MASTER_PASSWORD --yes`.
After re-encryption, protected saves require `VOIDB_MASTER_PASSWORD` to be set
for the current process.

The profile CLI emits a machine-readable
`security.default_passphrase_credential_risk` warning when saved profile
configuration contains credential-shaped fields that are still protected only by
the default passphrase path. The warning reports counts and plugin IDs only; it
must not expose connection names, hosts, passwords, tokens, or decrypted
`plugin_config`. The TUI warning is even narrower and shows counts only.

## Capability-First Boundary

The capability-first agent/plugin boundary is defined in
[Secret Brokering and Redaction Policy](secret-brokering-redaction-policy.md).
In short, agents invoke capabilities by profile ID or alias, while plugins may
receive scoped credential grants only when Core authorizes a specific invocation
or runtime instance.

Agent-triggered local filesystem access is governed separately by the
[Local Path Authorization Policy](local-path-authorization-policy.md). A
capability grant never implies permission to read, scan, create, replace, or
resume against a local path; those operations require a narrow, expiring local
path grant and fail-closed path resolution.

## Central Agent Authorization Boundary

Connection Manager and the local interactive `agent request review` command are
the human authorization surfaces; the local CLI broker is the only grant
store/enforcement boundary. Plugins declare capability risk, authorization
metadata, and semantic session purposes; they must not persist grants, evaluate
agent policy, render a second authorization screen, or infer execute consent
from opening a plugin.

Read-only remains the default. Interactive/Execute requires an exact centrally
resolved preset and explicit destructive consent. Full access resolves every
currently declared plugin capability into an exact stored snapshot and requires
explicit destructive consent when applicable; later catalog additions are not
inherited. Custom is also exact; empty or wildcard scope is denied. Consent
exists at two levels: the grant may permit destructive calls, and every
destructive call must still acknowledge its own action. Profile policy can deny
either path.

Frontend grant/status responses exclude broker tokens, socket paths, master
passwords, decrypted profiles, and credential material. Broker health and live
session count are separate: offline/stale authorization is not reported as
active, while a valid grant with zero sessions remains valid. Revoke,
replacement, expiry, and use exhaustion close grant-owned sessions and remove
private runtime artifacts. See
[Unified Agent Authorization Contract](agent-authorization-contract.md) and
[Agent Authorization Broker](agent-authorization-broker.md).

## Release Gate

Security gates are mandatory for release candidates. See
[Security Release Checklist](security-release-checklist.md) for the required
command set and release-gate expectations around TLS defaults, file
permissions, credential warnings, destructive-operation controls, and residual
default-passphrase risk.
