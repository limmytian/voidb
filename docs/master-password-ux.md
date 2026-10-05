# Master Password UX and Credential Protection State

This document defines the master-password flow for VoidB. The current
implementation includes the shared protection state model, an explicit
re-encryption command, protected config saves, real protection-state warnings,
and a Connection Manager setup/unlock/re-encrypt entry point.

## Goals

- Replace silent default-passphrase saves with an explicit user-controlled master
  password path.
- Keep legacy configs readable until users choose to migrate or re-encrypt them.
- Never persist plaintext master passwords or print decrypted credential
  material.
- Make failure states recoverable without silently overwriting existing
  credentials.

## Protection State Model

Core exposes `CredentialProtectionState` so CLI, TUI, and migration commands can
share one vocabulary.

| Store | Meaning | Initial mode | Strong target |
| --- | --- | --- | --- |
| `config` | Legacy `config.toml` entries with encrypted `plugin_config` blobs. | `default_passphrase` when credential material exists and no user password is active. | `user_passphrase` after explicit re-encryption. |
| `profile` | Agent-safe native profile metadata in `profiles.json`. | Metadata only; profile files must not contain secrets. | Native metadata with credential refs only. |
| `credential` | Encrypted local plugin configuration records in `credentials.json`. | `default_passphrase` until the user sets a master password. | `user_passphrase` after explicit re-encryption. |

Modes are:

| Mode | Meaning |
| --- | --- |
| `default_passphrase` | Credential material is protected only by VoidB's compiled fallback passphrase. This requires re-encryption before warnings can disappear. |
| `user_passphrase` | Credential material was encrypted with a user-provided master password. |
| `migrated` | The store contains migrated metadata or credential references, not plaintext credential material. |
| `unknown` | VoidB cannot safely determine protection state, usually because a file cannot be parsed or decrypted. |

Master-password session states are `not_configured`, `locked`, `unlocked`,
`forgotten`, and `unknown`. `unlocked` is process memory only.

## Short-Lived Agent Authorization

Agents do not need the master password. `voidb-cli agent authorize` starts a
small local broker that keeps the password in memory and issues a scoped grant.
The default grant is limited to one profile and plugin, lasts 15 minutes, has no
operation-count limit, and rejects destructive acknowledgements. Passing
`--uses <n>` adds an optional finite budget. Its Unix socket and grant record are
private to the local user.

```bash
voidb-cli agent authorize --profile prod --plugin ssh
voidb-cli agent list
voidb-cli agent exec ssh.sftp_list --profile prod \
  --input-json '{"path":"."}' \
  --purpose "List deployment artifacts needed for release verification"
voidb-cli agent revoke --all
```

Authorization prompts for the master password with terminal echo disabled when
the current process is not already unlocked. The broker executes only `profile
test` and `invoke run`; it never returns the master password. Profile, plugin,
and capability scope are checked before execution. `agent exec` resolves the
friendly profile name and binds the broker call to its immutable Profile ID
internally. The lower-level `agent run` command still requires that immutable
ID explicitly. `--input-file` is rejected to prevent a grant from becoming a
local-file read primitive.

If `agent exec` must create a JIT request, `--purpose` is required and is shown
to the user during local review. Pending requests that reach their request TTL
are automatically denied; the master password cannot be used to approve them
after the deadline.

Destructive acknowledgement is denied by default. A user must explicitly add
both `--allow-destructive` and `--yes` when authorizing such access. Even then,
normal profile policy and per-invocation `--yes` checks still apply. TTL is
bounded to 1–60 minutes and an optional use count to 1–100. Expiration or
explicit use exhaustion shuts down the broker and deletes its runtime files.
`agent revoke` and `agent revoke --all` immediately block new calls without
requiring the master password. An already-running call is still bounded by the
grant expiration.

For several profiles, `voidb-cli agent authorize-batch --spec <path>` renders
one local CLI review, prompts for the master password once, and starts separate
profile/plugin-bound brokers. The spec contains only profile references,
plugins, a concrete non-secret purpose for each grant, presets, execution
modes, and capability IDs; it must never contain credentials.

## CLI Flow

The stable command names can land in the implementation slice, but the flow
should behave as follows:

1. `voidb credential master setup`
   Prompts for a new master password twice with terminal echo disabled. Empty
   passwords are rejected. On success, the command records only password-derived
   metadata needed to validate future unlock attempts. This command is reserved
   for a follow-up; the current setup path is `reencrypt`.
2. `voidb credential master reencrypt`
   Requires the current or newly confirmed master password, decrypts existing
   default-passphrase credential blobs, writes them with the user passphrase, and
   leaves the original file untouched if any item fails. The implemented command
   is:

   ```bash
   voidb-cli credential master reencrypt --new-password-env VOIDB_MASTER_PASSWORD --yes
   ```

   Omit `--new-password-env` for an interactive hidden prompt. Add
   `--current-password-env <VAR>` only when re-encrypting from an existing
   user-passphrase config. Use `--dry-run` to inspect counts without writing.
3. `voidb credential master unlock`
   Prompts for the master password and unlocks only the current process. For
   short-lived CLI invocations this usually means the same command immediately
   performs the protected operation. Current CLI unlock state is supplied through
   `VOIDB_MASTER_PASSWORD` for the process.
4. `voidb credential master forget`
   Clears any in-memory master password for long-lived processes. In one-shot
   CLI commands it should be a harmless no-op with a redacted status response.
5. Commands that need credentials while locked must fail with a master-password
   required error instead of falling back to the default passphrase for new
   writes.
6. Agent workflows should use a short-lived broker grant instead of exporting
   `VOIDB_MASTER_PASSWORD` into an agent process.

CLI JSON output may report protection modes, counts, plugin IDs, and file paths.
It must not report connection names, hosts, decrypted `plugin_config`, password
checks, or passphrase-derived key material.

After re-encryption, `AppConfig::save()` refuses to write user-passphrase config
unless the process has `VOIDB_MASTER_PASSWORD` set. Legacy configs without
master-password metadata remain readable and writable through the default
passphrase path for backward compatibility.

## TUI Flow

The Connection Manager is the first TUI surface because it owns credential
creation and edits.

Current behavior:

1. The Connection Manager header shows a redacted credential-protection summary:
   counts, protection mode, and the next action. It does not show connection
   names, hosts, plugin-specific target metadata, passwords, tokens, or
   decrypted `plugin_config`.
2. Press `m` to open the master-password dialog.
3. If the config is still on the default passphrase path, the dialog asks for a
   new master password and confirmation, then calls the shared re-encryption
   primitive. Existing credential material is rewritten with the user
   passphrase and the in-memory connection registry is refreshed.
4. If the config is user-passphrase protected and locked, the same `m` entry
   point asks for the master password, verifies it, loads the decrypted config,
   and keeps the password only in the current TUI process memory.
5. If the config is already unlocked in the TUI session, `m` can re-encrypt with
   a new master password. Output remains count-based and redacted.
6. Press `a` on a selected profile to authorize a default read-only agent grant
   for 15 minutes with no operation-count limit. Press `x` to revoke all active
   agent grants.

The shell must still route hard globals (`Ctrl+Q`, `Ctrl+\`) while dialogs are
open. The Connection Manager requests raw input while the password dialog is
open so soft globals such as `q` do not intercept password characters. Plugins
that request raw input should not receive typed password characters unless they
own the password prompt.

Exiting the TUI drops its in-memory password. Agent brokers are separate
short-lived processes and stop at their own expiry, use exhaustion, or explicit
revocation.

## Recovery Limits

VoidB cannot recover a lost master password. Recovery options are limited to:

- retrying unlock with the correct password;
- restoring a backup created before re-encryption;
- exporting redacted profile metadata and recreating credentials manually;
- deleting protected credential blobs after explicit user confirmation.

Wrong-password, parse, or partial-write failures must leave existing files
unchanged and return redacted diagnostics.

## Warning Rules

The `security.default_passphrase_credential_risk` warning is valid only when the
protection report contains a `config` state with:

- `mode = default_passphrase`;
- `material = present`;
- `migration = required`.

Warnings disappear only after credential material is actually protected by a
user passphrase or moved behind a future protected credential store. Migrating
profiles alone does not clear the legacy config warning, because migrated
credential refs can still point at default-passphrase `plugin_config` blobs.

## Validation

Focused changes to this flow should run:

```bash
cargo test -p voidb-core credential_protection --quiet
cargo test -p voidb-core reencrypt_config_file_sets_user_passphrase_metadata --quiet
cargo test -p voidb-core configured_user_passphrase_save_requires_active_password --quiet
cargo test -p voidb-cli master_reencrypt_command_exposes_safe_password_sources --quiet
cargo test -p voidb-cli default_passphrase_warning_is_redacted_and_machine_readable --quiet
cargo test -p voidb-cli user_passphrase_protection_suppresses_default_passphrase_warning --quiet
cargo test -p voidb-tui credential --quiet
git diff --check
```
