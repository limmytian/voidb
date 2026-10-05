# Profile Migration

VoidB now supports an explicit, non-destructive migration path from legacy
`ConnectionConfig` entries to capability-first local profile records.
For the complete backup, JSON compatibility, authorization-mode, verification,
troubleshooting, and safe rollback workflow, use the
[Agent Operator, Migration, and Troubleshooting Guide](agent-operator-guide.md).

## Local files

The migration writes two private JSON files under the VoidB config directory:

- `profiles.json` stores active, agent-safe `ConnectionProfile` records.
- `credentials.json` stores credential references and AES-256-GCM encrypted
  plugin configuration records.

Both files are written with `0600` permissions on Unix-like systems. Neither
file stores plaintext credential values. Migrated profiles resolve directly
from these two stores and do not read live connection details from
`config.toml`.

## Commands

Preview a migration without writing files:

```bash
voidb-cli profile migrate preview --format json
```

Apply the migration:

```bash
voidb-cli profile migrate apply --format json
```

Both commands support `--plugin <PLUGIN_ID>` to limit migration to one plugin.
`postgres` and legacy `postgresql` filters both match PostgreSQL connections.

## Connection Manager Setup Flow

Humans can start from the standalone Connection Manager:

```bash
voidb-cli connections tui
```

Recommended setup order:

1. Press `n` to create a native profile, or select an existing profile and
   press `e` to edit it.
2. Press `m` to set or unlock the master password before saving sensitive
   credential material.
3. Press `t` on a saved profile to run the service-backed `profile test` path
   without blocking the TUI.
4. Press `c` to inspect capability metadata for the selected profile's plugin.
   The browser shows command guidance only; capability execution still belongs
   to `voidb-cli invoke run`.
5. Use `voidb-cli profile migrate preview --format json` and
   `voidb-cli profile migrate apply --format json` when moving legacy configs
   into explicit profile records.

The Connection Manager may show plugin-owned TUI command guidance such as
`voidb-cli ssh tui --profile id:<profile-id>`, but it must not launch or host
that plugin TUI.

## Compatibility

Migration is intentionally non-destructive: existing `config.toml` connection
records remain as a rollback backup. They are not shown by the native
Connection Manager and are not used by normal profile/invoke resolution after
migration. Unmigrated records require an explicit migration command.
