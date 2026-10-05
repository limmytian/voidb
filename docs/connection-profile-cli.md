# Connection Profile CLI Contract

This document defines the first public CLI contract for saved connection
profiles. It belongs to the capability-first CLI work and builds on:

- [Capability Core Model](capability-core-model.md)
- [Secret Brokering and Redaction Policy](secret-brokering-redaction-policy.md)
- [Audit and Structured Error Schema](audit-and-error-schema.md)
- [Plugin Manifest Schema](plugin-manifest-schema.md)

The scope is profile management only: list, create, update, inspect, validate,
and test saved profiles without exposing plaintext secrets. Generic capability
discovery and invocation are defined in
[Capability Discovery and Invocation CLI Contract](capability-cli.md).

## Command Group

The canonical command group is:

```bash
voidb profile <command>
```

`voidb connection <command>` may be kept as a compatibility alias while the old
`voidb connections` built-in command is migrated, but new documentation and
agent workflows should use `profile`.

The noun is intentionally `profile`, not `connection`, because a profile is
saved configuration. It is not a live socket, session, pool member, tunnel, or
runtime instance.

## Profile References

Commands that accept a profile reference use this grammar:

```text
<profile-ref> := <name> | id:<profile-id> | name:<name>
```

Every profile has a globally unique, immutable Profile ID. Its name must be
unique within its plugin, using a case-insensitive comparison; the same name
may be used by different plugins. Commands that encounter an ambiguous bare
name across plugins must fail with
`conflict.profile_ref_ambiguous` and include candidate profile IDs and plugin
IDs, not decrypted config.

Examples:

```bash
voidb profile show prod-db --format json
voidb profile show id:profile:4c26ea66-9c35-4b82-8876-239c72f68d89 --format json
voidb profile test name:prod-db --timeout 30s --format json
```

## Common Flags

All commands that return data support:

| Flag | Meaning |
|---|---|
| `--format table` | Human-readable output. This is the default for interactive terminals. |
| `--format json` | Stable machine-readable JSON. Required for agents. |
| `--quiet` | Print only the minimal success value for scripts, when supported. |

Mutating commands support:

| Flag | Meaning |
|---|---|
| `--expected-version <n>` | Optimistic concurrency guard for updates and deletes. |
| `--dry-run` | Validate and show the planned mutation without storing it. |
| `--yes` | Confirm non-interactive destructive or replacement behavior. |

Commands that may call a plugin support:

| Flag | Meaning |
|---|---|
| `--timeout <duration>` | Effective timeout, such as `5s`, `30s`, or `2m`. |
| `--format json` | Returns structured success or structured errors. |

## Redaction Rules

The CLI must never print plaintext passwords, tokens, API keys, private keys,
passphrases, decrypted `plugin_config`, full credential-bearing URLs, signed
URLs, authorization headers, cookies, or plugin stderr before redaction.

`--reveal-secrets` is intentionally not part of this contract.

Profile JSON input may contain credential references, but it must not contain
plaintext credential material. If an input document includes a secret-shaped
field where a credential reference is required, the command must fail with
`validation.secret_in_profile_payload`.

Human local workflows may import or replace credential material through
dedicated secret source flags:

```bash
voidb profile create --plugin mysql --name prod-db \
  --input mysql-profile.json \
  --credential password:env=VOIDB_MYSQL_PASSWORD \
  --format json

voidb profile update prod-db \
  --credential password:file=./password.txt \
  --expected-version 7 \
  --format json
```

Secret source values are operational input to Core. They are converted into
credential references before any agent-facing output is written. They must not
be echoed in stdout, stderr, logs, traces, audit records, or diagnostic output.

## JSON Output Envelope

Non-streaming `--format json` commands return one JSON object.

Successful commands use:

```json
{
  "ok": true,
  "schema_version": 1,
  "command": "profile",
  "data": {},
  "warnings": []
}
```

Failed commands use the structured error contract from
[Audit and Structured Error Schema](audit-and-error-schema.md):

```json
{
  "ok": false,
  "schema_version": 1,
  "command": "profile",
  "error": {
    "category": "validation",
    "code": "validation.profile_schema_mismatch",
    "message": "Profile input did not match the plugin profile schema.",
    "details": {},
    "target": null,
    "retryable": false,
    "redaction": "not_required"
  }
}
```

Human messages may change, but `ok`, `error.category`, `error.code`,
`error.retryable`, and redacted structured details are stable.

## Profile JSON Shape

Agent-facing profile output follows the `ConnectionProfile` model:

```json
{
  "id": "profile:4c26ea66-9c35-4b82-8876-239c72f68d89",
  "name": "prod-db",
  "plugin_id": "mysql",
  "display_name": "Production MySQL",
  "metadata": {
    "host": "db.example.internal",
    "port": 3306,
    "database": "app"
  },
  "default_options": {
    "readonly": true
  },
  "credential_refs": [
    {
      "id": "cred_01JZ0V8G8Y8Z8GJ7K8B9C0D1E2",
      "class": {
        "kind": "password"
      },
      "label": "primary"
    }
  ],
  "policy": {
    "allowed_capabilities": ["query"],
    "denied_capabilities": ["exec"],
    "allow_destructive_by_default": false
  },
  "version": 7
}
```

`metadata` must be schema-validated against the selected plugin's profile
schema. If a plugin marks a metadata field as sensitive, table output must
redact or omit it and JSON output must include only the redacted representation
allowed by policy.

## Commands

### `profile list`

List saved profiles.

```bash
voidb profile list --format json
voidb profile list --plugin mysql --format table
```

Options:

| Option | Meaning |
|---|---|
| `--plugin <plugin-id>` | Return only profiles owned by one plugin. |
| `--include-disabled` | Include disabled profiles. |
| `--limit <n>` | Limit returned profiles. |
| `--page-token <token>` | Continue from a previous page. |

JSON output:

```json
{
  "ok": true,
  "schema_version": 1,
  "command": "profile",
  "data": {
    "profiles": [
      {
        "id": "profile:4c26ea66-9c35-4b82-8876-239c72f68d89",
        "name": "prod-db",
        "plugin_id": "mysql",
        "display_name": "Production MySQL",
        "credential_refs": [
          {
            "id": "cred_01JZ0V8G8Y8Z8GJ7K8B9C0D1E2",
            "class": {
              "kind": "password"
            },
            "label": "primary"
          }
        ],
        "policy": {
          "allowed_capabilities": ["query"],
          "denied_capabilities": ["exec"],
          "allow_destructive_by_default": false
        },
        "version": 7
      }
    ],
    "page": {
      "next_page_token": null
    }
  },
  "warnings": []
}
```

`list` should not include full metadata by default. It returns enough data for
selection, filtering, policy inspection, and follow-up `show`.

### `profile show`

Inspect one profile.

```bash
voidb profile show prod-db --format json
voidb profile show prod-db --include metadata,policy,credential_refs --format json
```

Options:

| Option | Meaning |
|---|---|
| `--include <parts>` | Comma-separated parts: `metadata`, `default_options`, `policy`, `credential_refs`, `schema_status`. |
| `--plugin <plugin-id>` | Resolve a name shared by different plugins. |

Default JSON output includes the full redacted profile. Plaintext secrets are
never included. `schema_status` reports whether the current stored profile still
validates against the installed plugin schema.

### `profile validate`

Validate a profile document before create or update.

```bash
voidb profile validate --plugin mysql --input mysql-profile.json --format json
voidb profile validate --plugin mysql --input - --format json
```

Options:

| Option | Meaning |
|---|---|
| `--plugin <plugin-id>` | Plugin whose profile schema should validate the document. |
| `--input <path-or->` | Profile JSON input. `-` reads from stdin. |

Validation checks:

- JSON is valid.
- Required top-level fields are present.
- Metadata matches the plugin profile schema.
- Credential reference classes match the plugin manifest's declared secret
  classes.
- Plaintext secret-shaped fields are rejected.
- Policy capability IDs refer to known plugin capabilities when the capability
  catalog is available.

### `profile create`

Create one saved profile.

```bash
voidb profile create --plugin mysql --name prod-db --input mysql-profile.json --format json
voidb profile create --plugin s3 --name assets --input - --credential cloud_secret_key:env=VOIDB_AWS_SECRET_ACCESS_KEY --format json
```

Options:

| Option | Meaning |
|---|---|
| `--plugin <plugin-id>` | Required plugin owner. |
| `--name <name>` | Required stable name, unique within the plugin (case-insensitive). |
| `--display-name <name>` | Optional human display name. |
| `--input <path-or->` | Profile JSON payload containing metadata, defaults, credential refs, and policy. |
| `--credential <class>:<source>` | Optional local secret import source, converted into a credential reference. |
| `--dry-run` | Validate and return the planned redacted profile without storing it. |

The input document must not set `id`, `plugin_id`, `name`, or `version`; those
come from flags and Core. It may set:

- `metadata`
- `default_options`
- `credential_refs`
- `policy`

JSON output returns the created profile with credential references only.

### `profile update`

Patch one saved profile.

```bash
voidb profile update prod-db --input profile.patch.json --expected-version 7 --format json
voidb profile update prod-db --set metadata.database=app2 --expected-version 7 --format json
voidb profile update prod-db --credential password:env=VOIDB_MYSQL_PASSWORD --expected-version 7 --format json
```

Options:

| Option | Meaning |
|---|---|
| `--input <path-or->` | JSON Merge Patch over allowed mutable fields. |
| `--set <path=value>` | Small scalar patch for shell usage. Repeatable. |
| `--unset <path>` | Remove an optional field. Repeatable. |
| `--credential <class>:<source>` | Add or replace a credential reference from a local secret source. |
| `--expected-version <n>` | Required for non-interactive updates. |
| `--dry-run` | Validate and return the planned redacted profile without storing it. |

Mutable fields:

- `name`
- `display_name`
- `metadata`
- `default_options`
- `credential_refs`
- `policy`

`id` and `plugin_id` are immutable. Changing a profile's plugin requires
creating a new profile because schemas, credential classes, and capabilities are
plugin-owned.

### `profile test`

Test whether a profile can create the runtime access needed by a plugin.

```bash
voidb profile test prod-db --format json
voidb profile test prod-db --capability query --timeout 15s --format json
```

Options:

| Option | Meaning |
|---|---|
| `--capability <capability-id>` | Test access for a specific capability when the plugin exposes one. |
| `--timeout <duration>` | Effective timeout for validation, credential brokering, plugin startup, and target access. |
| `--plugin <plugin-id>` | Resolve a name shared by different plugins. |

`test` is a capability-style operation. Core resolves the profile, brokers only
the credential classes required by the plugin test operation, starts or reuses
the plugin process as needed, and returns a structured result.

Successful JSON output:

```json
{
  "ok": true,
  "schema_version": 1,
  "command": "profile",
  "data": {
    "profile": {
      "kind": "name",
      "value": "prod-db"
    },
    "plugin_id": "mysql",
    "capability_id": "connection.test",
    "status": "succeeded",
    "timing": {
      "duration_ms": 284,
      "timeout_ms": 15000
    },
    "redaction": "not_required"
  },
  "warnings": []
}
```

Failed tests return `ok: false` with a structured error. Target authentication
failures use `auth`; missing credential references use `credential`; denied
profile or capability policy uses `permission` or `policy`; plugin crashes use
`plugin`; target network failures use `transport` or `target_system` depending
on where the failure happened.

## Legacy Mapping

The existing CLI has a `connections` built-in command group with `list`, `show`,
and `test`. During migration:

1. `voidb profile list` reads current `ConnectionConfig` values through a
   storage adapter and emits `ConnectionProfile`-shaped JSON.
2. `voidb profile show` treats `plugin_config` as storage-internal data and
   emits only redacted profile metadata and credential references.
3. `voidb profile test` moves away from direct driver dispatch in the generic
   CLI command and routes through plugin-owned test capabilities.
4. `voidb connections ...` remains a compatibility wrapper until existing
   scripts can move to `voidb profile ...`.

## Invariants

- Agents reference profiles by ID or name, not by plaintext secrets.
- The CLI never prints plaintext credential material.
- `profile list` is safe for agents by default and omits detailed metadata.
- `profile show` returns a redacted `ConnectionProfile` representation.
- `profile create` and `profile update` reject plaintext secrets in JSON input.
- Local secret source flags create or replace credential references without
  echoing secret values.
- `profile test` routes through plugin-owned capability behavior instead of
  generic CLI driver calls.
- Mutating commands support optimistic concurrency.
- JSON errors use stable categories and codes from the audit/error contract.
