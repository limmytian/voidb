# Plugin Installation Model

This document defines the installation model for capability-first VoidB
process plugins. It covers installed directories, manifest ownership, version
compatibility, update paths, lifecycle state, and deferral boundaries. The
implemented scope is local package management; a hosted marketplace remains
out of scope.

It builds on:

- [Plugin Manifest Schema](plugin-manifest-schema.md)
- [Runtime Plugin Discovery](runtime-plugin-discovery.md)
- [Process Plugin Package Management](process-plugin-package-management.md)
- [Capability Discovery and Invocation CLI Contract](capability-cli.md)
- [Secret Brokering and Redaction Policy](secret-brokering-redaction-policy.md)
- [Sync Boundary Under The Capability Model](sync-boundary.md)

## Decision

VoidB should treat plugin installation as local package management over
validated process-plugin directories. A plugin package installs a directory
that contains `plugin.toml`, runtime files, schemas, and optional assets. Core
discovers that directory through the runtime discovery roots.

The first installation model is intentionally local and deterministic:

- no hosted catalog requirement;
- no marketplace ranking, billing, reviews, or remote trust model;
- no implicit execution from a project checkout;
- no sync of plugin binaries;
- no dynamic linking contract.

Hosted catalogs can be added later as a source that resolves to the same local
package format and validation pipeline.

## Relationship To Runtime Discovery

[Runtime Plugin Discovery](runtime-plugin-discovery.md) defines how Core reads
installed plugin directories. This document defines how those directories get
there and how they are updated, disabled, or removed.

The v1 discovery-compatible active layout remains:

```text
<plugin-root>/
  mysql/
    plugin.toml
    bin/
      voidb-plugin-mysql
    schemas/
      mysql-profile.schema.json
      query-input.schema.json
      query-output.schema.json
    README.md
    LICENSE
  redis/
    plugin.toml
    bin/
      voidb-plugin-redis
    schemas/
      ...
  .voidb-install/
    mysql/
      install.toml
      previous/
        1.2.2/
          ...
    redis/
      install.toml
```

Immediate child directories that start with `.` are install-manager metadata
and must be ignored by plugin discovery. Active plugin directories keep
`plugin.toml` at their root so the discovery algorithm does not need a separate
version resolver.

## Install Roots

Installation commands write to the user install root by default:

| Root | Writable by VoidB install commands | Purpose |
|---|---:|---|
| `VOIDB_PLUGIN_PATH` | No | Explicit development override only; trust level `explicit_development`; highest precedence. |
| User install root | Yes | Normal per-user plugin installs and updates; trust level `user_installed`. |
| System install root | No by default | OS package manager or administrator-managed plugins; trust level `administrator_managed`. |
| Bundled app resource root | No | Read-only plugins shipped with packaged VoidB; trust level `bundled`; lowest precedence. |

VoidB should not mutate development, system, or bundled roots unless a future
command explicitly supports that mode and the user accepts the privilege and
trust implications.

Discovery treats all process plugins as trusted local code execution, not as a
sandbox. The trust level is still exposed in machine-readable discovery output
so agents and release checks can distinguish opt-in development overrides from
installed packages. Only explicit development roots may resolve bare runtime
commands from `PATH`; user, system, and bundled roots must carry package-local
runtime executables under `bin/`.

## Package Shape

The first package input can be either an unpacked local directory or a local
archive. Both must contain exactly one plugin directory or exactly one
`plugin.toml` root.

Recommended archive extension:

```text
<plugin-id>-<version>.voidb-plugin.tar.zst
```

Required package contents:

- `plugin.toml`;
- every schema referenced by the manifest;
- every package-local runtime executable referenced by the manifest;
- any non-secret runtime assets required by the plugin.

Recommended package contents:

- `README.md`;
- `LICENSE`;
- `CHANGELOG.md`;
- checksums for large assets if the package builder provides them.

Package contents must not include plaintext credentials, user profiles,
tokens, local config files, synced data, or device state.

## Manifest Ownership

`plugin.toml` is package-owned metadata. VoidB reads and validates it, but
does not edit it during install, update, disable, or uninstall.

VoidB-owned installation state lives outside the active plugin directory under
`.voidb-install/<plugin-id>/install.toml`.

The install record should include:

- plugin ID;
- installed version;
- manifest digest;
- package digest;
- source type, such as `local_directory`, `local_archive`, or future `catalog`;
- source locator, redacted when needed;
- install root;
- installed timestamp;
- installed by actor;
- enabled/disabled state;
- previous version kept for rollback;
- compatibility status from the last validation run.

Disable state, pin state, trust decisions, and rollback metadata belong to the
install record, not to `plugin.toml`.

## Installation Flow

The installation command should follow this flow:

1. Resolve the source path or archive.
2. Unpack into a temporary staging directory on the same filesystem as the user
   install root.
3. Reject unsafe archive paths, symlinks that escape the staging directory,
   world-writable executables, and unexpected absolute paths.
4. Parse `plugin.toml`.
5. Validate manifest shape against
   [`schemas/plugin-manifest.schema.json`](../schemas/plugin-manifest.schema.json).
6. Run semantic validation from
   [Runtime Plugin Discovery](runtime-plugin-discovery.md).
7. Verify platform, Core version, protocol version, and transport
   compatibility.
8. Resolve package-local runtime commands and schemas.
9. Compute manifest and package digests.
10. Write or update the VoidB-owned install record.
11. Atomically replace the active plugin directory.
12. Re-run discovery and mark the candidate `available`, `incompatible`, or
    `invalid`.
13. Optionally run `voidb.health` before reporting a healthy install.

If any validation step fails, the active plugin directory must remain
unchanged.

## Update Flow

Updates are installs over an existing plugin ID with stricter checks:

1. The new package manifest ID must match the installed plugin ID.
2. Core must validate the new package before replacing the active directory.
3. The old active directory should be moved to
   `.voidb-install/<plugin-id>/previous/<version>/` before activation.
4. Profiles, credential references, local plugin data, and sync state are not
   deleted by update.
5. If discovery or health check fails after activation, VoidB should offer a
   rollback to the previous version.
6. Downgrades require an explicit flag because profile schemas or data formats
   may have migrated forward.

Updates must not silently loosen profile policy, destructive-operation
defaults, or credential requirements. If the new manifest changes required
secret classes or declared permissions, Core should surface that as a
compatibility review item before activation.

## Disable, Enable, And Uninstall

Disabling a plugin:

- records disabled state in the install record;
- removes the candidate from normal invocation eligibility;
- does not delete package files;
- does not delete profiles, credential references, saved data, or audit
  records;
- should cause profiles for that plugin to appear as unavailable, not corrupt.

Enabling a plugin:

- clears disabled state;
- re-runs manifest validation and compatibility checks;
- should fail if the active package no longer passes validation.

Uninstalling a plugin:

- removes the active package directory after confirmation;
- keeps profiles and credential records by default;
- may offer a separate `--remove-plugin-data` option later;
- must not remove audit records;
- should preserve enough install metadata to explain why profiles are
  unavailable.

The default uninstall policy should be conservative because deleting a plugin
does not mean the user intended to delete connection profiles or credentials.

## Version Compatibility

Compatibility has separate axes:

| Axis | Source | Install behavior |
|---|---|---|
| Manifest schema | `plugin.toml` shape and schema URI | Reject packages that Core cannot parse or validate. |
| Process protocol | `protocol_version` | Reject unsupported major versions before launch. |
| Core requirement | `requirements.voidb_core` | Reject packages whose semver constraint excludes the running Core. |
| Platform | `requirements.platforms` | Reject packages that do not support the current OS. |
| Package version | `version` | Record for diagnostics, update ordering, and rollback. |
| Profile schema | `connections.profile_schema` | Validate for profile CRUD and migration planning. |

The plugin package version does not by itself prove profile compatibility.
Profile migration requires an explicit migration model in a later slice. Until
that exists, updates that change profile schemas should be treated as
compatibility-sensitive. Existing config compatibility is handled by the
explicit migration workflow in
[Profile Migration](profile-migration.md).

## CLI Shape

The CLI exposes installation as local package management:

```bash
vb plugin install ./mysql-1.2.3.voidb-plugin.tar.zst --format json
vb plugin install ./target/plugin/mysql --format json
vb plugin update mysql --from ./mysql-1.2.4.voidb-plugin.tar.zst --format json
vb plugin update --all --dry-run --format json
vb plugin update --all --yes --format json
vb plugin disable mysql --format json
vb plugin enable mysql --format json
vb plugin uninstall mysql --keep-profiles --format json
```

`vb plugin update --all` compares every installed plugin in the install root
against the registry and updates only the outdated ones. It prints the plan
(installed version → target version), requires a typed `UPDATE` confirmation
on a terminal or `--yes` for scripts, honors `--dry-run`, and continues past
per-plugin failures with a structured summary (`updated`, `up_to_date`,
`failed`).

JSON output should include:

- plugin ID;
- installed version;
- candidate state;
- manifest path;
- install root;
- warnings;
- structured errors when validation, compatibility, or filesystem operations
  fail.

Human table output is a convenience layer only. Agents should branch on stable
JSON fields and structured error categories.

## Release Automation

The official plugin registry updates itself when a plugin is released; nobody
re-runs `update-registry.yml` by hand.

- Every official plugin repository's `release.yml` ends its publish job with a
  `repository_dispatch(plugin_released)` step targeting the core repository
  (`limmytian/voidb`) with `client_payload.plugin_id` and
  `client_payload.release = v<version>`.
- Core's `.github/workflows/update-registry.yml` listens for that event,
  resolves the version from `client_payload.release`, and stages only the
  released plugin's archives (per-plugin sync) via
  `scripts/download-release-plugins.py --plugin-id`, merging the entry into
  `registry/index.json`. A manual `workflow_dispatch` with an empty
  `plugin_id` still performs a full sync of all 14 plugins at the given
  version.
- Cross-repository dispatch cannot use the plugin repo's `GITHUB_TOKEN`; each
  plugin repository requires a `DISPATCH_TOKEN` secret (a PAT with repo scope
  on the core repository). The dispatch step fails loudly on a non-2xx
  response and prints the manual recovery command
  (`gh workflow run update-registry.yml -R limmytian/voidb -f version=... -f
  plugin_id=...`).
- `.github/workflows/templates/plugin-release.yml` carries the same step so
  future plugin repositories inherit the automation.

## Trust And Security

User-installed plugins are local code execution. VoidB should describe them as
trusted local extensions, not as sandboxed code.

Security rules:

- Never pass plaintext credentials through manifests, package metadata,
  environment variables, or installer logs.
- Redact source locators if they contain tokens or credentials.
- Do not run package build scripts during install.
- Do not execute plugin binaries during validation unless the user requested a
  post-install health check.
- Do not install from the current working directory implicitly.
- Prefer package-local executables under `bin/`.
- Require explicit development roots through `VOIDB_PLUGIN_PATH`.
- Keep future signature or provenance verification as an additive gate over the
  same local package format.

## Sync And Distribution Boundary

Sync may record installed plugin identity and compatibility metadata, but it
must not sync plugin binaries.

Synced profiles that reference a missing plugin should remain visible with an
unavailable status. The receiving device can then install a compatible plugin
locally. This keeps sync independent from distribution and avoids turning sync
into a hidden marketplace.

Future hosted catalogs should produce package metadata and package bytes that
flow through the same local install pipeline. Catalogs may help users discover
plugins, but they must not define the runtime, profile, credential, or
capability contracts.

## Non-Goals

- Designing a hosted marketplace, ratings system, billing flow, or remote
  entitlement system.
- Sandboxing user-installed plugin code.
- Syncing plugin binaries across devices.
- Migrating built-in Rust plugin factories to process plugins in one step.
- Defining profile schema migration machinery.
- Adding dynamic library loading as a plugin ABI.
