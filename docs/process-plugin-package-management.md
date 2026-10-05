# Process Plugin Package Management

VoidB process-plugin packages are installed from local directories or local
archives. There is no hosted marketplace in this model.

## Package Inputs

Valid inputs are:

- an unpacked directory containing exactly one plugin directory;
- an unpacked directory whose root contains exactly one `plugin.toml`;
- a `.tar` or `.tar.zst` archive with the same shape.

The recommended archive suffix is:

```bash
<plugin-id>-<version>.voidb-plugin.tar.zst
```

Packages must include `plugin.toml`, every referenced JSON schema, and
package-local runtime executables under `bin/`. Packages must not contain
plaintext credentials, saved profiles, tokens, local config files, synced data,
or device state.

## Commands

Install a package:

```bash
voidb plugin install ./redis-0.1.0.voidb-plugin.tar.zst --format json
voidb plugin install ./target/process-plugins/redis --format table
```

Update an installed package:

```bash
voidb plugin update redis --from ./redis-0.2.0.voidb-plugin.tar.zst --format json
voidb plugin update redis --from ./redis-0.1.0.voidb-plugin.tar.zst --allow-downgrade --format json
```

Lifecycle operations:

```bash
voidb plugin disable redis --format json
voidb plugin enable redis --format json
voidb plugin uninstall redis --keep-profiles --format json
```

`--install-root <path>` is available for explicit local testing and automation.
Without it, commands use the normal writable user install root. `VOIDB_PLUGIN_PATH`
remains a read-only development discovery override and is not mutated by
install commands.

## JSON Contract

Successful package operations return the standard plugin envelope:

```json
{
  "ok": true,
  "schema_version": 1,
  "command": "plugin",
  "data": {
    "operation": "install",
    "plugin": {
      "id": "redis",
      "installed_version": "0.2.0",
      "candidate_state": "available",
      "manifest_path": ".../redis/plugin.toml",
      "active_plugin_dir": ".../redis",
      "install_root": ".../plugins",
      "install_record_path": ".../.voidb-install/redis/install.toml",
      "manifest_digest": "sha256:...",
      "package_digest": "sha256:..."
    }
  },
  "warnings": []
}
```

Errors are structured with `category`, `code`, `message`, `details`,
`retryable`, and `redaction`. Agents should branch on `code`, not on human text.

## Install Records And Rollback Metadata

VoidB writes install records under:

```text
<install-root>/.voidb-install/<plugin-id>/install.toml
```

The record stores the package version, manifest digest, package digest, redacted
source locator, enabled state, compatibility status, and previous-version
metadata. Updates preserve the old active package under:

```text
<install-root>/.voidb-install/<plugin-id>/previous/<version>/
```

Downgrades are blocked unless `--allow-downgrade` is passed. Updates that
change profile schema references, declared secret classes, or capability
permissions emit review warnings.

## Disable, Enable, And Uninstall

`disable` sets `enabled = false` in the install record. Runtime discovery reads
that record and reports the candidate as `disabled`, so the plugin no longer
acts as an available process-plugin candidate.

`enable` sets `enabled = true` and requires the active package directory to
still exist.

`uninstall` removes the active package directory and sets `enabled = false`.
Connection profiles, credentials, plugin data, install metadata, and historical
audit records are preserved by default. This keeps uninstall conservative and
avoids deleting user-owned state.

## Security Boundaries

The installer validates packages without executing plugin binaries. It rejects:

- archive paths with absolute, parent-directory, or prefix components;
- symlinks that escape the package root;
- world-writable executable files;
- packages that do not resolve runtime commands from package-local `bin/`
  outside explicit development roots;
- manifests, schemas, protocol versions, transports, platforms, or Core version
  requirements that fail process-plugin discovery validation.

Source locators are redacted before they are written to install records or
agent-facing package summaries. Install commands require an explicit source
path; they do not implicitly install from the current working directory.

## Validation

Focused process-plugin package-management changes should run:

```bash
cargo test -p voidb-core process_plugin
cargo test -p voidb-core process_plugin_runtime
cargo test -p voidb-cli plugin
cargo test -p voidb-cli invoke
cargo clippy -p voidb-core --all-targets --no-deps
cargo clippy -p voidb-cli --all-targets --no-deps
git diff --check
```
