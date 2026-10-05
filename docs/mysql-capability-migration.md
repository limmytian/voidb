# MySQL Capability Migration

MySQL is the first networked SQL plugin migrated onto the shared SQL
capability contract. The implementation keeps driver calls inside
`voidb-plugin-mysql/src/service/` and exposes agent-facing behavior through
`mysql.query`, `mysql.exec`, `mysql.tables`, and `mysql.describe_table`.

## Profile Shape

MySQL profiles use `MySqlConfig::profile_schema()` as the canonical shape for
host, port, username, optional database, TLS mode, charset, pool size, timeout,
and credential refs. The legacy encrypted `password` field remains supported
for stored `ConnectionConfig` compatibility, but new capability-first profile
surfaces should prefer `credential_refs`.

Diagnostics must not echo decrypted `plugin_config`. Capability errors use a
shape-only profile summary for details and put redacted target diagnostics under
`CapabilityError.target`.

## Capability Behavior

- `mysql.query` accepts read-oriented SQL only and supports `InvocationControls`
  pagination over returned rows.
- `mysql.exec` is destructive, supports dry-run without target mutation, and
  returns affected-row summaries when executed.
- `mysql.tables` and `mysql.describe_table` require a database from input or the
  profile config before connecting.
- Connection, auth, TLS, timeout, unavailable target, and database-selection
  failures are mapped through `CapabilityError`.

## Fast Fixture Gate

Run this gate for MySQL capability changes:

```bash
cargo test -p voidb-plugin-mysql
cargo test -p voidb-cli invoke
cargo test -p voidb-core sql_contract
git diff --check
```

The plugin test suite includes deterministic fixtures for schema discovery,
policy rejection, dry-run behavior, database validation, redaction, and
unavailable-target diagnostics. These do not require a live MySQL server.

## Fixture-Backed Live Smoke

The preferred live smoke uses the shared local fixture harness and does not
require external credentials:

```bash
scripts/mysql-fixture-smoke.sh \
  --report target/tmp/mysql-fixture-smoke-evidence.md
```

The fixture-backed readiness decision is recorded in
MySQL Release Readiness.

The older ignored test remains available when an explicitly provisioned MySQL
target is already running.

Example local container:

```bash
docker run --rm --name voidb-mysql-smoke \
  -e MYSQL_ALLOW_EMPTY_PASSWORD=yes \
  -e MYSQL_DATABASE=voidb_smoke \
  -p 3307:3306 \
  mysql:8
```

In another shell, run:

```bash
VOIDB_MYSQL_TEST_HOST=127.0.0.1 \
VOIDB_MYSQL_TEST_PORT=3307 \
VOIDB_MYSQL_TEST_USER=root \
VOIDB_MYSQL_TEST_PASSWORD='' \
VOIDB_MYSQL_TEST_DATABASE=voidb_smoke \
cargo test -p voidb-plugin-mysql --test capability_fixtures \
  live_mysql_query_metadata_smoke -- --ignored
```

The live smoke verifies a simple query and metadata discovery against the
configured database. Keep additional destructive or schema-mutating live checks
behind explicit tests and isolated disposable databases.
