# SQL Plugin Migration Guide

This guide explains how SQLite, MySQL, PostgreSQL, and DuckDB should adopt the
[Shared SQL Capability Contract](sql-capability-contract.md) without moving SQL
semantics back into TUI-only code.

## Migration Order

1. Keep all driver calls inside the plugin service layer.
2. Expose capability metadata for `query`, `exec`, `tables`, and
   `describe_table`.
3. Run the reusable SQL capability conformance helper against the capability
   catalog.
4. Implement invocation handlers through service direct mode or a process-plugin
   equivalent.
5. Add target-behavior tests for pagination, dry-run, destructive policy,
   metadata, redaction, and target errors.
6. Add `table_page`, `table_count`, row mutation, import, and export
   capabilities only after the base query/metadata contract is stable.

## Reusable Conformance Check

Rust SQL plugins can validate the minimum shared metadata contract with:

```rust
use voidb_core::validate_sql_capability_contract;

#[test]
fn capabilities_conform_to_shared_sql_contract() {
    validate_sql_capability_contract("sqlite", &sqlite_capabilities()).unwrap();
}
```

The helper checks the shared capability catalog and schema surface only. Plugins
still need plugin-local tests for actual target behavior, such as SQL execution,
metadata loading, network failures, and credential redaction.

## Capability Handlers

Handlers should follow this pattern:

```text
CapabilityInvocation
  validate plugin_id and capability_id
  validate direct-call input fields
  enforce capability-specific policy
  call service direct mode
  map service result into shared output shape
  map target failures into CapabilityError
```

Do not import driver crates from TUI code. Do not duplicate table browser logic
inside handlers. If a TUI needs SQL data, it should call capability/service
boundaries or remain behind an explicit legacy UI feature.

## Plugin Notes

### SQLite

SQLite is the reference local SQL implementation.

- Keep using `SqliteService::new_direct` for capability invocation.
- Preserve bounded `query`/`exec` output and `InvocationControls.page` support.
- Keep temporary database tests for deterministic fast coverage.
- Use SQLite-specific metadata only in non-secret `dialect` fields.

### MySQL

MySQL is the first networked SQL migration target.

- Build capabilities on top of the MySQL service layer, not the legacy TUI
  browser/table/editor state.
- Use `MySqlConfig::profile_schema()` for profile fields and
  `MySqlService::new_direct_capability` for capability entrypoints.
- Profile metadata should select host, port, database, TLS mode, charset, pool
  size, and credential refs; passwords stay behind credential refs or legacy
  redacted config adapters.
- Fast tests should cover schema discovery, input validation, dry-run, redacted
  target errors, and unavailable-service behavior without requiring a live
  server.
- Live MySQL tests should be opt-in and container-friendly. See
  [MySQL Capability Migration](mysql-capability-migration.md).

### PostgreSQL

PostgreSQL now starts the same baseline shared SQL contract as MySQL:
`postgres.query`, `postgres.exec`, `postgres.tables`, and
`postgres.describe_table`.

- Keep driver calls inside `PostgresService::new_direct` and the existing
  service modules.
- Keep the connected database fixed by the profile. PostgreSQL cannot switch
  databases on an existing connection, so invocation input should not expose a
  per-call database override.
- Use optional `schema` input for metadata capabilities and default it to
  `public`.
- Normalize PostgreSQL-specific types into shared `data_type` labels and
  preserve native names in `native_type`.
- Treat session changes, search path changes, DDL, COPY imports, and
  maintenance commands as destructive unless proven otherwise.
- Fast tests should cover shared contract validation, read-query policy,
  `exec` dry-run without connecting, legacy `postgresql` profile aliasing in
  generic invoke, and target diagnostic redaction. Live PostgreSQL checks should
  remain opt-in until a disposable service fixture is added.

### DuckDB

DuckDB now mirrors SQLite for the baseline local direct-mode SQL capabilities
while preserving its own service constraints.

- Keep `!Send` or native-driver constraints behind service boundaries.
- Use temporary databases for fast tests.
- Treat file import/export paths as brokered inputs or future artifact sinks,
  not arbitrary plugin-side filesystem writes.
- Avoid mixing heavy native build churn into unrelated contract changes.

DuckDB local analytics capability path:

1. Keep `duckdb.query`, `duckdb.exec`, `duckdb.tables`, and
   `duckdb.describe_table` through `DuckDbService::new_direct`, matching the
   SQLite output and pagination shape.
2. Restrict the baseline profile to the configured database path or `:memory:`.
   Do not allow capability input to open arbitrary paths, write exports, or
   attach additional databases.
3. Keep file-ingest features such as `read_csv`, `read_parquet`, `COPY`, and
   `EXPORT DATABASE` behind explicit future file grants or artifact-sink
   capabilities. They should not be smuggled into default `duckdb.query`.
4. Mark `duckdb.exec` destructive with dry-run. Treat `ATTACH`, `COPY`, `EXPORT`,
   `INSTALL`, `LOAD`, and filesystem-affecting pragmas as destructive or
   blocked until policy gates exist.
5. Add focused tests only when touching DuckDB because bundled DuckDB builds are
   heavy. Use temporary databases and avoid making DuckDB part of unrelated
   fast gates.

## Testing Checklist

Every SQL plugin migration should include:

- capability discovery includes the required shared capability IDs
- `validate_sql_capability_contract` passes
- `query` rejects mutating SQL before target execution
- `query` returns bounded row output with summary fields
- `exec` is destructive and supports dry-run without target mutation
- `tables` returns table and view metadata
- `describe_table` returns columns, indexes, and foreign keys
- target errors use `target_system` with redacted diagnostic text
- audit summaries describe shape, counts, and refs rather than raw secrets

## Release Gate

For the shared SQL contract itself, run:

```bash
cargo test -p voidb-core sql_contract
cargo test -p voidb-plugin-sqlite sqlite_capabilities_conform_to_shared_sql_contract
git diff --check
```

When a networked SQL plugin adopts the contract, add that plugin's fast tests
and any opt-in live-service smoke command documented for the plugin.

For MySQL capability changes, run:

```bash
cargo test -p voidb-plugin-mysql
cargo test -p voidb-cli invoke
cargo test -p voidb-core sql_contract
git diff --check
```

Optional live smoke is documented in
[MySQL Capability Migration](mysql-capability-migration.md) and must remain
outside the default fast gate.

For PostgreSQL capability changes, run:

```bash
cargo test -p voidb-plugin-postgres capabilities
cargo test -p voidb-cli invoke
cargo test -p voidb-core sql_contract
git diff --check
```

Until an opt-in PostgreSQL service fixture exists, this gate verifies catalog
conformance, policy and dry-run behavior, profile aliasing, and redaction
without requiring a live server.

For DuckDB capability changes, run:

```bash
cargo test -p voidb-plugin-duckdb
cargo test -p voidb-cli invoke
cargo test -p voidb-core sql_contract
git diff --check
```
