# SQL Agent Parity Matrix

This matrix is the canonical comparison for the built-in PostgreSQL, MySQL,
SQLite, and DuckDB Agent surfaces. The shared wire contract is documented in
[sql-capability-contract.md](sql-capability-contract.md).

## Capability Parity

| Surface | PostgreSQL | MySQL / MariaDB | SQLite | DuckDB |
|---|---|---|---|---|
| `query`, `explain`, `exec` | Yes | Yes | Yes | Yes |
| `catalogs` | Databases + schemas | Databases; schemas alias databases | One local database | One local database |
| `tables`, `describe_table` | Yes | Yes | Yes | Yes |
| Normalized column and relation metadata | Contract v2 | Contract v2 | Contract v2 | Contract v2 |
| Cursor pagination | Offset cursor, max 1,000 | Offset cursor, max 1,000 | Offset cursor, max 1,000 | Offset cursor, max 1,000 |
| `export_query` | CSV / JSON / JSONL | CSV / JSON / JSONL | CSV / JSON / JSONL | CSV / JSON / JSONL |
| `import_plan`, `import_apply` | Append / abort | Append / abort | Append / abort | Append / abort |
| Persistent query/transaction session | Yes | Yes | Yes, via `SyncWorker` | Yes, via `SyncWorker` |

All four export handlers accept exactly one read-oriented statement and execute
a database-side `limit + 1` probe page. This keeps driver materialization
bounded even when the source relation has millions of rows. Local destinations
use approved roots and atomic no-replace writes.

All four import handlers read only from an explicitly approved local root.
CSV and JSONL are decoded one bounded page at a time. JSON arrays are limited
to 16 MiB. Apply calls insert at most 1,000 rows in one transaction and abort
the whole batch on the first row or statement error.

## Persistent Transaction Contract

Every persistent SQL session call returns:

```json
{
  "transaction": {
    "state": "idle",
    "isolation": "default",
    "savepoint_depth": 0,
    "savepoints": [],
    "nested_transactions": "savepoints_only",
    "auto_rollback_on_error": true,
    "auto_rollback_on_close": true,
    "last_transition": "none",
    "recovery": "none",
    "dialect": "sqlite"
  }
}
```

The common rules are:

- `BEGIN` is valid only while idle. A second `BEGIN` is rejected; nested work
  uses `SAVEPOINT`, `ROLLBACK TO SAVEPOINT`, and `RELEASE SAVEPOINT`.
- `COMMIT` and full `ROLLBACK` require an active transaction.
- Savepoint names use ASCII letters, digits, and underscores. This avoids
  dialect-specific quoted-name ambiguity.
- A statement error inside a transaction triggers an immediate best-effort
  full rollback. Successful cleanup returns the session to `idle` with
  `last_transition = "auto_rollback_error"`. Failed cleanup makes the state
  `failed` and requires a full `ROLLBACK`.
- Cancel and close always make a final best-effort rollback before releasing
  the owned connection.
- Isolation is selected in the session-open input, for example
  `{"isolation":"serializable"}`. Session SQL that changes isolation directly
  is rejected so reported state cannot diverge from target state.

## Isolation Support

| Isolation | PostgreSQL | MySQL / MariaDB | SQLite | DuckDB |
|---|---|---|---|---|
| `default` | Yes | Yes | Yes | Yes |
| `read_uncommitted` | No; target treats it as read committed | Yes | Yes, `PRAGMA read_uncommitted` | No |
| `read_committed` | Yes | Yes | No | No |
| `repeatable_read` | Yes | Yes | No | No |
| `serializable` | Yes | Yes | Yes, `read_uncommitted = false` | Yes, engine default |

Unsupported levels fail session open with `session.policy_denied`; VoidB does
not silently map them to a different level.

## Intentional Engine Exceptions

- MySQL schemas and databases are the same catalog scope. `catalogs` preserves
  the shared arrays but emits a warning and leaves the schema array empty.
- SQLite and DuckDB do not expose server database/schema switching. Their
  catalog scope is `local_database`.
- Row-count metadata is exact only when the target service returns an exact
  count. PostgreSQL estimates are normalized to non-negative unsigned values.
- Network-engine transaction journeys require configured fixtures. The shared
  state-machine tests run without a server, while PostgreSQL/MySQL fixture
  suites validate their retained single-connection services when those
  fixtures are enabled.

## Validation Coverage

The requirement-wide focused suite covers:

- shared schema and metadata conformance for all four capability catalogs;
- normalized typing, discovery, result paging, and million-row export bounds;
- scoped import/export authorization and no-replace local writes;
- import transaction batches and row-error rollback;
- shared begin/commit/rollback/savepoint state transitions and isolation
  validation;
- SQLite and DuckDB retained-connection state plus rollback on error,
  cancellation, and close;
- CLI discovery count and JSON contract stability.
