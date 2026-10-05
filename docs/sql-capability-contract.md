# Shared SQL Capability Contract

This document defines the shared SQL capability contract for VoidB plugins. It
builds on the capability model and the SQLite/Redis first protocol pair:

- [Capability Core Model](capability-core-model.md)
- [Capability Discovery and Invocation CLI Contract](capability-cli.md)
- [Agent-Friendly Execution Controls](agent-friendly-execution-controls.md)
- [Agent Capability Examples](agent-capability-examples.md)

The contract is intentionally dialect-aware but not dialect-owned. SQLite is the
local reference implementation. MySQL is the first networked SQL validation
target. PostgreSQL and DuckDB should converge on the same shapes instead of
creating plugin-specific table browser semantics.

## Scope

The first shared SQL contract covers these capability IDs:

| Capability | Purpose | Destructive | Dry-run |
|---|---|---:|---:|
| `query` | Execute read-oriented SQL and return bounded row sets. | No | No |
| `explain` | Inspect a safe query plan for one read-oriented statement. | No | No |
| `exec` | Execute SQL that may mutate schema or data. | Yes | Yes |
| `catalogs` | List databases and schemas with explicit engine support metadata. | No | No |
| `tables` | List table and view metadata. | No | No |
| `describe_table` | Describe columns, indexes, and foreign keys for one relation. | No | No |
| `table_page` | Fetch a bounded page from one relation. | No | No |
| `table_count` | Count rows for one relation and filter shape. | No | No |
| `row_mutation_plan` | Validate and preview insert/update/delete/upsert work. | Yes | Yes |
| `row_mutation_apply` | Apply an acknowledged row mutation plan. | Yes | Yes |
| `import_plan` | Validate an import mapping and impact before loading data. | Yes | Yes |
| `import_apply` | Apply an acknowledged import plan. | Yes | Yes |
| `export_query` | Export a bounded or streamed query/table result. | No | No |

Plugin-qualified capability IDs remain plugin-owned: `sqlite.query`,
`mysql.query`, `duckdb.describe_table`, and so on. Shared behavior lives in
input/output shape, policy, summary, pagination, redaction, and error handling.

The built-in PostgreSQL, MySQL, SQLite, and DuckDB plugins are expected to
conform to these shared names, schema shapes, pagination fields, mutation
gates, and explain safety rules. See the canonical
[SQL Agent parity matrix](sql-agent-parity.md) for implemented engine support
and intentional exceptions.

## Common Rules

SQL capabilities must follow these rules:

- Row and catalog responses use `contract_version = 2`. Version 2 is additive:
  legacy `tables`, string `views`, `ColumnInfo` compatibility fields, and
  offset cursors remain available while normalized metadata is exposed.
- TUI code must not be the protocol boundary. Handlers call service-layer direct
  methods or process-plugin equivalents.
- Saved profiles and credential refs stay behind Core. Capability input must
  not contain plaintext passwords, connection URLs, or decrypted
  `plugin_config`.
- Large row, table, or metadata outputs must be bounded through
  `InvocationControls.page`, plugin-defined filters, or truncation metadata.
- Cursors are opaque strings owned by the plugin. Agents pass them back
  unchanged.
- Dry-run output must not mutate the target and must not echo sensitive SQL
  literal values unless the caller already supplied them in non-secret input and
  the output needs them for disambiguation.
- Statement, target, transport, and permission failures use `CapabilityError`.
  Failed SQL statements do not appear as successful `statements` items.
- Human-readable messages may change. Agents branch on stable fields:
  `status`, `output_summary`, `page.next_cursor`, `error.category`, and
  `error.code`.

## `query`

`query` executes read-oriented SQL. A plugin may use a dialect-aware classifier
or a conservative allow-list. If the SQL may mutate data or schema, `query`
must fail before target execution with:

```json
{
  "category": "policy",
  "code": "policy.destructive_requires_exec_capability",
  "details": { "capability_id": "query" },
  "target": null,
  "redaction": "not_required"
}
```

Input schema:

```json
{
  "type": "object",
  "required": ["sql"],
  "properties": {
    "sql": { "type": "string", "minLength": 1 }
  },
  "additionalProperties": false
}
```

Output schema:

```json
{
  "type": "object",
  "required": [
    "statements",
    "row_limit",
    "row_count",
    "source_row_count",
    "truncated",
    "cursor",
    "next_cursor"
  ],
  "properties": {
    "statements": { "type": "array" },
    "row_limit": { "type": "integer", "minimum": 1 },
    "row_count": { "type": "integer", "minimum": 0 },
    "source_row_count": { "type": "integer", "minimum": 0 },
    "truncated": { "type": "boolean" },
    "cursor": { "type": ["string", "null"] },
    "next_cursor": { "type": ["string", "null"] },
    "database": { "type": "string" },
    "schema": { "type": "string" }
  },
  "additionalProperties": false
}
```

`output_summary` must include:

```json
{
  "statement_count": 1,
  "row_count": 100,
  "source_row_count": 250,
  "truncated": true,
  "next_cursor": "opaque"
}
```

When more rows are available, the invocation result must also set
`page.next_cursor`.

## `explain`

`explain` inspects the target query plan for exactly one read-oriented
statement. It is read-only by default and rejects mutation, session,
maintenance, transaction-control, unknown, and multi-statement input before
opening a target connection.

Input schema is the same as `query`, plus optional `analyze`:

```json
{
  "type": "object",
  "required": ["sql"],
  "properties": {
    "sql": { "type": "string", "minLength": 1 },
    "analyze": { "type": "boolean", "default": false }
  },
  "additionalProperties": false
}
```

Built-in SQL plugins reject `analyze = true` with
`policy.explain_analyze_disabled`, because analyze-style plans may execute
target work. A future plugin may expose an explicitly destructive
`explain_analyze` capability or require `exec`-level policy gates.

Successful output uses the same bounded statement result fields as `query`,
plus:

```json
{
  "analyze": false,
  "format": "rows",
  "dialect": "sqlite",
  "explained_statement_count": 1
}
```

`output_summary` should include the same explain metadata without raw SQL text.

## `exec`

`exec` runs SQL that may mutate schema or data. It is destructive by default
and must require policy acknowledgement or dry-run through the generic invoke
path.

Input schema is the same as `query`.

Successful non-dry-run output uses the same `statements`, row-bound, and cursor
fields as `query`, plus:

```json
{
  "rows_affected": 2,
  "mutation_gate": {
    "destructive": true,
    "acknowledged": true,
    "dry_run": false,
    "dialect": "postgres",
    "statement_count": 1,
    "transaction_control": false,
    "transaction_policy": "allowed_with_invocation_acknowledgement"
  }
}
```

`output_summary` must include `rows_affected` when the target reports affected
rows and should include the same redacted `mutation_gate` metadata. If the
target cannot report affected rows, use `null` rather than guessing.

Dry-run output uses this minimum shape:

```json
{
  "dry_run": true,
  "would_execute": true,
  "destructive": true,
  "operation": "exec"
}
```

Plugins may add redacted validation details, such as statement count or
classifier output. They must not open a target connection solely to satisfy a
dry-run unless that target-side validation is explicitly documented and has no
side effects.

The built-in PostgreSQL, MySQL, SQLite, and DuckDB `exec` handlers include
`statement_count`, `classifications`, `checks`, and `mutation_gate` in dry-run
output. The classifier is heuristic and never echoes raw SQL text or literal
values; agents should branch on `classification`, `reason_code`, and
`mutation_gate.transaction_control` rather than parsing SQL from output.

## Statement Classification And Policy

SQL plugins should classify statement intent before choosing a capability path
or constructing audit summaries. Classification is intentionally conservative:
unknown statements are treated as destructive.

Statement classification labels:

| Label | Meaning | Allowed in `query` |
|---|---|---:|
| `read` | `select`, safe `with`, safe metadata reads, or dialect read-only forms. | Yes |
| `explain` | Query plan inspection that does not execute mutations. | Yes |
| `write` | `insert`, `update`, `delete`, `merge`, `replace`, or bulk load. | No |
| `schema` | `create`, `alter`, `drop`, `truncate`, `rename`, indexes, constraints. | No |
| `transaction` | `begin`, `commit`, `rollback`, savepoints, locks. | No |
| `session` | `set`, `use`, pragma/session options that change execution context. | No |
| `maintenance` | Vacuum, analyze, repair, optimize, checkpoint, or similar commands. | No |
| `unknown` | Parser could not prove a read-only statement. | No |

`query` may reject a full SQL string if any statement is not read-oriented.
`exec` accepts all classifications subject to policy. `exec` remains
destructive even when a specific statement is classified as read, because the
capability grants broader target authority.

Dry-run classification output should use this shape:

```json
{
  "dry_run": true,
  "would_execute": true,
  "destructive": true,
  "operation": "exec",
  "statement_count": 2,
  "classifications": [
    {
      "index": 0,
      "classification": "schema",
      "confidence": "heuristic",
      "reason_code": "statement.create_table"
    }
  ],
  "checks": []
}
```

Rules:

- `confidence` is `parser`, `heuristic`, `target`, or `unknown`.
- `reason_code` is stable and non-localized.
- Dry-run must not include raw secret-bearing literals in classification
  details.
- A plugin may include target-side validation warnings only when validation is
  known to have no side effects.

## Mutation Planning

Row mutation capabilities exist so lightweight UI handoffs and agents can
replace table-grid internals without constructing ad hoc SQL.

### `row_mutation_plan`

`row_mutation_plan` validates one insert/update/delete/upsert request and
returns a redacted plan. It must not mutate the target.

Input shape:

```json
{
  "table": "users",
  "schema": "public",
  "operation": "update",
  "keys": { "id": 1 },
  "values": { "name": "Ada" },
  "expected": { "updated_at": "2026-07-04T00:00:00Z" },
  "returning": ["id", "name"]
}
```

Output shape:

```json
{
  "dry_run": true,
  "would_execute": true,
  "destructive": true,
  "operation": "row_update",
  "plan_id": "optional-plugin-plan-id",
  "target": { "table": "users", "schema": "public" },
  "statement_count": 1,
  "estimated_rows_affected": 1,
  "sql_preview": "update public.users set name = ? where id = ?",
  "parameters_summary": {
    "key_count": 1,
    "value_count": 1,
    "redaction": "applied"
  },
  "checks": [
    { "code": "primary_key_present", "ok": true }
  ],
  "warnings": []
}
```

Rules:

- `sql_preview` must use placeholders or redacted literals.
- `parameters_summary` describes shape only. It must not echo secret-looking
  values.
- `expected` supports optimistic concurrency checks. Plugins that cannot
  enforce it must return a validation error rather than silently ignoring it.
- Delete and replace operations are destructive even when the estimated impact
  is zero.

### `row_mutation_apply`

`row_mutation_apply` applies a mutation plan or repeats the same mutation input
with explicit acknowledgement. It is destructive and supports dry-run.

Input shape:

```json
{
  "plan_id": "optional-plugin-plan-id",
  "table": "users",
  "schema": "public",
  "operation": "update",
  "keys": { "id": 1 },
  "values": { "name": "Ada" },
  "returning": ["id", "name"]
}
```

Successful output:

```json
{
  "ok": true,
  "operation": "row_update",
  "rows_affected": 1,
  "returned_rows": [
    { "id": 1, "name": "Ada" }
  ]
}
```

Policy rules:

- Core must require destructive acknowledgement or dry-run according to the
  same policy path as `exec`.
- Applying a stale or unknown `plan_id` returns `conflict.plan_stale` or
  `validation.plan_not_found`.
- Returned rows must follow the shared column and row-value rules.

## Import And Export Policy

Import and export workflows must not smuggle filesystem or credential behavior
into SQL plugins. PostgreSQL, MySQL, SQLite, and DuckDB use Core's
`LocalPathScope`: callers grant an absolute `local_root` plus a root-relative
`local_path`, links and escapes are rejected, source identity is revalidated
during reads, and exports use atomic no-replace writes. Raw roots and paths are
never returned; results expose only an invocation-scoped `local_scope_id`.

### `import_plan`

`import_plan` validates an import mapping and reports expected impact. It must
not mutate the target.

Input shape:

```json
{
  "table": "users",
  "schema": "public",
  "format": "csv",
  "mode": "append",
  "columns": ["id", "name"],
  "has_header": true,
  "local_root": "/approved/import-root",
  "local_path": "users.csv"
}
```

Output shape:

```json
{
  "dry_run": true,
  "would_execute": true,
  "destructive": true,
  "operation": "import_plan",
  "format": "csv",
  "table": "users",
  "columns": ["id", "name"],
  "row_count": 100,
  "source_file_bytes": 16384,
  "truncated": true,
  "cursor": null,
  "next_cursor": "100",
  "transaction_scope": "batch",
  "row_error_policy": "abort",
  "local_scope_id": "local-scope:invoke-123",
  "checks": [],
  "warnings": []
}
```

The shipped v2 contract intentionally starts with one conservative mode:

| Mode | Meaning | Policy |
|---|---|---|
| `append` | Insert new rows only. | Destructive. |

`import_apply` uses the same target and mapping shape, requires explicit
destructive acknowledgement, and returns `rows_inserted`. CSV and JSONL sources
are decoded one bounded page at a time; JSON arrays are capped at 16 MiB and
larger inputs must use JSONL. Each apply page is one transaction with
`row_error_policy = "abort"`, a default batch of 100 rows, and a hard maximum of
1,000 rows. Callers continue with `page.next_cursor`.

### `export_query`

`export_query` is read-only but must remain bounded or streamed. It should use
the same SQL input as `query`, plus output format options:

```json
{
  "sql": "select id, name from users order by id",
  "format": "csv",
  "include_header": true,
  "local_root": "/approved/export-root",
  "local_path": "users-0001.csv"
}
```

The handler accepts exactly one read-oriented statement and wraps it in a
dialect-specific `LIMIT limit + 1 OFFSET cursor` query. This makes the database
driver materialize at most one bounded probe page even for million-row source
queries. An omitted destination returns a bounded inline preview and honors
`max_output_bytes`; an approved destination writes the current page and never
replaces an existing file.

```json
{
  "format": "csv",
  "row_count": 100,
  "bytes": 2048,
  "truncated": true,
  "next_cursor": "opaque",
  "destination_written": true,
  "local_scope_id": "local-scope:invoke-123",
  "preview": null,
  "progress": {
    "rows_completed": 100,
    "bytes_completed": 2048,
    "terminal": false
  }
}
```

## Statement Results

`statements` is an ordered array of statement result objects. Each item has a
`kind`.

### Select Result

```json
{
  "kind": "select",
  "columns": [],
  "rows": [],
  "row_count": 100,
  "source_row_count": 250,
  "truncated": true
}
```

Rules:

- `row_count` is the number of rows included in this response for this
  statement.
- `source_row_count` is the best available count from the executed statement
  before response paging or truncation.
- `truncated` is true when this response omits rows available after the cursor.
- Multi-statement outputs apply pagination across select rows in statement
  order unless a plugin documents a stronger dialect-specific cursor.

### Affected Result

```json
{
  "kind": "affected",
  "rows_affected": 2
}
```

### Empty Result

```json
{
  "kind": "empty"
}
```

Statement-level target failures must fail the invocation with
`status = "failed"` and a structured `CapabilityError`. Do not return
`{ "kind": "error" }` inside a successful invocation.

## Columns

Column metadata in row-producing statements and `describe_table` uses one
shared shape. Fields are optional when the target cannot provide them cheaply,
but `name` must always be present.

```json
{
  "name": "customer_id",
  "source_name": "customer_id",
  "table": "orders",
  "schema": "public",
  "database": "sales",
  "ordinal": 1,
  "data_type": "integer",
  "native_type": "INTEGER",
  "nullable": false,
  "default": null,
  "primary_key": true,
  "auto_increment": true,
  "max_length": null,
  "numeric_precision": 64,
  "numeric_scale": 0,
  "comment": null,
  "dialect": {}
}
```

Rules:

- Version 2 preserves `is_primary_key`, `default_value`, `max_length`, and
  `extra` for existing consumers while adding normalized aliases.
- `name` is the row-object key. If a result has duplicate target column names,
  the plugin must disambiguate `name` and may preserve the target name in
  `source_name`.
- `data_type` is a normalized label. `native_type` preserves the target type.
- `dialect` may contain non-secret plugin-specific metadata. It must never
  contain credentials, connection strings, host secrets, or raw driver debug
  objects.

Normalized `data_type` labels:

| Label | Meaning |
|---|---|
| `text` | Character or string value. |
| `integer` | Signed or unsigned integer. |
| `float` | Floating point value. |
| `decimal` | Exact numeric value. |
| `boolean` | Boolean value. |
| `date` | Calendar date. |
| `time` | Time of day. |
| `datetime` | Date and time, with or without timezone. |
| `binary` | Binary data. |
| `json` | JSON or document value. |
| `uuid` | UUID value. |
| `unknown` | Target type could not be normalized. |

## Row Values

Rows are JSON objects keyed by `columns[].name`.

Value rules:

- SQL NULL maps to JSON `null`.
- Booleans map to JSON booleans.
- Integers that fit safely in JSON consumers may map to JSON numbers.
- Large integers, decimals, dates, times, datetimes, UUIDs, and binary values
  should map to strings unless the plugin can preserve type safely.
- Binary values should be base64 strings with column metadata
  `data_type = "binary"`.
- Driver-specific objects must be converted to JSON primitives or redacted
  structured values before leaving the plugin.

## Pagination

SQL row-producing capabilities use `InvocationControls.page`.

Default row limits are plugin policy, but a plugin must publish its maximum in
the output schema or capability documentation. The SQLite reference currently
uses a default row limit of 100 and a maximum of 1000.

Result fields:

| Field | Meaning |
|---|---|
| `contract_version` | Stable result contract version; currently `2`. |
| `row_limit` | Effective row limit for this response. |
| `batch_size` | Alias for the effective response batch size. |
| `row_count` | Number of rows included across select statements. |
| `source_row_count` | Best available count before response paging or truncation. |
| `truncated` | True when more rows are available. |
| `cursor` | Cursor requested by the caller, or null for the first page. |
| `next_cursor` | Opaque cursor for the next page, or null when terminal. |
| `warnings` | Stable warning objects; an empty array means no degraded behavior. |

The invocation result must set `page.next_cursor` whenever output
`next_cursor` is non-null.

## Table Paging And Counting

`table_page` and `table_count` are the shared replacement contract for
heavyweight table-grid internals. They read table data through service-layer
capabilities, not through TUI-only state.

### Shared Table Scope

Both capabilities use the same table scope and filter primitives:

```json
{
  "table": "orders",
  "schema": "public",
  "database": "sales",
  "columns": ["id", "customer_id", "total"],
  "filters": [
    { "column": "status", "op": "eq", "value": "open" }
  ],
  "order_by": [
    { "column": "id", "direction": "asc" }
  ],
  "include_row_identity": true
}
```

Filter operators:

| Operator | Meaning |
|---|---|
| `eq` / `ne` | Equality or inequality. |
| `lt` / `lte` / `gt` / `gte` | Ordered comparison. |
| `is_null` / `is_not_null` | Null checks; omit `value`. |
| `like` / `not_like` | Dialect string pattern. |
| `in` / `not_in` | `value` is an array. |
| `between` | `value` is a two-item array. |

Rules:

- `columns` omitted means plugin default columns, usually all visible columns.
- `order_by` omitted means target default order. Agents should not assume
  stable pagination without an explicit order.
- Values in `filters` are caller-supplied input. Audit records should summarize
  filter shape and counts instead of copying raw values.
- Plugins must quote identifiers through structured APIs or dialect-safe
  helpers. They must not string-concatenate untrusted identifiers.

### `table_page`

`table_page` returns one bounded page of rows from a relation.

Input schema:

```json
{
  "type": "object",
  "required": ["table"],
  "properties": {
    "table": { "type": "string", "minLength": 1 },
    "schema": { "type": "string" },
    "database": { "type": "string" },
    "columns": { "type": "array", "items": { "type": "string" } },
    "filters": { "type": "array" },
    "order_by": { "type": "array" },
    "include_row_identity": { "type": "boolean", "default": true }
  },
  "additionalProperties": false
}
```

Output shape:

```json
{
  "table": "orders",
  "schema": "public",
  "database": "sales",
  "columns": [],
  "rows": [],
  "row_identity": [
    { "pk": { "id": 1 } }
  ],
  "row_limit": 100,
  "row_count": 100,
  "truncated": true,
  "cursor": null,
  "next_cursor": "opaque",
  "order_by": [
    { "column": "id", "direction": "asc" }
  ],
  "filters_summary": {
    "filter_count": 1,
    "redaction": "applied"
  }
}
```

Rules:

- `rows` follow the shared row-value rules.
- `columns` follow the shared column rules and describe the returned row keys.
- `row_identity` is optional but recommended for table-grid replacement. It
  should use primary keys or target-specific stable row locators.
- `row_identity` must not include hidden secret columns.
- `next_cursor` is opaque and must also be copied to `page.next_cursor`.
- `filters_summary` and `order_by` help audit and replay without exposing
  sensitive filter values.

`output_summary` should include:

```json
{
  "table": "orders",
  "row_count": 100,
  "truncated": true,
  "next_cursor": "opaque",
  "filter_count": 1
}
```

### `table_count`

`table_count` returns a count for the same table/filter shape used by
`table_page`.

Input schema is the same as `table_page` without `columns`, `order_by`, and
`include_row_identity`.

Output shape:

```json
{
  "table": "orders",
  "schema": "public",
  "database": "sales",
  "count": 1234,
  "exact": true,
  "filtered": true,
  "filters_summary": {
    "filter_count": 1,
    "redaction": "applied"
  }
}
```

Rules:

- `exact = true` means the plugin ran an exact count for the requested filter.
- `exact = false` means `count` is an estimate. Include
  `dialect.estimate_source` when available.
- If exact counting would exceed timeout or target policy, return
  `timeout.target` or a structured warning rather than silently switching to an
  estimate.
- Agents should pair `table_count` with `table_page` only when they use the
  same table, schema, database, and filters.

## Metadata Capabilities

### `catalogs`

`catalogs` is the live discovery operation for databases and schemas. It is
separate from static capability discovery and accepts the shared `pattern` and
`include_system` filters. `InvocationControls.page` bounds the combined
catalog result and `page.next_cursor` mirrors output `next_cursor`.

```json
{
  "contract_version": 2,
  "scope": {
    "kind": "schema",
    "database": "sales",
    "schema": "public"
  },
  "databases": [
    {
      "name": "sales",
      "kind": "database",
      "database": null,
      "current": true,
      "system": false
    }
  ],
  "schemas": [
    {
      "name": "public",
      "kind": "schema",
      "database": "sales",
      "current": true,
      "system": false
    }
  ],
  "next_cursor": null,
  "warnings": []
}
```

Engine behavior is intentional:

- PostgreSQL returns databases and user schemas.
- MySQL returns databases and reports that its schema namespace is the database
  namespace.
- SQLite returns the active connection as the `main` database/schema alias.
- DuckDB currently exposes the active database and `main` schema and reports
  the limited attached-catalog scope as a warning.

### `tables`

`tables` lists relation metadata for the current profile scope. Networked SQL
plugins may use profile defaults for database/schema selection. Plugins that
support cross-database browsing should keep broad discovery bounded and expose
database/schema filters in a later contract slice.

Input schema:

```json
{
  "type": "object",
  "properties": {
    "database": { "type": "string" },
    "schema": { "type": "string" },
    "pattern": { "type": "string" },
    "include_system": { "type": "boolean", "default": false }
  },
  "additionalProperties": false
}
```

Output schema:

```json
{
  "type": "object",
  "required": [
    "contract_version",
    "tables",
    "views",
    "relations",
    "next_cursor",
    "warnings"
  ],
  "properties": {
    "tables": { "type": "array" },
    "views": { "type": "array" },
    "relations": { "type": "array" },
    "next_cursor": { "type": ["string", "null"] }
  },
  "additionalProperties": false
}
```

Relation summary shape:

```json
{
  "name": "orders",
  "relation_type": "table",
  "table_type": "base_table",
  "database": "sales",
  "schema": "public",
  "rows": 1234,
  "comment": null,
  "dialect": {}
}
```

Rules:

- `tables` contains relations with `relation_type = "table"`.
- `views` contains relations with `relation_type = "view"`.
- The compatibility `tables` and string `views` arrays are retained. New
  consumers should use `relations`, whose entries always include
  `relation_type`, scope, row estimate, comment, and dialect metadata.
- `pattern` is a case-insensitive name filter. `include_system` defaults to
  false. Catalog output is bounded with `InvocationControls.page`.
- `rows` is an estimate unless the plugin documents that it is exact.
- System relations are excluded unless `include_system = true`.
- The compatibility `views` output remains a list of names. The normalized
  relation objects live in `relations`.

`output_summary` should include `table_count`, `view_count`, and `next_cursor`
when more metadata is available.

### `describe_table`

`describe_table` describes one relation.

Input schema:

```json
{
  "type": "object",
  "required": ["table"],
  "properties": {
    "table": { "type": "string", "minLength": 1 },
    "schema": { "type": "string" },
    "database": { "type": "string" }
  },
  "additionalProperties": false
}
```

Output schema:

```json
{
  "type": "object",
  "required": ["table", "columns", "indexes", "foreign_keys"],
  "properties": {
    "table": { "type": "string" },
    "relation": { "type": "object" },
    "columns": { "type": "array" },
    "indexes": { "type": "array" },
    "foreign_keys": { "type": "array" },
    "dialect": { "type": "object" }
  },
  "additionalProperties": false
}
```

Index shape:

```json
{
  "name": "orders_pkey",
  "columns": ["id"],
  "unique": true,
  "primary": true,
  "index_type": "btree",
  "dialect": {}
}
```

Foreign key shape:

```json
{
  "name": "orders_customer_id_fkey",
  "columns": ["customer_id"],
  "referenced_table": "customers",
  "referenced_schema": "public",
  "referenced_columns": ["id"],
  "on_update": "no_action",
  "on_delete": "cascade",
  "dialect": {}
}
```

`output_summary` should include `column_count`, `index_count`, and
`foreign_key_count`.

## Structured Target Errors

SQL target failures must use `CapabilityErrorCategory::TargetSystem`.

Example:

```json
{
  "category": "target_system",
  "code": "sqlite.statement_failed",
  "message": "SQLite target operation failed.",
  "details": null,
  "target": {
    "system": "sqlite",
    "code": null,
    "message": "no such table: users"
  },
  "retryable": false,
  "redaction": "not_required"
}
```

Rules:

- `target.system` is the plugin ID or target system label.
- `code` is stable enough for agents to branch on, and may be plugin-specific.
- `target.message` is diagnostic text only. Redact connection URLs,
  credentials, SQL literals that contain secrets, host secrets, and raw driver
  debug objects before returning it.
- Network transport failures still use `target_system` when the SQL target
  rejected or failed the operation. Core/plugin process failures use
  `transport`, `plugin`, or `unavailable` categories as appropriate.

## Conformance Direction

SQLite already anchors the first contract with bounded `query`/`exec` outputs,
dry-run metadata, structured target errors, and schema metadata. Follow-up
slices should align MySQL, PostgreSQL, and DuckDB with this document, then add
shared conformance tests so each SQL plugin proves:

- discovery schemas include the shared required fields
- read queries are bounded and paginated
- mutating SQL is rejected from `query`
- `exec` is destructive and supports dry-run
- `tables` and `describe_table` return stable metadata shapes
- `table_page` and `table_count` use the same filter scope and bounded output
- row mutation and import capabilities expose safe dry-run plans before apply
- target errors are structured and redacted
