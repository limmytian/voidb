# Data Inspector CLI-First Decisions

This note records the Requirement 76 slice decision for data inspector TUIs and
the Requirement 77 rebaseline that removed the old compatibility UI.
It covers MySQL, PostgreSQL, SQLite, DuckDB, Redis, MongoDB, and
Elasticsearch after the plugin-owned CLI-launched TUI pilots.

The decision is intentionally narrower than the older
Database TUI Downscoping Plan: it decides what
to do in the plugin-owned TUI migration, not whether interactive data
inspection is valuable forever.

## Decision

Data inspector workflows are CLI-first unless a plugin-specific proposal passes
the Requirement 83 data inspector TUI acceptance gate below.

Do not build standalone `mysql tui`, `postgres tui`, `sqlite tui`,
`duckdb tui`, `redis tui`, `mongodb tui`, or `elasticsearch tui` commands
unless a follow-up task supplies plugin-specific evidence that the human
workflow beats the existing CLI/capability path and can meet the standalone TUI
evidence gate.

Existing router-hosted data inspector UIs were removed in Requirement 77:

- MySQL, PostgreSQL, SQLite, DuckDB, and Redis no longer have legacy database
  browser/table/query-editor adapters.
- The default TUI must show CLI/capability guidance for SQL and Redis profiles.
- MongoDB and Elasticsearch should not gain new router-hosted inspector
  behavior. Their release-candidate path is generic invoke plus plugin CLI.
- New data read, search, mutation, import, export, and diagnostics behavior
  belongs in services, capabilities, and plugin CLI commands first.

Docs and release notes should point users to the CLI/capability path. There is
no legacy data-inspector feature gate.

## Requirement 83 TUI Acceptance Gate

This gate fails closed. A data inspector is `CLI-only` until a decision record
shows that every hard gate below is satisfied or intentionally deferred with a
`later candidate` outcome.

| Gate | Required evidence before implementation starts |
|---|---|
| Named human workflow | The proposal names a concrete operator workflow, starting state, success state, and why repeated CLI or `voidb invoke` commands are materially worse. Generic "browse data" does not pass. |
| Capability-backed bounded reads | The read path is implemented in services/capabilities first, with explicit limit/page controls, deterministic continuation where the target supports it, target timeout behavior, and structured result summaries. |
| Pagination and large-result safety | The TUI can render the first page without loading unbounded rows, keys, documents, hits, or aggregates into memory. Empty, partial, and truncated states are visible. |
| Redaction and error shape | Profile refs, target labels, stderr, panic output, logs, and audit records must not expose plaintext secrets or decrypted config. Errors keep validation/auth/permission/transport/timeout/plugin/target categories. |
| Mutation safety | The first viewport is read-only. Mutations require capability policy, dry-run or preview where supported, non-default acknowledgement, typed confirmation for high-blast-radius actions, and redacted audit summaries. |
| Fixture and target-error evidence | Local fixture or deterministic transcript coverage exists for normal, empty, target-error, timeout/disconnected, and destructive-confirmation states. Fixture errors must prove the TUI remains responsive. |
| PTY lifecycle evidence | PTY tests cover first frame, normal quit, terminal cleanup, resize or compact fallback, and raw-mode cleanup when raw input is used. |
| No legacy dependency | The command is plugin-owned and CLI-launched, uses service/capability operations, and does not depend on removed router-hosted factories, shared legacy data widgets, or shell-owned plugin UI state. |

Decision records use these states:

| State | Meaning for data inspectors |
|---|---|
| CLI-only | CLI/capability commands are the supported surface. A TUI must not be advertised. |
| Later candidate | A named workflow may justify a TUI later, but at least one hard gate or evidence item is missing. |
| Accepted pilot | The hard gates are satisfied enough to build one bounded plugin-owned pilot with PTY and fixture evidence in the same requirement. |
| Retained | A pilot has completed the standalone TUI UX acceptance review and is supported as a product surface. |

Every plugin decision should record:

- plugin and profile type;
- selected state;
- named workflow or explicit reason no workflow passes;
- capability/CLI commands that cover the supported path;
- missing gates, if the state is `later candidate`;
- validation commands and evidence docs;
- migration note explaining that removed router-hosted UI is not restored.

## Evidence Matrix

| Plugin | Current CLI and capability coverage | Release or test evidence | Migration decision |
|---|---|---|---|
| MySQL | `mysql query`, `mysql databases`, `mysql tables`, `mysql describe`; `mysql.query`, `mysql.exec`, `mysql.tables`, `mysql.describe_table`, and `mysql.explain` follow the shared SQL contract. | MySQL Release Readiness records local fixture-backed SQL capability evidence. `mysql_capabilities_conform_to_shared_sql_contract` exists in `crates/plugins/voidb-plugin-mysql/src/capabilities.rs`. | CLI-first. Do not create `mysql tui` until a future plugin-owned TUI proposal passes the rebuild gate. |
| PostgreSQL | `postgres query`, `postgres databases`, `postgres tables`, `postgres describe`; shared SQL capabilities include query, exec, metadata, and explain. | `postgres_capabilities_conform_to_shared_sql_contract` and redaction/policy tests exist in `crates/plugins/voidb-plugin-postgres/src/capabilities.rs`. Live PostgreSQL remains opt-in per [SQL Plugin Migration Guide](sql-plugin-migration-guide.md). | CLI-first. No standalone inspector until PostgreSQL has the same fixture and table-page evidence as MySQL. |
| SQLite | `sqlite query`, `sqlite tables`, `sqlite describe`; local SQL capabilities include query, exec, metadata, explain, bounded output, and dry-run policy. | SQLite is the reference local SQL path in [Agent Capability Examples](agent-capability-examples.md) and validates the shared SQL contract in `crates/plugins/voidb-plugin-sqlite/src/capabilities.rs`. | CLI-first. No standalone inspector until table-page and mutation-preview capabilities are the contract. |
| DuckDB | `duckdb query`, `duckdb tables`, `duckdb describe`, `duckdb schemas`, import/export and extension CLI commands; shared SQL capabilities include query, exec, metadata, and explain. | DuckDB and Redis Release Readiness records DuckDB beta certification, bounded output, mutation gates, and native build-cost constraints. | CLI-first. Do not add standalone DuckDB TUI in this migration; native build cost and analytics repeatability favor CLI/capability workflows. |
| Redis | `redis keys`, `redis get`, `redis set`, `redis del`, `redis ttl`, `redis type`, `redis info`, `redis exec`; capabilities provide bounded key scans, split read-only TTL/destructive expire, live observation, dry-run writes, and redacted target errors. | DuckDB and Redis Release Readiness records Redis release-candidate capability evidence and local fixture smoke. | CLI-first. No standalone `redis tui` until key browsing has a plugin-owned design and PTY evidence. |
| MongoDB | `mongodb dbs`, `collections`, `stats`, `find`, `count`, `insert`, `update`, `delete`, `aggregate`, `indexes`, `create-index`, `exec`, `test`; capabilities cover bounded read paths and dry-run mutation/raw-command gates. | MongoDB Release Readiness records local fixture-backed readiness, redaction checks, and run-scoped fixture cleanup. | CLI-first. Do not keep adding router-hosted MongoDB inspector behavior; a future `mongodb tui` must be a thin document triage app over capabilities. |
| Elasticsearch | `elasticsearch health`, `nodes`, `indices`, `search`, `get`, `count`, `mapping`, `api`; capabilities cover cluster/index/document reads and dry-run raw API gates. | Elasticsearch Release Readiness records local fixture-backed readiness and endpoint/auth redaction evidence. | CLI-first. Do not keep adding router-hosted Elasticsearch inspector behavior; a future `elasticsearch tui` must prove search triage value over CLI. |

## Requirement 83 SQL And Redis Decision Records

Validation baseline on 2026-07-07:

- `target/debug/voidb-cli invoke list mysql --format json`
- `target/debug/voidb-cli invoke list postgres --format json`
- `target/debug/voidb-cli invoke list sqlite --format json`
- `target/debug/voidb-cli invoke list duckdb --format json`
- `target/debug/voidb-cli invoke list redis --format json`

The SQL plugins all advertised `describe_table`, `exec`, `explain`, `query`,
and `tables`. Redis advertised `del`, `exec`, `get`, `info`, `keys`, `set`,
and `ttl`.

| Plugin | Reviewed human workflow | Gate result | Requirement 83 decision |
|---|---|---|---|
| MySQL | Networked schema lookup, table listing, one-off query/explain, and explicit SQL execution during incident triage. | Shared SQL CLI/capabilities cover the supported read/query path. The workflow is not plugin-unique enough to justify a standalone TUI before shared table-page and mutation-preview capabilities exist. | `CLI-only`. Do not add `mysql tui`; keep Connection Manager guidance pointed at `voidb-cli mysql ...` and `voidb-cli invoke run mysql.<capability> ...`. |
| PostgreSQL | Networked schema lookup, table listing, one-off query/explain, and explicit SQL execution. | Shared SQL CLI/capabilities cover the supported path. PostgreSQL lacks a plugin-specific inspector UX brief and retained fixture/transcript evidence that beats repeated CLI commands. | `CLI-only`. Do not add `postgres tui`; future work should first strengthen fixture-backed SQL capability evidence. |
| SQLite | Local file triage: list tables, inspect schema, run bounded read queries, and possibly inspect a small table page during debugging. | The workflow is plausible because local SQLite is deterministic and fixture-friendly, but the gate is incomplete: no dedicated table-page/table-count capability contract, no row-mutation preview, and no PTY evidence. | `Later candidate`, shipping as `CLI-only`. Do not add `sqlite tui` in Requirement 83; reconsider only after shared table-page and mutation safety capabilities exist. |
| DuckDB | Analytics file triage, schema lookup, repeatable query execution, import/export, and extension diagnostics. | CLI/capability workflows are more repeatable for analytics and import/export. Native build cost and extension variability make it a poor first inspector pilot. | `CLI-only`. Do not add `duckdb tui`; keep analytics workflows scriptable through CLI/capabilities. |
| Redis | Prefix triage: scan bounded keys, inspect type/TTL/value, review server info, and perform explicit single-key writes/deletes. | Bounded key/read/write capabilities and local fixture evidence exist, so the workflow is a possible future pilot. The gate is still incomplete because there is no plugin-owned UX brief, no PTY lifecycle evidence, and no destructive-confirmation transcript for bulk or irreversible key operations. | `Later candidate`, shipping as `CLI-only`. Do not add `redis tui` in Requirement 83; require a focused key-triage pilot proposal before implementation. |

This slice does not accept any SQL or Redis pilot. No `voidb-cli <plugin> tui`
command should be added for these plugins from this requirement, and no default
TUI path should advertise one.

## Requirement 83 Document And Search Decision Records

Validation baseline on 2026-07-07:

- `target/debug/voidb-cli invoke list mongodb --format json`
- `target/debug/voidb-cli invoke list elasticsearch --format json`

MongoDB advertised `aggregate`, `collections`, `count`, `create_index`,
`databases`, `delete`, `diagnostics`, `find`, `indexes`, `insert`,
`run_command`, and `update`. Elasticsearch advertised `count`, `diagnostics`,
`get`, `health`, `indices`, `mapping`, `nodes`, `raw_api`, and `search`.

| Plugin | Reviewed human workflow | Gate result | Requirement 83 decision |
|---|---|---|---|
| MongoDB | Document triage: list databases/collections, inspect bounded find and aggregate results, check indexes, preview targeted document mutations, and avoid raw command mistakes. | Capability and fixture evidence are strong enough to make this a future candidate: reads are bounded, aggregation rejects mutating stages, mutations support dry-run, and target errors are redacted. The TUI gate is still incomplete because there is no plugin-owned document-triage UX brief, PTY evidence, first-frame/error transcripts, or TUI mutation confirmation design. | `Later candidate`, shipping as `CLI-only`. Do not add `mongodb tui` in Requirement 83; a future pilot must be a thin document triage app over capabilities, not a restored browser. |
| Elasticsearch | Search triage: inspect cluster/index health, run bounded search/count, preview one document, inspect mapping summaries, and avoid unsafe raw API calls. | Capability and fixture evidence are strong enough to make this a future candidate: search is bounded, mappings omit raw bodies, raw API is destructive-gated, and endpoint/auth errors are redacted. The TUI gate is still incomplete because there is no search-triage UX brief, PTY evidence, disconnected-target transcript, or destructive raw API confirmation transcript. | `Later candidate`, shipping as `CLI-only`. Do not add `elasticsearch tui` in Requirement 83; a future pilot must prove search triage value over CLI and generic invoke. |

This slice does not accept a document/search pilot. MongoDB and Elasticsearch
remain release-candidate capability surfaces, not retained TUI surfaces.

## Requirement 83 No-Pilot Decision

Requirement 83 does not accept or build a data inspector TUI pilot.

Final states:

| State | Plugins |
|---|---|
| `CLI-only` | MySQL, PostgreSQL, DuckDB |
| `Later candidate`, shipping as `CLI-only` | SQLite, Redis, MongoDB, Elasticsearch |
| `Accepted pilot` | None |
| `Retained` | None |

No plugin passed every hard gate at the same time:

- no plugin has a completed plugin-owned data-inspector UX brief with PTY
  lifecycle evidence;
- SQL table-page/table-count and row-mutation preview contracts are not yet a
  shared release surface;
- Redis, MongoDB, and Elasticsearch have strong capability and fixture
  evidence, but lack a bounded TUI interaction design and destructive
  confirmation transcripts;
- MySQL, PostgreSQL, and DuckDB do not currently show plugin-specific human
  workflow evidence that beats repeated CLI or generic invoke commands.

User-facing migration note:

- use `voidb-cli <plugin> ...` commands and
  `voidb-cli invoke list|describe|run <plugin>...` for data inspection;
- use the Connection Manager as a profile catalog and command guidance surface;
- do not document or advertise `mysql tui`, `postgres tui`, `sqlite tui`,
  `duckdb tui`, `redis tui`, `mongodb tui`, or `elasticsearch tui`;
- treat any future data inspector as new plugin-owned work with fresh evidence,
  not as a restoration of removed router-hosted UI.

## Default UI Expectations

The default TUI should not advertise missing standalone data inspector commands.
For these profiles it should show command guidance, not open a router-hosted
browser:

```text
voidb invoke describe <plugin>.<capability> --format json
voidb invoke run <plugin>.<capability> --profile <name> --input-json '<json>'
voidb <plugin> <cli-command> ...
```

No compatibility build is shipped for the old data inspector UI.

## Standalone TUI Rebuild Gate

A future data inspector may become a plugin-owned TUI only after it supplies all
of this evidence:

1. Capability coverage for the data operation, including bounded reads,
   pagination, structured target errors, redaction, dry-run or confirmation for
   mutations, and audit summaries.
2. Plugin-specific UX brief that beats repeated CLI commands for a named human
   workflow. Generic "browse data" is not enough.
3. `voidb <plugin> tui --profile <name>` or an equivalent packaged command
   with secret-free
   `--format json` preflight and no plaintext config in args, env, stderr,
   panic output, or audit records.
4. PTY lifecycle tests for first frame, resize or stable viewport, graceful
   exit, raw-mode cleanup if used, and at least one disconnected or target-error
   state.
5. Fixture-backed or deterministic transcript evidence for the primary
   workflow and destructive-action safety.
6. A statement that the feature is new plugin-owned UI work and does not depend
   on removed router-hosted factories, tests, or shared legacy widgets.

Until those gates are met, data inspector work should continue in services,
capabilities, CLI commands, and release evidence.

## Follow-Up Removal Rules

Future data inspector UI work may start only when these conditions hold:

- CLI/capability commands named above are still registered in `voidb-cli`.
- Default TUI tests continue to pass without loading database inspector plugin
  factories.
- Release docs say data surfaces are CLI-first unless a new plugin-owned TUI
  has passed the rebuild gate.

These rules let VoidB retire router-hosted data inspectors without pretending a
new standalone TUI exists.
