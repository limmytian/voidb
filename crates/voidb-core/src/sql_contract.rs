//! Shared SQL capability contract conformance helpers.
//!
//! These helpers validate the metadata and schema surface that SQL plugins
//! should expose before plugin-specific tests exercise target behavior.

use serde_json::{Map, Value, json};

use crate::capability::CapabilityDefinition;
use crate::database::types::{ColumnInfo, ForeignKeyInfo};

const REQUIRED_SQL_CAPABILITIES: &[&str] = &[
    "query",
    "explain",
    "exec",
    "catalogs",
    "tables",
    "describe_table",
    "export_query",
    "import_plan",
    "import_apply",
];

pub const SQL_DEFAULT_ROW_LIMIT: usize = 100;
pub const SQL_MAX_ROW_LIMIT: usize = 1_000;
pub const SQL_RESULT_CONTRACT_VERSION: u64 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqlDialect {
    DuckDb,
    MySql,
    Postgres,
    Sqlite,
}

impl SqlDialect {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DuckDb => "duckdb",
            Self::MySql => "mysql",
            Self::Postgres => "postgres",
            Self::Sqlite => "sqlite",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqlCatalogScope {
    LocalDatabase,
    Database,
    Schema,
}

impl SqlCatalogScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LocalDatabase => "local_database",
            Self::Database => "database",
            Self::Schema => "schema",
        }
    }

    fn input_field(self) -> Option<&'static str> {
        match self {
            Self::LocalDatabase => None,
            Self::Database => Some("database"),
            Self::Schema => Some("schema"),
        }
    }

    fn input_description(self) -> &'static str {
        match self {
            Self::LocalDatabase => "",
            Self::Database => {
                "Optional database override. Defaults to the profile database when present."
            }
            Self::Schema => "Optional schema override. Defaults to public.",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SqlInputScope {
    kind: SqlCatalogScope,
    required: bool,
}

impl SqlInputScope {
    pub const fn none() -> Self {
        Self {
            kind: SqlCatalogScope::LocalDatabase,
            required: false,
        }
    }

    pub const fn database(required: bool) -> Self {
        Self {
            kind: SqlCatalogScope::Database,
            required,
        }
    }

    pub const fn schema(required: bool) -> Self {
        Self {
            kind: SqlCatalogScope::Schema,
            required,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SqlIntrospectionSupport {
    pub supports_databases: bool,
    pub supports_schemas: bool,
    pub supports_views: bool,
    pub supports_row_counts: bool,
    pub supports_indexes: bool,
    pub supports_foreign_keys: bool,
    pub supports_constraints: bool,
    pub supports_comments: bool,
}

pub fn sql_text_input_schema(sql_description: &str, scope: SqlInputScope) -> Value {
    let mut required = vec!["sql".to_string()];
    let mut properties = Map::new();
    add_scope_input_property(&mut properties, &mut required, scope);
    properties.insert(
        "sql".into(),
        json!({
            "type": "string",
            "minLength": 1,
            "description": sql_description
        }),
    );

    object_schema(required, properties)
}

pub fn sql_explain_input_schema(scope: SqlInputScope) -> Value {
    let mut schema = sql_text_input_schema(
        "Read-oriented SQL statement to explain. Mutating statements and analyze execution are rejected by default.",
        scope,
    );
    if let Some(properties) = schema.get_mut("properties").and_then(Value::as_object_mut) {
        properties.insert(
            "analyze".into(),
            json!({
                "type": "boolean",
                "default": false,
                "description": "Request runtime analyze. Built-in SQL plugins reject true by default to avoid side effects."
            }),
        );
    }
    schema
}

pub fn sql_tables_input_schema(scope: SqlInputScope) -> Value {
    let mut required = Vec::new();
    let mut properties = Map::new();
    add_scope_input_property(&mut properties, &mut required, scope);
    add_catalog_filter_properties(&mut properties);

    object_schema(required, properties)
}

pub fn sql_catalogs_input_schema() -> Value {
    let mut properties = Map::new();
    add_catalog_filter_properties(&mut properties);
    object_schema(Vec::new(), properties)
}

pub fn sql_describe_table_input_schema(scope: SqlInputScope) -> Value {
    let mut required = vec!["table".to_string()];
    let mut properties = Map::new();
    add_scope_input_property(&mut properties, &mut required, scope);
    properties.insert("table".into(), json!({ "type": "string", "minLength": 1 }));

    object_schema(required, properties)
}

pub fn sql_statements_output_schema(include_exec_fields: bool) -> Value {
    let mut properties = Map::new();
    properties.insert(
        "statements".into(),
        json!({ "type": "array", "items": sql_statement_schema() }),
    );
    properties.insert(
        "row_limit".into(),
        json!({ "type": "integer", "minimum": 1, "maximum": SQL_MAX_ROW_LIMIT }),
    );
    properties.insert(
        "row_count".into(),
        json!({ "type": "integer", "minimum": 0 }),
    );
    properties.insert(
        "source_row_count".into(),
        json!({ "type": "integer", "minimum": 0 }),
    );
    properties.insert("truncated".into(), json!({ "type": "boolean" }));
    properties.insert("cursor".into(), json!({ "type": ["string", "null"] }));
    properties.insert("next_cursor".into(), json!({ "type": ["string", "null"] }));
    properties.insert(
        "contract_version".into(),
        json!({ "type": "integer", "const": SQL_RESULT_CONTRACT_VERSION }),
    );
    properties.insert(
        "batch_size".into(),
        json!({ "type": "integer", "minimum": 1, "maximum": SQL_MAX_ROW_LIMIT }),
    );
    properties.insert(
        "warnings".into(),
        json!({ "type": "array", "items": sql_warning_schema() }),
    );
    properties.insert("database".into(), json!({ "type": "string" }));
    properties.insert("schema".into(), json!({ "type": "string" }));

    let required = if include_exec_fields {
        properties.insert(
            "rows_affected".into(),
            json!({ "type": "integer", "minimum": 0 }),
        );
        properties.insert("dry_run".into(), json!({ "type": "boolean" }));
        properties.insert("would_execute".into(), json!({ "type": "boolean" }));
        properties.insert("destructive".into(), json!({ "type": "boolean" }));
        properties.insert("operation".into(), json!({ "type": "string" }));
        properties.insert(
            "statement_count".into(),
            json!({ "type": "integer", "minimum": 0 }),
        );
        properties.insert(
            "classifications".into(),
            json!({ "type": "array", "items": sql_statement_classification_schema() }),
        );
        properties.insert(
            "checks".into(),
            json!({ "type": "array", "items": sql_mutation_check_schema() }),
        );
        properties.insert("mutation_gate".into(), sql_mutation_gate_schema());
        Vec::new()
    } else {
        vec![
            "statements".to_string(),
            "row_limit".to_string(),
            "row_count".to_string(),
            "source_row_count".to_string(),
            "truncated".to_string(),
            "cursor".to_string(),
            "next_cursor".to_string(),
            "contract_version".to_string(),
            "batch_size".to_string(),
            "warnings".to_string(),
        ]
    };

    object_schema(required, properties)
}

pub fn sql_explain_output_schema() -> Value {
    let mut schema = sql_statements_output_schema(false);
    if let Some(properties) = schema.get_mut("properties").and_then(Value::as_object_mut) {
        properties.insert("analyze".into(), json!({ "type": "boolean" }));
        properties.insert("format".into(), json!({ "type": "string" }));
        properties.insert("dialect".into(), json!({ "type": "string" }));
        properties.insert(
            "explained_statement_count".into(),
            json!({ "type": "integer", "minimum": 1 }),
        );
    }
    if let Some(required) = schema.get_mut("required").and_then(Value::as_array_mut) {
        required.push(json!("analyze"));
        required.push(json!("format"));
        required.push(json!("dialect"));
        required.push(json!("explained_statement_count"));
    }
    schema
}

pub fn sql_tables_output_schema(scope: SqlCatalogScope) -> Value {
    let mut required = vec![
        "contract_version".to_string(),
        "scope".to_string(),
        "capabilities".to_string(),
        "tables".to_string(),
        "views".to_string(),
        "relations".to_string(),
        "next_cursor".to_string(),
        "warnings".to_string(),
    ];
    let mut properties = common_introspection_properties(scope);
    properties.insert(
        "tables".into(),
        json!({
            "type": "array",
            "items": {
                "type": "object",
                "required": ["name", "table_type", "rows"],
                "properties": {
                    "name": { "type": "string" },
                    "table_type": { "type": "string" },
                    "rows": { "type": ["integer", "null"], "minimum": 0 },
                    "comment": { "type": ["string", "null"] }
                },
                "additionalProperties": false
            }
        }),
    );
    properties.insert(
        "views".into(),
        json!({ "type": "array", "items": { "type": "string" } }),
    );
    properties.insert(
        "relations".into(),
        json!({ "type": "array", "items": sql_relation_schema() }),
    );
    properties.insert("next_cursor".into(), json!({ "type": ["string", "null"] }));
    properties.insert(
        "warnings".into(),
        json!({ "type": "array", "items": sql_warning_schema() }),
    );
    add_scope_required(scope, &mut required);

    object_schema(required, properties)
}

pub fn sql_catalogs_output_schema(scope: SqlCatalogScope) -> Value {
    let mut required = vec![
        "contract_version".to_string(),
        "scope".to_string(),
        "capabilities".to_string(),
        "databases".to_string(),
        "schemas".to_string(),
        "next_cursor".to_string(),
        "warnings".to_string(),
    ];
    let mut properties = common_introspection_properties(scope);
    properties.insert(
        "databases".into(),
        json!({ "type": "array", "items": sql_catalog_entry_schema("database") }),
    );
    properties.insert(
        "schemas".into(),
        json!({ "type": "array", "items": sql_catalog_entry_schema("schema") }),
    );
    properties.insert("next_cursor".into(), json!({ "type": ["string", "null"] }));
    properties.insert(
        "warnings".into(),
        json!({ "type": "array", "items": sql_warning_schema() }),
    );
    add_scope_required(scope, &mut required);
    object_schema(required, properties)
}

pub fn sql_describe_table_output_schema(scope: SqlCatalogScope) -> Value {
    let mut required = vec![
        "contract_version".to_string(),
        "scope".to_string(),
        "capabilities".to_string(),
        "table".to_string(),
        "columns".to_string(),
        "indexes".to_string(),
        "foreign_keys".to_string(),
        "constraints".to_string(),
        "warnings".to_string(),
    ];
    let mut properties = common_introspection_properties(scope);
    properties.insert("table".into(), json!({ "type": "string" }));
    properties.insert(
        "columns".into(),
        json!({ "type": "array", "items": sql_column_schema() }),
    );
    properties.insert(
        "indexes".into(),
        json!({
            "type": "array",
            "items": {
                "type": "object",
                "required": ["name", "columns", "unique", "index_type"],
                "properties": {
                    "name": { "type": "string" },
                    "columns": { "type": "array", "items": { "type": "string" } },
                    "unique": { "type": "boolean" },
                    "index_type": { "type": "string" }
                },
                "additionalProperties": false
            }
        }),
    );
    properties.insert("foreign_keys".into(), json!({ "type": "array" }));
    properties.insert(
        "constraints".into(),
        json!({
            "type": "array",
            "items": {
                "type": "object",
                "required": ["name", "constraint_type", "columns"],
                "properties": {
                    "name": { "type": "string" },
                    "constraint_type": { "type": "string" },
                    "columns": { "type": "array", "items": { "type": "string" } },
                    "referenced_table": { "type": ["string", "null"] },
                    "referenced_columns": {
                        "type": "array",
                        "items": { "type": "string" }
                    },
                    "on_update": { "type": ["string", "null"] },
                    "on_delete": { "type": ["string", "null"] }
                },
                "additionalProperties": false
            }
        }),
    );
    properties.insert(
        "warnings".into(),
        json!({ "type": "array", "items": sql_warning_schema() }),
    );
    add_scope_required(scope, &mut required);

    object_schema(required, properties)
}

pub fn sql_scope(kind: SqlCatalogScope, database: Option<&str>, schema: Option<&str>) -> Value {
    json!({
        "kind": kind.as_str(),
        "database": database,
        "schema": schema,
    })
}

pub fn sql_introspection_capabilities(support: SqlIntrospectionSupport) -> Value {
    json!({
        "supports_databases": support.supports_databases,
        "supports_schemas": support.supports_schemas,
        "supports_views": support.supports_views,
        "supports_row_counts": support.supports_row_counts,
        "supports_indexes": support.supports_indexes,
        "supports_foreign_keys": support.supports_foreign_keys,
        "supports_constraints": support.supports_constraints,
        "supports_comments": support.supports_comments,
    })
}

pub fn sql_column_metadata(column: &ColumnInfo, ordinal: usize, dialect: SqlDialect) -> Value {
    let native_type = column.data_type.clone();
    json!({
        "name": column.name,
        "source_name": column.name,
        "ordinal": ordinal,
        "data_type": sql_normalized_data_type(&native_type),
        "native_type": native_type,
        "nullable": column.nullable,
        "is_primary_key": column.is_primary_key,
        "primary_key": column.is_primary_key,
        "default_value": column.default_value,
        "default": column.default_value,
        "max_length": column.max_length,
        "extra": column.extra,
        "dialect": {
            "name": dialect.as_str()
        }
    })
}

pub fn sql_catalog_entry(
    name: &str,
    kind: &str,
    database: Option<&str>,
    current: bool,
    system: bool,
) -> Value {
    json!({
        "name": name,
        "kind": kind,
        "database": database,
        "current": current,
        "system": system,
    })
}

pub fn sql_relation(
    name: &str,
    relation_type: &str,
    table_type: &str,
    database: Option<&str>,
    schema: Option<&str>,
    rows: Option<u64>,
    comment: Option<&str>,
) -> Value {
    json!({
        "name": name,
        "relation_type": relation_type,
        "table_type": table_type,
        "database": database,
        "schema": schema,
        "rows": rows,
        "comment": comment,
        "dialect": {},
    })
}

pub fn sql_result_metadata(row_limit: usize) -> Value {
    json!({
        "contract_version": SQL_RESULT_CONTRACT_VERSION,
        "batch_size": row_limit,
        "warnings": [],
    })
}

pub fn sql_foreign_key_constraints(foreign_keys: &[ForeignKeyInfo]) -> Vec<Value> {
    foreign_keys
        .iter()
        .map(|foreign_key| {
            json!({
                "name": foreign_key.name,
                "constraint_type": "foreign_key",
                "columns": foreign_key.columns,
                "referenced_table": foreign_key.referenced_table,
                "referenced_columns": foreign_key.referenced_columns,
                "on_update": foreign_key.on_update,
                "on_delete": foreign_key.on_delete,
            })
        })
        .collect()
}

pub fn sql_allows_read_only_query(sql: &str, dialect: SqlDialect) -> bool {
    let classifications = sql_statement_classifications(sql, dialect);
    !classifications.is_empty()
        && classifications.iter().all(|classification| {
            matches!(
                classification.classification,
                SqlStatementIntent::Read | SqlStatementIntent::Explain
            )
        })
}

pub fn sql_statement_classification_values(sql: &str, dialect: SqlDialect) -> Vec<Value> {
    sql_statement_classifications(sql, dialect)
        .into_iter()
        .map(|classification| classification.into_value())
        .collect()
}

pub fn sql_statement_count(sql: &str, dialect: SqlDialect) -> usize {
    sql_statement_classifications(sql, dialect).len()
}

pub fn sql_explain_statement(sql: &str, dialect: SqlDialect) -> String {
    if first_keyword(sql).as_deref() == Some("explain") {
        return sql.trim().to_string();
    }

    match dialect {
        SqlDialect::DuckDb => format!("EXPLAIN {}", sql.trim()),
        SqlDialect::Sqlite => format!("EXPLAIN QUERY PLAN {}", sql.trim()),
        SqlDialect::MySql => format!("EXPLAIN FORMAT=JSON {}", sql.trim()),
        SqlDialect::Postgres => format!("EXPLAIN (FORMAT JSON) {}", sql.trim()),
    }
}

pub fn sql_mutation_preview(sql: &str, dialect: SqlDialect, acknowledged: bool) -> Value {
    let classifications = sql_statement_classifications(sql, dialect);
    let contains_transaction_control = classifications
        .iter()
        .any(|classification| classification.classification == SqlStatementIntent::Transaction);
    let checks = sql_mutation_checks(classifications.len(), contains_transaction_control);
    json!({
        "dry_run": true,
        "would_execute": true,
        "destructive": true,
        "operation": "exec",
        "statement_count": classifications.len(),
        "classifications": classifications.into_iter().map(SqlStatementClassification::into_value).collect::<Vec<_>>(),
        "checks": checks,
        "mutation_gate": sql_mutation_gate(
            sql,
            dialect,
            acknowledged,
            true,
        ),
    })
}

pub fn sql_mutation_gate(
    sql: &str,
    dialect: SqlDialect,
    acknowledged: bool,
    dry_run: bool,
) -> Value {
    let classifications = sql_statement_classifications(sql, dialect);
    let contains_transaction_control = classifications
        .iter()
        .any(|classification| classification.classification == SqlStatementIntent::Transaction);
    json!({
        "destructive": true,
        "acknowledged": acknowledged,
        "dry_run": dry_run,
        "dialect": dialect.as_str(),
        "statement_count": classifications.len(),
        "transaction_control": contains_transaction_control,
        "transaction_policy": "allowed_with_invocation_acknowledgement",
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SqlStatementIntent {
    Read,
    Explain,
    Write,
    Schema,
    Transaction,
    Session,
    Maintenance,
    Unknown,
}

impl SqlStatementIntent {
    fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Explain => "explain",
            Self::Write => "write",
            Self::Schema => "schema",
            Self::Transaction => "transaction",
            Self::Session => "session",
            Self::Maintenance => "maintenance",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SqlStatementClassification {
    index: usize,
    classification: SqlStatementIntent,
    reason_code: &'static str,
}

impl SqlStatementClassification {
    fn into_value(self) -> Value {
        json!({
            "index": self.index,
            "classification": self.classification.as_str(),
            "confidence": "heuristic",
            "reason_code": self.reason_code,
        })
    }
}

fn sql_statement_classifications(
    sql: &str,
    dialect: SqlDialect,
) -> Vec<SqlStatementClassification> {
    crate::sql_split::split_statements(sql)
        .into_iter()
        .enumerate()
        .map(|(index, statement)| {
            let (classification, reason_code) = classify_statement(statement, dialect);
            SqlStatementClassification {
                index,
                classification,
                reason_code,
            }
        })
        .collect()
}

fn classify_statement(statement: &str, dialect: SqlDialect) -> (SqlStatementIntent, &'static str) {
    let lowered = statement.to_ascii_lowercase();
    if matches!(dialect, SqlDialect::DuckDb) && contains_duckdb_external_access(&lowered) {
        return (
            SqlStatementIntent::Session,
            "statement.duckdb_external_access",
        );
    }

    match first_keyword(statement).as_deref() {
        Some("select") | Some("with") => (SqlStatementIntent::Read, "statement.read_query"),
        Some("explain") => (SqlStatementIntent::Explain, "statement.explain"),
        Some("values") if matches!(dialect, SqlDialect::DuckDb | SqlDialect::Postgres) => {
            (SqlStatementIntent::Read, "statement.values")
        }
        Some("show")
            if matches!(
                dialect,
                SqlDialect::DuckDb | SqlDialect::MySql | SqlDialect::Postgres
            ) =>
        {
            (SqlStatementIntent::Read, "statement.show")
        }
        Some("table") if matches!(dialect, SqlDialect::Postgres) => {
            (SqlStatementIntent::Read, "statement.postgres_table")
        }
        Some("describe") if matches!(dialect, SqlDialect::DuckDb | SqlDialect::MySql) => {
            (SqlStatementIntent::Read, "statement.describe")
        }
        Some("desc") if matches!(dialect, SqlDialect::MySql) => {
            (SqlStatementIntent::Read, "statement.describe")
        }
        Some("pragma") if matches!(dialect, SqlDialect::Sqlite) => {
            (SqlStatementIntent::Read, "statement.sqlite_pragma")
        }
        Some("insert") | Some("update") | Some("delete") | Some("merge") | Some("replace")
        | Some("copy") => (SqlStatementIntent::Write, "statement.write"),
        Some("create") | Some("alter") | Some("drop") | Some("truncate") | Some("rename") => {
            (SqlStatementIntent::Schema, "statement.schema")
        }
        Some("begin") | Some("commit") | Some("rollback") | Some("savepoint") | Some("release")
        | Some("lock") | Some("unlock") | Some("start") => {
            (SqlStatementIntent::Transaction, "statement.transaction")
        }
        Some("set") | Some("use") | Some("reset") | Some("attach") | Some("detach")
        | Some("load") | Some("install") => (SqlStatementIntent::Session, "statement.session"),
        Some("vacuum") | Some("analyze") | Some("repair") | Some("optimize")
        | Some("checkpoint") | Some("reindex") => {
            (SqlStatementIntent::Maintenance, "statement.maintenance")
        }
        Some(_) | None => (SqlStatementIntent::Unknown, "statement.unknown"),
    }
}

fn contains_duckdb_external_access(lowered: &str) -> bool {
    [
        "read_csv",
        "read_json",
        "read_parquet",
        "copy ",
        "attach ",
        "export ",
        "install ",
        "load ",
    ]
    .iter()
    .any(|fragment| lowered.contains(fragment))
}

fn first_keyword(statement: &str) -> Option<String> {
    let mut rest = statement.trim_start();
    loop {
        if let Some(after_line_comment) = rest.strip_prefix("--") {
            let (_, after_newline) = after_line_comment.split_once('\n')?;
            rest = after_newline.trim_start();
            continue;
        }
        if let Some(after_block_start) = rest.strip_prefix("/*") {
            let (_, after_block) = after_block_start.split_once("*/")?;
            rest = after_block.trim_start();
            continue;
        }
        break;
    }

    let keyword = rest
        .chars()
        .take_while(|character| character.is_ascii_alphabetic() || *character == '_')
        .collect::<String>();
    if keyword.is_empty() {
        None
    } else {
        Some(keyword.to_ascii_lowercase())
    }
}

fn sql_mutation_checks(statement_count: usize, contains_transaction_control: bool) -> Vec<Value> {
    let mut checks = vec![json!({
        "code": "sql.statement_classification",
        "status": "passed",
        "statement_count": statement_count,
    })];
    checks.push(json!({
        "code": "sql.transaction_control",
        "status": if contains_transaction_control { "warning" } else { "passed" },
        "message": if contains_transaction_control {
            "SQL contains explicit transaction control; execution requires the generic invocation mutation gate."
        } else {
            "No explicit transaction control detected."
        },
    }));
    checks
}

fn add_scope_input_property(
    properties: &mut Map<String, Value>,
    required: &mut Vec<String>,
    scope: SqlInputScope,
) {
    let Some(field) = scope.kind.input_field() else {
        return;
    };
    if scope.required {
        required.push(field.to_string());
    }
    properties.insert(
        field.into(),
        json!({
            "type": "string",
            "minLength": 1,
            "description": scope.kind.input_description()
        }),
    );
}

fn add_catalog_filter_properties(properties: &mut Map<String, Value>) {
    properties.insert(
        "pattern".into(),
        json!({
            "type": "string",
            "description": "Optional case-insensitive substring used to filter catalog names."
        }),
    );
    properties.insert(
        "include_system".into(),
        json!({
            "type": "boolean",
            "default": false,
            "description": "Include target-defined system catalogs and relations."
        }),
    );
}

fn common_introspection_properties(scope: SqlCatalogScope) -> Map<String, Value> {
    let mut properties = Map::new();
    properties.insert(
        "contract_version".into(),
        json!({ "type": "integer", "const": SQL_RESULT_CONTRACT_VERSION }),
    );
    properties.insert("scope".into(), sql_scope_schema());
    properties.insert(
        "capabilities".into(),
        sql_introspection_capabilities_schema(),
    );
    if matches!(scope, SqlCatalogScope::Database | SqlCatalogScope::Schema) {
        properties.insert("database".into(), json!({ "type": "string" }));
    }
    if matches!(scope, SqlCatalogScope::Schema) {
        properties.insert("schema".into(), json!({ "type": "string" }));
    }
    properties
}

fn add_scope_required(scope: SqlCatalogScope, required: &mut Vec<String>) {
    if matches!(scope, SqlCatalogScope::Database | SqlCatalogScope::Schema) {
        required.push("database".to_string());
    }
    if matches!(scope, SqlCatalogScope::Schema) {
        required.push("schema".to_string());
    }
}

fn object_schema(required: Vec<String>, properties: Map<String, Value>) -> Value {
    json!({
        "type": "object",
        "required": required,
        "properties": properties,
        "additionalProperties": false
    })
}

fn sql_statement_schema() -> Value {
    json!({
        "type": "object",
        "required": ["kind"],
        "properties": {
            "kind": { "type": "string", "enum": ["select", "affected", "empty"] },
            "columns": { "type": "array", "items": sql_column_schema() },
            "rows": { "type": "array" },
            "row_count": { "type": "integer", "minimum": 0 },
            "source_row_count": { "type": "integer", "minimum": 0 },
            "truncated": { "type": "boolean" },
            "rows_affected": { "type": "integer", "minimum": 0 }
        },
        "additionalProperties": false
    })
}

fn sql_column_schema() -> Value {
    json!({
        "type": "object",
        "required": [
            "name",
            "source_name",
            "ordinal",
            "data_type",
            "native_type",
            "nullable",
            "is_primary_key",
            "primary_key",
            "default_value",
            "default",
            "max_length",
            "extra",
            "dialect"
        ],
        "properties": {
            "name": { "type": "string" },
            "source_name": { "type": "string" },
            "ordinal": { "type": "integer", "minimum": 1 },
            "data_type": {
                "type": "string",
                "enum": [
                    "text",
                    "integer",
                    "float",
                    "decimal",
                    "boolean",
                    "date",
                    "time",
                    "datetime",
                    "binary",
                    "json",
                    "uuid",
                    "unknown"
                ]
            },
            "native_type": { "type": "string" },
            "nullable": { "type": "boolean" },
            "is_primary_key": { "type": "boolean" },
            "primary_key": { "type": "boolean" },
            "default_value": { "type": ["string", "null"] },
            "default": { "type": ["string", "null"] },
            "max_length": { "type": ["integer", "null"], "minimum": 0 },
            "extra": { "type": "string" },
            "dialect": { "type": "object" }
        },
        "additionalProperties": false
    })
}

fn sql_warning_schema() -> Value {
    json!({
        "type": "object",
        "required": ["code", "message"],
        "properties": {
            "code": { "type": "string" },
            "message": { "type": "string" },
            "details": {}
        },
        "additionalProperties": false
    })
}

fn sql_relation_schema() -> Value {
    json!({
        "type": "object",
        "required": [
            "name",
            "relation_type",
            "table_type",
            "database",
            "schema",
            "rows",
            "comment",
            "dialect"
        ],
        "properties": {
            "name": { "type": "string" },
            "relation_type": { "type": "string", "enum": ["table", "view"] },
            "table_type": { "type": "string" },
            "database": { "type": ["string", "null"] },
            "schema": { "type": ["string", "null"] },
            "rows": { "type": ["integer", "null"], "minimum": 0 },
            "comment": { "type": ["string", "null"] },
            "dialect": { "type": "object" }
        },
        "additionalProperties": false
    })
}

fn sql_catalog_entry_schema(kind: &str) -> Value {
    json!({
        "type": "object",
        "required": ["name", "kind", "database", "current", "system"],
        "properties": {
            "name": { "type": "string" },
            "kind": { "type": "string", "const": kind },
            "database": { "type": ["string", "null"] },
            "current": { "type": "boolean" },
            "system": { "type": "boolean" }
        },
        "additionalProperties": false
    })
}

fn sql_normalized_data_type(native_type: &str) -> &'static str {
    let normalized = native_type.trim().to_ascii_lowercase();
    if normalized.contains("bool") {
        "boolean"
    } else if normalized.contains("int") || normalized.contains("serial") {
        "integer"
    } else if normalized.contains("decimal") || normalized.contains("numeric") {
        "decimal"
    } else if normalized.contains("real")
        || normalized.contains("float")
        || normalized.contains("double")
    {
        "float"
    } else if normalized == "date" {
        "date"
    } else if normalized == "time" || normalized.starts_with("time(") {
        "time"
    } else if normalized.contains("timestamp") || normalized.contains("datetime") {
        "datetime"
    } else if normalized.contains("blob")
        || normalized.contains("binary")
        || normalized.contains("bytea")
    {
        "binary"
    } else if normalized.contains("json") {
        "json"
    } else if normalized.contains("uuid") {
        "uuid"
    } else if normalized.contains("char")
        || normalized.contains("text")
        || normalized.contains("string")
        || normalized.contains("clob")
        || normalized.contains("enum")
    {
        "text"
    } else {
        "unknown"
    }
}

fn sql_statement_classification_schema() -> Value {
    json!({
        "type": "object",
        "required": ["index", "classification", "confidence", "reason_code"],
        "properties": {
            "index": { "type": "integer", "minimum": 0 },
            "classification": {
                "type": "string",
                "enum": [
                    "read",
                    "explain",
                    "write",
                    "schema",
                    "transaction",
                    "session",
                    "maintenance",
                    "unknown"
                ]
            },
            "confidence": {
                "type": "string",
                "enum": ["parser", "heuristic", "target", "unknown"]
            },
            "reason_code": { "type": "string" }
        },
        "additionalProperties": false
    })
}

fn sql_mutation_check_schema() -> Value {
    json!({
        "type": "object",
        "required": ["code", "status"],
        "properties": {
            "code": { "type": "string" },
            "status": {
                "type": "string",
                "enum": ["passed", "warning", "failed", "skipped"]
            },
            "message": { "type": "string" },
            "statement_count": { "type": "integer", "minimum": 0 }
        },
        "additionalProperties": false
    })
}

fn sql_mutation_gate_schema() -> Value {
    json!({
        "type": "object",
        "required": [
            "destructive",
            "acknowledged",
            "dry_run",
            "dialect",
            "statement_count",
            "transaction_control",
            "transaction_policy"
        ],
        "properties": {
            "destructive": { "type": "boolean" },
            "acknowledged": { "type": "boolean" },
            "dry_run": { "type": "boolean" },
            "dialect": { "type": "string" },
            "statement_count": { "type": "integer", "minimum": 0 },
            "transaction_control": { "type": "boolean" },
            "transaction_policy": { "type": "string" }
        },
        "additionalProperties": false
    })
}

fn sql_scope_schema() -> Value {
    json!({
        "type": "object",
        "required": ["kind"],
        "properties": {
            "kind": {
                "type": "string",
                "enum": ["local_database", "database", "schema"]
            },
            "database": { "type": ["string", "null"] },
            "schema": { "type": ["string", "null"] }
        },
        "additionalProperties": false
    })
}

fn sql_introspection_capabilities_schema() -> Value {
    json!({
        "type": "object",
        "required": [
            "supports_databases",
            "supports_schemas",
            "supports_views",
            "supports_row_counts",
            "supports_indexes",
            "supports_foreign_keys",
            "supports_constraints",
            "supports_comments"
        ],
        "properties": {
            "supports_databases": { "type": "boolean" },
            "supports_schemas": { "type": "boolean" },
            "supports_views": { "type": "boolean" },
            "supports_row_counts": { "type": "boolean" },
            "supports_indexes": { "type": "boolean" },
            "supports_foreign_keys": { "type": "boolean" },
            "supports_constraints": { "type": "boolean" },
            "supports_comments": { "type": "boolean" }
        },
        "additionalProperties": false
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SqlContractViolation {
    pub capability_id: Option<String>,
    pub code: &'static str,
    pub message: String,
}

impl SqlContractViolation {
    fn new(capability_id: Option<&str>, code: &'static str, message: impl Into<String>) -> Self {
        Self {
            capability_id: capability_id.map(str::to_string),
            code,
            message: message.into(),
        }
    }
}

pub fn validate_sql_capability_contract(
    plugin_id: &str,
    capabilities: &[CapabilityDefinition],
) -> Result<(), Vec<SqlContractViolation>> {
    let mut violations = Vec::new();

    for capability in capabilities {
        if capability.plugin_id != plugin_id {
            violations.push(SqlContractViolation::new(
                Some(&capability.id),
                "sql.plugin_id_mismatch",
                format!(
                    "Capability '{}' belongs to plugin '{}', expected '{}'.",
                    capability.id, capability.plugin_id, plugin_id
                ),
            ));
        }
    }

    for capability_id in REQUIRED_SQL_CAPABILITIES {
        if find_capability(capabilities, capability_id).is_none() {
            violations.push(SqlContractViolation::new(
                Some(capability_id),
                "sql.capability_missing",
                format!("Required SQL capability '{}' is missing.", capability_id),
            ));
        }
    }

    if let Some(query) = find_capability(capabilities, "query") {
        validate_sql_text_capability(query, "sql.query", false, false, &mut violations);
        require_output_property(query, "statements", &mut violations);
        require_output_property(query, "row_limit", &mut violations);
        require_output_property(query, "row_count", &mut violations);
        require_output_property(query, "source_row_count", &mut violations);
        require_output_property(query, "truncated", &mut violations);
        require_output_property(query, "cursor", &mut violations);
        require_output_property(query, "next_cursor", &mut violations);
        require_output_property(query, "contract_version", &mut violations);
        require_output_property(query, "batch_size", &mut violations);
        require_output_property(query, "warnings", &mut violations);
        require_output_required(query, "statements", &mut violations);
        require_output_required(query, "row_limit", &mut violations);
        require_output_required(query, "row_count", &mut violations);
        require_output_required(query, "source_row_count", &mut violations);
        require_output_required(query, "truncated", &mut violations);
        require_output_required(query, "cursor", &mut violations);
        require_output_required(query, "next_cursor", &mut violations);
        require_output_required(query, "contract_version", &mut violations);
        require_output_required(query, "batch_size", &mut violations);
        require_output_required(query, "warnings", &mut violations);
    }

    if let Some(explain) = find_capability(capabilities, "explain") {
        validate_sql_text_capability(explain, "sql.explain", false, false, &mut violations);
        require_output_property(explain, "statements", &mut violations);
        require_output_property(explain, "row_limit", &mut violations);
        require_output_property(explain, "row_count", &mut violations);
        require_output_property(explain, "source_row_count", &mut violations);
        require_output_property(explain, "truncated", &mut violations);
        require_output_property(explain, "cursor", &mut violations);
        require_output_property(explain, "next_cursor", &mut violations);
        require_output_property(explain, "analyze", &mut violations);
        require_output_property(explain, "format", &mut violations);
        require_output_property(explain, "dialect", &mut violations);
        require_output_property(explain, "explained_statement_count", &mut violations);
        require_output_required(explain, "statements", &mut violations);
        require_output_required(explain, "row_limit", &mut violations);
        require_output_required(explain, "row_count", &mut violations);
        require_output_required(explain, "source_row_count", &mut violations);
        require_output_required(explain, "truncated", &mut violations);
        require_output_required(explain, "cursor", &mut violations);
        require_output_required(explain, "next_cursor", &mut violations);
        require_output_required(explain, "analyze", &mut violations);
        require_output_required(explain, "format", &mut violations);
        require_output_required(explain, "dialect", &mut violations);
        require_output_required(explain, "explained_statement_count", &mut violations);
    }

    if let Some(exec) = find_capability(capabilities, "exec") {
        validate_sql_text_capability(exec, "sql.exec", true, true, &mut violations);
        require_output_property(exec, "statements", &mut violations);
        require_output_property(exec, "rows_affected", &mut violations);
        require_output_property(exec, "dry_run", &mut violations);
        require_output_property(exec, "would_execute", &mut violations);
        require_output_property(exec, "destructive", &mut violations);
        require_output_property(exec, "operation", &mut violations);
        require_output_property(exec, "statement_count", &mut violations);
        require_output_property(exec, "classifications", &mut violations);
        require_output_property(exec, "checks", &mut violations);
        require_output_property(exec, "mutation_gate", &mut violations);
    }

    if let Some(tables) = find_capability(capabilities, "tables") {
        validate_metadata_capability(tables, "schema.list", &mut violations);
        require_output_property(tables, "scope", &mut violations);
        require_output_property(tables, "capabilities", &mut violations);
        require_output_property(tables, "tables", &mut violations);
        require_output_property(tables, "views", &mut violations);
        require_output_property(tables, "relations", &mut violations);
        require_output_property(tables, "next_cursor", &mut violations);
        require_output_property(tables, "warnings", &mut violations);
        require_output_required(tables, "scope", &mut violations);
        require_output_required(tables, "capabilities", &mut violations);
        require_output_required(tables, "tables", &mut violations);
        require_output_required(tables, "views", &mut violations);
        require_output_required(tables, "relations", &mut violations);
        require_output_required(tables, "next_cursor", &mut violations);
        require_output_required(tables, "warnings", &mut violations);
    }

    if let Some(catalogs) = find_capability(capabilities, "catalogs") {
        validate_metadata_capability(catalogs, "schema.list", &mut violations);
        require_output_property(catalogs, "scope", &mut violations);
        require_output_property(catalogs, "capabilities", &mut violations);
        require_output_property(catalogs, "databases", &mut violations);
        require_output_property(catalogs, "schemas", &mut violations);
        require_output_property(catalogs, "next_cursor", &mut violations);
        require_output_property(catalogs, "warnings", &mut violations);
        require_output_required(catalogs, "scope", &mut violations);
        require_output_required(catalogs, "capabilities", &mut violations);
        require_output_required(catalogs, "databases", &mut violations);
        require_output_required(catalogs, "schemas", &mut violations);
        require_output_required(catalogs, "next_cursor", &mut violations);
        require_output_required(catalogs, "warnings", &mut violations);
    }

    if let Some(describe_table) = find_capability(capabilities, "describe_table") {
        validate_metadata_capability(describe_table, "schema.describe", &mut violations);
        require_input_required(describe_table, "table", &mut violations);
        require_input_property(describe_table, "table", &mut violations);
        require_output_property(describe_table, "scope", &mut violations);
        require_output_property(describe_table, "capabilities", &mut violations);
        require_output_property(describe_table, "table", &mut violations);
        require_output_property(describe_table, "columns", &mut violations);
        require_output_property(describe_table, "indexes", &mut violations);
        require_output_property(describe_table, "foreign_keys", &mut violations);
        require_output_property(describe_table, "constraints", &mut violations);
        require_output_required(describe_table, "scope", &mut violations);
        require_output_required(describe_table, "capabilities", &mut violations);
        require_output_required(describe_table, "table", &mut violations);
        require_output_required(describe_table, "columns", &mut violations);
        require_output_required(describe_table, "indexes", &mut violations);
        require_output_required(describe_table, "foreign_keys", &mut violations);
        require_output_required(describe_table, "constraints", &mut violations);
    }

    if let Some(export) = find_capability(capabilities, "export_query") {
        validate_sql_text_capability(export, "sql.export", false, false, &mut violations);
        require_bool(export, "streaming", export.streaming, true, &mut violations);
        for field in ["format", "include_header", "local_root", "local_path"] {
            require_input_property(export, field, &mut violations);
        }
        for field in [
            "format",
            "columns",
            "row_count",
            "bytes",
            "truncated",
            "cursor",
            "next_cursor",
            "destination_written",
            "local_scope_id",
            "preview",
            "progress",
        ] {
            require_output_property(export, field, &mut violations);
            require_output_required(export, field, &mut violations);
        }
    }

    for (capability_id, permission, destructive, supports_dry_run) in [
        ("import_plan", "sql.import.plan", false, false),
        ("import_apply", "sql.import.apply", true, true),
    ] {
        if let Some(import) = find_capability(capabilities, capability_id) {
            validate_transfer_capability(
                import,
                permission,
                destructive,
                supports_dry_run,
                &mut violations,
            );
            for field in [
                "table",
                "format",
                "local_root",
                "local_path",
                "has_header",
                "columns",
                "mode",
                "row_error_policy",
            ] {
                require_input_property(import, field, &mut violations);
            }
            for field in ["table", "format", "local_root", "local_path"] {
                require_input_required(import, field, &mut violations);
            }
            for field in [
                "dry_run",
                "would_execute",
                "destructive",
                "operation",
                "format",
                "table",
                "columns",
                "row_count",
                "source_file_bytes",
                "truncated",
                "cursor",
                "next_cursor",
                "transaction_scope",
                "row_error_policy",
                "local_scope_id",
                "checks",
                "warnings",
            ] {
                require_output_property(import, field, &mut violations);
                require_output_required(import, field, &mut violations);
            }
            if capability_id == "import_apply" {
                require_output_property(import, "rows_inserted", &mut violations);
                require_output_required(import, "rows_inserted", &mut violations);
            }
        }
    }

    if violations.is_empty() {
        Ok(())
    } else {
        Err(violations)
    }
}

fn find_capability<'a>(
    capabilities: &'a [CapabilityDefinition],
    capability_id: &str,
) -> Option<&'a CapabilityDefinition> {
    capabilities
        .iter()
        .find(|capability| capability.id == capability_id)
}

fn validate_sql_text_capability(
    capability: &CapabilityDefinition,
    required_permission: &str,
    destructive: bool,
    supports_dry_run: bool,
    violations: &mut Vec<SqlContractViolation>,
) {
    require_permission(capability, required_permission, violations);
    require_bool(
        capability,
        "destructive",
        capability.destructive,
        destructive,
        violations,
    );
    require_bool(
        capability,
        "supports_dry_run",
        capability.supports_dry_run,
        supports_dry_run,
        violations,
    );
    require_connection(capability, violations);
    require_object_schema(capability, "input", &capability.input_schema, violations);
    require_input_required(capability, "sql", violations);
    require_input_property(capability, "sql", violations);
    require_additional_properties_false(capability, "input", &capability.input_schema, violations);
    require_object_schema(capability, "output", &capability.output_schema, violations);
}

fn validate_metadata_capability(
    capability: &CapabilityDefinition,
    required_permission: &str,
    violations: &mut Vec<SqlContractViolation>,
) {
    require_permission(capability, required_permission, violations);
    require_bool(
        capability,
        "destructive",
        capability.destructive,
        false,
        violations,
    );
    require_bool(
        capability,
        "supports_dry_run",
        capability.supports_dry_run,
        false,
        violations,
    );
    require_connection(capability, violations);
    require_object_schema(capability, "input", &capability.input_schema, violations);
    require_additional_properties_false(capability, "input", &capability.input_schema, violations);
    require_object_schema(capability, "output", &capability.output_schema, violations);
}

fn validate_transfer_capability(
    capability: &CapabilityDefinition,
    required_permission: &str,
    destructive: bool,
    supports_dry_run: bool,
    violations: &mut Vec<SqlContractViolation>,
) {
    require_permission(capability, required_permission, violations);
    require_bool(
        capability,
        "destructive",
        capability.destructive,
        destructive,
        violations,
    );
    require_bool(
        capability,
        "supports_dry_run",
        capability.supports_dry_run,
        supports_dry_run,
        violations,
    );
    require_connection(capability, violations);
    require_object_schema(capability, "input", &capability.input_schema, violations);
    require_additional_properties_false(capability, "input", &capability.input_schema, violations);
    require_object_schema(capability, "output", &capability.output_schema, violations);
    require_additional_properties_false(
        capability,
        "output",
        &capability.output_schema,
        violations,
    );
}

fn require_permission(
    capability: &CapabilityDefinition,
    permission: &str,
    violations: &mut Vec<SqlContractViolation>,
) {
    if !capability
        .permissions
        .iter()
        .any(|existing| existing == permission)
    {
        violations.push(SqlContractViolation::new(
            Some(&capability.id),
            "sql.permission_missing",
            format!(
                "Capability '{}' must include permission '{}'.",
                capability.id, permission
            ),
        ));
    }
}

fn require_bool(
    capability: &CapabilityDefinition,
    field: &'static str,
    actual: bool,
    expected: bool,
    violations: &mut Vec<SqlContractViolation>,
) {
    if actual != expected {
        violations.push(SqlContractViolation::new(
            Some(&capability.id),
            "sql.metadata_bool_mismatch",
            format!(
                "Capability '{}' must set {} = {}.",
                capability.id, field, expected
            ),
        ));
    }
}

fn require_connection(
    capability: &CapabilityDefinition,
    violations: &mut Vec<SqlContractViolation>,
) {
    if !capability.connection_required {
        violations.push(SqlContractViolation::new(
            Some(&capability.id),
            "sql.connection_required_missing",
            format!(
                "Capability '{}' must require a connection profile.",
                capability.id
            ),
        ));
    }
}

fn require_object_schema(
    capability: &CapabilityDefinition,
    label: &'static str,
    schema: &Value,
    violations: &mut Vec<SqlContractViolation>,
) {
    if schema.get("type").and_then(Value::as_str) != Some("object") {
        violations.push(SqlContractViolation::new(
            Some(&capability.id),
            "sql.schema_not_object",
            format!(
                "Capability '{}' {} schema must be an object.",
                capability.id, label
            ),
        ));
    }
}

fn require_additional_properties_false(
    capability: &CapabilityDefinition,
    label: &'static str,
    schema: &Value,
    violations: &mut Vec<SqlContractViolation>,
) {
    if schema.get("additionalProperties") != Some(&Value::Bool(false)) {
        violations.push(SqlContractViolation::new(
            Some(&capability.id),
            "sql.schema_additional_properties",
            format!(
                "Capability '{}' {} schema must set additionalProperties=false.",
                capability.id, label
            ),
        ));
    }
}

fn require_input_required(
    capability: &CapabilityDefinition,
    field: &str,
    violations: &mut Vec<SqlContractViolation>,
) {
    require_required(
        &capability.input_schema,
        capability,
        "input",
        field,
        violations,
    );
}

fn require_output_required(
    capability: &CapabilityDefinition,
    field: &str,
    violations: &mut Vec<SqlContractViolation>,
) {
    require_required(
        &capability.output_schema,
        capability,
        "output",
        field,
        violations,
    );
}

fn require_required(
    schema: &Value,
    capability: &CapabilityDefinition,
    label: &'static str,
    field: &str,
    violations: &mut Vec<SqlContractViolation>,
) {
    let contains = schema
        .get("required")
        .and_then(Value::as_array)
        .is_some_and(|required| required.iter().any(|value| value.as_str() == Some(field)));
    if !contains {
        violations.push(SqlContractViolation::new(
            Some(&capability.id),
            "sql.schema_required_missing",
            format!(
                "Capability '{}' {} schema must require '{}'.",
                capability.id, label, field
            ),
        ));
    }
}

fn require_input_property(
    capability: &CapabilityDefinition,
    field: &str,
    violations: &mut Vec<SqlContractViolation>,
) {
    require_property(
        &capability.input_schema,
        capability,
        "input",
        field,
        violations,
    );
}

fn require_output_property(
    capability: &CapabilityDefinition,
    field: &str,
    violations: &mut Vec<SqlContractViolation>,
) {
    require_property(
        &capability.output_schema,
        capability,
        "output",
        field,
        violations,
    );
}

fn require_property(
    schema: &Value,
    capability: &CapabilityDefinition,
    label: &'static str,
    field: &str,
    violations: &mut Vec<SqlContractViolation>,
) {
    let contains = schema
        .get("properties")
        .and_then(Value::as_object)
        .is_some_and(|properties| properties.contains_key(field));
    if !contains {
        violations.push(SqlContractViolation::new(
            Some(&capability.id),
            "sql.schema_property_missing",
            format!(
                "Capability '{}' {} schema must define property '{}'.",
                capability.id, label, field
            ),
        ));
    }
}

#[cfg(test)]
mod tests {
    use crate::capability::CapabilityRiskLevel;

    use super::*;

    #[test]
    fn accepts_minimum_sql_contract_catalog() {
        let capabilities = vec![
            capability(
                "query",
                sql_text_input_schema("Read-oriented SQL.", SqlInputScope::none()),
                sql_statements_output_schema(false),
                &["connection.read", "sql.query"],
                false,
                false,
            ),
            capability(
                "explain",
                sql_explain_input_schema(SqlInputScope::none()),
                sql_explain_output_schema(),
                &["connection.read", "sql.explain"],
                false,
                false,
            ),
            capability(
                "exec",
                sql_text_input_schema("SQL that may mutate data.", SqlInputScope::none()),
                sql_statements_output_schema(true),
                &["connection.read", "sql.exec"],
                true,
                true,
            ),
            capability(
                "catalogs",
                sql_catalogs_input_schema(),
                sql_catalogs_output_schema(SqlCatalogScope::LocalDatabase),
                &["connection.read", "schema.list"],
                false,
                false,
            ),
            capability(
                "tables",
                sql_tables_input_schema(SqlInputScope::none()),
                sql_tables_output_schema(SqlCatalogScope::LocalDatabase),
                &["connection.read", "schema.list"],
                false,
                false,
            ),
            capability(
                "describe_table",
                sql_describe_table_input_schema(SqlInputScope::none()),
                sql_describe_table_output_schema(SqlCatalogScope::LocalDatabase),
                &["connection.read", "schema.describe"],
                false,
                false,
            ),
            capability(
                "export_query",
                crate::sql_transfer::sql_export_input_schema(SqlInputScope::none()),
                crate::sql_transfer::sql_export_output_schema(),
                &["connection.read", "sql.export", "local.write"],
                false,
                false,
            ),
            capability(
                "import_plan",
                crate::sql_transfer::sql_import_input_schema(SqlInputScope::none()),
                crate::sql_transfer::sql_import_output_schema(false),
                &["connection.read", "sql.import.plan", "local.read"],
                false,
                false,
            ),
            capability(
                "import_apply",
                crate::sql_transfer::sql_import_input_schema(SqlInputScope::none()),
                crate::sql_transfer::sql_import_output_schema(true),
                &["connection.read", "sql.import.apply", "local.read"],
                true,
                true,
            ),
        ];

        assert!(validate_sql_capability_contract("sqlite", &capabilities).is_ok());
    }

    #[test]
    fn query_schema_requires_stable_pagination_fields() {
        let schema = sql_statements_output_schema(false);
        let required = schema["required"].as_array().expect("required fields");

        assert!(
            required
                .iter()
                .any(|field| field.as_str() == Some("cursor"))
        );
        assert!(
            required
                .iter()
                .any(|field| field.as_str() == Some("next_cursor"))
        );
        assert_eq!(
            schema["properties"]["row_limit"]["maximum"].as_u64(),
            Some(SQL_MAX_ROW_LIMIT as u64)
        );
        assert_eq!(
            schema["properties"]["contract_version"]["const"].as_u64(),
            Some(SQL_RESULT_CONTRACT_VERSION)
        );
        assert_eq!(
            schema["properties"]["statements"]["items"]["properties"]["columns"]["items"]["properties"]
                ["native_type"]["type"],
            "string"
        );
    }

    #[test]
    fn normalizes_column_types_without_discarding_native_metadata() {
        let column = ColumnInfo {
            name: "total".into(),
            data_type: "NUMERIC(12,2)".into(),
            nullable: false,
            is_primary_key: false,
            default_value: Some("0".into()),
            max_length: None,
            extra: String::new(),
        };

        let metadata = sql_column_metadata(&column, 1, SqlDialect::Postgres);
        assert_eq!(metadata["data_type"], "decimal");
        assert_eq!(metadata["native_type"], "NUMERIC(12,2)");
        assert_eq!(metadata["ordinal"], 1);
        assert_eq!(metadata["dialect"]["name"], "postgres");
    }

    #[test]
    fn classifies_read_and_transaction_statements() {
        assert!(sql_allows_read_only_query(
            "/* leading */ select 1; explain select 1",
            SqlDialect::Postgres,
        ));
        assert!(!sql_allows_read_only_query(
            "select 1; begin; update users set name = 'Ada'",
            SqlDialect::Postgres,
        ));

        let classifications = sql_statement_classification_values(
            "select 1; begin; update users set name = 'Ada'",
            SqlDialect::Postgres,
        );
        assert_eq!(classifications[0]["classification"], "read");
        assert_eq!(classifications[1]["classification"], "transaction");
        assert_eq!(classifications[2]["classification"], "write");
    }

    #[test]
    fn builds_safe_explain_statements_per_dialect() {
        assert_eq!(
            sql_explain_statement("select * from users", SqlDialect::Sqlite),
            "EXPLAIN QUERY PLAN select * from users"
        );
        assert_eq!(
            sql_explain_statement("select * from users", SqlDialect::Postgres),
            "EXPLAIN (FORMAT JSON) select * from users"
        );
        assert_eq!(
            sql_explain_statement("explain select * from users", SqlDialect::MySql),
            "explain select * from users"
        );
    }

    #[test]
    fn mutation_preview_uses_redacted_stable_metadata() {
        let preview = sql_mutation_preview(
            "begin; insert into users(password) values ('secret')",
            SqlDialect::Sqlite,
            true,
        );

        assert_eq!(preview["dry_run"], true);
        assert_eq!(preview["statement_count"], 2);
        assert_eq!(
            preview["classifications"][0]["classification"],
            "transaction"
        );
        assert_eq!(preview["classifications"][1]["classification"], "write");
        assert_eq!(preview["mutation_gate"]["acknowledged"], true);
        assert_eq!(preview["mutation_gate"]["transaction_control"], true);
        assert!(!serde_json::to_string(&preview).unwrap().contains("secret"));
    }

    #[test]
    fn reports_missing_required_capability() {
        let error = validate_sql_capability_contract("sqlite", &[]).unwrap_err();

        assert!(
            error
                .iter()
                .any(|violation| violation.code == "sql.capability_missing"
                    && violation.capability_id.as_deref() == Some("query"))
        );
    }

    fn capability(
        id: &str,
        input_schema: Value,
        output_schema: Value,
        permissions: &[&str],
        destructive: bool,
        supports_dry_run: bool,
    ) -> CapabilityDefinition {
        CapabilityDefinition {
            plugin_id: "sqlite".into(),
            id: id.into(),
            description: id.into(),
            input_schema,
            output_schema,
            permissions: permissions
                .iter()
                .map(|permission| permission.to_string())
                .collect(),
            authorization: Default::default(),
            risk: CapabilityRiskLevel::from_destructive(destructive),
            destructive,
            streaming: id == "export_query",
            execution_mode: crate::CapabilityExecutionMode::Stateless,
            session_handoff: None,
            connection_required: true,
            required_secret_classes: Vec::new(),
            supports_dry_run,
            default_timeout_ms: None,
        }
    }
}
