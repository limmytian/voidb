//! Generic SQL process plugin scaffolding.
//!
//! Provides reusable AST inspection, query plan verification, pagination,
//! and standard SQL capability routing for external SQL plugins.

use std::sync::Arc;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use voidb_core::{
    CapabilityDefinition, CapabilityError, CapabilityInvocation, CapabilityInvocationResult,
    CapabilityRiskLevel, CredentialClass, InvocationStatus, SQL_DEFAULT_ROW_LIMIT,
    SQL_RESULT_CONTRACT_VERSION, SqlCatalogScope, SqlDialect, SqlInputScope,
    SqlIntrospectionSupport, sql_allows_read_only_query, sql_catalog_entry,
    sql_catalogs_input_schema, sql_catalogs_output_schema, sql_column_metadata,
    sql_describe_table_input_schema, sql_describe_table_output_schema, sql_explain_input_schema,
    sql_explain_output_schema, sql_explain_statement, sql_introspection_capabilities,
    sql_mutation_gate, sql_mutation_preview, sql_relation, sql_scope, sql_statements_output_schema,
    sql_tables_input_schema, sql_tables_output_schema, sql_text_input_schema,
};

use voidb_core::database::types::{ColumnInfo, ForeignKeyInfo};

use crate::{CapabilityRouter, plugin_error, validation_error};

/// Column value representation in standard tabular results.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SqlValue {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    String(String),
    Bytes(Vec<u8>),
    Json(Value),
}

impl From<Value> for SqlValue {
    fn from(value: Value) -> Self {
        match value {
            Value::Null => Self::Null,
            Value::Bool(b) => Self::Bool(b),
            Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    Self::Int(i)
                } else if let Some(f) = n.as_f64() {
                    Self::Float(f)
                } else {
                    Self::String(n.to_string())
                }
            }
            Value::String(s) => Self::String(s),
            other => Self::Json(other),
        }
    }
}

impl From<SqlValue> for Value {
    fn from(val: SqlValue) -> Self {
        match val {
            SqlValue::Null => Value::Null,
            SqlValue::Bool(b) => json!(b),
            SqlValue::Int(i) => json!(i),
            SqlValue::Float(f) => json!(f),
            SqlValue::String(s) => json!(s),
            SqlValue::Bytes(b) => json!(b),
            SqlValue::Json(j) => j,
        }
    }
}

/// A tabular query result statement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqlQueryResult {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<SqlValue>>,
}

/// An executed mutating statement result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqlExecResult {
    pub rows_affected: u64,
}

/// Catalog entry metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqlCatalogItem {
    pub name: String,
    pub description: Option<String>,
}

/// Table / view relation entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqlTableItem {
    pub name: String,
    pub is_view: bool,
    pub row_count: Option<u64>,
    pub comment: Option<String>,
}

/// Full table schema description.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SqlTableDescription {
    pub table_name: String,
    pub columns: Vec<ColumnInfo>,
    pub foreign_keys: Vec<ForeignKeyInfo>,
    pub comment: Option<String>,
}

/// Backend interface for generic SQL plugins.
///
/// Implementing this trait is all that is required to build a compliant
/// VoidB process plugin for any standard SQL engine (ClickHouse, TiDB, MariaDB, Snowflake, etc.).
pub trait GenericSqlBackend: Send + Sync + 'static {
    /// Return the SQL dialect of the backend.
    fn dialect(&self) -> SqlDialect;

    /// Scope kind for catalog resolution (Database vs Schema vs LocalDatabase).
    fn catalog_scope(&self) -> SqlCatalogScope {
        SqlCatalogScope::Database
    }

    /// Introspection capabilities supported by the backend.
    fn introspection_support(&self) -> SqlIntrospectionSupport {
        SqlIntrospectionSupport {
            supports_databases: true,
            supports_schemas: false,
            supports_views: true,
            supports_row_counts: true,
            supports_indexes: true,
            supports_foreign_keys: true,
            supports_constraints: true,
            supports_comments: true,
        }
    }

    /// Execute a read-only query statement and return rows.
    fn query(
        &self,
        scope: Option<&str>,
        sql: &str,
    ) -> Result<SqlQueryResult, CapabilityError>;

    /// Inspect query plan for read-oriented SQL.
    fn explain(
        &self,
        scope: Option<&str>,
        sql: &str,
    ) -> Result<SqlQueryResult, CapabilityError> {
        let explain_sql = sql_explain_statement(sql, self.dialect());
        self.query(scope, &explain_sql)
    }

    /// Execute a mutating SQL statement.
    fn exec(
        &self,
        scope: Option<&str>,
        sql: &str,
    ) -> Result<SqlExecResult, CapabilityError>;

    /// List databases or schemas.
    fn list_catalogs(&self) -> Result<Vec<SqlCatalogItem>, CapabilityError> {
        Ok(Vec::new())
    }

    /// List tables and views.
    fn list_tables(&self, scope: Option<&str>) -> Result<Vec<SqlTableItem>, CapabilityError> {
        let _ = scope;
        Ok(Vec::new())
    }

    /// Describe table schema.
    fn describe_table(
        &self,
        scope: Option<&str>,
        table: &str,
    ) -> Result<SqlTableDescription, CapabilityError> {
        let _ = (scope, table);
        Err(plugin_error(
            "sql.describe_not_implemented",
            "describe_table is not implemented for this backend",
            json!({}),
        ))
    }
}

/// Standard capability definitions for any generic SQL plugin.
pub fn generic_sql_capabilities(
    plugin_id: &str,
    scope: SqlInputScope,
    catalog_scope: SqlCatalogScope,
) -> Vec<CapabilityDefinition> {
    vec![
        sql_capability(
            plugin_id,
            "query",
            "Execute read-oriented SQL and return row sets.",
            sql_text_input_schema("Read-oriented SQL statement.", scope),
            sql_statements_output_schema(false),
            vec!["connection.read", "sql.query"],
            false,
            false,
        ),
        sql_capability(
            plugin_id,
            "explain",
            "Inspect the query plan for one read-oriented SQL statement.",
            sql_explain_input_schema(scope),
            sql_explain_output_schema(),
            vec!["connection.read", "sql.explain"],
            false,
            false,
        ),
        sql_capability(
            plugin_id,
            "exec",
            "Execute SQL that may mutate schema or data.",
            sql_text_input_schema("Mutating SQL statement.", scope),
            sql_statements_output_schema(true),
            vec!["connection.read", "sql.exec"],
            true,
            true,
        ),
        sql_capability(
            plugin_id,
            "catalogs",
            "List databases using a bounded, filterable catalog.",
            sql_catalogs_input_schema(),
            sql_catalogs_output_schema(catalog_scope),
            vec!["connection.read", "schema.list"],
            false,
            false,
        ),
        sql_capability(
            plugin_id,
            "tables",
            "List tables and views.",
            sql_tables_input_schema(scope),
            sql_tables_output_schema(catalog_scope),
            vec!["connection.read", "schema.list"],
            false,
            false,
        ),
        sql_capability(
            plugin_id,
            "describe_table",
            "Describe table columns, indexes, and constraints.",
            sql_describe_table_input_schema(scope),
            sql_describe_table_output_schema(catalog_scope),
            vec!["connection.read", "schema.describe"],
            false,
            false,
        ),
    ]
}

#[allow(clippy::too_many_arguments)]
fn sql_capability(
    plugin_id: &str,
    id: &str,
    description: &str,
    input_schema: Value,
    output_schema: Value,
    permissions: Vec<&str>,
    destructive: bool,
    supports_dry_run: bool,
) -> CapabilityDefinition {
    CapabilityDefinition {
        plugin_id: plugin_id.to_string(),
        id: id.to_string(),
        description: description.to_string(),
        input_schema,
        output_schema,
        permissions: permissions.into_iter().map(str::to_string).collect(),
        authorization: voidb_core::CapabilityAuthorizationMetadata::declared(),
        risk: if destructive {
            CapabilityRiskLevel::Mutating
        } else {
            CapabilityRiskLevel::ReadOnly
        },
        destructive,
        streaming: false,
        execution_mode: voidb_core::CapabilityExecutionMode::Stateless,
        session_handoff: None,
        connection_required: false,
        required_secret_classes: Vec::<CredentialClass>::new(),
        supports_dry_run,
        default_timeout_ms: Some(30_000),
    }
}

/// Attach standard generic SQL capabilities to a `CapabilityRouter`.
pub fn mount_generic_sql_router<B: GenericSqlBackend>(
    router: CapabilityRouter,
    backend: B,
) -> CapabilityRouter {
    let backend = Arc::new(backend);
    let b1 = Arc::clone(&backend);
    let b2 = Arc::clone(&backend);
    let b3 = Arc::clone(&backend);
    let b4 = Arc::clone(&backend);
    let b5 = Arc::clone(&backend);
    let b6 = Arc::clone(&backend);

    router
        .capability("query", move |inv, _grants| handle_query(&b1, inv))
        .capability("explain", move |inv, _grants| handle_explain(&b2, inv))
        .capability("exec", move |inv, _grants| handle_exec(&b3, inv))
        .capability("catalogs", move |inv, _grants| handle_catalogs(&b4, inv))
        .capability("tables", move |inv, _grants| handle_tables(&b5, inv))
        .capability("describe_table", move |inv, _grants| handle_describe_table(&b6, inv))
}

fn handle_query<B: GenericSqlBackend>(
    backend: &Arc<B>,
    invocation: CapabilityInvocation,
) -> Result<CapabilityInvocationResult, CapabilityError> {
    let sql = required_str(&invocation.input, "sql")?;
    if !sql_allows_read_only_query(&sql, backend.dialect()) {
        return Err(validation_error(
            "policy.read_only_violation",
            "query capability only allows read-oriented SQL; use exec for mutations.",
            json!({ "sql": sql }),
        ));
    }
    let scope = optional_scope(&invocation.input, backend.catalog_scope());
    let result = backend.query(scope.as_deref(), &sql)?;
    let row_count = result.rows.len();

    let output = json!({
        "contract_version": SQL_RESULT_CONTRACT_VERSION,
        "statements": [{
            "columns": result.columns,
            "rows": result.rows.into_iter().map(|r| r.into_iter().map(Value::from).collect::<Vec<_>>()).collect::<Vec<_>>(),
            "row_count": row_count,
        }],
        "row_limit": SQL_DEFAULT_ROW_LIMIT,
        "row_count": row_count,
        "source_row_count": row_count,
        "truncated": false,
        "cursor": null,
        "next_cursor": null,
        "batch_size": SQL_DEFAULT_ROW_LIMIT,
        "warnings": [],
    });

    Ok(CapabilityInvocationResult {
        invocation_id: invocation.id,
        status: InvocationStatus::Succeeded,
        output_summary: json!({ "row_count": row_count }),
        output,
        page: None,
    })
}

fn handle_explain<B: GenericSqlBackend>(
    backend: &Arc<B>,
    invocation: CapabilityInvocation,
) -> Result<CapabilityInvocationResult, CapabilityError> {
    let sql = required_str(&invocation.input, "sql")?;
    let scope = optional_scope(&invocation.input, backend.catalog_scope());
    let result = backend.explain(scope.as_deref(), &sql)?;
    let row_count = result.rows.len();

    let output = json!({
        "contract_version": SQL_RESULT_CONTRACT_VERSION,
        "statements": [{
            "columns": result.columns,
            "rows": result.rows.into_iter().map(|r| r.into_iter().map(Value::from).collect::<Vec<_>>()).collect::<Vec<_>>(),
            "row_count": row_count,
        }],
        "row_limit": SQL_DEFAULT_ROW_LIMIT,
        "row_count": row_count,
        "source_row_count": row_count,
        "truncated": false,
        "cursor": null,
        "next_cursor": null,
        "batch_size": SQL_DEFAULT_ROW_LIMIT,
        "warnings": [],
        "analyze": false,
        "format": "text",
        "dialect": backend.dialect().as_str(),
        "explained_statement_count": 1,
    });

    Ok(CapabilityInvocationResult {
        invocation_id: invocation.id,
        status: InvocationStatus::Succeeded,
        output_summary: json!({ "row_count": row_count, "dialect": backend.dialect().as_str() }),
        output,
        page: None,
    })
}

fn handle_exec<B: GenericSqlBackend>(
    backend: &Arc<B>,
    invocation: CapabilityInvocation,
) -> Result<CapabilityInvocationResult, CapabilityError> {
    let sql = required_str(&invocation.input, "sql")?;
    let dry_run = invocation.controls.dry_run;
    let scope = optional_scope(&invocation.input, backend.catalog_scope());

    if dry_run {
        let preview = sql_mutation_preview(
            &sql,
            backend.dialect(),
            invocation.controls.acknowledgement.is_some(),
        );
        return Ok(CapabilityInvocationResult {
            invocation_id: invocation.id,
            status: InvocationStatus::Succeeded,
            output_summary: preview.clone(),
            output: preview,
            page: None,
        });
    }

    let exec_res = backend.exec(scope.as_deref(), &sql)?;
    let gate = sql_mutation_gate(
        &sql,
        backend.dialect(),
        invocation.controls.acknowledgement.is_some(),
        false,
    );

    let output = json!({
        "contract_version": SQL_RESULT_CONTRACT_VERSION,
        "rows_affected": exec_res.rows_affected,
        "dry_run": false,
        "would_execute": true,
        "destructive": true,
        "operation": "exec",
        "statement_count": 1,
        "mutation_gate": gate,
        "statements": [],
        "row_limit": SQL_DEFAULT_ROW_LIMIT,
        "row_count": 0,
        "source_row_count": 0,
        "truncated": false,
        "cursor": null,
        "next_cursor": null,
        "batch_size": SQL_DEFAULT_ROW_LIMIT,
        "warnings": [],
    });

    Ok(CapabilityInvocationResult {
        invocation_id: invocation.id,
        status: InvocationStatus::Succeeded,
        output_summary: json!({ "rows_affected": exec_res.rows_affected }),
        output,
        page: None,
    })
}

fn handle_catalogs<B: GenericSqlBackend>(
    backend: &Arc<B>,
    invocation: CapabilityInvocation,
) -> Result<CapabilityInvocationResult, CapabilityError> {
    let items = backend.list_catalogs()?;
    let scope_kind = backend.catalog_scope().as_str();
    let entries = items
        .into_iter()
        .map(|item| sql_catalog_entry(&item.name, scope_kind, None, false, false))
        .collect::<Vec<_>>();

    let output = json!({
        "contract_version": SQL_RESULT_CONTRACT_VERSION,
        "scope": sql_scope(backend.catalog_scope(), None, None),
        "catalogs": entries,
        "next_cursor": null,
        "warnings": [],
    });

    Ok(CapabilityInvocationResult {
        invocation_id: invocation.id,
        status: InvocationStatus::Succeeded,
        output_summary: json!({ "count": output["catalogs"].as_array().map_or(0, Vec::len) }),
        output,
        page: None,
    })
}

fn handle_tables<B: GenericSqlBackend>(
    backend: &Arc<B>,
    invocation: CapabilityInvocation,
) -> Result<CapabilityInvocationResult, CapabilityError> {
    let scope = optional_scope(&invocation.input, backend.catalog_scope());
    let items = backend.list_tables(scope.as_deref())?;

    let relations = items
        .iter()
        .map(|item| {
            let rel_type = if item.is_view { "view" } else { "table" };
            sql_relation(
                &item.name,
                rel_type,
                rel_type,
                scope.as_deref(),
                None,
                item.row_count,
                item.comment.as_deref(),
            )
        })
        .collect::<Vec<_>>();

    let tables = items
        .iter()
        .filter(|t| !t.is_view)
        .map(|t| json!({ "name": t.name, "table_type": "table", "rows": t.row_count, "comment": t.comment }))
        .collect::<Vec<_>>();

    let views = items
        .iter()
        .filter(|t| t.is_view)
        .map(|t| t.name.clone())
        .collect::<Vec<_>>();

    let output = json!({
        "contract_version": SQL_RESULT_CONTRACT_VERSION,
        "scope": sql_scope(backend.catalog_scope(), scope.as_deref(), None),
        "capabilities": sql_introspection_capabilities(backend.introspection_support()),
        "tables": tables,
        "views": views,
        "relations": relations,
        "next_cursor": null,
        "warnings": [],
    });

    Ok(CapabilityInvocationResult {
        invocation_id: invocation.id,
        status: InvocationStatus::Succeeded,
        output_summary: json!({
            "table_count": output["tables"].as_array().map_or(0, Vec::len),
            "view_count": output["views"].as_array().map_or(0, Vec::len)
        }),
        output,
        page: None,
    })
}

fn handle_describe_table<B: GenericSqlBackend>(
    backend: &Arc<B>,
    invocation: CapabilityInvocation,
) -> Result<CapabilityInvocationResult, CapabilityError> {
    let table = required_str(&invocation.input, "table")?;
    let scope = optional_scope(&invocation.input, backend.catalog_scope());
    let desc = backend.describe_table(scope.as_deref(), &table)?;
    let dialect = backend.dialect();

    let columns_meta = desc
        .columns
        .iter()
        .enumerate()
        .map(|(idx, c)| sql_column_metadata(c, idx + 1, dialect))
        .collect::<Vec<_>>();

    let output = json!({
        "contract_version": SQL_RESULT_CONTRACT_VERSION,
        "scope": sql_scope(backend.catalog_scope(), scope.as_deref(), None),
        "capabilities": sql_introspection_capabilities(backend.introspection_support()),
        "table": desc.table_name,
        "columns": columns_meta,
        "indexes": [],
        "foreign_keys": [],
        "warnings": [],
    });

    Ok(CapabilityInvocationResult {
        invocation_id: invocation.id,
        status: InvocationStatus::Succeeded,
        output_summary: json!({
            "table": table,
            "column_count": output["columns"].as_array().map_or(0, Vec::len)
        }),
        output,
        page: None,
    })
}

fn required_str(input: &Value, field: &str) -> Result<String, CapabilityError> {
    input
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| {
            validation_error(
                "validation.missing_field",
                format!("Missing required field '{field}'"),
                json!({ "field": field }),
            )
        })
}

fn optional_scope(input: &Value, scope: SqlCatalogScope) -> Option<String> {
    match scope {
        SqlCatalogScope::Database => input.get("database").and_then(Value::as_str).map(str::to_string),
        SqlCatalogScope::Schema => input.get("schema").and_then(Value::as_str).map(str::to_string),
        SqlCatalogScope::LocalDatabase => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use voidb_core::{
        ActorRef, ActorType, InvocationConnectionTarget, InvocationControls,
    };

    struct MockSqlBackend {
        dialect: SqlDialect,
    }

    impl GenericSqlBackend for MockSqlBackend {
        fn dialect(&self) -> SqlDialect {
            self.dialect
        }

        fn query(
            &self,
            _scope: Option<&str>,
            _sql: &str,
        ) -> Result<SqlQueryResult, CapabilityError> {
            Ok(SqlQueryResult {
                columns: vec!["id".into(), "name".into()],
                rows: vec![
                    vec![SqlValue::Int(1), SqlValue::String("Alice".into())],
                    vec![SqlValue::Int(2), SqlValue::String("Bob".into())],
                ],
            })
        }

        fn exec(
            &self,
            _scope: Option<&str>,
            _sql: &str,
        ) -> Result<SqlExecResult, CapabilityError> {
            Ok(SqlExecResult { rows_affected: 2 })
        }

        fn list_catalogs(&self) -> Result<Vec<SqlCatalogItem>, CapabilityError> {
            Ok(vec![
                SqlCatalogItem {
                    name: "default".into(),
                    description: Some("Default database".into()),
                },
            ])
        }

        fn list_tables(&self, _scope: Option<&str>) -> Result<Vec<SqlTableItem>, CapabilityError> {
            Ok(vec![
                SqlTableItem {
                    name: "users".into(),
                    is_view: false,
                    row_count: Some(42),
                    comment: None,
                },
                SqlTableItem {
                    name: "active_users".into(),
                    is_view: true,
                    row_count: None,
                    comment: None,
                },
            ])
        }
    }

    fn sample_invocation(capability_id: &str, input: Value, dry_run: bool) -> CapabilityInvocation {
        CapabilityInvocation {
            id: format!("test-{capability_id}"),
            plugin_id: "mock_sql".into(),
            capability_id: capability_id.into(),
            connection: InvocationConnectionTarget::Stateless,
            input,
            controls: InvocationControls {
                dry_run,
                ..InvocationControls::default()
            },
            actor: Some(ActorRef {
                id: "test-agent".into(),
                actor_type: ActorType::Agent,
            }),
            requested_at: Utc::now(),
        }
    }

    #[test]
    fn generic_sql_query_succeeds_for_read_statements() {
        let backend = MockSqlBackend {
            dialect: SqlDialect::MySql,
        };
        let mut router = mount_generic_sql_router(
            CapabilityRouter::new("mock_sql"),
            backend,
        );

        let inv = sample_invocation("query", json!({ "sql": "SELECT * FROM users" }), false);
        let res = crate::ProcessPluginHandler::invoke(&mut router, inv, vec![]).expect("invoke query");
        assert_eq!(res.status, InvocationStatus::Succeeded);
        assert_eq!(res.output_summary["row_count"], 2);
    }

    #[test]
    fn generic_sql_query_blocks_mutating_statements() {
        let backend = MockSqlBackend {
            dialect: SqlDialect::MySql,
        };
        let mut router = mount_generic_sql_router(
            CapabilityRouter::new("mock_sql"),
            backend,
        );

        let inv = sample_invocation("query", json!({ "sql": "DROP TABLE users" }), false);
        let err = crate::ProcessPluginHandler::invoke(&mut router, inv, vec![]).expect_err("should reject mutation");
        assert_eq!(err.code, "policy.read_only_violation");
    }

    #[test]
    fn generic_sql_exec_supports_dry_run_preview() {
        let backend = MockSqlBackend {
            dialect: SqlDialect::MySql,
        };
        let mut router = mount_generic_sql_router(
            CapabilityRouter::new("mock_sql"),
            backend,
        );

        let inv = sample_invocation("exec", json!({ "sql": "DELETE FROM users WHERE id = 1" }), true);
        let res = crate::ProcessPluginHandler::invoke(&mut router, inv, vec![]).expect("dry run preview");
        assert_eq!(res.status, InvocationStatus::Succeeded);
        assert_eq!(res.output["dry_run"], true);
        assert_eq!(res.output["would_execute"], true);
    }

    #[test]
    fn generic_sql_exec_executes_mutation() {
        let backend = MockSqlBackend {
            dialect: SqlDialect::MySql,
        };
        let mut router = mount_generic_sql_router(
            CapabilityRouter::new("mock_sql"),
            backend,
        );

        let inv = sample_invocation("exec", json!({ "sql": "DELETE FROM users WHERE id = 1" }), false);
        let res = crate::ProcessPluginHandler::invoke(&mut router, inv, vec![]).expect("exec mutation");
        assert_eq!(res.status, InvocationStatus::Succeeded);
        assert_eq!(res.output["rows_affected"], 2);
    }

    #[test]
    fn generic_sql_lists_catalogs_and_tables() {
        let backend = MockSqlBackend {
            dialect: SqlDialect::MySql,
        };
        let mut router = mount_generic_sql_router(
            CapabilityRouter::new("mock_sql"),
            backend,
        );

        let inv = sample_invocation("catalogs", json!({}), false);
        let res = crate::ProcessPluginHandler::invoke(&mut router, inv, vec![]).expect("list catalogs");
        assert_eq!(res.output_summary["count"], 1);

        let inv2 = sample_invocation("tables", json!({ "database": "default" }), false);
        let res2 = crate::ProcessPluginHandler::invoke(&mut router, inv2, vec![]).expect("list tables");
        assert_eq!(res2.output_summary["table_count"], 1);
        assert_eq!(res2.output_summary["view_count"], 1);
    }
}

