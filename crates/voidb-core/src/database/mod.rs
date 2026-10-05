pub mod types;

use async_trait::async_trait;
use types::*;

use crate::connection::{ConnectionConfig, DatabaseType};
use crate::error::VoidbError;

/// The core trait that all database adapters must implement.
#[async_trait]
pub trait DatabaseAdapter: Send + Sync {
    /// Establish a connection.
    async fn connect(config: &ConnectionConfig) -> Result<Box<dyn DatabaseAdapter>, VoidbError>
    where
        Self: Sized;

    /// Test if the connection is alive.
    async fn ping(&self) -> Result<(), VoidbError>;

    /// Disconnect and clean up.
    async fn disconnect(&mut self) -> Result<(), VoidbError>;

    /// Get the database type.
    fn db_type(&self) -> DatabaseType;

    /// Get the connection ID (usually the config name).
    fn connection_id(&self) -> String;

    // --- Schema introspection ---

    /// List all databases/schemas accessible by this connection.
    async fn list_databases(&self) -> Result<Vec<String>, VoidbError>;

    /// List tables in the given database.
    async fn list_tables(&self, database: &str) -> Result<Vec<TableInfo>, VoidbError>;

    /// List views in the given database.
    async fn list_views(&self, database: &str) -> Result<Vec<ViewInfo>, VoidbError>;

    /// Get full schema information for a table.
    async fn describe_table(
        &self,
        database: &str,
        table: &str,
    ) -> Result<TableSchema, VoidbError>;

    /// Get indexes for a table.
    async fn list_indexes(
        &self,
        database: &str,
        table: &str,
    ) -> Result<Vec<IndexInfo>, VoidbError>;

    /// Get foreign keys for a table.
    async fn list_foreign_keys(
        &self,
        database: &str,
        table: &str,
    ) -> Result<Vec<ForeignKeyInfo>, VoidbError>;

    // --- Data operations ---

    /// Execute a SELECT query with pagination.
    async fn query_rows(
        &self,
        sql: &str,
        params: &[QueryParam],
        offset: u64,
        limit: u64,
    ) -> Result<QueryResult, VoidbError>;

    /// Execute arbitrary SQL (INSERT, UPDATE, DELETE, DDL).
    async fn execute(
        &self,
        sql: &str,
        params: &[QueryParam],
    ) -> Result<ExecuteResult, VoidbError>;

    /// Execute arbitrary SQL and return result set (for user queries in editor).
    /// If database is not empty, it will be selected before executing the query.
    async fn execute_query(&self, sql: &str, database: Option<&str>) -> Result<QueryResult, VoidbError>;

    /// Execute multiple SQL statements in sequence on the same connection.
    /// This preserves connection context (USE statements, transactions, etc.).
    /// Returns a vector of results, one for each statement.
    async fn execute_statements(&self, statements: &[String], initial_database: Option<&str>) -> Result<Vec<QueryResult>, VoidbError> {
        // Default implementation: execute each statement independently (no context sharing)
        let mut results = Vec::new();
        for statement in statements {
            let result = self.execute_query(statement, initial_database).await?;
            results.push(result);
        }
        Ok(results)
    }

    /// Get the total row count for a table (for pagination).
    async fn count_rows(
        &self,
        database: &str,
        table: &str,
        filter: Option<&str>,
    ) -> Result<u64, VoidbError>;

    // --- DDL operations ---

    /// Generate CREATE TABLE SQL for the given schema.
    fn generate_create_table_sql(&self, schema: &TableSchema) -> String;

    /// Get the CREATE TABLE statement for an existing table.
    async fn get_create_table_sql(&self, database: &str, table: &str) -> Result<String, VoidbError>;

    /// Quote an identifier according to database dialect.
    fn quote_identifier(&self, name: &str) -> String;
}
