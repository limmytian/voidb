use serde::{Deserialize, Serialize};
use std::time::Duration;

/// A database-agnostic cell value.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CellValue {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Text(String),
    Blob(Vec<u8>),
    DateTime(String), // ISO 8601 format
    Date(String),
    Time(String),
    Json(String),
    Uuid(String),
    /// Unknown type that couldn't be decoded (stores type name)
    Unknown(String),
}

impl CellValue {
    /// Format the cell value for display in the grid.
    pub fn display(&self) -> String {
        match self {
            Self::Null => "NULL".to_string(),
            Self::Bool(b) => b.to_string(),
            Self::Int(i) => i.to_string(),
            Self::Float(f) => f.to_string(),
            Self::Text(s) => s.clone(),
            Self::Blob(b) => format!("[BLOB {} bytes]", b.len()),
            Self::DateTime(s) | Self::Date(s) | Self::Time(s) => s.clone(),
            Self::Json(s) => s.clone(),
            Self::Uuid(s) => s.clone(),
            Self::Unknown(type_name) => format!("[UNKNOWN: {}]", type_name),
        }
    }
}

/// A single row is a vector of CellValues.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Row {
    pub values: Vec<CellValue>,
}

/// Query result: column definitions plus rows.
#[derive(Debug, Clone)]
pub struct QueryResult {
    pub columns: Vec<ColumnInfo>,
    pub rows: Vec<Row>,
    pub execution_time: Duration,
    pub rows_affected: Option<u64>,
}

/// Column metadata.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ColumnInfo {
    pub name: String,
    pub data_type: String,
    pub nullable: bool,
    pub is_primary_key: bool,
    pub default_value: Option<String>,
    pub max_length: Option<u64>,
    pub extra: String,
}

/// Table metadata for introspection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TableInfo {
    pub name: String,
    pub table_type: String, // "TABLE", "VIEW", etc.
    pub comment: Option<String>,
    pub row_count: Option<u64>,
}

/// View metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViewInfo {
    pub name: String,
    pub definition: Option<String>,
}

/// Complete table schema for introspection and design.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TableSchema {
    pub database: String,
    pub table_name: String,
    pub columns: Vec<ColumnInfo>,
    pub indexes: Vec<IndexInfo>,
    pub foreign_keys: Vec<ForeignKeyInfo>,
    pub engine: Option<String>,
    pub comment: Option<String>,
}

/// Index metadata.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IndexInfo {
    pub name: String,
    pub columns: Vec<String>,
    pub unique: bool,
    pub index_type: String, // BTREE, HASH, etc.
}

/// Foreign key metadata.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ForeignKeyInfo {
    pub name: String,
    pub columns: Vec<String>,
    pub referenced_table: String,
    pub referenced_columns: Vec<String>,
    pub on_update: String,
    pub on_delete: String,
}

/// Result of an execute operation (INSERT, UPDATE, DELETE, DDL).
#[derive(Debug, Clone)]
pub struct ExecuteResult {
    pub rows_affected: u64,
    pub last_insert_id: Option<i64>,
}

/// Query parameter for prepared statements.
#[derive(Debug, Clone)]
pub enum QueryParam {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Text(String),
    Blob(Vec<u8>),
}
