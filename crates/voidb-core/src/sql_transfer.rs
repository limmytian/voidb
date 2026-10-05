//! Shared bounded SQL import/export helpers.
//!
//! Plugins retain ownership of target connections and execution. This module
//! only defines schemas, bounded file parsing/encoding, and dialect-safe SQL
//! construction from already-authorized inputs.

use std::io::{BufRead, BufReader, Read};

use serde_json::{Map, Value, json};

use crate::{SqlDialect, SqlInputScope};

pub const SQL_IMPORT_DEFAULT_BATCH_ROWS: usize = 100;
pub const SQL_IMPORT_MAX_BATCH_ROWS: usize = 1_000;
pub const SQL_IMPORT_MAX_JSON_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SqlDataFormat {
    Csv,
    Json,
    Jsonl,
}

impl SqlDataFormat {
    pub fn parse(value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "csv" => Ok(Self::Csv),
            "json" => Ok(Self::Json),
            "jsonl" | "ndjson" => Ok(Self::Jsonl),
            _ => Err("format must be csv, json, or jsonl".to_string()),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Csv => "csv",
            Self::Json => "json",
            Self::Jsonl => "jsonl",
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SqlExportChunk {
    pub columns: Vec<String>,
    pub rows: Vec<Value>,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SqlImportPage {
    pub columns: Vec<String>,
    pub rows: Vec<Value>,
    pub cursor: usize,
    pub truncated: bool,
}

impl SqlImportPage {
    pub fn next_cursor(&self) -> Option<String> {
        self.truncated
            .then(|| self.cursor.saturating_add(self.rows.len()).to_string())
    }
}

pub fn sql_export_input_schema(scope: SqlInputScope) -> Value {
    let mut schema = crate::sql_text_input_schema("Read-oriented SQL to export.", scope);
    let properties = schema["properties"]
        .as_object_mut()
        .expect("SQL export schema properties");
    properties.insert(
        "format".into(),
        json!({ "type": "string", "enum": ["csv", "json", "jsonl"], "default": "jsonl" }),
    );
    properties.insert(
        "include_header".into(),
        json!({ "type": "boolean", "default": true }),
    );
    properties.insert(
        "local_root".into(),
        json!({
            "type": "string",
            "minLength": 1,
            "description": "Human-approved absolute output root; never returned."
        }),
    );
    properties.insert(
        "local_path".into(),
        json!({
            "type": "string",
            "minLength": 1,
            "description": "New output file relative to local_root. Existing files are never replaced."
        }),
    );
    schema
}

pub fn sql_export_output_schema() -> Value {
    json!({
        "type": "object",
        "required": [
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
            "progress"
        ],
        "properties": {
            "format": { "type": "string", "enum": ["csv", "json", "jsonl"] },
            "columns": { "type": "array", "items": { "type": "string" } },
            "row_count": { "type": "integer", "minimum": 0 },
            "bytes": { "type": "integer", "minimum": 0 },
            "truncated": { "type": "boolean" },
            "cursor": { "type": ["string", "null"] },
            "next_cursor": { "type": ["string", "null"] },
            "destination_written": { "type": "boolean" },
            "local_scope_id": { "type": ["string", "null"] },
            "preview": { "type": ["string", "null"] },
            "progress": {
                "type": "object",
                "required": ["rows_completed", "bytes_completed", "terminal"],
                "properties": {
                    "rows_completed": { "type": "integer", "minimum": 0 },
                    "bytes_completed": { "type": "integer", "minimum": 0 },
                    "terminal": { "type": "boolean" }
                },
                "additionalProperties": false
            }
        },
        "additionalProperties": false
    })
}

/// Wrap one read-only statement in a database-side page.
///
/// The extra row is intentional: callers use it to determine whether a next
/// cursor exists without asking a driver to materialize the entire result.
pub fn sql_export_page_query(
    sql: &str,
    dialect: SqlDialect,
    cursor: usize,
    limit: usize,
) -> Result<String, String> {
    if limit == 0 || limit > crate::SQL_MAX_ROW_LIMIT {
        return Err(format!(
            "export page limit must be between 1 and {}",
            crate::SQL_MAX_ROW_LIMIT
        ));
    }
    if crate::sql_statement_count(sql, dialect) != 1 {
        return Err("export accepts exactly one SQL statement".to_string());
    }
    if !crate::sql_allows_read_only_query(sql, dialect) {
        return Err("export only accepts read-oriented SQL".to_string());
    }
    let sql = sql.trim().trim_end_matches(';').trim();
    if sql.is_empty() {
        return Err("export SQL must not be empty".to_string());
    }
    Ok(format!(
        "SELECT * FROM ({sql}) AS voidb_export_page LIMIT {} OFFSET {cursor}",
        limit.saturating_add(1)
    ))
}

pub fn sql_import_input_schema(scope: SqlInputScope) -> Value {
    let mut schema = crate::sql_describe_table_input_schema(scope);
    let required = schema["required"]
        .as_array_mut()
        .expect("SQL import required fields");
    required.extend(
        ["format", "local_root", "local_path"]
            .into_iter()
            .map(|field| json!(field)),
    );
    let properties = schema["properties"]
        .as_object_mut()
        .expect("SQL import schema properties");
    properties.insert(
        "format".into(),
        json!({ "type": "string", "enum": ["csv", "json", "jsonl"] }),
    );
    properties.insert(
        "local_root".into(),
        json!({
            "type": "string",
            "minLength": 1,
            "description": "Human-approved absolute source root; never returned."
        }),
    );
    properties.insert(
        "local_path".into(),
        json!({
            "type": "string",
            "minLength": 1,
            "description": "Existing source file relative to local_root."
        }),
    );
    properties.insert(
        "has_header".into(),
        json!({ "type": "boolean", "default": true }),
    );
    properties.insert(
        "columns".into(),
        json!({
            "type": "array",
            "items": { "type": "string", "minLength": 1 },
            "description": "Required for headerless CSV; otherwise overrides source column order."
        }),
    );
    properties.insert(
        "mode".into(),
        json!({ "type": "string", "enum": ["append"], "default": "append" }),
    );
    properties.insert(
        "row_error_policy".into(),
        json!({ "type": "string", "enum": ["abort"], "default": "abort" }),
    );
    schema
}

pub fn sql_import_output_schema(apply: bool) -> Value {
    let mut required = vec![
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
    ];
    if apply {
        required.push("rows_inserted");
    }
    let mut properties = Map::new();
    properties.insert("dry_run".into(), json!({ "type": "boolean" }));
    properties.insert("would_execute".into(), json!({ "type": "boolean" }));
    properties.insert("destructive".into(), json!({ "type": "boolean" }));
    properties.insert("operation".into(), json!({ "type": "string" }));
    properties.insert(
        "format".into(),
        json!({ "type": "string", "enum": ["csv", "json", "jsonl"] }),
    );
    properties.insert("table".into(), json!({ "type": "string" }));
    properties.insert(
        "columns".into(),
        json!({ "type": "array", "items": { "type": "string" } }),
    );
    properties.insert(
        "row_count".into(),
        json!({ "type": "integer", "minimum": 0 }),
    );
    properties.insert(
        "source_file_bytes".into(),
        json!({ "type": "integer", "minimum": 0 }),
    );
    properties.insert("truncated".into(), json!({ "type": "boolean" }));
    properties.insert("cursor".into(), json!({ "type": ["string", "null"] }));
    properties.insert("next_cursor".into(), json!({ "type": ["string", "null"] }));
    properties.insert("transaction_scope".into(), json!({ "type": "string" }));
    properties.insert("row_error_policy".into(), json!({ "type": "string" }));
    properties.insert("local_scope_id".into(), json!({ "type": "string" }));
    properties.insert("checks".into(), json!({ "type": "array" }));
    properties.insert("warnings".into(), json!({ "type": "array" }));
    if apply {
        properties.insert(
            "rows_inserted".into(),
            json!({ "type": "integer", "minimum": 0 }),
        );
    }
    json!({
        "type": "object",
        "required": required,
        "properties": properties,
        "additionalProperties": false
    })
}

pub fn encode_sql_export(
    query_output: &Value,
    format: SqlDataFormat,
    include_header: bool,
) -> Result<SqlExportChunk, String> {
    let statements = query_output["statements"]
        .as_array()
        .ok_or_else(|| "query output is missing statements".to_string())?;
    let mut columns = Vec::new();
    let mut rows = Vec::new();
    for statement in statements {
        if statement["kind"] != "select" {
            continue;
        }
        let statement_columns = statement["columns"]
            .as_array()
            .ok_or_else(|| "select statement is missing columns".to_string())?
            .iter()
            .map(|column| {
                column["name"]
                    .as_str()
                    .map(str::to_string)
                    .ok_or_else(|| "column metadata is missing name".to_string())
            })
            .collect::<Result<Vec<_>, _>>()?;
        if columns.is_empty() {
            columns = statement_columns;
        } else if columns != statement_columns {
            return Err("multi-statement export requires identical column shapes".to_string());
        }
        rows.extend(
            statement["rows"]
                .as_array()
                .ok_or_else(|| "select statement is missing rows".to_string())?
                .iter()
                .cloned(),
        );
    }

    let bytes = match format {
        SqlDataFormat::Csv => encode_csv(&columns, &rows, include_header)?,
        SqlDataFormat::Json => {
            serde_json::to_vec_pretty(&rows).map_err(|error| error.to_string())?
        }
        SqlDataFormat::Jsonl => {
            let mut output = Vec::new();
            for row in &rows {
                serde_json::to_writer(&mut output, row).map_err(|error| error.to_string())?;
                output.push(b'\n');
            }
            output
        }
    };
    Ok(SqlExportChunk {
        columns,
        rows,
        bytes,
    })
}

pub fn parse_sql_import_page<R: Read>(
    reader: R,
    source_file_bytes: u64,
    format: SqlDataFormat,
    has_header: bool,
    requested_columns: Option<&[String]>,
    cursor: usize,
    limit: usize,
) -> Result<SqlImportPage, String> {
    if limit == 0 || limit > SQL_IMPORT_MAX_BATCH_ROWS {
        return Err(format!(
            "import batch limit must be between 1 and {SQL_IMPORT_MAX_BATCH_ROWS}"
        ));
    }
    match format {
        SqlDataFormat::Csv => parse_csv_page(reader, has_header, requested_columns, cursor, limit),
        SqlDataFormat::Jsonl => parse_jsonl_page(reader, requested_columns, cursor, limit),
        SqlDataFormat::Json => {
            if source_file_bytes > SQL_IMPORT_MAX_JSON_BYTES {
                return Err(format!(
                    "JSON array imports are limited to {SQL_IMPORT_MAX_JSON_BYTES} bytes; use JSONL for larger inputs"
                ));
            }
            parse_json_page(reader, requested_columns, cursor, limit)
        }
    }
}

pub fn build_sql_import_batch(
    dialect: SqlDialect,
    database: Option<&str>,
    schema: Option<&str>,
    table: &str,
    columns: &[String],
    rows: &[Value],
) -> Result<String, String> {
    if columns.is_empty() {
        return Err("import requires at least one column".to_string());
    }
    if rows.is_empty() {
        return Ok(String::new());
    }
    let target = match dialect {
        SqlDialect::MySql => database
            .map(|database| {
                format!(
                    "{}.{}",
                    quote_identifier(database, dialect),
                    quote_identifier(table, dialect)
                )
            })
            .unwrap_or_else(|| quote_identifier(table, dialect)),
        SqlDialect::Postgres => schema
            .map(|schema| {
                format!(
                    "{}.{}",
                    quote_identifier(schema, dialect),
                    quote_identifier(table, dialect)
                )
            })
            .unwrap_or_else(|| quote_identifier(table, dialect)),
        SqlDialect::Sqlite | SqlDialect::DuckDb => quote_identifier(table, dialect),
    };
    let quoted_columns = columns
        .iter()
        .map(|column| quote_identifier(column, dialect))
        .collect::<Vec<_>>();
    let mut value_groups = Vec::with_capacity(rows.len());
    for row in rows {
        let object = row
            .as_object()
            .ok_or_else(|| "import rows must be JSON objects".to_string())?;
        let values = columns
            .iter()
            .map(|source_name| {
                object
                    .get(source_name)
                    .map(sql_literal)
                    .unwrap_or_else(|| "NULL".to_string())
            })
            .collect::<Vec<_>>();
        value_groups.push(format!("({})", values.join(", ")));
    }
    Ok(format!(
        "BEGIN;\nINSERT INTO {target} ({}) VALUES\n{};\nCOMMIT;",
        quoted_columns.join(", "),
        value_groups.join(",\n")
    ))
}

fn encode_csv(columns: &[String], rows: &[Value], include_header: bool) -> Result<Vec<u8>, String> {
    let mut writer = csv::WriterBuilder::new()
        .has_headers(false)
        .from_writer(Vec::new());
    if include_header {
        writer
            .write_record(columns)
            .map_err(|error| error.to_string())?;
    }
    for row in rows {
        let object = row
            .as_object()
            .ok_or_else(|| "export rows must be JSON objects".to_string())?;
        writer
            .write_record(columns.iter().map(|column| csv_value(object.get(column))))
            .map_err(|error| error.to_string())?;
    }
    writer
        .into_inner()
        .map_err(|error| error.into_error().to_string())
}

fn csv_value(value: Option<&Value>) -> String {
    match value {
        None | Some(Value::Null) => String::new(),
        Some(Value::String(value)) => value.clone(),
        Some(value) => value.to_string(),
    }
}

fn parse_csv_page<R: Read>(
    reader: R,
    has_header: bool,
    requested_columns: Option<&[String]>,
    cursor: usize,
    limit: usize,
) -> Result<SqlImportPage, String> {
    let mut reader = csv::ReaderBuilder::new()
        .has_headers(has_header)
        .from_reader(reader);
    let source_columns = if has_header {
        reader
            .headers()
            .map_err(|error| error.to_string())?
            .iter()
            .map(str::to_string)
            .collect::<Vec<_>>()
    } else {
        requested_columns
            .filter(|columns| !columns.is_empty())
            .map(|columns| columns.to_vec())
            .ok_or_else(|| "headerless CSV imports require columns".to_string())?
    };
    let columns = requested_columns
        .filter(|columns| !columns.is_empty())
        .map(|columns| columns.to_vec())
        .unwrap_or(source_columns);
    let mut rows = Vec::new();
    for record in reader.records().skip(cursor).take(limit.saturating_add(1)) {
        let record = record.map_err(|error| error.to_string())?;
        if record.len() != columns.len() {
            return Err(format!(
                "CSV row has {} fields but {} columns were declared",
                record.len(),
                columns.len()
            ));
        }
        let object = columns
            .iter()
            .zip(record.iter())
            .map(|(column, value)| (column.clone(), Value::String(value.to_string())))
            .collect::<Map<_, _>>();
        rows.push(Value::Object(object));
    }
    let truncated = rows.len() > limit;
    rows.truncate(limit);
    Ok(SqlImportPage {
        columns,
        rows,
        cursor,
        truncated,
    })
}

fn parse_jsonl_page<R: Read>(
    reader: R,
    requested_columns: Option<&[String]>,
    cursor: usize,
    limit: usize,
) -> Result<SqlImportPage, String> {
    let mut rows = Vec::new();
    for line in BufReader::new(reader)
        .lines()
        .skip(cursor)
        .take(limit.saturating_add(1))
    {
        let line = line.map_err(|error| error.to_string())?;
        let row = serde_json::from_str::<Value>(&line).map_err(|error| error.to_string())?;
        if !row.is_object() {
            return Err("JSONL import rows must be objects".to_string());
        }
        rows.push(row);
    }
    let truncated = rows.len() > limit;
    rows.truncate(limit);
    let columns = import_columns(&rows, requested_columns)?;
    Ok(SqlImportPage {
        columns,
        rows,
        cursor,
        truncated,
    })
}

fn parse_json_page<R: Read>(
    reader: R,
    requested_columns: Option<&[String]>,
    cursor: usize,
    limit: usize,
) -> Result<SqlImportPage, String> {
    let value = serde_json::from_reader::<_, Value>(reader).map_err(|error| error.to_string())?;
    let rows = value
        .as_array()
        .ok_or_else(|| "JSON import must contain an array of objects".to_string())?;
    if rows.iter().any(|row| !row.is_object()) {
        return Err("JSON import rows must be objects".to_string());
    }
    let page_rows = rows
        .iter()
        .skip(cursor)
        .take(limit)
        .cloned()
        .collect::<Vec<_>>();
    let columns = import_columns(&page_rows, requested_columns)?;
    Ok(SqlImportPage {
        columns,
        rows: page_rows,
        cursor,
        truncated: cursor.saturating_add(limit) < rows.len(),
    })
}

fn import_columns(
    rows: &[Value],
    requested_columns: Option<&[String]>,
) -> Result<Vec<String>, String> {
    if let Some(columns) = requested_columns.filter(|columns| !columns.is_empty()) {
        return Ok(columns.to_vec());
    }
    rows.first()
        .and_then(Value::as_object)
        .map(|object| object.keys().cloned().collect())
        .or_else(|| rows.is_empty().then(Vec::new))
        .ok_or_else(|| "import rows must be objects".to_string())
}

fn quote_identifier(identifier: &str, dialect: SqlDialect) -> String {
    match dialect {
        SqlDialect::MySql => format!("`{}`", identifier.replace('`', "``")),
        SqlDialect::DuckDb | SqlDialect::Postgres | SqlDialect::Sqlite => {
            format!("\"{}\"", identifier.replace('"', "\"\""))
        }
    }
}

fn sql_literal(value: &Value) -> String {
    match value {
        Value::Null => "NULL".to_string(),
        Value::Bool(value) => {
            if *value {
                "TRUE".to_string()
            } else {
                "FALSE".to_string()
            }
        }
        Value::Number(value) => value.to_string(),
        Value::String(value) => format!("'{}'", value.replace('\'', "''")),
        Value::Array(_) | Value::Object(_) => {
            format!("'{}'", value.to_string().replace('\'', "''"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_import_pages_without_buffering_all_rows() {
        let input = b"id,name\n1,Ada\n2,Grace\n3,Linus\n";
        let page = parse_sql_import_page(
            &input[..],
            input.len() as u64,
            SqlDataFormat::Csv,
            true,
            None,
            0,
            2,
        )
        .unwrap();

        assert_eq!(page.columns, vec!["id", "name"]);
        assert_eq!(page.rows.len(), 2);
        assert!(page.truncated);
        assert_eq!(page.next_cursor().as_deref(), Some("2"));
    }

    #[test]
    fn insert_batch_quotes_identifiers_and_values() {
        let sql = build_sql_import_batch(
            SqlDialect::Postgres,
            None,
            Some("public"),
            "users",
            &["name".into()],
            &[json!({ "name": "O'Brien" })],
        )
        .unwrap();

        assert!(sql.contains("INSERT INTO \"public\".\"users\""));
        assert!(sql.contains("'O''Brien'"));
        assert!(sql.starts_with("BEGIN;"));
        assert!(sql.ends_with("COMMIT;"));
    }

    #[test]
    fn export_query_pushes_down_a_bounded_probe_page() {
        let query = sql_export_page_query(
            "select id from users order by id;",
            SqlDialect::Postgres,
            200,
            100,
        )
        .unwrap();

        assert_eq!(
            query,
            "SELECT * FROM (select id from users order by id) AS voidb_export_page LIMIT 101 OFFSET 200"
        );
        assert!(sql_export_page_query("select 1; select 2", SqlDialect::Sqlite, 0, 10).is_err());
        assert!(sql_export_page_query("delete from users", SqlDialect::MySql, 0, 10).is_err());
    }
}
