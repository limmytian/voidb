use std::io::Write;

use crate::database::types::{CellValue, ColumnInfo, Row};
use crate::error::VoidbError;

/// Supported export formats.
#[derive(Debug, Clone, PartialEq)]
pub enum ExportFormat {
    Csv,
    Json,
    Sql,
}

/// Export rows to CSV format.
/// Returns the number of rows written.
pub fn export_csv<W: Write>(
    writer: W,
    columns: &[ColumnInfo],
    rows: &[Row],
) -> Result<u64, VoidbError> {
    let mut wtr = csv::Writer::from_writer(writer);

    // Write header
    let headers: Vec<&str> = columns.iter().map(|c| c.name.as_str()).collect();
    wtr.write_record(&headers)
        .map_err(|e| VoidbError::Other(format!("CSV write header error: {}", e)))?;

    // Write data rows
    for row in rows {
        let record: Vec<String> = row
            .values
            .iter()
            .map(|v| match v {
                CellValue::Null => String::new(),
                other => other.display(),
            })
            .collect();
        wtr.write_record(&record)
            .map_err(|e| VoidbError::Other(format!("CSV write row error: {}", e)))?;
    }

    wtr.flush()
        .map_err(|e| VoidbError::Other(format!("CSV flush error: {}", e)))?;

    Ok(rows.len() as u64)
}

/// Export rows to JSON format (array of objects).
/// Returns the number of rows written.
pub fn export_json<W: Write>(
    mut writer: W,
    columns: &[ColumnInfo],
    rows: &[Row],
) -> Result<u64, VoidbError> {
    let mut objects = Vec::with_capacity(rows.len());

    for row in rows {
        let mut obj = serde_json::Map::new();
        for (i, value) in row.values.iter().enumerate() {
            let col_name = columns
                .get(i)
                .map(|c| c.name.clone())
                .unwrap_or_else(|| format!("col_{}", i));

            let json_value = cell_value_to_json(value);
            obj.insert(col_name, json_value);
        }
        objects.push(serde_json::Value::Object(obj));
    }

    let json = serde_json::to_string_pretty(&objects)
        .map_err(|e| VoidbError::Other(format!("JSON serialize error: {}", e)))?;

    writer
        .write_all(json.as_bytes())
        .map_err(|e| VoidbError::Other(format!("JSON write error: {}", e)))?;

    Ok(rows.len() as u64)
}

/// Export rows as INSERT statements.
/// Returns the number of rows written.
pub fn export_sql<W: Write>(
    mut writer: W,
    table_name: &str,
    columns: &[ColumnInfo],
    rows: &[Row],
    quote_fn: &dyn Fn(&str) -> String,
) -> Result<u64, VoidbError> {
    if rows.is_empty() {
        return Ok(0);
    }

    let col_names: Vec<String> = columns.iter().map(|c| quote_fn(&c.name)).collect();
    let col_list = col_names.join(", ");
    let quoted_table = quote_fn(table_name);

    let batch_size = 100;
    let mut count = 0u64;

    for chunk in rows.chunks(batch_size) {
        writeln!(writer, "INSERT INTO {} ({}) VALUES", quoted_table, col_list)
            .map_err(|e| VoidbError::Other(format!("SQL write error: {}", e)))?;

        for (i, row) in chunk.iter().enumerate() {
            let values: Vec<String> = row.values.iter().map(cell_value_to_sql).collect();
            let separator = if i + 1 < chunk.len() { ",\n" } else { ";\n" };
            write!(writer, "  ({}){}", values.join(", "), separator)
                .map_err(|e| VoidbError::Other(format!("SQL write error: {}", e)))?;
        }

        count += chunk.len() as u64;
    }

    writer
        .flush()
        .map_err(|e| VoidbError::Other(format!("SQL flush error: {}", e)))?;

    Ok(count)
}

fn cell_value_to_json(value: &CellValue) -> serde_json::Value {
    match value {
        CellValue::Null => serde_json::Value::Null,
        CellValue::Bool(b) => serde_json::Value::Bool(*b),
        CellValue::Int(i) => serde_json::Value::Number((*i).into()),
        CellValue::Float(f) => {
            serde_json::Number::from_f64(*f)
                .map(serde_json::Value::Number)
                .unwrap_or(serde_json::Value::Null)
        }
        CellValue::Text(s) => serde_json::Value::String(s.clone()),
        CellValue::Blob(b) => {
            use serde_json::Value;
            Value::String(format!("base64:{}", base64_encode(b)))
        }
        CellValue::DateTime(s) | CellValue::Date(s) | CellValue::Time(s) => {
            serde_json::Value::String(s.clone())
        }
        CellValue::Json(s) => {
            serde_json::from_str(s).unwrap_or_else(|_| serde_json::Value::String(s.clone()))
        }
        CellValue::Uuid(s) => serde_json::Value::String(s.clone()),
        CellValue::Unknown(type_name) => {
            serde_json::Value::String(format!("[UNKNOWN: {}]", type_name))
        }
    }
}

fn cell_value_to_sql(value: &CellValue) -> String {
    match value {
        CellValue::Null => "NULL".to_string(),
        CellValue::Bool(b) => if *b { "TRUE" } else { "FALSE" }.to_string(),
        CellValue::Int(i) => i.to_string(),
        CellValue::Float(f) => f.to_string(),
        CellValue::Text(s) => format!("'{}'", escape_sql_string(s)),
        CellValue::Blob(b) => format!("X'{}'", hex_encode(b)),
        CellValue::DateTime(s) | CellValue::Date(s) | CellValue::Time(s) => {
            format!("'{}'", escape_sql_string(s))
        }
        CellValue::Json(s) => format!("'{}'", escape_sql_string(s)),
        CellValue::Uuid(s) => format!("'{}'", escape_sql_string(s)),
        CellValue::Unknown(type_name) => {
            format!("'[UNKNOWN: {}]'", escape_sql_string(type_name))
        }
    }
}

fn escape_sql_string(s: &str) -> String {
    s.replace('\'', "''")
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02X}", b)).collect()
}

fn base64_encode(bytes: &[u8]) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut result = String::new();
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let triple = (b0 << 16) | (b1 << 8) | b2;

        result.push(CHARS[((triple >> 18) & 0x3F) as usize] as char);
        result.push(CHARS[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARS[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
        if chunk.len() > 2 {
            result.push(CHARS[(triple & 0x3F) as usize] as char);
        } else {
            result.push('=');
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_columns(names: &[&str]) -> Vec<ColumnInfo> {
        names
            .iter()
            .map(|name| ColumnInfo {
                name: name.to_string(),
                data_type: "TEXT".to_string(),
                nullable: true,
                is_primary_key: false,
                default_value: None,
                max_length: None,
                extra: String::new(),
            })
            .collect()
    }

    fn make_row(values: Vec<CellValue>) -> Row {
        Row { values }
    }

    #[test]
    fn test_export_csv_basic() {
        let columns = make_columns(&["id", "name", "email"]);
        let rows = vec![
            make_row(vec![
                CellValue::Int(1),
                CellValue::Text("Alice".to_string()),
                CellValue::Text("alice@example.com".to_string()),
            ]),
            make_row(vec![
                CellValue::Int(2),
                CellValue::Text("Bob".to_string()),
                CellValue::Null,
            ]),
        ];

        let mut buf = Vec::new();
        let count = export_csv(&mut buf, &columns, &rows).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert_eq!(count, 2);
        assert!(output.starts_with("id,name,email\n"));
        assert!(output.contains("1,Alice,alice@example.com"));
        assert!(output.contains("2,Bob,"));
    }

    #[test]
    fn test_export_csv_special_chars() {
        let columns = make_columns(&["data"]);
        let rows = vec![make_row(vec![CellValue::Text(
            "hello, \"world\"".to_string(),
        )])];

        let mut buf = Vec::new();
        export_csv(&mut buf, &columns, &rows).unwrap();
        let output = String::from_utf8(buf).unwrap();

        // CSV should properly quote/escape the field
        assert!(output.contains("\"hello, \"\"world\"\"\""));
    }

    #[test]
    fn test_export_csv_null_handling() {
        let columns = make_columns(&["value"]);
        let rows = vec![make_row(vec![CellValue::Null])];

        let mut buf = Vec::new();
        export_csv(&mut buf, &columns, &rows).unwrap();
        let output = String::from_utf8(buf).unwrap();

        // NULL should be written as empty field in CSV
        // The csv crate will parse it back as an empty string
        let mut rdr = csv::ReaderBuilder::new().from_reader(output.as_bytes());
        let record = rdr.records().next().unwrap().unwrap();
        assert_eq!(&record[0], "");
    }

    #[test]
    fn test_export_json_basic() {
        let columns = make_columns(&["id", "name"]);
        let rows = vec![
            make_row(vec![
                CellValue::Int(1),
                CellValue::Text("Alice".to_string()),
            ]),
            make_row(vec![CellValue::Int(2), CellValue::Null]),
        ];

        let mut buf = Vec::new();
        let count = export_json(&mut buf, &columns, &rows).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert_eq!(count, 2);

        let parsed: serde_json::Value = serde_json::from_str(&output).unwrap();
        let arr = parsed.as_array().unwrap();
        assert_eq!(arr.len(), 2);
        assert_eq!(arr[0]["id"], 1);
        assert_eq!(arr[0]["name"], "Alice");
        assert!(arr[1]["name"].is_null());
    }

    #[test]
    fn test_export_sql_basic() {
        let columns = make_columns(&["id", "name"]);
        let rows = vec![
            make_row(vec![
                CellValue::Int(1),
                CellValue::Text("Alice".to_string()),
            ]),
            make_row(vec![
                CellValue::Int(2),
                CellValue::Text("Bob".to_string()),
            ]),
        ];

        let quote = |s: &str| format!("`{}`", s);
        let mut buf = Vec::new();
        let count = export_sql(&mut buf, "users", &columns, &rows, &quote).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert_eq!(count, 2);
        assert!(output.contains("INSERT INTO `users` (`id`, `name`) VALUES"));
        assert!(output.contains("(1, 'Alice')"));
        assert!(output.contains("(2, 'Bob')"));
    }

    #[test]
    fn test_export_sql_escaping() {
        let columns = make_columns(&["name"]);
        let rows = vec![make_row(vec![CellValue::Text(
            "O'Brien".to_string(),
        )])];

        let quote = |s: &str| format!("`{}`", s);
        let mut buf = Vec::new();
        export_sql(&mut buf, "users", &columns, &rows, &quote).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert!(output.contains("'O''Brien'"));
    }

    #[test]
    fn test_export_sql_empty() {
        let columns = make_columns(&["id"]);
        let rows: Vec<Row> = vec![];

        let quote = |s: &str| format!("`{}`", s);
        let mut buf = Vec::new();
        let count = export_sql(&mut buf, "users", &columns, &rows, &quote).unwrap();

        assert_eq!(count, 0);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_export_sql_batching() {
        let columns = make_columns(&["id"]);
        let rows: Vec<Row> = (0..150)
            .map(|i| make_row(vec![CellValue::Int(i)]))
            .collect();

        let quote = |s: &str| format!("`{}`", s);
        let mut buf = Vec::new();
        let count = export_sql(&mut buf, "t", &columns, &rows, &quote).unwrap();
        let output = String::from_utf8(buf).unwrap();

        assert_eq!(count, 150);
        // Should have 2 INSERT statements (100 + 50)
        let insert_count = output.matches("INSERT INTO").count();
        assert_eq!(insert_count, 2);
    }
}
