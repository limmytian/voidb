//! Shared CLI output formatters.
//!
//! Provides functions for converting `CellValue` to JSON, CSV, and display
//! strings, plus a table-formatted printer for `QueryResult`. These are used
//! by all CLI plugins to avoid code duplication.

use crate::database::types::{CellValue, QueryResult};

/// Convert a CellValue to a serde_json::Value for JSON output.
pub fn cell_value_to_json(v: &CellValue) -> serde_json::Value {
    match v {
        CellValue::Null => serde_json::Value::Null,
        CellValue::Bool(b) => serde_json::Value::Bool(*b),
        CellValue::Int(i) => serde_json::json!(i),
        CellValue::Float(f) => serde_json::json!(f),
        CellValue::Text(s) | CellValue::Date(s) | CellValue::DateTime(s) | CellValue::Time(s)
        | CellValue::Uuid(s) => serde_json::Value::String(s.clone()),
        CellValue::Blob(b) => serde_json::Value::String(hex::encode(b)),
        CellValue::Json(s) => {
            serde_json::from_str(s).unwrap_or_else(|_| serde_json::Value::String(s.clone()))
        }
        CellValue::Unknown(s) => serde_json::Value::String(s.clone()),
    }
}

/// Convert a CellValue to a CSV-safe string.
pub fn cell_value_to_csv(v: &CellValue) -> String {
    match v {
        CellValue::Null => String::new(),
        CellValue::Bool(b) => b.to_string(),
        CellValue::Int(i) => i.to_string(),
        CellValue::Float(f) => f.to_string(),
        CellValue::Text(s) => {
            if s.contains(',') || s.contains('"') || s.contains('\n') {
                format!("\"{}\"", s.replace('"', "\"\""))
            } else {
                s.clone()
            }
        }
        CellValue::Date(s) | CellValue::DateTime(s) | CellValue::Time(s) | CellValue::Uuid(s) => {
            s.clone()
        }
        CellValue::Blob(b) => hex::encode(b),
        CellValue::Json(s) | CellValue::Unknown(s) => s.clone(),
    }
}

/// Convert a CellValue to a human-readable display string.
pub fn cell_value_to_display(v: &CellValue) -> String {
    match v {
        CellValue::Null => "NULL".to_string(),
        CellValue::Bool(b) => b.to_string(),
        CellValue::Int(i) => i.to_string(),
        CellValue::Float(f) => f.to_string(),
        CellValue::Text(s) | CellValue::Date(s) | CellValue::DateTime(s) | CellValue::Time(s)
        | CellValue::Uuid(s) | CellValue::Json(s) | CellValue::Unknown(s) => s.clone(),
        CellValue::Blob(b) => format!("0x{}", hex::encode(&b[..b.len().min(16)])),
    }
}

/// Print a QueryResult as a formatted ASCII table to stdout.
pub fn print_table(result: &QueryResult) {
    if result.columns.is_empty() {
        return;
    }

    // Calculate column widths
    let mut widths: Vec<usize> = result.columns.iter().map(|c| c.name.len()).collect();

    for row in &result.rows {
        for (i, val) in row.values.iter().enumerate() {
            if i < widths.len() {
                let val_str = cell_value_to_display(val);
                widths[i] = widths[i].max(val_str.len()).min(50);
            }
        }
    }

    // Header
    let header: Vec<String> = result
        .columns
        .iter()
        .enumerate()
        .map(|(i, c)| format!("{:<width$}", c.name, width = widths[i]))
        .collect();
    println!("{}", header.join(" | "));
    let separator: Vec<String> = widths.iter().map(|w| "-".repeat(*w)).collect();
    println!("{}", separator.join("-+-"));

    // Rows
    for row in &result.rows {
        let values: Vec<String> = row
            .values
            .iter()
            .enumerate()
            .map(|(i, v)| {
                let s = cell_value_to_display(v);
                let w = widths.get(i).copied().unwrap_or(10);
                if s.len() > w {
                    format!("{}...", &s[..w.saturating_sub(3)])
                } else {
                    format!("{:<width$}", s, width = w)
                }
            })
            .collect();
        println!("{}", values.join(" | "));
    }
}
