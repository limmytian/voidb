use std::io::Read;

use crate::error::VoidbError;

/// Parsed CSV import data.
pub struct ImportData {
    pub headers: Vec<String>,
    pub rows: Vec<Vec<String>>,
}

/// Parse a CSV file into ImportData.
pub fn parse_csv<R: Read>(reader: R) -> Result<ImportData, VoidbError> {
    let mut rdr = csv::ReaderBuilder::new()
        .has_headers(true)
        .from_reader(reader);

    let headers: Vec<String> = rdr
        .headers()
        .map_err(|e| VoidbError::Other(format!("CSV header parse error: {}", e)))?
        .iter()
        .map(|h| h.to_string())
        .collect();

    let mut rows = Vec::new();
    for result in rdr.records() {
        let record =
            result.map_err(|e| VoidbError::Other(format!("CSV record parse error: {}", e)))?;
        let row: Vec<String> = record.iter().map(|f| f.to_string()).collect();
        rows.push(row);
    }

    Ok(ImportData { headers, rows })
}

/// Generate INSERT statements from imported data.
/// Groups rows into batches for efficiency.
pub fn generate_insert_statements(
    table_name: &str,
    columns: &[String],
    rows: &[Vec<String>],
    quote_fn: &dyn Fn(&str) -> String,
    batch_size: usize,
) -> Vec<String> {
    if rows.is_empty() || columns.is_empty() {
        return Vec::new();
    }

    let col_list: Vec<String> = columns.iter().map(|c| quote_fn(c)).collect();
    let col_names = col_list.join(", ");
    let quoted_table = quote_fn(table_name);

    let mut statements = Vec::new();

    for chunk in rows.chunks(batch_size) {
        let value_rows: Vec<String> = chunk
            .iter()
            .map(|row| {
                let values: Vec<String> = row
                    .iter()
                    .map(|v| {
                        if v.is_empty() || v.eq_ignore_ascii_case("null") {
                            "NULL".to_string()
                        } else {
                            format!("'{}'", v.replace('\'', "''"))
                        }
                    })
                    .collect();
                format!("  ({})", values.join(", "))
            })
            .collect();

        let stmt = format!(
            "INSERT INTO {} ({}) VALUES\n{}",
            quoted_table,
            col_names,
            value_rows.join(",\n")
        );
        statements.push(stmt);
    }

    statements
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_csv_basic() {
        let csv_data = "id,name,email\n1,Alice,alice@example.com\n2,Bob,bob@example.com\n";
        let data = parse_csv(csv_data.as_bytes()).unwrap();

        assert_eq!(data.headers, vec!["id", "name", "email"]);
        assert_eq!(data.rows.len(), 2);
        assert_eq!(data.rows[0], vec!["1", "Alice", "alice@example.com"]);
        assert_eq!(data.rows[1], vec!["2", "Bob", "bob@example.com"]);
    }

    #[test]
    fn test_parse_csv_quoted_fields() {
        let csv_data = "name,bio\n\"Alice\",\"She said \"\"hello\"\"\"\n";
        let data = parse_csv(csv_data.as_bytes()).unwrap();

        assert_eq!(data.rows[0][1], "She said \"hello\"");
    }

    #[test]
    fn test_generate_insert_basic() {
        let columns = vec!["id".to_string(), "name".to_string()];
        let rows = vec![
            vec!["1".to_string(), "Alice".to_string()],
            vec!["2".to_string(), "Bob".to_string()],
        ];

        let quote = |s: &str| format!("`{}`", s);
        let stmts = generate_insert_statements("users", &columns, &rows, &quote, 100);

        assert_eq!(stmts.len(), 1);
        assert!(stmts[0].contains("INSERT INTO `users` (`id`, `name`) VALUES"));
        assert!(stmts[0].contains("('1', 'Alice')"));
        assert!(stmts[0].contains("('2', 'Bob')"));
    }

    #[test]
    fn test_generate_insert_escaping() {
        let columns = vec!["name".to_string()];
        let rows = vec![vec!["O'Brien".to_string()]];

        let quote = |s: &str| format!("`{}`", s);
        let stmts = generate_insert_statements("users", &columns, &rows, &quote, 100);

        assert!(stmts[0].contains("'O''Brien'"));
    }

    #[test]
    fn test_generate_insert_null_handling() {
        let columns = vec!["value".to_string()];
        let rows = vec![
            vec!["".to_string()],
            vec!["NULL".to_string()],
            vec!["null".to_string()],
        ];

        let quote = |s: &str| format!("`{}`", s);
        let stmts = generate_insert_statements("t", &columns, &rows, &quote, 100);

        // Empty and "NULL"/"null" should become SQL NULL
        assert_eq!(stmts[0].matches("NULL").count(), 3);
    }

    #[test]
    fn test_generate_insert_batching() {
        let columns = vec!["id".to_string()];
        let rows: Vec<Vec<String>> = (0..5).map(|i| vec![i.to_string()]).collect();

        let quote = |s: &str| format!("`{}`", s);
        let stmts = generate_insert_statements("t", &columns, &rows, &quote, 2);

        assert_eq!(stmts.len(), 3); // 2 + 2 + 1
    }

    #[test]
    fn test_generate_insert_empty() {
        let columns = vec!["id".to_string()];
        let rows: Vec<Vec<String>> = vec![];

        let quote = |s: &str| format!("`{}`", s);
        let stmts = generate_insert_statements("t", &columns, &rows, &quote, 100);

        assert!(stmts.is_empty());
    }
}
