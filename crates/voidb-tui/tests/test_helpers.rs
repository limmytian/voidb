/// Test helpers for creating test data.
use voidb_core::{CellValue, ColumnInfo, Row};

/// Create a test column with all required fields.
pub fn test_column(
    name: &str,
    data_type: &str,
    is_primary_key: bool,
    nullable: bool,
) -> ColumnInfo {
    ColumnInfo {
        name: name.to_string(),
        data_type: data_type.to_string(),
        nullable,
        is_primary_key,
        default_value: None,
        max_length: None,
        extra: String::new(),
    }
}

/// Create sample data for testing: id, name, age columns with 3 rows.
pub fn create_sample_data() -> (Vec<ColumnInfo>, Vec<Row>) {
    let columns = vec![
        test_column("id", "INTEGER", true, false),
        test_column("name", "TEXT", false, false),
        test_column("age", "INTEGER", false, true),
    ];

    let rows = vec![
        Row {
            values: vec![
                CellValue::Int(1),
                CellValue::Text("Alice".to_string()),
                CellValue::Int(28),
            ],
        },
        Row {
            values: vec![
                CellValue::Int(2),
                CellValue::Text("Bob".to_string()),
                CellValue::Int(35),
            ],
        },
        Row {
            values: vec![
                CellValue::Int(3),
                CellValue::Text("Charlie".to_string()),
                CellValue::Int(42),
            ],
        },
    ];

    (columns, rows)
}
