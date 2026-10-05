use arboard::Clipboard;
use serde::{Deserialize, Serialize};

use crate::{CellValue, ColumnInfo, Row, TableSchema};

pub fn copy_to_clipboard(text: &str) -> Result<(), String> {
    let mut cb = Clipboard::new().map_err(|e| format!("Clipboard init failed: {}", e))?;
    cb.set_text(text).map_err(|e| format!("Clipboard write failed: {}", e))
}

pub fn paste_from_clipboard() -> Result<String, String> {
    let mut cb = Clipboard::new().map_err(|e| format!("Clipboard init failed: {}", e))?;
    cb.get_text().map_err(|e| format!("Clipboard read failed: {}", e))
}

/// Structured clipboard data for row copy/paste across tables and connections.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClipboardRows {
    pub column_names: Vec<String>,
    pub rows: Vec<Vec<CellValue>>,
    pub source_table: Option<String>,
}

const CLIPBOARD_MAGIC: &str = "VOIDB_ROWS:";

impl ClipboardRows {
    pub fn from_single_row(columns: &[ColumnInfo], row: &Row, table: Option<String>) -> Self {
        Self {
            column_names: columns.iter().map(|c| c.name.clone()).collect(),
            rows: vec![row.values.clone()],
            source_table: table,
        }
    }

    pub fn from_rows(columns: &[ColumnInfo], rows: &[Row], table: Option<String>) -> Self {
        Self {
            column_names: columns.iter().map(|c| c.name.clone()).collect(),
            rows: rows.iter().map(|r| r.values.clone()).collect(),
            source_table: table,
        }
    }

    pub fn from_selected(
        columns: &[ColumnInfo],
        all_rows: &[Row],
        indices: &[usize],
        table: Option<String>,
    ) -> Self {
        Self {
            column_names: columns.iter().map(|c| c.name.clone()).collect(),
            rows: indices
                .iter()
                .filter_map(|&i| all_rows.get(i).map(|r| r.values.clone()))
                .collect(),
            source_table: table,
        }
    }

    pub fn copy_to_system(&self) -> Result<(), String> {
        // Build human-readable TSV lines first (for external paste)
        let mut tsv_lines: Vec<String> = Vec::with_capacity(self.rows.len());
        for row in &self.rows {
            let line: Vec<String> = row.iter().map(|v| {
                match v {
                    CellValue::Null => "NULL".to_string(),
                    _ => v.display(),
                }
            }).collect();
            tsv_lines.push(line.join("\t"));
        }
        // Append structured JSON on last line for VoidB-to-VoidB paste
        let json = serde_json::to_string(self).map_err(|e| format!("Serialize failed: {}", e))?;
        tsv_lines.push(format!("{}{}", CLIPBOARD_MAGIC, json));
        let text = tsv_lines.join("\n");
        copy_to_clipboard(&text)
    }

    /// Try to parse from system clipboard.  Returns Ok(rows, columns_matched)
    /// if it's our JSON format.  Falls back to TSV if not.
    pub fn parse_from_system(target_columns: &[ColumnInfo]) -> Result<(Self, bool), String> {
        let text = paste_from_clipboard()?;
        Self::parse_text(&text, target_columns)
    }

    pub fn parse_text(text: &str, target_columns: &[ColumnInfo]) -> Result<(Self, bool), String> {
        // Check first line (legacy format) or last line (new format) for structured JSON
        let json_result = text.strip_prefix(CLIPBOARD_MAGIC)
            .map(|s| {
                // Legacy: entire text is VOIDB_ROWS:JSON
                s.to_string()
            })
            .or_else(|| {
                // New format: TSV lines + last line is VOIDB_ROWS:JSON
                text.lines().last()
                    .and_then(|last| last.strip_prefix(CLIPBOARD_MAGIC))
                    .map(|s| s.to_string())
            });

        if let Some(json_str) = json_result {
            let clip: ClipboardRows =
                serde_json::from_str(&json_str).map_err(|e| format!("Parse failed: {}", e))?;
            let target_names: Vec<String> = target_columns.iter().map(|c| c.name.to_lowercase()).collect();
            let matched = clip.column_names.len() == target_names.len()
                && clip.column_names.iter().zip(target_names.iter()).all(|(a, b)| a.to_lowercase() == *b);
            Ok((clip, matched))
        } else {
            let clip = Self::parse_tsv(text, target_columns);
            Ok((clip, true))
        }
    }

    fn parse_tsv(text: &str, target_columns: &[ColumnInfo]) -> Self {
        let lines: Vec<&str> = text.lines().collect();
        let col_count = target_columns.len();
        let rows: Vec<Vec<CellValue>> = lines
            .iter()
            .filter(|l| !l.is_empty())
            .map(|line| {
                let parts: Vec<&str> = line.split('\t').collect();
                (0..col_count)
                    .map(|i| {
                        parts
                            .get(i)
                            .map(|s| {
                                if s.eq_ignore_ascii_case("NULL") {
                                    CellValue::Null
                                } else {
                                    CellValue::Text(s.to_string())
                                }
                            })
                            .unwrap_or(CellValue::Null)
                    })
                    .collect()
            })
            .collect();

        Self {
            column_names: target_columns.iter().map(|c| c.name.clone()).collect(),
            rows,
            source_table: None,
        }
    }

    pub fn row_count(&self) -> usize {
        self.rows.len()
    }
}

// ---------------------------------------------------------------------------
// Table / Database level clipboard (internal, not system clipboard)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DatabaseDialect {
    MySQL,
    PostgreSQL,
    SQLite,
    DuckDB,
}

impl std::fmt::Display for DatabaseDialect {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MySQL => write!(f, "MySQL"),
            Self::PostgreSQL => write!(f, "PostgreSQL"),
            Self::SQLite => write!(f, "SQLite"),
            Self::DuckDB => write!(f, "DuckDB"),
        }
    }
}

/// A copied table: schema + optional data rows.
#[derive(Debug, Clone)]
pub struct TableClipboard {
    pub dialect: DatabaseDialect,
    pub source_connection: String,
    pub source_database: String,
    pub table_name: String,
    pub create_table_sql: String,
    pub schema: TableSchema,
    pub data: Option<Vec<Row>>,
}

impl TableClipboard {
    pub fn row_count(&self) -> usize {
        self.data.as_ref().map_or(0, |d| d.len())
    }

    pub fn has_data(&self) -> bool {
        self.data.is_some()
    }
}

/// A copied database: all tables.
#[derive(Debug, Clone)]
pub struct DatabaseClipboard {
    pub dialect: DatabaseDialect,
    pub source_connection: String,
    pub database_name: String,
    pub tables: Vec<TableClipboard>,
}

impl DatabaseClipboard {
    pub fn table_count(&self) -> usize {
        self.tables.len()
    }

    pub fn total_rows(&self) -> usize {
        self.tables.iter().map(|t| t.row_count()).sum()
    }
}

/// Internal clipboard shared across plugins via ShellCapabilities.
#[derive(Debug, Clone)]
pub enum VoidbClipboard {
    Table(Box<TableClipboard>),
    Tables(Vec<TableClipboard>),
    Database(DatabaseClipboard),
}

impl VoidbClipboard {
    pub fn dialect(&self) -> &DatabaseDialect {
        match self {
            Self::Table(t) => &t.dialect,
            Self::Tables(ts) => &ts[0].dialect,
            Self::Database(d) => &d.dialect,
        }
    }

    pub fn summary(&self) -> String {
        match self {
            Self::Table(t) => {
                if t.has_data() {
                    format!("Table '{}' ({} rows)", t.table_name, t.row_count())
                } else {
                    format!("Table '{}' (structure only)", t.table_name)
                }
            }
            Self::Tables(ts) => {
                let total: usize = ts.iter().map(|t| t.row_count()).sum();
                if total > 0 {
                    format!("{} tables ({} rows total)", ts.len(), total)
                } else {
                    format!("{} tables (structure only)", ts.len())
                }
            }
            Self::Database(d) => {
                let total = d.total_rows();
                if total > 0 {
                    format!("Database '{}' ({} tables, {} rows)", d.database_name, d.table_count(), total)
                } else {
                    format!("Database '{}' ({} tables, structure only)", d.database_name, d.table_count())
                }
            }
        }
    }
}
