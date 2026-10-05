//! SQL Autocomplete Engine
//!
//! Provides context-aware SQL completion suggestions including keywords,
//! table names, column names, and functions.

use std::collections::HashSet;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SuggestionKind {
    Keyword,
    Function,
    Table,
    Column,
    Schema,
    Database,
}

#[derive(Debug, Clone)]
pub struct Suggestion {
    pub label: String,
    pub kind: SuggestionKind,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SqlContext {
    /// Start of statement or after semicolon
    StatementStart,
    /// After SELECT — expect columns, *, functions
    SelectColumns,
    /// After FROM / JOIN — expect tables
    FromTable,
    /// After WHERE / AND / OR — expect columns
    WhereCondition,
    /// After SET — expect columns
    SetColumns,
    /// After INTO — expect tables
    IntoTable,
    /// After ORDER BY / GROUP BY — expect columns
    OrderByColumns,
    /// After UPDATE — expect tables
    UpdateTable,
    /// After ALTER / DROP / CREATE — expect TABLE/INDEX/etc.
    DdlObject,
    /// Generic / unknown context
    Generic,
}

static SQL_KEYWORDS: &[&str] = &[
    "SELECT", "FROM", "WHERE", "AND", "OR", "NOT", "IN", "IS", "NULL",
    "INSERT", "INTO", "VALUES", "UPDATE", "SET", "DELETE",
    "CREATE", "ALTER", "DROP", "TABLE", "INDEX", "VIEW", "DATABASE", "SCHEMA",
    "JOIN", "INNER", "LEFT", "RIGHT", "OUTER", "CROSS", "FULL", "ON",
    "ORDER", "BY", "ASC", "DESC", "GROUP", "HAVING",
    "LIMIT", "OFFSET", "DISTINCT", "AS", "CASE", "WHEN", "THEN", "ELSE", "END",
    "UNION", "ALL", "EXCEPT", "INTERSECT",
    "EXISTS", "BETWEEN", "LIKE", "ILIKE",
    "PRIMARY", "KEY", "FOREIGN", "REFERENCES", "UNIQUE", "CHECK", "DEFAULT",
    "CONSTRAINT", "CASCADE", "RESTRICT",
    "BEGIN", "COMMIT", "ROLLBACK", "TRANSACTION",
    "GRANT", "REVOKE", "TRUNCATE",
    "IF", "REPLACE", "TEMPORARY", "TEMP",
    "WITH", "RECURSIVE", "RETURNING",
    "EXPLAIN", "ANALYZE", "VERBOSE",
    "TRUE", "FALSE",
];

static SQL_FUNCTIONS: &[&str] = &[
    "COUNT", "SUM", "AVG", "MIN", "MAX",
    "COALESCE", "NULLIF", "CAST",
    "CONCAT", "LENGTH", "LOWER", "UPPER", "TRIM", "SUBSTRING", "REPLACE",
    "ROUND", "CEIL", "FLOOR", "ABS", "MOD",
    "NOW", "CURRENT_TIMESTAMP", "CURRENT_DATE", "CURRENT_TIME",
    "DATE", "YEAR", "MONTH", "DAY", "HOUR", "MINUTE", "SECOND",
    "DATE_FORMAT", "DATE_ADD", "DATE_SUB", "DATEDIFF", "TIMESTAMPDIFF",
    "IF", "IFNULL", "IIF",
    "ROW_NUMBER", "RANK", "DENSE_RANK", "NTILE", "LEAD", "LAG",
    "OVER", "PARTITION",
    "STRING_AGG", "GROUP_CONCAT", "ARRAY_AGG",
    "JSON_EXTRACT", "JSON_OBJECT", "JSON_ARRAY",
];

pub struct AutocompleteEngine {
    tables: Vec<String>,
    columns: Vec<(String, String)>,  // (table, column)
    schemas: Vec<String>,
}

impl Default for AutocompleteEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl AutocompleteEngine {
    pub fn new() -> Self {
        Self {
            tables: Vec::new(),
            columns: Vec::new(),
            schemas: Vec::new(),
        }
    }

    pub fn set_tables(&mut self, tables: Vec<String>) {
        self.tables = tables;
    }

    pub fn set_columns(&mut self, columns: Vec<(String, String)>) {
        self.columns = columns;
    }

    pub fn set_schemas(&mut self, schemas: Vec<String>) {
        self.schemas = schemas;
    }

    /// Get completions for the current input state.
    /// `text` is the full query text, `cursor_pos` is the byte offset of the cursor.
    pub fn complete(&self, text: &str, cursor_pos: usize) -> Vec<Suggestion> {
        let prefix = self.extract_prefix(text, cursor_pos);
        if prefix.is_empty() {
            return Vec::new();
        }

        let context = self.detect_context(text, cursor_pos);
        let prefix_upper = prefix.to_uppercase();
        let prefix_lower = prefix.to_lowercase();

        let mut suggestions = Vec::new();
        let mut seen = HashSet::new();

        match context {
            SqlContext::FromTable | SqlContext::IntoTable | SqlContext::UpdateTable => {
                self.add_tables(&prefix_lower, &mut suggestions, &mut seen);
                self.add_schemas(&prefix_lower, &mut suggestions, &mut seen);
                self.add_keywords(&prefix_upper, &mut suggestions, &mut seen);
            }
            SqlContext::SelectColumns | SqlContext::WhereCondition
            | SqlContext::SetColumns | SqlContext::OrderByColumns => {
                self.add_columns(&prefix_lower, &mut suggestions, &mut seen);
                self.add_functions(&prefix_upper, &mut suggestions, &mut seen);
                self.add_tables(&prefix_lower, &mut suggestions, &mut seen);
                self.add_keywords(&prefix_upper, &mut suggestions, &mut seen);
            }
            SqlContext::DdlObject => {
                self.add_keywords(&prefix_upper, &mut suggestions, &mut seen);
                self.add_tables(&prefix_lower, &mut suggestions, &mut seen);
            }
            SqlContext::StatementStart => {
                self.add_keywords(&prefix_upper, &mut suggestions, &mut seen);
            }
            SqlContext::Generic => {
                self.add_keywords(&prefix_upper, &mut suggestions, &mut seen);
                self.add_functions(&prefix_upper, &mut suggestions, &mut seen);
                self.add_tables(&prefix_lower, &mut suggestions, &mut seen);
                self.add_columns(&prefix_lower, &mut suggestions, &mut seen);
            }
        }

        suggestions.truncate(15);
        suggestions
    }

    fn extract_prefix(&self, text: &str, cursor_pos: usize) -> String {
        let before = &text[..cursor_pos.min(text.len())];
        let start = before.rfind(|c: char| !c.is_alphanumeric() && c != '_' && c != '.')
            .map(|i| i + 1)
            .unwrap_or(0);
        before[start..].to_string()
    }

    fn detect_context(&self, text: &str, cursor_pos: usize) -> SqlContext {
        let before = text[..cursor_pos.min(text.len())].to_uppercase();
        let tokens: Vec<&str> = before.split_whitespace().collect();

        if tokens.is_empty() {
            return SqlContext::StatementStart;
        }

        // Walk backwards to find the most recent context keyword
        for i in (0..tokens.len()).rev() {
            let token = tokens[i].trim_end_matches(|c: char| !c.is_alphabetic());
            match token {
                "SELECT" | "DISTINCT" => return SqlContext::SelectColumns,
                "FROM" | "JOIN" | "INNER" | "LEFT" | "RIGHT" | "CROSS" | "FULL" => {
                    return SqlContext::FromTable;
                }
                "WHERE" | "AND" | "OR" | "ON" | "HAVING" => {
                    return SqlContext::WhereCondition;
                }
                "SET" => return SqlContext::SetColumns,
                "INTO" => return SqlContext::IntoTable,
                "UPDATE" => return SqlContext::UpdateTable,
                "BY" => {
                    if i > 0 && (tokens[i - 1] == "ORDER" || tokens[i - 1] == "GROUP") {
                        return SqlContext::OrderByColumns;
                    }
                }
                "CREATE" | "ALTER" | "DROP" => return SqlContext::DdlObject,
                "," => {
                    // Look back further for the clause keyword
                    continue;
                }
                _ => {
                    // Check if this looks like a complete statement start
                    if i == 0 && (token == "INSERT" || token == "DELETE" || token == "BEGIN"
                        || token == "COMMIT" || token == "ROLLBACK" || token == "EXPLAIN") {
                        return SqlContext::StatementStart;
                    }
                    continue;
                }
            }
        }

        if tokens.len() == 1 {
            SqlContext::StatementStart
        } else {
            SqlContext::Generic
        }
    }

    fn add_keywords(&self, prefix: &str, suggestions: &mut Vec<Suggestion>, seen: &mut HashSet<String>) {
        for &kw in SQL_KEYWORDS {
            if kw.starts_with(prefix) && !seen.contains(kw) {
                seen.insert(kw.to_string());
                suggestions.push(Suggestion {
                    label: kw.to_string(),
                    kind: SuggestionKind::Keyword,
                    detail: None,
                });
            }
        }
    }

    fn add_functions(&self, prefix: &str, suggestions: &mut Vec<Suggestion>, seen: &mut HashSet<String>) {
        for &func in SQL_FUNCTIONS {
            if func.starts_with(prefix) && !seen.contains(func) {
                seen.insert(func.to_string());
                suggestions.push(Suggestion {
                    label: format!("{}()", func),
                    kind: SuggestionKind::Function,
                    detail: Some("function".into()),
                });
            }
        }
    }

    fn add_tables(&self, prefix: &str, suggestions: &mut Vec<Suggestion>, seen: &mut HashSet<String>) {
        for table in &self.tables {
            let lower = table.to_lowercase();
            if lower.starts_with(prefix) && !seen.contains(&lower) {
                seen.insert(lower);
                suggestions.push(Suggestion {
                    label: table.clone(),
                    kind: SuggestionKind::Table,
                    detail: Some("table".into()),
                });
            }
        }
    }

    fn add_columns(&self, prefix: &str, suggestions: &mut Vec<Suggestion>, seen: &mut HashSet<String>) {
        for (table, col) in &self.columns {
            let lower = col.to_lowercase();
            if lower.starts_with(prefix) && !seen.contains(&lower) {
                seen.insert(lower);
                suggestions.push(Suggestion {
                    label: col.clone(),
                    kind: SuggestionKind::Column,
                    detail: Some(table.clone()),
                });
            }
        }
    }

    fn add_schemas(&self, prefix: &str, suggestions: &mut Vec<Suggestion>, seen: &mut HashSet<String>) {
        for schema in &self.schemas {
            let lower = schema.to_lowercase();
            if lower.starts_with(prefix) && !seen.contains(&lower) {
                seen.insert(lower);
                suggestions.push(Suggestion {
                    label: schema.clone(),
                    kind: SuggestionKind::Schema,
                    detail: Some("schema".into()),
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keyword_completion() {
        let engine = AutocompleteEngine::new();
        let suggestions = engine.complete("SEL", 3);
        assert!(!suggestions.is_empty());
        assert!(suggestions.iter().any(|s| s.label == "SELECT"));
    }

    #[test]
    fn test_table_completion_after_from() {
        let mut engine = AutocompleteEngine::new();
        engine.set_tables(vec!["users".into(), "products".into(), "orders".into()]);
        let suggestions = engine.complete("SELECT * FROM us", 16);
        assert!(suggestions.iter().any(|s| s.label == "users" && s.kind == SuggestionKind::Table));
    }

    #[test]
    fn test_column_completion_after_select() {
        let mut engine = AutocompleteEngine::new();
        engine.set_columns(vec![
            ("users".into(), "id".into()),
            ("users".into(), "name".into()),
            ("users".into(), "email".into()),
        ]);
        let suggestions = engine.complete("SELECT na", 9);
        assert!(suggestions.iter().any(|s| s.label == "name" && s.kind == SuggestionKind::Column));
    }

    #[test]
    fn test_function_completion() {
        let engine = AutocompleteEngine::new();
        let suggestions = engine.complete("SELECT COU", 10);
        assert!(suggestions.iter().any(|s| s.label == "COUNT()" && s.kind == SuggestionKind::Function));
    }

    #[test]
    fn test_empty_prefix() {
        let engine = AutocompleteEngine::new();
        let suggestions = engine.complete("SELECT ", 7);
        assert!(suggestions.is_empty());
    }

    #[test]
    fn test_where_context() {
        let mut engine = AutocompleteEngine::new();
        engine.set_columns(vec![
            ("users".into(), "age".into()),
            ("users".into(), "active".into()),
        ]);
        let suggestions = engine.complete("SELECT * FROM users WHERE a", 27);
        assert!(suggestions.iter().any(|s| s.label == "age"));
        assert!(suggestions.iter().any(|s| s.label == "active"));
    }
}
