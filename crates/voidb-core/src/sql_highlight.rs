use ratatui::style::{Color, Style};
use ratatui::text::Span;

const KEYWORDS: &[&str] = &[
    "SELECT", "FROM", "WHERE", "AND", "OR", "NOT", "IN", "IS", "NULL",
    "INSERT", "INTO", "VALUES", "UPDATE", "SET", "DELETE", "CREATE", "ALTER",
    "DROP", "TABLE", "DATABASE", "INDEX", "VIEW", "TRIGGER", "FUNCTION",
    "PROCEDURE", "IF", "EXISTS", "PRIMARY", "KEY", "FOREIGN", "REFERENCES",
    "UNIQUE", "CHECK", "DEFAULT", "AUTO_INCREMENT", "SERIAL",
    "JOIN", "LEFT", "RIGHT", "INNER", "OUTER", "CROSS", "ON", "USING",
    "GROUP", "BY", "ORDER", "HAVING", "LIMIT", "OFFSET", "UNION", "ALL",
    "DISTINCT", "AS", "CASE", "WHEN", "THEN", "ELSE", "END",
    "BEGIN", "COMMIT", "ROLLBACK", "TRANSACTION", "SAVEPOINT",
    "GRANT", "REVOKE", "EXPLAIN", "ANALYZE", "SHOW", "DESCRIBE", "DESC",
    "ASC", "LIKE", "BETWEEN", "CAST", "COALESCE", "NULLIF",
    "TRUE", "FALSE", "WITH", "RECURSIVE", "RETURNING", "CONFLICT",
    "DO", "NOTHING", "CONSTRAINT", "CASCADE", "RESTRICT",
    "SCHEMA", "OWNER", "TO", "TYPE", "ENUM", "SEQUENCE",
    "REPLACE", "TRUNCATE", "RENAME", "ADD", "COLUMN", "MODIFY",
    "INT", "INTEGER", "BIGINT", "SMALLINT", "TINYINT", "FLOAT", "DOUBLE",
    "DECIMAL", "NUMERIC", "CHAR", "VARCHAR", "TEXT", "BLOB", "BOOLEAN",
    "DATE", "TIME", "DATETIME", "TIMESTAMP", "JSON", "UUID",
    "NOT", "TEMPORARY", "TEMP",
];

const FUNCTIONS: &[&str] = &[
    "COUNT", "SUM", "AVG", "MIN", "MAX", "ABS", "CEIL", "FLOOR", "ROUND",
    "UPPER", "LOWER", "TRIM", "LTRIM", "RTRIM", "LENGTH", "SUBSTRING",
    "CONCAT", "REPLACE", "REVERSE", "LEFT", "RIGHT",
    "NOW", "CURDATE", "CURTIME", "DATE_FORMAT", "DATEDIFF",
    "IFNULL", "COALESCE", "NULLIF", "CAST", "CONVERT",
    "GROUP_CONCAT", "STRING_AGG", "ARRAY_AGG",
    "ROW_NUMBER", "RANK", "DENSE_RANK", "LAG", "LEAD", "OVER", "PARTITION",
    "EXISTS", "ANY", "SOME",
];

fn is_keyword(word: &str) -> bool {
    let upper = word.to_uppercase();
    KEYWORDS.iter().any(|k| *k == upper)
}

fn is_function(word: &str) -> bool {
    let upper = word.to_uppercase();
    FUNCTIONS.iter().any(|f| *f == upper)
}

/// Tokenize SQL and return styled spans.
pub fn highlight_sql(sql: &str) -> Vec<Span<'static>> {
    let mut spans = Vec::new();
    let chars: Vec<char> = sql.chars().collect();
    let len = chars.len();
    let mut i = 0;

    let kw_style = Style::default().fg(Color::Blue);
    let fn_style = Style::default().fg(Color::Cyan);
    let str_style = Style::default().fg(Color::Green);
    let num_style = Style::default().fg(Color::Yellow);
    let comment_style = Style::default().fg(Color::DarkGray);
    let default_style = Style::default().fg(Color::White);

    while i < len {
        let c = chars[i];

        // Single-line comment
        if c == '-' && i + 1 < len && chars[i + 1] == '-' {
            let start = i;
            while i < len && chars[i] != '\n' {
                i += 1;
            }
            spans.push(Span::styled(chars[start..i].iter().collect::<String>(), comment_style));
            continue;
        }

        // Multi-line comment
        if c == '/' && i + 1 < len && chars[i + 1] == '*' {
            let start = i;
            i += 2;
            while i + 1 < len && !(chars[i] == '*' && chars[i + 1] == '/') {
                i += 1;
            }
            if i + 1 < len { i += 2; } else { i = len; }
            spans.push(Span::styled(chars[start..i].iter().collect::<String>(), comment_style));
            continue;
        }

        // Quoted string
        if c == '\'' {
            let start = i;
            i += 1;
            while i < len {
                if chars[i] == '\'' {
                    if i + 1 < len && chars[i + 1] == '\'' {
                        i += 2; // escaped quote
                    } else {
                        i += 1;
                        break;
                    }
                } else {
                    i += 1;
                }
            }
            spans.push(Span::styled(chars[start..i].iter().collect::<String>(), str_style));
            continue;
        }

        // Number
        if c.is_ascii_digit() || (c == '.' && i + 1 < len && chars[i + 1].is_ascii_digit()) {
            let start = i;
            while i < len && (chars[i].is_ascii_digit() || chars[i] == '.') {
                i += 1;
            }
            spans.push(Span::styled(chars[start..i].iter().collect::<String>(), num_style));
            continue;
        }

        // Word (keyword / identifier / function)
        if c.is_alphanumeric() || c == '_' {
            let start = i;
            while i < len && (chars[i].is_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            let word: String = chars[start..i].iter().collect();

            // Check if next non-space char is '(' → function
            let next_paren = {
                let mut j = i;
                while j < len && chars[j] == ' ' { j += 1; }
                j < len && chars[j] == '('
            };

            let style = if is_keyword(&word) {
                kw_style
            } else if next_paren && is_function(&word) {
                fn_style
            } else {
                default_style
            };
            spans.push(Span::styled(word, style));
            continue;
        }

        // Default: single char
        spans.push(Span::styled(c.to_string(), default_style));
        i += 1;
    }

    spans
}

/// Highlight SQL with a cursor position. Returns a single Line with the cursor rendered.
pub fn highlight_sql_with_cursor(sql: &str, cursor_pos: usize) -> Vec<Span<'static>> {
    if sql.is_empty() {
        return vec![
            Span::styled("\u{258c}", Style::default().fg(Color::White)),
            Span::styled("Type your SQL query here...", Style::default().fg(Color::DarkGray)),
        ];
    }

    let raw_spans = highlight_sql(sql);

    // Now we need to split the spans at cursor_pos to insert the cursor styling
    let mut result = Vec::new();
    let mut char_offset = 0;
    let cursor_style = Style::default().bg(Color::White).fg(Color::Black);

    for span in raw_spans {
        let span_len = span.content.len();
        let span_start = char_offset;
        let span_end = char_offset + span_len;

        if cursor_pos >= span_start && cursor_pos < span_end {
            let local_pos = cursor_pos - span_start;
            let text = span.content.to_string();

            if local_pos > 0 {
                result.push(Span::styled(text[..local_pos].to_string(), span.style));
            }

            let cursor_char = &text[local_pos..local_pos + text[local_pos..].chars().next().map(|c| c.len_utf8()).unwrap_or(1)];
            result.push(Span::styled(cursor_char.to_string(), cursor_style));

            let after_cursor = local_pos + cursor_char.len();
            if after_cursor < text.len() {
                result.push(Span::styled(text[after_cursor..].to_string(), span.style));
            }
        } else {
            result.push(Span::styled(span.content.to_string(), span.style));
        }

        char_offset = span_end;
    }

    // If cursor is at the end
    if cursor_pos >= char_offset {
        result.push(Span::styled(" ", cursor_style));
    }

    result
}
