/// Split a SQL string into individual statements, respecting string literals,
/// quoted identifiers, and comments.
pub fn split_statements(sql: &str) -> Vec<&str> {
    let bytes = sql.as_bytes();
    let len = bytes.len();
    let mut i = 0;
    let mut start = 0;
    let mut results = Vec::new();

    while i < len {
        match bytes[i] {
            b'\'' => {
                i += 1;
                while i < len {
                    if bytes[i] == b'\'' {
                        i += 1;
                        if i < len && bytes[i] == b'\'' {
                            i += 1; // escaped ''
                        } else {
                            break;
                        }
                    } else if bytes[i] == b'\\' {
                        i += 2; // backslash escape
                    } else {
                        i += 1;
                    }
                }
            }
            b'"' => {
                i += 1;
                while i < len && bytes[i] != b'"' {
                    if bytes[i] == b'"' && i + 1 < len && bytes[i + 1] == b'"' {
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                if i < len { i += 1; }
            }
            b'`' => {
                i += 1;
                while i < len && bytes[i] != b'`' { i += 1; }
                if i < len { i += 1; }
            }
            b'-' if i + 1 < len && bytes[i + 1] == b'-' => {
                while i < len && bytes[i] != b'\n' { i += 1; }
            }
            b'/' if i + 1 < len && bytes[i + 1] == b'*' => {
                i += 2;
                while i + 1 < len && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                if i + 1 < len { i += 2; }
            }
            b';' => {
                let stmt = sql[start..i].trim();
                if !stmt.is_empty() {
                    results.push(stmt);
                }
                i += 1;
                start = i;
            }
            _ => { i += 1; }
        }
    }

    let last = sql[start..].trim();
    if !last.is_empty() {
        results.push(last);
    }
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simple_split() {
        let stmts = split_statements("SELECT 1; SELECT 2;");
        assert_eq!(stmts, vec!["SELECT 1", "SELECT 2"]);
    }

    #[test]
    fn string_with_semicolon() {
        let stmts = split_statements("SELECT 'a;b'; SELECT 2");
        assert_eq!(stmts, vec!["SELECT 'a;b'", "SELECT 2"]);
    }

    #[test]
    fn comment_with_semicolon() {
        let stmts = split_statements("SELECT 1 -- comment;\n; SELECT 2");
        assert_eq!(stmts, vec!["SELECT 1 -- comment;", "SELECT 2"]);
    }

    #[test]
    fn block_comment() {
        let stmts = split_statements("SELECT /* ; */ 1; SELECT 2");
        assert_eq!(stmts, vec!["SELECT /* ; */ 1", "SELECT 2"]);
    }

    #[test]
    fn empty_and_whitespace() {
        let stmts = split_statements("  ; SELECT 1;  ;  ");
        assert_eq!(stmts, vec!["SELECT 1"]);
    }

    #[test]
    fn backtick_identifier() {
        let stmts = split_statements("SELECT `a;b`; SELECT 2");
        assert_eq!(stmts, vec!["SELECT `a;b`", "SELECT 2"]);
    }
}
