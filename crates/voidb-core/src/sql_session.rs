//! Shared persistent SQL-session transaction state and policy.

use serde_json::{Value, json};

use crate::SqlDialect;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransactionState {
    Idle,
    Active,
    Failed,
}

impl TransactionState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Active => "active",
            Self::Failed => "failed",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransactionIsolation {
    Default,
    ReadUncommitted,
    ReadCommitted,
    RepeatableRead,
    Serializable,
}

impl TransactionIsolation {
    fn parse(value: Option<&str>) -> Result<Self, String> {
        match value.unwrap_or("default").trim().to_ascii_lowercase().as_str() {
            "default" => Ok(Self::Default),
            "read_uncommitted" | "read uncommitted" => Ok(Self::ReadUncommitted),
            "read_committed" | "read committed" => Ok(Self::ReadCommitted),
            "repeatable_read" | "repeatable read" => Ok(Self::RepeatableRead),
            "serializable" => Ok(Self::Serializable),
            _ => Err(
                "transaction isolation must be default, read_uncommitted, read_committed, repeatable_read, or serializable"
                    .to_string(),
            ),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Default => "default",
            Self::ReadUncommitted => "read_uncommitted",
            Self::ReadCommitted => "read_committed",
            Self::RepeatableRead => "repeatable_read",
            Self::Serializable => "serializable",
        }
    }
}

#[derive(Debug, Clone)]
pub struct SqlSessionTransactionPlan {
    state: TransactionState,
    savepoints: Vec<String>,
    transition: &'static str,
    touched_transaction: bool,
}

#[derive(Debug, Clone)]
pub struct SqlSessionTransactionTracker {
    dialect: SqlDialect,
    isolation: TransactionIsolation,
    state: TransactionState,
    savepoints: Vec<String>,
    last_transition: &'static str,
}

impl SqlSessionTransactionTracker {
    pub fn from_open_input(dialect: SqlDialect, input: &Value) -> Result<Self, String> {
        let isolation = input.get("isolation").or_else(|| {
            input
                .get("transaction")
                .and_then(|value| value.get("isolation"))
        });
        let isolation = match isolation {
            Some(value) => TransactionIsolation::parse(Some(
                value
                    .as_str()
                    .ok_or_else(|| "transaction isolation must be a string".to_string())?,
            ))?,
            None => TransactionIsolation::Default,
        };
        validate_isolation(dialect, isolation)?;
        Ok(Self {
            dialect,
            isolation,
            state: TransactionState::Idle,
            savepoints: Vec::new(),
            last_transition: "none",
        })
    }

    pub fn isolation_setup_sql(&self) -> Option<&'static str> {
        match (self.dialect, self.isolation) {
            (_, TransactionIsolation::Default) => None,
            (SqlDialect::MySql, TransactionIsolation::ReadUncommitted) => {
                Some("SET SESSION TRANSACTION ISOLATION LEVEL READ UNCOMMITTED")
            }
            (SqlDialect::MySql, TransactionIsolation::ReadCommitted) => {
                Some("SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED")
            }
            (SqlDialect::MySql, TransactionIsolation::RepeatableRead) => {
                Some("SET SESSION TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            }
            (SqlDialect::MySql, TransactionIsolation::Serializable) => {
                Some("SET SESSION TRANSACTION ISOLATION LEVEL SERIALIZABLE")
            }
            (SqlDialect::Postgres, TransactionIsolation::ReadCommitted) => {
                Some("SET SESSION CHARACTERISTICS AS TRANSACTION ISOLATION LEVEL READ COMMITTED")
            }
            (SqlDialect::Postgres, TransactionIsolation::RepeatableRead) => {
                Some("SET SESSION CHARACTERISTICS AS TRANSACTION ISOLATION LEVEL REPEATABLE READ")
            }
            (SqlDialect::Postgres, TransactionIsolation::Serializable) => {
                Some("SET SESSION CHARACTERISTICS AS TRANSACTION ISOLATION LEVEL SERIALIZABLE")
            }
            (SqlDialect::Sqlite, TransactionIsolation::ReadUncommitted) => {
                Some("PRAGMA read_uncommitted = true")
            }
            (SqlDialect::Sqlite, TransactionIsolation::Serializable) => {
                Some("PRAGMA read_uncommitted = false")
            }
            (SqlDialect::DuckDb, TransactionIsolation::Serializable) => None,
            _ => None,
        }
    }

    pub fn plan(&self, sql: &str) -> Result<SqlSessionTransactionPlan, String> {
        let statements = crate::sql_split::split_statements(sql);
        if statements.is_empty() {
            return Err("SQL is required".to_string());
        }
        let mut state = self.state;
        let mut savepoints = self.savepoints.clone();
        let mut transition = "none";
        let mut touched_transaction = false;

        for statement in statements {
            let command = transaction_command(statement)?;
            if state == TransactionState::Failed
                && !matches!(
                    command,
                    TransactionCommand::Rollback | TransactionCommand::RollbackTo(_)
                )
            {
                return Err("transaction is failed; issue ROLLBACK before continuing".to_string());
            }
            match command {
                TransactionCommand::Begin => {
                    touched_transaction = true;
                    if state != TransactionState::Idle {
                        return Err(
                            "nested BEGIN is not supported; use SAVEPOINT inside an active transaction"
                                .to_string(),
                        );
                    }
                    state = TransactionState::Active;
                    savepoints.clear();
                    transition = "begin";
                }
                TransactionCommand::Commit => {
                    touched_transaction = true;
                    if state != TransactionState::Active {
                        return Err("COMMIT requires an active transaction".to_string());
                    }
                    state = TransactionState::Idle;
                    savepoints.clear();
                    transition = "commit";
                }
                TransactionCommand::Rollback => {
                    touched_transaction = true;
                    if state == TransactionState::Idle {
                        return Err("ROLLBACK requires an active transaction".to_string());
                    }
                    state = TransactionState::Idle;
                    savepoints.clear();
                    transition = "rollback";
                }
                TransactionCommand::Savepoint(name) => {
                    touched_transaction = true;
                    if state != TransactionState::Active {
                        return Err("SAVEPOINT requires an active transaction".to_string());
                    }
                    savepoints.push(name);
                    transition = "savepoint";
                }
                TransactionCommand::Release(name) => {
                    touched_transaction = true;
                    if state != TransactionState::Active {
                        return Err("RELEASE SAVEPOINT requires an active transaction".to_string());
                    }
                    let position = savepoints
                        .iter()
                        .rposition(|existing| existing.eq_ignore_ascii_case(&name))
                        .ok_or_else(|| "RELEASE references an unknown savepoint".to_string())?;
                    savepoints.truncate(position);
                    transition = "release_savepoint";
                }
                TransactionCommand::RollbackTo(name) => {
                    touched_transaction = true;
                    if state == TransactionState::Idle {
                        return Err(
                            "ROLLBACK TO SAVEPOINT requires an active transaction".to_string()
                        );
                    }
                    let position = savepoints
                        .iter()
                        .rposition(|existing| existing.eq_ignore_ascii_case(&name))
                        .ok_or_else(|| "ROLLBACK TO references an unknown savepoint".to_string())?;
                    savepoints.truncate(position + 1);
                    state = TransactionState::Active;
                    transition = "rollback_to_savepoint";
                }
                TransactionCommand::SetIsolation => {
                    return Err(
                        "set transaction isolation when opening the session, not with session SQL"
                            .to_string(),
                    );
                }
                TransactionCommand::Other => {}
            }
        }

        Ok(SqlSessionTransactionPlan {
            state,
            savepoints,
            transition,
            touched_transaction,
        })
    }

    pub fn failure_requires_rollback(&self, plan: &SqlSessionTransactionPlan) -> bool {
        self.state != TransactionState::Idle
            || plan.state != TransactionState::Idle
            || plan.touched_transaction
    }

    pub fn record_success(&mut self, plan: SqlSessionTransactionPlan) {
        self.state = plan.state;
        self.savepoints = plan.savepoints;
        self.last_transition = plan.transition;
    }

    pub fn record_failure(&mut self, plan: &SqlSessionTransactionPlan, rollback_succeeded: bool) {
        if self.failure_requires_rollback(plan) {
            if rollback_succeeded {
                self.state = TransactionState::Idle;
                self.savepoints.clear();
                self.last_transition = "auto_rollback_error";
            } else {
                self.state = TransactionState::Failed;
                self.last_transition = "auto_rollback_failed";
            }
        } else {
            self.last_transition = "statement_error";
        }
    }

    pub fn status(&self) -> Value {
        json!({
            "state": self.state.as_str(),
            "isolation": self.isolation.as_str(),
            "savepoint_depth": self.savepoints.len(),
            "savepoints": self.savepoints,
            "nested_transactions": "savepoints_only",
            "auto_rollback_on_error": true,
            "auto_rollback_on_close": true,
            "last_transition": self.last_transition,
            "recovery": if self.state == TransactionState::Failed {
                "rollback_required"
            } else {
                "none"
            },
            "dialect": self.dialect.as_str()
        })
    }
}

fn validate_isolation(dialect: SqlDialect, isolation: TransactionIsolation) -> Result<(), String> {
    let supported = match dialect {
        SqlDialect::MySql => true,
        SqlDialect::Postgres => !matches!(isolation, TransactionIsolation::ReadUncommitted),
        SqlDialect::Sqlite => matches!(
            isolation,
            TransactionIsolation::Default
                | TransactionIsolation::ReadUncommitted
                | TransactionIsolation::Serializable
        ),
        SqlDialect::DuckDb => matches!(
            isolation,
            TransactionIsolation::Default | TransactionIsolation::Serializable
        ),
    };
    supported.then_some(()).ok_or_else(|| {
        format!(
            "{} does not support isolation '{}' through the shared session contract",
            dialect.as_str(),
            isolation.as_str()
        )
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum TransactionCommand {
    Begin,
    Commit,
    Rollback,
    Savepoint(String),
    Release(String),
    RollbackTo(String),
    SetIsolation,
    Other,
}

fn transaction_command(statement: &str) -> Result<TransactionCommand, String> {
    let statement = strip_leading_sql_comments(statement);
    let words = statement
        .trim_end_matches(';')
        .split_whitespace()
        .collect::<Vec<_>>();
    let upper = words
        .iter()
        .map(|word| word.to_ascii_uppercase())
        .collect::<Vec<_>>();
    let normalized = upper.join(" ");
    if normalized.starts_with("PRAGMA READ_UNCOMMITTED")
        || normalized.starts_with("SET TRANSACTION ")
        || normalized.starts_with("SET SESSION TRANSACTION ")
        || normalized.starts_with("SET SESSION CHARACTERISTICS AS TRANSACTION ")
    {
        return Ok(TransactionCommand::SetIsolation);
    }
    match upper.as_slice() {
        [first, ..] if first == "BEGIN" => Ok(TransactionCommand::Begin),
        [first, second, ..] if first == "START" && second == "TRANSACTION" => {
            Ok(TransactionCommand::Begin)
        }
        [first, ..] if first == "COMMIT" || first == "END" => Ok(TransactionCommand::Commit),
        [first, second, third, ..]
            if first == "ROLLBACK" && second == "TO" && third == "SAVEPOINT" =>
        {
            savepoint_name(words.get(3)).map(TransactionCommand::RollbackTo)
        }
        [first, second, ..] if first == "ROLLBACK" && second == "TO" => {
            savepoint_name(words.get(2)).map(TransactionCommand::RollbackTo)
        }
        [first, ..] if first == "ROLLBACK" => Ok(TransactionCommand::Rollback),
        [first, ..] if first == "SAVEPOINT" => {
            savepoint_name(words.get(1)).map(TransactionCommand::Savepoint)
        }
        [first, second, ..] if first == "RELEASE" && second == "SAVEPOINT" => {
            savepoint_name(words.get(2)).map(TransactionCommand::Release)
        }
        [first, ..] if first == "RELEASE" => {
            savepoint_name(words.get(1)).map(TransactionCommand::Release)
        }
        _ => Ok(TransactionCommand::Other),
    }
}

fn strip_leading_sql_comments(mut value: &str) -> &str {
    loop {
        value = value.trim_start();
        if let Some(comment) = value.strip_prefix("--") {
            value = comment
                .find('\n')
                .map(|index| &comment[index + 1..])
                .unwrap_or("");
            continue;
        }
        if let Some(comment) = value.strip_prefix("/*") {
            value = comment
                .find("*/")
                .map(|index| &comment[index + 2..])
                .unwrap_or("");
            continue;
        }
        return value;
    }
}

fn savepoint_name(value: Option<&&str>) -> Result<String, String> {
    let value = value
        .copied()
        .ok_or_else(|| "savepoint name is required".to_string())?;
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(
            "savepoint names must contain only ASCII letters, digits, and underscores".to_string(),
        );
    }
    Ok(value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_begin_savepoint_rollback_and_commit_transitions() {
        let mut tracker =
            SqlSessionTransactionTracker::from_open_input(SqlDialect::Sqlite, &Value::Null)
                .unwrap();
        let begin = tracker.plan("BEGIN").unwrap();
        tracker.record_success(begin);
        assert_eq!(tracker.status()["state"], "active");

        let savepoint = tracker.plan("SAVEPOINT nested_1").unwrap();
        tracker.record_success(savepoint);
        assert_eq!(tracker.status()["savepoint_depth"], 1);

        let rollback = tracker.plan("ROLLBACK TO SAVEPOINT nested_1").unwrap();
        tracker.record_success(rollback);
        assert_eq!(tracker.status()["last_transition"], "rollback_to_savepoint");

        let commit = tracker.plan("COMMIT").unwrap();
        tracker.record_success(commit);
        assert_eq!(tracker.status()["state"], "idle");
    }

    #[test]
    fn rejects_nested_begin_and_unsupported_isolation() {
        let mut tracker =
            SqlSessionTransactionTracker::from_open_input(SqlDialect::DuckDb, &Value::Null)
                .unwrap();
        let begin = tracker.plan("BEGIN").unwrap();
        tracker.record_success(begin);

        assert!(tracker.plan("BEGIN").unwrap_err().contains("SAVEPOINT"));
        assert!(
            SqlSessionTransactionTracker::from_open_input(
                SqlDialect::DuckDb,
                &json!({ "isolation": "read_committed" })
            )
            .is_err()
        );
    }

    #[test]
    fn failed_transaction_auto_rollback_is_visible() {
        let mut tracker =
            SqlSessionTransactionTracker::from_open_input(SqlDialect::Postgres, &Value::Null)
                .unwrap();
        let plan = tracker
            .plan("BEGIN; INSERT INTO missing VALUES (1)")
            .unwrap();
        tracker.record_failure(&plan, true);

        assert_eq!(tracker.status()["state"], "idle");
        assert_eq!(tracker.status()["last_transition"], "auto_rollback_error");
    }
}
