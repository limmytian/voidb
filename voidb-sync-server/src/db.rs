//! SQLite connection pool + migration runner.
//!
//! Author: Limmy

use std::path::Path;

use anyhow::Context;
use r2d2::Pool;
use r2d2_sqlite::SqliteConnectionManager;

pub type DbPool = Pool<SqliteConnectionManager>;
pub type DbConn = r2d2::PooledConnection<SqliteConnectionManager>;

/// Embedded migration list. The versions must match `schema_version`.
const MIGRATIONS: &[(u32, &str)] = &[
    (1, include_str!("../migrations/0001_initial.sql")),
    (2, include_str!("../migrations/0002_object_sync.sql")),
    (3, include_str!("../migrations/0003_dek_recovery.sql")),
];

/// Open (or create) a pooled SQLite database at `path` and run migrations.
pub fn open(path: &Path) -> anyhow::Result<DbPool> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).ok();
    }

    let manager = SqliteConnectionManager::file(path).with_init(|c| {
        // Safer concurrent access for multi-worker Axum handlers.
        c.pragma_update(None, "journal_mode", "WAL")?;
        c.pragma_update(None, "synchronous", "NORMAL")?;
        c.pragma_update(None, "foreign_keys", "ON")?;
        c.busy_timeout(std::time::Duration::from_secs(5))?;
        Ok(())
    });

    let pool = Pool::builder()
        .max_size(16)
        .build(manager)
        .context("failed to build sqlite pool")?;

    {
        let conn = pool.get()?;
        run_migrations(&conn)?;
    }

    Ok(pool)
}

fn run_migrations(conn: &rusqlite::Connection) -> anyhow::Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL);",
    )?;

    let current: u32 = conn
        .query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version",
            [],
            |r| r.get(0),
        )
        .unwrap_or(0);

    for (version, sql) in MIGRATIONS {
        if *version > current {
            tracing::info!(version, "applying migration");
            conn.execute_batch(sql)
                .with_context(|| format!("migration {version} failed"))?;
        }
    }

    Ok(())
}
