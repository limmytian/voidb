//! MySQL connection pool creation.
//!
//! Provides a factory function for creating `mysql_async::Pool` instances
//! from `MySqlConfig`. Uses `OptsBuilder` (field-based) rather than URL
//! construction to avoid password leakage in logs (threat T-02-02).

use mysql_async::{OptsBuilder, Pool};

use crate::config::MySqlConfig;

/// Create a new `mysql_async::Pool` from a `MySqlConfig`.
///
/// The pool is created with default connection limits. It does NOT
/// test the connection -- callers should issue a ping after creation
/// to verify connectivity.
///
/// # Arguments
///
/// * `config` - MySQL connection configuration.
///
/// # Errors
///
/// Returns an error string if the pool options are invalid.
pub fn create_pool(config: &MySqlConfig) -> Result<Pool, String> {
    let opts = OptsBuilder::default()
        .ip_or_hostname(&config.host)
        .tcp_port(config.port)
        .user(Some(&config.username))
        .pass(Some(&config.password))
        .db_name(config.normalized_database());

    Ok(Pool::new(opts))
}
