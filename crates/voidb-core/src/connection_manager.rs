//! Connection Pool Management
//!
//! This module provides a global connection pool registry for managing
//! database connections across the application.

use anyhow::{anyhow, Result};
use once_cell::sync::Lazy;
use sqlx::MySqlPool;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Global connection pool registry
static CONNECTION_POOLS: Lazy<Arc<Mutex<HashMap<String, MySqlPool>>>> =
    Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));

/// Register a connection pool with a unique ID
///
/// # Arguments
///
/// * `id` - Unique identifier for the connection
/// * `url` - MySQL connection URL (e.g., "mysql://user:pass@host:port/db")
///
/// # Example
///
/// ```rust
/// register_pool("local-mysql".to_string(), "mysql://root@localhost:3306").await?;
/// ```
pub async fn register_pool(id: String, url: &str) -> Result<()> {
    let pool = MySqlPool::connect(url).await?;
    CONNECTION_POOLS
        .lock()
        .unwrap()
        .insert(id, pool);
    Ok(())
}

/// Get a connection pool by ID
///
/// # Arguments
///
/// * `id` - Unique identifier for the connection
///
/// # Returns
///
/// * `Result<MySqlPool>` - Cloned connection pool or error if not found
pub fn get_pool(id: &str) -> Result<MySqlPool> {
    CONNECTION_POOLS
        .lock()
        .unwrap()
        .get(id)
        .cloned()
        .ok_or_else(|| anyhow!("Connection not found: {}", id))
}

/// Remove a connection pool
///
/// # Arguments
///
/// * `id` - Unique identifier for the connection
pub fn remove_pool(id: &str) -> Result<()> {
    CONNECTION_POOLS
        .lock()
        .unwrap()
        .remove(id)
        .ok_or_else(|| anyhow!("Connection not found: {}", id))?;
    Ok(())
}

/// List all registered connection IDs
pub fn list_connections() -> Vec<String> {
    CONNECTION_POOLS
        .lock()
        .unwrap()
        .keys()
        .cloned()
        .collect()
}
