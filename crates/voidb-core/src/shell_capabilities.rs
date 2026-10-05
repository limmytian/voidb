//! Shell capabilities provided to plugins
//!
//! This module defines the minimal interface between VoidB shell and plugins.
//! Plugins receive these capabilities at initialization and can use them to
//! interact with the shell.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::RwLock;

use crate::clipboard::VoidbClipboard;
use crate::connection::ConnectionConfig;
use crate::plugin::registry::PluginRegistry;
use crate::session::PluginSessionRegistry;

/// Capabilities provided by VoidB shell to plugins
///
/// This is the **only** interface between plugins and the shell.
/// Plugins are otherwise completely autonomous.
#[derive(Clone)]
pub struct ShellCapabilities {
    /// Access to connection configuration registry (shared metadata)
    pub connections: Arc<RwLock<ConnectionConfigRegistry>>,

    /// Tab management operations
    pub tabs: Arc<dyn TabManager>,

    /// Internal clipboard for table/database level copy-paste across plugins
    pub clipboard: Arc<RwLock<Option<VoidbClipboard>>>,

    /// Plugin registry (read-only, for querying plugin metadata like connection fields)
    pub plugin_registry: Arc<PluginRegistry>,

    /// Shared plugin session descriptor registry and lifecycle coordinator.
    ///
    /// This stores metadata, leases, and close requests only. Live protocol
    /// handles remain inside the owning plugin service.
    pub sessions: Arc<PluginSessionRegistry>,

    /// Shared tokio runtime handle from `#[tokio::main]` (ARCH-04).
    ///
    /// Plugins use this to spawn async tasks via `caps.runtime.spawn(...)`
    /// instead of creating per-operation `Runtime::new()` instances. This
    /// eliminates runtime proliferation and ensures all async work runs on
    /// the same executor.
    ///
    /// In tests, provide a test runtime handle for isolation:
    /// ```rust,ignore
    /// let rt = tokio::runtime::Runtime::new().unwrap();
    /// let handle = rt.handle().clone();
    /// ```
    pub runtime: tokio::runtime::Handle,
}

impl ShellCapabilities {
    /// Create new shell capabilities
    ///
    /// # Arguments
    ///
    /// * `connections` - Shared connection configuration registry
    /// * `tabs` - Tab management interface
    /// * `plugin_registry` - Read-only plugin metadata registry
    /// * `runtime` - Shared tokio runtime handle (typically `Handle::current()`)
    pub fn new(
        connections: Arc<RwLock<ConnectionConfigRegistry>>,
        tabs: Arc<dyn TabManager>,
        plugin_registry: Arc<PluginRegistry>,
        runtime: tokio::runtime::Handle,
    ) -> Self {
        Self::with_sessions(
            connections,
            tabs,
            plugin_registry,
            Arc::new(PluginSessionRegistry::new()),
            runtime,
        )
    }

    /// Create shell capabilities with an explicit session registry.
    pub fn with_sessions(
        connections: Arc<RwLock<ConnectionConfigRegistry>>,
        tabs: Arc<dyn TabManager>,
        plugin_registry: Arc<PluginRegistry>,
        sessions: Arc<PluginSessionRegistry>,
        runtime: tokio::runtime::Handle,
    ) -> Self {
        Self {
            connections,
            tabs,
            clipboard: Arc::new(RwLock::new(None)),
            plugin_registry,
            sessions,
            runtime,
        }
    }
}

/// Connection configuration registry (shared data source for all plugins)
///
/// **Important**: This only stores connection **configurations** (host, port, credentials),
/// not active database connections or connection pools. Each plugin manages its own
/// database connections independently.
///
/// This is the single source of truth for connection configurations.
/// The ConnectionManager plugin has write access, other plugins have read access.
pub struct ConnectionConfigRegistry {
    connections: HashMap<String, ConnectionConfig>,
}

impl ConnectionConfigRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            connections: HashMap::new(),
        }
    }

    /// Create registry from configuration
    pub fn from_connections(connections: Vec<ConnectionConfig>) -> Self {
        let mut map = HashMap::new();
        for conn in connections {
            map.insert(conn.connection_key(), conn);
        }
        Self { connections: map }
    }

    /// List all connections
    pub fn list(&self) -> Vec<ConnectionConfig> {
        self.connections.values().cloned().collect()
    }

    /// Get a specific connection by ID
    pub fn get(&self, id: &str) -> Option<ConnectionConfig> {
        self.connections.get(id).cloned()
    }

    /// Add or update a connection (keyed by `connection_key()`)
    ///
    /// This should typically only be called by the ConnectionManager plugin.
    pub fn upsert(&mut self, conn: ConnectionConfig) {
        self.connections.insert(conn.connection_key(), conn);
    }

    /// Delete a connection by its old key, then insert with the new key.
    ///
    /// Used when editing a connection whose name (and thus key) may have changed.
    pub fn replace(&mut self, old_key: &str, conn: ConnectionConfig) {
        self.connections.remove(old_key);
        self.connections.insert(conn.connection_key(), conn);
    }

    /// Delete a connection
    ///
    /// This should typically only be called by the ConnectionManager plugin.
    pub fn delete(&mut self, id: &str) -> Option<ConnectionConfig> {
        self.connections.remove(id)
    }

    /// Check if a connection exists
    pub fn exists(&self, id: &str) -> bool {
        self.connections.contains_key(id)
    }

    /// Get all connection IDs
    pub fn ids(&self) -> Vec<String> {
        self.connections.keys().cloned().collect()
    }

    /// Get connection count
    pub fn count(&self) -> usize {
        self.connections.len()
    }
}

impl Default for ConnectionConfigRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Information about an open tab
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TabInfo {
    /// Tab index (0-based)
    pub index: usize,
    /// Tab title
    pub title: String,
    /// Plugin ID
    pub plugin_id: String,
    /// Plugin-specific context (contains connection_id, table_name, etc.)
    pub context: Value,
    /// Whether this is the currently active tab
    pub is_active: bool,
}

impl TabInfo {
    /// Extract connection_id from context if available
    pub fn connection_id(&self) -> Option<String> {
        self.context
            .get("connection_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    }
}

/// Tab management operations
///
/// Plugins can use this to open new tabs or close themselves.
pub trait TabManager: Send + Sync {
    /// Open a new tab with the specified plugin
    ///
    /// # Arguments
    ///
    /// * `title` - Tab title to display
    /// * `plugin_id` - Plugin identifier (must be registered in PluginRegistry)
    /// * `context` - Plugin-specific context data (e.g., connection_id, table_name)
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // Open a MySQL connection in a new tab
    /// caps.tabs.open(
    ///     "MySQL - production",
    ///     "mysql",
    ///     json!({ "connection_id": "prod-mysql-01" })
    /// )?;
    /// ```
    fn open(&self, title: String, plugin_id: String, context: Value) -> Result<()>;

    /// Close the current tab
    ///
    /// This closes the tab that the calling plugin is running in.
    /// If it's the last tab, the application will quit.
    fn close_current(&self) -> Result<()>;

    /// Update the current tab's title
    ///
    /// Allows plugins to dynamically update their tab title
    /// (e.g., to show the current table name).
    fn set_title(&self, title: String) -> Result<()>;

    /// Request an immediate re-render
    ///
    /// Plugins can call this when they have async updates ready
    /// (e.g., data loaded from database via channel).
    /// This avoids waiting for the next event or periodic render.
    fn request_render(&self) -> Result<()>;

    /// List all open tabs
    ///
    /// Returns information about all tabs, including their index,
    /// title, plugin ID, and context data.
    fn list_tabs(&self) -> Result<Vec<TabInfo>>;

    /// Close a specific tab by index
    ///
    /// Returns an error if the index is out of bounds.
    fn close_tab(&self, index: usize) -> Result<()>;

    /// Switch to a specific tab by index
    ///
    /// Returns an error if the index is out of bounds.
    fn switch_to(&self, index: usize) -> Result<()>;

    /// Get the current active tab index
    fn active_tab_index(&self) -> Result<usize>;

    /// Quit the application
    fn quit(&self) -> Result<()>;
}
