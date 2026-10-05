use serde::{Deserialize, Serialize};

/// Connection configuration for any supported database or service.
///
/// ## Architecture
///
/// All plugins use `plugin_config` to store their configuration:
/// - All configuration stored in `plugin_config` as JSON
/// - Plugin defines its own structure (host, credentials, protocol settings, etc.)
/// - Encrypted as a whole for security
/// - Examples: Email plugin, MySQL plugin, PostgreSQL plugin, SQLite plugin
///
/// The plugin_id field determines which plugin handles this connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionConfig {
    /// Connection name (user-visible identifier)
    pub name: String,

    /// Connection type (determines which plugin handles it)
    pub db_type: DatabaseType,

    /// Plugin ID (determines which plugin handles this connection)
    #[serde(default)]
    pub plugin_id: Option<String>,

    /// Plugin-specific configuration as JSON
    ///
    /// Contains all connection details including credentials, server settings,
    /// and protocol-specific options.
    ///
    /// **Structure is plugin-defined**: Each plugin deserializes this into
    /// its own config struct (e.g., MySqlConfig, EmailConfig).
    ///
    /// **Encrypted at rest**: Entire JSON blob is encrypted by Core.
    #[serde(default)]
    pub plugin_config: Option<serde_json::Value>,
}

impl ConnectionConfig {
    /// Get display name for UI (always uses the name field)
    pub fn display_name(&self) -> String {
        self.name.clone()
    }

    /// Resolve the effective plugin ID for this connection.
    ///
    /// For `DatabaseType::Plugin`, returns the `plugin_id` field.
    /// For built-in types (MySQL, PostgreSQL, SQLite), returns `db_type.protocol_name()`.
    pub fn effective_plugin_id(&self) -> &str {
        if let Some(ref id) = self.plugin_id {
            id.as_str()
        } else {
            self.db_type.protocol_name()
        }
    }

    /// Internal unique key: `"{effective_plugin_id}::{name}"`.
    ///
    /// This allows different plugins to have connections with the same user-visible
    /// name without collision. For example, `"mysql::prod"` and `"redis::prod"`
    /// can coexist.
    pub fn connection_key(&self) -> String {
        format!("{}::{}", self.effective_plugin_id(), self.name)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum DatabaseType {
    MySQL,
    PostgreSQL,
    SQLite,
    /// A plugin-provided database type.
    /// The actual protocol is determined by `plugin_id` in ConnectionConfig.
    Plugin,
}

impl DatabaseType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::MySQL => "MySQL",
            Self::PostgreSQL => "PostgreSQL",
            Self::SQLite => "SQLite",
            Self::Plugin => "Plugin",
        }
    }

    /// Return the protocol name used for plugin routing.
    pub fn protocol_name(&self) -> &'static str {
        match self {
            Self::MySQL => "mysql",
            Self::PostgreSQL => "postgresql",
            Self::SQLite => "sqlite",
            Self::Plugin => "plugin",
        }
    }

    pub fn default_port(&self) -> u16 {
        match self {
            Self::MySQL => 3306,
            Self::PostgreSQL => 5432,
            Self::SQLite => 0,
            Self::Plugin => 0,
        }
    }
}

impl std::fmt::Display for DatabaseType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Unique identifier for a connection.
pub type ConnectionId = String;
