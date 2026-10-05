/// Connection Display Provider trait - universal display protocol.
///
/// This trait allows plugins to control how connections are displayed in the
/// Connection Manager list/grid view. Plugins can choose from predefined view
/// modes or provide custom rendering.
use crate::plugin::connection_data::ColumnDefinition;

/// Plugin trait for controlling connection display
pub trait ConnectionDisplayProvider: Send + Sync {
    /// Plugin identifier (same as NativePlugin::plugin_id)
    fn plugin_id(&self) -> &str;

    /// Get display configuration for this connection type
    fn get_display_config(&self) -> DisplayConfig;

    /// Check if this plugin provides custom row rendering
    ///
    /// If true, the UI layer will call the plugin's UI component
    /// for rendering. Most plugins should return false and use
    /// DisplayConfig instead.
    fn has_custom_rendering(&self) -> bool {
        false // Default: use standard rendering
    }
}

/// Display configuration for a connection type
#[derive(Debug, Clone)]
pub struct DisplayConfig {
    /// View mode for this connection type
    pub view_mode: ViewMode,

    /// Default columns to display (standard fields)
    pub default_columns: Vec<DefaultColumn>,

    /// Custom columns (plugin-defined)
    pub custom_columns: Vec<ColumnDefinition>,

    /// Sort options available
    pub sort_options: Vec<SortOption>,

    /// Filter options available
    pub filter_options: Vec<FilterOption>,
}

/// View mode for displaying connections
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ViewMode {
    /// Standard table view (most connections)
    /// - Columns aligned
    /// - Good for structured data
    Table,

    /// Card-based view
    /// - Each connection as a card
    /// - Good for rich metadata
    Cards,

    /// Compact list view
    /// - Single line per connection
    /// - Good for many connections
    Compact,

    /// Custom rendering (plugin provides render_row)
    Custom,
}

/// Default column (standard field from ConnectionConfig)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultColumn {
    /// Connection status indicator (🟢/🔴/🟡)
    Status,

    /// Plugin-provided icon
    Icon,

    /// Connection name
    Name,

    /// Database/protocol type
    Type,

    /// Host:port or URL
    Address,

    /// Username
    User,

    /// Database name (if applicable)
    Database,

    /// Last used timestamp
    LastUsed,

    /// Tags/labels
    Tags,
}

/// Sort option
#[derive(Debug, Clone)]
pub enum SortOption {
    /// Sort by name (alphabetical)
    Name,

    /// Sort by last used (most recent first)
    LastUsed,

    /// Sort by status (connected first)
    Status,

    /// Sort by type (group by database type)
    Type,

    /// Custom sort (plugin-defined column)
    Custom(String),
}

/// Filter option
#[derive(Debug, Clone)]
pub enum FilterOption {
    /// Filter by connection status
    ByStatus,

    /// Filter by tag
    ByTag,

    /// Filter by type
    ByType,

    /// Custom filter (plugin-defined)
    Custom {
        /// Filter ID
        id: String,

        /// Filter label for UI
        label: String,

        /// Filter description
        description: Option<String>,
    },
}

impl Default for DisplayConfig {
    fn default() -> Self {
        Self {
            view_mode: ViewMode::Table,
            default_columns: vec![
                DefaultColumn::Status,
                DefaultColumn::Icon,
                DefaultColumn::Name,
                DefaultColumn::Type,
                DefaultColumn::Address,
                DefaultColumn::LastUsed,
            ],
            custom_columns: Vec::new(),
            sort_options: vec![SortOption::Name, SortOption::LastUsed],
            filter_options: vec![FilterOption::ByStatus, FilterOption::ByType],
        }
    }
}

// Types are defined directly in this module, no re-export needed
