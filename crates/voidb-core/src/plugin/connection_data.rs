/// Connection Data Provider trait - plugins provide connection metadata and configuration.
///
/// This trait allows database/protocol plugins to define:
/// - Connection summary information for display
/// - Custom form fields for connection configuration
/// - Field validation rules
/// - Quick actions available for this connection type
use serde_json::Value;
use std::collections::HashMap;

use crate::connection::ConnectionConfig;

/// Plugin trait for providing connection data and metadata
pub trait ConnectionDataProvider: Send + Sync {
    /// Plugin ID (must match the protocol name)
    fn plugin_id(&self) -> &str;

    /// Provide connection summary for display in Connection Manager
    fn get_connection_summary(&self, config: &ConnectionConfig) -> ConnectionSummary;

    /// Provide custom fields for connection form (beyond standard fields)
    fn get_custom_fields(&self) -> Vec<FieldDefinition>;

    /// Validate a custom field value
    fn validate_custom_field(&self, name: &str, value: &Value) -> Result<(), String>;

    /// Get quick actions available for this connection type
    fn get_quick_actions(&self) -> Vec<QuickAction>;
}

/// Connection summary for display in Connection Manager
#[derive(Debug, Clone)]
pub struct ConnectionSummary {
    /// Icon to display (emoji or Unicode)
    pub icon: String,

    /// Display name (usually same as config.name)
    pub display_name: String,

    /// Type label (e.g., "MySQL 8.0", "IMAP/SMTP", "Redis 7.0")
    pub type_label: String,

    /// Primary info (usually address:port)
    pub primary_info: String,

    /// Secondary info (additional context, e.g., "database: mydb")
    pub secondary_info: String,

    /// Tags for filtering/grouping
    pub tags: Vec<String>,

    /// Additional metadata (key-value pairs for display)
    pub metadata: HashMap<String, String>,

    /// Display layout configuration (controls how this connection is rendered)
    pub display_layout: DisplayLayout,
}

/// Display layout configuration
#[derive(Debug, Clone)]
pub struct DisplayLayout {
    /// Columns to show in list view (plugin-defined)
    pub columns: Vec<ColumnDefinition>,

    /// Badges to show (e.g., unread count, SSL indicator)
    pub badges: Vec<Badge>,

    /// Inline widgets (e.g., progress bars, graphs)
    pub inline_widgets: Vec<InlineWidget>,
}

/// Column definition for list view
#[derive(Debug, Clone)]
pub struct ColumnDefinition {
    /// Column ID (unique within plugin)
    pub id: String,

    /// Column label for header
    pub label: String,

    /// Column value for this connection
    pub value: String,

    /// Column width
    pub width: ColumnWidth,

    /// Text alignment
    pub alignment: Alignment,

    /// Value format (for custom rendering)
    pub format: ColumnFormat,
}

/// Column width specification
#[derive(Debug, Clone, Copy)]
pub enum ColumnWidth {
    /// Fixed width in characters
    Fixed(u16),

    /// Percentage of available width
    Percent(u16),

    /// Auto-size based on content
    Auto,
}

impl ColumnWidth {
    /// Resolve width to actual characters
    pub fn resolve(&self, available_width: u16) -> u16 {
        match self {
            Self::Fixed(w) => *w,
            Self::Percent(p) => (available_width as f32 * (*p as f32 / 100.0)) as u16,
            Self::Auto => available_width / 4, // Default heuristic
        }
    }
}

/// Text alignment
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alignment {
    Left,
    Center,
    Right,
}

/// Column value format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColumnFormat {
    /// Plain text
    Text,

    /// Render as badge
    Badge,

    /// Format as byte size (e.g., "2.3 GB")
    ByteSize,

    /// Format as relative time (e.g., "5m ago")
    RelativeTime,

    /// Format as number with thousands separator
    Number,
}

/// Badge for inline display
#[derive(Debug, Clone)]
pub struct Badge {
    /// Badge text
    pub text: String,

    /// Badge style
    pub style: BadgeStyle,

    /// Optional icon
    pub icon: Option<String>,
}

/// Badge style
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BadgeStyle {
    Info,
    Success,
    Warning,
    Error,
}

/// Inline widget for rich display
#[derive(Debug, Clone)]
pub struct InlineWidget {
    /// Widget type
    pub widget_type: WidgetType,

    /// Widget-specific data
    pub data: Value,
}

/// Widget type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WidgetType {
    /// Plain text
    Text,

    /// Progress bar
    ProgressBar,

    /// Sparkline graph
    Graph,

    /// Custom rendering (plugin-specific)
    Custom,
}

/// Custom field definition for connection form
#[derive(Debug, Clone)]
pub struct FieldDefinition {
    /// Field name (used as key in config)
    pub name: String,

    /// Field label for display
    pub label: String,

    /// Field type
    pub field_type: FieldType,

    /// Default value
    pub default_value: Option<Value>,

    /// Validation rule
    pub validation: ValidationRule,

    /// Help text
    pub help_text: Option<String>,

    /// Whether this field is required
    pub required: bool,
}

/// Field type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldType {
    /// Single-line text input
    Text,

    /// Number input
    Number,

    /// Password input (masked)
    Password,

    /// Multi-line text
    TextArea,

    /// Dropdown select
    Select { options: Vec<String> },

    /// Checkbox
    Checkbox,

    /// File path picker
    FilePath,
}

/// Validation rule
#[derive(Debug, Clone)]
pub enum ValidationRule {
    /// No validation
    None,

    /// Must match regex pattern
    Regex(String),

    /// Must be within range (for numbers)
    Range { min: i64, max: i64 },

    /// Must be one of the allowed values
    OneOf(Vec<String>),

    /// Custom validation (description only, actual validation in plugin)
    Custom(String),
}

/// Quick action definition
#[derive(Debug, Clone)]
pub struct QuickAction {
    /// Action ID (unique within plugin)
    pub id: String,

    /// Action label for button
    pub label: String,

    /// Action icon (optional)
    pub icon: Option<String>,

    /// Action description (for tooltip)
    pub description: Option<String>,
}

// Types are defined directly in this module, no re-export needed
