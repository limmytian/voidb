//! Plugin system for VoidB
//!
//! # Architecture v4.0: Autonomous Plugins with Service Layer
//!
//! VoidB uses a pure router architecture where plugins are autonomous
//! applications running within the VoidB shell. Each plugin's data
//! operations are extracted into a `service/` submodule, enabling
//! TUI, CLI, and future interfaces to share the same logic.
//!
//! # Core Plugin System
//!
//! ```rust,no_run
//! use voidb_core::Plugin;
//! // Implement Plugin trait for autonomous plugins
//! ```

pub mod native;

// Connection Manager plugin traits (Phase 1)
pub mod connection_data;
pub mod connection_display;
pub mod connection_dialog;

// UI plugin trait for tree rendering (RFC 002 Phase 1)
pub mod ui_plugin;

// v4.0 Core Plugin trait
pub mod plugin_trait;

// v4.0 Plugin registry system
pub mod registry;

// CLI plugin trait
pub mod cli;

pub use native::NativePlugin;

// Re-export connection plugin traits
pub use connection_data::{
    Alignment, Badge, BadgeStyle, ColumnDefinition, ColumnFormat, ColumnWidth,
    ConnectionDataProvider, ConnectionSummary, DisplayLayout, FieldDefinition, FieldType,
    InlineWidget, QuickAction, ValidationRule, WidgetType,
};
pub use connection_display::{
    ConnectionDisplayProvider, DefaultColumn, DisplayConfig, FilterOption, SortOption, ViewMode,
};
pub use connection_dialog::{ConnectionDialogComponent, DialogAction};

// Re-export UI plugin traits
pub use ui_plugin::{TreeNodeDef, UiPlugin};

// Re-export v4.0 Plugin trait
pub use plugin_trait::Plugin;

// Re-export v4.0 Plugin registry
pub use registry::{PluginFactory, PluginInfo, PluginRegistry};

// Re-export CLI plugin traits
pub use cli::{CliContext, CliPlugin, CliPluginManager};
