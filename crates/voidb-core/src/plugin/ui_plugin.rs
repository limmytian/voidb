//! UI Plugin trait for tree rendering
//!
//! This module defines the `UiPlugin` trait that allows database plugins
//! to render their own tree structure in the VoidB TUI.

use anyhow::Result;
use serde_json::Value;

/// Tree node definition returned by plugins
#[derive(Debug, Clone)]
pub struct TreeNodeDef {
    /// Display label for the node
    pub label: String,
    /// Icon/prefix to display (e.g., "🗄️", "📄", "[+]")
    pub icon: String,
    /// Whether this node can be expanded
    pub expandable: bool,
    /// Child nodes (empty if not expandable or not yet loaded)
    pub children: Vec<TreeNodeDef>,
    /// Plugin-specific metadata (stored as JSON)
    pub metadata: Value,
}

/// UI plugin trait for rendering database structure in the tree
pub trait UiPlugin: Send + Sync {
    /// Unique identifier for this plugin
    fn plugin_id(&self) -> &str;

    /// Render the tree structure for a connection
    ///
    /// # Arguments
    /// * `connection_id` - The connection ID to render
    /// * `state` - Plugin-specific state (can be downcast to concrete type)
    ///
    /// # Returns
    /// A vector of top-level tree nodes (typically databases or schemas)
    fn render_tree(
        &self,
        connection_id: &str,
        state: &dyn std::any::Any,
    ) -> Result<Vec<TreeNodeDef>>;
}
