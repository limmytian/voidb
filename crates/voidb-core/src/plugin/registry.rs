//! Plugin registry and factory system
//!
//! This module provides a registry for plugin factories, allowing the VoidB shell
//! to dynamically instantiate plugins based on plugin IDs.

use std::collections::HashMap;

use anyhow::{anyhow, Result};
use serde_json::Value;

use super::Plugin;
use super::connection_dialog::ConnectionDialogComponent;
use crate::ConnectionConfig;

/// Factory for creating plugin instances
///
/// Each plugin type registers a factory that can create new instances
/// with the given context data.
pub trait PluginFactory: Send + Sync {
    /// Create a new plugin instance
    ///
    /// # Arguments
    ///
    /// * `context` - Plugin-specific context data (e.g., connection_id, table_name)
    ///
    /// # Returns
    ///
    /// A boxed plugin instance ready to be initialized
    fn create(&self, context: Value) -> Result<Box<dyn Plugin>>;

    /// Get the plugin ID this factory creates
    fn plugin_id(&self) -> &str;

    /// Get human-readable plugin name
    fn plugin_name(&self) -> &str;

    /// Get plugin description
    fn description(&self) -> &str {
        ""
    }

    /// Create a custom connection dialog component for this plugin.
    ///
    /// If the plugin returns Some, it takes full control of the connection
    /// configuration UI. The plugin can define arbitrary fields, validation
    /// logic, and interaction flows.
    ///
    /// If None, the ConnectionManager will use the default dialog with
    /// standard fields + custom fields from `connection_fields()`.
    ///
    /// # Arguments
    ///
    /// * `existing_config` - If editing an existing connection, this contains
    ///   the current configuration. If creating a new connection, this is None.
    ///
    /// # Returns
    ///
    /// A boxed ConnectionDialogComponent, or None to use the default dialog.
    fn create_connection_dialog(
        &self,
        _existing_config: Option<&ConnectionConfig>,
    ) -> Option<Box<dyn ConnectionDialogComponent>> {
        None
    }
}

/// Registry of plugin factories
///
/// The VoidB shell uses this registry to instantiate plugins when:
/// - Opening a new tab
/// - Restoring a session
/// - User selects a plugin from the menu
pub struct PluginRegistry {
    factories: HashMap<String, Box<dyn PluginFactory>>,
}

impl PluginRegistry {
    /// Create a new empty plugin registry
    pub fn new() -> Self {
        Self {
            factories: HashMap::new(),
        }
    }

    /// Register a plugin factory
    ///
    /// # Arguments
    ///
    /// * `factory` - Plugin factory to register
    ///
    /// # Panics
    ///
    /// Panics if a factory with the same plugin_id is already registered.
    /// This is intentional to catch configuration errors early.
    pub fn register(&mut self, factory: Box<dyn PluginFactory>) {
        let plugin_id = factory.plugin_id().to_string();
        if self.factories.contains_key(&plugin_id) {
            panic!("Plugin factory already registered: {}", plugin_id);
        }
        self.factories.insert(plugin_id, factory);
    }

    /// Create a plugin instance
    ///
    /// # Arguments
    ///
    /// * `plugin_id` - Plugin identifier (must be registered)
    /// * `context` - Plugin-specific context data
    ///
    /// # Returns
    ///
    /// A boxed plugin instance (not yet initialized)
    pub fn create(&self, plugin_id: &str, context: Value) -> Result<Box<dyn Plugin>> {
        let factory = self
            .factories
            .get(plugin_id)
            .ok_or_else(|| anyhow!("Unknown plugin: {}", plugin_id))?;

        factory.create(context)
    }

    /// Check if a plugin is registered
    pub fn has_plugin(&self, plugin_id: &str) -> bool {
        self.factories.contains_key(plugin_id)
    }

    /// List all registered plugin IDs
    pub fn list_plugins(&self) -> Vec<String> {
        self.factories.keys().cloned().collect()
    }

    /// Get plugin information
    pub fn get_plugin_info(&self, plugin_id: &str) -> Option<PluginInfo> {
        self.factories.get(plugin_id).map(|factory| PluginInfo {
            id: factory.plugin_id().to_string(),
            name: factory.plugin_name().to_string(),
            description: factory.description().to_string(),
        })
    }

    /// Create a custom connection dialog component for a plugin
    ///
    /// # Arguments
    ///
    /// * `plugin_id` - Plugin identifier
    /// * `existing_config` - Optional existing configuration (for editing)
    ///
    /// # Returns
    ///
    /// A boxed ConnectionDialogComponent if the plugin provides one, or None
    /// to use the default dialog.
    pub fn create_connection_dialog(
        &self,
        plugin_id: &str,
        existing_config: Option<&ConnectionConfig>,
    ) -> Option<Box<dyn ConnectionDialogComponent>> {
        self.factories
            .get(plugin_id)
            .and_then(|f| f.create_connection_dialog(existing_config))
    }

    /// List all plugin information
    pub fn list_plugin_info(&self) -> Vec<PluginInfo> {
        self.factories
            .values()
            .map(|factory| PluginInfo {
                id: factory.plugin_id().to_string(),
                name: factory.plugin_name().to_string(),
                description: factory.description().to_string(),
            })
            .collect()
    }
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Plugin information
#[derive(Debug, Clone)]
pub struct PluginInfo {
    /// Plugin ID
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Description
    pub description: String,
}
