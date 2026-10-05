//! CLI Plugin trait for plugin-driven CLI commands.
//!
//! Plugins implement `CliPlugin` to register their own CLI subcommands.
//! The CLI binary acts as a pure router, collecting commands from all
//! registered CliPlugins and dispatching execution to the right one.
//!
//! # Example
//!
//! ```rust,ignore
//! use clap::{Arg, ArgMatches, Command};
//! use voidb_core::plugin::cli::{CliPlugin, CliContext};
//!
//! struct MySqlCliPlugin;
//!
//! #[async_trait::async_trait]
//! impl CliPlugin for MySqlCliPlugin {
//!     fn plugin_id(&self) -> &str { "mysql" }
//!     fn name(&self) -> &str { "MySQL" }
//!
//!     fn commands(&self) -> Vec<Command> {
//!         vec![
//!             Command::new("query")
//!                 .about("Execute a SQL query")
//!                 .arg(Arg::new("connection").short('c').required(true)),
//!         ]
//!     }
//!
//!     async fn execute(
//!         &self,
//!         command: &str,
//!         matches: &ArgMatches,
//!         ctx: &CliContext,
//!     ) -> Result<(), crate::VoidbError> {
//!         Ok(())
//!     }
//! }
//! ```

use std::collections::HashMap;

use crate::capability::ConnectionProfile;
use crate::config::AppConfig;
use crate::connection::ConnectionConfig;
use crate::error::VoidbError;
use crate::profile_store::LocalProfileStore;
use async_trait::async_trait;
use clap::ArgMatches;

/// Context passed to CLI plugins during command execution.
///
/// Provides access to application configuration and connection configs
/// (already decrypted by core).
pub struct CliContext {
    pub config: AppConfig,
    master_password: Option<String>,
}

impl CliContext {
    pub fn new(config: AppConfig) -> Self {
        Self {
            config,
            master_password: None,
        }
    }

    pub fn with_master_password(mut self, master_password: Option<String>) -> Self {
        self.master_password = master_password;
        self
    }

    pub fn credential_master_password(&self) -> Result<Option<&str>, VoidbError> {
        if self.config.requires_master_password() && self.master_password.is_none() {
            return Err(VoidbError::Config(
                "Master password is not available in this CLI process".to_string(),
            ));
        }
        Ok(self.master_password.as_deref())
    }

    /// Find a connection by user-visible name.
    pub fn find_connection(&self, name: &str) -> Option<&ConnectionConfig> {
        self.config.connections.iter().find(|c| c.name == name)
    }

    /// Find connections belonging to a specific plugin.
    pub fn connections_for_plugin(&self, plugin_id: &str) -> Vec<&ConnectionConfig> {
        self.config
            .connections
            .iter()
            .filter(|c| c.effective_plugin_id() == plugin_id)
            .collect()
    }

    /// Load persisted native profiles.
    ///
    /// Legacy connections enter this store only through the explicit migration
    /// command; they are never projected into the active profile catalog.
    pub fn profiles(&self) -> Result<Vec<ConnectionProfile>, VoidbError> {
        let store = LocalProfileStore::default_store()?;
        store.load_profiles()
    }

    /// Resolve a profile into the internal service connection DTO.
    pub fn resolve_profile_connection(
        &self,
        profile_ref: &str,
        plugin_filter: Option<&str>,
    ) -> Result<(ConnectionProfile, ConnectionConfig), VoidbError> {
        let profiles = self.profiles()?;
        let matches = profiles
            .into_iter()
            .filter(|profile| plugin_filter.is_none_or(|plugin| profile.plugin_id == plugin))
            .filter(|profile| profile_ref_matches(profile, profile_ref))
            .collect::<Vec<_>>();

        let profile = match matches.len() {
            0 => {
                let plugin_hint = plugin_filter
                    .map(|plugin| format!(" for plugin '{}'", plugin))
                    .unwrap_or_default();
                return Err(VoidbError::Plugin(format!(
                    "Profile '{}' not found{}",
                    profile_ref, plugin_hint
                )));
            }
            1 => matches.into_iter().next().expect("len checked"),
            _ => {
                return Err(VoidbError::Plugin(format!(
                    "Profile '{}' is ambiguous; pass id:<profile-id> or --plugin where available",
                    profile_ref
                )));
            }
        };

        let store = LocalProfileStore::default_store()?;
        let master_password = self.credential_master_password()?;
        let connection = match store.native_connection(&profile, master_password) {
            Ok(connection) => connection,
            Err(native_error) => {
                let legacy_key = profile
                    .metadata
                    .get("legacy_connection_key")
                    .and_then(serde_json::Value::as_str);
                match legacy_key.and_then(|key| self.config.connection_by_key_or_name(key)) {
                    Some(connection) => connection.clone(),
                    None => return Err(native_error),
                }
            }
        };

        Ok((profile, connection))
    }
}

fn profile_ref_matches(profile: &ConnectionProfile, profile_ref: &str) -> bool {
    if let Some(id) = profile_ref.strip_prefix("id:") {
        profile.id == id
    } else if let Some(name) = profile_ref
        .strip_prefix("name:")
        .or_else(|| profile_ref.strip_prefix("alias:"))
    {
        crate::profile_names_equal(&profile.name, name)
    } else {
        crate::profile_names_equal(&profile.name, profile_ref) || profile.id == profile_ref
    }
}

/// Trait for plugins that provide CLI commands.
///
/// Independent from `Plugin` (TUI). A plugin crate can
/// implement any combination of these traits.
#[async_trait]
pub trait CliPlugin: Send + Sync {
    /// Unique plugin identifier — must match the plugin's ID across
    /// all trait implementations (NativePlugin, Plugin, etc.)
    fn plugin_id(&self) -> &str;

    /// Human-readable plugin name
    fn name(&self) -> &str;

    /// Return the clap Command definitions this plugin provides.
    ///
    /// Each `Command` becomes a subcommand under `voidb <plugin_id> <command>`.
    /// Plugins have full control over arguments, flags, subcommands, help text.
    fn commands(&self) -> Vec<clap::Command>;

    /// Execute a matched command.
    ///
    /// - `command`: the subcommand name that was matched
    /// - `matches`: parsed `ArgMatches` for this subcommand
    /// - `ctx`: CLI context with config and connections
    ///
    /// Plugins write directly to stdout/stderr. No global formatting layer.
    async fn execute(
        &self,
        command: &str,
        matches: &ArgMatches,
        ctx: &CliContext,
    ) -> Result<(), VoidbError>;
}

/// Manager for CLI plugins.
pub struct CliPluginManager {
    plugins: HashMap<String, Box<dyn CliPlugin>>,
}

impl Default for CliPluginManager {
    fn default() -> Self {
        Self::new()
    }
}

impl CliPluginManager {
    pub fn new() -> Self {
        Self {
            plugins: HashMap::new(),
        }
    }

    pub fn register(&mut self, plugin: Box<dyn CliPlugin>) {
        let id = plugin.plugin_id().to_string();
        self.plugins.insert(id, plugin);
    }

    pub fn get(&self, plugin_id: &str) -> Option<&dyn CliPlugin> {
        self.plugins.get(plugin_id).map(|p| p.as_ref())
    }

    pub fn list(&self) -> Vec<&str> {
        self.plugins.keys().map(|s| s.as_str()).collect()
    }

    /// Build the clap command tree from all registered plugins.
    ///
    /// Each plugin becomes: `voidb <plugin_id> <subcommand> [args...]`
    pub fn build_commands(&self) -> Vec<clap::Command> {
        let mut cmds: Vec<_> = self
            .plugins
            .values()
            .map(|plugin| {
                let name: &'static str = plugin.plugin_id().to_string().leak();
                let about: &'static str = format!("{} commands", plugin.name()).leak();
                let mut cmd = clap::Command::new(name)
                    .about(about)
                    .subcommand_required(true)
                    .arg_required_else_help(true);
                for subcmd in plugin.commands() {
                    cmd = cmd.subcommand(subcmd);
                }
                cmd
            })
            .collect();
        cmds.sort_by(|a, b| a.get_name().cmp(b.get_name()));
        cmds
    }

    /// Route a matched command to the appropriate plugin.
    pub async fn dispatch(
        &self,
        plugin_id: &str,
        matches: &ArgMatches,
        ctx: &CliContext,
    ) -> Result<(), VoidbError> {
        let plugin = self
            .get(plugin_id)
            .ok_or_else(|| VoidbError::Plugin(format!("CLI plugin not found: {}", plugin_id)))?;

        let (subcommand, sub_matches) = matches.subcommand().ok_or_else(|| {
            VoidbError::Plugin(format!(
                "No subcommand specified for '{}'. Run 'voidb {} --help' for available commands.",
                plugin_id, plugin_id
            ))
        })?;

        plugin.execute(subcommand, sub_matches, ctx).await
    }
}
