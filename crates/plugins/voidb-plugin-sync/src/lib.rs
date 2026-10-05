//! VoidB Sync Plugin — E2E encrypted config/data sync.
//!
//! Entrypoints:
//!   - [`ops::push`] / [`ops::pull`] — library surface reusable from a CLI
//!
//! Author: Limmy

pub mod bundler;
pub mod capabilities;
pub mod cli_plugin;
pub mod client;
pub mod config;
pub mod crypto;
pub mod error;
pub mod ops;
pub mod session;
pub mod token_store;

pub use capabilities::{
    invoke_sync_capability, invoke_sync_capability_with_config, sync_capabilities,
};
pub use cli_plugin::create_sync_cli_plugin;
pub use error::SyncError;
