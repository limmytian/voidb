use std::future::Future;
use std::pin::Pin;

use crate::connection::ConnectionConfig;
use crate::database::DatabaseAdapter;
use crate::error::VoidbError;

/// Boxed future returned by `NativePlugin::create_adapter`.
pub type CreateAdapterFuture =
    Pin<Box<dyn Future<Output = Result<Box<dyn DatabaseAdapter>, VoidbError>> + Send>>;

/// Trait for native (compiled-in) plugins.
///
/// Native plugins are Rust crates compiled into the binary via feature gates.
/// They implement database protocol handling directly, with full access to
/// async I/O (networking, filesystem, etc.) — unlike Wasm plugins which run
/// in a sandbox.
///
/// Each native plugin provides a factory method to create a `DatabaseAdapter`
/// for a given connection configuration.
pub trait NativePlugin: Send + Sync {
    /// Unique plugin identifier (e.g. "mysql", "postgres").
    fn plugin_id(&self) -> &str;

    /// Human-readable name (e.g. "MySQL", "PostgreSQL").
    fn name(&self) -> &str;

    /// Protocol identifiers this plugin handles (e.g. ["mysql", "mariadb"]).
    fn protocols(&self) -> &[&str];

    /// Default port for this protocol (e.g. 3306 for MySQL).
    fn default_port(&self) -> u16;

    /// Create a new database adapter for the given connection config.
    fn create_adapter(&self, config: &ConnectionConfig) -> CreateAdapterFuture;
}
