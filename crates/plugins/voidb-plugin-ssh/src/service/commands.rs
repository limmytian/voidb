//! SSH service command types.
//!
//! Commands are sent from the TUI plugin to the background service task
//! via an unbounded mpsc channel. Uses grouped sub-enums for SFTP,
//! forwarding, and metrics domains.

use crate::config::SshConfig;
use super::types::ForwardType;

/// Top-level command enum for the SSH service.
///
/// Covers connection lifecycle, SFTP sub-service management,
/// port forwarding, and system metrics collection.
#[derive(Debug)]
pub enum SshCommand {
    // --- Connection lifecycle ---
    /// Create SSH connection using the given config.
    Connect { config: SshConfig },

    /// Disconnect the current session gracefully.
    Disconnect,

    /// Reconnect using the last known config with exponential backoff.
    Reconnect,

    /// Notify the service of a terminal resize.
    Resize { cols: u16, rows: u16 },

    // --- SFTP sub-service (D-04) ---
    /// SFTP sub-service management commands.
    Sftp(SftpServiceCommand),

    // --- Port forwarding (D-06) ---
    /// Port forwarding management commands.
    Forward(ForwardServiceCommand),

    // --- System metrics (D-07) ---
    /// System metrics collection commands.
    Metrics(MetricsServiceCommand),
}

/// Service-level SFTP commands.
///
/// These control the SFTP sub-service lifecycle, NOT individual file operations.
/// Fine-grained SFTP operations (ListDir, Download, etc.) go through the
/// `SftpHandle` returned by `SshEvent::SftpReady`.
#[derive(Debug)]
pub enum SftpServiceCommand {
    /// Open the SFTP subsystem channel and create a worker.
    Open,
    /// Close the SFTP subsystem and drop the worker.
    Close,
}

/// Port forwarding management commands.
#[derive(Debug)]
pub enum ForwardServiceCommand {
    /// Add a new forwarding rule.
    Add(ForwardType),
    /// Remove a forwarding rule by its ID.
    Remove(u32),
}

/// System metrics collection commands.
#[derive(Debug)]
pub enum MetricsServiceCommand {
    /// Start the metrics collector.
    Start,
    /// Stop the metrics collector.
    Stop,
    /// Trigger an immediate metrics refresh.
    Refresh,
}
