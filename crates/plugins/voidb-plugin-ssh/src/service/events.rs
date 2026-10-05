//! SSH service event types.
//!
//! Events are sent from the background service task to the TUI plugin
//! via an unbounded mpsc channel. PTY data flows through a separate
//! dedicated byte channel (not as events) per the hybrid I/O design.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use tokio::sync::{mpsc, oneshot};

use super::types::{ForwardStatus, SftpCommand, SftpEvent, SystemMetrics};

/// Events produced by the SSH service for the TUI plugin.
///
/// NOTE: This enum does NOT derive Clone because `HostKeyVerify` contains
/// a `oneshot::Sender` which is !Clone. The TUI must consume events by
/// draining the channel.
#[derive(Debug)]
pub enum SshEvent {
    /// SSH connection established successfully.
    Connected,

    /// SSH session disconnected.
    Disconnected,

    /// Attempting automatic reconnection.
    Reconnecting {
        attempt: u32,
        max_attempts: u32,
        retry_in_secs: f64,
    },

    /// All reconnection attempts exhausted.
    ReconnectFailed,

    /// An error occurred in the SSH session.
    Error(String),

    /// Host key verification required. The TUI must respond via the
    /// oneshot sender (true = accept, false = reject).
    HostKeyVerify {
        host: String,
        port: u16,
        fingerprint: String,
        /// `true` if key exists in known_hosts but does NOT match (potential MITM).
        key_changed: bool,
        reply: oneshot::Sender<bool>,
    },

    /// SFTP subsystem is ready. The handle provides independent channels
    /// for SFTP operations (ListDir, Download, Upload, etc.).
    SftpReady(SftpHandle),

    /// SFTP subsystem was closed.
    SftpClosed,

    /// SFTP subsystem failed to open or encountered a fatal error.
    SftpError(String),

    /// A forwarding rule's status changed.
    ForwardStatusChanged {
        id: u32,
        status: ForwardStatus,
    },

    /// New system metrics snapshot available.
    MetricsUpdate(SystemMetrics),

    /// System metrics collection error.
    MetricsError(String),
}

/// Handle for interacting with the SFTP worker.
///
/// Provides independent command/event channels so the SFTP browser can
/// communicate directly with the worker without going through the main
/// SshService command channel.
pub struct SftpHandle {
    /// Send SFTP commands (ListDir, Download, Upload, etc.) to the worker.
    pub cmd_tx: mpsc::UnboundedSender<SftpCommand>,
    /// Receive SFTP events (DirListed, Progress, etc.) from the worker.
    pub event_rx: mpsc::UnboundedReceiver<SftpEvent>,
    /// Shared cancellation flag for active transfers.
    pub cancel: Arc<AtomicBool>,
}

impl SftpHandle {
    /// Send a command to the SFTP worker.
    pub fn send(&self, cmd: SftpCommand) {
        let _ = self.cmd_tx.send(cmd);
    }

    /// Poll for the next SFTP event (non-blocking).
    pub fn poll_event(&mut self) -> Option<SftpEvent> {
        self.event_rx.try_recv().ok()
    }

    /// Signal the worker to cancel any active transfer.
    pub fn cancel_transfer(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }
}

impl std::fmt::Debug for SftpHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SftpHandle")
            .field("cancel", &self.cancel.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_send<T: Send>() {}

    #[test]
    fn ssh_command_is_send() {
        assert_send::<super::super::commands::SshCommand>();
    }

    #[test]
    fn ssh_event_is_send() {
        assert_send::<SshEvent>();
    }

    #[test]
    fn sftp_handle_is_send() {
        assert_send::<SftpHandle>();
    }
}
