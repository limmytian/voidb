//! Shared types for the SSH service layer.
//!
//! Consolidates types from SFTP, port forwarding, and system metrics
//! into a single module for the service layer's public API.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

// === SFTP types (from sftp/types.rs) ===

/// A remote filesystem entry
pub struct RemoteEntry {
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub permissions: Option<u32>,
    /// Unix timestamp (seconds since epoch)
    pub mtime: Option<u32>,
}

/// Commands sent from the UI to the SFTP worker
pub enum SftpCommand {
    /// List directory contents at the given path
    ListDir(String),
    /// Download a remote file to a local path
    DownloadFile {
        remote: String,
        local: String,
    },
    /// Upload a local file to a remote directory
    UploadFile {
        local: String,
        remote_dir: String,
    },
    /// Delete a remote file
    DeleteFile(String),
    /// Delete a remote directory
    DeleteDir(String),
    /// Rename a remote file or directory
    Rename {
        old: String,
        new: String,
    },
    /// Create a remote directory
    CreateDir(String),
    /// Change permissions of a remote file or directory
    Chmod {
        path: String,
        mode: u32,
    },
    /// Cancel all active transfers
    CancelTransfer,
}

/// Events sent from the SFTP worker back to the UI
pub enum SftpEvent {
    /// Directory listing completed
    DirListed {
        path: String,
        entries: Vec<RemoteEntry>,
    },
    /// An error occurred
    Error(String),
    /// File download completed
    DownloadComplete {
        #[allow(dead_code)]
        remote: String,
        local: String,
    },
    /// File download progress update
    DownloadProgress {
        remote: String,
        transferred: u64,
        total: u64,
    },
    /// File upload progress update
    UploadProgress {
        local: String,
        transferred: u64,
        total: u64,
    },
    /// File upload completed
    UploadComplete {
        local: String,
        #[allow(dead_code)]
        remote: String,
    },
    /// A mutation operation completed successfully (with message)
    OperationComplete(String),
    /// Transfer was cancelled
    TransferCancelled,
}

/// Tracks progress of an active file transfer
pub struct TransferProgress {
    /// Display filename
    pub filename: String,
    /// Bytes transferred so far
    pub transferred: u64,
    /// Total file size
    pub total: u64,
    /// When the transfer started
    pub started_at: Instant,
    /// Whether this is a download (true) or upload (false)
    pub is_download: bool,
}

impl TransferProgress {
    /// Calculate transfer speed in bytes per second
    pub fn speed_bps(&self) -> f64 {
        let elapsed = self.started_at.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            self.transferred as f64 / elapsed
        } else {
            0.0
        }
    }

    /// Calculate estimated time remaining in seconds
    pub fn eta_secs(&self) -> Option<f64> {
        let speed = self.speed_bps();
        if speed > 0.0 && self.total > self.transferred {
            Some((self.total - self.transferred) as f64 / speed)
        } else {
            None
        }
    }

    /// Progress as a fraction 0.0..1.0
    pub fn fraction(&self) -> f64 {
        if self.total > 0 {
            (self.transferred as f64 / self.total as f64).min(1.0)
        } else {
            0.0
        }
    }
}

// === Port forwarding types (from forwarding/types.rs) ===

/// Port forwarding rule type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardType {
    /// Local forwarding: listen locally, forward to remote via SSH (-L)
    Local {
        bind_addr: String,
        bind_port: u16,
        remote_host: String,
        remote_port: u16,
    },
    /// Remote forwarding: listen on remote, forward to local (-R)
    Remote {
        remote_addr: String,
        remote_port: u16,
        local_host: String,
        local_port: u16,
    },
    /// Dynamic SOCKS5 proxy: listen locally as SOCKS5 proxy (-D)
    Dynamic {
        bind_addr: String,
        bind_port: u16,
    },
}

/// Status of a forwarding rule
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardStatus {
    /// Rule is starting up
    Starting,
    /// Actively listening / forwarding
    Active,
    /// Rule encountered an error
    Error(String),
    /// Rule was stopped
    Stopped,
}

/// A port forwarding rule with runtime stats
#[derive(Clone)]
pub struct ForwardRule {
    pub id: u32,
    pub forward_type: ForwardType,
    pub status: ForwardStatus,
    pub stats: Arc<ForwardStats>,
}

/// Thread-safe forwarding statistics
pub struct ForwardStats {
    pub bytes_sent: AtomicU64,
    pub bytes_received: AtomicU64,
    pub active_connections: AtomicU64,
    pub total_connections: AtomicU64,
    pub enabled: AtomicBool,
}

impl Default for ForwardStats {
    fn default() -> Self {
        Self {
            bytes_sent: AtomicU64::new(0),
            bytes_received: AtomicU64::new(0),
            active_connections: AtomicU64::new(0),
            total_connections: AtomicU64::new(0),
            enabled: AtomicBool::new(true),
        }
    }
}

impl ForwardStats {
    pub fn add_sent(&self, n: u64) {
        self.bytes_sent.fetch_add(n, Ordering::Relaxed);
    }

    pub fn add_received(&self, n: u64) {
        self.bytes_received.fetch_add(n, Ordering::Relaxed);
    }
}

impl ForwardType {
    /// Human-readable summary
    pub fn summary(&self) -> String {
        match self {
            ForwardType::Local {
                bind_addr,
                bind_port,
                remote_host,
                remote_port,
            } => format!("-L {}:{}:{}:{}", bind_addr, bind_port, remote_host, remote_port),
            ForwardType::Remote {
                remote_addr,
                remote_port,
                local_host,
                local_port,
            } => format!("-R {}:{}:{}:{}", remote_addr, remote_port, local_host, local_port),
            ForwardType::Dynamic {
                bind_addr,
                bind_port,
            } => format!("-D {}:{}", bind_addr, bind_port),
        }
    }

    pub fn type_label(&self) -> &'static str {
        match self {
            ForwardType::Local { .. } => "Local",
            ForwardType::Remote { .. } => "Remote",
            ForwardType::Dynamic { .. } => "SOCKS5",
        }
    }
}

// === System metrics types (from monitor/types.rs) ===

/// Detected remote operating system
#[derive(Debug, Clone, PartialEq)]
pub enum OsType {
    Linux,
    MacOS,
    Unknown(String),
}

/// Memory information in bytes
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct MemoryInfo {
    pub total: u64,
    pub used: u64,
    pub available: u64,
}

/// Disk partition information
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct DiskInfo {
    pub filesystem: String,
    pub mountpoint: String,
    /// Total size in bytes
    pub total: u64,
    /// Used space in bytes
    pub used: u64,
    /// Available space in bytes
    pub available: u64,
}

/// Snapshot of remote system metrics
#[derive(Debug, Clone)]
pub struct SystemMetrics {
    pub cpu_usage: f64,
    pub memory: MemoryInfo,
    pub disks: Vec<DiskInfo>,
    pub load_average: [f64; 3],
    pub uptime_secs: u64,
    pub os_type: OsType,
    pub hostname: String,
    pub timestamp: Instant,
}

/// Commands sent from the service to the metrics collector (internal)
pub enum MetricsCommand {
    /// Trigger an immediate refresh
    Refresh,
    /// Stop the collector
    #[allow(dead_code)]
    Stop,
}

/// Events sent from the metrics collector to the service (internal)
pub enum MetricsEvent {
    /// New metrics snapshot available
    Updated(SystemMetrics),
    /// An error occurred during collection
    Error(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    // --- TransferProgress tests ---

    fn make_progress(transferred: u64, total: u64, elapsed: Duration) -> TransferProgress {
        TransferProgress {
            filename: "test.bin".to_string(),
            transferred,
            total,
            started_at: Instant::now() - elapsed,
            is_download: true,
        }
    }

    #[test]
    fn fraction_normal() {
        let p = make_progress(500, 1000, Duration::from_secs(1));
        assert!((p.fraction() - 0.5).abs() < 0.001);
    }

    #[test]
    fn fraction_zero_total() {
        let p = make_progress(0, 0, Duration::from_secs(1));
        assert_eq!(p.fraction(), 0.0);
    }

    #[test]
    fn fraction_capped_at_one() {
        let p = make_progress(2000, 1000, Duration::from_secs(1));
        assert_eq!(p.fraction(), 1.0);
    }

    #[test]
    fn fraction_complete() {
        let p = make_progress(1000, 1000, Duration::from_secs(1));
        assert!((p.fraction() - 1.0).abs() < 0.001);
    }

    #[test]
    fn speed_bps_after_elapsed() {
        let p = make_progress(10_000, 100_000, Duration::from_secs(2));
        let speed = p.speed_bps();
        // 10000 bytes / 2 seconds = ~5000 bps (allow some tolerance for timing)
        assert!(speed > 4000.0 && speed < 6000.0, "speed was {speed}");
    }

    #[test]
    fn speed_bps_zero_elapsed() {
        let p = TransferProgress {
            filename: "test.bin".to_string(),
            transferred: 1000,
            total: 2000,
            started_at: Instant::now(),
            is_download: false,
        };
        // Could be 0 or very large depending on timing; just ensure no panic
        let _ = p.speed_bps();
    }

    #[test]
    fn eta_secs_mid_transfer() {
        let p = make_progress(50_000, 100_000, Duration::from_secs(5));
        let eta = p.eta_secs();
        assert!(eta.is_some());
        let eta_val = eta.unwrap();
        assert!(eta_val > 3.0 && eta_val < 7.0, "eta was {eta_val}");
    }

    #[test]
    fn eta_secs_complete() {
        let p = make_progress(1000, 1000, Duration::from_secs(1));
        assert!(p.eta_secs().is_none());
    }

    // --- ForwardType tests ---

    #[test]
    fn local_forward_summary() {
        let fwd = ForwardType::Local {
            bind_addr: "127.0.0.1".into(),
            bind_port: 8080,
            remote_host: "db.internal".into(),
            remote_port: 5432,
        };
        assert_eq!(fwd.summary(), "-L 127.0.0.1:8080:db.internal:5432");
        assert_eq!(fwd.type_label(), "Local");
    }

    #[test]
    fn remote_forward_summary() {
        let fwd = ForwardType::Remote {
            remote_addr: "0.0.0.0".into(),
            remote_port: 3000,
            local_host: "localhost".into(),
            local_port: 3000,
        };
        assert_eq!(fwd.summary(), "-R 0.0.0.0:3000:localhost:3000");
        assert_eq!(fwd.type_label(), "Remote");
    }

    #[test]
    fn dynamic_forward_summary() {
        let fwd = ForwardType::Dynamic {
            bind_addr: "127.0.0.1".into(),
            bind_port: 1080,
        };
        assert_eq!(fwd.summary(), "-D 127.0.0.1:1080");
        assert_eq!(fwd.type_label(), "SOCKS5");
    }

    #[test]
    fn forward_stats_default() {
        let stats = ForwardStats::default();
        assert_eq!(stats.bytes_sent.load(Ordering::Relaxed), 0);
        assert_eq!(stats.bytes_received.load(Ordering::Relaxed), 0);
        assert_eq!(stats.active_connections.load(Ordering::Relaxed), 0);
        assert_eq!(stats.total_connections.load(Ordering::Relaxed), 0);
        assert!(stats.enabled.load(Ordering::Relaxed));
    }

    #[test]
    fn forward_stats_add() {
        let stats = ForwardStats::default();
        stats.add_sent(100);
        stats.add_sent(200);
        stats.add_received(50);
        assert_eq!(stats.bytes_sent.load(Ordering::Relaxed), 300);
        assert_eq!(stats.bytes_received.load(Ordering::Relaxed), 50);
    }

    #[test]
    fn forward_status_eq() {
        assert_eq!(ForwardStatus::Starting, ForwardStatus::Starting);
        assert_eq!(ForwardStatus::Active, ForwardStatus::Active);
        assert_ne!(ForwardStatus::Starting, ForwardStatus::Active);
        assert_eq!(
            ForwardStatus::Error("timeout".into()),
            ForwardStatus::Error("timeout".into())
        );
    }
}
