//! Background SFTP worker that executes async SFTP operations.
//!
//! Processes SFTP commands (list, download, upload, delete, etc.) on a
//! background task, reporting results and progress via the event channel.
//! Internal to the service module -- only the service background task
//! creates SftpWorker instances.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use russh_sftp::client::SftpSession;
use russh_sftp::protocol::FileAttributes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::timeout;
use tracing::error;

use super::types::{RemoteEntry, SftpCommand, SftpEvent};

/// Chunk size for streaming transfers (1 MB)
/// Larger chunks reduce SFTP protocol round-trips, improving throughput on fast networks.
const TRANSFER_CHUNK_SIZE: usize = 1024 * 1024;

/// Timeout for SFTP metadata/directory operations
const SFTP_OP_TIMEOUT: Duration = Duration::from_secs(30);

/// Background worker that processes SFTP commands asynchronously
pub(super) struct SftpWorker;

impl SftpWorker {
    /// Spawn a background task that processes SFTP commands.
    /// Returns a cancellation flag that the UI can set to abort transfers.
    pub fn spawn(
        sftp: SftpSession,
        mut cmd_rx: mpsc::UnboundedReceiver<SftpCommand>,
        event_tx: mpsc::UnboundedSender<SftpEvent>,
    ) -> Arc<AtomicBool> {
        let cancel = Arc::new(AtomicBool::new(false));
        let cancel_clone = cancel.clone();

        tokio::spawn(async move {
            while let Some(cmd) = cmd_rx.recv().await {
                match cmd {
                    SftpCommand::ListDir(path) => {
                        Self::handle_list_dir(&sftp, &path, &event_tx).await;
                    }
                    SftpCommand::DownloadFile { remote, local } => {
                        Self::handle_download(&sftp, &remote, &local, &event_tx, &cancel_clone)
                            .await;
                    }
                    SftpCommand::UploadFile { local, remote_dir } => {
                        Self::handle_upload(&sftp, &local, &remote_dir, &event_tx, &cancel_clone)
                            .await;
                    }
                    SftpCommand::DeleteFile(path) => {
                        Self::handle_delete_file(&sftp, &path, &event_tx).await;
                    }
                    SftpCommand::DeleteDir(path) => {
                        Self::handle_delete_dir(&sftp, &path, &event_tx).await;
                    }
                    SftpCommand::Rename { old, new } => {
                        Self::handle_rename(&sftp, &old, &new, &event_tx).await;
                    }
                    SftpCommand::CreateDir(path) => {
                        Self::handle_mkdir(&sftp, &path, &event_tx).await;
                    }
                    SftpCommand::Chmod { path, mode } => {
                        Self::handle_chmod(&sftp, &path, mode, &event_tx).await;
                    }
                    SftpCommand::CancelTransfer => {
                        cancel_clone.store(true, Ordering::Relaxed);
                    }
                }
            }
        });

        cancel
    }

    async fn handle_list_dir(
        sftp: &SftpSession,
        path: &str,
        event_tx: &mpsc::UnboundedSender<SftpEvent>,
    ) {
        let canonical = match timeout(SFTP_OP_TIMEOUT, sftp.canonicalize(path)).await {
            Ok(Ok(p)) => p,
            Ok(Err(e)) => {
                let _ = event_tx.send(SftpEvent::Error(format!("Failed to resolve path: {}", e)));
                return;
            }
            Err(_) => {
                let _ = event_tx.send(SftpEvent::Error("Timed out resolving path".to_string()));
                return;
            }
        };

        match timeout(SFTP_OP_TIMEOUT, sftp.read_dir(&canonical)).await {
            Err(_) => {
                let _ = event_tx.send(SftpEvent::Error("Timed out listing directory".to_string()));
            }
            Ok(Ok(read_dir)) => {
                let mut entries: Vec<RemoteEntry> = read_dir
                    .map(|entry| {
                        let meta = entry.metadata();
                        RemoteEntry {
                            name: entry.file_name(),
                            is_dir: meta.is_dir(),
                            size: meta.size.unwrap_or(0),
                            permissions: meta.permissions,
                            mtime: meta.mtime,
                        }
                    })
                    .collect();

                entries.sort_by(|a, b| {
                    b.is_dir.cmp(&a.is_dir).then_with(|| a.name.cmp(&b.name))
                });

                let _ = event_tx.send(SftpEvent::DirListed {
                    path: canonical,
                    entries,
                });
            }
            Ok(Err(e)) => {
                error!("SFTP readdir failed: {}", e);
                let _ = event_tx.send(SftpEvent::Error(format!(
                    "Failed to list directory: {}",
                    e
                )));
            }
        }
    }

    async fn handle_download(
        sftp: &SftpSession,
        remote: &str,
        local: &str,
        event_tx: &mpsc::UnboundedSender<SftpEvent>,
        cancel: &AtomicBool,
    ) {
        // Reset cancel flag at start of transfer
        cancel.store(false, Ordering::Relaxed);

        let total = match timeout(SFTP_OP_TIMEOUT, sftp.metadata(remote)).await {
            Ok(Ok(meta)) => meta.size.unwrap_or(0),
            _ => 0,
        };

        // Open remote file for streaming read
        let mut file = match timeout(SFTP_OP_TIMEOUT, sftp.open(remote)).await {
            Ok(Ok(f)) => f,
            Ok(Err(e)) => {
                error!("SFTP open failed: {}", e);
                let _ =
                    event_tx.send(SftpEvent::Error(format!("Failed to open remote file: {}", e)));
                return;
            }
            Err(_) => {
                let _ =
                    event_tx.send(SftpEvent::Error("Timed out opening remote file".to_string()));
                return;
            }
        };

        // Create local file
        let mut local_file = match tokio::fs::File::create(local).await {
            Ok(f) => f,
            Err(e) => {
                let _ = event_tx.send(SftpEvent::Error(format!(
                    "Failed to create local file: {}",
                    e
                )));
                return;
            }
        };

        let mut transferred: u64 = 0;
        let mut buf = vec![0u8; TRANSFER_CHUNK_SIZE];

        loop {
            // Check cancellation
            if cancel.load(Ordering::Relaxed) {
                // Clean up partial file
                let _ = tokio::fs::remove_file(local).await;
                let _ = event_tx.send(SftpEvent::TransferCancelled);
                return;
            }

            match file.read(&mut buf).await {
                Ok(0) => break, // EOF
                Ok(n) => {
                    if let Err(e) = local_file.write_all(&buf[..n]).await {
                        let _ = tokio::fs::remove_file(local).await;
                        let _ = event_tx.send(SftpEvent::Error(format!(
                            "Failed to write local file: {}",
                            e
                        )));
                        return;
                    }
                    transferred += n as u64;
                    let _ = event_tx.send(SftpEvent::DownloadProgress {
                        remote: remote.to_string(),
                        transferred,
                        total,
                    });
                }
                Err(e) => {
                    let _ = tokio::fs::remove_file(local).await;
                    error!("SFTP read failed: {}", e);
                    let _ = event_tx.send(SftpEvent::Error(format!(
                        "Failed to download file: {}",
                        e
                    )));
                    return;
                }
            }
        }

        let _ = event_tx.send(SftpEvent::DownloadComplete {
            remote: remote.to_string(),
            local: local.to_string(),
        });
    }

    async fn handle_upload(
        sftp: &SftpSession,
        local: &str,
        remote_dir: &str,
        event_tx: &mpsc::UnboundedSender<SftpEvent>,
        cancel: &AtomicBool,
    ) {
        // Reset cancel flag at start of transfer
        cancel.store(false, Ordering::Relaxed);

        // Get local file size
        let metadata = match tokio::fs::metadata(local).await {
            Ok(m) => m,
            Err(e) => {
                let _ = event_tx.send(SftpEvent::Error(format!(
                    "Failed to read local file '{}': {}",
                    local, e
                )));
                return;
            }
        };
        let total = metadata.len();

        // Open local file for reading
        let mut local_file = match tokio::fs::File::open(local).await {
            Ok(f) => f,
            Err(e) => {
                let _ = event_tx.send(SftpEvent::Error(format!(
                    "Failed to open local file '{}': {}",
                    local, e
                )));
                return;
            }
        };

        // Extract filename from local path
        let filename = std::path::Path::new(local)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(local);

        let remote_path = format!("{}/{}", remote_dir, filename);

        // Create remote file
        let mut remote_file = match timeout(SFTP_OP_TIMEOUT, sftp.create(&remote_path)).await {
            Ok(Ok(f)) => f,
            Ok(Err(e)) => {
                let _ = event_tx.send(SftpEvent::Error(format!("Upload failed: {}", e)));
                return;
            }
            Err(_) => {
                let _ = event_tx.send(SftpEvent::Error(
                    "Timed out creating remote file".to_string(),
                ));
                return;
            }
        };

        let mut transferred: u64 = 0;
        let mut buf = vec![0u8; TRANSFER_CHUNK_SIZE];

        loop {
            // Check cancellation
            if cancel.load(Ordering::Relaxed) {
                // Try to clean up partial remote file
                let _ = sftp.remove_file(&remote_path).await;
                let _ = event_tx.send(SftpEvent::TransferCancelled);
                return;
            }

            match local_file.read(&mut buf).await {
                Ok(0) => break, // EOF
                Ok(n) => {
                    if let Err(e) = remote_file.write_all(&buf[..n]).await {
                        let _ = sftp.remove_file(&remote_path).await;
                        let _ = event_tx.send(SftpEvent::Error(format!("Upload failed: {}", e)));
                        return;
                    }
                    transferred += n as u64;
                    let _ = event_tx.send(SftpEvent::UploadProgress {
                        local: local.to_string(),
                        transferred,
                        total,
                    });
                }
                Err(e) => {
                    let _ = sftp.remove_file(&remote_path).await;
                    let _ = event_tx.send(SftpEvent::Error(format!(
                        "Failed to read local file: {}",
                        e
                    )));
                    return;
                }
            }
        }

        let _ = event_tx.send(SftpEvent::UploadComplete {
            local: local.to_string(),
            remote: remote_path.clone(),
        });

        let _ = event_tx.send(SftpEvent::OperationComplete(format!(
            "Uploaded '{}' ({})",
            filename,
            format_size(total)
        )));
        // Auto-refresh directory
        Self::handle_list_dir(sftp, remote_dir, event_tx).await;
    }

    async fn handle_delete_file(
        sftp: &SftpSession,
        path: &str,
        event_tx: &mpsc::UnboundedSender<SftpEvent>,
    ) {
        match sftp.remove_file(path).await {
            Ok(()) => {
                let name = path.rsplit('/').next().unwrap_or(path);
                let _ = event_tx.send(SftpEvent::OperationComplete(format!(
                    "Deleted '{}'",
                    name
                )));
                // Auto-refresh parent directory
                let parent = parent_path(path);
                Self::handle_list_dir(sftp, &parent, event_tx).await;
            }
            Err(e) => {
                let _ = event_tx.send(SftpEvent::Error(format!("Delete failed: {}", e)));
            }
        }
    }

    async fn handle_delete_dir(
        sftp: &SftpSession,
        path: &str,
        event_tx: &mpsc::UnboundedSender<SftpEvent>,
    ) {
        match Self::remove_dir_recursive(sftp, path).await {
            Ok(()) => {
                let name = path.rsplit('/').next().unwrap_or(path);
                let _ = event_tx.send(SftpEvent::OperationComplete(format!(
                    "Removed directory '{}'",
                    name
                )));
                let parent = parent_path(path);
                Self::handle_list_dir(sftp, &parent, event_tx).await;
            }
            Err(e) => {
                let _ = event_tx.send(SftpEvent::Error(format!(
                    "Remove directory failed: {}",
                    e
                )));
            }
        }
    }

    /// Recursively remove a directory and all its contents
    async fn remove_dir_recursive(
        sftp: &SftpSession,
        path: &str,
    ) -> Result<(), russh_sftp::client::error::Error> {
        let entries = sftp.read_dir(path).await?;
        for entry in entries {
            let name = entry.file_name();
            if name == "." || name == ".." {
                continue;
            }
            let child = format!("{}/{}", path, name);
            if entry.metadata().is_dir() {
                // Box the recursive future to avoid infinite-size type
                Box::pin(Self::remove_dir_recursive(sftp, &child)).await?;
            } else {
                sftp.remove_file(&child).await?;
            }
        }
        sftp.remove_dir(path).await
    }

    async fn handle_rename(
        sftp: &SftpSession,
        old: &str,
        new: &str,
        event_tx: &mpsc::UnboundedSender<SftpEvent>,
    ) {
        match sftp.rename(old, new).await {
            Ok(()) => {
                let old_name = old.rsplit('/').next().unwrap_or(old);
                let new_name = new.rsplit('/').next().unwrap_or(new);
                let _ = event_tx.send(SftpEvent::OperationComplete(format!(
                    "Renamed '{}' -> '{}'",
                    old_name, new_name
                )));
                let parent = parent_path(old);
                Self::handle_list_dir(sftp, &parent, event_tx).await;
            }
            Err(e) => {
                let _ = event_tx.send(SftpEvent::Error(format!("Rename failed: {}", e)));
            }
        }
    }

    async fn handle_mkdir(
        sftp: &SftpSession,
        path: &str,
        event_tx: &mpsc::UnboundedSender<SftpEvent>,
    ) {
        match sftp.create_dir(path).await {
            Ok(()) => {
                let name = path.rsplit('/').next().unwrap_or(path);
                let _ = event_tx.send(SftpEvent::OperationComplete(format!(
                    "Created directory '{}'",
                    name
                )));
                let parent = parent_path(path);
                Self::handle_list_dir(sftp, &parent, event_tx).await;
            }
            Err(e) => {
                let _ = event_tx.send(SftpEvent::Error(format!(
                    "Create directory failed: {}",
                    e
                )));
            }
        }
    }

    async fn handle_chmod(
        sftp: &SftpSession,
        path: &str,
        mode: u32,
        event_tx: &mpsc::UnboundedSender<SftpEvent>,
    ) {
        let attrs = FileAttributes {
            permissions: Some(mode),
            ..FileAttributes::default()
        };

        match sftp.set_metadata(path, attrs).await {
            Ok(()) => {
                let name = path.rsplit('/').next().unwrap_or(path);
                let _ = event_tx.send(SftpEvent::OperationComplete(format!(
                    "Changed permissions of '{}' to {:o}",
                    name, mode
                )));
                let parent = parent_path(path);
                Self::handle_list_dir(sftp, &parent, event_tx).await;
            }
            Err(e) => {
                let _ = event_tx.send(SftpEvent::Error(format!("Chmod failed: {}", e)));
            }
        }
    }
}

/// Extract parent directory from a path
fn parent_path(path: &str) -> String {
    if let Some(pos) = path.rfind('/') {
        if pos == 0 {
            "/".to_string()
        } else {
            path[..pos].to_string()
        }
    } else {
        ".".to_string()
    }
}

/// Format file size in human-readable form
fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{}B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1}K", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1}M", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.1}G", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}
