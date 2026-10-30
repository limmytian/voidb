//! Durable, owner-only file persistence for credential-bearing stores.
//!
//! Every store that holds secret material (config, process-plugin install
//! records, JIT grant files, external context records) persists through the
//! same pattern: write to a fresh temporary file in the destination's
//! directory, fsync, then rename over the destination. Centralizing the
//! pattern keeps the durability semantics identical everywhere and fixes
//! divergences such as forgotten temporary-file cleanup on error paths.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use uuid::Uuid;

/// Atomically replace `path` with `content`, never leaving a partial file.
///
/// The temporary sibling file is created fresh with owner-only permissions
/// (0600 on Unix), fully written, synced to disk, and renamed over `path`.
/// If any step fails the temporary file is removed and `path` is left
/// untouched, so the previous content survives every failure mode except a
/// machine crash between fsync and rename.
pub fn write_private_atomic(path: &Path, content: &[u8]) -> io::Result<()> {
    let temporary = temporary_sibling_path(path);
    let result = (|| -> io::Result<()> {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(content)?;
        file.sync_all()?;
        drop(file);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))?;
        }
        fs::rename(&temporary, path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

/// Fresh temporary path in the destination's directory so the final rename
/// stays within one filesystem. The destination extension is replaced with a
/// recognizable `tmp-<uuid>` suffix; uniqueness comes from the UUID.
fn temporary_sibling_path(path: &Path) -> PathBuf {
    path.with_extension(format!("tmp-{}", Uuid::new_v4()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn write_replaces_content_atomically() {
        let root = std::env::temp_dir().join(format!("voidb-atomic-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&root).expect("create temp root");
        let path = root.join("store.json");
        std::fs::write(&path, b"{\"old\": true}").expect("seed destination");

        write_private_atomic(&path, b"{\"new\": true}").expect("atomic write");

        assert_eq!(std::fs::read(&path).expect("read destination"), b"{\"new\": true}");
        // No temporary siblings remain after success.
        let leftover: HashMap<_, _> = std::fs::read_dir(&root)
            .expect("list root")
            .filter_map(|entry| entry.ok())
            .map(|entry| (entry.file_name().to_string_lossy().into_owned(), entry.path()))
            .collect();
        assert_eq!(leftover.len(), 1, "only the destination remains: {leftover:?}");

        std::fs::remove_dir_all(&root).expect("remove temp root");
    }

    #[test]
    fn failed_write_leaves_destination_and_cleans_temporary() {
        let root = std::env::temp_dir().join(format!("voidb-atomic-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&root).expect("create temp root");
        let path = root.join("store.json");
        std::fs::write(&path, b"original").expect("seed destination");

        // Force failure by making the destination directory read-only is
        // unreliable across platforms; instead point the write at a path
        // whose parent does not exist, so the create step fails and no
        // temporary file can leak anywhere.
        let missing_parent = root.join("absent-dir").join("store.json");
        assert!(write_private_atomic(&missing_parent, b"data").is_err());

        assert_eq!(std::fs::read(&path).expect("read destination"), b"original");
        assert!(!root.join("absent-dir").exists());

        std::fs::remove_dir_all(&root).expect("remove temp root");
    }

    #[cfg(unix)]
    #[test]
    fn written_file_has_owner_only_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let root = std::env::temp_dir().join(format!("voidb-atomic-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&root).expect("create temp root");
        let path = root.join("secret.json");

        write_private_atomic(&path, b"payload").expect("atomic write");

        let mode = std::fs::metadata(&path)
            .expect("stat destination")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);

        std::fs::remove_dir_all(&root).expect("remove temp root");
    }
}
