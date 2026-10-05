//! Filesystem-backed blob storage.
//!
//! Layout: `<data_dir>/blobs/<user_id>/<kind>/<revision>.bin`
//!
//! Binary payloads are written via an atomic `write + rename` pattern so that
//! partial writes (e.g. on NFS) never surface to readers.
//!
//! Author: Limmy

use std::path::{Path, PathBuf};

use anyhow::Context;
use sha2::{Digest, Sha256};

#[derive(Clone, Debug)]
pub struct BlobStore {
    root: PathBuf,
}

impl BlobStore {
    pub fn new(root: impl Into<PathBuf>) -> anyhow::Result<Self> {
        let root = root.into();
        std::fs::create_dir_all(&root)
            .with_context(|| format!("failed to create blob root {}", root.display()))?;
        Ok(Self { root })
    }

    /// Compose the filesystem path for a (user, kind, revision) triple.
    ///
    /// `kind` is sanitized: slashes are replaced to prevent path escape.
    pub fn blob_path(&self, user_id: &str, kind: &str, revision: i64) -> PathBuf {
        let safe_kind = kind.replace(['/', '\\'], "_");
        self.root
            .join(user_id)
            .join(safe_kind)
            .join(format!("{revision}.bin"))
    }

    /// Return the `<data_dir>/blobs/` relative path used in DB rows.
    pub fn relative_path(&self, user_id: &str, kind: &str, revision: i64) -> String {
        let safe_kind = kind.replace(['/', '\\'], "_");
        format!("{user_id}/{safe_kind}/{revision}.bin")
    }

    /// Atomically write `bytes` to the target path. Returns (size, sha256).
    pub fn write(&self, relative: &str, bytes: &[u8]) -> anyhow::Result<(u64, [u8; 32])> {
        let target = self.root.join(relative);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let tmp = target.with_extension("bin.tmp");
        std::fs::write(&tmp, bytes)
            .with_context(|| format!("write tmp failed: {}", tmp.display()))?;
        std::fs::rename(&tmp, &target)
            .with_context(|| format!("rename failed: {}", target.display()))?;

        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        Ok((bytes.len() as u64, out))
    }

    pub fn read(&self, relative: &str) -> anyhow::Result<Vec<u8>> {
        let path = self.root.join(relative);
        let bytes = std::fs::read(&path)
            .with_context(|| format!("read failed: {}", path.display()))?;
        Ok(bytes)
    }

    pub fn delete(&self, relative: &str) {
        let path = self.root.join(relative);
        let _ = std::fs::remove_file(&path);
    }

    pub fn root(&self) -> &Path {
        &self.root
    }
}
