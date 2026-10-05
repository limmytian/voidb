//! Bundle `~/.config/voidb/` into a deterministic tar.zst archive for sync.
//!
//! The bundle is *plaintext* at this layer — encryption happens later in
//! [`crate::crypto::encrypt_bundle`]. A plaintext manifest (file paths,
//! sizes, sha256) is produced alongside so the server (and the operator)
//! can inspect what changed without needing the DEK.
//!
//! We explicitly exclude `sync.toml` from the bundle: it contains
//! device-specific bookkeeping that would otherwise clobber other devices'
//! state on every pull.
//!
//! Author: Limmy

use std::collections::HashSet;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::SyncError;

/// Plaintext manifest entry — one per file in the bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestEntry {
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub version: u32,
    pub created_at: String,
    pub files: Vec<ManifestEntry>,
    pub total_size: u64,
}

/// Paths (relative to the bundle root) never included in a bundle.
fn default_excludes() -> HashSet<String> {
    let mut s = HashSet::new();
    s.insert("sync.toml".to_string());
    s.insert(".DS_Store".to_string());
    s
}

fn is_excluded(rel: &Path, excludes: &HashSet<String>) -> bool {
    let s = rel.to_string_lossy().to_string();
    if excludes.contains(&s) {
        return true;
    }
    for part in rel.components() {
        let p = part.as_os_str().to_string_lossy().to_string();
        // Crude global patterns; good enough for MVP.
        if p == ".DS_Store" || p.ends_with(".tmp") || p.ends_with(".lock") {
            return true;
        }
    }
    false
}

fn kind_includes(kind: &str, rel: &Path) -> bool {
    match kind {
        "full" => true,
        "global" => !rel.starts_with("plugins"),
        other => {
            if let Some(id) = other.strip_prefix("plugin:") {
                rel.starts_with(format!("plugins/{id}").as_str())
            } else {
                true
            }
        }
    }
}

fn walk(root: &Path, excludes: &HashSet<String>) -> Result<Vec<(PathBuf, PathBuf)>, SyncError> {
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let abs = entry.path();
            let rel = abs.strip_prefix(root).unwrap_or(&abs).to_path_buf();
            if is_excluded(&rel, excludes) {
                continue;
            }
            let ft = entry.file_type()?;
            if ft.is_dir() {
                stack.push(abs);
            } else if ft.is_file() {
                out.push((abs, rel));
            }
        }
    }
    out.sort_by(|a, b| a.1.cmp(&b.1));
    Ok(out)
}

/// Build a (manifest, tar.zst bytes) pair for the subset of `root` selected by `kind`.
///
/// `kind` controls which files are included:
/// - `"full"` — everything under `root` (default)
/// - `"global"` — top-level files only (no `plugins/` subtree)
/// - `"plugin:<id>"` — `plugins/<id>/` only
pub fn build_for_kind(root: &Path, kind: &str) -> Result<(Manifest, Vec<u8>), SyncError> {
    let excludes = default_excludes();
    let all_files = walk(root, &excludes)?;
    let files: Vec<_> = all_files
        .into_iter()
        .filter(|(_, rel)| kind_includes(kind, rel))
        .collect();

    let mut manifest_entries = Vec::with_capacity(files.len());
    let mut total_size = 0u64;

    let zstd_encoder = zstd::stream::write::Encoder::new(Vec::new(), 10)
        .map_err(|e| SyncError::Bundle(format!("zstd encoder: {e}")))?;
    let mut tar_builder = tar::Builder::new(zstd_encoder);
    tar_builder.mode(tar::HeaderMode::Deterministic);

    for (abs, rel) in &files {
        let mut f = std::fs::File::open(abs)?;
        let mut bytes = Vec::new();
        f.read_to_end(&mut bytes)?;

        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let sha = hex::encode(hasher.finalize());

        let size = bytes.len() as u64;
        total_size += size;
        manifest_entries.push(ManifestEntry {
            path: rel.to_string_lossy().replace('\\', "/"),
            size,
            sha256: sha,
        });

        let mut header = tar::Header::new_gnu();
        header.set_size(size);
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_cksum();
        tar_builder
            .append_data(&mut header, rel, &bytes[..])
            .map_err(|e| SyncError::Bundle(format!("tar append: {e}")))?;
    }

    let zstd_encoder = tar_builder
        .into_inner()
        .map_err(|e| SyncError::Bundle(format!("tar finalize: {e}")))?;
    let archive = zstd_encoder
        .finish()
        .map_err(|e| SyncError::Bundle(format!("zstd finish: {e}")))?;

    let manifest = Manifest {
        version: 1,
        created_at: chrono::Utc::now().to_rfc3339(),
        files: manifest_entries,
        total_size,
    };

    Ok((manifest, archive))
}

/// Build a (manifest, tar.zst bytes) pair for the contents of `root`.
///
/// Returns the serialized tar.zst archive plus a manifest describing it.
pub fn build(root: &Path) -> Result<(Manifest, Vec<u8>), SyncError> {
    build_for_kind(root, "full")
}

/// Extract a bundle built by [`build`] into `dest`. Files listed in
/// `preserve` (relative to `dest`) are left untouched when the archive does
/// NOT contain a replacement for them.
pub fn extract(dest: &Path, archive: &[u8], preserve: &HashSet<String>) -> Result<(), SyncError> {
    std::fs::create_dir_all(dest)?;

    let decoder = zstd::stream::read::Decoder::new(std::io::Cursor::new(archive))
        .map_err(|e| SyncError::Bundle(format!("zstd decoder: {e}")))?;
    let mut ar = tar::Archive::new(decoder);

    let mut unpacked: HashSet<String> = HashSet::new();
    for entry in ar
        .entries()
        .map_err(|e| SyncError::Bundle(format!("tar entries: {e}")))?
    {
        let mut entry = entry.map_err(|e| SyncError::Bundle(format!("tar entry: {e}")))?;
        let path = entry
            .path()
            .map_err(|e| SyncError::Bundle(format!("tar path: {e}")))?
            .into_owned();
        let rel_str = path.to_string_lossy().to_string();

        if rel_str.contains("..") {
            return Err(SyncError::Bundle(format!("rejecting unsafe path: {rel_str}")));
        }
        if preserve.contains(&rel_str) {
            // The archive shouldn't have preserved entries anyway (they're in
            // `default_excludes`), but defend against malicious bundles.
            continue;
        }

        let target = dest.join(&path);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let mut buf = Vec::new();
        entry
            .read_to_end(&mut buf)
            .map_err(|e| SyncError::Bundle(format!("tar read: {e}")))?;

        let tmp = target.with_extension("sync.tmp");
        {
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&buf)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &target)?;
        unpacked.insert(rel_str);
    }

    Ok(())
}

/// Convenience alias: files that must never be overwritten on extract.
pub fn preserve_on_extract() -> HashSet<String> {
    let mut s = HashSet::new();
    s.insert("sync.toml".to_string());
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn make_fixture() -> TempDir {
        let src = TempDir::new().unwrap();
        fs::write(src.path().join("config.toml"), b"global").unwrap();
        fs::write(src.path().join("saved_queries.json"), b"{}").unwrap();
        fs::write(src.path().join("sync.toml"), b"ignored").unwrap();
        fs::create_dir_all(src.path().join("plugins/mysql")).unwrap();
        fs::write(src.path().join("plugins/mysql/state.json"), b"mysql-data").unwrap();
        fs::create_dir_all(src.path().join("plugins/postgres")).unwrap();
        fs::write(src.path().join("plugins/postgres/state.json"), b"pg-data").unwrap();
        src
    }

    #[test]
    fn bundle_roundtrip() {
        let src = make_fixture();
        let dst = TempDir::new().unwrap();

        let (manifest, archive) = build(src.path()).unwrap();
        assert_eq!(manifest.files.len(), 4); // config.toml, saved_queries.json, plugins/mysql/state.json, plugins/postgres/state.json
        assert!(manifest.files.iter().any(|e| e.path == "config.toml"));
        assert!(manifest.files.iter().any(|e| e.path == "plugins/mysql/state.json"));
        assert!(!manifest.files.iter().any(|e| e.path == "sync.toml"));

        extract(dst.path(), &archive, &preserve_on_extract()).unwrap();
        assert_eq!(fs::read(dst.path().join("config.toml")).unwrap(), b"global");
    }

    #[test]
    fn kind_global_excludes_plugins() {
        let src = make_fixture();
        let (manifest, _) = build_for_kind(src.path(), "global").unwrap();
        assert!(manifest.files.iter().all(|e| !e.path.starts_with("plugins")));
        assert!(manifest.files.iter().any(|e| e.path == "config.toml"));
        assert!(manifest.files.iter().any(|e| e.path == "saved_queries.json"));
    }

    #[test]
    fn kind_plugin_mysql_only() {
        let src = make_fixture();
        let (manifest, archive) = build_for_kind(src.path(), "plugin:mysql").unwrap();
        assert_eq!(manifest.files.len(), 1);
        assert_eq!(manifest.files[0].path, "plugins/mysql/state.json");

        let dst = TempDir::new().unwrap();
        extract(dst.path(), &archive, &preserve_on_extract()).unwrap();
        assert_eq!(
            fs::read(dst.path().join("plugins/mysql/state.json")).unwrap(),
            b"mysql-data"
        );
        assert!(!dst.path().join("config.toml").exists());
    }

    #[test]
    fn kind_full_includes_everything() {
        let src = make_fixture();
        let (manifest_full, _) = build_for_kind(src.path(), "full").unwrap();
        let (manifest_build, _) = build(src.path()).unwrap();
        assert_eq!(manifest_full.files.len(), manifest_build.files.len());
    }
}
