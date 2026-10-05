//! Shared local-filesystem authorization primitives for agent-facing capabilities.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::CapabilityErrorCategory;

pub const DEFAULT_LOCAL_SCAN_MAX_DEPTH: usize = 64;
pub const DEFAULT_LOCAL_SCAN_MAX_ENTRIES: usize = 10_000;
pub const DEFAULT_LOCAL_SCAN_MAX_PATH_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalScanLimits {
    pub max_depth: usize,
    pub max_entries: usize,
    pub max_path_bytes: usize,
}

impl Default for LocalScanLimits {
    fn default() -> Self {
        Self {
            max_depth: DEFAULT_LOCAL_SCAN_MAX_DEPTH,
            max_entries: DEFAULT_LOCAL_SCAN_MAX_ENTRIES,
            max_path_bytes: DEFAULT_LOCAL_SCAN_MAX_PATH_BYTES,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalScanEntry {
    pub relative_path: String,
    pub is_dir: bool,
    pub size: u64,
    pub modified: Option<SystemTime>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalScanReport {
    pub entries: Vec<LocalScanEntry>,
    pub observed_depth: usize,
    pub observed_path_bytes: usize,
    pub limits: LocalScanLimits,
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum LocalPathError {
    #[error("local path input is invalid")]
    Invalid,
    #[error("local path root is unavailable")]
    RootUnavailable,
    #[error("local path is outside the approved scope")]
    OutsideScope,
    #[error("local path link traversal is denied")]
    LinkDenied,
    #[error("local scan limit was exceeded")]
    ScanLimitExceeded,
    #[error("local destination already exists")]
    Exists,
    #[error("local path changed during authorization")]
    Changed,
    #[error("safe local staging is unavailable")]
    StagingUnavailable,
}

impl LocalPathError {
    pub fn category(&self) -> CapabilityErrorCategory {
        match self {
            Self::Invalid => CapabilityErrorCategory::Validation,
            Self::RootUnavailable | Self::StagingUnavailable => {
                CapabilityErrorCategory::Unavailable
            }
            Self::OutsideScope => CapabilityErrorCategory::Permission,
            Self::LinkDenied | Self::ScanLimitExceeded => CapabilityErrorCategory::Policy,
            Self::Exists | Self::Changed => CapabilityErrorCategory::Conflict,
        }
    }

    pub fn code(&self) -> &'static str {
        match self {
            Self::Invalid => "validation.local_path_invalid",
            Self::RootUnavailable => "unavailable.local_path_root",
            Self::OutsideScope => "permission.local_path_outside_scope",
            Self::LinkDenied => "policy.local_path_link_denied",
            Self::ScanLimitExceeded => "policy.local_scan_limit_exceeded",
            Self::Exists => "conflict.local_path_exists",
            Self::Changed => "conflict.local_path_changed",
            Self::StagingUnavailable => "unavailable.local_staging",
        }
    }

    pub fn safe_message(&self) -> &'static str {
        match self {
            Self::Invalid => "Local path input is invalid.",
            Self::RootUnavailable => "The approved local path root is unavailable.",
            Self::OutsideScope => "Local path access is outside the approved scope.",
            Self::LinkDenied => "Local path link traversal is denied by policy.",
            Self::ScanLimitExceeded => "The local directory scan exceeded its approved limit.",
            Self::Exists => "The local destination already exists and overwrite is disabled.",
            Self::Changed => "The local path changed while the operation was being authorized.",
            Self::StagingUnavailable => "A safe local staging file could not be committed.",
        }
    }

    pub fn retryable(&self) -> bool {
        matches!(self, Self::Changed | Self::StagingUnavailable)
    }
}

/// Canonical local root captured for one invocation or bounded transfer.
#[derive(Debug, Clone)]
pub struct LocalPathScope {
    canonical_root: PathBuf,
    root_metadata: fs::Metadata,
}

/// Read-only file handle bound to the approved root and original file identity.
///
/// Identity is revalidated before and after every read so streaming consumers
/// cannot be redirected through a path swap after authorization.
#[derive(Debug)]
pub struct ScopedLocalFile {
    file: File,
    scope: LocalPathScope,
    path_metadata: fs::Metadata,
}

impl ScopedLocalFile {
    pub fn len(&self) -> u64 {
        self.path_metadata.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Read for ScopedLocalFile {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.scope
            .ensure_root_unchanged()
            .map_err(local_path_io_error)?;
        let current = self.file.metadata()?;
        if !same_file_identity(&self.path_metadata, &current) {
            return Err(local_path_io_error(LocalPathError::Changed));
        }
        let read = self.file.read(buffer)?;
        let current = self.file.metadata()?;
        if !same_file_identity(&self.path_metadata, &current)
            || current.len() != self.path_metadata.len()
        {
            return Err(local_path_io_error(LocalPathError::Changed));
        }
        self.scope
            .ensure_root_unchanged()
            .map_err(local_path_io_error)?;
        Ok(read)
    }
}

impl LocalPathScope {
    pub fn new(root: impl AsRef<Path>) -> Result<Self, LocalPathError> {
        let root = root.as_ref();
        if !root.is_absolute() {
            return Err(LocalPathError::Invalid);
        }
        let metadata = fs::symlink_metadata(root).map_err(|_| LocalPathError::RootUnavailable)?;
        if metadata.file_type().is_symlink() {
            return Err(LocalPathError::LinkDenied);
        }
        if !metadata.is_dir() {
            return Err(LocalPathError::Invalid);
        }
        let canonical_root = fs::canonicalize(root).map_err(|_| LocalPathError::RootUnavailable)?;
        let root_metadata =
            fs::symlink_metadata(&canonical_root).map_err(|_| LocalPathError::RootUnavailable)?;
        if root_metadata.file_type().is_symlink()
            || !root_metadata.is_dir()
            || !same_file_identity(&metadata, &root_metadata)
        {
            return Err(LocalPathError::Changed);
        }
        Ok(Self {
            canonical_root,
            root_metadata,
        })
    }

    pub fn resolve_existing_file(
        &self,
        relative: impl AsRef<Path>,
    ) -> Result<PathBuf, LocalPathError> {
        let path = self.resolve_existing(relative.as_ref())?;
        let metadata = fs::symlink_metadata(&path).map_err(|_| LocalPathError::Changed)?;
        if !metadata.is_file() {
            return Err(LocalPathError::Invalid);
        }
        Ok(path)
    }

    pub fn resolve_existing_directory(
        &self,
        relative: impl AsRef<Path>,
    ) -> Result<PathBuf, LocalPathError> {
        let path = self.resolve_existing(relative.as_ref())?;
        let metadata = fs::symlink_metadata(&path).map_err(|_| LocalPathError::Changed)?;
        if !metadata.is_dir() {
            return Err(LocalPathError::Invalid);
        }
        Ok(path)
    }

    pub fn read_file(&self, relative: impl AsRef<Path>) -> Result<Vec<u8>, LocalPathError> {
        let mut file = self.open_existing_file(relative)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)
            .map_err(|_| LocalPathError::Changed)?;
        Ok(data)
    }

    pub fn open_existing_file(
        &self,
        relative: impl AsRef<Path>,
    ) -> Result<ScopedLocalFile, LocalPathError> {
        let path = self.resolve_existing_file(relative)?;
        let path_metadata = fs::symlink_metadata(&path).map_err(|_| LocalPathError::Changed)?;
        let file = File::open(&path).map_err(|_| LocalPathError::Changed)?;
        let file_metadata = file.metadata().map_err(|_| LocalPathError::Changed)?;
        if !same_file_identity(&path_metadata, &file_metadata) {
            return Err(LocalPathError::Changed);
        }
        Ok(ScopedLocalFile {
            file,
            scope: self.clone(),
            path_metadata,
        })
    }

    /// Validate a not-yet-existing destination before target-side work begins.
    /// The final write repeats the full check immediately before staging.
    pub fn validate_new_file(&self, relative: impl AsRef<Path>) -> Result<(), LocalPathError> {
        self.resolve_new_file(relative.as_ref()).map(|_| ())
    }

    /// Stage and atomically link a new file into place without replacement.
    pub fn write_new_file(
        &self,
        relative: impl AsRef<Path>,
        data: &[u8],
    ) -> Result<(), LocalPathError> {
        let destination = self.resolve_new_file(relative.as_ref())?;
        let parent = destination.parent().ok_or(LocalPathError::Invalid)?;
        let parent_identity = fs::canonicalize(parent).map_err(|_| LocalPathError::Changed)?;

        let (mut staging, staging_path) = create_staging_file(parent)?;
        let mut cleanup = StagingCleanup(Some(staging_path.clone()));
        staging
            .write_all(data)
            .and_then(|_| staging.sync_all())
            .map_err(|_| LocalPathError::StagingUnavailable)?;
        let staging_metadata = staging
            .metadata()
            .map_err(|_| LocalPathError::StagingUnavailable)?;
        drop(staging);

        self.ensure_root_unchanged()?;
        let current_parent = fs::canonicalize(parent).map_err(|_| LocalPathError::Changed)?;
        if current_parent != parent_identity || !current_parent.starts_with(&self.canonical_root) {
            return Err(LocalPathError::Changed);
        }

        match fs::hard_link(&staging_path, &destination) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                return Err(LocalPathError::Exists);
            }
            Err(_) => return Err(LocalPathError::StagingUnavailable),
        }

        fs::remove_file(&staging_path).map_err(|_| LocalPathError::StagingUnavailable)?;
        cleanup.0 = None;
        let destination_metadata =
            fs::symlink_metadata(&destination).map_err(|_| LocalPathError::Changed)?;
        if !destination_metadata.is_file()
            || destination_metadata.file_type().is_symlink()
            || !same_file_identity(&staging_metadata, &destination_metadata)
        {
            return Err(LocalPathError::Changed);
        }
        self.ensure_root_unchanged()?;
        Ok(())
    }

    pub fn scan_directory(
        &self,
        relative: impl AsRef<Path>,
        limits: LocalScanLimits,
    ) -> Result<LocalScanReport, LocalPathError> {
        if limits.max_depth == 0 || limits.max_entries == 0 || limits.max_path_bytes == 0 {
            return Err(LocalPathError::Invalid);
        }
        let base = self.resolve_existing_directory(relative)?;
        let mut entries = Vec::new();
        let mut stack = vec![(base, PathBuf::new(), 0_usize)];
        let mut observed_depth = 0_usize;
        let mut observed_path_bytes = 0_usize;

        while let Some((directory, relative_directory, depth)) = stack.pop() {
            self.ensure_root_unchanged()?;
            let canonical = fs::canonicalize(&directory).map_err(|_| LocalPathError::Changed)?;
            if !canonical.starts_with(&self.canonical_root) {
                return Err(LocalPathError::OutsideScope);
            }
            let metadata = fs::symlink_metadata(&directory).map_err(|_| LocalPathError::Changed)?;
            if metadata.file_type().is_symlink() {
                return Err(LocalPathError::LinkDenied);
            }

            let mut children = fs::read_dir(&directory)
                .map_err(|_| LocalPathError::RootUnavailable)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| LocalPathError::RootUnavailable)?;
            children.sort_by_key(|entry| entry.file_name());

            for child in children {
                let child_depth = depth.saturating_add(1);
                if child_depth > limits.max_depth {
                    return Err(LocalPathError::ScanLimitExceeded);
                }
                let metadata =
                    fs::symlink_metadata(child.path()).map_err(|_| LocalPathError::Changed)?;
                if metadata.file_type().is_symlink() {
                    return Err(LocalPathError::LinkDenied);
                }
                if !same_filesystem(&self.root_metadata, &metadata) {
                    return Err(LocalPathError::LinkDenied);
                }
                if !metadata.is_file() && !metadata.is_dir() {
                    return Err(LocalPathError::LinkDenied);
                }

                let relative_path = relative_directory.join(child.file_name());
                let relative_text = relative_path
                    .to_str()
                    .ok_or(LocalPathError::Invalid)?
                    .replace('\\', "/");
                observed_path_bytes = observed_path_bytes.saturating_add(relative_text.len());
                if entries.len() >= limits.max_entries
                    || observed_path_bytes > limits.max_path_bytes
                {
                    return Err(LocalPathError::ScanLimitExceeded);
                }
                observed_depth = observed_depth.max(child_depth);
                entries.push(LocalScanEntry {
                    relative_path: relative_text,
                    is_dir: metadata.is_dir(),
                    size: metadata.len(),
                    modified: metadata.modified().ok(),
                });

                if metadata.is_dir() {
                    stack.push((child.path(), relative_path, child_depth));
                }
            }
        }

        self.ensure_root_unchanged()?;
        entries.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
        Ok(LocalScanReport {
            entries,
            observed_depth,
            observed_path_bytes,
            limits,
        })
    }

    fn resolve_existing(&self, relative: &Path) -> Result<PathBuf, LocalPathError> {
        self.ensure_root_unchanged()?;
        let components = validated_relative_components(relative, true)?;
        let mut current = self.canonical_root.clone();
        for component in components {
            current.push(component);
            let metadata = fs::symlink_metadata(&current).map_err(|_| LocalPathError::Invalid)?;
            if metadata.file_type().is_symlink() {
                return Err(LocalPathError::LinkDenied);
            }
            if !same_filesystem(&self.root_metadata, &metadata) {
                return Err(LocalPathError::LinkDenied);
            }
        }
        let canonical = fs::canonicalize(&current).map_err(|_| LocalPathError::Invalid)?;
        if !canonical.starts_with(&self.canonical_root) {
            return Err(LocalPathError::OutsideScope);
        }
        self.ensure_root_unchanged()?;
        Ok(canonical)
    }

    fn resolve_new_file(&self, relative: &Path) -> Result<PathBuf, LocalPathError> {
        let components = validated_relative_components(relative, false)?;
        let relative = components.iter().collect::<PathBuf>();
        let file_name = relative.file_name().ok_or(LocalPathError::Invalid)?;
        let parent_relative = relative
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let parent = self.resolve_existing_directory(parent_relative)?;
        let destination = parent.join(file_name);
        match fs::symlink_metadata(&destination) {
            Ok(_) => Err(LocalPathError::Exists),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                self.ensure_root_unchanged()?;
                Ok(destination)
            }
            Err(_) => Err(LocalPathError::StagingUnavailable),
        }
    }

    fn ensure_root_unchanged(&self) -> Result<(), LocalPathError> {
        let metadata =
            fs::symlink_metadata(&self.canonical_root).map_err(|_| LocalPathError::Changed)?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || !same_file_identity(&self.root_metadata, &metadata)
        {
            return Err(LocalPathError::Changed);
        }
        Ok(())
    }
}

fn local_path_io_error(error: LocalPathError) -> io::Error {
    io::Error::other(error)
}

fn validated_relative_components(
    relative: &Path,
    allow_root: bool,
) -> Result<Vec<std::ffi::OsString>, LocalPathError> {
    if relative.as_os_str().is_empty() || relative.is_absolute() {
        return Err(LocalPathError::Invalid);
    }
    let mut components = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(component) => {
                if component.to_string_lossy().contains('\0') {
                    return Err(LocalPathError::Invalid);
                }
                components.push(component.to_os_string());
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(LocalPathError::OutsideScope);
            }
        }
    }
    if components.is_empty() && !allow_root {
        return Err(LocalPathError::Invalid);
    }
    Ok(components)
}

fn create_staging_file(parent: &Path) -> Result<(File, PathBuf), LocalPathError> {
    for _ in 0..8 {
        let path = parent.join(format!(".voidb-stage-{}", Uuid::new_v4()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(file) => return Ok((file, path)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(_) => return Err(LocalPathError::StagingUnavailable),
        }
    }
    Err(LocalPathError::StagingUnavailable)
}

struct StagingCleanup(Option<PathBuf>);

impl Drop for StagingCleanup {
    fn drop(&mut self) {
        if let Some(path) = &self.0 {
            let _ = fs::remove_file(path);
        }
    }
}

#[cfg(unix)]
fn same_file_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev() && left.ino() == right.ino()
}

#[cfg(unix)]
fn same_filesystem(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    left.dev() == right.dev()
}

#[cfg(windows)]
fn same_file_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    left.volume_serial_number() == right.volume_serial_number()
        && left.file_index() == right.file_index()
}

#[cfg(windows)]
fn same_filesystem(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    left.volume_serial_number() == right.volume_serial_number()
}

#[cfg(not(any(unix, windows)))]
fn same_file_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.file_type() == right.file_type()
        && left.len() == right.len()
        && left.modified().ok() == right.modified().ok()
}

#[cfg(not(any(unix, windows)))]
fn same_filesystem(_left: &fs::Metadata, _right: &fs::Metadata) -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestRoot(PathBuf);

    impl TestRoot {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("voidb-local-path-{}", Uuid::new_v4()));
            fs::create_dir(&path).expect("create test root");
            Self(path)
        }
    }

    impl Drop for TestRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn local_filesystem_boundary_rejects_absolute_parent_and_nul_aliases() {
        let root = TestRoot::new();
        fs::write(root.0.join("inside.txt"), b"inside").unwrap();
        let scope = LocalPathScope::new(&root.0).unwrap();

        assert_eq!(scope.read_file("inside.txt").unwrap(), b"inside");
        assert_eq!(
            scope.read_file("../outside.txt"),
            Err(LocalPathError::OutsideScope)
        );
        assert_eq!(scope.read_file(&root.0), Err(LocalPathError::Invalid));
        assert_eq!(
            scope.read_file("inside\0.txt"),
            Err(LocalPathError::Invalid)
        );
    }

    #[test]
    fn local_filesystem_boundary_staged_write_never_replaces_an_existing_destination() {
        let root = TestRoot::new();
        fs::write(root.0.join("existing.txt"), b"original").unwrap();
        let scope = LocalPathScope::new(&root.0).unwrap();

        assert_eq!(
            scope.write_new_file("existing.txt", b"replacement"),
            Err(LocalPathError::Exists)
        );
        assert_eq!(fs::read(root.0.join("existing.txt")).unwrap(), b"original");

        scope.write_new_file("new.txt", b"new").unwrap();
        assert_eq!(fs::read(root.0.join("new.txt")).unwrap(), b"new");
        assert!(fs::read_dir(&root.0).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".voidb-stage-")
        }));
    }

    #[test]
    fn local_filesystem_boundary_scan_is_deterministic_and_enforces_every_limit() {
        let root = TestRoot::new();
        fs::create_dir(root.0.join("nested")).unwrap();
        fs::write(root.0.join("z.txt"), b"z").unwrap();
        fs::write(root.0.join("nested/a.txt"), b"a").unwrap();
        let scope = LocalPathScope::new(&root.0).unwrap();

        let report = scope
            .scan_directory(".", LocalScanLimits::default())
            .unwrap();
        assert_eq!(
            report
                .entries
                .iter()
                .map(|entry| entry.relative_path.as_str())
                .collect::<Vec<_>>(),
            vec!["nested", "nested/a.txt", "z.txt"]
        );
        assert_eq!(
            scope.scan_directory(
                ".",
                LocalScanLimits {
                    max_entries: 2,
                    ..LocalScanLimits::default()
                }
            ),
            Err(LocalPathError::ScanLimitExceeded)
        );
        assert_eq!(
            scope.scan_directory(
                ".",
                LocalScanLimits {
                    max_depth: 1,
                    ..LocalScanLimits::default()
                }
            ),
            Err(LocalPathError::ScanLimitExceeded)
        );
        assert_eq!(
            scope.scan_directory(
                ".",
                LocalScanLimits {
                    max_path_bytes: 2,
                    ..LocalScanLimits::default()
                }
            ),
            Err(LocalPathError::ScanLimitExceeded)
        );
    }

    #[test]
    fn local_filesystem_boundary_preserves_unicode_names_without_normalizing_them() {
        let root = TestRoot::new();
        fs::create_dir(root.0.join("数据")).unwrap();
        fs::write(root.0.join("数据/résumé-😀.txt"), b"unicode").unwrap();
        let scope = LocalPathScope::new(&root.0).unwrap();

        assert_eq!(scope.read_file("数据/résumé-😀.txt").unwrap(), b"unicode");
        let report = scope
            .scan_directory(".", LocalScanLimits::default())
            .unwrap();
        assert_eq!(
            report
                .entries
                .iter()
                .map(|entry| entry.relative_path.as_str())
                .collect::<Vec<_>>(),
            vec!["数据", "数据/résumé-😀.txt"]
        );
    }

    #[test]
    fn local_filesystem_boundary_concurrent_creators_have_exactly_one_winner() {
        use std::sync::{Arc, Barrier};

        let root = TestRoot::new();
        let scope = Arc::new(LocalPathScope::new(&root.0).unwrap());
        let barrier = Arc::new(Barrier::new(2));
        let handles = [b"first".as_slice(), b"second".as_slice()].map(|content| {
            let scope = Arc::clone(&scope);
            let barrier = Arc::clone(&barrier);
            std::thread::spawn(move || {
                barrier.wait();
                scope.write_new_file("race.txt", content)
            })
        });
        let results = handles.map(|handle| handle.join().expect("creator thread"));

        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| **result == Err(LocalPathError::Exists))
                .count(),
            1
        );
        assert!(
            [b"first".as_slice(), b"second".as_slice()]
                .contains(&fs::read(root.0.join("race.txt")).unwrap().as_slice())
        );
        assert!(fs::read_dir(&root.0).unwrap().all(|entry| {
            !entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".voidb-stage-")
        }));
    }

    #[test]
    fn local_filesystem_boundary_rejects_replaced_approved_root_identity() {
        let root = TestRoot::new();
        fs::write(root.0.join("approved.txt"), b"approved").unwrap();
        let scope = LocalPathScope::new(&root.0).unwrap();
        let moved = root.0.with_extension(format!("moved-{}", Uuid::new_v4()));
        fs::rename(&root.0, &moved).unwrap();
        fs::create_dir(&root.0).unwrap();
        fs::write(root.0.join("approved.txt"), b"replacement").unwrap();

        assert_eq!(
            scope.read_file("approved.txt"),
            Err(LocalPathError::Changed)
        );
        assert_eq!(
            scope.validate_new_file("new.txt"),
            Err(LocalPathError::Changed)
        );
        assert_eq!(
            scope.scan_directory(".", LocalScanLimits::default()),
            Err(LocalPathError::Changed)
        );
        assert!(!root.0.join("new.txt").exists());

        fs::remove_dir_all(moved).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn local_filesystem_boundary_rejects_symlink_roots_reads_writes_and_scans() {
        use std::os::unix::fs::symlink;

        let root = TestRoot::new();
        let outside = TestRoot::new();
        fs::write(outside.0.join("secret.txt"), b"secret").unwrap();
        symlink(outside.0.join("secret.txt"), root.0.join("read-link")).unwrap();
        symlink(&outside.0, root.0.join("dir-link")).unwrap();
        let root_link = root.0.with_extension(format!("link-{}", Uuid::new_v4()));
        symlink(&root.0, &root_link).unwrap();
        assert!(matches!(
            LocalPathScope::new(&root_link),
            Err(LocalPathError::LinkDenied)
        ));
        let scope = LocalPathScope::new(&root.0).unwrap();

        assert_eq!(
            scope.read_file("read-link"),
            Err(LocalPathError::LinkDenied)
        );
        assert_eq!(
            scope.write_new_file("dir-link/write.txt", b"blocked"),
            Err(LocalPathError::LinkDenied)
        );
        assert_eq!(
            scope.scan_directory(".", LocalScanLimits::default()),
            Err(LocalPathError::LinkDenied)
        );
        assert!(!outside.0.join("write.txt").exists());
        fs::remove_file(root_link).unwrap();
    }
}
