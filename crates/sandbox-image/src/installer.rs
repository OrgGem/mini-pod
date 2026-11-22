//! Anti-tamper bundle tree verification and atomic staging/swap installer.

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

use sandbox_core::SandboxError;
use sha2::{Digest, Sha256};

use crate::crypto::{encode_hex, sha256_reader, BundleVerifier};
use crate::manifest::{
    ArtifactRole, BundleManifest, MANIFEST_FILENAME, MAX_MANIFEST_BYTES, SIGNATURE_FILENAME,
};

const COPY_BUFFER_BYTES: usize = 64 * 1024;
const MAX_BUNDLE_TREE_DEPTH: usize = 32;
const WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
// shortcut: 5s try_lock polling deadline rejects concurrent bundle swap when live VMs hold read guards, add explicit drain-and-upgrade command if zero-downtime hot bundle swap is needed post-MVP
const BUNDLE_EXCLUSIVE_LOCK_TIMEOUT: Duration = Duration::from_secs(5);
const BUNDLE_EXCLUSIVE_LOCK_POLL: Duration = Duration::from_millis(5);

static NEXT_TEMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Verified Portable Runtime Bundle directory and its authenticated [`BundleManifest`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstalledBundle {
    root_dir: PathBuf,
    manifest: BundleManifest,
}

impl InstalledBundle {
    /// Returns the verified bundle root directory path.
    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }

    /// Returns the authenticated [`BundleManifest`] for this bundle.
    pub fn manifest(&self) -> &BundleManifest {
        &self.manifest
    }

    /// Returns the host filesystem path of the first artifact matching `role`, if present.
    pub fn role_path(&self, role: ArtifactRole) -> Option<PathBuf> {
        self.manifest
            .entries
            .iter()
            .find(|entry| entry.role == role)
            .map(|entry| rel_path_to_host(&self.root_dir, &entry.rel_path))
    }

    /// Returns the host filesystem path of the bundle's guest kernel artifact.
    pub fn kernel_path(&self) -> PathBuf {
        self.role_path(ArtifactRole::Kernel)
            .expect("validated BundleManifest must include a Kernel entry")
    }

    /// Returns the host filesystem path of the bundle's guest initrd artifact.
    pub fn initrd_path(&self) -> PathBuf {
        self.role_path(ArtifactRole::Initrd)
            .expect("validated BundleManifest must include an Initrd entry")
    }

    /// Returns the host filesystem path of the bundle's read-only base rootfs `qcow2` artifact.
    pub fn base_rootfs_qcow2_path(&self) -> PathBuf {
        self.role_path(ArtifactRole::BaseRootfsQcow2)
            .expect("validated BundleManifest must include a BaseRootfsQcow2 entry")
    }
}

/// Validates signature, manifest invariants, anti-tamper tree hygiene, and single-pass SHA-256
/// copy into a staging directory before atomically swapping into `<install_parent_dir>/<bundle_id>`.
pub fn install_bundle_atomic(
    source_bundle_dir: &Path,
    install_parent_dir: &Path,
    verifier: &BundleVerifier,
) -> Result<InstalledBundle, SandboxError> {
    check_dir_path(source_bundle_dir)?;

    let manifest_bytes = read_bounded_regular_file(&source_bundle_dir.join(MANIFEST_FILENAME), MAX_MANIFEST_BYTES)?;
    let sig_bytes = read_bounded_regular_file(&source_bundle_dir.join(SIGNATURE_FILENAME), MAX_MANIFEST_BYTES)?;

    // Trust boundary: verify Ed25519 signature strictly before parsing or scanning files.
    let manifest = verifier.verify_and_parse_manifest(&manifest_bytes, &sig_bytes)?;
    manifest.ensure_compatible_host_os(std::env::consts::OS)?;

    let declared: BTreeSet<&str> = manifest.entries.iter().map(|e| e.rel_path.as_str()).collect();
    validate_bundle_tree(source_bundle_dir, &declared)?;

    ensure_clean_parent_dir(install_parent_dir)?;

    let staging_dir = create_unique_temp_dir(install_parent_dir, "staging", &manifest.bundle_id)?;
    let mut staging_guard = TempDirGuard::new(staging_dir.clone());

    for entry in &manifest.entries {
        let src_path = rel_path_to_host(source_bundle_dir, &entry.rel_path);
        let dst_path = ensure_staging_parent_dirs(&staging_dir, &entry.rel_path)?;
        copy_verify_and_sync(&src_path, &dst_path, &entry.sha256, entry.size_bytes)?;
    }

    write_new_synced_file(&staging_dir.join(MANIFEST_FILENAME), &manifest_bytes)?;
    write_new_synced_file(&staging_dir.join(SIGNATURE_FILENAME), &sig_bytes)?;

    let target_dir = install_parent_dir.join(&manifest.bundle_id);
    atomic_swap_dir(
        &staging_dir,
        &target_dir,
        &manifest.bundle_id,
        verifier,
        &mut staging_guard,
    )?;

    Ok(InstalledBundle {
        root_dir: target_dir,
        manifest,
    })
}

/// Verifies an already-installed bundle in place: root non-link check, Ed25519 manifest signature,
/// anti-tamper directory walk (no symlinks, reparse points, hardlinks, or extra files), and
/// exact SHA-256 + byte-size match for every declared artifact.
pub fn verify_installed_bundle(
    bundle_dir: &Path,
    verifier: &BundleVerifier,
) -> Result<InstalledBundle, SandboxError> {
    with_verified_installed_bundle_read_locked(bundle_dir, verifier, |installed, _read_guard| {
        Ok(installed)
    })
}

/// Acquires a shared OS lock on `<install_parent>/.lock-<bundle_id>` (healing any interrupted
/// `.promote-<bundle_id>.v1` swap first), verifies `bundle_dir`, and runs `op` while holding the
/// shared read lock (passing the lock file handle so callers can extend the shared read lock
/// across subsequent VM launches) so concurrent live upgrades cannot swap `bundle_dir` mid-operation.
pub(crate) fn with_verified_installed_bundle_read_locked<T, F>(
    bundle_dir: &Path,
    verifier: &BundleVerifier,
    op: F,
) -> Result<T, SandboxError>
where
    F: FnOnce(InstalledBundle, Option<File>) -> Result<T, SandboxError>,
{
    let read_guard = acquire_bundle_read_guard(bundle_dir, verifier)?;
    let installed = verify_installed_bundle_once(bundle_dir, verifier)?;
    op(installed, read_guard)
}

fn verify_installed_bundle_once(
    bundle_dir: &Path,
    verifier: &BundleVerifier,
) -> Result<InstalledBundle, SandboxError> {
    check_dir_path(bundle_dir)?;

    let manifest_bytes = read_bounded_regular_file(&bundle_dir.join(MANIFEST_FILENAME), MAX_MANIFEST_BYTES)?;
    let sig_bytes = read_bounded_regular_file(&bundle_dir.join(SIGNATURE_FILENAME), MAX_MANIFEST_BYTES)?;

    let manifest = verifier.verify_and_parse_manifest(&manifest_bytes, &sig_bytes)?;

    let declared: BTreeSet<&str> = manifest.entries.iter().map(|e| e.rel_path.as_str()).collect();
    validate_bundle_tree(bundle_dir, &declared)?;

    for entry in &manifest.entries {
        let entry_path = rel_path_to_host(bundle_dir, &entry.rel_path);
        let meta = check_regular_file_path(&entry_path, true)?;
        if meta.len() != entry.size_bytes {
            return Err(SandboxError::PolicyViolation(format!(
                "bundle artifact '{}' size mismatch: expected {} bytes, found {} bytes",
                entry.rel_path,
                entry.size_bytes,
                meta.len()
            )));
        }
        let mut file = File::open(&entry_path)
            .map_err(|err| map_fs_error(&entry_path, "open bundle artifact for verification", err))?;
        let open_meta = file
            .metadata()
            .map_err(|err| map_fs_error(&entry_path, "inspect open bundle artifact", err))?;
        validate_metadata_no_link(&entry_path, &open_meta, false, true)?;

        let (actual_sha256, actual_size) = sha256_reader(&mut file)?;
        if actual_size != entry.size_bytes || actual_sha256 != entry.sha256 {
            return Err(SandboxError::PolicyViolation(format!(
                "bundle artifact '{}' integrity check failed (expected {} bytes sha256={}, got {} bytes sha256={})",
                entry.rel_path,
                entry.size_bytes,
                encode_hex(&entry.sha256),
                actual_size,
                encode_hex(&actual_sha256),
            )));
        }
    }

    Ok(InstalledBundle {
        root_dir: bundle_dir.to_path_buf(),
        manifest,
    })
}

/// Recursively walks `bundle_dir` using `symlink_metadata`, rejecting symlinks, Windows reparse
/// points (`0x0400`), non-regular/non-dir nodes, Unix hardlinks (`nlink > 1`), missing declared
/// entries, and any undeclared extra files other than root `manifest.v1` and `manifest.sig`.
pub fn validate_bundle_tree(
    bundle_dir: &Path,
    declared_rel_paths: &BTreeSet<&str>,
) -> Result<(), SandboxError> {
    check_dir_path(bundle_dir)?;

    let mut seen_entries = BTreeSet::new();
    let mut stack = vec![(bundle_dir.to_path_buf(), String::new(), 0usize)];

    while let Some((dir_path, rel_prefix, depth)) = stack.pop() {
        let entries = fs::read_dir(&dir_path)
            .map_err(|err| map_fs_error(&dir_path, "read bundle directory", err))?;

        let mut children: Vec<(String, PathBuf)> = Vec::new();
        for item in entries {
            let item = item.map_err(|err| map_fs_error(&dir_path, "iterate bundle directory", err))?;
            let raw_name = item.file_name();
            let name = raw_name.to_str().ok_or_else(|| {
                SandboxError::PolicyViolation(format!(
                    "refusing non-UTF-8 entry inside bundle directory '{}'",
                    dir_path.display()
                ))
            })?;
            children.push((name.to_owned(), item.path()));
        }
        children.sort_by(|a, b| a.0.cmp(&b.0));

        for (name, child_path) in children {
            let meta = fs::symlink_metadata(&child_path)
                .map_err(|err| map_fs_error(&child_path, "inspect bundle node metadata", err))?;
            let rel = if rel_prefix.is_empty() {
                name
            } else {
                format!("{rel_prefix}/{name}")
            };

            if meta.file_type().is_symlink() {
                return Err(SandboxError::PolicyViolation(format!(
                    "refusing symlink '{rel}' inside bundle '{}'",
                    bundle_dir.display()
                )));
            }
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                if has_windows_reparse_attribute(meta.file_attributes()) {
                    return Err(SandboxError::PolicyViolation(format!(
                        "refusing Windows reparse point/junction '{rel}' inside bundle '{}'",
                        bundle_dir.display()
                    )));
                }
            }

            if meta.file_type().is_dir() {
                if depth + 1 > MAX_BUNDLE_TREE_DEPTH {
                    return Err(SandboxError::PolicyViolation(format!(
                        "bundle directory nesting exceeds maximum depth {MAX_BUNDLE_TREE_DEPTH} at '{rel}'"
                    )));
                }
                if rel == MANIFEST_FILENAME
                    || rel == SIGNATURE_FILENAME
                    || declared_rel_paths.contains(rel.as_str())
                {
                    return Err(SandboxError::PolicyViolation(format!(
                        "directory '{rel}' collides with declared bundle file path"
                    )));
                }
                stack.push((child_path, rel, depth + 1));
            } else if meta.file_type().is_file() {
                validate_metadata_no_link(&child_path, &meta, false, true)?;
                if rel == MANIFEST_FILENAME || rel == SIGNATURE_FILENAME {
                    continue;
                }
                if declared_rel_paths.contains(rel.as_str()) {
                    seen_entries.insert(rel);
                } else {
                    return Err(SandboxError::PolicyViolation(format!(
                        "refusing undeclared extra file '{rel}' inside bundle '{}'",
                        bundle_dir.display()
                    )));
                }
            } else {
                return Err(SandboxError::PolicyViolation(format!(
                    "refusing special non-regular filesystem node '{rel}' inside bundle '{}'",
                    bundle_dir.display()
                )));
            }
        }
    }

    for expected in declared_rel_paths {
        if !seen_entries.contains(*expected) {
            return Err(SandboxError::NotFound(format!(
                "missing declared bundle artifact '{expected}' in '{}'",
                bundle_dir.display()
            )));
        }
    }

    Ok(())
}

pub(crate) fn next_temp_suffix() -> String {
    format!(
        "{}-{}",
        std::process::id(),
        NEXT_TEMP_SEQ.fetch_add(1, Ordering::Relaxed)
    )
}

#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) const fn has_windows_reparse_attribute(file_attributes: u32) -> bool {
    (file_attributes & WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT) != 0
}

pub(crate) fn validate_metadata_no_link(
    path: &Path,
    meta: &fs::Metadata,
    expect_dir: bool,
    reject_hardlinks: bool,
) -> Result<(), SandboxError> {
    if meta.file_type().is_symlink() {
        return Err(SandboxError::PolicyViolation(format!(
            "refusing symlink at '{}'",
            path.display()
        )));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if has_windows_reparse_attribute(meta.file_attributes()) {
            return Err(SandboxError::PolicyViolation(format!(
                "refusing Windows reparse point/junction at '{}'",
                path.display()
            )));
        }
    }

    if expect_dir {
        if !meta.file_type().is_dir() {
            return Err(SandboxError::PolicyViolation(format!(
                "expected directory (found non-directory) at '{}'",
                path.display()
            )));
        }
    } else {
        if !meta.file_type().is_file() {
            return Err(SandboxError::PolicyViolation(format!(
                "refusing non-regular file at '{}'",
                path.display()
            )));
        }
        #[cfg(unix)]
        if reject_hardlinks {
            use std::os::unix::fs::MetadataExt;
            if meta.nlink() > 1 {
                return Err(SandboxError::PolicyViolation(format!(
                    "refusing hardlinked file (nlink={}) at '{}'",
                    meta.nlink(),
                    path.display()
                )));
            }
        }
        #[cfg(not(unix))]
        let _ = reject_hardlinks;
    }

    Ok(())
}

pub(crate) fn check_dir_path(path: &Path) -> Result<fs::Metadata, SandboxError> {
    let meta = fs::symlink_metadata(path)
        .map_err(|err| map_fs_error(path, "inspect directory metadata", err))?;
    validate_metadata_no_link(path, &meta, true, false)?;
    Ok(meta)
}

pub(crate) fn check_regular_file_path(
    path: &Path,
    reject_hardlinks: bool,
) -> Result<fs::Metadata, SandboxError> {
    let meta = fs::symlink_metadata(path)
        .map_err(|err| map_fs_error(path, "inspect file metadata", err))?;
    validate_metadata_no_link(path, &meta, false, reject_hardlinks)?;
    Ok(meta)
}

pub(crate) fn map_fs_error(path: &Path, action: &str, err: io::Error) -> SandboxError {
    match err.kind() {
        ErrorKind::NotFound => SandboxError::NotFound(format!(
            "cannot {action} '{}': {err}",
            path.display()
        )),
        ErrorKind::PermissionDenied => SandboxError::PolicyViolation(format!(
            "permission denied while attempting to {action} '{}': {err}",
            path.display()
        )),
        _ => SandboxError::Internal(format!(
            "failed to {action} '{}': {err}",
            path.display()
        )),
    }
}

fn rel_path_to_host(root: &Path, rel_path: &str) -> PathBuf {
    let mut out = root.to_path_buf();
    for segment in rel_path.split('/') {
        out.push(segment);
    }
    out
}

fn read_bounded_regular_file(path: &Path, max_bytes: usize) -> Result<Vec<u8>, SandboxError> {
    let meta = check_regular_file_path(path, true)?;
    if meta.len() > max_bytes as u64 {
        return Err(SandboxError::InvalidSpec(format!(
            "file '{}' size {} bytes exceeds maximum allowed {} bytes",
            path.display(),
            meta.len(),
            max_bytes
        )));
    }
    let file = File::open(path).map_err(|err| map_fs_error(path, "open file", err))?;
    let open_meta = file
        .metadata()
        .map_err(|err| map_fs_error(path, "inspect open file metadata", err))?;
    validate_metadata_no_link(path, &open_meta, false, true)?;

    let mut buf = Vec::with_capacity((open_meta.len() as usize).min(max_bytes));
    file.take((max_bytes as u64).saturating_add(1))
        .read_to_end(&mut buf)
        .map_err(|err| map_fs_error(path, "read file", err))?;
    if buf.len() > max_bytes {
        return Err(SandboxError::InvalidSpec(format!(
            "file '{}' exceeds maximum allowed {} bytes",
            path.display(),
            max_bytes
        )));
    }
    Ok(buf)
}

fn ensure_clean_parent_dir(parent_dir: &Path) -> Result<(), SandboxError> {
    match fs::symlink_metadata(parent_dir) {
        Ok(meta) => validate_metadata_no_link(parent_dir, &meta, true, false),
        Err(err) if err.kind() == ErrorKind::NotFound => {
            fs::create_dir_all(parent_dir)
                .map_err(|e| map_fs_error(parent_dir, "create install parent directory", e))?;
            check_dir_path(parent_dir)?;
            Ok(())
        }
        Err(err) => Err(map_fs_error(
            parent_dir,
            "inspect install parent directory",
            err,
        )),
    }
}

fn create_unique_temp_dir(
    parent: &Path,
    prefix: &str,
    bundle_id: &str,
) -> Result<PathBuf, SandboxError> {
    for _ in 0..64 {
        let candidate = parent.join(format!(".{prefix}-{bundle_id}-{}", next_temp_suffix()));
        match fs::create_dir(&candidate) {
            Ok(()) => return Ok(candidate),
            Err(err) if err.kind() == ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(map_fs_error(&candidate, "create staging directory", err)),
        }
    }
    Err(SandboxError::Internal(format!(
        "exhausted attempts creating unique staging directory under '{}'",
        parent.display()
    )))
}

fn ensure_staging_parent_dirs(staging_root: &Path, rel_path: &str) -> Result<PathBuf, SandboxError> {
    let mut cur = staging_root.to_path_buf();
    let mut segments = rel_path.split('/').peekable();
    while let Some(seg) = segments.next() {
        cur.push(seg);
        if segments.peek().is_some() {
            match fs::create_dir(&cur) {
                Ok(()) => {}
                Err(err) if err.kind() == ErrorKind::AlreadyExists => {
                    check_dir_path(&cur)?;
                }
                Err(err) => {
                    return Err(map_fs_error(&cur, "create staging subdirectory", err));
                }
            }
        }
    }
    Ok(cur)
}

/// Copies `src` to `dst` in one streaming pass, hashing and counting the exact bytes written so
/// no TOCTOU window exists between digest verification and disk persistence.
fn copy_verify_and_sync(
    src: &Path,
    dst: &Path,
    expected_sha256: &[u8; 32],
    expected_size: u64,
) -> Result<(), SandboxError> {
    let src_lstat = check_regular_file_path(src, true)?;
    if src_lstat.len() != expected_size {
        return Err(SandboxError::PolicyViolation(format!(
            "source bundle artifact '{}' size mismatch: expected {} bytes, found {} bytes",
            src.display(),
            expected_size,
            src_lstat.len()
        )));
    }

    let mut src_file = File::open(src).map_err(|err| map_fs_error(src, "open source artifact", err))?;
    let src_open_meta = src_file
        .metadata()
        .map_err(|err| map_fs_error(src, "inspect open source artifact", err))?;
    validate_metadata_no_link(src, &src_open_meta, false, true)?;

    let mut dst_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(dst)
        .map_err(|err| map_fs_error(dst, "create staged artifact", err))?;

    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; COPY_BUFFER_BYTES];
    let mut total_written: u64 = 0;

    loop {
        match src_file.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                total_written = total_written.checked_add(n as u64).ok_or_else(|| {
                    SandboxError::PolicyViolation("copied artifact byte count overflow".to_owned())
                })?;
                if total_written > expected_size {
                    return Err(SandboxError::PolicyViolation(format!(
                        "source bundle artifact '{}' grew beyond declared {} bytes during copy",
                        src.display(),
                        expected_size
                    )));
                }
                hasher.update(&buf[..n]);
                dst_file
                    .write_all(&buf[..n])
                    .map_err(|err| map_fs_error(dst, "write staged artifact", err))?;
            }
            Err(err) if err.kind() == ErrorKind::Interrupted => continue,
            Err(err) => return Err(map_fs_error(src, "read source artifact", err)),
        }
    }

    let actual_sha256: [u8; 32] = hasher.finalize().into();
    if total_written != expected_size || actual_sha256 != *expected_sha256 {
        return Err(SandboxError::PolicyViolation(format!(
            "staged artifact '{}' failed single-pass verification (expected {} bytes sha256={}, copied {} bytes sha256={})",
            src.display(),
            expected_size,
            encode_hex(expected_sha256),
            total_written,
            encode_hex(&actual_sha256),
        )));
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Preserve executable bit for bundled binaries while stripping any setuid/setgid/special bits.
        let mode = if (src_open_meta.permissions().mode() & 0o111) != 0 {
            0o755
        } else {
            0o644
        };
        dst_file
            .set_permissions(fs::Permissions::from_mode(mode))
            .map_err(|err| map_fs_error(dst, "set staged artifact permissions", err))?;
    }

    dst_file
        .sync_all()
        .map_err(|err| map_fs_error(dst, "sync staged artifact to disk", err))?;

    Ok(())
}

fn write_new_synced_file(path: &Path, bytes: &[u8]) -> Result<(), SandboxError> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|err| map_fs_error(path, "create staged metadata file", err))?;
    file.write_all(bytes)
        .map_err(|err| map_fs_error(path, "write staged metadata file", err))?;
    file.sync_all()
        .map_err(|err| map_fs_error(path, "sync staged metadata file", err))?;
    Ok(())
}

fn atomic_swap_dir(
    staging_dir: &Path,
    target_dir: &Path,
    bundle_id: &str,
    verifier: &BundleVerifier,
    staging_guard: &mut TempDirGuard,
) -> Result<(), SandboxError> {
    let parent = target_dir.parent().ok_or_else(|| {
        SandboxError::Internal("target bundle directory has no parent".to_owned())
    })?;
    let lock_path = parent.join(format!(".lock-{bundle_id}"));
    let _swap_lock = open_bundle_lock_exclusive(&lock_path)?;

    let intent_path = parent.join(format!(".promote-{bundle_id}.v1"));
    if path_exists_no_follow(&intent_path)? {
        recover_promotion_under_exclusive_lock(target_dir, &intent_path, verifier)?;
    }
    sweep_stale_backup_dirs(parent, bundle_id);

    match fs::symlink_metadata(target_dir) {
        Err(err) if err.kind() == ErrorKind::NotFound => {
            rename_with_brief_retry(staging_dir, target_dir)
                .map_err(|e| map_fs_error(target_dir, "promote staged bundle directory", e))?;
            staging_guard.disarm();
            Ok(())
        }
        Ok(existing_meta) => {
            validate_metadata_no_link(target_dir, &existing_meta, true, false)?;
            let backup_name = format!(".backup-{bundle_id}-{}", next_temp_suffix());
            let backup_dir = parent.join(&backup_name);
            let staging_name = staging_dir
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| {
                    SandboxError::Internal("staging directory missing UTF-8 filename".to_owned())
                })?;

            let intent_payload = format!("staging={staging_name}\nbackup={backup_name}\n");
            write_synced_intent_file(&intent_path, intent_payload.as_bytes())?;

            if let Err(err) = rename_with_brief_retry(target_dir, &backup_dir) {
                let _ = fs::remove_file(&intent_path);
                return Err(map_fs_error(
                    target_dir,
                    "move existing bundle directory to backup",
                    err,
                ));
            }

            if let Err(promote_err) = rename_with_brief_retry(staging_dir, target_dir) {
                let rollback_res = rename_with_brief_retry(&backup_dir, target_dir);
                if rollback_res.is_ok() {
                    let _ = fs::remove_file(&intent_path);
                }
                return Err(match rollback_res {
                    Ok(()) => SandboxError::Internal(format!(
                        "failed to swap staged bundle '{}' into '{}' (rolled back previous bundle): {promote_err}",
                        staging_dir.display(),
                        target_dir.display()
                    )),
                    Err(rollback_err) => SandboxError::Internal(format!(
                        "failed to swap staged bundle '{}' into '{}' ({promote_err}) AND rollback from '{}' failed: {rollback_err}",
                        staging_dir.display(),
                        target_dir.display(),
                        backup_dir.display()
                    )),
                });
            }

            staging_guard.disarm();
            let _ = fs::remove_file(&intent_path);
            // Promotion is already committed; best-effort cleanup avoids reporting a false
            // install failure if an external scanner briefly holds a handle inside `backup_dir`.
            let _ = remove_dir_all_with_brief_retry(&backup_dir);
            Ok(())
        }
        Err(err) => Err(map_fs_error(
            target_dir,
            "inspect target bundle directory",
            err,
        )),
    }
}

fn path_exists_no_follow(path: &Path) -> Result<bool, SandboxError> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(false),
        Err(err) => Err(map_fs_error(path, "inspect bundle recovery path", err)),
    }
}

fn sweep_stale_backup_dirs(parent: &Path, bundle_id: &str) {
    let prefix = format!(".backup-{bundle_id}-");
    let Ok(entries) = fs::read_dir(parent) else {
        return;
    };
    for entry in entries.flatten() {
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if !name.starts_with(&prefix) {
            continue;
        }
        let path = entry.path();
        if let Ok(meta) = fs::symlink_metadata(&path) {
            if validate_metadata_no_link(&path, &meta, true, false).is_ok() {
                let _ = remove_dir_all_with_brief_retry(&path);
            }
        }
    }
}

fn bundle_parent_and_name(target_dir: &Path) -> Option<(PathBuf, &str)> {
    let name = target_dir.file_name()?.to_str()?;
    if name.is_empty() || name.contains('/') || name.contains('\\') {
        return None;
    }
    let parent = match target_dir.parent() {
        Some(p) if !p.as_os_str().is_empty() => p.to_path_buf(),
        Some(_) => std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
        None => return None,
    };
    Some((parent, name))
}

fn bundle_lock_and_intent_paths(target_dir: &Path) -> Option<(PathBuf, PathBuf)> {
    let (parent, name) = bundle_parent_and_name(target_dir)?;
    Some((
        parent.join(format!(".lock-{name}")),
        parent.join(format!(".promote-{name}.v1")),
    ))
}

fn open_bundle_lock_file(lock_path: &Path, create_if_missing: bool) -> Result<Option<File>, SandboxError> {
    if let Ok(meta) = fs::symlink_metadata(lock_path) {
        validate_metadata_no_link(lock_path, &meta, false, false)?;
    }
    let mut opts = OpenOptions::new();
    opts.read(true).write(true).create(create_if_missing).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    match opts.open(lock_path) {
        Ok(file) => Ok(Some(file)),
        Err(err) if !create_if_missing && err.kind() == ErrorKind::NotFound => Ok(None),
        Err(err)
            if matches!(
                err.kind(),
                ErrorKind::PermissionDenied | ErrorKind::ReadOnlyFilesystem
            ) =>
        {
            match File::open(lock_path) {
                Ok(file) => Ok(Some(file)),
                Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
                Err(e) => Err(map_fs_error(lock_path, "open bundle lock file", e)),
            }
        }
        Err(err) => Err(map_fs_error(lock_path, "open bundle lock file", err)),
    }
}

fn open_bundle_lock_exclusive(lock_path: &Path) -> Result<File, SandboxError> {
    open_bundle_lock_exclusive_timeout(lock_path, BUNDLE_EXCLUSIVE_LOCK_TIMEOUT)
}

fn open_bundle_lock_exclusive_timeout(
    lock_path: &Path,
    timeout: Duration,
) -> Result<File, SandboxError> {
    let file = open_bundle_lock_file(lock_path, true)?.ok_or_else(|| {
        SandboxError::Internal(format!(
            "bundle lock file '{}' unexpectedly missing after create",
            lock_path.display()
        ))
    })?;
    let deadline = std::time::Instant::now() + timeout;
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(file),
            Err(fs::TryLockError::WouldBlock) => {
                let now = std::time::Instant::now();
                if now >= deadline {
                    return Err(SandboxError::AdmissionRejected(format!(
                        "timed out after {} ms waiting for exclusive bundle lock '{}' (active or warm VMs may still hold read guards)",
                        timeout.as_millis(),
                        lock_path.display()
                    )));
                }
                let sleep_for =
                    BUNDLE_EXCLUSIVE_LOCK_POLL.min(deadline.saturating_duration_since(now));
                thread::sleep(sleep_for);
            }
            Err(fs::TryLockError::Error(err)) => {
                return Err(map_fs_error(
                    lock_path,
                    "acquire exclusive bundle swap lock",
                    err,
                ));
            }
        }
    }
}

fn acquire_bundle_read_guard(
    target_dir: &Path,
    verifier: &BundleVerifier,
) -> Result<Option<File>, SandboxError> {
    let Some((lock_path, intent_path)) = bundle_lock_and_intent_paths(target_dir) else {
        return Ok(None);
    };
    let Some(parent_dir) = lock_path.parent() else {
        return Ok(None);
    };
    match fs::symlink_metadata(parent_dir) {
        Ok(meta) => validate_metadata_no_link(parent_dir, &meta, true, false)?,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(map_fs_error(
                parent_dir,
                "inspect install parent directory",
                err,
            ))
        }
    }
    // Check target_dir before creating `.lock-*` so symlink/junction rejections never leave lock files behind.
    match fs::symlink_metadata(target_dir) {
        Ok(meta) => validate_metadata_no_link(target_dir, &meta, true, false)?,
        Err(err) if err.kind() == ErrorKind::NotFound => {
            if !path_exists_no_follow(&intent_path)? && !path_exists_no_follow(&lock_path)? {
                return Ok(None);
            }
        }
        Err(err) => return Err(map_fs_error(target_dir, "inspect installed bundle dir", err)),
    }

    let Some(shared_file) = open_bundle_lock_file(&lock_path, true)? else {
        return Ok(None);
    };
    shared_file
        .lock_shared()
        .map_err(|err| map_fs_error(&lock_path, "acquire shared bundle read lock", err))?;

    if !path_exists_no_follow(&intent_path)? {
        return Ok(Some(shared_file));
    }

    // Because `lock_shared()` is held, no active writer owns `lock()`. The leftover intent file
    // belongs to a crashed promotion; upgrade to an exclusive lock to heal `target_dir`.
    drop(shared_file);
    {
        let _excl = open_bundle_lock_exclusive(&lock_path)?;
        if path_exists_no_follow(&intent_path)? {
            recover_promotion_under_exclusive_lock(target_dir, &intent_path, verifier)?;
        }
    }

    let healed_shared = open_bundle_lock_file(&lock_path, true)?.ok_or_else(|| {
        SandboxError::Internal(format!(
            "bundle lock file '{}' disappeared after recovery",
            lock_path.display()
        ))
    })?;
    healed_shared
        .lock_shared()
        .map_err(|err| map_fs_error(&lock_path, "re-acquire shared bundle read lock", err))?;
    Ok(Some(healed_shared))
}

fn write_synced_intent_file(intent_path: &Path, payload: &[u8]) -> Result<(), SandboxError> {
    if let Ok(meta) = fs::symlink_metadata(intent_path) {
        validate_metadata_no_link(intent_path, &meta, false, false)?;
    }
    let mut opts = OpenOptions::new();
    opts.read(true).write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(intent_path)
        .map_err(|err| map_fs_error(intent_path, "open bundle promotion intent", err))?;
    file.write_all(payload)
        .and_then(|()| file.sync_all())
        .map_err(|err| map_fs_error(intent_path, "persist bundle promotion intent", err))
}

fn inspect_verified_bundle_dir(
    path: &Path,
    verifier: &BundleVerifier,
) -> Result<Option<bool>, SandboxError> {
    match fs::symlink_metadata(path) {
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
        Err(err) => Err(map_fs_error(path, "inspect bundle candidate directory", err)),
        Ok(meta) => {
            validate_metadata_no_link(path, &meta, true, false)?;
            Ok(Some(verify_installed_bundle_once(path, verifier).is_ok()))
        }
    }
}

fn recover_promotion_under_exclusive_lock(
    target_dir: &Path,
    intent_path: &Path,
    verifier: &BundleVerifier,
) -> Result<(), SandboxError> {
    let meta = match fs::symlink_metadata(intent_path) {
        Ok(m) => m,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(map_fs_error(intent_path, "inspect bundle promotion intent", err)),
    };
    validate_metadata_no_link(intent_path, &meta, false, false)?;

    let text = match fs::read_to_string(intent_path) {
        Ok(t) => t,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(map_fs_error(intent_path, "read bundle promotion intent", err)),
    };

    let mut staging_name: Option<String> = None;
    let mut backup_name: Option<String> = None;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("staging=") {
            staging_name = Some(rest.trim().to_owned());
        } else if let Some(rest) = line.strip_prefix("backup=") {
            backup_name = Some(rest.trim().to_owned());
        }
    }

    let Some((parent, _)) = bundle_parent_and_name(target_dir) else {
        return Err(SandboxError::Internal(
            "target bundle directory has no parent during recovery".to_owned(),
        ));
    };

    let staging_path = staging_name
        .as_deref()
        .filter(|n| is_safe_sibling_dir_name(n))
        .map(|n| parent.join(n));
    let backup_path = backup_name
        .as_deref()
        .filter(|n| is_safe_sibling_dir_name(n))
        .map(|n| parent.join(n));

    let target_state = inspect_verified_bundle_dir(target_dir, verifier)?;
    let staging_state = match staging_path.as_deref() {
        Some(sp) => inspect_verified_bundle_dir(sp, verifier)?,
        None => None,
    };
    let backup_state = match backup_path.as_deref() {
        Some(bp) => inspect_verified_bundle_dir(bp, verifier)?,
        None => None,
    };

    if target_state == Some(true) {
        if staging_state.is_some() {
            if let Some(ref sp) = staging_path {
                let _ = remove_dir_all_with_brief_retry(sp);
            }
        }
        if backup_state.is_some() {
            if let Some(ref bp) = backup_path {
                let _ = remove_dir_all_with_brief_retry(bp);
            }
        }
        let _ = fs::remove_file(intent_path);
        return Ok(());
    }

    if target_state == Some(false) {
        if staging_state != Some(true) && backup_state != Some(true) {
            return Err(SandboxError::PolicyViolation(format!(
                "interrupted bundle promotion at '{}' has unverified target and no verified backup or staging bundle",
                target_dir.display()
            )));
        }
        remove_dir_all_with_brief_retry(target_dir)
            .map_err(|e| map_fs_error(target_dir, "remove unverified target bundle directory", e))?;
    }

    // `target_dir` is now absent: promote `staging_path` only if verified; otherwise roll back verified `backup_path`.
    if staging_state == Some(true) {
        if let Some(ref sp) = staging_path {
            if rename_with_brief_retry(sp, target_dir).is_ok()
                && inspect_verified_bundle_dir(target_dir, verifier)? == Some(true)
            {
                if backup_state.is_some() {
                    if let Some(ref bp) = backup_path {
                        let _ = remove_dir_all_with_brief_retry(bp);
                    }
                }
                let _ = fs::remove_file(intent_path);
                return Ok(());
            }
        }
    }

    if backup_state == Some(true) {
        if let Some(ref bp) = backup_path {
            rename_with_brief_retry(bp, target_dir)
                .map_err(|e| map_fs_error(target_dir, "restore verified backup bundle", e))?;
            if inspect_verified_bundle_dir(target_dir, verifier)? == Some(true) {
                if staging_state.is_some() {
                    if let Some(ref sp) = staging_path {
                        let _ = remove_dir_all_with_brief_retry(sp);
                    }
                }
                let _ = fs::remove_file(intent_path);
                return Ok(());
            }
        }
    }

    Err(SandboxError::PolicyViolation(format!(
        "unable to recover a verified bundle at '{}' from interrupted promotion",
        target_dir.display()
    )))
}

fn is_safe_sibling_dir_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains('/')
        && !name.contains('\\')
        && !name.contains('\0')
}

fn rename_with_brief_retry(src: &Path, dst: &Path) -> io::Result<()> {
    let mut last_err = None;
    for attempt in 0..10 {
        match fs::rename(src, dst) {
            Ok(()) => return Ok(()),
            Err(err) if err.kind() == ErrorKind::PermissionDenied && attempt < 9 => {
                last_err = Some(err);
                thread::sleep(Duration::from_millis(10));
            }
            Err(err) => return Err(err),
        }
    }
    Err(last_err.unwrap_or_else(|| io::Error::other("rename retries exhausted")))
}

fn remove_dir_all_with_brief_retry(path: &Path) -> io::Result<()> {
    let mut last_err = None;
    for attempt in 0..10 {
        match fs::remove_dir_all(path) {
            Ok(()) => return Ok(()),
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(()),
            Err(err) if err.kind() == ErrorKind::PermissionDenied && attempt < 9 => {
                last_err = Some(err);
                thread::sleep(Duration::from_millis(10));
            }
            Err(err) => return Err(err),
        }
    }
    Err(last_err.unwrap_or_else(|| io::Error::other("remove_dir_all retries exhausted")))
}

struct TempDirGuard {
    path: Option<PathBuf>,
}

impl TempDirGuard {
    fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    fn disarm(&mut self) {
        self.path = None;
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = fs::remove_dir_all(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{public_key_from_secret, sign_manifest_hex};
    use crate::manifest::BundleFileEntry;
    use sandbox_core::GuestArch;
    use sha2::Sha256;
    use std::collections::BTreeMap;

    struct TestTempDir(PathBuf);

    impl TestTempDir {
        fn new(label: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "minipod-img-test-{label}-{}",
                next_temp_suffix()
            ));
            fs::create_dir_all(&dir).expect("create test temp dir");
            Self(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestTempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn write_signed_bundle(
        bundle_dir: &Path,
        bundle_id: &str,
        secret: &[u8; 32],
        files: &[(&str, ArtifactRole, &[u8])],
    ) -> BundleManifest {
        let mut entries = Vec::with_capacity(files.len());
        for (rel_path, role, bytes) in files {
            let dst = rel_path_to_host(bundle_dir, rel_path);
            if let Some(parent) = dst.parent() {
                fs::create_dir_all(parent).expect("create artifact parent dir");
            }
            fs::write(&dst, bytes).expect("write test bundle artifact");
            let digest: [u8; 32] = Sha256::digest(bytes).into();
            entries.push(BundleFileEntry {
                role: *role,
                rel_path: (*rel_path).to_owned(),
                sha256: digest,
                size_bytes: bytes.len() as u64,
            });
        }

        let mut source_pins = BTreeMap::new();
        source_pins.insert("alpine".to_owned(), "3.20.3".to_owned());
        source_pins.insert("qemu".to_owned(), "9.1.0".to_owned());

        let manifest = BundleManifest {
            format_version: 1,
            bundle_id: bundle_id.to_owned(),
            host_os: "any".to_owned(),
            guest_arch: GuestArch::X86_64,
            source_pins,
            entries,
        };
        let canonical = manifest.encode_canonical().expect("canonical encode");
        let sig_hex = sign_manifest_hex(secret, canonical.as_bytes());
        fs::write(bundle_dir.join(MANIFEST_FILENAME), canonical.as_bytes()).expect("write manifest");
        fs::write(
            bundle_dir.join(SIGNATURE_FILENAME),
            format!("{sig_hex}\n").as_bytes(),
        )
        .expect("write signature");
        manifest
    }

    #[test]
    fn atomic_bundle_install_upgrade_and_in_place_verification() {
        let tmp = TestTempDir::new("install-upgrade");
        let src_v1 = tmp.path().join("src-v1");
        let src_v2 = tmp.path().join("src-v2");
        let install_root = tmp.path().join("installed");
        fs::create_dir_all(&src_v1).unwrap();
        fs::create_dir_all(&src_v2).unwrap();

        let secret = [0x24u8; 32];
        let verifier = BundleVerifier::with_public_key(public_key_from_secret(&secret)).unwrap();

        write_signed_bundle(
            &src_v1,
            "minipod-mvp-x86_64",
            &secret,
            &[
                ("boot/vmlinuz", ArtifactRole::Kernel, b"kernel-v1-bytes"),
                ("boot/initrd.img", ArtifactRole::Initrd, b"initrd-v1"),
                (
                    "images/base.qcow2",
                    ArtifactRole::BaseRootfsQcow2,
                    b"qcow2-v1-payload",
                ),
                ("support/readme.txt", ArtifactRole::SupportFile, b"v1"),
            ],
        );

        let installed_v1 = install_bundle_atomic(&src_v1, &install_root, &verifier)
            .expect("initial atomic install must succeed");
        assert_eq!(installed_v1.root_dir(), install_root.join("minipod-mvp-x86_64"));
        assert_eq!(
            installed_v1.kernel_path(),
            installed_v1.root_dir().join("boot").join("vmlinuz")
        );
        assert_eq!(
            installed_v1.initrd_path(),
            installed_v1.root_dir().join("boot").join("initrd.img")
        );
        assert_eq!(
            installed_v1.base_rootfs_qcow2_path(),
            installed_v1.root_dir().join("images").join("base.qcow2")
        );
        assert_eq!(
            installed_v1.role_path(ArtifactRole::SupportFile),
            Some(installed_v1.root_dir().join("support").join("readme.txt"))
        );
        assert_eq!(installed_v1.role_path(ArtifactRole::Firmware), None);

        let verified_v1 = verify_installed_bundle(installed_v1.root_dir(), &verifier)
            .expect("verify_installed_bundle must pass for valid install");
        assert_eq!(verified_v1.manifest(), installed_v1.manifest());

        // Upgrade same bundle_id with different file layout and verify old files + temp dirs vanish.
        write_signed_bundle(
            &src_v2,
            "minipod-mvp-x86_64",
            &secret,
            &[
                ("boot/vmlinuz", ArtifactRole::Kernel, b"kernel-v2-new-bytes"),
                ("boot/initrd.img", ArtifactRole::Initrd, b"initrd-v2"),
                (
                    "images/base.qcow2",
                    ArtifactRole::BaseRootfsQcow2,
                    b"qcow2-v2-payload",
                ),
            ],
        );

        let installed_v2 = install_bundle_atomic(&src_v2, &install_root, &verifier)
            .expect("upgrade atomic swap must succeed");
        assert_eq!(
            fs::read(installed_v2.kernel_path()).unwrap(),
            b"kernel-v2-new-bytes"
        );
        assert!(!installed_v2
            .root_dir()
            .join("support")
            .join("readme.txt")
            .exists());
        verify_installed_bundle(installed_v2.root_dir(), &verifier).unwrap();

        let mut leftover_entries: Vec<String> = fs::read_dir(&install_root)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        leftover_entries.sort();
        assert_eq!(
            leftover_entries,
            vec![
                ".lock-minipod-mvp-x86_64".to_owned(),
                "minipod-mvp-x86_64".to_owned(),
            ]
        );
    }

    #[test]
    fn rejects_tampered_artifact_during_install_and_verify_without_leaving_staging() {
        let tmp = TestTempDir::new("tamper");
        let src = tmp.path().join("src");
        let install_root = tmp.path().join("installed");
        fs::create_dir_all(&src).unwrap();

        let secret = [0x33u8; 32];
        let verifier = BundleVerifier::with_public_key(public_key_from_secret(&secret)).unwrap();

        write_signed_bundle(
            &src,
            "tamper-bundle",
            &secret,
            &[
                ("boot/vmlinuz", ArtifactRole::Kernel, b"good-kernel"),
                ("boot/initrd.img", ArtifactRole::Initrd, b"good-initrd"),
                (
                    "images/base.qcow2",
                    ArtifactRole::BaseRootfsQcow2,
                    b"good-rootfs",
                ),
            ],
        );

        // Install a clean copy first so we can verify in-place tampering separately.
        let installed = install_bundle_atomic(&src, &install_root, &verifier).unwrap();

        // Tamper with installed artifact in place (same byte length, altered byte).
        fs::write(installed.kernel_path(), b"evil-kernel").unwrap();
        assert!(matches!(
            verify_installed_bundle(installed.root_dir(), &verifier),
            Err(SandboxError::PolicyViolation(_))
        ));

        // Tamper with source artifact before installing to a fresh root.
        let clean_root = tmp.path().join("clean-root");
        fs::write(src.join("boot").join("vmlinuz"), b"evil-kernel").unwrap();
        assert!(matches!(
            install_bundle_atomic(&src, &clean_root, &verifier),
            Err(SandboxError::PolicyViolation(_))
        ));
        assert!(!clean_root.join("tamper-bundle").exists());
        let staging_leftovers: Vec<_> = fs::read_dir(&clean_root)
            .unwrap()
            .filter_map(Result::ok)
            .collect();
        assert!(
            staging_leftovers.is_empty(),
            "failed install must leave zero staging dirs"
        );
    }

    #[test]
    fn rejects_rogue_extra_files_and_invalid_signature() {
        let tmp = TestTempDir::new("rogue");
        let src = tmp.path().join("src");
        let install_root = tmp.path().join("installed");
        fs::create_dir_all(&src).unwrap();

        let secret = [0x44u8; 32];
        let verifier = BundleVerifier::with_public_key(public_key_from_secret(&secret)).unwrap();

        write_signed_bundle(
            &src,
            "rogue-bundle",
            &secret,
            &[
                ("boot/vmlinuz", ArtifactRole::Kernel, b"k"),
                ("boot/initrd.img", ArtifactRole::Initrd, b"i"),
                ("images/base.qcow2", ArtifactRole::BaseRootfsQcow2, b"r"),
            ],
        );

        let installed = install_bundle_atomic(&src, &install_root, &verifier).unwrap();

        // Drop a rogue DLL at root and inside subdir in installed bundle.
        fs::write(installed.root_dir().join("version.dll"), b"trojan").unwrap();
        assert!(matches!(
            verify_installed_bundle(installed.root_dir(), &verifier),
            Err(SandboxError::PolicyViolation(_))
        ));
        fs::remove_file(installed.root_dir().join("version.dll")).unwrap();

        // Nested manifest.v1 must NOT bypass the root-only manifest exception.
        fs::write(installed.root_dir().join("boot").join(MANIFEST_FILENAME), b"fake").unwrap();
        assert!(matches!(
            verify_installed_bundle(installed.root_dir(), &verifier),
            Err(SandboxError::PolicyViolation(_))
        ));
        fs::remove_file(installed.root_dir().join("boot").join(MANIFEST_FILENAME)).unwrap();

        // Rogue file in source bundle blocks install.
        fs::write(src.join("version.dll"), b"sideload").unwrap();
        let install_root_2 = tmp.path().join("installed-2");
        assert!(matches!(
            install_bundle_atomic(&src, &install_root_2, &verifier),
            Err(SandboxError::PolicyViolation(_))
        ));
        fs::remove_file(src.join("version.dll")).unwrap();

        // Wrong verifying key fails signature verification.
        let wrong_verifier =
            BundleVerifier::with_public_key(public_key_from_secret(&[0x99u8; 32])).unwrap();
        assert!(matches!(
            verify_installed_bundle(installed.root_dir(), &wrong_verifier),
            Err(SandboxError::PolicyViolation(_))
        ));
        assert!(matches!(
            install_bundle_atomic(&src, &install_root_2, &wrong_verifier),
            Err(SandboxError::PolicyViolation(_))
        ));
    }

    #[test]
    fn windows_reparse_attribute_bitmask_is_detected() {
        assert!(has_windows_reparse_attribute(0x0400));
        assert!(has_windows_reparse_attribute(0x0410));
        assert!(!has_windows_reparse_attribute(0x0010));
        assert!(!has_windows_reparse_attribute(0x0020));
        assert!(!has_windows_reparse_attribute(0));
    }

    #[cfg(windows)]
    #[test]
    fn rejects_windows_ntfs_directory_junction_reparse_points() {
        use std::process::Command;

        let tmp = TestTempDir::new("win-junction");
        let src = tmp.path().join("src");
        let target = tmp.path().join("outside-target");
        let install_root = tmp.path().join("installed");
        fs::create_dir_all(&src).unwrap();
        fs::create_dir_all(&target).unwrap();
        fs::write(target.join("payload.bin"), b"outside").unwrap();

        let secret = [0x66u8; 32];
        let verifier = BundleVerifier::with_public_key(public_key_from_secret(&secret)).unwrap();
        write_signed_bundle(
            &src,
            "junction-bundle",
            &secret,
            &[
                ("boot/vmlinuz", ArtifactRole::Kernel, b"k"),
                ("boot/initrd.img", ArtifactRole::Initrd, b"i"),
                ("images/base.qcow2", ArtifactRole::BaseRootfsQcow2, b"r"),
            ],
        );

        let installed = install_bundle_atomic(&src, &install_root, &verifier).unwrap();

        // Create an NTFS junction at root-level and inside the bundle.
        let junction_inside = installed.root_dir().join("evil-junction");
        let status = Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&junction_inside)
            .arg(&target)
            .status()
            .expect("invoke cmd mklink /J");
        assert!(status.success(), "NTFS directory junction creation failed");

        assert!(matches!(
            verify_installed_bundle(installed.root_dir(), &verifier),
            Err(SandboxError::PolicyViolation(_))
        ));
        fs::remove_dir(&junction_inside).unwrap();

        // Also verify bundle root itself as a junction is rejected.
        let junction_root = tmp.path().join("bundle-junction");
        let status = Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&junction_root)
            .arg(installed.root_dir())
            .status()
            .expect("invoke cmd mklink /J for bundle root");
        assert!(status.success());

        assert!(matches!(
            verify_installed_bundle(&junction_root, &verifier),
            Err(SandboxError::PolicyViolation(_))
        ));
        fs::remove_dir(&junction_root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn rejects_unix_symlinks_and_hardlinks() {
        use std::os::unix::fs::symlink;

        let tmp = TestTempDir::new("unix-links");
        let src = tmp.path().join("src");
        let install_root = tmp.path().join("installed");
        fs::create_dir_all(&src).unwrap();

        let secret = [0x77u8; 32];
        let verifier = BundleVerifier::with_public_key(public_key_from_secret(&secret)).unwrap();
        write_signed_bundle(
            &src,
            "link-bundle",
            &secret,
            &[
                ("boot/vmlinuz", ArtifactRole::Kernel, b"kernel-bytes"),
                ("boot/initrd.img", ArtifactRole::Initrd, b"initrd-bytes"),
                (
                    "images/base.qcow2",
                    ArtifactRole::BaseRootfsQcow2,
                    b"rootfs-bytes",
                ),
            ],
        );

        let installed = install_bundle_atomic(&src, &install_root, &verifier).unwrap();

        // Symlinked root directory is rejected.
        let sym_root = tmp.path().join("sym-bundle");
        symlink(installed.root_dir(), &sym_root).unwrap();
        assert!(matches!(
            verify_installed_bundle(&sym_root, &verifier),
            Err(SandboxError::PolicyViolation(_))
        ));

        // Symlinked artifact inside bundle is rejected.
        let outside = tmp.path().join("outside");
        fs::write(&outside, b"kernel-bytes").unwrap();
        fs::remove_file(installed.kernel_path()).unwrap();
        symlink(&outside, installed.kernel_path()).unwrap();
        assert!(matches!(
            verify_installed_bundle(installed.root_dir(), &verifier),
            Err(SandboxError::PolicyViolation(_))
        ));

        // Hardlinked artifact inside bundle (nlink > 1) is rejected.
        fs::remove_file(installed.kernel_path()).unwrap();
        fs::hard_link(&outside, installed.kernel_path()).unwrap();
        assert!(matches!(
            verify_installed_bundle(installed.root_dir(), &verifier),
            Err(SandboxError::PolicyViolation(_))
        ));
    }

    #[test]
    fn interrupted_promotion_crash_recovers_and_concurrent_readers_never_observe_missing_bundle() {
        use std::sync::atomic::AtomicBool;
        use std::sync::Arc;

        let tmp = TestTempDir::new("promo-recovery-and-concurrency");
        let src_v1 = tmp.path().join("src-v1");
        let src_v2 = tmp.path().join("src-v2");
        let install_root = tmp.path().join("installed");
        fs::create_dir_all(&src_v1).unwrap();
        fs::create_dir_all(&src_v2).unwrap();

        let secret = [0x66u8; 32];
        let verifier = BundleVerifier::with_public_key(public_key_from_secret(&secret)).unwrap();

        write_signed_bundle(
            &src_v1,
            "minipod-rc-test",
            &secret,
            &[
                ("boot/vmlinuz", ArtifactRole::Kernel, b"kernel-v1"),
                ("boot/initrd.img", ArtifactRole::Initrd, b"initrd-v1"),
                ("images/base.qcow2", ArtifactRole::BaseRootfsQcow2, b"qcow2-v1"),
            ],
        );
        write_signed_bundle(
            &src_v2,
            "minipod-rc-test",
            &secret,
            &[
                ("boot/vmlinuz", ArtifactRole::Kernel, b"kernel-v2-upgraded"),
                ("boot/initrd.img", ArtifactRole::Initrd, b"initrd-v2-upgraded"),
                ("images/base.qcow2", ArtifactRole::BaseRootfsQcow2, b"qcow2-v2-upgraded"),
            ],
        );

        let installed = install_bundle_atomic(&src_v1, &install_root, &verifier).unwrap();
        let target_dir = installed.root_dir().to_path_buf();

        // 1. Simulate process crash right after renaming `target_dir` -> `.backup-*` before promoting `.staging-*`.
        let backup_dir = install_root.join(".backup-minipod-rc-test-crashed");
        let staging_dir = install_root.join(".staging-minipod-rc-test-crashed");
        fs::rename(&target_dir, &backup_dir).unwrap();
        // Copy valid v2 into staging_dir.
        write_signed_bundle(
            &staging_dir,
            "minipod-rc-test",
            &secret,
            &[
                ("boot/vmlinuz", ArtifactRole::Kernel, b"kernel-v2-upgraded"),
                ("boot/initrd.img", ArtifactRole::Initrd, b"initrd-v2-upgraded"),
                ("images/base.qcow2", ArtifactRole::BaseRootfsQcow2, b"qcow2-v2-upgraded"),
            ],
        );
        fs::write(
            install_root.join(".promote-minipod-rc-test.v1"),
            "staging=.staging-minipod-rc-test-crashed\nbackup=.backup-minipod-rc-test-crashed\n",
        )
        .unwrap();
        assert!(!target_dir.exists());

        let recovered = verify_installed_bundle(&target_dir, &verifier)
            .expect("verify_installed_bundle must recover crashed promotion automatically");
        assert_eq!(fs::read(recovered.kernel_path()).unwrap(), b"kernel-v2-upgraded");
        assert!(!backup_dir.exists());
        assert!(!staging_dir.exists());
        assert!(!install_root.join(".promote-minipod-rc-test.v1").exists());

        // 2. Concurrent readers loop during repeated live upgrades without ever observing NotFound.
        let done = Arc::new(AtomicBool::new(false));
        let mut readers = Vec::new();
        for _ in 0..3 {
            let done_r = Arc::clone(&done);
            let dir_r = target_dir.clone();
            let ver_r = verifier.clone();
            readers.push(thread::spawn(move || {
                while !done_r.load(Ordering::Acquire) {
                    verify_installed_bundle(&dir_r, &ver_r)
                        .expect("concurrent reader must never observe missing or partial bundle");
                    thread::sleep(Duration::from_millis(5));
                }
            }));
        }

        for idx in 0..8 {
            let src = if idx % 2 == 0 { &src_v1 } else { &src_v2 };
            install_bundle_atomic(src, &install_root, &verifier)
                .expect("live bundle upgrade must succeed");
        }
        done.store(true, Ordering::Release);
        for handle in readers {
            handle.join().expect("reader thread panicked");
        }
    }

    #[test]
    fn read_guard_locks_preexisting_unpromoted_bundle_and_blocks_concurrent_swap() {
        let temp = TestTempDir::new("preexisting-lock");
        let install_root = temp.path().join("bundles");
        fs::create_dir_all(&install_root).expect("create install root");

        let secret = [17u8; 32];
        let verifier =
            BundleVerifier::with_public_key(public_key_from_secret(&secret)).expect("verifier");
        let bundle_id = "bundle-preexisting";
        let target_dir = install_root.join(bundle_id);

        let files_v1 = [
            ("guest/vmlinuz", ArtifactRole::Kernel, b"kernel-v1".as_slice()),
            (
                "guest/initrd.img",
                ArtifactRole::Initrd,
                b"initrd-v1".as_slice(),
            ),
            (
                "guest/base.qcow2",
                ArtifactRole::BaseRootfsQcow2,
                b"qcow2-v1".as_slice(),
            ),
            (
                "guest/tiny-init",
                ArtifactRole::TinyInit,
                b"init-v1".as_slice(),
            ),
            (
                "guest/sandbox-agent",
                ArtifactRole::GuestAgent,
                b"agent-v1".as_slice(),
            ),
        ];
        write_signed_bundle(&target_dir, bundle_id, &secret, &files_v1);

        let src_v2 = temp.path().join("src-v2");
        let files_v2 = [
            ("guest/vmlinuz", ArtifactRole::Kernel, b"kernel-v2".as_slice()),
            (
                "guest/initrd.img",
                ArtifactRole::Initrd,
                b"initrd-v2".as_slice(),
            ),
            (
                "guest/base.qcow2",
                ArtifactRole::BaseRootfsQcow2,
                b"qcow2-v2".as_slice(),
            ),
            (
                "guest/tiny-init",
                ArtifactRole::TinyInit,
                b"init-v2".as_slice(),
            ),
            (
                "guest/sandbox-agent",
                ArtifactRole::GuestAgent,
                b"agent-v2".as_slice(),
            ),
        ];
        write_signed_bundle(&src_v2, bundle_id, &secret, &files_v2);

        let guard = with_verified_installed_bundle_read_locked(
            &target_dir,
            &verifier,
            |_installed, read_guard| Ok(read_guard),
        )
        .expect("verified preexisting bundle")
        .expect("read guard must be created even before any install promotion");

        let (tx, rx) = std::sync::mpsc::channel();
        let swap_src = src_v2.clone();
        let swap_root = install_root.clone();
        let swap_verifier = verifier.clone();
        let swap_thread = std::thread::spawn(move || {
            let res = install_bundle_atomic(&swap_src, &swap_root, &swap_verifier);
            let _ = tx.send(res);
        });

        assert!(
            matches!(
                rx.recv_timeout(std::time::Duration::from_millis(200)),
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            ),
            "concurrent bundle swap must block while shared read guard is held"
        );
        assert_eq!(
            fs::read(target_dir.join("guest/vmlinuz")).expect("read v1 kernel"),
            b"kernel-v1"
        );

        drop(guard);

        let swap_res = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("swap finishes after read guard drops");
        swap_res.expect("bundle upgrade succeeds after guard release");
        swap_thread.join().expect("swap thread joins");
        assert_eq!(
            fs::read(target_dir.join("guest/vmlinuz")).expect("read v2 kernel"),
            b"kernel-v2"
        );
    }

    #[test]
    fn corrupt_staging_or_target_recovery_never_deletes_backup_before_verification() {
        let tmp = TestTempDir::new("corrupt-staging-recovery");
        let src_v1 = tmp.path().join("src-v1");
        let install_root = tmp.path().join("installed");
        fs::create_dir_all(&src_v1).unwrap();

        let secret = [0x51u8; 32];
        let verifier = BundleVerifier::with_public_key(public_key_from_secret(&secret)).unwrap();
        let bundle_id = "minipod-safe-recover";
        write_signed_bundle(
            &src_v1,
            bundle_id,
            &secret,
            &[
                ("boot/vmlinuz", ArtifactRole::Kernel, b"kernel-v1-good"),
                ("boot/initrd.img", ArtifactRole::Initrd, b"initrd-v1-good"),
                (
                    "images/base.qcow2",
                    ArtifactRole::BaseRootfsQcow2,
                    b"qcow2-v1-good",
                ),
            ],
        );
        let installed = install_bundle_atomic(&src_v1, &install_root, &verifier).unwrap();
        let target_dir = installed.root_dir().to_path_buf();

        // Case 1: Crash after `target_dir -> backup_dir` when `staging_dir` is incomplete/tampered.
        let backup_dir = install_root.join(".backup-minipod-safe-recover-1");
        let staging_dir = install_root.join(".staging-minipod-safe-recover-1");
        fs::rename(&target_dir, &backup_dir).unwrap();
        write_signed_bundle(
            &staging_dir,
            bundle_id,
            &secret,
            &[
                ("boot/vmlinuz", ArtifactRole::Kernel, b"kernel-v2"),
                ("boot/initrd.img", ArtifactRole::Initrd, b"initrd-v2"),
                ("images/base.qcow2", ArtifactRole::BaseRootfsQcow2, b"qcow2-v2"),
            ],
        );
        // Corrupt staging kernel so SHA-256 verification fails.
        fs::write(staging_dir.join("boot/vmlinuz"), b"corrupt-staging!").unwrap();
        fs::write(
            install_root.join(".promote-minipod-safe-recover.v1"),
            "staging=.staging-minipod-safe-recover-1\nbackup=.backup-minipod-safe-recover-1\n",
        )
        .unwrap();

        let recovered = verify_installed_bundle(&target_dir, &verifier)
            .expect("recovery must roll back verified backup instead of promoting corrupt staging");
        assert_eq!(
            fs::read(recovered.kernel_path()).unwrap(),
            b"kernel-v1-good"
        );
        assert!(!backup_dir.exists());
        assert!(!staging_dir.exists());
        assert!(!install_root.join(".promote-minipod-safe-recover.v1").exists());

        // Case 2: Both staging and target are missing/corrupt AND backup is ALSO corrupt -> must fail
        // without deleting backup so forensic state is preserved.
        let bad_backup = install_root.join(".backup-minipod-safe-recover-2");
        fs::rename(&target_dir, &bad_backup).unwrap();
        fs::write(bad_backup.join("boot/vmlinuz"), b"also-corrupted").unwrap();
        fs::write(
            install_root.join(".promote-minipod-safe-recover.v1"),
            "staging=.staging-missing\nbackup=.backup-minipod-safe-recover-2\n",
        )
        .unwrap();
        assert!(matches!(
            verify_installed_bundle(&target_dir, &verifier),
            Err(SandboxError::PolicyViolation(_))
        ));
        assert!(
            bad_backup.exists(),
            "unrecoverable backup must not be deleted when no verified bundle exists"
        );
    }

    #[test]
    fn install_bundle_atomic_rejects_incompatible_host_os() {
        let tmp = TestTempDir::new("incompatible-host-os");
        let src = tmp.path().join("src");
        let install_root = tmp.path().join("installed");
        fs::create_dir_all(&src).unwrap();

        let secret = [0x52u8; 32];
        let verifier = BundleVerifier::with_public_key(public_key_from_secret(&secret)).unwrap();
        write_signed_bundle(
            &src,
            "wrong-os-bundle",
            &secret,
            &[
                ("boot/vmlinuz", ArtifactRole::Kernel, b"k"),
                ("boot/initrd.img", ArtifactRole::Initrd, b"i"),
                ("images/base.qcow2", ArtifactRole::BaseRootfsQcow2, b"r"),
            ],
        );

        let mismatched_os = if std::env::consts::OS == "linux" {
            "windows"
        } else {
            "linux"
        };
        let manifest_text = fs::read_to_string(src.join(MANIFEST_FILENAME))
            .unwrap()
            .replace("host_os=any\n", &format!("host_os={mismatched_os}\n"));
        let sig_hex = sign_manifest_hex(&secret, manifest_text.as_bytes());
        fs::write(src.join(MANIFEST_FILENAME), manifest_text.as_bytes()).unwrap();
        fs::write(src.join(SIGNATURE_FILENAME), format!("{sig_hex}\n").as_bytes()).unwrap();

        assert!(matches!(
            install_bundle_atomic(&src, &install_root, &verifier),
            Err(SandboxError::InvalidSpec(_))
        ));
    }

    #[test]
    fn exclusive_bundle_lock_times_out_when_read_guard_is_held() {
        let tmp = TestTempDir::new("exclusive-lock-timeout");
        let target_dir = tmp.path().join("bundles").join("locked-bundle");
        fs::create_dir_all(target_dir.parent().unwrap()).unwrap();

        let secret = [0x53u8; 32];
        let verifier = BundleVerifier::with_public_key(public_key_from_secret(&secret)).unwrap();
        write_signed_bundle(
            &target_dir,
            "locked-bundle",
            &secret,
            &[
                ("boot/vmlinuz", ArtifactRole::Kernel, b"k"),
                ("boot/initrd.img", ArtifactRole::Initrd, b"i"),
                ("images/base.qcow2", ArtifactRole::BaseRootfsQcow2, b"r"),
            ],
        );

        let guard = with_verified_installed_bundle_read_locked(
            &target_dir,
            &verifier,
            |_installed, read_guard| Ok(read_guard),
        )
        .unwrap()
        .expect("read guard acquired");

        let (lock_path, _) = bundle_lock_and_intent_paths(&target_dir).unwrap();
        let err = open_bundle_lock_exclusive_timeout(&lock_path, Duration::from_millis(40))
            .expect_err("exclusive lock must fail with bounded timeout while read guard is held");
        assert!(matches!(err, SandboxError::AdmissionRejected(_)), "got {err:?}");

        drop(guard);
        open_bundle_lock_exclusive_timeout(&lock_path, Duration::from_millis(100))
            .expect("exclusive lock succeeds after read guard drops");

        let (rel_lock, rel_intent) = bundle_lock_and_intent_paths(Path::new("my-bundle"))
            .expect("single-component relative bundle path must resolve lock and intent paths");
        assert!(rel_lock.ends_with(".lock-my-bundle"));
        assert!(rel_intent.ends_with(".promote-my-bundle.v1"));
    }
}
