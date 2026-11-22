//! QCOW2 header inspection, QEMU-safe host path cleaning, and atomic CoW overlay creation.

use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{self, ErrorKind, Read};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use sandbox_core::SandboxError;

use crate::installer::{
    check_dir_path, check_regular_file_path, map_fs_error, next_temp_suffix,
    validate_metadata_no_link,
};

const QCOW2_MAGIC: u32 = 0x5146_49fb; // "QFI\xfb"
const QCOW2_V2_MIN_HEADER_BYTES: usize = 72;
const QEMU_IMG_CREATE_TIMEOUT: Duration = Duration::from_secs(30);

/// Exit status and captured output from an external `qemu-img` invocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HelperCommandOutput {
    pub success: bool,
    pub status_label: String,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Driven callback executing `qemu-img` inside OS process confinement (e.g. Win32 Job Object +
/// handle whitelist + timeout) injected by the outer composition root.
pub type HelperCommandRunner =
    Arc<dyn Fn(&Path, &[OsString], Duration) -> Result<HelperCommandOutput, SandboxError> + Send + Sync>;

/// Parsed fields from the big-endian header of a QCOW2 disk image.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Qcow2HeaderInfo {
    pub version: u32,
    pub backing_file_offset: u64,
    pub backing_file_size: u32,
    pub virtual_size_bytes: u64,
}

/// Validates that `path` is a non-symlink/non-reparse regular file, reads its 72-byte QCOW2
/// header, and returns its validated [`Qcow2HeaderInfo`].
pub fn inspect_qcow2_header(path: &Path) -> Result<Qcow2HeaderInfo, SandboxError> {
    check_regular_file_path(path, false)?;

    let mut file = File::open(path).map_err(|err| map_fs_error(path, "open qcow2 image", err))?;
    let open_meta = file
        .metadata()
        .map_err(|err| map_fs_error(path, "inspect open qcow2 image", err))?;
    validate_metadata_no_link(path, &open_meta, false, false)?;

    let mut header = [0u8; QCOW2_V2_MIN_HEADER_BYTES];
    file.read_exact(&mut header).map_err(|err| {
        if err.kind() == ErrorKind::UnexpectedEof {
            SandboxError::InvalidSpec(format!(
                "qcow2 header at '{}' is truncated (fewer than {} bytes)",
                path.display(),
                QCOW2_V2_MIN_HEADER_BYTES
            ))
        } else {
            map_fs_error(path, "read qcow2 header", err)
        }
    })?;

    let magic = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
    if magic != QCOW2_MAGIC {
        return Err(SandboxError::InvalidSpec(format!(
            "invalid qcow2 magic 0x{magic:08x} at '{}' (expected 0x{QCOW2_MAGIC:08x})",
            path.display()
        )));
    }

    let version = u32::from_be_bytes([header[4], header[5], header[6], header[7]]);
    if !matches!(version, 2 | 3) {
        return Err(SandboxError::InvalidSpec(format!(
            "unsupported qcow2 version {version} at '{}' (expected 2 or 3)",
            path.display()
        )));
    }

    let backing_file_offset = u64::from_be_bytes([
        header[8], header[9], header[10], header[11], header[12], header[13], header[14],
        header[15],
    ]);
    let backing_file_size = u32::from_be_bytes([header[16], header[17], header[18], header[19]]);
    let virtual_size_bytes = u64::from_be_bytes([
        header[24], header[25], header[26], header[27], header[28], header[29], header[30],
        header[31],
    ]);

    Ok(Qcow2HeaderInfo {
        version,
        backing_file_offset,
        backing_file_size,
        virtual_size_bytes,
    })
}

/// Resolves an existing or non-existing host path into a clean UTF-8 path suitable for `qemu-img`
/// and QEMU CLI flags: strips Windows `\\?\` / `\\?\UNC\` verbatim prefixes and rejects commas,
/// NUL bytes, and CR/LF characters.
pub fn clean_qemu_host_path(path: &Path) -> Result<PathBuf, SandboxError> {
    if path.as_os_str().is_empty() {
        return Err(SandboxError::InvalidSpec(
            "QEMU host path must not be empty".to_owned(),
        ));
    }
    if let Some(raw_str) = path.to_str() {
        reject_qemu_forbidden_chars(raw_str)?;
    } else {
        return Err(SandboxError::InvalidSpec(format!(
            "QEMU host path '{}' is not valid UTF-8",
            path.display()
        )));
    }

    let resolved = resolve_existing_or_parent_path(path)?;
    let resolved_str = resolved.to_str().ok_or_else(|| {
        SandboxError::InvalidSpec(format!(
            "resolved QEMU host path '{}' is not valid UTF-8",
            resolved.display()
        ))
    })?;
    let stripped = strip_windows_verbatim_prefix(resolved_str);
    reject_qemu_forbidden_chars(&stripped)?;

    if stripped.is_empty() {
        return Err(SandboxError::InvalidSpec(
            "cleaned QEMU host path resolved to empty string".to_owned(),
        ));
    }

    Ok(PathBuf::from(stripped))
}

/// Atomically creates a Copy-on-Write `qcow2` overlay backed by `base_qcow2` via `qemu-img`.
///
/// Rejects base images that already carry a backing file, validates requested `virtual_disk_mb`
/// against the base image virtual size, creates a sibling temp file, validates the generated
/// QCOW2 header, and promotes it atomically to `overlay_path`.
pub fn create_qcow2_overlay_atomic(
    qemu_img_bin: &Path,
    base_qcow2: &Path,
    overlay_path: &Path,
    virtual_disk_mb: Option<u32>,
) -> Result<Qcow2HeaderInfo, SandboxError> {
    create_qcow2_overlay_atomic_with_runner(
        qemu_img_bin,
        base_qcow2,
        overlay_path,
        virtual_disk_mb,
        None,
    )
}

/// Same as [`create_qcow2_overlay_atomic`], executing `qemu-img` through an optional confined
/// [`HelperCommandRunner`] injected by the composition root.
pub fn create_qcow2_overlay_atomic_with_runner(
    qemu_img_bin: &Path,
    base_qcow2: &Path,
    overlay_path: &Path,
    virtual_disk_mb: Option<u32>,
    runner: Option<&HelperCommandRunner>,
) -> Result<Qcow2HeaderInfo, SandboxError> {
    let base_info = inspect_qcow2_header(base_qcow2)?;
    if base_info.backing_file_offset != 0 || base_info.backing_file_size != 0 {
        return Err(SandboxError::PolicyViolation(format!(
            "refusing to create overlay on '{}' because it already has a backing file (chained backing files are forbidden)",
            base_qcow2.display()
        )));
    }

    if let Some(mb) = virtual_disk_mb {
        let requested_bytes = (mb as u64).checked_mul(1024 * 1024).ok_or_else(|| {
            SandboxError::InvalidSpec(format!("virtual_disk_mb {mb} overflows u64 bytes"))
        })?;
        if mb == 0 || requested_bytes < base_info.virtual_size_bytes {
            return Err(SandboxError::InvalidSpec(format!(
                "virtual_disk_mb ({mb} MiB = {requested_bytes} bytes) cannot be smaller than base image virtual size ({} bytes)",
                base_info.virtual_size_bytes
            )));
        }
    }

    let overlay_file_name = overlay_path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| {
            SandboxError::InvalidSpec(format!(
                "overlay path '{}' must end with a valid UTF-8 filename",
                overlay_path.display()
            ))
        })?;

    let overlay_parent = overlay_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    check_dir_path(overlay_parent)?;

    match fs::symlink_metadata(overlay_path) {
        Ok(existing_meta) => validate_metadata_no_link(overlay_path, &existing_meta, false, false)?,
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => {
            return Err(map_fs_error(
                overlay_path,
                "inspect target overlay path",
                err,
            ));
        }
    }

    let clean_base = clean_qemu_host_path(base_qcow2)?;
    let clean_overlay = clean_qemu_host_path(overlay_path)?;
    let clean_parent = clean_overlay.parent().ok_or_else(|| {
        SandboxError::InvalidSpec(format!(
            "cleaned overlay path '{}' has no parent directory",
            clean_overlay.display()
        ))
    })?;

    let tmp_overlay = clean_parent.join(format!(".{overlay_file_name}.tmp-{}", next_temp_suffix()));
    let clean_tmp_overlay = clean_qemu_host_path(&tmp_overlay)?;
    let mut tmp_guard = TempFileGuard::new(clean_tmp_overlay.clone());

    let mut args: Vec<OsString> = vec![
        OsString::from("create"),
        OsString::from("-f"),
        OsString::from("qcow2"),
        OsString::from("-F"),
        OsString::from("qcow2"),
        OsString::from("-b"),
        clean_base.as_os_str().to_os_string(),
        clean_tmp_overlay.as_os_str().to_os_string(),
    ];
    if let Some(mb) = virtual_disk_mb {
        args.push(OsString::from(format!("{mb}M")));
    }

    let output = match runner {
        Some(run) => run(qemu_img_bin, &args, QEMU_IMG_CREATE_TIMEOUT)?,
        None => {
            let raw = Command::new(qemu_img_bin)
                .args(&args)
                .output()
                .map_err(|err| classify_qemu_img_error(qemu_img_bin, &err))?;
            HelperCommandOutput {
                success: raw.status.success(),
                status_label: raw.status.to_string(),
                stdout: raw.stdout,
                stderr: raw.stderr,
            }
        }
    };
    if !output.success {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        return Err(SandboxError::Internal(format!(
            "qemu-img create failed with status {} (stderr='{}', stdout='{}')",
            output.status_label,
            stderr.trim(),
            stdout.trim()
        )));
    }

    let created_info = inspect_qcow2_header(&clean_tmp_overlay)?;
    if created_info.backing_file_offset == 0 || created_info.backing_file_size == 0 {
        return Err(SandboxError::PolicyViolation(format!(
            "created overlay '{}' has no backing file header after qemu-img create",
            clean_tmp_overlay.display()
        )));
    }

    fs::rename(&clean_tmp_overlay, &clean_overlay).map_err(|err| {
        map_fs_error(&clean_overlay, "promote temporary qcow2 overlay", err)
    })?;
    tmp_guard.disarm();

    Ok(created_info)
}

fn resolve_existing_or_parent_path(path: &Path) -> Result<PathBuf, SandboxError> {
    if let Ok(canon) = fs::canonicalize(path) {
        return Ok(canon);
    }

    if let Some(file_name) = path.file_name() {
        match path.parent().filter(|p| !p.as_os_str().is_empty()) {
            Some(parent) => {
                if let Ok(canon_parent) = fs::canonicalize(parent) {
                    return Ok(canon_parent.join(file_name));
                }
            }
            None => {
                if let Ok(canon_cwd) = fs::canonicalize(".") {
                    return Ok(canon_cwd.join(file_name));
                }
            }
        }
    }

    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        let cwd = std::env::current_dir().map_err(|err| {
            SandboxError::Internal(format!(
                "failed to determine current working directory while cleaning '{}': {err}",
                path.display()
            ))
        })?;
        Ok(cwd.join(path))
    }
}

fn strip_windows_verbatim_prefix(raw: &str) -> String {
    if let Some(rest) = raw.strip_prefix(r"\\?\") {
        if let Some(unc) = rest
            .strip_prefix(r"UNC\")
            .or_else(|| rest.strip_prefix(r"unc\"))
        {
            return format!(r"\\{unc}");
        }
        return rest.to_owned();
    }
    raw.to_owned()
}

fn reject_qemu_forbidden_chars(raw: &str) -> Result<(), SandboxError> {
    for ch in [',', '\0', '\r', '\n'] {
        if raw.contains(ch) {
            return Err(SandboxError::InvalidSpec(format!(
                "QEMU host path '{}' contains forbidden character {:?}",
                raw, ch
            )));
        }
    }
    Ok(())
}

fn classify_qemu_img_error(qemu_img_bin: &Path, err: &io::Error) -> SandboxError {
    let path = qemu_img_bin.display();
    match err.raw_os_error() {
        Some(code @ (1260 | 786)) => SandboxError::BinaryExecutionBlocked(format!(
            "qemu-img binary '{path}' was blocked by Windows AppLocker / software restriction policy (OS error {code}): {err}"
        )),
        Some(code @ (4551 | 4556..=4559 | 4580..=4582)) => SandboxError::BinaryExecutionBlocked(format!(
            "qemu-img binary '{path}' was blocked by Windows Defender Application Control / Smart App Control (OS error {code}): {err}"
        )),
        Some(code @ (5 | 13 | 1)) => SandboxError::BinaryExecutionBlocked(format!(
            "qemu-img binary '{path}' execution was denied by OS security or permission policy (OS error {code}): {err}"
        )),
        _ => match err.kind() {
            ErrorKind::PermissionDenied => SandboxError::BinaryExecutionBlocked(format!(
                "qemu-img binary '{path}' execution was blocked by OS permission policy: {err}"
            )),
            ErrorKind::NotFound => SandboxError::NotFound(format!(
                "qemu-img binary '{path}' was not found: {err}"
            )),
            _ => SandboxError::Internal(format!(
                "failed to launch qemu-img binary '{path}': {err}"
            )),
        },
    }
}

struct TempFileGuard {
    path: Option<PathBuf>,
}

impl TempFileGuard {
    fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    fn disarm(&mut self) {
        self.path = None;
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = fs::remove_file(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TestTempDir(PathBuf);

    impl TestTempDir {
        fn new(label: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "minipod-qcow2-test-{label}-{}",
                next_temp_suffix()
            ));
            fs::create_dir_all(&dir).expect("create qcow2 test temp dir");
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

    fn synthetic_qcow2_header(
        magic: u32,
        version: u32,
        backing_offset: u64,
        backing_size: u32,
        virtual_size: u64,
        total_len: usize,
    ) -> Vec<u8> {
        let mut buf = vec![0u8; total_len];
        if total_len >= 4 {
            buf[0..4].copy_from_slice(&magic.to_be_bytes());
        }
        if total_len >= 8 {
            buf[4..8].copy_from_slice(&version.to_be_bytes());
        }
        if total_len >= 16 {
            buf[8..16].copy_from_slice(&backing_offset.to_be_bytes());
        }
        if total_len >= 20 {
            buf[16..20].copy_from_slice(&backing_size.to_be_bytes());
        }
        if total_len >= 32 {
            buf[24..32].copy_from_slice(&virtual_size.to_be_bytes());
        }
        buf
    }

    fn find_qemu_img_binary() -> Option<PathBuf> {
        let exe_name = if cfg!(windows) {
            "qemu-img.exe"
        } else {
            "qemu-img"
        };

        if let Some(path_var) = std::env::var_os("PATH") {
            for dir in std::env::split_paths(&path_var) {
                if !dir.is_absolute() {
                    continue;
                }
                let candidate = dir.join(exe_name);
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
        }

        #[cfg(windows)]
        {
            if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") {
                let candidate = PathBuf::from(local_app_data)
                    .join("Programs")
                    .join("qemu")
                    .join(exe_name);
                if candidate.is_file() {
                    return Some(candidate);
                }
            }
            let program_files = PathBuf::from(r"C:\Program Files\qemu").join(exe_name);
            if program_files.is_file() {
                return Some(program_files);
            }
        }

        None
    }

    #[test]
    fn inspect_qcow2_header_parses_v2_v3_and_rejects_bad_magic_version_or_truncated() {
        let tmp = TestTempDir::new("header");

        let v2_path = tmp.path().join("v2.qcow2");
        fs::write(
            &v2_path,
            synthetic_qcow2_header(QCOW2_MAGIC, 2, 104, 21, 128 * 1024 * 1024, 72),
        )
        .unwrap();
        let v2 = inspect_qcow2_header(&v2_path).expect("valid v2 header");
        assert_eq!(
            v2,
            Qcow2HeaderInfo {
                version: 2,
                backing_file_offset: 104,
                backing_file_size: 21,
                virtual_size_bytes: 128 * 1024 * 1024,
            }
        );

        let v3_path = tmp.path().join("v3.qcow2");
        fs::write(
            &v3_path,
            synthetic_qcow2_header(QCOW2_MAGIC, 3, 0, 0, 256 * 1024 * 1024, 104),
        )
        .unwrap();
        let v3 = inspect_qcow2_header(&v3_path).expect("valid v3 header");
        assert_eq!(
            v3,
            Qcow2HeaderInfo {
                version: 3,
                backing_file_offset: 0,
                backing_file_size: 0,
                virtual_size_bytes: 256 * 1024 * 1024,
            }
        );

        let bad_magic = tmp.path().join("bad-magic.qcow2");
        fs::write(
            &bad_magic,
            synthetic_qcow2_header(0xdead_beef, 3, 0, 0, 64 * 1024 * 1024, 72),
        )
        .unwrap();
        assert!(matches!(
            inspect_qcow2_header(&bad_magic),
            Err(SandboxError::InvalidSpec(_))
        ));

        for bad_ver in [1u32, 4u32] {
            let bad_ver_path = tmp.path().join(format!("bad-v{bad_ver}.qcow2"));
            fs::write(
                &bad_ver_path,
                synthetic_qcow2_header(QCOW2_MAGIC, bad_ver, 0, 0, 64 * 1024 * 1024, 72),
            )
            .unwrap();
            assert!(matches!(
                inspect_qcow2_header(&bad_ver_path),
                Err(SandboxError::InvalidSpec(_))
            ));
        }

        let truncated = tmp.path().join("truncated.qcow2");
        fs::write(
            &truncated,
            synthetic_qcow2_header(QCOW2_MAGIC, 2, 0, 0, 64 * 1024 * 1024, 71),
        )
        .unwrap();
        assert!(matches!(
            inspect_qcow2_header(&truncated),
            Err(SandboxError::InvalidSpec(_))
        ));

        // Directory is rejected as non-regular file.
        assert!(matches!(
            inspect_qcow2_header(tmp.path()),
            Err(SandboxError::PolicyViolation(_))
        ));
    }

    #[test]
    fn clean_qemu_host_path_strips_verbatim_prefixes_and_rejects_commas() {
        assert_eq!(
            strip_windows_verbatim_prefix(r"\\?\C:\Users\Gem\base.qcow2"),
            r"C:\Users\Gem\base.qcow2"
        );
        assert_eq!(
            strip_windows_verbatim_prefix(r"\\?\UNC\filesrv\share\base.qcow2"),
            r"\\filesrv\share\base.qcow2"
        );
        assert_eq!(
            strip_windows_verbatim_prefix("/var/lib/minipod/base.qcow2"),
            "/var/lib/minipod/base.qcow2"
        );

        let tmp = TestTempDir::new("clean-path");
        let non_existing = tmp.path().join("overlay-new.qcow2");
        let cleaned = clean_qemu_host_path(&non_existing).expect("clean non-existing path");
        let cleaned_str = cleaned.to_str().unwrap();
        assert!(!cleaned_str.starts_with(r"\\?\"));
        assert!(cleaned.ends_with("overlay-new.qcow2"));

        for bad in [
            Path::new(""),
            Path::new("bad,comma.qcow2"),
            Path::new("bad\nnewline.qcow2"),
            Path::new("bad\rreturn.qcow2"),
        ] {
            assert!(
                matches!(clean_qemu_host_path(bad), Err(SandboxError::InvalidSpec(_))),
                "expected InvalidSpec for path {:?}",
                bad
            );
        }
    }

    #[test]
    fn classify_qemu_img_error_maps_os_blocks_and_not_found() {
        let bin = Path::new("qemu-img");

        let applocker = classify_qemu_img_error(bin, &io::Error::from_raw_os_error(1260));
        assert!(matches!(applocker, SandboxError::BinaryExecutionBlocked(_)));
        let applocker_no_ui = classify_qemu_img_error(bin, &io::Error::from_raw_os_error(786));
        assert!(matches!(applocker_no_ui, SandboxError::BinaryExecutionBlocked(_)));

        let wdac = classify_qemu_img_error(bin, &io::Error::from_raw_os_error(4551));
        assert!(matches!(wdac, SandboxError::BinaryExecutionBlocked(_)));
        let sac = classify_qemu_img_error(bin, &io::Error::from_raw_os_error(4556));
        assert!(matches!(sac, SandboxError::BinaryExecutionBlocked(_)));

        for code in [5, 13, 1] {
            let denied = classify_qemu_img_error(bin, &io::Error::from_raw_os_error(code));
            assert!(matches!(denied, SandboxError::BinaryExecutionBlocked(_)));
        }

        let perm = classify_qemu_img_error(bin, &io::Error::new(ErrorKind::PermissionDenied, "x"));
        assert!(matches!(perm, SandboxError::BinaryExecutionBlocked(_)));

        let missing = classify_qemu_img_error(bin, &io::Error::new(ErrorKind::NotFound, "missing"));
        assert!(matches!(missing, SandboxError::NotFound(_)));
    }

    #[test]
    fn create_qcow2_overlay_atomic_creates_cow_overlay_and_rejects_chained_backing() {
        let Some(qemu_img) = find_qemu_img_binary() else {
            if std::env::var_os("MINIPOD_REQUIRE_QEMU_TESTS").is_some() {
                panic!("qemu-img binary must be available on PATH or standard QEMU install dir");
            }
            eprintln!(
                "[sandbox_image::qcow2::create_qcow2_overlay_atomic] SKIPPED: qemu-img binary unavailable"
            );
            return;
        };
        let tmp = TestTempDir::new("overlay-e2e");
        let base_path = clean_qemu_host_path(&tmp.path().join("base.qcow2")).unwrap();

        let status = Command::new(&qemu_img)
            .args(["create", "-f", "qcow2"])
            .arg(&base_path)
            .arg("64M")
            .status()
            .expect("invoke qemu-img create for base image");
        assert!(status.success(), "failed creating base qcow2 image");

        let base_info = inspect_qcow2_header(&base_path).unwrap();
        assert_eq!(base_info.backing_file_offset, 0);
        assert_eq!(base_info.backing_file_size, 0);
        assert_eq!(base_info.virtual_size_bytes, 64 * 1024 * 1024);

        // Reject virtual_disk_mb smaller than base image size.
        let small_overlay = tmp.path().join("too-small.qcow2");
        assert!(matches!(
            create_qcow2_overlay_atomic(&qemu_img, &base_path, &small_overlay, Some(32)),
            Err(SandboxError::InvalidSpec(_))
        ));
        assert!(!small_overlay.exists());

        // Reject comma in overlay path before invoking qemu-img.
        let comma_overlay = tmp.path().join("bad,overlay.qcow2");
        assert!(matches!(
            create_qcow2_overlay_atomic(&qemu_img, &base_path, &comma_overlay, None),
            Err(SandboxError::InvalidSpec(_))
        ));

        // Create valid CoW overlay expanded to 128 MiB.
        let overlay_path = tmp.path().join("worker-overlay.qcow2");
        let overlay_info =
            create_qcow2_overlay_atomic(&qemu_img, &base_path, &overlay_path, Some(128))
                .expect("atomic qcow2 overlay creation must succeed");
        assert!(matches!(overlay_info.version, 2 | 3));
        assert_ne!(overlay_info.backing_file_offset, 0);
        assert_ne!(overlay_info.backing_file_size, 0);
        assert_eq!(overlay_info.virtual_size_bytes, 128 * 1024 * 1024);
        assert!(overlay_path.is_file());

        // Reject creating an overlay on top of another overlay (chained backing files).
        let chained_path = tmp.path().join("chained.qcow2");
        assert!(matches!(
            create_qcow2_overlay_atomic(&qemu_img, &overlay_path, &chained_path, None),
            Err(SandboxError::PolicyViolation(_))
        ));
        assert!(!chained_path.exists());

        // Confirm no temporary `.tmp-*` files remain.
        let files: Vec<String> = fs::read_dir(tmp.path())
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        assert!(!files.iter().any(|name| name.contains(".tmp-")));
    }
}
