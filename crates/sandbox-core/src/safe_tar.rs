//! Safe host-side tar packing and extraction enforcing strict path, entry-type, symlink,
//! Windows reparse point, entry-count, and cumulative byte-budget invariants.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Cursor, ErrorKind, Read, Write};
use std::path::{Component, Path, PathBuf, Prefix};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::UNIX_EPOCH;

use crate::error::SandboxError;

const COPY_IO_BUFFER_BYTES: usize = 64 * 1024;
pub const MAX_TAR_DIRECTORY_DEPTH: usize = 128;
pub const MAX_PACK_ENTRIES: usize = 65_536;
const MAX_MEASURE_ENTRIES: usize = 262_144;
pub const WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
pub const WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

static NEXT_STAGE_SEQ: AtomicU64 = AtomicU64::new(0);

#[cfg(all(
    target_os = "linux",
    any(
        target_arch = "x86_64",
        target_arch = "x86",
        target_arch = "riscv64",
        target_arch = "loongarch64",
        target_arch = "s390x"
    )
))]
const UNIX_O_NOFOLLOW: Option<i32> = Some(0o400000);
// <asm-generic/fcntl.h> vs ARM/PowerPC Linux ABI: `O_NOFOLLOW` is 0x8000 (0o100000), while 0o400000 is `O_LARGEFILE`.
#[cfg(all(
    target_os = "linux",
    any(
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "powerpc",
        target_arch = "powerpc64"
    )
))]
const UNIX_O_NOFOLLOW: Option<i32> = Some(0o100000);
#[cfg(target_os = "macos")]
const UNIX_O_NOFOLLOW: Option<i32> = Some(0x0100);
#[cfg(all(
    unix,
    not(target_os = "macos"),
    not(all(
        target_os = "linux",
        any(
            target_arch = "x86_64",
            target_arch = "x86",
            target_arch = "riscv64",
            target_arch = "loongarch64",
            target_arch = "s390x",
            target_arch = "aarch64",
            target_arch = "arm",
            target_arch = "powerpc",
            target_arch = "powerpc64"
        )
    ))
))]
const UNIX_O_NOFOLLOW: Option<i32> = None;

#[cfg(all(
    target_os = "linux",
    any(
        target_arch = "x86_64",
        target_arch = "x86",
        target_arch = "riscv64",
        target_arch = "loongarch64",
        target_arch = "s390x",
        target_arch = "aarch64",
        target_arch = "arm",
        target_arch = "powerpc",
        target_arch = "powerpc64"
    )
))]
const UNIX_O_NONBLOCK: Option<i32> = Some(0o4000);
#[cfg(target_os = "macos")]
const UNIX_O_NONBLOCK: Option<i32> = Some(0x0004);
#[cfg(all(
    unix,
    not(target_os = "macos"),
    not(all(
        target_os = "linux",
        any(
            target_arch = "x86_64",
            target_arch = "x86",
            target_arch = "riscv64",
            target_arch = "loongarch64",
            target_arch = "s390x",
            target_arch = "aarch64",
            target_arch = "arm",
            target_arch = "powerpc",
            target_arch = "powerpc64"
        )
    ))
))]
const UNIX_O_NONBLOCK: Option<i32> = None;

/// Configures `opts` not to follow terminal symlinks (`O_NOFOLLOW` on Unix) or Windows reparse
/// points (`FILE_FLAG_OPEN_REPARSE_POINT` on Windows) so post-open handle inspection sees the
/// link/reparse entry itself rather than a target swapped in via TOCTOU.
pub fn apply_open_no_follow(opts: &mut OpenOptions) {
    #[cfg(unix)]
    if let Some(flag) = UNIX_O_NOFOLLOW {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(flag);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        opts.custom_flags(WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let _ = opts;
}

fn apply_open_read_no_follow_nonblock(opts: &mut OpenOptions) {
    #[cfg(unix)]
    {
        let flags = UNIX_O_NOFOLLOW.unwrap_or(0) | UNIX_O_NONBLOCK.unwrap_or(0);
        if flags != 0 {
            use std::os::unix::fs::OpenOptionsExt;
            opts.custom_flags(flags);
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        opts.custom_flags(WINDOWS_FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let _ = opts;
}

enum PlannedEntry {
    Dir {
        rel: String,
        meta: fs::Metadata,
    },
    File {
        rel: String,
        disk_path: PathBuf,
        meta: fs::Metadata,
    },
}

struct BoundedVecWriter {
    buf: Vec<u8>,
    max_bytes: u64,
    budget_exceeded: bool,
}

impl BoundedVecWriter {
    fn new(max_bytes: u64) -> Self {
        Self {
            buf: Vec::new(),
            max_bytes,
            budget_exceeded: false,
        }
    }
}

impl Write for BoundedVecWriter {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let next_len = (self.buf.len() as u64).checked_add(data.len() as u64);
        match next_len {
            Some(len) if len <= self.max_bytes => {
                self.buf.extend_from_slice(data);
                Ok(data.len())
            }
            _ => {
                self.budget_exceeded = true;
                Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("tar archive exceeds max_bytes ({})", self.max_bytes),
                ))
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Returns `true` when `meta` represents a symlink or Windows reparse point/junction.
pub fn is_symlink_or_reparse(meta: &fs::Metadata) -> bool {
    if meta.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if (meta.file_attributes() & WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            return true;
        }
    }
    #[cfg(not(windows))]
    let _ = WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT;
    false
}

/// Rejects `path` if `meta` is a symlink or Windows reparse point/junction.
pub fn reject_symlink_or_reparse(path: &Path, meta: &fs::Metadata) -> Result<(), SandboxError> {
    if is_symlink_or_reparse(meta) {
        return Err(SandboxError::PolicyViolation(format!(
            "refusing symlink or Windows reparse point at '{}'",
            path.display()
        )));
    }
    Ok(())
}

/// Maps a host filesystem `io::Error` into the appropriate [`SandboxError`] variant.
pub fn map_fs_error(path: &Path, action: &str, err: io::Error) -> SandboxError {
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

/// Packs a host regular file or directory tree into an in-memory GNU tar archive bounded by
/// `max_bytes`, inspecting every host path with `symlink_metadata` and rejecting symlinks,
/// Windows reparse points, and non-regular/non-directory nodes.
pub fn pack_host_path_to_tar(src_host: &Path, max_bytes: u64) -> Result<Vec<u8>, SandboxError> {
    pack_host_path_to_tar_with_limits(
        src_host,
        max_bytes,
        MAX_PACK_ENTRIES,
        MAX_TAR_DIRECTORY_DEPTH,
    )
}

fn pack_host_path_to_tar_with_limits(
    src_host: &Path,
    max_bytes: u64,
    max_entries: usize,
    max_depth: usize,
) -> Result<Vec<u8>, SandboxError> {
    let root_meta = inspect_existing_host_path_no_link(src_host)?;

    let mut plan = Vec::new();
    let mut raw_bytes_total: u64 = 0;

    if root_meta.file_type().is_file() {
        if max_entries == 0 {
            return Err(SandboxError::BudgetExceeded(format!(
                "source entry count exceeds max_entries ({max_entries})"
            )));
        }
        if max_depth == 0 {
            return Err(SandboxError::PolicyViolation(format!(
                "source path '{}' exceeds maximum depth ({max_depth})",
                src_host.display()
            )));
        }
        let name = src_host.file_name().and_then(|n| n.to_str()).ok_or_else(|| {
            SandboxError::PolicyViolation(format!(
                "source path '{}' does not have a valid UTF-8 file name",
                src_host.display()
            ))
        })?;
        validate_archive_segment(name)?;

        raw_bytes_total = root_meta.len();
        if raw_bytes_total > max_bytes {
            return Err(SandboxError::BudgetExceeded(format!(
                "source file '{}' ({raw_bytes_total} bytes) exceeds max_bytes ({max_bytes})",
                src_host.display()
            )));
        }
        plan.push(PlannedEntry::File {
            rel: name.to_owned(),
            disk_path: src_host.to_path_buf(),
            meta: root_meta,
        });
    } else if root_meta.file_type().is_dir() {
        collect_dir_plan(
            src_host,
            "",
            1,
            &mut plan,
            &mut raw_bytes_total,
            max_bytes,
            max_entries,
            max_depth,
        )?;
    } else {
        return Err(SandboxError::PolicyViolation(format!(
            "refusing non-regular source node '{}'",
            src_host.display()
        )));
    }

    let mut writer = BoundedVecWriter::new(max_bytes);
    let finish_res = {
        let mut builder = tar::Builder::new(&mut writer);
        for item in plan {
            match item {
                PlannedEntry::Dir { rel, meta } => {
                    let mut header = tar::Header::new_gnu();
                    header.set_entry_type(tar::EntryType::Directory);
                    header.set_size(0);
                    header.set_mode(safe_archive_mode(&meta, true));
                    header.set_mtime(mtime_secs(&meta));
                    header.set_uid(0);
                    header.set_gid(0);
                    header.set_cksum();
                    if let Err(err) = builder.append_data(&mut header, &rel, io::empty()) {
                        return Err(map_pack_write_err(&rel, err));
                    }
                }
                PlannedEntry::File {
                    rel,
                    disk_path,
                    meta: lstat_meta,
                } => {
                    let mut file = open_source_regular_no_follow(&disk_path, &lstat_meta)?;
                    let open_meta = file.metadata().map_err(|err| {
                        map_fs_error(&disk_path, "inspect opened source file", err)
                    })?;
                    verify_opened_regular_matches(&disk_path, &lstat_meta, &open_meta)?;

                    let size = open_meta.len();
                    let mut header = tar::Header::new_gnu();
                    header.set_entry_type(tar::EntryType::Regular);
                    header.set_size(size);
                    header.set_mode(safe_archive_mode(&open_meta, false));
                    header.set_mtime(mtime_secs(&open_meta));
                    header.set_uid(0);
                    header.set_gid(0);
                    header.set_cksum();

                    if let Err(err) =
                        builder.append_data(&mut header, &rel, (&mut file).take(size))
                    {
                        return Err(map_pack_write_err(&rel, err));
                    }
                }
            }
        }
        builder.finish()
    };

    if writer.budget_exceeded {
        return Err(SandboxError::BudgetExceeded(format!(
            "packed tar archive exceeds max_bytes ({max_bytes})"
        )));
    }
    finish_res
        .map_err(|err| SandboxError::Internal(format!("failed finalizing tar archive: {err}")))?;
    Ok(writer.buf)
}

fn map_pack_write_err(rel: &str, err: io::Error) -> SandboxError {
    if err.kind() == ErrorKind::InvalidInput {
        SandboxError::BudgetExceeded(format!("packing '{rel}' exceeded max_bytes: {err}"))
    } else {
        SandboxError::Internal(format!("failed packing tar entry '{rel}': {err}"))
    }
}

/// Safely extracts `tar_bytes` into `dst_host` without calling `tar::Archive::unpack` /
/// `unpack_in`. Enforces `max_entries`, `max_bytes`, strict relative UTF-8 path validation,
/// `Regular`/`Directory` entry-type allowlisting, and component-by-component symlink/reparse checks.
pub fn extract_tar_safely(
    tar_bytes: &[u8],
    dst_host: &Path,
    max_bytes: u64,
    max_entries: usize,
) -> Result<u64, SandboxError> {
    ensure_safe_dir_path(dst_host, true)?;

    let mut archive = tar::Archive::new(Cursor::new(tar_bytes));
    let entries = archive
        .entries()
        .map_err(|err| SandboxError::InvalidSpec(format!("invalid tar archive header: {err}")))?;

    let mut total_extracted: u64 = 0;
    let mut copy_buf = vec![0u8; COPY_IO_BUFFER_BYTES];

    for (entry_count, entry_res) in entries.enumerate() {
        if entry_count >= max_entries {
            return Err(SandboxError::BudgetExceeded(format!(
                "tar entry count exceeds max_entries ({max_entries})"
            )));
        }

        let mut entry = entry_res
            .map_err(|err| SandboxError::InvalidSpec(format!("invalid tar entry: {err}")))?;
        let entry_type = entry.header().entry_type();
        let raw_path_bytes = entry.path_bytes().into_owned();
        let (is_dir, rel_segments) = validate_entry_type_and_path(entry_type, &raw_path_bytes)?;

        if is_dir {
            if let Some(segments) = rel_segments {
                create_safe_subdirs(dst_host, &segments)?;
            }
            continue;
        }

        let segments = rel_segments.ok_or_else(|| {
            SandboxError::PolicyViolation(
                "tar regular file entry cannot target destination root '.'".to_owned(),
            )
        })?;
        let header_size = entry
            .header()
            .size()
            .map_err(|err| SandboxError::InvalidSpec(format!("invalid tar entry size: {err}")))?;
        let declared_size = entry.size().max(header_size);
        let remaining = max_bytes.saturating_sub(total_extracted);
        if declared_size > remaining {
            return Err(SandboxError::BudgetExceeded(format!(
                "tar entry size {declared_size} bytes exceeds remaining max_bytes budget ({remaining})"
            )));
        }

        let (parent_segs, file_name) = segments.split_at(segments.len() - 1);
        let parent_dir = create_safe_subdirs(dst_host, parent_segs)?;
        let file_path = parent_dir.join(&file_name[0]);
        let mode = entry.header().mode().unwrap_or(0o644) & 0o777;

        validate_extract_destination_before_replace(&file_path)?;
        let mut staged = StagedExtractFile::create(&parent_dir)?;
        let mut copied: u64 = 0;
        let mut limited = (&mut entry).take(remaining.saturating_add(1));

        loop {
            let n = match limited.read(&mut copy_buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(err) => {
                    return Err(SandboxError::InvalidSpec(format!(
                        "failed reading tar payload for '{}': {err}",
                        segments.join("/")
                    )));
                }
            };
            copied = copied
                .checked_add(n as u64)
                .ok_or_else(|| SandboxError::BudgetExceeded("extracted byte count overflow".to_owned()))?;
            if copied > remaining {
                return Err(SandboxError::BudgetExceeded(format!(
                    "tar extraction exceeded max_bytes ({max_bytes})"
                )));
            }
            if let Err(err) = staged.write_all(&copy_buf[..n]) {
                return Err(map_fs_error(&file_path, "write staged extracted file", err));
            }
        }

        if copied != declared_size {
            return Err(SandboxError::InvalidSpec(format!(
                "truncated tar entry '{}': expected {declared_size} bytes, got {copied}",
                segments.join("/")
            )));
        }

        staged.commit(&file_path, mode)?;
        total_extracted = total_extracted
            .checked_add(copied)
            .ok_or_else(|| SandboxError::BudgetExceeded("extracted byte count overflow".to_owned()))?;
    }

    Ok(total_extracted)
}

/// Validates an in-memory tar archive without touching disk, enforcing `max_entries`, `max_bytes`,
/// strict relative UTF-8 paths, `Regular`/`Directory` entry-type allowlisting, and payload completeness.
pub fn validate_tar_bytes(
    tar_bytes: &[u8],
    max_bytes: u64,
    max_entries: usize,
) -> Result<u64, SandboxError> {
    let mut archive = tar::Archive::new(Cursor::new(tar_bytes));
    let entries = archive
        .entries()
        .map_err(|err| SandboxError::InvalidSpec(format!("invalid tar archive header: {err}")))?;

    let mut total_validated: u64 = 0;
    let mut drain_buf = vec![0u8; COPY_IO_BUFFER_BYTES];

    for (entry_count, entry_res) in entries.enumerate() {
        if entry_count >= max_entries {
            return Err(SandboxError::BudgetExceeded(format!(
                "tar entry count exceeds max_entries ({max_entries})"
            )));
        }

        let mut entry = entry_res
            .map_err(|err| SandboxError::InvalidSpec(format!("invalid tar entry: {err}")))?;
        let entry_type = entry.header().entry_type();
        let raw_path_bytes = entry.path_bytes().into_owned();
        let (is_dir, rel_segments) = validate_entry_type_and_path(entry_type, &raw_path_bytes)?;

        if is_dir {
            continue;
        }

        let segments = rel_segments.ok_or_else(|| {
            SandboxError::PolicyViolation(
                "tar regular file entry cannot target destination root '.'".to_owned(),
            )
        })?;
        let header_size = entry
            .header()
            .size()
            .map_err(|err| SandboxError::InvalidSpec(format!("invalid tar entry size: {err}")))?;
        let declared_size = entry.size().max(header_size);
        let remaining = max_bytes.saturating_sub(total_validated);
        if declared_size > remaining {
            return Err(SandboxError::BudgetExceeded(format!(
                "tar entry size {declared_size} bytes exceeds remaining max_bytes budget ({remaining})"
            )));
        }

        let mut read_bytes: u64 = 0;
        let mut limited = (&mut entry).take(remaining.saturating_add(1));
        loop {
            let n = limited.read(&mut drain_buf).map_err(|err| {
                SandboxError::InvalidSpec(format!(
                    "failed reading tar payload for '{}': {err}",
                    segments.join("/")
                ))
            })?;
            if n == 0 {
                break;
            }
            read_bytes = read_bytes
                .checked_add(n as u64)
                .ok_or_else(|| SandboxError::BudgetExceeded("tar byte count overflow".to_owned()))?;
            if read_bytes > remaining {
                return Err(SandboxError::BudgetExceeded(format!(
                    "tar payload exceeded max_bytes ({max_bytes})"
                )));
            }
        }

        if read_bytes != declared_size {
            return Err(SandboxError::InvalidSpec(format!(
                "truncated tar entry '{}': expected {declared_size} bytes, got {read_bytes}",
                segments.join("/")
            )));
        }

        total_validated = total_validated
            .checked_add(read_bytes)
            .ok_or_else(|| SandboxError::BudgetExceeded("tar byte count overflow".to_owned()))?;
    }

    Ok(total_validated)
}

fn validate_entry_type_and_path(
    entry_type: tar::EntryType,
    raw_path_bytes: &[u8],
) -> Result<(bool, Option<Vec<String>>), SandboxError> {
    let is_dir = match entry_type {
        tar::EntryType::Directory => true,
        tar::EntryType::Regular => false,
        tar::EntryType::Symlink => {
            return Err(SandboxError::PolicyViolation(
                "refusing tar symlink entry".to_owned(),
            ));
        }
        tar::EntryType::Link => {
            return Err(SandboxError::PolicyViolation(
                "refusing tar hardlink entry".to_owned(),
            ));
        }
        tar::EntryType::Fifo
        | tar::EntryType::Char
        | tar::EntryType::Block
        | tar::EntryType::Continuous => {
            return Err(SandboxError::PolicyViolation(format!(
                "refusing forbidden tar entry type {entry_type:?}"
            )));
        }
        other => {
            return Err(SandboxError::PolicyViolation(format!(
                "refusing unsupported tar entry type {other:?}"
            )));
        }
    };

    let rel_segments = validate_tar_entry_segments(raw_path_bytes, is_dir)?;
    Ok((is_dir, rel_segments))
}

fn collect_dir_plan(
    disk_dir: &Path,
    rel_prefix: &str,
    segment_depth: usize,
    plan: &mut Vec<PlannedEntry>,
    raw_bytes_total: &mut u64,
    max_bytes: u64,
    max_entries: usize,
    max_depth: usize,
) -> Result<(), SandboxError> {
    let entries = fs::read_dir(disk_dir)
        .map_err(|err| map_fs_error(disk_dir, "read source directory", err))?;

    let mut children = Vec::new();
    for entry_res in entries {
        let entry = entry_res
            .map_err(|err| map_fs_error(disk_dir, "iterate source directory", err))?;
        if segment_depth > max_depth {
            return Err(SandboxError::PolicyViolation(format!(
                "source directory nesting inside '{}' exceeds maximum depth ({max_depth})",
                disk_dir.display()
            )));
        }
        let raw_name = entry.file_name();
        let name = raw_name.to_str().ok_or_else(|| {
            SandboxError::PolicyViolation(format!(
                "refusing non-UTF-8 entry inside '{}'",
                disk_dir.display()
            ))
        })?;
        validate_archive_segment(name)?;
        children.push((name.to_owned(), entry.path()));
        if plan.len().saturating_add(children.len()) > max_entries {
            return Err(SandboxError::BudgetExceeded(format!(
                "source entry count exceeds max_entries ({max_entries})"
            )));
        }
    }
    children.sort_by(|a, b| a.0.cmp(&b.0));

    for (name, child_path) in children {
        if plan.len() >= max_entries {
            return Err(SandboxError::BudgetExceeded(format!(
                "source entry count exceeds max_entries ({max_entries})"
            )));
        }
        let meta = fs::symlink_metadata(&child_path)
            .map_err(|err| map_fs_error(&child_path, "inspect source entry metadata", err))?;
        reject_symlink_or_reparse(&child_path, &meta)?;

        let rel = if rel_prefix.is_empty() {
            name
        } else {
            format!("{rel_prefix}/{name}")
        };

        if meta.file_type().is_dir() {
            plan.push(PlannedEntry::Dir {
                rel: rel.clone(),
                meta,
            });
            collect_dir_plan(
                &child_path,
                &rel,
                segment_depth + 1,
                plan,
                raw_bytes_total,
                max_bytes,
                max_entries,
                max_depth,
            )?;
        } else if meta.file_type().is_file() {
            *raw_bytes_total = raw_bytes_total
                .checked_add(meta.len())
                .ok_or_else(|| SandboxError::BudgetExceeded("source byte count overflow".to_owned()))?;
            if *raw_bytes_total > max_bytes {
                return Err(SandboxError::BudgetExceeded(format!(
                    "source content size {} bytes exceeds max_bytes ({max_bytes})",
                    *raw_bytes_total
                )));
            }
            plan.push(PlannedEntry::File {
                rel,
                disk_path: child_path,
                meta,
            });
        } else {
            return Err(SandboxError::PolicyViolation(format!(
                "refusing non-regular source node '{}'",
                child_path.display()
            )));
        }
    }
    Ok(())
}

fn validate_tar_entry_segments(
    raw_bytes: &[u8],
    is_dir: bool,
) -> Result<Option<Vec<String>>, SandboxError> {
    if raw_bytes.is_empty() {
        return Err(SandboxError::PolicyViolation(
            "tar entry path must not be empty".to_owned(),
        ));
    }
    if raw_bytes.contains(&0) {
        return Err(SandboxError::PolicyViolation(
            "tar entry path contains forbidden NUL byte".to_owned(),
        ));
    }
    if raw_bytes.contains(&b'\\') {
        return Err(SandboxError::PolicyViolation(
            "tar entry path contains forbidden backslash '\\'".to_owned(),
        ));
    }

    let raw_str = std::str::from_utf8(raw_bytes).map_err(|_| {
        SandboxError::PolicyViolation("tar entry path is not valid UTF-8".to_owned())
    })?;

    if raw_str.starts_with('/') {
        return Err(SandboxError::PolicyViolation(format!(
            "tar entry path '{raw_str}' must not be absolute"
        )));
    }
    let bytes = raw_str.as_bytes();
    if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
        return Err(SandboxError::PolicyViolation(format!(
            "tar entry path '{raw_str}' must not contain Windows drive prefix"
        )));
    }

    if raw_str == "." || raw_str == "./" {
        if is_dir {
            return Ok(None);
        }
        return Err(SandboxError::PolicyViolation(format!(
            "tar regular entry cannot use '{raw_str}'"
        )));
    }

    if !is_dir && raw_str.ends_with('/') {
        return Err(SandboxError::PolicyViolation(format!(
            "tar regular entry '{raw_str}' must not end with '/'"
        )));
    }

    let trimmed = if is_dir {
        raw_str.strip_suffix('/').unwrap_or(raw_str)
    } else {
        raw_str
    };
    let trimmed = trimmed.strip_prefix("./").unwrap_or(trimmed);

    let mut segments = Vec::new();
    for seg in trimmed.split('/') {
        validate_archive_segment(seg)?;
        segments.push(seg.to_owned());
        if segments.len() > MAX_TAR_DIRECTORY_DEPTH {
            return Err(SandboxError::PolicyViolation(format!(
                "tar entry path '{raw_str}' exceeds maximum depth ({MAX_TAR_DIRECTORY_DEPTH})"
            )));
        }
    }

    if segments.is_empty() {
        return Err(SandboxError::PolicyViolation(format!(
            "tar entry path '{raw_str}' resolved to no path segments"
        )));
    }

    Ok(Some(segments))
}

fn validate_archive_segment(seg: &str) -> Result<(), SandboxError> {
    if seg.is_empty() || seg == "." || seg == ".." {
        return Err(SandboxError::PolicyViolation(format!(
            "tar entry contains forbidden segment '{seg}'"
        )));
    }
    if seg.contains('/') || seg.contains('\\') || seg.contains('\0') {
        return Err(SandboxError::PolicyViolation(format!(
            "tar entry segment '{seg}' contains forbidden path character"
        )));
    }
    #[cfg(windows)]
    if is_windows_invalid_segment(seg) {
        return Err(SandboxError::PolicyViolation(format!(
            "tar entry segment '{seg}' uses forbidden Windows device, trailing dot/space, or special syntax"
        )));
    }
    #[cfg(not(windows))]
    let _ = is_windows_invalid_segment;
    let mut comps = Path::new(seg).components();
    match (comps.next(), comps.next()) {
        (Some(Component::Normal(_)), None) => Ok(()),
        _ => Err(SandboxError::PolicyViolation(format!(
            "tar entry segment '{seg}' is not a normal path component"
        ))),
    }
}

fn is_windows_invalid_segment(seg: &str) -> bool {
    if seg.is_empty() || seg.ends_with('.') || seg.ends_with(' ') {
        return true;
    }
    if seg.chars().any(|c| {
        (c as u32) < 0x20 || matches!(c, '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*')
    }) {
        return true;
    }
    is_windows_reserved_device_name(seg)
}

fn is_windows_reserved_device_name(seg: &str) -> bool {
    let stem = seg.split('.').next().unwrap_or(seg).trim_end_matches(' ');
    if matches!(
        stem.to_ascii_uppercase().as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$" | "CLOCK$"
    ) {
        return true;
    }
    if let Some(prefix) = stem.get(..3) {
        if prefix.eq_ignore_ascii_case("COM") || prefix.eq_ignore_ascii_case("LPT") {
            return matches!(
                &stem[3..],
                "1" | "2"
                    | "3"
                    | "4"
                    | "5"
                    | "6"
                    | "7"
                    | "8"
                    | "9"
                    | "\u{00B9}"
                    | "\u{00B2}"
                    | "\u{00B3}"
            );
        }
    }
    false
}

fn inspect_existing_host_path_no_link(path: &Path) -> Result<fs::Metadata, SandboxError> {
    validate_host_path_components(path)?;
    let mut cur = PathBuf::new();
    let components: Vec<_> = path.components().collect();
    let last_normal_idx = components
        .iter()
        .rposition(|c| matches!(c, Component::Normal(_)));

    let mut final_meta = None;
    for (idx, comp) in components.into_iter().enumerate() {
        match comp {
            Component::Prefix(p) => cur.push(p.as_os_str()),
            Component::RootDir => cur.push(comp.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(SandboxError::PolicyViolation(format!(
                    "host path '{}' must not contain '..'",
                    path.display()
                )));
            }
            Component::Normal(part) => {
                cur.push(part);
                let meta = fs::symlink_metadata(&cur)
                    .map_err(|err| map_fs_error(&cur, "inspect host path component", err))?;
                if is_allowed_macos_root_symlink(&cur, &meta) {
                    continue;
                }
                reject_symlink_or_reparse(&cur, &meta)?;
                if Some(idx) != last_normal_idx {
                    if !meta.file_type().is_dir() {
                        return Err(SandboxError::PolicyViolation(format!(
                            "intermediate host path component '{}' is not a directory",
                            cur.display()
                        )));
                    }
                } else {
                    final_meta = Some(meta);
                }
            }
        }
    }

    match final_meta {
        Some(meta) => Ok(meta),
        None => {
            let root = if cur.as_os_str().is_empty() {
                Path::new(".")
            } else {
                cur.as_path()
            };
            let meta = fs::symlink_metadata(root)
                .map_err(|err| map_fs_error(root, "inspect host root path", err))?;
            reject_symlink_or_reparse(root, &meta)?;
            Ok(meta)
        }
    }
}

/// Validates every component of `path` against symlinks/reparse points and optionally creates missing
/// subdirectories safely without following links.
pub fn ensure_safe_dir_path(path: &Path, create_missing: bool) -> Result<(), SandboxError> {
    validate_host_path_components(path)?;
    let mut cur = PathBuf::new();
    let mut saw_normal = false;

    for comp in path.components() {
        match comp {
            Component::Prefix(p) => cur.push(p.as_os_str()),
            Component::RootDir => cur.push(comp.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(SandboxError::PolicyViolation(format!(
                    "host directory path '{}' must not contain '..'",
                    path.display()
                )));
            }
            Component::Normal(part) => {
                saw_normal = true;
                step_dir_no_link(&mut cur, part, create_missing)?;
            }
        }
    }

    if !saw_normal {
        let root = if cur.as_os_str().is_empty() {
            Path::new(".")
        } else {
            cur.as_path()
        };
        let meta = fs::symlink_metadata(root)
            .map_err(|err| map_fs_error(root, "inspect host directory", err))?;
        reject_symlink_or_reparse(root, &meta)?;
        if !meta.file_type().is_dir() {
            return Err(SandboxError::PolicyViolation(format!(
                "path '{}' is not a directory",
                root.display()
            )));
        }
    }
    Ok(())
}

/// Sums regular file byte lengths inside `path` using `symlink_metadata`, never following
/// symlinks or Windows reparse points/junctions.
pub fn measure_dir_bytes(path: &Path) -> Result<u64, SandboxError> {
    validate_host_path_components(path)?;
    let root_meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(0),
        Err(err) => return Err(map_fs_error(path, "inspect directory size root", err)),
    };
    if is_symlink_or_reparse(&root_meta) {
        return Err(SandboxError::PolicyViolation(format!(
            "refusing symlink or Windows reparse point at '{}'",
            path.display()
        )));
    }
    if root_meta.file_type().is_file() {
        return Ok(root_meta.len());
    }
    if !root_meta.file_type().is_dir() {
        return Ok(0);
    }

    let mut total_bytes: u64 = 0;
    let mut visited_entries: usize = 0;
    let mut stack = vec![(path.to_path_buf(), 0usize)];
    while let Some((dir, depth)) = stack.pop() {
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(err) if err.kind() == ErrorKind::NotFound => continue,
            Err(err) => {
                return Err(map_fs_error(
                    &dir,
                    "read directory for size measurement",
                    err,
                ))
            }
        };
        for entry_res in entries {
            let entry = match entry_res {
                Ok(entry) => entry,
                Err(err) if err.kind() == ErrorKind::NotFound => continue,
                Err(err) => {
                    return Err(map_fs_error(
                        &dir,
                        "iterate directory for size measurement",
                        err,
                    ))
                }
            };
            visited_entries = visited_entries.saturating_add(1);
            if visited_entries > MAX_MEASURE_ENTRIES {
                return Err(SandboxError::BudgetExceeded(format!(
                    "directory measurement entry count inside '{}' exceeds maximum ({MAX_MEASURE_ENTRIES})",
                    path.display()
                )));
            }
            if depth + 1 > MAX_TAR_DIRECTORY_DEPTH {
                return Err(SandboxError::PolicyViolation(format!(
                    "directory nesting inside '{}' exceeds maximum depth ({MAX_TAR_DIRECTORY_DEPTH})",
                    path.display()
                )));
            }
            let child = entry.path();
            let meta = match fs::symlink_metadata(&child) {
                Ok(meta) => meta,
                Err(err) if err.kind() == ErrorKind::NotFound => continue,
                Err(err) => return Err(map_fs_error(&child, "inspect entry metadata", err)),
            };
            if is_symlink_or_reparse(&meta) {
                continue;
            }
            if meta.file_type().is_dir() {
                stack.push((child, depth + 1));
            } else if meta.file_type().is_file() {
                total_bytes = total_bytes.saturating_add(meta.len());
            }
        }
    }
    Ok(total_bytes)
}

fn validate_host_path_components(path: &Path) -> Result<(), SandboxError> {
    if path.as_os_str().is_empty() {
        return Err(SandboxError::InvalidSpec(
            "host path must not be empty".to_owned(),
        ));
    }
    #[cfg(windows)]
    {
        // `Path::components` only checks raw trailing dots/spaces on `as_os_str()`, because
        // `Component::Normal` on non-verbatim paths may still preserve trailing dots/spaces or ADS.
        let raw_lossy = path.as_os_str().to_string_lossy();
        if raw_lossy.ends_with(' ') || (raw_lossy.ends_with('.') && raw_lossy != "." && !raw_lossy.ends_with("\\.") && !raw_lossy.ends_with("/.")) {
            return Err(SandboxError::PolicyViolation(format!(
                "host path '{}' must not end with trailing space or dot",
                path.display()
            )));
        }
    }
    for comp in path.components() {
        match comp {
            Component::ParentDir => {
                return Err(SandboxError::PolicyViolation(format!(
                    "host path '{}' must not contain '..'",
                    path.display()
                )));
            }
            Component::Prefix(prefix) => {
                if matches!(prefix.kind(), Prefix::DeviceNS(_)) {
                    return Err(SandboxError::PolicyViolation(format!(
                        "refusing Windows device namespace path '{}'",
                        path.display()
                    )));
                }
            }
            #[cfg(windows)]
            Component::Normal(part) => {
                let Some(seg) = part.to_str() else {
                    return Err(SandboxError::PolicyViolation(format!(
                        "host path '{}' contains invalid UTF-8 component",
                        path.display()
                    )));
                };
                if is_windows_invalid_segment(seg) {
                    return Err(SandboxError::PolicyViolation(format!(
                        "host path '{}' contains forbidden Windows device, ADS colon, or trailing dot/space component '{seg}'",
                        path.display()
                    )));
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn create_safe_subdirs(root: &Path, segments: &[String]) -> Result<PathBuf, SandboxError> {
    let mut cur = root.to_path_buf();
    for seg in segments {
        step_dir_no_link(&mut cur, seg.as_ref(), true)?;
    }
    Ok(cur)
}

fn step_dir_no_link(
    cur: &mut PathBuf,
    part: &std::ffi::OsStr,
    create_missing: bool,
) -> Result<(), SandboxError> {
    cur.push(part);
    match fs::symlink_metadata(&*cur) {
        Ok(meta) => {
            if is_allowed_macos_root_symlink(cur, &meta) {
                return Ok(());
            }
            reject_symlink_or_reparse(cur, &meta)?;
            if !meta.file_type().is_dir() {
                return Err(SandboxError::PolicyViolation(format!(
                    "path component '{}' exists and is not a directory",
                    cur.display()
                )));
            }
            Ok(())
        }
        Err(err) if err.kind() == ErrorKind::NotFound => {
            if !create_missing {
                return Err(SandboxError::NotFound(format!(
                    "directory '{}' does not exist",
                    cur.display()
                )));
            }
            match fs::create_dir(&*cur) {
                Ok(()) => {}
                Err(create_err) if create_err.kind() == ErrorKind::AlreadyExists => {}
                Err(create_err) => {
                    return Err(map_fs_error(cur, "create directory", create_err));
                }
            }
            let meta = fs::symlink_metadata(&*cur)
                .map_err(|meta_err| map_fs_error(cur, "verify created directory", meta_err))?;
            reject_symlink_or_reparse(cur, &meta)?;
            if !meta.file_type().is_dir() {
                return Err(SandboxError::PolicyViolation(format!(
                    "path component '{}' is not a directory",
                    cur.display()
                )));
            }
            Ok(())
        }
        Err(err) => Err(map_fs_error(cur, "inspect directory component", err)),
    }
}

fn open_source_regular_no_follow(
    path: &Path,
    lstat_meta: &fs::Metadata,
) -> Result<File, SandboxError> {
    reject_symlink_or_reparse(path, lstat_meta)?;
    if !lstat_meta.file_type().is_file() {
        return Err(SandboxError::PolicyViolation(format!(
            "refusing non-regular source file '{}'",
            path.display()
        )));
    }

    let mut opts = OpenOptions::new();
    opts.read(true);
    apply_open_read_no_follow_nonblock(&mut opts);
    let file = opts
        .open(path)
        .map_err(|err| map_fs_error(path, "open source file", err))?;
    let open_meta = file
        .metadata()
        .map_err(|err| map_fs_error(path, "inspect opened source file", err))?;
    reject_symlink_or_reparse(path, &open_meta)?;
    if !open_meta.file_type().is_file() {
        return Err(SandboxError::PolicyViolation(format!(
            "refusing non-regular opened source file '{}'",
            path.display()
        )));
    }
    Ok(file)
}

struct StagedExtractFile {
    tmp_path: PathBuf,
    file: Option<File>,
    armed: bool,
}

impl StagedExtractFile {
    fn create(parent_dir: &Path) -> Result<Self, SandboxError> {
        for _ in 0..16 {
            let seq = NEXT_STAGE_SEQ.fetch_add(1, Ordering::Relaxed);
            let tmp_path = parent_dir.join(format!(
                ".minipod-extract-{}-{seq}.tmp",
                std::process::id()
            ));
            let mut opts = OpenOptions::new();
            opts.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(0o600);
            }
            apply_open_no_follow(&mut opts);
            match opts.open(&tmp_path) {
                Ok(file) => {
                    return Ok(Self {
                        tmp_path,
                        file: Some(file),
                        armed: true,
                    });
                }
                Err(err) if err.kind() == ErrorKind::AlreadyExists => continue,
                Err(err) => {
                    return Err(map_fs_error(&tmp_path, "create staged extraction file", err));
                }
            }
        }
        Err(SandboxError::Internal(format!(
            "exhausted temporary extraction filenames in '{}'",
            parent_dir.display()
        )))
    }

    fn write_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        match self.file.as_mut() {
            Some(f) => f.write_all(bytes),
            None => Err(io::Error::new(
                ErrorKind::BrokenPipe,
                "staged extraction file already closed",
            )),
        }
    }

    fn commit(mut self, dst_path: &Path, mode: u32) -> Result<(), SandboxError> {
        if let Some(file) = self.file.take() {
            apply_safe_file_mode(&file, mode)?;
            file.sync_data()
                .map_err(|err| map_fs_error(&self.tmp_path, "sync staged extraction file", err))?;
        }
        validate_extract_destination_before_replace(dst_path)?;
        fs::rename(&self.tmp_path, dst_path)
            .map_err(|err| map_fs_error(dst_path, "commit extracted file", err))?;
        self.armed = false;
        Ok(())
    }
}

impl Drop for StagedExtractFile {
    fn drop(&mut self) {
        self.file.take();
        if self.armed {
            let _ = fs::remove_file(&self.tmp_path);
        }
    }
}

fn validate_extract_destination_before_replace(path: &Path) -> Result<(), SandboxError> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            reject_symlink_or_reparse(path, &meta)?;
            if meta.file_type().is_dir() {
                return Err(SandboxError::PolicyViolation(format!(
                    "destination '{}' is an existing directory",
                    path.display()
                )));
            }
            if !meta.file_type().is_file() {
                return Err(SandboxError::PolicyViolation(format!(
                    "destination '{}' is an existing non-regular node",
                    path.display()
                )));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                if meta.nlink() > 1 {
                    return Err(SandboxError::PolicyViolation(format!(
                        "refusing to overwrite hardlinked file (nlink={}) at '{}'",
                        meta.nlink(),
                        path.display()
                    )));
                }
            }
            Ok(())
        }
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
        Err(err) => Err(map_fs_error(path, "inspect destination file", err)),
    }
}

fn verify_opened_regular_matches(
    path: &Path,
    lstat_meta: &fs::Metadata,
    open_meta: &fs::Metadata,
) -> Result<(), SandboxError> {
    reject_symlink_or_reparse(path, open_meta)?;
    if !open_meta.file_type().is_file() {
        return Err(SandboxError::PolicyViolation(format!(
            "opened file '{}' is not regular",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if (lstat_meta.dev(), lstat_meta.ino()) != (open_meta.dev(), open_meta.ino()) {
            return Err(SandboxError::PolicyViolation(format!(
                "file '{}' changed identity between lstat and open",
                path.display()
            )));
        }
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        // shortcut: stable `std` lacks `file_index`/`volume_serial_number`, switch to `ByHandleFileInformation` if sub-100ns replacement collisions matter.
        if (lstat_meta.creation_time(), lstat_meta.file_attributes())
            != (open_meta.creation_time(), open_meta.file_attributes())
        {
            return Err(SandboxError::PolicyViolation(format!(
                "file '{}' changed metadata identity between lstat and open",
                path.display()
            )));
        }
    }
    #[cfg(not(any(unix, windows)))]
    let _ = (path, lstat_meta);
    Ok(())
}

/// macOS maps `/var`, `/tmp`, and `/etc` at `/` as SIP-protected symlinks to `private/*`.
/// Permit ONLY those exact root system links while still checking every descendant component.
fn is_allowed_macos_root_symlink(path: &Path, meta: &fs::Metadata) -> bool {
    #[cfg(target_os = "macos")]
    {
        if meta.file_type().is_symlink() {
            let expected = if path == Path::new("/var") {
                Some("private/var")
            } else if path == Path::new("/tmp") {
                Some("private/tmp")
            } else if path == Path::new("/etc") {
                Some("private/etc")
            } else {
                None
            };
            if let Some(target) = expected {
                return fs::read_link(path).is_ok_and(|link| link == Path::new(target));
            }
        }
        false
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (path, meta);
        false
    }
}

fn apply_safe_file_mode(file: &File, mode: u32) -> Result<(), SandboxError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(mode & 0o777);
        file.set_permissions(perms)
            .map_err(|err| SandboxError::Internal(format!("failed setting file permissions: {err}")))?;
    }
    #[cfg(not(unix))]
    let _ = (file, mode);
    Ok(())
}

fn safe_archive_mode(meta: &fs::Metadata, is_dir: bool) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = is_dir;
        meta.permissions().mode() & 0o777
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        if is_dir {
            0o755
        } else {
            0o644
        }
    }
}

fn mtime_secs(meta: &fs::Metadata) -> u64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_SEQ: AtomicU64 = AtomicU64::new(0);

    struct TestTempDir(PathBuf);

    impl TestTempDir {
        fn new(label: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "minipod-core-tar-{label}-{}-{}",
                std::process::id(),
                TEST_SEQ.fetch_add(1, Ordering::Relaxed)
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

    type RawTarEntry<'a> = (&'a [u8], tar::EntryType, &'a [u8], Option<&'a [u8]>);

    fn make_raw_tar(entries: &[RawTarEntry<'_>]) -> Vec<u8> {
        let mut archive = Vec::new();
        for (raw_path, entry_type, payload, link_target) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(*entry_type);
            header.set_size(payload.len() as u64);
            header.set_mode(0o644);
            header.set_uid(0);
            header.set_gid(0);

            let raw_hdr = header.as_mut_bytes();
            let path_len = raw_path.len().min(100);
            raw_hdr[0..path_len].copy_from_slice(&raw_path[..path_len]);
            if path_len < 100 {
                raw_hdr[path_len..100].fill(0);
            }
            if let Some(target) = link_target {
                let target_len = target.len().min(100);
                raw_hdr[157..157 + target_len].copy_from_slice(&target[..target_len]);
                if target_len < 100 {
                    raw_hdr[157 + target_len..257].fill(0);
                }
            }
            header.set_cksum();
            archive.extend_from_slice(header.as_bytes());

            if !payload.is_empty() {
                archive.extend_from_slice(payload);
                let rem = payload.len() % 512;
                if rem != 0 {
                    archive.resize(archive.len() + (512 - rem), 0);
                }
            }
        }
        archive.resize(archive.len() + 1024, 0);
        archive
    }

    #[test]
    fn pack_and_extract_roundtrip_directory_and_single_file() {
        let tmp = TestTempDir::new("safe-tar-rt");
        let src_dir = tmp.path().join("src");
        let nested_dir = src_dir.join("nested").join("empty");
        fs::create_dir_all(&nested_dir).unwrap();

        let big_payload = vec![0x5Au8; 80_000];
        fs::write(src_dir.join("hello.txt"), b"hello safe tar").unwrap();
        fs::write(src_dir.join("empty.bin"), b"").unwrap();
        fs::write(src_dir.join("nested").join("blob.bin"), &big_payload).unwrap();

        let tar_bytes = pack_host_path_to_tar(&src_dir, 1024 * 1024).unwrap();
        let dst_dir = tmp.path().join("dst").join("unpacked");
        let extracted = extract_tar_safely(&tar_bytes, &dst_dir, 1024 * 1024, 100).unwrap();

        assert_eq!(extracted, (b"hello safe tar".len() + big_payload.len()) as u64);
        assert_eq!(fs::read(dst_dir.join("hello.txt")).unwrap(), b"hello safe tar");
        assert_eq!(fs::read(dst_dir.join("empty.bin")).unwrap(), b"");
        assert_eq!(
            fs::read(dst_dir.join("nested").join("blob.bin")).unwrap(),
            big_payload
        );
        assert!(dst_dir.join("nested").join("empty").is_dir());

        // Single regular file round-trip.
        let single_tar = pack_host_path_to_tar(&src_dir.join("hello.txt"), 64 * 1024).unwrap();
        let single_dst = tmp.path().join("single-out");
        let single_extracted =
            extract_tar_safely(&single_tar, &single_dst, 64 * 1024, 16).unwrap();
        assert_eq!(single_extracted, b"hello safe tar".len() as u64);
        assert_eq!(fs::read(single_dst.join("hello.txt")).unwrap(), b"hello safe tar");
    }

    #[test]
    fn extract_rejects_traversal_absolute_windows_drive_nul_and_non_utf8_paths() {
        let tmp = TestTempDir::new("safe-tar-paths");
        let dst = tmp.path().join("dst");
        fs::create_dir_all(&dst).unwrap();

        let bad_paths: [&[u8]; 12] = [
            b"../escape.txt",
            b"sub/../../escape.txt",
            b"./../escape.txt",
            b"a/./b.txt",
            b"a/.",
            b".",
            b"/etc/passwd",
            b"C:\\evil.txt",
            b"C:/evil.txt",
            b"C:evil.txt",
            b"sub\\evil.txt",
            b"\xFF\xFE.txt",
        ];

        for bad in bad_paths {
            let tar = make_raw_tar(&[(bad, tar::EntryType::Regular, b"pwn", None)]);
            let res = extract_tar_safely(&tar, &dst, 64 * 1024, 32);
            assert!(
                matches!(res, Err(SandboxError::PolicyViolation(_))),
                "expected PolicyViolation for {:?}, got {res:?}",
                String::from_utf8_lossy(bad)
            );
        }

        // Embedded NUL via GNU LongName extension (`path_bytes` preserves embedded `\0`).
        let nul_tar = make_raw_tar(&[
            (
                b"././@LongLink",
                tar::EntryType::GNULongName,
                b"foo\0bar.txt\0",
                None,
            ),
            (b"foo", tar::EntryType::Regular, b"pwn", None),
        ]);
        assert!(matches!(
            extract_tar_safely(&nul_tar, &dst, 64 * 1024, 32),
            Err(SandboxError::PolicyViolation(_))
        ));

        #[cfg(windows)]
        {
            for dos_name in [b"NUL".as_slice(), b"CON.txt".as_slice(), b"COM1".as_slice()] {
                let tar = make_raw_tar(&[(dos_name, tar::EntryType::Regular, b"pwn", None)]);
                assert!(matches!(
                    extract_tar_safely(&tar, &dst, 64 * 1024, 32),
                    Err(SandboxError::PolicyViolation(_))
                ));
            }
        }

        assert!(!tmp.path().join("escape.txt").exists());
        assert_eq!(fs::read_dir(&dst).unwrap().count(), 0);
    }

    #[test]
    fn extract_rejects_forbidden_entry_types() {
        let tmp = TestTempDir::new("safe-tar-types");
        let dst = tmp.path().join("dst");
        fs::create_dir_all(&dst).unwrap();

        let cases = [
            (
                b"sym".as_slice(),
                tar::EntryType::Symlink,
                b"".as_slice(),
                Some(b"/etc/passwd".as_slice()),
            ),
            (
                b"hard".as_slice(),
                tar::EntryType::Link,
                b"".as_slice(),
                Some(b"target.txt".as_slice()),
            ),
            (b"fifo".as_slice(), tar::EntryType::Fifo, b"".as_slice(), None),
            (b"char".as_slice(), tar::EntryType::Char, b"".as_slice(), None),
            (b"blk".as_slice(), tar::EntryType::Block, b"".as_slice(), None),
            (
                b"cont".as_slice(),
                tar::EntryType::Continuous,
                b"abc".as_slice(),
                None,
            ),
        ];

        for case in cases {
            let tar = make_raw_tar(&[case]);
            let res = extract_tar_safely(&tar, &dst, 64 * 1024, 32);
            assert!(
                matches!(res, Err(SandboxError::PolicyViolation(_))),
                "expected PolicyViolation for {:?}, got {res:?}",
                case.1
            );
        }
    }

    #[test]
    fn pack_and_extract_enforce_budgets_and_detect_truncated_tar() {
        let tmp = TestTempDir::new("safe-tar-budget");
        let src = tmp.path().join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("a.txt"), vec![b'a'; 60]).unwrap();
        fs::write(src.join("b.txt"), vec![b'b'; 60]).unwrap();

        assert!(matches!(
            pack_host_path_to_tar(&src, 100),
            Err(SandboxError::BudgetExceeded(_))
        ));

        let valid_tar = pack_host_path_to_tar(&src, 64 * 1024).unwrap();
        let dst = tmp.path().join("dst");

        // Too few max_entries.
        assert!(matches!(
            extract_tar_safely(&valid_tar, &dst, 64 * 1024, 1),
            Err(SandboxError::BudgetExceeded(_))
        ));

        // Cumulative max_bytes exceeded on second file (60 + 60 > 100).
        assert!(matches!(
            extract_tar_safely(&valid_tar, &dst, 100, 16),
            Err(SandboxError::BudgetExceeded(_))
        ));

        // Header-declared tar bomb size exceeding max_bytes.
        let mut bomb_header = tar::Header::new_gnu();
        bomb_header.set_entry_type(tar::EntryType::Regular);
        bomb_header.set_path("bomb.bin").unwrap();
        bomb_header.set_size(10_000_000);
        bomb_header.set_mode(0o644);
        bomb_header.set_cksum();
        let mut bomb_tar = bomb_header.as_bytes().to_vec();
        bomb_tar.resize(bomb_tar.len() + 1024, 0);
        assert!(matches!(
            extract_tar_safely(&bomb_tar, &dst, 1024, 16),
            Err(SandboxError::BudgetExceeded(_))
        ));

        // Truncated payload (declared 100 bytes, only 32 bytes present before EOF).
        let mut trunc_header = tar::Header::new_gnu();
        trunc_header.set_entry_type(tar::EntryType::Regular);
        trunc_header.set_path("trunc.bin").unwrap();
        trunc_header.set_size(100);
        trunc_header.set_mode(0o644);
        trunc_header.set_cksum();
        let mut trunc_tar = trunc_header.as_bytes().to_vec();
        trunc_tar.extend_from_slice(&[0x11u8; 32]);
        let trunc_res = extract_tar_safely(&trunc_tar, &dst, 1024, 16);
        assert!(trunc_res.is_err());
        assert!(!dst.join("trunc.bin").exists());
    }

    #[cfg(unix)]
    #[test]
    fn unix_pack_and_extract_reject_host_symlinks() {
        use std::os::unix::fs::symlink;

        let tmp = TestTempDir::new("safe-tar-unix-sym");
        let outside = tmp.path().join("outside");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("secret.txt"), b"secret").unwrap();

        let src = tmp.path().join("src");
        fs::create_dir_all(&src).unwrap();
        symlink(&outside, src.join("link_dir")).unwrap();
        assert!(matches!(
            pack_host_path_to_tar(&src, 64 * 1024),
            Err(SandboxError::PolicyViolation(_))
        ));

        let dst_root = tmp.path().join("dst");
        fs::create_dir_all(&dst_root).unwrap();
        symlink(&outside, dst_root.join("sub")).unwrap();
        let tar = make_raw_tar(&[(b"sub/pwn.txt", tar::EntryType::Regular, b"pwn", None)]);
        assert!(matches!(
            extract_tar_safely(&tar, &dst_root, 64 * 1024, 16),
            Err(SandboxError::PolicyViolation(_))
        ));
        assert!(!outside.join("pwn.txt").exists());
    }

    #[cfg(windows)]
    #[test]
    fn windows_pack_and_extract_reject_reparse_junctions() {
        use std::process::Command;

        let tmp = TestTempDir::new("safe-tar-win-junction");
        let outside = tmp.path().join("outside");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("secret.txt"), b"secret").unwrap();

        let src = tmp.path().join("src");
        fs::create_dir_all(&src).unwrap();
        let src_junction = src.join("junc");
        let status = Command::new("cmd")
            .args([
                "/C",
                "mklink",
                "/J",
                &src_junction.to_string_lossy(),
                &outside.to_string_lossy(),
            ])
            .status()
            .expect("invoke mklink /J");
        assert!(status.success(), "mklink /J must succeed");

        assert!(matches!(
            pack_host_path_to_tar(&src, 64 * 1024),
            Err(SandboxError::PolicyViolation(_))
        ));

        let dst_root = tmp.path().join("dst");
        fs::create_dir_all(&dst_root).unwrap();
        let dst_junction = dst_root.join("sub");
        let status2 = Command::new("cmd")
            .args([
                "/C",
                "mklink",
                "/J",
                &dst_junction.to_string_lossy(),
                &outside.to_string_lossy(),
            ])
            .status()
            .expect("invoke mklink /J");
        assert!(status2.success(), "mklink /J must succeed");

        let tar = make_raw_tar(&[(b"sub/pwn.txt", tar::EntryType::Regular, b"pwn", None)]);
        assert!(matches!(
            extract_tar_safely(&tar, &dst_root, 64 * 1024, 16),
            Err(SandboxError::PolicyViolation(_))
        ));
        assert!(!outside.join("pwn.txt").exists());

        // Junction as ancestor of dst_host itself must also be rejected.
        let nested_under_junction = dst_junction.join("nested");
        let ok_tar = make_raw_tar(&[(b"ok.txt", tar::EntryType::Regular, b"hi", None)]);
        assert!(matches!(
            extract_tar_safely(&ok_tar, &nested_under_junction, 64 * 1024, 16),
            Err(SandboxError::PolicyViolation(_))
        ));
        assert!(!outside.join("nested").exists());
    }

    #[test]
    fn measure_dir_bytes_sums_nested_files_and_ignores_symlinks_or_reparse_points() {
        let tmp = TestTempDir::new("measure-dir-bytes");
        assert_eq!(measure_dir_bytes(&tmp.path().join("missing")).unwrap(), 0);

        let root = tmp.path().join("work");
        let sub = root.join("nested");
        fs::create_dir_all(&sub).unwrap();
        fs::write(root.join("a.bin"), vec![1u8; 120]).unwrap();
        fs::write(sub.join("b.bin"), vec![2u8; 345]).unwrap();

        let outside = tmp.path().join("outside");
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("big.bin"), vec![3u8; 99_999]).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            symlink(&outside, root.join("link_out")).unwrap();
            assert!(matches!(
                measure_dir_bytes(&root.join("link_out")),
                Err(SandboxError::PolicyViolation(_))
            ));
        }

        #[cfg(windows)]
        {
            use std::process::Command;
            let junc = root.join("junc_out");
            let status = Command::new("cmd")
                .args([
                    "/C",
                    "mklink",
                    "/J",
                    &junc.to_string_lossy(),
                    &outside.to_string_lossy(),
                ])
                .status()
                .expect("invoke mklink /J");
            assert!(status.success(), "mklink /J must succeed");
            assert!(matches!(
                measure_dir_bytes(&junc),
                Err(SandboxError::PolicyViolation(_))
            ));
        }

        assert_eq!(measure_dir_bytes(&root).unwrap(), 120 + 345);
    }

    #[test]
    fn validate_tar_bytes_accepts_valid_and_rejects_traversal_links_and_budget() {
        let tmp = TestTempDir::new("validate-tar-bytes");
        let src = tmp.path().join("src");
        fs::create_dir_all(src.join("sub")).unwrap();
        fs::write(src.join("a.txt"), vec![b'a'; 60]).unwrap();
        fs::write(src.join("sub").join("b.txt"), vec![b'b'; 60]).unwrap();

        let valid_tar = pack_host_path_to_tar(&src, 64 * 1024).unwrap();
        assert_eq!(validate_tar_bytes(&valid_tar, 64 * 1024, 32).unwrap(), 120);

        for bad_path in [
            b"../escape.txt".as_slice(),
            b"/etc/passwd".as_slice(),
            b"sub\\evil.txt".as_slice(),
        ] {
            let tar = make_raw_tar(&[(bad_path, tar::EntryType::Regular, b"pwn", None)]);
            assert!(matches!(
                validate_tar_bytes(&tar, 64 * 1024, 16),
                Err(SandboxError::PolicyViolation(_))
            ));
        }

        for bad_type in [
            (
                b"sym".as_slice(),
                tar::EntryType::Symlink,
                b"".as_slice(),
                Some(b"/etc/passwd".as_slice()),
            ),
            (
                b"hard".as_slice(),
                tar::EntryType::Link,
                b"".as_slice(),
                Some(b"a.txt".as_slice()),
            ),
            (b"fifo".as_slice(), tar::EntryType::Fifo, b"".as_slice(), None),
        ] {
            let tar = make_raw_tar(&[bad_type]);
            assert!(matches!(
                validate_tar_bytes(&tar, 64 * 1024, 16),
                Err(SandboxError::PolicyViolation(_))
            ));
        }

        assert!(matches!(
            validate_tar_bytes(&valid_tar, 100, 16),
            Err(SandboxError::BudgetExceeded(_))
        ));
        assert!(matches!(
            validate_tar_bytes(&valid_tar, 64 * 1024, 1),
            Err(SandboxError::BudgetExceeded(_))
        ));

        let mut trunc_header = tar::Header::new_gnu();
        trunc_header.set_entry_type(tar::EntryType::Regular);
        trunc_header.set_path("trunc.bin").unwrap();
        trunc_header.set_size(100);
        trunc_header.set_mode(0o644);
        trunc_header.set_cksum();
        let mut trunc_tar = trunc_header.as_bytes().to_vec();
        trunc_tar.extend_from_slice(&[0x11u8; 32]);
        assert!(matches!(
            validate_tar_bytes(&trunc_tar, 1024, 16),
            Err(SandboxError::InvalidSpec(_))
        ));
    }

    #[test]
    fn extract_never_mutates_hardlinked_outside_file_and_preserves_existing_file_on_truncated_tar() {
        let tmp = TestTempDir::new("hardlink-and-truncated");
        let out = tmp.path().join("out");
        fs::create_dir_all(&out).unwrap();

        let outside = tmp.path().join("outside.txt");
        fs::write(&outside, b"original").unwrap();
        fs::hard_link(&outside, out.join("linked.txt")).unwrap();

        let overwrite_tar = make_raw_tar(&[(
            b"linked.txt",
            tar::EntryType::Regular,
            b"overwritten",
            None,
        )]);
        let res = extract_tar_safely(&overwrite_tar, &out, 65536, 20);
        #[cfg(unix)]
        assert!(matches!(res, Err(SandboxError::PolicyViolation(_))));
        #[cfg(windows)]
        {
            assert_eq!(res.unwrap(), 11);
            assert_eq!(fs::read(out.join("linked.txt")).unwrap(), b"overwritten");
        }
        assert_eq!(
            fs::read(&outside).unwrap(),
            b"original",
            "hardlinked file outside destination must never be modified"
        );

        let valuable = out.join("valuable.txt");
        fs::write(&valuable, b"original").unwrap();
        let mut truncated = make_raw_tar(&[(
            b"valuable.txt",
            tar::EntryType::Regular,
            b"new contents",
            None,
        )]);
        truncated.truncate(515);

        let err = extract_tar_safely(&truncated, &out, 65536, 20);
        assert!(matches!(err, Err(SandboxError::InvalidSpec(_))));
        assert_eq!(
            fs::read(&valuable).unwrap(),
            b"original",
            "truncated archive must never clobber or delete pre-existing destination file"
        );
        let has_leftover_tmp = fs::read_dir(&out)
            .unwrap()
            .filter_map(Result::ok)
            .any(|e| {
                e.file_name()
                    .to_string_lossy()
                    .starts_with(".minipod-extract-")
            });
        assert!(
            !has_leftover_tmp,
            "temporary staged file must be removed on error"
        );
    }

    #[test]
    fn windows_segment_rules_reject_extended_devices_superscripts_trailing_dots_and_spaces() {
        let forbidden = [
            "CON",
            "PRN",
            "AUX",
            "NUL",
            "CONIN$",
            "conin$.txt",
            "CONOUT$",
            "CLOCK$",
            "clock$.log",
            "NUL .txt",
            "COM1 .log",
            "COM\u{00B9}",
            "com\u{00B2}.txt",
            "COM\u{00B3}",
            "LPT\u{00B9}",
            "LPT\u{00B2}",
            "lpt\u{00B3}.dat",
            "trailing.",
            "trailing ",
            "dots...",
            "file.txt:ads",
            "bad*glob",
            "bad?char",
            "ctrl\x07bell",
        ];
        for seg in forbidden {
            assert!(
                is_windows_invalid_segment(seg),
                "expected Windows segment check to reject {seg:?}"
            );
        }

        let allowed = [
            "COM0",
            "COM10",
            "LPT0",
            "LPT10",
            "CONSOLE",
            "CONIN",
            "CONOUT",
            "CLOCK",
            "my file.txt",
            ".gitignore",
        ];
        for seg in allowed {
            assert!(
                !is_windows_invalid_segment(seg),
                "expected Windows segment check to allow {seg:?}"
            );
        }

        #[cfg(windows)]
        {
            let tmp = TestTempDir::new("win-ext-devices");
            let dst = tmp.path().join("dst");
            fs::create_dir_all(&dst).unwrap();

            for raw in [
                "CONIN$".as_bytes(),
                "CONOUT$.txt".as_bytes(),
                "CLOCK$".as_bytes(),
                "COM\u{00B9}".as_bytes(),
                "LPT\u{00B3}.log".as_bytes(),
                "NUL .txt".as_bytes(),
                "sneaky. ".as_bytes(),
                "sneaky.".as_bytes(),
            ] {
                let tar = make_raw_tar(&[(raw, tar::EntryType::Regular, b"x", None)]);
                assert!(
                    matches!(
                        extract_tar_safely(&tar, &dst, 64 * 1024, 16),
                        Err(SandboxError::PolicyViolation(_))
                    ),
                    "expected PolicyViolation extracting {:?}",
                    String::from_utf8_lossy(raw)
                );
            }

            assert!(matches!(
                ensure_safe_dir_path(&tmp.path().join("CONIN$"), true),
                Err(SandboxError::PolicyViolation(_))
            ));
            assert!(matches!(
                ensure_safe_dir_path(&tmp.path().join("dir. "), true),
                Err(SandboxError::PolicyViolation(_))
            ));
        }
    }

    #[test]
    fn pack_and_extract_enforce_directory_depth_and_pack_entry_caps() {
        let tmp = TestTempDir::new("depth-and-entry-caps");
        let src = tmp.path().join("src");
        let deep = src.join("d1").join("d2").join("d3");
        fs::create_dir_all(&deep).unwrap();
        fs::write(deep.join("leaf.txt"), b"ok").unwrap();

        // 4 segments (`d1/d2/d3/leaf.txt`): allowed at max_depth=4, rejected at max_depth=3.
        assert!(pack_host_path_to_tar_with_limits(&src, 64 * 1024, 16, 4).is_ok());
        assert!(matches!(
            pack_host_path_to_tar_with_limits(&src, 64 * 1024, 16, 3),
            Err(SandboxError::PolicyViolation(_))
        ));

        // 4 planned entries (`d1`, `d1/d2`, `d1/d2/d3`, `d1/d2/d3/leaf.txt`): rejected at max_entries=3.
        assert!(matches!(
            pack_host_path_to_tar_with_limits(&src, 64 * 1024, 3, 16),
            Err(SandboxError::BudgetExceeded(_))
        ));

        // Archive entry exceeding `MAX_TAR_DIRECTORY_DEPTH` (129 segments via GNU LongName).
        let mut long_path = "d/".repeat(MAX_TAR_DIRECTORY_DEPTH);
        long_path.push_str("leaf.txt\0");
        let deep_tar = make_raw_tar(&[
            (
                b"././@LongLink",
                tar::EntryType::GNULongName,
                long_path.as_bytes(),
                None,
            ),
            (b"leaf.txt", tar::EntryType::Regular, b"x", None),
        ]);
        let dst = tmp.path().join("dst");
        assert!(matches!(
            validate_tar_bytes(&deep_tar, 64 * 1024, 16),
            Err(SandboxError::PolicyViolation(_))
        ));
        assert!(matches!(
            extract_tar_safely(&deep_tar, &dst, 64 * 1024, 16),
            Err(SandboxError::PolicyViolation(_))
        ));
    }
}
