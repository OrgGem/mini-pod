//! Durable crash-recovery journal (`v1` escaped KV files with atomic write/rename)
//! and exponential-backoff artifact cleanup.

use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use sandbox_core::{DestroyStatus, SandboxError, SandboxId};

use crate::safe_tar::{ensure_safe_dir_path, reject_symlink_or_reparse};
use crate::{is_symlink_or_reparse, map_fs_error};

const JOURNAL_FORMAT_VERSION: &str = "1";
const JOURNAL_EXT: &str = ".journal";
const MAX_JOURNAL_FILE_BYTES: usize = 1024 * 1024;
const MAX_SANDBOX_ID_LEN: usize = 128;
const MAX_BACKOFF_DELAY: Duration = Duration::from_secs(5);

/// Durable sandbox lifecycle phase persisted across daemon crashes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JournalLifecycleState {
    Spawning,
    Active,
    Destroying,
}

impl JournalLifecycleState {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Spawning => "spawning",
            Self::Active => "active",
            Self::Destroying => "destroying",
        }
    }

    fn parse(raw: &str) -> Result<Self, SandboxError> {
        match raw {
            "spawning" => Ok(Self::Spawning),
            "active" => Ok(Self::Active),
            "destroying" => Ok(Self::Destroying),
            other => Err(SandboxError::InvalidSpec(format!(
                "unknown journal lifecycle state '{other}'"
            ))),
        }
    }
}

/// Crash-recovery record for a single sandbox instance.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalRecord {
    pub sandbox_id: SandboxId,
    pub state: JournalLifecycleState,
    pub pid: Option<u32>,
    pub start_token: Option<u64>,
    pub artifact_paths: Vec<PathBuf>,
    pub expires_at_unix_ms: u64,
}

/// File-backed atomic journal store in a dedicated owner-only host directory.
#[derive(Clone, Debug)]
pub struct JournalStore {
    root_dir: PathBuf,
}

impl JournalStore {
    /// Creates or opens a [`JournalStore`] at `root_dir`, refusing symlinks and Windows reparse points.
    pub fn new(root_dir: impl Into<PathBuf>) -> Result<Self, SandboxError> {
        let root_dir = root_dir.into();
        ensure_safe_dir_path(&root_dir, true)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root_dir, fs::Permissions::from_mode(0o700)).map_err(|err| {
                map_fs_error(&root_dir, "set journal directory permissions", err)
            })?;
        }
        Ok(Self { root_dir })
    }

    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }

    /// Atomically persists `record` (`<id>.journal.tmp` -> `write_all` -> `sync_all` -> `rename`
    /// -> parent directory `sync_all` on Unix).
    pub fn write_record(&self, record: &JournalRecord) -> Result<(), SandboxError> {
        validate_sandbox_id_filename(&record.sandbox_id)?;
        ensure_safe_dir_path(&self.root_dir, true)?;

        let encoded = encode_record(record)?;
        let stem = record.sandbox_id.as_str();
        let tmp_path = self.root_dir.join(format!("{stem}{JOURNAL_EXT}.tmp"));
        let final_path = self.root_dir.join(format!("{stem}{JOURNAL_EXT}"));

        ensure_target_not_link_if_exists(&tmp_path)?;
        ensure_target_not_link_if_exists(&final_path)?;

        let mut opts = OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }

        let mut file = opts
            .open(&tmp_path)
            .map_err(|err| map_fs_error(&tmp_path, "open temporary journal file", err))?;
        let meta = file
            .metadata()
            .map_err(|err| map_fs_error(&tmp_path, "inspect temporary journal file", err))?;
        reject_symlink_or_reparse(&tmp_path, &meta)?;
        if !meta.file_type().is_file() {
            return Err(SandboxError::PolicyViolation(format!(
                "temporary journal path '{}' is not a regular file",
                tmp_path.display()
            )));
        }

        file.write_all(encoded.as_bytes())
            .map_err(|err| map_fs_error(&tmp_path, "write temporary journal file", err))?;
        file.sync_all()
            .map_err(|err| map_fs_error(&tmp_path, "sync temporary journal file", err))?;
        drop(file);

        fs::rename(&tmp_path, &final_path)
            .map_err(|err| map_fs_error(&final_path, "atomically commit journal record", err))?;

        sync_dir_unix(&self.root_dir)?;
        Ok(())
    }

    /// Loads all committed `.journal` records for startup reconciliation, skipping `*.tmp` files.
    pub fn load_records(&self) -> Result<Vec<JournalRecord>, SandboxError> {
        if !self.check_root_exists_and_safe()? {
            return Ok(Vec::new());
        }

        let entries = fs::read_dir(&self.root_dir)
            .map_err(|err| map_fs_error(&self.root_dir, "read journal directory", err))?;

        let mut records = Vec::new();
        for entry_res in entries {
            let entry = entry_res
                .map_err(|err| map_fs_error(&self.root_dir, "iterate journal directory", err))?;
            let file_name_os = entry.file_name();
            let Some(file_name) = file_name_os.to_str() else {
                continue;
            };
            if file_name.ends_with(".tmp") {
                continue;
            }
            let Some(stem) = file_name.strip_suffix(JOURNAL_EXT) else {
                continue;
            };

            let record = self.read_and_decode_record(&entry.path(), stem)?;
            records.push(record);
        }

        records.sort_by(|a, b| a.sandbox_id.cmp(&b.sandbox_id));
        Ok(records)
    }

    /// Loads a single committed `.journal` record by sandbox ID, if present.
    pub fn load_record(&self, id: &SandboxId) -> Result<Option<JournalRecord>, SandboxError> {
        validate_sandbox_id_filename(id)?;
        if !self.check_root_exists_and_safe()? {
            return Ok(None);
        }
        let stem = id.as_str();
        let path = self.root_dir.join(format!("{stem}{JOURNAL_EXT}"));
        match fs::symlink_metadata(&path) {
            Ok(_) => self.read_and_decode_record(&path, stem).map(Some),
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
            Err(err) => Err(map_fs_error(&path, "inspect journal file", err)),
        }
    }

    fn check_root_exists_and_safe(&self) -> Result<bool, SandboxError> {
        match fs::symlink_metadata(&self.root_dir) {
            Ok(meta) => {
                reject_symlink_or_reparse(&self.root_dir, &meta)?;
                if !meta.file_type().is_dir() {
                    return Err(SandboxError::PolicyViolation(format!(
                        "journal root '{}' is not a directory",
                        self.root_dir.display()
                    )));
                }
                Ok(true)
            }
            Err(err) if err.kind() == ErrorKind::NotFound => Ok(false),
            Err(err) => Err(map_fs_error(&self.root_dir, "inspect journal root", err)),
        }
    }

    fn read_and_decode_record(
        &self,
        path: &Path,
        expected_stem: &str,
    ) -> Result<JournalRecord, SandboxError> {
        let meta = fs::symlink_metadata(path)
            .map_err(|err| map_fs_error(path, "inspect journal file", err))?;
        reject_symlink_or_reparse(path, &meta)?;
        if !meta.file_type().is_file() {
            return Err(SandboxError::PolicyViolation(format!(
                "journal entry '{}' is not a regular file",
                path.display()
            )));
        }
        if meta.len() > MAX_JOURNAL_FILE_BYTES as u64 {
            return Err(SandboxError::InvalidSpec(format!(
                "journal file '{}' exceeds max size ({} bytes)",
                path.display(),
                MAX_JOURNAL_FILE_BYTES
            )));
        }

        let file = File::open(path).map_err(|err| map_fs_error(path, "open journal file", err))?;
        let open_meta = file
            .metadata()
            .map_err(|err| map_fs_error(path, "inspect opened journal file", err))?;
        reject_symlink_or_reparse(path, &open_meta)?;

        let mut raw = Vec::new();
        file.take((MAX_JOURNAL_FILE_BYTES as u64).saturating_add(1))
            .read_to_end(&mut raw)
            .map_err(|err| map_fs_error(path, "read journal file", err))?;
        if raw.len() > MAX_JOURNAL_FILE_BYTES {
            return Err(SandboxError::InvalidSpec(format!(
                "journal file '{}' exceeds max size ({} bytes)",
                path.display(),
                MAX_JOURNAL_FILE_BYTES
            )));
        }

        let text = String::from_utf8(raw).map_err(|_| {
            SandboxError::InvalidSpec(format!(
                "journal file '{}' contains invalid UTF-8",
                path.display()
            ))
        })?;
        let record = decode_record(&text)?;
        if record.sandbox_id.as_str() != expected_stem {
            return Err(SandboxError::InvalidSpec(format!(
                "journal file '{}' sandbox_id mismatch ('{}')",
                path.display(),
                record.sandbox_id
            )));
        }
        Ok(record)
    }

    /// Returns the total physical byte footprint of `<id>.journal` (and any `.tmp`) on disk.
    pub fn record_disk_bytes(&self, id: &SandboxId) -> Result<u64, SandboxError> {
        validate_sandbox_id_filename(id)?;
        let stem = id.as_str();
        let mut total: u64 = 0;
        for path in [
            self.root_dir.join(format!("{stem}{JOURNAL_EXT}")),
            self.root_dir.join(format!("{stem}{JOURNAL_EXT}.tmp")),
        ] {
            match fs::symlink_metadata(&path) {
                Ok(meta) => {
                    if !is_symlink_or_reparse(&meta) && meta.file_type().is_file() {
                        total = total.saturating_add(meta.len());
                    }
                }
                Err(err) if err.kind() == ErrorKind::NotFound => {}
                Err(err) => return Err(map_fs_error(&path, "inspect journal file size", err)),
            }
        }
        Ok(total)
    }

    /// Idempotently removes a sandbox's committed journal (and any leftover `.tmp` file).
    pub fn remove_record(&self, id: &SandboxId) -> Result<(), SandboxError> {
        validate_sandbox_id_filename(id)?;
        let stem = id.as_str();
        let final_path = self.root_dir.join(format!("{stem}{JOURNAL_EXT}"));
        let tmp_path = self.root_dir.join(format!("{stem}{JOURNAL_EXT}.tmp"));

        let removed_final = remove_file_idempotent(&final_path)?;
        let _ = remove_file_idempotent(&tmp_path)?;
        if removed_final {
            sync_dir_unix(&self.root_dir)?;
        }
        Ok(())
    }
}

/// Attempts to delete all `paths` (files and directories, never following symlinks/reparse points),
/// retrying transient failures (such as Windows sharing violations right after `TerminateProcess`)
/// with capped exponential backoff (`initial_delay * 2^attempt`).
pub async fn cleanup_artifacts_with_backoff(
    paths: &[PathBuf],
    max_attempts: usize,
    initial_delay: Duration,
) -> DestroyStatus {
    if paths.is_empty() {
        return DestroyStatus::AllResourcesCleaned;
    }

    let mut remaining = paths.to_vec();
    if max_attempts == 0 {
        remaining.retain(|p| path_exists_no_follow(p));
        return if remaining.is_empty() {
            DestroyStatus::AllResourcesCleaned
        } else {
            DestroyStatus::ProcessExited {
                remaining_artifacts: remaining,
            }
        };
    }

    for attempt in 0..max_attempts {
        let candidates = remaining.clone();
        match tokio::task::spawn_blocking(move || remove_paths_once(candidates)).await {
            Ok(left) => remaining = left,
            Err(_) => {
                return DestroyStatus::ProcessExited {
                    remaining_artifacts: remaining,
                };
            }
        }

        if remaining.is_empty() {
            return DestroyStatus::AllResourcesCleaned;
        }
        if attempt + 1 < max_attempts && !initial_delay.is_zero() {
            let factor = 1u32.checked_shl(attempt.min(30) as u32).unwrap_or(u32::MAX);
            let delay = initial_delay.saturating_mul(factor).min(MAX_BACKOFF_DELAY);
            tokio::time::sleep(delay).await;
        }
    }

    DestroyStatus::ProcessExited {
        remaining_artifacts: remaining,
    }
}

fn remove_paths_once(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut remaining = Vec::new();
    for path in paths {
        if !remove_single_artifact(&path) {
            remaining.push(path);
        }
    }
    remaining
}

fn remove_single_artifact(path: &Path) -> bool {
    let meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == ErrorKind::NotFound => return true,
        Err(_) => return false,
    };

    if is_symlink_or_reparse(&meta) {
        return remove_link_entry_only(path, &meta);
    }
    if meta.file_type().is_dir() {
        match fs::remove_dir_all(path) {
            Ok(()) => true,
            Err(err) if err.kind() == ErrorKind::NotFound => true,
            Err(_) => false,
        }
    } else {
        match fs::remove_file(path) {
            Ok(()) => true,
            Err(err) if err.kind() == ErrorKind::NotFound => true,
            Err(_) => false,
        }
    }
}

fn remove_link_entry_only(path: &Path, meta: &fs::Metadata) -> bool {
    #[cfg(windows)]
    let res = {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;
        if (meta.file_attributes() & FILE_ATTRIBUTE_DIRECTORY) != 0 {
            fs::remove_dir(path)
        } else {
            fs::remove_file(path)
        }
    };
    #[cfg(not(windows))]
    let res = {
        let _ = meta;
        fs::remove_file(path)
    };
    match res {
        Ok(()) => true,
        Err(err) if err.kind() == ErrorKind::NotFound => true,
        Err(_) => false,
    }
}

fn path_exists_no_follow(path: &Path) -> bool {
    !matches!(fs::symlink_metadata(path), Err(err) if err.kind() == ErrorKind::NotFound)
}

fn validate_sandbox_id_filename(id: &SandboxId) -> Result<(), SandboxError> {
    let s = id.as_str();
    if s.is_empty() || s.len() > MAX_SANDBOX_ID_LEN {
        return Err(SandboxError::InvalidSpec(format!(
            "sandbox_id '{s}' length must be in 1..={MAX_SANDBOX_ID_LEN}"
        )));
    }
    if s.starts_with('.') || s.contains("..") {
        return Err(SandboxError::InvalidSpec(format!(
            "sandbox_id '{s}' must not start with '.' or contain '..'"
        )));
    }
    if !s
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err(SandboxError::InvalidSpec(format!(
            "sandbox_id '{s}' contains unsupported characters for journal filename"
        )));
    }
    Ok(())
}

fn ensure_target_not_link_if_exists(path: &Path) -> Result<(), SandboxError> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            reject_symlink_or_reparse(path, &meta)?;
            if !meta.file_type().is_file() {
                return Err(SandboxError::PolicyViolation(format!(
                    "journal target '{}' exists and is not a regular file",
                    path.display()
                )));
            }
            Ok(())
        }
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
        Err(err) => Err(map_fs_error(path, "inspect journal file target", err)),
    }
}

fn remove_file_idempotent(path: &Path) -> Result<bool, SandboxError> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            reject_symlink_or_reparse(path, &meta)?;
            match fs::remove_file(path) {
                Ok(()) => Ok(true),
                Err(err) if err.kind() == ErrorKind::NotFound => Ok(false),
                Err(err) => Err(map_fs_error(path, "remove journal file", err)),
            }
        }
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(false),
        Err(err) => Err(map_fs_error(path, "inspect journal file for removal", err)),
    }
}

fn sync_dir_unix(dir: &Path) -> Result<(), SandboxError> {
    #[cfg(unix)]
    {
        let dir_handle =
            File::open(dir).map_err(|err| map_fs_error(dir, "open journal directory for sync", err))?;
        dir_handle
            .sync_all()
            .map_err(|err| map_fs_error(dir, "sync journal directory", err))?;
    }
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

fn encode_record(record: &JournalRecord) -> Result<String, SandboxError> {
    let mut out = String::new();
    writeln!(out, "version={JOURNAL_FORMAT_VERSION}")
        .map_err(|e| SandboxError::Internal(e.to_string()))?;
    writeln!(
        out,
        "sandbox_id={}",
        escape_bytes(record.sandbox_id.as_str().as_bytes())
    )
    .map_err(|e| SandboxError::Internal(e.to_string()))?;
    writeln!(out, "state={}", record.state.as_str())
        .map_err(|e| SandboxError::Internal(e.to_string()))?;
    match record.pid {
        Some(pid) => writeln!(out, "pid={pid}"),
        None => writeln!(out, "pid=none"),
    }
    .map_err(|e| SandboxError::Internal(e.to_string()))?;
    match record.start_token {
        Some(tok) => writeln!(out, "start_token={tok}"),
        None => writeln!(out, "start_token=none"),
    }
    .map_err(|e| SandboxError::Internal(e.to_string()))?;
    writeln!(out, "expires_at_unix_ms={}", record.expires_at_unix_ms)
        .map_err(|e| SandboxError::Internal(e.to_string()))?;
    writeln!(out, "artifact_count={}", record.artifact_paths.len())
        .map_err(|e| SandboxError::Internal(e.to_string()))?;

    for path in &record.artifact_paths {
        let escaped = escape_path(path)?;
        writeln!(out, "artifact={escaped}").map_err(|e| SandboxError::Internal(e.to_string()))?;
    }
    Ok(out)
}

fn decode_record(text: &str) -> Result<JournalRecord, SandboxError> {
    if text.contains('\r') {
        return Err(SandboxError::InvalidSpec(
            "journal record must use LF line endings".to_owned(),
        ));
    }
    let body = text.strip_suffix('\n').ok_or_else(|| {
        SandboxError::InvalidSpec("journal record must end with trailing LF".to_owned())
    })?;
    let mut lines = body.split('\n');

    let version = expect_kv(&mut lines, "version")?;
    if version != JOURNAL_FORMAT_VERSION {
        return Err(SandboxError::InvalidSpec(format!(
            "unsupported journal version '{version}'; expected '{JOURNAL_FORMAT_VERSION}'"
        )));
    }

    let id_bytes = unescape_bytes(expect_kv(&mut lines, "sandbox_id")?)?;
    let id_str = String::from_utf8(id_bytes).map_err(|_| {
        SandboxError::InvalidSpec("journal sandbox_id is not valid UTF-8".to_owned())
    })?;
    let sandbox_id = SandboxId::new(id_str);
    validate_sandbox_id_filename(&sandbox_id)?;

    let state = JournalLifecycleState::parse(expect_kv(&mut lines, "state")?)?;
    let pid = match expect_kv(&mut lines, "pid")? {
        "none" => None,
        raw => Some(raw.parse::<u32>().map_err(|err| {
            SandboxError::InvalidSpec(format!("invalid journal pid '{raw}': {err}"))
        })?),
    };
    let start_token = match expect_kv(&mut lines, "start_token")? {
        "none" => None,
        raw => Some(raw.parse::<u64>().map_err(|err| {
            SandboxError::InvalidSpec(format!("invalid journal start_token '{raw}': {err}"))
        })?),
    };
    let expires_raw = expect_kv(&mut lines, "expires_at_unix_ms")?;
    let expires_at_unix_ms = expires_raw.parse::<u64>().map_err(|err| {
        SandboxError::InvalidSpec(format!(
            "invalid journal expires_at_unix_ms '{expires_raw}': {err}"
        ))
    })?;

    let count_raw = expect_kv(&mut lines, "artifact_count")?;
    let artifact_count = count_raw.parse::<usize>().map_err(|err| {
        SandboxError::InvalidSpec(format!("invalid journal artifact_count '{count_raw}': {err}"))
    })?;

    let mut artifact_paths = Vec::with_capacity(artifact_count.min(1024));
    for _ in 0..artifact_count {
        let escaped = expect_kv(&mut lines, "artifact")?;
        artifact_paths.push(unescape_path(escaped)?);
    }

    if let Some(extra) = lines.next() {
        return Err(SandboxError::InvalidSpec(format!(
            "unexpected trailing line in journal record: '{extra}'"
        )));
    }

    Ok(JournalRecord {
        sandbox_id,
        state,
        pid,
        start_token,
        artifact_paths,
        expires_at_unix_ms,
    })
}

fn expect_kv<'a>(lines: &mut std::str::Split<'a, char>, key: &str) -> Result<&'a str, SandboxError> {
    let line = lines.next().ok_or_else(|| {
        SandboxError::InvalidSpec(format!("missing expected journal field '{key}'"))
    })?;
    let Some((actual_key, value)) = line.split_once('=') else {
        return Err(SandboxError::InvalidSpec(format!(
            "malformed journal line '{line}'; expected '{key}=...'"
        )));
    };
    if actual_key != key {
        return Err(SandboxError::InvalidSpec(format!(
            "unexpected journal key '{actual_key}'; expected '{key}'"
        )));
    }
    Ok(value)
}

fn escape_path(path: &Path) -> Result<String, SandboxError> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        Ok(escape_bytes(path.as_os_str().as_bytes()))
    }
    #[cfg(not(unix))]
    {
        let s = path.to_str().ok_or_else(|| {
            SandboxError::InvalidSpec(format!(
                "artifact path '{}' contains non-Unicode characters",
                path.display()
            ))
        })?;
        Ok(escape_bytes(s.as_bytes()))
    }
}

fn unescape_path(raw: &str) -> Result<PathBuf, SandboxError> {
    let bytes = unescape_bytes(raw)?;
    #[cfg(unix)]
    {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        Ok(PathBuf::from(OsString::from_vec(bytes)))
    }
    #[cfg(not(unix))]
    {
        let s = String::from_utf8(bytes).map_err(|_| {
            SandboxError::InvalidSpec("journal artifact path is not valid UTF-8".to_owned())
        })?;
        Ok(PathBuf::from(s))
    }
}

fn escape_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for &b in bytes {
        if !b.is_ascii() || b == b'%' || b < 0x20 || b == 0x7F {
            let _ = write!(out, "%{b:02X}");
        } else {
            out.push(b as char);
        }
    }
    out
}

fn unescape_bytes(raw: &str) -> Result<Vec<u8>, SandboxError> {
    let input = raw.as_bytes();
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'%' {
            if i + 2 >= input.len() {
                return Err(SandboxError::InvalidSpec(
                    "truncated percent-escape sequence in journal field".to_owned(),
                ));
            }
            let hi = hex_nibble(input[i + 1])?;
            let lo = hex_nibble(input[i + 2])?;
            out.push((hi << 4) | lo);
            i += 3;
        } else {
            out.push(input[i]);
            i += 1;
        }
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, SandboxError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(SandboxError::InvalidSpec(format!(
            "invalid hex digit '{}' in journal percent-escape",
            b as char
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::TestTempDir;

    #[test]
    fn journal_store_roundtrip_unicode_spaces_ignores_tmp_and_remove_is_idempotent() {
        let tmp = TestTempDir::new("journal-rt");
        let store = JournalStore::new(tmp.path().join("journals")).unwrap();

        let rec1 = JournalRecord {
            sandbox_id: SandboxId::new("sb-alpha_01"),
            state: JournalLifecycleState::Spawning,
            pid: None,
            start_token: None,
            artifact_paths: vec![
                PathBuf::from(r"C:\Users\Việt Nam\mini pod\đĩa 1.qcow2"),
                PathBuf::from("/tmp/mini pod/tệp 🚀\nwith=special%chars"),
            ],
            expires_at_unix_ms: 1_700_000_000_123,
        };
        let rec2 = JournalRecord {
            sandbox_id: SandboxId::new("sb-beta-02"),
            state: JournalLifecycleState::Active,
            pid: Some(42_123),
            start_token: Some(9_876_543_210),
            artifact_paths: vec![tmp.path().join("disk two.qcow2")],
            expires_at_unix_ms: 1_700_000_999_999,
        };

        store.write_record(&rec1).unwrap();
        store.write_record(&rec2).unwrap();

        // Simulate crash mid-write leaving a corrupt `.tmp` file.
        fs::write(store.root_dir().join("sb-gamma.journal.tmp"), b"corrupt-partial").unwrap();

        let loaded = store.load_records().unwrap();
        assert_eq!(loaded, vec![rec1.clone(), rec2.clone()]);

        // Overwrite rec1 atomically.
        let rec1_updated = JournalRecord {
            state: JournalLifecycleState::Destroying,
            pid: Some(99),
            start_token: Some(1234),
            ..rec1.clone()
        };
        store.write_record(&rec1_updated).unwrap();
        let loaded2 = store.load_records().unwrap();
        assert_eq!(loaded2, vec![rec1_updated, rec2.clone()]);

        // Idempotent removal.
        assert!(store.record_disk_bytes(&rec1.sandbox_id).unwrap() > 0);
        store.remove_record(&rec1.sandbox_id).unwrap();
        assert_eq!(store.record_disk_bytes(&rec1.sandbox_id).unwrap(), 0);
        store.remove_record(&rec1.sandbox_id).unwrap();
        assert_eq!(store.load_records().unwrap(), vec![rec2]);
    }

    #[test]
    fn journal_store_rejects_unsafe_ids_and_corrupt_journal_files() {
        let tmp = TestTempDir::new("journal-invalid");
        let store = JournalStore::new(tmp.path().join("journals")).unwrap();

        for bad_id in ["", ".", "..", ".hidden", "../escape", "a/b", "a\\b"] {
            let rec = JournalRecord {
                sandbox_id: SandboxId::new(bad_id),
                state: JournalLifecycleState::Spawning,
                pid: None,
                start_token: None,
                artifact_paths: Vec::new(),
                expires_at_unix_ms: 1,
            };
            assert!(matches!(
                store.write_record(&rec),
                Err(SandboxError::InvalidSpec(_))
            ));
        }

        fs::write(store.root_dir().join("bad.journal"), b"version=99\n").unwrap();
        assert!(matches!(
            store.load_records(),
            Err(SandboxError::InvalidSpec(_))
        ));
    }

    #[tokio::test]
    async fn cleanup_artifacts_with_backoff_cleans_files_dirs_and_missing_paths() {
        let tmp = TestTempDir::new("cleanup-ok");
        let file_path = tmp.path().join("overlay.qcow2");
        let dir_path = tmp.path().join("sandbox-work");
        fs::create_dir_all(dir_path.join("sub")).unwrap();
        fs::write(&file_path, b"qcow2").unwrap();
        fs::write(dir_path.join("sub").join("log.txt"), b"hello").unwrap();
        let missing = tmp.path().join("already-gone.sock");

        let status = cleanup_artifacts_with_backoff(
            &[file_path.clone(), dir_path.clone(), missing],
            3,
            Duration::from_millis(2),
        )
        .await;
        assert_eq!(status, DestroyStatus::AllResourcesCleaned);
        assert!(!file_path.exists());
        assert!(!dir_path.exists());
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn cleanup_artifacts_with_backoff_retries_locked_file_until_released() {
        use std::os::windows::fs::OpenOptionsExt;

        let tmp = TestTempDir::new("cleanup-win-lock");
        let locked_file_path = tmp.path().join("in_use.qcow2");
        let handle = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .share_mode(0)
            .open(&locked_file_path)
            .unwrap();

        // Exhaust attempts while file is locked with share_mode(0) (sharing violation).
        let status = cleanup_artifacts_with_backoff(
            std::slice::from_ref(&locked_file_path),
            2,
            Duration::from_millis(5),
        )
        .await;
        assert_eq!(
            status,
            DestroyStatus::ProcessExited {
                remaining_artifacts: vec![locked_file_path.clone()],
            }
        );

        // Release the handle asynchronously so retry succeeds with exponential backoff.
        let releaser = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(25)).await;
            drop(handle);
        });

        let status_after = cleanup_artifacts_with_backoff(
            std::slice::from_ref(&locked_file_path),
            8,
            Duration::from_millis(10),
        )
        .await;
        releaser.await.unwrap();
        assert_eq!(status_after, DestroyStatus::AllResourcesCleaned);
        assert!(!locked_file_path.exists());
    }
}
