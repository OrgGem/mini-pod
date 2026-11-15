//! Safe tar-based `CopyInStart` and `CopyOutStart` handlers.
//!
//! Enforces strict path traversal & entry-type invariants:
//! - Rejects `..`, non-UTF-8/NUL/backslash tar paths, absolute tar entries, symlinks,
//!   hardlinks, FIFOs, sockets, device nodes, and Windows reparse points.
//! - Walks existing destination and source path components individually to forbid
//!   traversing existing symlinks (`O_NOFOLLOW` on Unix file opens).
//! - Enforces `max_bytes` on both wire tar stream length and extracted/emitted content.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex};
use std::time::UNIX_EPOCH;

use sandbox_protocol::{Message, StreamChannel, StreamId};

use crate::OutboundQueue;

const COPY_CHUNK_BYTES: usize = 64 * 1024;
const TAR_BLOCK_BYTES: u64 = 512;
const TAR_TRAILER_BYTES: u64 = 1024;
const MAX_COPY_IO_BUF: usize = 64 * 1024;

pub(crate) enum CopyInItem {
    Chunk { data: Vec<u8>, eof: bool },
    Abort,
}

pub(crate) struct ActiveCopyIn {
    tx: Mutex<Option<mpsc::Sender<CopyInItem>>>,
}

impl ActiveCopyIn {
    pub(crate) fn new() -> (Arc<Self>, mpsc::Receiver<CopyInItem>) {
        let (tx, rx) = mpsc::channel();
        (
            Arc::new(Self {
                tx: Mutex::new(Some(tx)),
            }),
            rx,
        )
    }

    pub(crate) fn push_chunk(&self, data: Vec<u8>, eof: bool) {
        let mut guard = self.tx.lock().unwrap_or_else(|e| e.into_inner());
        let Some(tx) = guard.as_ref() else {
            return;
        };
        if tx.send(CopyInItem::Chunk { data, eof }).is_err() || eof {
            *guard = None;
        }
    }

    pub(crate) fn abort(&self) {
        let tx = self.tx.lock().unwrap_or_else(|e| e.into_inner()).take();
        if let Some(tx) = tx {
            let _ = tx.send(CopyInItem::Abort);
        }
    }
}

pub(crate) fn run_copy_in(
    stream_id: StreamId,
    dst_guest: String,
    max_bytes: u64,
    rx: mpsc::Receiver<CopyInItem>,
    outbound: Arc<OutboundQueue>,
    active_copy_ins: Arc<Mutex<HashMap<StreamId, Arc<ActiveCopyIn>>>>,
) {
    let result = execute_copy_in(stream_id, &dst_guest, max_bytes, rx, &outbound);
    active_copy_ins
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&stream_id);
    outbound.clear_stream(stream_id);

    let reply = match result {
        Ok(bytes_transferred) => Message::CopyDone { bytes_transferred },
        Err(message) => Message::CopyError { message },
    };
    if let Err(err) = outbound.push_message(stream_id, &reply) {
        eprintln!("[sandbox-agent] copy_in stream {stream_id} failed to enqueue reply: {err}");
    }
}

pub(crate) fn run_copy_out(
    stream_id: StreamId,
    src_guest: String,
    max_bytes: u64,
    outbound: Arc<OutboundQueue>,
) {
    let result = execute_copy_out(stream_id, &src_guest, max_bytes, &outbound);
    outbound.clear_stream(stream_id);

    let reply = match result {
        Ok(bytes_transferred) => Message::CopyDone { bytes_transferred },
        Err(message) => Message::CopyError { message },
    };
    if let Err(err) = outbound.push_message(stream_id, &reply) {
        eprintln!("[sandbox-agent] copy_out stream {stream_id} failed to enqueue reply: {err}");
    }
}

fn execute_copy_in(
    stream_id: StreamId,
    dst_guest: &str,
    max_bytes: u64,
    rx: mpsc::Receiver<CopyInItem>,
    outbound: &Arc<OutboundQueue>,
) -> Result<u64, String> {
    let dst_root = validate_absolute_guest_path(dst_guest)?;
    ensure_dir_no_symlink(&dst_root, true)?;

    let mut reader = CopyInReader::new(stream_id, max_bytes, rx, outbound);
    let mut extracted_bytes: u64 = 0;

    {
        let mut archive = tar::Archive::new(&mut reader);
        let mut entries = archive
            .entries()
            .map_err(|err| format!("invalid tar stream header: {err}"))?;
        let mut copy_buf = vec![0u8; MAX_COPY_IO_BUF];

        while let Some(entry_res) = entries.next() {
            let mut entry = entry_res.map_err(|err| format!("invalid tar entry: {err}"))?;
            let entry_type = entry.header().entry_type();
            let raw_path_bytes = entry.path_bytes();
            let entry_path = entry
                .path()
                .map_err(|err| format!("invalid tar entry path: {err}"))?;
            let rel_path = validate_tar_entry_path(&raw_path_bytes, &entry_path)?;

            match entry_type {
                tar::EntryType::Directory => {
                    if let Some(rel) = rel_path {
                        create_relative_dir_no_symlink(&dst_root, &rel)?;
                    }
                }
                tar::EntryType::Regular => {
                    let rel = rel_path.ok_or_else(|| {
                        "tar regular file entry cannot target destination root '.'".to_owned()
                    })?;
                    let entry_size = entry
                        .header()
                        .size()
                        .map_err(|err| format!("invalid tar entry size: {err}"))?;
                    let next_extracted = extracted_bytes
                        .checked_add(entry_size)
                        .ok_or_else(|| "copy_in extracted byte count overflow".to_owned())?;
                    if next_extracted > max_bytes {
                        return Err(format!(
                            "copy_in extracted payload exceeds max_bytes ({next_extracted} > {max_bytes})"
                        ));
                    }

                    let file_path = prepare_parent_dirs_no_symlink(&dst_root, &rel)?;
                    let mode = entry.header().mode().unwrap_or(0o644) & 0o777;
                    let mut out_file = open_extract_file_no_symlink(&file_path)?;

                    let mut copied: u64 = 0;
                    loop {
                        let n = entry
                            .read(&mut copy_buf)
                            .map_err(|err| format!("failed reading tar entry payload: {err}"))?;
                        if n == 0 {
                            break;
                        }
                        copied = copied
                            .checked_add(n as u64)
                            .ok_or_else(|| "copy_in byte count overflow".to_owned())?;
                        let running = extracted_bytes
                            .checked_add(copied)
                            .ok_or_else(|| "copy_in extracted byte count overflow".to_owned())?;
                        if running > max_bytes {
                            return Err(format!(
                                "copy_in extracted payload exceeds max_bytes ({running} > {max_bytes})"
                            ));
                        }
                        out_file
                            .write_all(&copy_buf[..n])
                            .map_err(|err| format!("failed writing '{}': {err}", file_path.display()))?;
                    }
                    if copied != entry_size {
                        return Err(format!(
                            "truncated tar entry '{}': expected {entry_size} bytes, got {copied}",
                            rel.display()
                        ));
                    }
                    extracted_bytes = extracted_bytes
                        .checked_add(copied)
                        .ok_or_else(|| "copy_in extracted byte count overflow".to_owned())?;
                    apply_safe_file_mode(&out_file, mode)?;
                }
                tar::EntryType::Symlink => {
                    return Err(format!(
                        "tar entry '{}' uses forbidden symlink type",
                        entry_path.display()
                    ));
                }
                tar::EntryType::Link => {
                    return Err(format!(
                        "tar entry '{}' uses forbidden hardlink type",
                        entry_path.display()
                    ));
                }
                tar::EntryType::Fifo | tar::EntryType::Char | tar::EntryType::Block => {
                    return Err(format!(
                        "tar entry '{}' uses forbidden special device/FIFO type {:?}",
                        entry_path.display(),
                        entry_type
                    ));
                }
                other => {
                    return Err(format!(
                        "tar entry '{}' uses unsupported/forbidden entry type {:?}",
                        entry_path.display(),
                        other
                    ));
                }
            }
        }
    }

    reader.drain_to_eof()?;
    Ok(reader.wire_bytes)
}

struct CopyInReader<'a> {
    stream_id: StreamId,
    max_bytes: u64,
    wire_bytes: u64,
    rx: mpsc::Receiver<CopyInItem>,
    outbound: &'a OutboundQueue,
    buf: Vec<u8>,
    pos: usize,
    eof_seen: bool,
    sticky_err: Option<String>,
}

impl<'a> CopyInReader<'a> {
    fn new(
        stream_id: StreamId,
        max_bytes: u64,
        rx: mpsc::Receiver<CopyInItem>,
        outbound: &'a OutboundQueue,
    ) -> Self {
        Self {
            stream_id,
            max_bytes,
            wire_bytes: 0,
            rx,
            outbound,
            buf: Vec::new(),
            pos: 0,
            eof_seen: false,
            sticky_err: None,
        }
    }

    fn pull_next_chunk(&mut self) -> io::Result<bool> {
        if let Some(ref msg) = self.sticky_err {
            return Err(io::Error::new(io::ErrorKind::InvalidData, msg.clone()));
        }
        if self.eof_seen {
            return Ok(false);
        }
        loop {
            match self.rx.recv() {
                Ok(CopyInItem::Abort) | Err(_) => {
                    let msg = "copy_in stream aborted before EOF".to_owned();
                    self.sticky_err = Some(msg.clone());
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, msg));
                }
                Ok(CopyInItem::Chunk { data, eof }) => {
                    let next = self
                        .wire_bytes
                        .checked_add(data.len() as u64)
                        .ok_or_else(|| {
                            io::Error::new(io::ErrorKind::InvalidData, "copy_in byte count overflow")
                        })?;
                    if next > self.max_bytes {
                        let msg = format!(
                            "copy_in tar stream exceeds max_bytes ({next} > {})",
                            self.max_bytes
                        );
                        self.sticky_err = Some(msg.clone());
                        return Err(io::Error::new(io::ErrorKind::InvalidData, msg));
                    }
                    self.wire_bytes = next;
                    if !eof && !data.is_empty() {
                        let _ = self.outbound.send_stdin_credit(self.stream_id, data.len());
                    }
                    self.eof_seen = eof;
                    if data.is_empty() {
                        if eof {
                            return Ok(false);
                        }
                        continue;
                    }
                    self.buf = data;
                    self.pos = 0;
                    return Ok(true);
                }
            }
        }
    }

    fn drain_to_eof(&mut self) -> Result<(), String> {
        if let Some(ref msg) = self.sticky_err {
            return Err(msg.clone());
        }
        while !self.eof_seen {
            if !self.pull_next_chunk().map_err(|e| e.to_string())? {
                break;
            }
            self.pos = self.buf.len();
        }
        Ok(())
    }
}

impl Read for CopyInReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        while self.pos >= self.buf.len() {
            if !self.pull_next_chunk()? {
                return Ok(0);
            }
        }
        let avail = self.buf.len() - self.pos;
        let n = out.len().min(avail);
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

enum PlannedEntry {
    Dir { rel: PathBuf, meta: fs::Metadata },
    File { rel: PathBuf, disk_path: PathBuf },
}

fn execute_copy_out(
    stream_id: StreamId,
    src_guest: &str,
    max_bytes: u64,
    outbound: &Arc<OutboundQueue>,
) -> Result<u64, String> {
    let src_path = validate_absolute_guest_path(src_guest)?;
    ensure_existing_path_no_symlink(&src_path)?;

    let root_meta = fs::symlink_metadata(&src_path)
        .map_err(|err| format!("failed to inspect '{}': {err}", src_path.display()))?;
    if is_symlink_or_reparse(&root_meta) {
        return Err(format!(
            "copy_out source '{}' is a symlink or reparse point",
            src_path.display()
        ));
    }

    let mut plan = Vec::new();
    let mut min_tar_bytes = TAR_TRAILER_BYTES;

    if root_meta.is_file() {
        let name = src_path
            .file_name()
            .ok_or_else(|| format!("copy_out source '{}' has no filename", src_path.display()))?;
        let file_bytes = padded_tar_blocks(root_meta.len())?;
        min_tar_bytes = min_tar_bytes
            .checked_add(TAR_BLOCK_BYTES)
            .and_then(|v| v.checked_add(file_bytes))
            .ok_or_else(|| "copy_out archive size overflow".to_owned())?;
        plan.push(PlannedEntry::File {
            rel: PathBuf::from(name),
            disk_path: src_path,
        });
    } else if root_meta.is_dir() {
        collect_dir_plan(&src_path, Path::new(""), &mut plan, &mut min_tar_bytes)?;
    } else {
        return Err(format!(
            "copy_out source '{}' is not a regular file or directory",
            src_path.display()
        ));
    }

    if min_tar_bytes > max_bytes {
        return Err(format!(
            "copy_out archive size ({min_tar_bytes} bytes minimum) exceeds max_bytes ({max_bytes})"
        ));
    }

    let mut writer = TarChunkWriter::new(stream_id, max_bytes, outbound);
    {
        let mut builder = tar::Builder::new(&mut writer);
        for item in plan {
            match item {
                PlannedEntry::Dir { rel, meta } => {
                    if is_symlink_or_reparse(&meta) || !meta.is_dir() {
                        return Err(format!(
                            "copy_out entry '{}' changed into unsafe file type",
                            rel.display()
                        ));
                    }
                    let mut header = tar::Header::new_gnu();
                    header.set_entry_type(tar::EntryType::Directory);
                    header.set_size(0);
                    header.set_mode(safe_archive_mode(&meta, true));
                    header.set_mtime(mtime_secs(&meta));
                    header.set_uid(0);
                    header.set_gid(0);
                    header.set_cksum();
                    builder
                        .append_data(&mut header, &rel, io::empty())
                        .map_err(|err| format!("failed packing dir '{}': {err}", rel.display()))?;
                }
                PlannedEntry::File { rel, disk_path } => {
                    let mut file = open_source_file_no_symlink(&disk_path)?;
                    let meta = file.metadata().map_err(|err| {
                        format!("failed to stat '{}': {err}", disk_path.display())
                    })?;
                    if is_symlink_or_reparse(&meta) || !meta.is_file() {
                        return Err(format!(
                            "copy_out file '{}' is not a regular file",
                            disk_path.display()
                        ));
                    }
                    let size = meta.len();
                    let mut header = tar::Header::new_gnu();
                    header.set_entry_type(tar::EntryType::Regular);
                    header.set_size(size);
                    header.set_mode(safe_archive_mode(&meta, false));
                    header.set_mtime(mtime_secs(&meta));
                    header.set_uid(0);
                    header.set_gid(0);
                    header.set_cksum();
                    builder
                        .append_data(&mut header, &rel, (&mut file).take(size))
                        .map_err(|err| format!("failed packing file '{}': {err}", rel.display()))?;
                }
            }
        }
        builder
            .finish()
            .map_err(|err| format!("failed finalizing tar archive: {err}"))?;
    }

    writer.finish()
}

fn collect_dir_plan(
    disk_dir: &Path,
    rel_prefix: &Path,
    plan: &mut Vec<PlannedEntry>,
    min_tar_bytes: &mut u64,
) -> Result<(), String> {
    let mut children: Vec<_> = fs::read_dir(disk_dir)
        .map_err(|err| format!("failed reading directory '{}': {err}", disk_dir.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| format!("failed iterating directory '{}': {err}", disk_dir.display()))?;
    children.sort_by_key(|entry| entry.file_name());

    for child in children {
        let name = child.file_name();
        let disk_path = child.path();
        let rel_path = if rel_prefix.as_os_str().is_empty() {
            PathBuf::from(&name)
        } else {
            rel_prefix.join(&name)
        };
        let meta = fs::symlink_metadata(&disk_path)
            .map_err(|err| format!("failed to inspect '{}': {err}", disk_path.display()))?;

        if is_symlink_or_reparse(&meta) {
            return Err(format!(
                "copy_out refuses symlink or reparse point '{}'",
                disk_path.display()
            ));
        }

        if meta.is_dir() {
            *min_tar_bytes = min_tar_bytes
                .checked_add(TAR_BLOCK_BYTES)
                .ok_or_else(|| "copy_out archive size overflow".to_owned())?;
            plan.push(PlannedEntry::Dir {
                rel: rel_path.clone(),
                meta,
            });
            collect_dir_plan(&disk_path, &rel_path, plan, min_tar_bytes)?;
        } else if meta.is_file() {
            let file_blocks = padded_tar_blocks(meta.len())?;
            *min_tar_bytes = min_tar_bytes
                .checked_add(TAR_BLOCK_BYTES)
                .and_then(|v| v.checked_add(file_blocks))
                .ok_or_else(|| "copy_out archive size overflow".to_owned())?;
            plan.push(PlannedEntry::File {
                rel: rel_path,
                disk_path,
            });
        } else {
            return Err(format!(
                "copy_out refuses non-regular filesystem entry '{}'",
                disk_path.display()
            ));
        }
    }
    Ok(())
}

struct TarChunkWriter<'a> {
    stream_id: StreamId,
    max_bytes: u64,
    total_bytes: u64,
    buf: Vec<u8>,
    outbound: &'a OutboundQueue,
}

impl<'a> TarChunkWriter<'a> {
    fn new(stream_id: StreamId, max_bytes: u64, outbound: &'a OutboundQueue) -> Self {
        Self {
            stream_id,
            max_bytes,
            total_bytes: 0,
            buf: Vec::with_capacity(COPY_CHUNK_BYTES),
            outbound,
        }
    }

    fn finish(self) -> Result<u64, String> {
        self.outbound
            .send_stream_data_final(self.stream_id, StreamChannel::Stdout, &self.buf)
            .map_err(|err| format!("failed streaming final copy_out chunk: {err}"))?;
        Ok(self.total_bytes)
    }
}

impl Write for TarChunkWriter<'_> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        let next = self
            .total_bytes
            .checked_add(data.len() as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "copy_out size overflow"))?;
        if next > self.max_bytes {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("copy_out archive exceeds max_bytes ({next} > {})", self.max_bytes),
            ));
        }
        self.total_bytes = next;
        self.buf.extend_from_slice(data);

        while self.buf.len() >= COPY_CHUNK_BYTES {
            let tail = self.buf.split_off(COPY_CHUNK_BYTES);
            let chunk = std::mem::replace(&mut self.buf, tail);
            self.outbound
                .send_stream_data(self.stream_id, StreamChannel::Stdout, &chunk)
                .map_err(|err| io::Error::new(io::ErrorKind::BrokenPipe, err.to_string()))?;
        }
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn padded_tar_blocks(size: u64) -> Result<u64, String> {
    let rem = size % TAR_BLOCK_BYTES;
    if rem == 0 {
        Ok(size)
    } else {
        size.checked_add(TAR_BLOCK_BYTES - rem)
            .ok_or_else(|| "tar entry block padding overflow".to_owned())
    }
}

fn validate_absolute_guest_path(raw: &str) -> Result<PathBuf, String> {
    if raw.is_empty() || raw.contains('\0') {
        return Err("copy path must be non-empty and must not contain NUL".to_owned());
    }
    let path = Path::new(raw);
    if !path.is_absolute() {
        return Err(format!("copy path '{raw}' must be absolute"));
    }
    for comp in path.components() {
        if matches!(comp, Component::ParentDir) {
            return Err(format!("copy path '{raw}' must not contain '..'"));
        }
    }
    Ok(path.to_path_buf())
}

fn ensure_dir_no_symlink(path: &Path, create_missing: bool) -> Result<(), String> {
    let mut cur = PathBuf::new();
    let mut saw_normal = false;
    for comp in path.components() {
        match comp {
            Component::Prefix(p) => cur.push(p.as_os_str()),
            Component::RootDir => cur.push(comp.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(format!("copy path '{}' must not contain '..'", path.display()));
            }
            Component::Normal(part) => {
                saw_normal = true;
                step_dir_no_symlink(&mut cur, part, create_missing)?;
            }
        }
    }
    if !saw_normal {
        let meta = fs::symlink_metadata(&cur)
            .map_err(|err| format!("failed to inspect '{}': {err}", cur.display()))?;
        if is_symlink_or_reparse(&meta) || !meta.is_dir() {
            return Err(format!("path '{}' is not a safe directory", cur.display()));
        }
    }
    Ok(())
}

fn ensure_existing_path_no_symlink(path: &Path) -> Result<(), String> {
    let mut cur = PathBuf::new();
    let components: Vec<_> = path.components().collect();
    let last_normal_idx = components
        .iter()
        .rposition(|c| matches!(c, Component::Normal(_)));

    for (idx, comp) in components.into_iter().enumerate() {
        match comp {
            Component::Prefix(p) => cur.push(p.as_os_str()),
            Component::RootDir => cur.push(comp.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(format!("copy path '{}' must not contain '..'", path.display()));
            }
            Component::Normal(part) => {
                cur.push(part);
                let meta = fs::symlink_metadata(&cur)
                    .map_err(|err| format!("failed to inspect '{}': {err}", cur.display()))?;
                if is_symlink_or_reparse(&meta) {
                    return Err(format!(
                        "path component '{}' is a symlink or reparse point",
                        cur.display()
                    ));
                }
                if Some(idx) != last_normal_idx && !meta.is_dir() {
                    return Err(format!(
                        "intermediate path component '{}' is not a directory",
                        cur.display()
                    ));
                }
            }
        }
    }
    Ok(())
}

fn step_dir_no_symlink(cur: &mut PathBuf, part: &std::ffi::OsStr, create_missing: bool) -> Result<(), String> {
    cur.push(part);
    match fs::symlink_metadata(&*cur) {
        Ok(meta) => {
            if is_symlink_or_reparse(&meta) {
                return Err(format!(
                    "path component '{}' is a symlink or reparse point",
                    cur.display()
                ));
            }
            if !meta.is_dir() {
                return Err(format!(
                    "path component '{}' exists and is not a directory",
                    cur.display()
                ));
            }
            Ok(())
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            if !create_missing {
                return Err(format!("directory '{}' does not exist", cur.display()));
            }
            match fs::create_dir(&*cur) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    let meta = fs::symlink_metadata(&*cur).map_err(|meta_err| {
                        format!("failed to inspect '{}': {meta_err}", cur.display())
                    })?;
                    if is_symlink_or_reparse(&meta) || !meta.is_dir() {
                        return Err(format!(
                            "path component '{}' is not a safe directory",
                            cur.display()
                        ));
                    }
                    Ok(())
                }
                Err(e) => Err(format!("failed to create directory '{}': {e}", cur.display())),
            }
        }
        Err(err) => Err(format!("failed to inspect '{}': {err}", cur.display())),
    }
}

fn create_relative_dir_no_symlink(root: &Path, rel: &Path) -> Result<PathBuf, String> {
    let mut cur = root.to_path_buf();
    for comp in rel.components() {
        match comp {
            Component::Normal(part) => step_dir_no_symlink(&mut cur, part, true)?,
            Component::CurDir => {}
            _ => return Err(format!("invalid relative directory path '{}'", rel.display())),
        }
    }
    Ok(cur)
}

fn prepare_parent_dirs_no_symlink(root: &Path, rel: &Path) -> Result<PathBuf, String> {
    let file_name = rel
        .file_name()
        .ok_or_else(|| format!("tar entry '{}' has no filename", rel.display()))?;
    let mut cur = match rel.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => {
            create_relative_dir_no_symlink(root, parent)?
        }
        _ => root.to_path_buf(),
    };
    cur.push(file_name);
    Ok(cur)
}

fn validate_tar_entry_path(raw_bytes: &[u8], entry_path: &Path) -> Result<Option<PathBuf>, String> {
    if raw_bytes.is_empty() {
        return Err("tar entry path must not be empty".to_owned());
    }
    if raw_bytes.contains(&0) || raw_bytes.contains(&b'\\') {
        return Err("tar entry path contains forbidden NUL or backslash character".to_owned());
    }
    let raw_str = std::str::from_utf8(raw_bytes)
        .map_err(|_| "tar entry path is not valid UTF-8".to_owned())?;
    if raw_str.starts_with('/') {
        return Err(format!("tar entry path '{raw_str}' must not be absolute"));
    }

    let mut rel = PathBuf::new();
    for comp in entry_path.components() {
        match comp {
            Component::Prefix(_) | Component::RootDir => {
                return Err(format!("tar entry path '{raw_str}' must not be absolute"));
            }
            Component::ParentDir => {
                return Err(format!("tar entry path '{raw_str}' must not contain '..'"));
            }
            Component::CurDir => {}
            Component::Normal(part) => {
                let Some(part_str) = part.to_str() else {
                    return Err("tar entry path component is not valid UTF-8".to_owned());
                };
                if part_str == ".." || part_str.contains('\\') || part_str.contains('\0') {
                    return Err(format!("tar entry path '{raw_str}' contains forbidden component"));
                }
                rel.push(part);
            }
        }
    }

    if rel.as_os_str().is_empty() {
        Ok(None)
    } else {
        Ok(Some(rel))
    }
}

fn open_extract_file_no_symlink(path: &Path) -> Result<File, String> {
    match fs::symlink_metadata(path) {
        Ok(meta) => {
            if is_symlink_or_reparse(&meta) {
                return Err(format!(
                    "destination target '{}' is a symlink or reparse point",
                    path.display()
                ));
            }
            if meta.is_dir() {
                return Err(format!(
                    "destination target '{}' is an existing directory",
                    path.display()
                ));
            }
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {}
        Err(err) => return Err(format!("failed to inspect '{}': {err}", path.display())),
    }

    let mut opts = OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    opts.open(path)
        .map_err(|err| format!("failed to open '{}' for write: {err}", path.display()))
}

fn open_source_file_no_symlink(path: &Path) -> Result<File, String> {
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    opts.open(path)
        .map_err(|err| format!("failed to open '{}' for read: {err}", path.display()))
}

fn apply_safe_file_mode(file: &File, mode: u32) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(mode & 0o777);
        file.set_permissions(perms)
            .map_err(|err| format!("failed to set file permissions: {err}"))?;
    }
    #[cfg(not(unix))]
    {
        let _ = (file, mode);
    }
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

fn is_symlink_or_reparse(meta: &fs::Metadata) -> bool {
    if meta.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        if (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            return true;
        }
    }
    false
}
