//! Unix process-group isolation, Linux per-exec cgroup v2 scope (`cgroup.kill`),
//! container `conmon` exec-tree termination, parent-death guard, and user switching.

#[cfg(target_os = "linux")]
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
#[cfg(target_os = "linux")]
use std::fs::OpenOptions;
use std::io;
#[cfg(target_os = "linux")]
use std::io::Read;
use std::os::fd::{AsRawFd, RawFd};
#[cfg(target_os = "linux")]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
#[cfg(target_os = "linux")]
use std::path::Path;
#[cfg(target_os = "linux")]
use std::path::PathBuf;
use std::process::Command;
#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
#[cfg(target_os = "linux")]
use std::thread;
#[cfg(target_os = "linux")]
use std::time::{Duration, Instant};

use sandbox_protocol::StreamId;

use crate::supervisor::resolve_user_ids_from_tables;
#[cfg(target_os = "linux")]
use crate::supervisor::{
    expand_scoped_proc_closure, extract_conmon_exec_pidfile, is_trusted_conmon_exe,
    parse_proc_stat_line, ProcStatEntry,
};

#[cfg(target_os = "linux")]
const CGROUP_ROOT: &str = "/sys/fs/cgroup";
#[cfg(target_os = "linux")]
const KILL_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
#[cfg(target_os = "linux")]
const KILL_DRAIN_POLL: Duration = Duration::from_millis(5);
#[cfg(target_os = "linux")]
const CONMON_EXIT_GRACE: Duration = Duration::from_millis(500);

#[cfg(target_os = "linux")]
static NEXT_EXEC_SCOPE_SEQ: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct UnixUser {
    pub uid: libc::uid_t,
    pub gid: libc::gid_t,
}

/// Per-execution isolation scope backed by a dedicated Linux cgroup v2 leaf directory when
/// writable (always true in the Alpine guest VM), with `/proc` tree + process-group fallback.
pub(crate) struct ExecScope {
    #[cfg(target_os = "linux")]
    cgroup_dir: Option<PathBuf>,
    spawn_procs_file: Mutex<Option<File>>,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    is_container_exec: bool,
    #[cfg(target_os = "linux")]
    leader_starttime: AtomicU64,
}

impl ExecScope {
    /// Creates a fresh per-exec cgroup v2 scope on Linux if `/sys/fs/cgroup` is writable,
    /// falling back gracefully to process-group + `/proc` tree tracking in unprivileged host tests.
    pub(crate) fn prepare(stream_id: StreamId, is_container_exec: bool) -> Self {
        #[cfg(target_os = "linux")]
        {
            if let Some((dir, procs_file)) = try_create_linux_exec_cgroup(stream_id) {
                return Self {
                    cgroup_dir: Some(dir),
                    spawn_procs_file: Mutex::new(Some(procs_file)),
                    is_container_exec,
                    leader_starttime: AtomicU64::new(0),
                };
            }
        }
        #[cfg(not(target_os = "linux"))]
        let _ = stream_id;

        Self {
            #[cfg(target_os = "linux")]
            cgroup_dir: None,
            spawn_procs_file: Mutex::new(None),
            is_container_exec,
            #[cfg(target_os = "linux")]
            leader_starttime: AtomicU64::new(0),
        }
    }

    /// Captures the unreaped leader's `/proc/<pid>/stat` `starttime` right after `spawn()` so
    /// subsequent `/proc` scans never match older unrelated guest processes.
    pub(crate) fn record_leader(&self, pgid: u32) {
        #[cfg(target_os = "linux")]
        {
            if let Ok(pid_i32) = i32::try_from(pgid) {
                if let Some(entry) = read_proc_stat_entry(pid_i32) {
                    self.leader_starttime
                        .store(entry.starttime, Ordering::Release);
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        let _ = pgid;
    }

    fn procs_raw_fd(&self) -> Option<RawFd> {
        self.spawn_procs_file
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(AsRawFd::as_raw_fd)
    }

    /// Closes the parent's `cgroup.procs` descriptor right after `Command::spawn()` returns.
    pub(crate) fn close_spawn_fd(&self) {
        let _ = self
            .spawn_procs_file
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
    }

    /// Terminates every process belonging to this execution scope (including `setsid()` detached
    /// children and `podman exec` / `conmon` container processes) and waits until they exit.
    pub(crate) fn kill_all(&self, pgid: u32) {
        #[cfg(target_os = "linux")]
        {
            let min_start = self.leader_starttime.load(Ordering::Acquire);
            kill_linux_exec_tree(
                self.cgroup_dir.as_deref(),
                pgid,
                self.is_container_exec,
                min_start,
            );
        }
        #[cfg(not(target_os = "linux"))]
        {
            kill_process_group(pgid);
        }
    }

    /// Ensures no detached background process outlives the execution and removes the leaf cgroup.
    pub(crate) fn cleanup_after_reap(&self, pgid: u32) {
        self.close_spawn_fd();
        #[cfg(target_os = "linux")]
        if let Some(ref dir) = self.cgroup_dir {
            let min_start = self.leader_starttime.load(Ordering::Acquire);
            let group_live = has_verified_group_survivors(pgid, min_start);
            // Skip costly `/proc` snapshots when a guest exec exited cleanly with empty pgid and leaf cgroup.
            if self.is_container_exec || group_live || !read_cgroup_pids(dir).is_empty() {
                kill_linux_exec_tree(
                    Some(dir.as_path()),
                    pgid,
                    self.is_container_exec,
                    min_start,
                );
            }
            remove_cgroup_dir_with_retry(dir);
            return;
        }
        self.kill_all(pgid);
    }
}

impl Drop for ExecScope {
    fn drop(&mut self) {
        self.close_spawn_fd();
        #[cfg(target_os = "linux")]
        if let Some(ref dir) = self.cgroup_dir {
            let _ = fs::write(dir.join("cgroup.kill"), b"1");
            remove_cgroup_dir_with_retry(dir);
        }
    }
}

#[cfg(target_os = "linux")]
fn resolve_writable_cgroup_parent() -> PathBuf {
    if let Ok(raw) = fs::read_to_string("/proc/self/cgroup") {
        for line in raw.lines() {
            if let Some(rel) = line.strip_prefix("0::") {
                let trimmed = rel.trim().trim_start_matches('/');
                if !trimmed.is_empty() {
                    let candidate = Path::new(CGROUP_ROOT).join(trimmed);
                    // Non-root cgroup v2 parents can host leaf process cgroups only when no
                    // domain controllers are enabled in `cgroup.subtree_control`.
                    let subtree_empty = fs::read_to_string(candidate.join("cgroup.subtree_control"))
                        .map(|s| s.trim().is_empty())
                        .unwrap_or(false);
                    if subtree_empty {
                        return candidate;
                    }
                }
            }
        }
    }
    PathBuf::from(CGROUP_ROOT)
}

#[cfg(target_os = "linux")]
fn try_create_linux_exec_cgroup(stream_id: StreamId) -> Option<(PathBuf, File)> {
    let parent = resolve_writable_cgroup_parent();
    let seq = NEXT_EXEC_SCOPE_SEQ.fetch_add(1, Ordering::Relaxed);
    let dir = parent.join(format!(
        "minipod-exec-{}-{}-{}",
        std::process::id(),
        stream_id.0,
        seq
    ));
    fs::create_dir(&dir).ok()?;
    match OpenOptions::new().write(true).open(dir.join("cgroup.procs")) {
        Ok(file) => Some((dir, file)),
        Err(_) => {
            let _ = fs::remove_dir(&dir);
            None
        }
    }
}

#[cfg(target_os = "linux")]
fn read_cgroup_pids(dir: &Path) -> Vec<i32> {
    let Ok(raw) = fs::read_to_string(dir.join("cgroup.procs")) else {
        return Vec::new();
    };
    raw.lines()
        .filter_map(|line| line.trim().parse::<i32>().ok())
        .filter(|&pid| pid > 1)
        .collect()
}

#[cfg(target_os = "linux")]
fn read_proc_stat_entry(pid: i32) -> Option<ProcStatEntry> {
    let raw = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    parse_proc_stat_line(&raw)
}

#[cfg(target_os = "linux")]
fn snapshot_proc_table() -> Vec<ProcStatEntry> {
    let Ok(entries) = fs::read_dir("/proc") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(s) = name.to_str() else {
            continue;
        };
        if !s.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        if let Ok(stat_raw) = fs::read_to_string(entry.path().join("stat")) {
            if let Some(parsed) = parse_proc_stat_line(&stat_raw) {
                out.push(parsed);
            }
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn is_pid_in_container_cgroup(pid: i32) -> bool {
    let Ok(cg) = fs::read_to_string(format!("/proc/{pid}/cgroup")) else {
        return false;
    };
    cg.contains("libpod-") || cg.contains("machine.slice") || cg.contains("/container")
}

#[cfg(target_os = "linux")]
fn discover_conmon_exec_pids(
    tracked: &HashMap<i32, u64>,
    table: &[ProcStatEntry],
    min_starttime: u64,
    self_pid: i32,
) -> Vec<(i32, u64)> {
    let mut discovered = Vec::new();
    for (&pid, &conmon_start) in tracked {
        let Ok(proc_meta) = fs::symlink_metadata(format!("/proc/{pid}")) else {
            continue;
        };
        if proc_meta.uid() != 0 {
            continue;
        }
        let Ok(exe_target) = fs::read_link(format!("/proc/{pid}/exe")) else {
            continue;
        };
        let Some(exe_str) = exe_target.to_str() else {
            continue;
        };
        if !is_trusted_conmon_exe(exe_str) {
            continue;
        }

        let Ok(cmdline) = fs::read(format!("/proc/{pid}/cmdline")) else {
            continue;
        };
        let arg_strs: Vec<&str> = cmdline
            .split(|&b| b == 0)
            .filter(|seg| !seg.is_empty())
            .filter_map(|seg| std::str::from_utf8(seg).ok())
            .collect();
        let Some(pidfile_path) = extract_conmon_exec_pidfile(&arg_strs) else {
            continue;
        };

        let mut opts = OpenOptions::new();
        opts.read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        let Ok(file) = opts.open(pidfile_path) else {
            continue;
        };
        let Ok(file_meta) = file.metadata() else {
            continue;
        };
        if !file_meta.is_file() || file_meta.uid() != 0 {
            continue;
        }
        let mut raw_pid = String::new();
        if file.take(64).read_to_string(&mut raw_pid).is_err() {
            continue;
        }
        let Ok(exec_pid) = raw_pid.trim().parse::<i32>() else {
            continue;
        };
        if exec_pid <= 1 || exec_pid == self_pid {
            continue;
        }

        let maybe_entry = table
            .iter()
            .copied()
            .find(|e| e.pid == exec_pid)
            .or_else(|| read_proc_stat_entry(exec_pid));
        let Some(exec_entry) = maybe_entry else {
            continue;
        };
        let effective_min = min_starttime.max(conmon_start);
        if exec_entry.starttime < effective_min {
            continue;
        }
        if exec_entry.ppid == pid || is_pid_in_container_cgroup(exec_pid) {
            discovered.push((exec_pid, exec_entry.starttime));
        }
    }
    discovered
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn kill_verified_pid_and_group(pid: i32, expected_starttime: u64) {
    if pid <= 1 {
        return;
    }
    let Some(entry) = read_proc_stat_entry(pid) else {
        return;
    };
    if entry.state == 'Z' || (expected_starttime != 0 && entry.starttime != expected_starttime) {
        return;
    }
    // SAFETY: `pid > 1` has been verified against its recorded `/proc/<pid>/stat` `starttime`.
    unsafe {
        if entry.pgrp == pid {
            let _ = libc::kill(-pid, libc::SIGKILL);
        }
        let _ = libc::kill(pid, libc::SIGKILL);
    }
}

#[cfg(target_os = "linux")]
fn has_verified_group_survivors(pgid: u32, min_starttime: u64) -> bool {
    let Ok(pgid_i32) = i32::try_from(pgid) else {
        return false;
    };
    if pgid_i32 <= 1 {
        return false;
    }
    if let Some(leader) = read_proc_stat_entry(pgid_i32) {
        if leader.state != 'Z' && (min_starttime == 0 || leader.starttime >= min_starttime) {
            return true;
        }
    }
    snapshot_proc_table().into_iter().any(|e| {
        e.state != 'Z'
            && (e.pgrp == pgid_i32 || e.session == pgid_i32)
            && e.starttime >= min_starttime
    })
}

#[cfg(target_os = "linux")]
fn is_verified_pid_alive(pid: i32, expected_starttime: u64) -> bool {
    read_proc_stat_entry(pid).is_some_and(|e| {
        e.state != 'Z' && (expected_starttime == 0 || e.starttime == expected_starttime)
    })
}

#[cfg(target_os = "linux")]
fn refresh_tracked_closure(
    tracked: &mut HashMap<i32, u64>,
    cgroup_dir: Option<&Path>,
    pgid: u32,
    is_container_exec: bool,
    min_starttime: u64,
    self_pid: i32,
) -> HashSet<i32> {
    let table = snapshot_proc_table();
    let mut host_cgroup_pids = HashSet::new();
    if let Some(dir) = cgroup_dir {
        for pid in read_cgroup_pids(dir) {
            if pid != self_pid {
                host_cgroup_pids.insert(pid);
                if let Some(entry) = table
                    .iter()
                    .copied()
                    .find(|e| e.pid == pid)
                    .or_else(|| read_proc_stat_entry(pid))
                {
                    tracked.entry(pid).or_insert(entry.starttime);
                }
            }
        }
    }

    if let Ok(root_pid) = i32::try_from(pgid) {
        if root_pid > 1 && root_pid != self_pid {
            for entry in &table {
                if entry.pid != self_pid
                    && entry.starttime >= min_starttime
                    && (entry.pid == root_pid
                        || entry.pgrp == root_pid
                        || entry.session == root_pid)
                {
                    tracked.entry(entry.pid).or_insert(entry.starttime);
                }
            }
        }
    }

    expand_scoped_proc_closure(tracked, &table, self_pid, min_starttime);
    if is_container_exec {
        for (exec_pid, start) in discover_conmon_exec_pids(tracked, &table, min_starttime, self_pid)
        {
            tracked.entry(exec_pid).or_insert(start);
        }
        expand_scoped_proc_closure(tracked, &table, self_pid, min_starttime);
    }
    host_cgroup_pids
}

#[cfg(target_os = "linux")]
fn kill_linux_exec_tree(
    cgroup_dir: Option<&Path>,
    pgid: u32,
    is_container_exec: bool,
    min_starttime: u64,
) {
    let self_pid = i32::try_from(std::process::id()).unwrap_or(i32::MAX);
    let mut tracked: HashMap<i32, u64> = HashMap::new();
    let host_cgroup_pids = refresh_tracked_closure(
        &mut tracked,
        cgroup_dir,
        pgid,
        is_container_exec,
        min_starttime,
        self_pid,
    );

    // Phase A: Kill container-side workload processes (outside `cgroup_dir`, e.g. in `libpod-<cid>`)
    // immediately while allowing `conmon -e` and `podman exec` inside `cgroup_dir` to reap the child
    // and write Podman's `.../exit/<cid>` file before Phase B's hard sweep.
    if let Some(dir) = cgroup_dir {
        if tracked.keys().any(|pid| !host_cgroup_pids.contains(pid)) {
            for (&pid, &start) in &tracked {
                if !host_cgroup_pids.contains(&pid) {
                    kill_verified_pid_and_group(pid, start);
                }
            }

            let grace_deadline = Instant::now() + CONMON_EXIT_GRACE;
            while Instant::now() < grace_deadline {
                let cur_host = refresh_tracked_closure(
                    &mut tracked,
                    Some(dir),
                    pgid,
                    is_container_exec,
                    min_starttime,
                    self_pid,
                );

                for (&pid, &start) in &tracked {
                    if !cur_host.contains(&pid) {
                        kill_verified_pid_and_group(pid, start);
                    }
                }

                let container_alive = tracked
                    .iter()
                    .any(|(&p, &st)| !cur_host.contains(&p) && is_verified_pid_alive(p, st));
                if cur_host.is_empty()
                    && !has_verified_group_survivors(pgid, min_starttime)
                    && !container_alive
                {
                    return;
                }
                thread::sleep(KILL_DRAIN_POLL);
            }
        }
    }

    // Phase B: Unconditional hard sweep across leaf cgroup and all starttime-verified closures.
    if let Some(dir) = cgroup_dir {
        let _ = fs::write(dir.join("cgroup.kill"), b"1");
    }

    if has_verified_group_survivors(pgid, min_starttime) {
        kill_process_group(pgid);
    }
    for (&pid, &start) in &tracked {
        kill_verified_pid_and_group(pid, start);
    }

    let deadline = Instant::now() + KILL_DRAIN_TIMEOUT;
    while Instant::now() < deadline {
        if let Some(dir) = cgroup_dir {
            let _ = fs::write(dir.join("cgroup.kill"), b"1");
        }
        let cur_host = refresh_tracked_closure(
            &mut tracked,
            cgroup_dir,
            pgid,
            is_container_exec,
            min_starttime,
            self_pid,
        );
        if !cur_host.is_empty() {
            for &pid in &cur_host {
                let st = tracked.get(&pid).copied().unwrap_or(0);
                kill_verified_pid_and_group(pid, st);
            }
            thread::sleep(KILL_DRAIN_POLL);
            continue;
        }

        let mut any_alive = false;
        for (&pid, &start) in &tracked {
            if is_verified_pid_alive(pid, start) {
                any_alive = true;
                kill_verified_pid_and_group(pid, start);
            }
        }
        if !any_alive {
            break;
        }
        thread::sleep(KILL_DRAIN_POLL);
    }
}

#[cfg(target_os = "linux")]
fn remove_cgroup_dir_with_retry(dir: &Path) {
    let deadline = Instant::now() + Duration::from_millis(250);
    loop {
        match fs::remove_dir(dir) {
            Ok(()) => return,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return,
            Err(_) if Instant::now() < deadline => {
                let _ = fs::write(dir.join("cgroup.kill"), b"1");
                thread::sleep(KILL_DRAIN_POLL);
            }
            Err(_) => return,
        }
    }
}

/// Resolves numeric `uid[:gid]` or `/etc/passwd` + `/etc/group` entries before `fork()`.
pub(crate) fn resolve_user(spec: &str) -> Result<UnixUser, String> {
    let passwd = read_optional_table("/etc/passwd")?;
    let group = read_optional_table("/etc/group")?;
    let (uid_u32, gid_u32) =
        resolve_user_ids_from_tables(spec, passwd.as_deref(), group.as_deref())?;
    let uid = libc::uid_t::try_from(uid_u32)
        .map_err(|_| format!("resolved uid {uid_u32} exceeds platform uid_t range"))?;
    let gid = libc::gid_t::try_from(gid_u32)
        .map_err(|_| format!("resolved gid {gid_u32} exceeds platform gid_t range"))?;
    Ok(UnixUser { uid, gid })
}

fn read_optional_table(path: &str) -> Result<Option<String>, String> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(format!("failed to read '{path}' for user lookup: {err}")),
    }
}

/// Configures a supervised `ExecStart` child to enter a dedicated process group (`pgid == child_pid`),
/// attach to `scope`'s leaf cgroup v2 (when present) before `setuid`/`execve`, bind `PR_SET_PDEATHSIG`,
/// and optionally switch `gid`/`uid`.
pub(crate) fn configure_exec_command(
    cmd: &mut Command,
    user: Option<UnixUser>,
    scope: &ExecScope,
) {
    configure_command_inner(cmd, user, true, scope.procs_raw_fd());
}

/// Configures a long-lived background child in a dedicated process group (`pgid == child_pid`)
/// without `PR_SET_PDEATHSIG`, because Linux fires `PR_SET_PDEATHSIG` when the spawning worker
/// thread exits rather than only when the whole `sandbox-agent` process terminates.
pub(crate) fn configure_process_group(cmd: &mut Command) {
    configure_command_inner(cmd, None, false, None);
}

#[allow(unsafe_code)]
fn configure_command_inner(
    cmd: &mut Command,
    user: Option<UnixUser>,
    bind_pdeathsig: bool,
    cgroup_procs_fd: Option<RawFd>,
) {
    #[cfg(target_os = "linux")]
    let expected_ppid = unsafe { libc::getpid() };
    #[cfg(not(target_os = "linux"))]
    let _ = (cgroup_procs_fd, bind_pdeathsig);

    // SAFETY: The `pre_exec` hook runs between `fork()` and `execve()` and invokes only
    // async-signal-safe syscalls (`setpgid`, `write` to `O_CLOEXEC` `cgroup.procs`, `setgroups`,
    // `setgid`, `setuid`, `prctl`, `getppid`) using `Copy` primitive IDs resolved prior to
    // `fork()` without allocating or locking.
    unsafe {
        cmd.pre_exec(move || {
            if libc::setpgid(0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            #[cfg(target_os = "linux")]
            if let Some(fd) = cgroup_procs_fd {
                let payload = b"0\n";
                let mut written = 0usize;
                while written < payload.len() {
                    let rc = libc::write(
                        fd,
                        payload[written..].as_ptr().cast::<libc::c_void>(),
                        payload.len() - written,
                    );
                    if rc > 0 {
                        written += rc as usize;
                    } else {
                        let err = io::Error::last_os_error();
                        if err.raw_os_error() == Some(libc::EINTR) {
                            continue;
                        }
                        return Err(err);
                    }
                }
            }
            if let Some(u) = user {
                if libc::setgroups(0, std::ptr::null()) != 0 {
                    let err = io::Error::last_os_error();
                    let allow_unpriv_self = libc::geteuid() != 0
                        && u.uid == libc::getuid()
                        && u.gid == libc::getgid()
                        && err.raw_os_error() == Some(libc::EPERM);
                    if !allow_unpriv_self {
                        return Err(err);
                    }
                }
                if libc::setgid(u.gid) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::setuid(u.uid) != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            // Must run AFTER `setgroups`/`setgid`/`setuid` because Linux clears `pdeath_signal`
            // whenever effective or filesystem UID/GID credentials change.
            #[cfg(target_os = "linux")]
            if bind_pdeathsig {
                if libc::prctl(
                    libc::PR_SET_PDEATHSIG,
                    libc::SIGKILL as libc::c_ulong,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                ) != 0
                {
                    return Err(io::Error::last_os_error());
                }
                if libc::getppid() != expected_ppid {
                    return Err(io::Error::from_raw_os_error(libc::ESRCH));
                }
            }
            Ok(())
        });
    }
}

/// Sends `sig` to every process in the dedicated process group `pgid`.
#[allow(unsafe_code)]
pub(crate) fn signal_process_group(pgid: u32, sig: libc::c_int) {
    let Ok(raw_pid) = libc::pid_t::try_from(pgid) else {
        return;
    };
    if raw_pid <= 0 {
        return;
    }
    // SAFETY: `raw_pid` is strictly positive and names the child's dedicated process group
    // established in `pre_exec` via `setpgid(0, 0)`, so `-raw_pid` targets only that tree.
    unsafe {
        let _ = libc::kill(-raw_pid, sig);
    }
}

/// Immediately sends `SIGKILL` to every process in the dedicated process group `pgid`.
pub(crate) fn kill_process_group(pgid: u32) {
    signal_process_group(pgid, libc::SIGKILL);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Stdio;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn configure_process_group_survives_spawning_worker_thread_exit() {
        let mut child = thread::spawn(|| {
            let mut cmd = Command::new("/bin/sleep");
            cmd.arg("5").stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
            configure_process_group(&mut cmd);
            cmd.spawn().expect("spawn sleep child in dedicated process group")
        })
        .join()
        .expect("worker thread finished cleanly");

        thread::sleep(Duration::from_millis(100));
        let exited = child.try_wait().expect("poll child status");
        assert!(
            exited.is_none(),
            "long-lived process-group child must survive spawning thread exit: {exited:?}"
        );

        let pid = child.id();
        kill_process_group(pid);
        let _ = child.wait();
    }

    #[test]
    fn fallback_exec_scope_without_cgroup_kills_surviving_process_group_on_cleanup() {
        #[cfg_attr(not(target_os = "linux"), allow(unsafe_code))]
        fn pid_is_alive(pid: i32) -> bool {
            #[cfg(target_os = "linux")]
            {
                is_verified_pid_alive(pid, 0)
            }
            #[cfg(not(target_os = "linux"))]
            {
                unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
            }
        }

        let scope = ExecScope {
            #[cfg(target_os = "linux")]
            cgroup_dir: None,
            spawn_procs_file: Mutex::new(None),
            is_container_exec: false,
            #[cfg(target_os = "linux")]
            leader_starttime: AtomicU64::new(0),
        };

        let mut cmd = Command::new("sh");
        cmd.args([
            "-c",
            "sleep 30 >/dev/null 2>&1 </dev/null & echo $!; exit 0",
        ]);
        cmd.stdout(Stdio::piped());
        configure_process_group(&mut cmd);

        let child = cmd.spawn().expect("spawn sh with background child");
        let pgid = child.id();
        let output = child.wait_with_output().expect("reap leader shell");
        assert!(output.status.success(), "leader shell failed: {:?}", output);
        let bg_pid: i32 = String::from_utf8_lossy(&output.stdout)
            .trim()
            .parse()
            .expect("parse background sleep pid");
        assert!(
            pid_is_alive(bg_pid),
            "background survivor {bg_pid} should still be running right after leader exits"
        );

        scope.cleanup_after_reap(pgid);

        let mut dead = false;
        for _ in 0..50 {
            if !pid_is_alive(bg_pid) {
                dead = true;
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(
            dead,
            "cleanup_after_reap without cgroup must kill surviving process group member {bg_pid}"
        );
    }

    #[test]
    #[allow(unsafe_code)]
    fn configure_exec_command_clears_supplementary_groups_and_preserves_pdeathsig_after_user_switch() {
        let is_root = unsafe { libc::geteuid() == 0 };
        let target_user = if is_root {
            UnixUser {
                uid: 65534,
                gid: 65534,
            }
        } else {
            UnixUser {
                uid: unsafe { libc::getuid() },
                gid: unsafe { libc::getgid() },
            }
        };

        let scope = ExecScope::prepare(StreamId(900), false);
        let mut id_cmd = Command::new("id");
        id_cmd.arg("-G").stdout(Stdio::piped()).stderr(Stdio::piped());
        configure_exec_command(&mut id_cmd, Some(target_user), &scope);
        let id_out = id_cmd.output().expect("spawn id -G with target_user");
        scope.close_spawn_fd();
        assert!(id_out.status.success(), "id -G failed: {id_out:?}");
        if is_root {
            let groups = String::from_utf8_lossy(&id_out.stdout);
            assert_eq!(
                groups.trim(),
                "65534",
                "supplementary root groups must be cleared on user switch, got {groups:?}"
            );
        }

        #[cfg(target_os = "linux")]
        {
            let scope2 = std::sync::Arc::new(ExecScope::prepare(StreamId(901), false));
            let scope2_bg = std::sync::Arc::clone(&scope2);
            let mut child = thread::spawn(move || {
                let mut cmd = Command::new("/bin/sleep");
                cmd.arg("10")
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null());
                configure_exec_command(&mut cmd, Some(target_user), &scope2_bg);
                cmd.spawn().expect("spawn sleep with user + pdeathsig")
            })
            .join()
            .expect("spawning worker thread exited");
            scope2.close_spawn_fd();

            // Because Linux triggers PR_SET_PDEATHSIG when the spawning thread exits, the child
            // must receive SIGKILL promptly even after switching UID/GID.
            let mut killed_by_pdeathsig = false;
            for _ in 0..50 {
                if let Some(_status) = child.try_wait().expect("poll sleep child") {
                    killed_by_pdeathsig = true;
                    break;
                }
                thread::sleep(Duration::from_millis(10));
            }
            if !killed_by_pdeathsig {
                let _ = child.kill();
                let _ = child.wait();
            }
            assert!(
                killed_by_pdeathsig,
                "PR_SET_PDEATHSIG must remain armed after setgroups/setgid/setuid"
            );
        }
    }
}
