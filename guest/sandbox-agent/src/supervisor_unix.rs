//! Unix process-group isolation, Linux per-exec cgroup v2 scope (`cgroup.kill`),
//! container `conmon` exec-tree termination, parent-death guard, and user switching.

#[cfg(target_os = "linux")]
use std::collections::HashSet;
use std::fs::{self, File};
#[cfg(target_os = "linux")]
use std::fs::OpenOptions;
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::process::CommandExt;
#[cfg(target_os = "linux")]
use std::path::Path;
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
    cgroup_dir: Option<PathBuf>,
    spawn_procs_file: Mutex<Option<File>>,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    is_container_exec: bool,
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
                };
            }
        }
        #[cfg(not(target_os = "linux"))]
        let _ = stream_id;

        Self {
            cgroup_dir: None,
            spawn_procs_file: Mutex::new(None),
            is_container_exec,
        }
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
            kill_linux_exec_tree(self.cgroup_dir.as_deref(), pgid);
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
            let leader_alive = process_group_has_live_members(pgid);
            // Skip costly `/proc` snapshots when a guest exec exited cleanly with empty pgid and leaf cgroup.
            if self.is_container_exec || leader_alive || !read_cgroup_pids(dir).is_empty() {
                kill_linux_exec_tree(Some(dir.as_path()), pgid);
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
#[derive(Clone, Copy)]
struct ProcStatEntry {
    pid: i32,
    state: char,
    ppid: i32,
    pgrp: i32,
    session: i32,
}

#[cfg(target_os = "linux")]
fn parse_proc_stat_line(raw: &str) -> Option<ProcStatEntry> {
    let open = raw.find('(')?;
    let close = raw.rfind(')')?;
    if close <= open {
        return None;
    }
    let pid = raw[..open].trim().parse::<i32>().ok()?;
    let mut fields = raw[close + 1..].split_ascii_whitespace();
    let state = fields.next()?.chars().next()?;
    let ppid = fields.next()?.parse::<i32>().ok()?;
    let pgrp = fields.next()?.parse::<i32>().ok()?;
    let session = fields.next()?.parse::<i32>().ok()?;
    Some(ProcStatEntry {
        pid,
        state,
        ppid,
        pgrp,
        session,
    })
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
fn discover_conmon_exec_pids(seed_pids: &HashSet<i32>) -> Vec<i32> {
    let mut discovered = Vec::new();
    for &pid in seed_pids {
        let Ok(cmdline) = fs::read(format!("/proc/{pid}/cmdline")) else {
            continue;
        };
        let args: Vec<&[u8]> = cmdline
            .split(|&b| b == 0)
            .filter(|seg| !seg.is_empty())
            .collect();
        let is_conmon = args
            .first()
            .and_then(|a| std::str::from_utf8(a).ok())
            .is_some_and(|bin| bin.ends_with("conmon"));
        if !is_conmon {
            continue;
        }

        let mut pidfile_path: Option<&str> = None;
        let mut idx = 0;
        while idx < args.len() {
            if let Ok(arg) = std::str::from_utf8(args[idx]) {
                if (arg == "-p" || arg == "--pidfile") && idx + 1 < args.len() {
                    pidfile_path = std::str::from_utf8(args[idx + 1]).ok();
                    break;
                }
                if let Some(rest) = arg.strip_prefix("--pidfile=") {
                    pidfile_path = Some(rest);
                    break;
                }
            }
            idx += 1;
        }

        if let Some(path) = pidfile_path.filter(|p| {
            p.starts_with("/run/")
                || p.starts_with("/var/run/")
                || p.starts_with("/var/lib/containers/")
                || p.starts_with("/tmp/")
        }) {
            if let Ok(raw_pid) = fs::read_to_string(path) {
                if let Ok(exec_pid) = raw_pid.trim().parse::<i32>() {
                    if exec_pid > 1 {
                        discovered.push(exec_pid);
                    }
                }
            }
        }
    }
    discovered
}

#[cfg(target_os = "linux")]
fn expand_proc_closure(seeds: &mut HashSet<i32>, self_pid: i32) {
    let table = snapshot_proc_table();
    loop {
        let mut added = false;
        for proc_entry in &table {
            if proc_entry.pid <= 1 || proc_entry.pid == self_pid || seeds.contains(&proc_entry.pid) {
                continue;
            }
            if seeds.contains(&proc_entry.ppid)
                || (proc_entry.pgrp > 1 && seeds.contains(&proc_entry.pgrp))
                || (proc_entry.session > 1 && seeds.contains(&proc_entry.session))
            {
                seeds.insert(proc_entry.pid);
                added = true;
            }
        }
        if !added {
            break;
        }
    }
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn kill_pid_and_group(pid: i32) {
    if pid <= 1 {
        return;
    }
    // SAFETY: `pid > 1` targets a verified descendant/cgroup member and its process group.
    unsafe {
        let _ = libc::kill(-pid, libc::SIGKILL);
        let _ = libc::kill(pid, libc::SIGKILL);
    }
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
fn process_group_has_live_members(pgid: u32) -> bool {
    let Ok(pgid_i32) = libc::pid_t::try_from(pgid) else {
        return false;
    };
    if pgid_i32 <= 0 {
        return false;
    }
    // SAFETY: signal 0 probes process-group existence without delivering a signal.
    let rc = unsafe { libc::kill(-pgid_i32, 0) };
    if rc == 0 {
        return true;
    }
    std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}

#[cfg(target_os = "linux")]
fn is_pid_alive_non_zombie(pid: i32) -> bool {
    let Ok(stat_raw) = fs::read_to_string(format!("/proc/{pid}/stat")) else {
        return false;
    };
    parse_proc_stat_line(&stat_raw).is_some_and(|e| e.state != 'Z')
}

#[cfg(target_os = "linux")]
fn kill_linux_exec_tree(cgroup_dir: Option<&Path>, pgid: u32) {
    let self_pid = i32::try_from(std::process::id()).unwrap_or(i32::MAX);
    let mut host_cgroup_pids = HashSet::new();
    if let Some(dir) = cgroup_dir {
        for pid in read_cgroup_pids(dir) {
            if pid != self_pid {
                host_cgroup_pids.insert(pid);
            }
        }
    }

    let mut all_pids = host_cgroup_pids.clone();
    if let Ok(root_pid) = i32::try_from(pgid) {
        if root_pid > 1 && root_pid != self_pid {
            all_pids.insert(root_pid);
        }
    }

    // Snapshot `/proc` closure BEFORE killing parent leaders so `setsid()` children and
    // `conmon --pidfile` container exec processes are captured prior to PID 1 reparenting.
    expand_proc_closure(&mut all_pids, self_pid);
    for container_exec_pid in discover_conmon_exec_pids(&all_pids) {
        if container_exec_pid != self_pid {
            all_pids.insert(container_exec_pid);
        }
    }
    expand_proc_closure(&mut all_pids, self_pid);

    // Phase A: Kill container-side workload processes (outside `cgroup_dir`, e.g. in `libpod-<cid>`)
    // immediately while allowing `conmon -e` and `podman exec` inside `cgroup_dir` to reap the child
    // and write Podman's `.../exit/<cid>` file before Phase B's hard sweep.
    if let Some(dir) = cgroup_dir {
        if all_pids.iter().any(|pid| !host_cgroup_pids.contains(pid)) {
            for &pid in &all_pids {
                if !host_cgroup_pids.contains(&pid) {
                    kill_pid_and_group(pid);
                }
            }

            let grace_deadline = Instant::now() + CONMON_EXIT_GRACE;
            while Instant::now() < grace_deadline {
                let cur_host: HashSet<i32> = read_cgroup_pids(dir)
                    .into_iter()
                    .filter(|&pid| pid != self_pid)
                    .collect();

                expand_proc_closure(&mut all_pids, self_pid);
                for container_exec_pid in discover_conmon_exec_pids(&all_pids) {
                    if container_exec_pid != self_pid {
                        all_pids.insert(container_exec_pid);
                    }
                }
                expand_proc_closure(&mut all_pids, self_pid);

                for &pid in &all_pids {
                    if !cur_host.contains(&pid) {
                        kill_pid_and_group(pid);
                    }
                }

                let container_alive = all_pids
                    .iter()
                    .any(|&p| !cur_host.contains(&p) && is_pid_alive_non_zombie(p));
                if cur_host.is_empty() && !process_group_has_live_members(pgid) && !container_alive {
                    return;
                }
                thread::sleep(KILL_DRAIN_POLL);
            }
        }
    }

    // Phase B: Unconditional hard sweep across leaf cgroup, process group, and all closures.
    // 1. Trigger atomic kernel `cgroup.kill` if available (Linux >= 5.14).
    if let Some(dir) = cgroup_dir {
        let _ = fs::write(dir.join("cgroup.kill"), b"1");
    }

    // 2. Kill initial process group and every surviving descendant / container exec process.
    kill_process_group(pgid);
    for &pid in &all_pids {
        kill_pid_and_group(pid);
    }
    if let Some(dir) = cgroup_dir {
        for pid in read_cgroup_pids(dir) {
            if pid != self_pid {
                all_pids.insert(pid);
                kill_pid_and_group(pid);
            }
        }
    }

    // 3. Wait until all cgroup tasks and tracked processes terminate before reporting completion.
    let deadline = Instant::now() + KILL_DRAIN_TIMEOUT;
    while Instant::now() < deadline {
        if let Some(dir) = cgroup_dir {
            let _ = fs::write(dir.join("cgroup.kill"), b"1");
            let remaining = read_cgroup_pids(dir);
            for &pid in &remaining {
                if pid != self_pid {
                    all_pids.insert(pid);
                    kill_pid_and_group(pid);
                }
            }
            if !remaining.is_empty() {
                thread::sleep(KILL_DRAIN_POLL);
                continue;
            }
        }

        expand_proc_closure(&mut all_pids, self_pid);
        let mut any_alive = false;
        for &pid in &all_pids {
            if is_pid_alive_non_zombie(pid) {
                any_alive = true;
                kill_pid_and_group(pid);
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
    #[cfg(not(target_os = "linux"))]
    let _ = (cgroup_procs_fd, bind_pdeathsig);

    // SAFETY: The `pre_exec` hook runs between `fork()` and `execve()` and invokes only
    // async-signal-safe syscalls (`setpgid`, `write` to `O_CLOEXEC` `cgroup.procs`, `prctl`,
    // `setgid`, `setuid`) using `Copy` primitive IDs resolved prior to `fork()` without
    // allocating or locking.
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
            #[cfg(target_os = "linux")]
            if bind_pdeathsig {
                let _ = libc::prctl(
                    libc::PR_SET_PDEATHSIG,
                    libc::SIGKILL as libc::c_ulong,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                );
            }
            if let Some(u) = user {
                if libc::setgid(u.gid) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::setuid(u.uid) != 0 {
                    return Err(io::Error::last_os_error());
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
                is_pid_alive_non_zombie(pid)
            }
            #[cfg(not(target_os = "linux"))]
            {
                unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
            }
        }

        let scope = ExecScope {
            cgroup_dir: None,
            spawn_procs_file: Mutex::new(None),
            is_container_exec: false,
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
}
