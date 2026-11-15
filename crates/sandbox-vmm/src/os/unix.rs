//! Unix-specific local IPC security primitives: pure-`std` `0700` owner-only runtime
//! directory validation/creation and `0600` Unix domain socket listener/stream for QEMU
//! `-chardev socket,...,server=off`.

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{
    DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt,
};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use sandbox_core::SandboxError;

use crate::accel::classify_launch_error;
use crate::ipc::validate_socket_path;
#[cfg(target_os = "linux")]
use crate::process::{parse_proc_stat_starttime, parse_proc_stat_state_and_starttime};
use crate::process::{ProcessExitStatus, ProcessLaunchSpec, ProcessStartIdentity, ProcessStdio};

/// Ensures `path` exists as a non-symlink directory owned by the current user with `0700` mode.
///
/// Creates the directory with mode `0700` if missing; if it already exists, inspects
/// `symlink_metadata` and rejects symlinks, non-directories, non-`0700` permissions, and
/// mismatched owner UIDs.
pub fn ensure_owner_only_dir(path: &Path) -> Result<(), SandboxError> {
    match DirBuilder::new().mode(0o700).create(path) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
        Err(err) => {
            return Err(SandboxError::Transport(format!(
                "failed to create owner-only directory '{}': {err}",
                path.display()
            )));
        }
    }

    let meta = fs::symlink_metadata(path).map_err(|err| {
        SandboxError::Transport(format!(
            "failed to inspect directory '{}': {err}",
            path.display()
        ))
    })?;
    if meta.file_type().is_symlink() {
        return Err(SandboxError::PolicyViolation(format!(
            "refusing runtime directory '{}': symlinks are not allowed",
            path.display()
        )));
    }
    if !meta.is_dir() {
        return Err(SandboxError::PolicyViolation(format!(
            "refusing runtime directory '{}': path exists and is not a directory",
            path.display()
        )));
    }

    let mode = meta.mode() & 0o777;
    if mode != 0o700 {
        return Err(SandboxError::PolicyViolation(format!(
            "runtime directory '{}' has insecure permissions {:04o}, expected 0700",
            path.display(),
            mode
        )));
    }

    let expected_uid = current_uid()?;
    if meta.uid() != expected_uid {
        return Err(SandboxError::PolicyViolation(format!(
            "runtime directory '{}' is owned by uid {}, expected uid {}",
            path.display(),
            meta.uid(),
            expected_uid
        )));
    }

    Ok(())
}

/// Host-bound Unix domain stream listener for QEMU `-chardev socket,...,server=off`.
pub struct UnixIpcListener {
    listener: UnixListener,
    path: PathBuf,
}

impl UnixIpcListener {
    /// Validates the `0700` parent runtime directory, removes a safe stale socket file if present,
    /// binds `socket_path`, enforces mode `0600`, and configures non-blocking accept polling.
    pub fn bind(socket_path: &Path) -> Result<Self, SandboxError> {
        validate_socket_path(socket_path)?;
        let parent = socket_path.parent().ok_or_else(|| {
            SandboxError::InvalidSpec(format!(
                "socket path '{}' must have a parent runtime directory",
                socket_path.display()
            ))
        })?;
        ensure_owner_only_dir(parent)?;
        remove_stale_socket_if_safe(socket_path)?;

        let listener = UnixListener::bind(socket_path).map_err(|err| {
            SandboxError::Transport(format!(
                "failed to bind Unix socket '{}': {err}",
                socket_path.display()
            ))
        })?;
        if let Err(err) = fs::set_permissions(socket_path, fs::Permissions::from_mode(0o600)) {
            drop(listener);
            let _ = fs::remove_file(socket_path);
            return Err(SandboxError::Transport(format!(
                "failed to set mode 0600 on Unix socket '{}': {err}",
                socket_path.display()
            )));
        }
        if let Err(err) = listener.set_nonblocking(true) {
            drop(listener);
            let _ = fs::remove_file(socket_path);
            return Err(SandboxError::Transport(format!(
                "failed to set non-blocking mode on Unix listener '{}': {err}",
                socket_path.display()
            )));
        }

        Ok(Self {
            listener,
            path: socket_path.to_path_buf(),
        })
    }

    /// Returns the bound filesystem path for this listener.
    pub fn socket_path(&self) -> &Path {
        &self.path
    }

    /// Polls until `timeout` for a QEMU connection so hung guests never block the host forever.
    pub fn accept_timeout(&self, timeout: Duration) -> Result<UnixIpcStream, SandboxError> {
        let deadline = Instant::now() + timeout;
        loop {
            match self.listener.accept() {
                Ok((stream, _)) => {
                    // macOS inherits O_NONBLOCK from the listening socket; normalize to blocking I/O.
                    stream.set_nonblocking(false).map_err(|err| {
                        SandboxError::Transport(format!(
                            "failed to set accepted Unix stream blocking on '{}': {err}",
                            self.path.display()
                        ))
                    })?;
                    return Ok(UnixIpcStream { stream });
                }
                Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                    let now = Instant::now();
                    if now >= deadline {
                        return Err(SandboxError::Transport(format!(
                            "timed out after {}ms waiting for connection on '{}'",
                            timeout.as_millis(),
                            self.path.display()
                        )));
                    }
                    let remaining = deadline.saturating_duration_since(now);
                    std::thread::sleep(remaining.min(Duration::from_millis(5)));
                }
                Err(err) => {
                    return Err(SandboxError::Transport(format!(
                        "accept on Unix socket '{}' failed: {err}",
                        self.path.display()
                    )));
                }
            }
        }
    }
}

/// Connected Unix domain stream implementing `Read` + `Write`.
pub struct UnixIpcStream {
    stream: UnixStream,
}

impl UnixIpcStream {
    /// Connects as a client to an existing Unix domain socket path.
    pub fn connect(socket_path: &Path) -> Result<Self, SandboxError> {
        validate_socket_path(socket_path)?;
        let stream = UnixStream::connect(socket_path).map_err(|err| {
            SandboxError::Transport(format!(
                "failed to connect to Unix socket '{}': {err}",
                socket_path.display()
            ))
        })?;
        Ok(Self { stream })
    }

    /// Configures the read timeout on the underlying Unix domain stream (`None` clears it).
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<(), SandboxError> {
        if matches!(timeout, Some(d) if d.is_zero()) {
            return Err(SandboxError::InvalidSpec(
                "IPC stream read timeout must be greater than zero (use None to clear)".to_owned(),
            ));
        }
        self.stream.set_read_timeout(timeout).map_err(|err| {
            SandboxError::Transport(format!("failed to set Unix stream read timeout: {err}"))
        })
    }

    /// Configures the write timeout on the underlying Unix domain stream (`None` clears it).
    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> Result<(), SandboxError> {
        if matches!(timeout, Some(d) if d.is_zero()) {
            return Err(SandboxError::InvalidSpec(
                "IPC stream write timeout must be greater than zero (use None to clear)".to_owned(),
            ));
        }
        self.stream.set_write_timeout(timeout).map_err(|err| {
            SandboxError::Transport(format!("failed to set Unix stream write timeout: {err}"))
        })
    }

    /// Reads bytes concurrently from a shared `&UnixIpcStream` reference.
    pub fn read_shared(&self, buf: &mut [u8]) -> io::Result<usize> {
        (&self.stream).read(buf)
    }

    /// Writes bytes concurrently to a shared `&UnixIpcStream` reference.
    pub fn write_shared(&self, buf: &[u8]) -> io::Result<usize> {
        (&self.stream).write(buf)
    }

    /// Shuts down both read and write halves of the underlying Unix domain stream.
    pub fn shutdown_both(&self) -> io::Result<()> {
        self.stream.shutdown(std::net::Shutdown::Both)
    }
}

impl Read for UnixIpcStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.read_shared(buf)
    }
}

impl Write for UnixIpcStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_shared(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        (&self.stream).flush()
    }
}

fn remove_stale_socket_if_safe(socket_path: &Path) -> Result<(), SandboxError> {
    let meta = match fs::symlink_metadata(socket_path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => {
            return Err(SandboxError::Transport(format!(
                "failed to inspect existing path '{}': {err}",
                socket_path.display()
            )));
        }
    };

    if meta.file_type().is_symlink() || meta.is_dir() || !meta.file_type().is_socket() {
        return Err(SandboxError::PolicyViolation(format!(
            "refusing to remove non-socket or symlink at '{}'",
            socket_path.display()
        )));
    }
    let expected_uid = current_uid()?;
    if meta.uid() != expected_uid {
        return Err(SandboxError::PolicyViolation(format!(
            "refusing to remove stale socket '{}' owned by uid {} (expected {})",
            socket_path.display(),
            meta.uid(),
            expected_uid
        )));
    }

    fs::remove_file(socket_path).map_err(|err| {
        SandboxError::Transport(format!(
            "failed to remove stale socket '{}': {err}",
            socket_path.display()
        ))
    })
}

fn current_uid() -> Result<u32, SandboxError> {
    #[cfg(target_os = "linux")]
    if let Ok(meta) = fs::metadata("/proc/self") {
        return Ok(meta.uid());
    }

    probe_uid_via_temp_file()
}

fn probe_uid_via_temp_file() -> Result<u32, SandboxError> {
    static SEQ: AtomicU64 = AtomicU64::new(0);

    struct ProbeCleanup(PathBuf);
    impl Drop for ProbeCleanup {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    let tmp_dir = std::env::temp_dir();
    for _ in 0..8 {
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let probe_path = tmp_dir.join(format!("mp-uid-{}-{seq}", std::process::id()));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&probe_path)
        {
            Ok(file) => {
                let _cleanup = ProbeCleanup(probe_path);
                let meta = file.metadata().map_err(|err| {
                    SandboxError::Internal(format!("failed to read UID probe metadata: {err}"))
                })?;
                return Ok(meta.uid());
            }
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(SandboxError::Internal(format!(
                    "failed to determine current UID via temp probe '{}': {err}",
                    probe_path.display()
                )));
            }
        }
    }

    Err(SandboxError::Internal(
        "exhausted retries while creating UID probe file".to_owned(),
    ))
}

pub(crate) type PlatformConfinedProcess = UnixConfinedProcess;

const UNIX_WAIT_POLL_INTERVAL: Duration = Duration::from_millis(25);

/// Unix child process confined to its own process group (`pgid == pid`) via `setpgid(0, 0)`.
pub struct UnixConfinedProcess {
    child: Child,
    identity: ProcessStartIdentity,
    exited: Option<ProcessExitStatus>,
    group_killed: bool,
}

impl UnixConfinedProcess {
    /// Returns the OS process ID (`pid`).
    pub fn id(&self) -> u32 {
        self.identity.pid
    }

    /// Returns the PID and captured start-time token (`/proc/<pid>/stat` field 22 on Linux,
    /// `0` fallback on Unix platforms without procfs).
    pub fn start_identity(&self) -> ProcessStartIdentity {
        self.identity
    }

    /// Non-blocking check for process exit.
    pub fn try_wait(&mut self) -> Result<Option<ProcessExitStatus>, SandboxError> {
        if let Some(status) = self.exited {
            return Ok(Some(status));
        }
        match self.child.try_wait() {
            Ok(Some(status)) => {
                let normalized = exit_status_from_std(status);
                self.exited = Some(normalized);
                Ok(Some(normalized))
            }
            Ok(None) => Ok(None),
            Err(err) => Err(SandboxError::Internal(format!(
                "failed to poll child process {}: {err}",
                self.identity.pid
            ))),
        }
    }

    /// Waits up to `timeout` for child exit, returning `Ok(None)` on timeout.
    pub fn wait_timeout(
        &mut self,
        timeout: Duration,
    ) -> Result<Option<ProcessExitStatus>, SandboxError> {
        let deadline = Instant::now() + timeout;
        // shortcut: polls child.try_wait() every 25ms on Unix until deadline; replace with waitid/pidfd/SIGCHLD wakeup if shutdown wait latency or idle polling becomes a bottleneck
        loop {
            if let Some(status) = self.try_wait()? {
                return Ok(Some(status));
            }
            let now = Instant::now();
            if now >= deadline {
                return Ok(None);
            }
            std::thread::sleep(deadline.saturating_duration_since(now).min(UNIX_WAIT_POLL_INTERVAL));
        }
    }

    /// Sends `SIGKILL` to the child's dedicated process group (`-pid`) and reaps the child.
    pub fn kill_and_wait(&mut self) -> Result<(), SandboxError> {
        if !self.group_killed {
            kill_process_group_raw(self.identity.pid)?;
            self.group_killed = true;
        }
        if self.exited.is_none() {
            match self.child.kill() {
                Ok(()) => {}
                Err(err) if err.kind() == io::ErrorKind::InvalidInput => {}
                Err(err) => {
                    return Err(SandboxError::Internal(format!(
                        "failed to kill child process {}: {err}",
                        self.identity.pid
                    )));
                }
            }
            let status = self.child.wait().map_err(|err| {
                SandboxError::Internal(format!(
                    "failed to reap child process {}: {err}",
                    self.identity.pid
                ))
            })?;
            self.exited = Some(exit_status_from_std(status));
        }
        Ok(())
    }
}

impl Drop for UnixConfinedProcess {
    fn drop(&mut self) {
        let _ = self.kill_and_wait();
    }
}

pub(crate) fn spawn_confined(spec: ProcessLaunchSpec) -> Result<UnixConfinedProcess, SandboxError> {
    let mut cmd = Command::new(&spec.program);
    cmd.args(&spec.args)
        .stdin(stdio_from(spec.stdin))
        .stdout(stdio_from(spec.stdout))
        .stderr(stdio_from(spec.stderr));
    if let Some(dir) = &spec.current_dir {
        cmd.current_dir(dir);
    }

    // SAFETY: `pre_exec` runs between `fork()` and `execve()` and invokes only the
    // async-signal-safe POSIX syscall `setpgid(0, 0)` without allocating or locking.
    unsafe {
        cmd.pre_exec(|| {
            if libc::setpgid(0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let child = cmd
        .spawn()
        .map_err(|err| classify_launch_error(&spec.program, &err))?;
    let pid = child.id();
    let start_token = read_process_start_token(pid);

    Ok(UnixConfinedProcess {
        child,
        identity: ProcessStartIdentity { pid, start_token },
        exited: None,
        group_killed: false,
    })
}

/// Verifies `pid` against `expected_start_token` before killing its process group (`-pid`) and PID.
///
/// On Linux, verifies `/proc/<pid>/stat` is not a zombie and its field 22 `starttime` matches
/// `expected_start_token`. On Unix platforms without `/proc` (macOS), accepts only the documented
/// `0` fallback token and verifies the PID is live before sending `SIGKILL`.
pub fn kill_verified_orphan_process(
    pid: u32,
    expected_start_token: u64,
) -> Result<bool, SandboxError> {
    let Ok(raw_pid) = libc::pid_t::try_from(pid) else {
        return Ok(false);
    };
    if raw_pid <= 0 || pid == std::process::id() {
        return Ok(false);
    }

    #[cfg(target_os = "linux")]
    {
        if expected_start_token == 0 {
            return Ok(false);
        }
        let stat = match fs::read_to_string(format!("/proc/{pid}/stat")) {
            Ok(s) => s,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(err) => {
                return Err(SandboxError::Internal(format!(
                    "failed to read /proc/{pid}/stat: {err}"
                )));
            }
        };
        let Some((state, actual_start_token)) = parse_proc_stat_state_and_starttime(&stat) else {
            return Ok(false);
        };
        if state == 'Z' || actual_start_token != expected_start_token {
            return Ok(false);
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        // shortcut: macOS/non-procfs Unix lacks /proc/<pid>/stat starttime; accepts only the
        // documented start_token=0 fallback until Darwin proc_pidinfo/sysctl verification is added
        if expected_start_token != 0 {
            return Ok(false);
        }
        // SAFETY: Signal `0` probes process existence for positive `raw_pid`.
        if unsafe { libc::kill(raw_pid, 0) } != 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ESRCH) {
                return Ok(false);
            }
            return Err(SandboxError::Internal(format!(
                "kill({raw_pid}, 0) failed: {err}"
            )));
        }
    }

    let mut signaled = false;
    if kill_process_group_raw(pid)? {
        signaled = true;
    }

    // SAFETY: `raw_pid > 0` targets the verified orphan process directly.
    if unsafe { libc::kill(raw_pid, libc::SIGKILL) } == 0 {
        signaled = true;
    } else {
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::ESRCH) {
            return Err(SandboxError::Internal(format!(
                "failed to kill orphan process {raw_pid}: {err}"
            )));
        }
    }

    Ok(signaled)
}

fn stdio_from(stdio: ProcessStdio) -> Stdio {
    match stdio {
        ProcessStdio::Null => Stdio::null(),
        ProcessStdio::File(file) => Stdio::from(file),
    }
}

fn exit_status_from_std(status: ExitStatus) -> ProcessExitStatus {
    if let Some(code) = status.code() {
        ProcessExitStatus::Exited(code)
    } else if let Some(sig) = status.signal() {
        ProcessExitStatus::Signaled(sig)
    } else {
        ProcessExitStatus::Exited(-1)
    }
}

fn kill_process_group_raw(pid: u32) -> Result<bool, SandboxError> {
    let Ok(raw_pid) = libc::pid_t::try_from(pid) else {
        return Ok(false);
    };
    if raw_pid <= 0 {
        return Ok(false);
    }
    // SAFETY: `raw_pid > 0` names the child's dedicated process group created by `setpgid(0, 0)`.
    if unsafe { libc::kill(-raw_pid, libc::SIGKILL) } == 0 {
        Ok(true)
    } else {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ESRCH) {
            Ok(false)
        } else {
            Err(SandboxError::Internal(format!(
                "failed to kill process group -{raw_pid}: {err}"
            )))
        }
    }
}

fn read_process_start_token(pid: u32) -> u64 {
    #[cfg(target_os = "linux")]
    {
        fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()
            .and_then(|s| parse_proc_stat_starttime(&s))
            .unwrap_or(0)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::thread;

    struct CleanupDir(PathBuf);

    impl CleanupDir {
        fn unique(prefix: &str) -> Self {
            static SEQ: AtomicU64 = AtomicU64::new(0);
            let seq = SEQ.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!("mpu-{prefix}-{}-{seq}", std::process::id()));
            Self(dir)
        }
    }

    impl Drop for CleanupDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn ensure_owner_only_dir_creates_0700_and_rejects_weak_modes_and_symlinks() {
        let dir = CleanupDir::unique("dir");
        ensure_owner_only_dir(&dir.0).expect("create 0700 dir");
        let meta = fs::symlink_metadata(&dir.0).expect("inspect created dir");
        assert_eq!(meta.mode() & 0o777, 0o700);

        // Idempotent when still 0700 and owned by current user.
        ensure_owner_only_dir(&dir.0).expect("idempotent check passes");

        // Reject 0755 directory.
        fs::set_permissions(&dir.0, fs::Permissions::from_mode(0o755)).expect("chmod 0755");
        assert!(matches!(
            ensure_owner_only_dir(&dir.0),
            Err(SandboxError::PolicyViolation(_))
        ));
        fs::set_permissions(&dir.0, fs::Permissions::from_mode(0o700)).expect("restore 0700");

        // Reject symlink even if pointing to a 0700 directory.
        let link_dir = CleanupDir::unique("link");
        symlink(&dir.0, &link_dir.0).expect("create symlink");
        let res = ensure_owner_only_dir(&link_dir.0);
        let _ = fs::remove_file(&link_dir.0);
        assert!(matches!(res, Err(SandboxError::PolicyViolation(_))));
    }

    #[test]
    fn unix_ipc_listener_sets_0600_removes_stale_socket_and_transfers_bytes() {
        let dir = CleanupDir::unique("sock");
        let sock_path = dir.0.join("agent.sock");

        let listener = UnixIpcListener::bind(&sock_path).expect("bind Unix socket");
        let sock_meta = fs::symlink_metadata(&sock_path).expect("inspect bound socket");
        assert_eq!(sock_meta.mode() & 0o777, 0o600);

        // Stale non-symlink socket file owned by us is replaced cleanly on rebind.
        drop(listener);
        let listener = UnixIpcListener::bind(&sock_path).expect("rebind over stale socket");

        assert!(matches!(
            listener.accept_timeout(Duration::from_millis(20)),
            Err(SandboxError::Transport(_))
        ));

        let client_path = sock_path.clone();
        let client_thread = thread::spawn(move || {
            let mut client = UnixIpcStream::connect(&client_path).expect("connect client");
            client.write_all(b"abc").expect("write");
            let mut buf = [0u8; 3];
            client.read_exact(&mut buf).expect("read");
            assert_eq!(&buf, b"xyz");
        });

        let mut server = listener
            .accept_timeout(Duration::from_secs(2))
            .expect("accept client");
        let mut buf = [0u8; 3];
        server.read_exact(&mut buf).expect("server read");
        assert_eq!(&buf, b"abc");
        server.write_all(b"xyz").expect("server write");
        drop(server);
        client_thread.join().expect("client finishes");
    }

    #[test]
    fn unix_confined_process_sets_process_group_and_kills_descendants_on_drop() {
        let dir = CleanupDir::unique("pgid");
        fs::create_dir_all(&dir.0).expect("create test temp dir");
        let out_path = dir.0.join("grandchild.pid");
        let out_file = fs::File::create(&out_path).expect("create stdout file");

        let mut spec = ProcessLaunchSpec::new(
            "/bin/sh",
            vec![
                "-c".into(),
                "sleep 20 & echo $!; wait".into(),
            ],
        );
        spec.stdout = ProcessStdio::File(out_file);

        let confined = spawn_confined(spec).expect("spawn confined shell");
        let child_pid = confined.id();
        #[cfg(target_os = "linux")]
        assert_ne!(confined.start_identity().start_token, 0);

        let mut grandchild_pid = None;
        for _ in 0..80 {
            if let Ok(text) = fs::read_to_string(&out_path) {
                if let Some(line) = text.lines().next() {
                    if let Ok(pid) = line.trim().parse::<u32>() {
                        grandchild_pid = Some(pid);
                        break;
                    }
                }
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let grandchild_pid = grandchild_pid.expect("shell should print grandchild PID");
        let grandchild_start_token = read_process_start_token(grandchild_pid);
        #[cfg(target_os = "linux")]
        assert_ne!(grandchild_start_token, 0);

        // SAFETY: Signal 0 checks liveness of grandchild PID.
        let alive_rc = unsafe { libc::kill(grandchild_pid as libc::pid_t, 0) };
        assert_eq!(alive_rc, 0, "grandchild PID {grandchild_pid} should be alive");

        drop(confined);

        // SAFETY: Child was reaped by Drop and grandchild was killed with process group.
        let child_after = unsafe { libc::kill(child_pid as libc::pid_t, 0) };
        assert_eq!(child_after, -1);

        let mut grandchild_gone = false;
        for _ in 0..40 {
            if is_process_terminated(grandchild_pid, grandchild_start_token) {
                grandchild_gone = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(15));
        }
        assert!(grandchild_gone, "grandchild PID {grandchild_pid} must be terminated on Drop");
    }

    fn is_process_terminated(pid: u32, expected_start_token: u64) -> bool {
        // SAFETY: Signal `0` probes process existence without delivering a signal.
        if unsafe { libc::kill(pid as libc::pid_t, 0) } == -1
            && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
        {
            return true;
        }
        #[cfg(target_os = "linux")]
        {
            // Inside containers without an active PID 1 zombie reaper (e.g. Docker without --init),
            // a SIGKILLed reparented grandchild briefly stays in state `'Z'` (zombie) where
            // `kill(pid, 0)` still returns `0` until PID 1 exits or reaps it.
            match fs::read_to_string(format!("/proc/{pid}/stat")) {
                Ok(stat) => match parse_proc_stat_state_and_starttime(&stat) {
                    Some((state, actual_start_token)) => {
                        state == 'Z'
                            || (expected_start_token != 0
                                && actual_start_token != expected_start_token)
                    }
                    None => false,
                },
                Err(err) if err.kind() == io::ErrorKind::NotFound => true,
                Err(_) => false,
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = expected_start_token;
            false
        }
    }

    #[test]
    fn unix_kill_verified_orphan_process_rejects_mismatch_and_kills_match() {
        let mut child = Command::new("/bin/sleep")
            .arg("20")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn sleep");
        let pid = child.id();
        let token = read_process_start_token(pid);
        #[cfg(target_os = "linux")]
        assert_ne!(token, 0);

        assert_eq!(kill_verified_orphan_process(pid, token ^ 1), Ok(false));
        assert_eq!(kill_verified_orphan_process(0, token), Ok(false));
        assert_eq!(
            kill_verified_orphan_process(std::process::id(), token),
            Ok(false)
        );
        assert!(child.try_wait().expect("try_wait").is_none());

        assert_eq!(kill_verified_orphan_process(pid, token), Ok(true));
        let status = child.wait().expect("reap killed sleep");
        assert!(!status.success());
        assert_eq!(kill_verified_orphan_process(pid, token), Ok(false));
    }
}
