//! Unix-specific local IPC security primitives: pure-`std` `0700` owner-only runtime
//! directory validation/creation and `0600` Unix domain socket listener/stream for QEMU
//! `-chardev socket,...,server=off`.

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Read, Write};
use std::mem::zeroed;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{
    DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt,
};
use std::os::unix::net::{UnixListener, UnixStream};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use sandbox_core::{EnforcementLevel, SandboxError};

use crate::accel::classify_launch_error;
use crate::ipc::validate_socket_path;
#[cfg(target_os = "linux")]
use crate::process::{
    millicores_to_cgroup_quota_us, parse_proc_stat_starttime, parse_proc_stat_state_and_starttime,
};
use crate::process::{
    ProcessExitStatus, ProcessLaunchSpec, ProcessResourceCapabilities, ProcessStartIdentity,
    ProcessStdio,
};
pub use crate::process::{parse_proc_self_cgroup_v2, parse_proc_statm_rss_bytes};

/// Outcome of probing kernel cross-user access denial on an owner-only Unix domain socket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CrossUserIpcCheck {
    /// OS kernel rejected `connect()` from the unprivileged UID/GID with `EACCES`.
    KernelRejectedAccess,
    /// Current process is unprivileged (`geteuid() != 0`) and cannot drop to a second UID/GID.
    SkippedUnprivilegedNoSetuid { reason: String },
}

fn validate_owner_only_dir_metadata(path: &Path) -> Result<u32, SandboxError> {
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

    Ok(expected_uid)
}

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

    validate_owner_only_dir_metadata(path).map(|_| ())
}

/// Verifies that `socket_path` sits in a non-symlink `0700` owner-only directory, is a
/// non-symlink `0600` socket owned by the current user, and—when running as root
/// (`geteuid() == 0`)—is rejected with `EACCES` (13) by the OS kernel when a forked
/// unprivileged child (`unprivileged_uid`/`unprivileged_gid`, cleared supplementary groups)
/// attempts `connect(AF_UNIX)`.
pub fn verify_non_owner_unix_socket_denied(
    socket_path: &Path,
    unprivileged_uid: u32,
    unprivileged_gid: u32,
) -> Result<CrossUserIpcCheck, SandboxError> {
    validate_socket_path(socket_path)?;
    let parent = socket_path.parent().ok_or_else(|| {
        SandboxError::InvalidSpec(format!(
            "socket path '{}' must have a parent runtime directory",
            socket_path.display()
        ))
    })?;
    let owner_uid = validate_owner_only_dir_metadata(parent)?;

    let sock_meta = fs::symlink_metadata(socket_path).map_err(|err| {
        SandboxError::Transport(format!(
            "failed to inspect Unix socket '{}': {err}",
            socket_path.display()
        ))
    })?;
    if sock_meta.file_type().is_symlink() {
        return Err(SandboxError::PolicyViolation(format!(
            "refusing Unix socket '{}': symlinks are not allowed",
            socket_path.display()
        )));
    }
    if !sock_meta.file_type().is_socket() {
        return Err(SandboxError::PolicyViolation(format!(
            "refusing Unix socket '{}': path exists and is not a Unix domain socket",
            socket_path.display()
        )));
    }
    let sock_mode = sock_meta.mode() & 0o777;
    if sock_mode != 0o600 {
        return Err(SandboxError::PolicyViolation(format!(
            "Unix socket '{}' has insecure permissions {:04o}, expected 0600",
            socket_path.display(),
            sock_mode
        )));
    }
    if sock_meta.uid() != owner_uid {
        return Err(SandboxError::PolicyViolation(format!(
            "Unix socket '{}' is owned by uid {}, expected uid {}",
            socket_path.display(),
            sock_meta.uid(),
            owner_uid
        )));
    }

    // SAFETY: `geteuid()` is a thread-safe POSIX query returning the caller's effective UID.
    let euid = unsafe { libc::geteuid() };
    if euid != 0 {
        return Ok(CrossUserIpcCheck::SkippedUnprivilegedNoSetuid {
            reason: format!(
                "effective uid is {euid} (non-root); kernel cross-user probe for uid={unprivileged_uid} requires root/CAP_SETUID"
            ),
        });
    }
    if unprivileged_uid == euid || unprivileged_uid == owner_uid {
        return Err(SandboxError::InvalidSpec(format!(
            "unprivileged_uid ({unprivileged_uid}) must differ from owner uid ({owner_uid})"
        )));
    }

    let path_bytes = socket_path.as_os_str().as_bytes();
    // SAFETY: `libc::sockaddr_un` is a C POD struct zero-initialized before populating fields.
    let mut addr: libc::sockaddr_un = unsafe { zeroed() };
    if path_bytes.is_empty() || path_bytes.len() >= addr.sun_path.len() || path_bytes.contains(&0)
    {
        return Err(SandboxError::InvalidSpec(format!(
            "socket path '{}' ({} bytes) exceeds sun_path capacity ({} bytes max)",
            socket_path.display(),
            path_bytes.len(),
            addr.sun_path.len().saturating_sub(1)
        )));
    }
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (dst, &byte) in addr.sun_path.iter_mut().zip(path_bytes.iter()) {
        *dst = byte as libc::c_char;
    }
    let sun_path_offset = (&addr.sun_path as *const _ as usize) - (&addr as *const _ as usize);
    let addr_len = (sun_path_offset + path_bytes.len() + 1) as libc::socklen_t;

    // SAFETY: Child executes strictly async-signal-safe `libc` calls (`setgroups`, `setgid`,
    // `setuid`, `socket`, `connect`, `close`, `_exit`) using stack-allocated `addr` with no
    // heap allocations or mutexes.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(SandboxError::Internal(format!(
            "fork() failed during Unix IPC cross-user probe: {}",
            io::Error::last_os_error()
        )));
    }
    if pid == 0 {
        // SAFETY: Freshly forked child branch; terminates unconditionally via `libc::_exit`.
        unsafe {
            unix_probe_child_exec(
                unprivileged_uid as libc::uid_t,
                unprivileged_gid as libc::gid_t,
                &addr,
                addr_len,
            );
        }
    }

    let mut status: libc::c_int = 0;
    loop {
        // SAFETY: `pid > 0` is our newly forked child; `status` is valid stack storage.
        let rc = unsafe { libc::waitpid(pid, &mut status, 0) };
        if rc == pid {
            break;
        }
        if rc == -1 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(SandboxError::Internal(format!(
                "waitpid({pid}) failed during Unix IPC cross-user probe: {err}"
            )));
        }
    }

    if libc::WIFEXITED(status) {
        let code = libc::WEXITSTATUS(status);
        if code == libc::EACCES {
            return Ok(CrossUserIpcCheck::KernelRejectedAccess);
        }
        if code == 0 {
            return Err(SandboxError::PolicyViolation(format!(
                "unprivileged uid={unprivileged_uid} gid={unprivileged_gid} unexpectedly connected to Unix socket '{}'",
                socket_path.display()
            )));
        }
        return Err(SandboxError::PolicyViolation(format!(
            "expected kernel EACCES ({}) connecting to Unix socket '{}' as uid={unprivileged_uid} gid={unprivileged_gid}, child exited with code {code}",
            libc::EACCES,
            socket_path.display()
        )));
    }

    Err(SandboxError::PolicyViolation(format!(
        "Unix IPC cross-user probe child exited abnormally (status={status:#x})"
    )))
}

unsafe fn unix_probe_child_exec(
    uid: libc::uid_t,
    gid: libc::gid_t,
    addr: &libc::sockaddr_un,
    addr_len: libc::socklen_t,
) -> ! {
    // Distinct sentinel codes (251..=255) ensure setup errors never masquerade as EACCES (13).
    const EXIT_SETGROUPS_FAILED: libc::c_int = 251;
    const EXIT_SETGID_FAILED: libc::c_int = 252;
    const EXIT_SETUID_FAILED: libc::c_int = 253;
    const EXIT_SOCKET_FAILED: libc::c_int = 254;
    const EXIT_UNEXPECTED_ERRNO: libc::c_int = 255;

    if libc::setgroups(0, ptr::null()) != 0 {
        libc::_exit(EXIT_SETGROUPS_FAILED);
    }
    if libc::setgid(gid) != 0 {
        libc::_exit(EXIT_SETGID_FAILED);
    }
    if libc::setuid(uid) != 0 {
        libc::_exit(EXIT_SETUID_FAILED);
    }
    let fd = libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0);
    if fd < 0 {
        libc::_exit(EXIT_SOCKET_FAILED);
    }
    let rc = libc::connect(
        fd,
        (addr as *const libc::sockaddr_un).cast::<libc::sockaddr>(),
        addr_len,
    );
    if rc == 0 {
        let _ = libc::close(fd);
        libc::_exit(0);
    }
    let err = current_errno();
    let _ = libc::close(fd);
    if err > 0 && err < 250 {
        libc::_exit(err);
    }
    libc::_exit(EXIT_UNEXPECTED_ERRNO);
}

#[inline]
unsafe fn current_errno() -> libc::c_int {
    #[cfg(target_os = "linux")]
    {
        *libc::__errno_location()
    }
    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))]
    {
        *libc::__error()
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    )))]
    {
        io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO)
    }
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

/// Unix child process confined to its own process group (`pgid == pid`) via `setpgid(0, 0)`
/// and optionally attached to a delegated Linux cgroup v2 leaf cgroup.
pub struct UnixConfinedProcess {
    child: Child,
    identity: ProcessStartIdentity,
    capabilities: ProcessResourceCapabilities,
    #[cfg(target_os = "linux")]
    cgroup_dir: Option<PathBuf>,
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

    /// Returns the honest CPU and memory enforcement levels active for this confined process.
    pub fn resource_capabilities(&self) -> ProcessResourceCapabilities {
        self.capabilities
    }

    /// Samples the live resident set size (`RSS`) in bytes via `/proc/<pid>/statm` on Linux,
    /// returning `None` if the process has exited or on non-Linux Unix platforms.
    pub fn current_rss_bytes(&self) -> Option<u64> {
        if self.exited.is_some() {
            return None;
        }
        #[cfg(target_os = "linux")]
        {
            let pid = self.identity.pid;
            if let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) {
                if let Some((state, _)) = parse_proc_stat_state_and_starttime(&stat) {
                    if state == 'Z' {
                        return None;
                    }
                }
            }
            let statm = fs::read_to_string(format!("/proc/{pid}/statm")).ok()?;
            // SAFETY: `sysconf(_SC_PAGESIZE)` is a read-only POSIX query returning OS page size.
            let raw_page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
            if raw_page_size <= 0 {
                return None;
            }
            let bytes = parse_proc_statm_rss_bytes(&statm, raw_page_size as u64)?;
            (bytes > 0).then_some(bytes)
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
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
                #[cfg(target_os = "linux")]
                self.try_remove_cgroup_dir_once();
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
        #[cfg(target_os = "linux")]
        self.cleanup_cgroup_dir_with_retry();
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn try_remove_cgroup_dir_once(&mut self) {
        if let Some(dir) = self.cgroup_dir.as_ref() {
            match fs::remove_dir(dir) {
                Ok(()) => {
                    self.cgroup_dir = None;
                }
                Err(err) if err.kind() == io::ErrorKind::NotFound => {
                    self.cgroup_dir = None;
                }
                Err(_) => {}
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn cleanup_cgroup_dir_with_retry(&mut self) {
        let Some(dir) = self.cgroup_dir.take() else {
            return;
        };
        for attempt in 0..10 {
            match fs::remove_dir(&dir) {
                Ok(()) => return,
                Err(err) if err.kind() == io::ErrorKind::NotFound => return,
                Err(err)
                    if err.raw_os_error() == Some(libc::EBUSY) && attempt < 9 =>
                {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => return,
            }
        }
    }
}

impl Drop for UnixConfinedProcess {
    fn drop(&mut self) {
        let _ = self.kill_and_wait();
        #[cfg(target_os = "linux")]
        self.cleanup_cgroup_dir_with_retry();
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

    #[cfg(target_os = "linux")]
    let (cgroup_dir, capabilities) = attach_linux_cgroup_v2(
        pid,
        spec.cpu_quota_millicores,
        spec.memory_limit_bytes,
    );
    #[cfg(not(target_os = "linux"))]
    let capabilities = ProcessResourceCapabilities {
        cpu_quota: if spec.cpu_quota_millicores.is_some() {
            EnforcementLevel::Unsupported
        } else {
            EnforcementLevel::BestEffort
        },
        host_rss: if spec.memory_limit_bytes.is_some() {
            EnforcementLevel::Unsupported
        } else {
            EnforcementLevel::BestEffort
        },
    };

    Ok(UnixConfinedProcess {
        child,
        identity: ProcessStartIdentity { pid, start_token },
        capabilities,
        #[cfg(target_os = "linux")]
        cgroup_dir,
        exited: None,
        group_killed: false,
    })
}

/// Verifies `pid` against `expected_start_token` before killing its process group (`-pid`) and PID.
///
/// On Linux, verifies `/proc/<pid>/stat` is not a zombie and its field 22 `starttime` matches
/// `expected_start_token`. On macOS, queries `proc_pidinfo(PROC_PIDTBSDINFO)` to verify non-zombie
/// status and matching microsecond creation time. Unverified (`0`) tokens are unconditionally
/// rejected on all Unix platforms to prevent PID-reuse kills.
pub fn kill_verified_orphan_process(
    pid: u32,
    expected_start_token: u64,
) -> Result<bool, SandboxError> {
    if expected_start_token == 0 {
        return Ok(false);
    }
    let Ok(raw_pid) = libc::pid_t::try_from(pid) else {
        return Ok(false);
    };
    if raw_pid <= 0 || pid == std::process::id() {
        return Ok(false);
    }

    #[cfg(target_os = "linux")]
    {
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

    #[cfg(target_os = "macos")]
    {
        let Some((is_zombie, actual_start_token)) = query_macos_proc_bsd_start_token(pid)? else {
            return Ok(false);
        };
        if is_zombie || actual_start_token != expected_start_token {
            return Ok(false);
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        return Ok(false);
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
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
}

fn stdio_from(stdio: ProcessStdio) -> Stdio {
    match stdio {
        ProcessStdio::Null => Stdio::null(),
        ProcessStdio::File(file) => Stdio::from(file),
        ProcessStdio::PipeWriter(writer) => Stdio::from(writer),
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

#[cfg(any(target_os = "linux", target_os = "macos"))]
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
    #[cfg(target_os = "macos")]
    {
        query_macos_proc_bsd_start_token(pid)
            .ok()
            .flatten()
            .map(|(_, token)| token)
            .unwrap_or(0)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = pid;
        0
    }
}

#[cfg(target_os = "macos")]
fn query_macos_proc_bsd_start_token(pid: u32) -> Result<Option<(bool, u64)>, SandboxError> {
    let Ok(raw_pid) = libc::c_int::try_from(pid) else {
        return Ok(None);
    };
    if raw_pid <= 0 {
        return Ok(None);
    }
    let expected_size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    // SAFETY: `proc_bsdinfo` is a POD C struct written by `proc_pidinfo(PROC_PIDTBSDINFO)`.
    let mut info: libc::proc_bsdinfo = unsafe { zeroed() };
    // SAFETY: `info` provides `expected_size` writable bytes for `PROC_PIDTBSDINFO`.
    let rc = unsafe {
        libc::proc_pidinfo(
            raw_pid,
            libc::PROC_PIDTBSDINFO,
            0,
            (&mut info as *mut libc::proc_bsdinfo).cast::<libc::c_void>(),
            expected_size,
        )
    };
    if rc <= 0 {
        let err = io::Error::last_os_error();
        return match err.raw_os_error() {
            None | Some(0) | Some(libc::ESRCH) => Ok(None),
            _ => Err(SandboxError::Internal(format!(
                "proc_pidinfo({raw_pid}, PROC_PIDTBSDINFO) failed: {err}"
            ))),
        };
    }
    if rc != expected_size {
        return Ok(None);
    }
    let is_zombie = info.pbi_status == libc::SZOMB;
    let token = info
        .pbi_start_tvsec
        .saturating_mul(1_000_000)
        .saturating_add(info.pbi_start_tvusec)
        .max(1);
    Ok(Some((is_zombie, token)))
}

#[cfg(target_os = "linux")]
fn cgroup_v2_dir_path(mount: &Path, cgroup_path: &str) -> PathBuf {
    let rel = cgroup_path.trim_start_matches('/');
    if rel.is_empty() {
        mount.to_path_buf()
    } else {
        mount.join(rel)
    }
}

#[cfg(target_os = "linux")]
fn has_cgroup_controller(list: &str, name: &str) -> bool {
    list.split_ascii_whitespace().any(|token| token == name)
}

#[cfg(target_os = "linux")]
fn is_writable_file(path: &Path) -> bool {
    OpenOptions::new().write(true).open(path).is_ok()
}

#[cfg(target_os = "linux")]
fn attach_linux_cgroup_v2(
    pid: u32,
    cpu_quota_millicores: Option<u32>,
    memory_limit_bytes: Option<u64>,
) -> (Option<PathBuf>, ProcessResourceCapabilities) {
    let fallback_caps = ProcessResourceCapabilities {
        cpu_quota: if cpu_quota_millicores.is_some() {
            EnforcementLevel::Unsupported
        } else {
            EnforcementLevel::BestEffort
        },
        host_rss: if memory_limit_bytes.is_some() {
            EnforcementLevel::Unsupported
        } else {
            EnforcementLevel::BestEffort
        },
    };

    if cpu_quota_millicores.is_none() && memory_limit_bytes.is_none() {
        return (None, fallback_caps);
    }

    let cgroup_mount = Path::new("/sys/fs/cgroup");
    if !cgroup_mount.join("cgroup.controllers").is_file() {
        return (None, fallback_caps);
    }

    let Ok(self_cgroup_raw) = fs::read_to_string("/proc/self/cgroup") else {
        return (None, fallback_caps);
    };
    let Some(self_cgroup_rel) = parse_proc_self_cgroup_v2(&self_cgroup_raw) else {
        return (None, fallback_caps);
    };
    let self_cg_dir = cgroup_v2_dir_path(cgroup_mount, &self_cgroup_rel);

    let mut candidates = Vec::with_capacity(2);
    candidates.push(self_cg_dir.clone());
    if self_cg_dir != cgroup_mount {
        if let Some(parent) = self_cg_dir.parent() {
            if parent.starts_with(cgroup_mount) {
                candidates.push(parent.to_path_buf());
            }
        }
    }

    for candidate in candidates {
        if let Some((dir, caps)) = try_attach_in_cgroup_parent(
            &candidate,
            pid,
            cpu_quota_millicores,
            memory_limit_bytes,
        ) {
            return (Some(dir), caps);
        }
    }

    (None, fallback_caps)
}

#[cfg(target_os = "linux")]
fn try_attach_in_cgroup_parent(
    parent_cg: &Path,
    pid: u32,
    cpu_req: Option<u32>,
    mem_req: Option<u64>,
) -> Option<(PathBuf, ProcessResourceCapabilities)> {
    static CGROUP_SEQ: AtomicU64 = AtomicU64::new(0);

    let procs_path = parent_cg.join("cgroup.procs");
    let subtree_path = parent_cg.join("cgroup.subtree_control");
    if !is_writable_file(&procs_path) {
        return None;
    }

    let subtree_before = fs::read_to_string(&subtree_path).ok()?;
    let need_enable_cpu = cpu_req.is_some() && !has_cgroup_controller(&subtree_before, "cpu");
    let need_enable_mem = mem_req.is_some() && !has_cgroup_controller(&subtree_before, "memory");
    if (need_enable_cpu || need_enable_mem) && !is_writable_file(&subtree_path) {
        return None;
    }

    let seq = CGROUP_SEQ.fetch_add(1, Ordering::Relaxed);
    let child_cg = parent_cg.join(format!("minipod-{}-{pid}-{seq}", std::process::id()));
    if fs::create_dir(&child_cg).is_err() {
        return None;
    }

    if need_enable_cpu {
        let _ = fs::write(&subtree_path, "+cpu");
    }
    if need_enable_mem {
        let _ = fs::write(&subtree_path, "+memory");
    }

    let mut cpu_level = if cpu_req.is_some() {
        EnforcementLevel::Unsupported
    } else {
        EnforcementLevel::BestEffort
    };
    if let Some(millicores) = cpu_req {
        let cpu_max_path = child_cg.join("cpu.max");
        let quota_line = format!("{} 100000", millicores_to_cgroup_quota_us(millicores));
        if cpu_max_path.is_file() && fs::write(&cpu_max_path, quota_line).is_ok() {
            cpu_level = EnforcementLevel::HardLimit;
        }
    }

    let mut host_rss_level = if mem_req.is_some() {
        EnforcementLevel::Unsupported
    } else {
        EnforcementLevel::BestEffort
    };
    if let Some(bytes) = mem_req {
        let mem_max_path = child_cg.join("memory.max");
        if mem_max_path.is_file() && fs::write(&mem_max_path, bytes.to_string()).is_ok() {
            let _ = fs::write(child_cg.join("memory.swap.max"), "0");
            host_rss_level = EnforcementLevel::HardLimit;
        }
    }

    if cpu_level != EnforcementLevel::HardLimit && host_rss_level != EnforcementLevel::HardLimit {
        let _ = fs::remove_dir(&child_cg);
        return None;
    }

    if fs::write(child_cg.join("cgroup.procs"), pid.to_string()).is_err() {
        let _ = fs::remove_dir(&child_cg);
        return None;
    }

    Some((
        child_cg,
        ProcessResourceCapabilities {
            cpu_quota: cpu_level,
            host_rss: host_rss_level,
        },
    ))
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
    fn unix_control_socket_denies_second_user_when_running_as_root() {
        let dir = CleanupDir::unique("xuser");
        ensure_owner_only_dir(&dir.0).expect("create 0700 runtime dir");
        let sock_path = dir.0.join("control.sock");

        let _listener = UnixListener::bind(&sock_path).expect("bind UnixListener");
        fs::set_permissions(&sock_path, fs::Permissions::from_mode(0o600))
            .expect("chmod 0600 control socket");

        let outcome = verify_non_owner_unix_socket_denied(&sock_path, 65534, 65534)
            .expect("verify non-owner access denial");
        // SAFETY: `geteuid()` is a thread-safe POSIX query.
        if unsafe { libc::geteuid() } == 0 {
            assert_eq!(outcome, CrossUserIpcCheck::KernelRejectedAccess);
        } else {
            assert!(matches!(
                outcome,
                CrossUserIpcCheck::SkippedUnprivilegedNoSetuid { .. }
            ));
        }

        // Permissive socket mode (0644) must be rejected immediately.
        fs::set_permissions(&sock_path, fs::Permissions::from_mode(0o644))
            .expect("chmod 0644 control socket");
        assert!(matches!(
            verify_non_owner_unix_socket_denied(&sock_path, 65534, 65534),
            Err(SandboxError::PolicyViolation(_))
        ));
        fs::set_permissions(&sock_path, fs::Permissions::from_mode(0o600))
            .expect("restore 0600 control socket");

        // Permissive parent directory mode (0755) must be rejected immediately.
        fs::set_permissions(&dir.0, fs::Permissions::from_mode(0o755))
            .expect("chmod 0755 runtime dir");
        assert!(matches!(
            verify_non_owner_unix_socket_denied(&sock_path, 65534, 65534),
            Err(SandboxError::PolicyViolation(_))
        ));
        fs::set_permissions(&dir.0, fs::Permissions::from_mode(0o700))
            .expect("restore 0700 runtime dir");

        // Symlink socket path must be rejected immediately.
        let link_sock = dir.0.join("link.sock");
        symlink(&sock_path, &link_sock).expect("create symlink to socket");
        assert!(matches!(
            verify_non_owner_unix_socket_denied(&link_sock, 65534, 65534),
            Err(SandboxError::PolicyViolation(_))
        ));
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
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        assert_ne!(token, 0);

        assert_eq!(kill_verified_orphan_process(pid, 0), Ok(false));
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

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_live_rss_sampling_and_cgroup_v2_capabilities_are_honest() {
        // 1. Uncapped confined child reports BestEffort capabilities and live RSS > 0 until killed.
        let mut uncapped = spawn_confined(ProcessLaunchSpec::new("/bin/sleep", vec!["20".into()]))
            .expect("spawn uncapped sleep");
        assert_eq!(
            uncapped.resource_capabilities(),
            ProcessResourceCapabilities {
                cpu_quota: EnforcementLevel::BestEffort,
                host_rss: EnforcementLevel::BestEffort,
            }
        );
        let rss = uncapped
            .current_rss_bytes()
            .expect("live Linux child must report RSS > 0 from /proc/<pid>/statm");
        assert!(rss > 0, "expected RSS > 0, got {rss}");
        uncapped.kill_and_wait().expect("kill uncapped sleep");
        assert_eq!(uncapped.current_rss_bytes(), None);

        // 2. Capped confined child honestly reports HardLimit (if delegated) or Unsupported (if not).
        let mut spec = ProcessLaunchSpec::new("/bin/sleep", vec!["20".into()]);
        spec.cpu_quota_millicores = Some(500);
        spec.memory_limit_bytes = Some(64 * 1024 * 1024);

        let mut capped = spawn_confined(spec).expect("spawn resource-capped sleep");
        let caps = capped.resource_capabilities();
        assert!(
            matches!(
                caps.cpu_quota,
                EnforcementLevel::HardLimit | EnforcementLevel::Unsupported
            ),
            "unexpected cpu_quota capability when quota requested: {:?}",
            caps.cpu_quota
        );
        assert!(
            matches!(
                caps.host_rss,
                EnforcementLevel::HardLimit | EnforcementLevel::Unsupported
            ),
            "unexpected host_rss capability when memory limit requested: {:?}",
            caps.host_rss
        );

        let capped_rss = capped
            .current_rss_bytes()
            .expect("live capped Linux child must report RSS > 0");
        assert!(capped_rss > 0);

        let maybe_cg_dir = capped.cgroup_dir.clone();
        if caps.cpu_quota == EnforcementLevel::HardLimit
            || caps.host_rss == EnforcementLevel::HardLimit
        {
            let cg_dir = maybe_cg_dir
                .as_ref()
                .expect("HardLimit requires active child cgroup dir");
            assert!(cg_dir.is_dir(), "expected cgroup dir '{}' to exist", cg_dir.display());
            let child_cg_raw = fs::read_to_string(format!("/proc/{}/cgroup", capped.id()))
                .expect("read child /proc/<pid>/cgroup");
            let child_cg_rel =
                parse_proc_self_cgroup_v2(&child_cg_raw).expect("parse child cgroup v2 path");
            let expected_name = cg_dir
                .file_name()
                .and_then(|s| s.to_str())
                .expect("child cgroup dir name");
            assert!(
                child_cg_rel.ends_with(expected_name),
                "expected child cgroup '{child_cg_rel}' to end with '{expected_name}'"
            );
        } else {
            assert!(
                maybe_cg_dir.is_none(),
                "Unsupported enforcement must not leave an unused cgroup directory"
            );
        }

        capped.kill_and_wait().expect("kill capped sleep");
        if let Some(cg_dir) = maybe_cg_dir {
            assert!(
                !cg_dir.exists(),
                "child cgroup dir '{}' must be removed after kill_and_wait",
                cg_dir.display()
            );
        }
    }
}
