//! Unix-specific local IPC security primitives: pure-`std` `0700` owner-only runtime
//! directory validation/creation and `0600` Unix domain socket listener/stream for QEMU
//! `-chardev socket,...,server=off`.

use std::fs::{self, DirBuilder, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{
    DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt,
};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use sandbox_core::SandboxError;

use crate::ipc::validate_socket_path;

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
        fs::set_permissions(socket_path, fs::Permissions::from_mode(0o600)).map_err(|err| {
            SandboxError::Transport(format!(
                "failed to set mode 0600 on Unix socket '{}': {err}",
                socket_path.display()
            ))
        })?;
        listener.set_nonblocking(true).map_err(|err| {
            SandboxError::Transport(format!(
                "failed to set non-blocking mode on Unix listener '{}': {err}",
                socket_path.display()
            ))
        })?;

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
}

impl Read for UnixIpcStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.read(buf)
    }
}

impl Write for UnixIpcStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
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
}
