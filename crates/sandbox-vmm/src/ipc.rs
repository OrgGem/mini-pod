//! Cross-platform host IPC transport for QEMU `virtio-serial` and local endpoint cleanup.
//!
//! # Phase 1 QEMU `virtio-serial` Transport Decision (Measured on QEMU 11.1.0 Windows)
//!
//! Empirical testing on Windows established that QEMU's `-chardev pipe,id=agent0,path=NAME`
//! creates the Named Pipe itself as the server via `CreateNamedPipe(..., NULL)`, applying a
//! permissive default DACL (`(A;;FR;;;WD)(A;;FR;;;AN)` — granting Everyone and Anonymous read
//! access) and failing with `All pipe instances are busy` if the host creates the first
//! instance with `FILE_FLAG_FIRST_PIPE_INSTANCE`.
//!
//! Conversely, QEMU `-chardev socket,id=agent0,path=<sock>,server=off` connects as a client
//! to a host-bound `AF_UNIX` stream listener (`WinSock2` `AF_UNIX` on Windows; Unix domain
//! socket on Linux/macOS) placed inside an owner-only runtime directory (`D:P(A;OICI;GA;;;{sid})`
//! on Windows; `0700` dir + `0600` socket on Unix). This keeps the channel strictly owner-only
//! from creation with zero TOCTOU race across all three platforms.

use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use sandbox_core::SandboxError;

#[cfg(unix)]
use crate::os::unix::{UnixIpcListener, UnixIpcStream};
#[cfg(windows)]
use crate::os::windows::{WindowsUnixListener, WindowsUnixStream};

/// Maximum UTF-8 byte length for a portable `AF_UNIX` socket path (`sun_path` on macOS is
/// 104 bytes including the trailing NUL terminator, so paths must be strictly `< 104` bytes).
pub const MAX_UNIX_SOCKET_PATH_BYTES: usize = 103;
const MAX_WINDOWS_PIPE_NAME_BYTES: usize = 246;

/// Validates that `socket_path` is non-empty UTF-8, has a non-empty parent directory, contains
/// no NUL or QEMU-option-separator characters (`,`), and fits within `< 104` UTF-8 bytes.
pub fn validate_socket_path(socket_path: &Path) -> Result<(), SandboxError> {
    let path_str = socket_path.to_str().ok_or_else(|| {
        SandboxError::InvalidSpec(format!(
            "socket path '{}' is not valid UTF-8",
            socket_path.display()
        ))
    })?;
    if path_str.is_empty() {
        return Err(SandboxError::InvalidSpec(
            "socket path must not be empty".to_owned(),
        ));
    }
    if path_str.contains('\0') || path_str.contains('\r') || path_str.contains('\n') {
        return Err(SandboxError::InvalidSpec(format!(
            "socket path '{}' contains forbidden control characters",
            socket_path.display()
        )));
    }
    if path_str.contains(',') {
        return Err(SandboxError::InvalidSpec(format!(
            "socket path '{}' must not contain ',' (reserved QEMU chardev option delimiter)",
            socket_path.display()
        )));
    }
    if path_str.len() > MAX_UNIX_SOCKET_PATH_BYTES {
        return Err(SandboxError::InvalidSpec(format!(
            "socket path '{}' is {} UTF-8 bytes; must be < 104 bytes for cross-platform AF_UNIX support",
            socket_path.display(),
            path_str.len()
        )));
    }
    let has_parent = socket_path
        .parent()
        .is_some_and(|parent| !parent.as_os_str().is_empty());
    if !has_parent || socket_path.file_name().is_none() {
        return Err(SandboxError::InvalidSpec(format!(
            "socket path '{}' must include an explicit owner-only parent directory and file name",
            socket_path.display()
        )));
    }
    Ok(())
}

/// Validates a bare Windows Named Pipe name (rejects empty strings, path separators, `..`, and NUL).
pub fn validate_pipe_name(pipe_name: &str) -> Result<(), SandboxError> {
    if pipe_name.is_empty() {
        return Err(SandboxError::InvalidSpec(
            "named pipe name must not be empty".to_owned(),
        ));
    }
    if pipe_name.len() > MAX_WINDOWS_PIPE_NAME_BYTES {
        return Err(SandboxError::InvalidSpec(format!(
            "named pipe name '{pipe_name}' exceeds {MAX_WINDOWS_PIPE_NAME_BYTES} bytes"
        )));
    }
    if pipe_name.contains('\0')
        || pipe_name.contains('\\')
        || pipe_name.contains('/')
        || pipe_name.contains("..")
    {
        return Err(SandboxError::InvalidSpec(format!(
            "named pipe name '{pipe_name}' contains forbidden path characters ('\\', '/', '..', or NUL)"
        )));
    }
    Ok(())
}

/// Cross-platform host `AF_UNIX` stream listener bound inside an owner-only runtime directory.
pub struct IpcListener {
    #[cfg(windows)]
    inner: WindowsUnixListener,
    #[cfg(unix)]
    inner: UnixIpcListener,
}

impl IpcListener {
    /// Binds a host `AF_UNIX` listener at `socket_path` after ensuring the parent directory is
    /// restricted strictly to the current user.
    pub fn bind(socket_path: &Path) -> Result<Self, SandboxError> {
        #[cfg(windows)]
        let inner = WindowsUnixListener::bind(socket_path)?;
        #[cfg(unix)]
        let inner = UnixIpcListener::bind(socket_path)?;
        Ok(Self { inner })
    }

    /// Returns the filesystem path of the bound socket.
    pub fn socket_path(&self) -> &Path {
        self.inner.socket_path()
    }

    /// Accepts a single connection within `timeout`.
    pub fn accept_timeout(&self, timeout: Duration) -> Result<IpcStream, SandboxError> {
        #[cfg(windows)]
        let inner = self.inner.accept_timeout(timeout)?;
        #[cfg(unix)]
        let inner = self.inner.accept_timeout(timeout)?;
        Ok(IpcStream { inner })
    }
}

/// Connected bidirectional host `AF_UNIX` stream implementing `Read` + `Write`.
pub struct IpcStream {
    #[cfg(windows)]
    inner: WindowsUnixStream,
    #[cfg(unix)]
    inner: UnixIpcStream,
}

impl IpcStream {
    /// Connects to an existing host `AF_UNIX` listener at `socket_path`.
    pub fn connect(socket_path: &Path) -> Result<Self, SandboxError> {
        #[cfg(windows)]
        let inner = WindowsUnixStream::connect(socket_path)?;
        #[cfg(unix)]
        let inner = UnixIpcStream::connect(socket_path)?;
        Ok(Self { inner })
    }

    /// Sets the read timeout for blocking reads on this stream (`None` clears the timeout).
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<(), SandboxError> {
        self.inner.set_read_timeout(timeout)
    }

    /// Sets the write timeout for blocking writes on this stream (`None` clears the timeout).
    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> Result<(), SandboxError> {
        self.inner.set_write_timeout(timeout)
    }

    /// Sets both read and write timeouts on this stream (`None` clears both timeouts).
    pub fn set_io_timeout(&self, timeout: Option<Duration>) -> Result<(), SandboxError> {
        self.set_read_timeout(timeout)?;
        self.set_write_timeout(timeout)
    }

    /// Shuts down both read and write directions, unblocking any concurrent blocking `read`/`write`.
    pub fn shutdown(&self) -> io::Result<()> {
        self.inner.shutdown_both()
    }

    /// Splits this bidirectional stream into concurrent `Read` and `Write` halves sharing the same
    /// underlying socket.
    pub fn into_split(self) -> (IpcReadHalf, IpcWriteHalf) {
        let shared = Arc::new(self);
        (
            IpcReadHalf {
                stream: Arc::clone(&shared),
            },
            IpcWriteHalf { stream: shared },
        )
    }
}

/// Shared read half produced by [`IpcStream::into_split`].
#[derive(Clone)]
pub struct IpcReadHalf {
    stream: Arc<IpcStream>,
}

impl IpcReadHalf {
    pub fn shutdown(&self) -> io::Result<()> {
        self.stream.shutdown()
    }
}

impl Read for IpcReadHalf {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream.inner.read_shared(buf)
    }
}

/// Shared write half produced by [`IpcStream::into_split`].
#[derive(Clone)]
pub struct IpcWriteHalf {
    stream: Arc<IpcStream>,
}

impl IpcWriteHalf {
    pub fn shutdown(&self) -> io::Result<()> {
        self.stream.shutdown()
    }
}

impl Write for IpcWriteHalf {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream.inner.write_shared(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Read for IpcStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read_shared(buf)
    }
}

impl Write for IpcStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write_shared(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// RAII host endpoint for a VM's `virtio-serial` agent channel.
///
/// Closes the listening socket before removing the socket file (and temp runtime directory if
/// owned) on `Drop`, avoiding Windows sharing violations during cleanup.
pub struct AgentIpcEndpoint {
    listener: Option<IpcListener>,
    socket_path: PathBuf,
    owned_dir: Option<PathBuf>,
}

impl AgentIpcEndpoint {
    /// Binds an `AgentIpcEndpoint` at an explicit `socket_path` (cleans up only `socket_path` on drop).
    pub fn bind(socket_path: &Path) -> Result<Self, SandboxError> {
        let listener = IpcListener::bind(socket_path)?;
        Ok(Self {
            listener: Some(listener),
            socket_path: socket_path.to_path_buf(),
            owned_dir: None,
        })
    }

    /// Creates a short unique owner-only runtime directory under `std::env::temp_dir()` and binds
    /// `a.sock` inside it; removes both the socket file and directory on drop.
    pub fn bind_temp(prefix: &str) -> Result<Self, SandboxError> {
        Self::bind_temp_in(None, prefix)
    }

    /// Creates a short unique owner-only runtime directory under `parent_dir` (or
    /// `std::env::temp_dir()` when `None`) and binds `a.sock` inside it; removes both the socket
    /// file and directory on drop.
    pub fn bind_temp_in(parent_dir: Option<&Path>, prefix: &str) -> Result<Self, SandboxError> {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let safe_prefix: String = prefix
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
            .take(12)
            .collect();
        let tag = if safe_prefix.is_empty() {
            "mp"
        } else {
            &safe_prefix
        };
        let base = match parent_dir {
            Some(parent) => {
                fs::create_dir_all(parent).map_err(|err| {
                    SandboxError::Transport(format!(
                        "failed to create runtime parent directory '{}': {err}",
                        parent.display()
                    ))
                })?;
                parent.to_path_buf()
            }
            None => std::env::temp_dir(),
        };
        let dir = base.join(format!("{tag}-{}-{seq}", std::process::id()));
        let socket_path = dir.join("a.sock");

        match IpcListener::bind(&socket_path) {
            Ok(listener) => Ok(Self {
                listener: Some(listener),
                socket_path,
                owned_dir: Some(dir),
            }),
            Err(err) => {
                let _ = fs::remove_dir(&dir);
                Err(err)
            }
        }
    }

    /// Returns the `AF_UNIX` socket path to pass to QEMU `-chardev socket,id=agent0,path=...,server=off`.
    pub fn socket_path(&self) -> &Path {
        &self.socket_path
    }

    /// Returns a reference to the underlying [`IpcListener`].
    pub fn listener(&self) -> &IpcListener {
        self.listener
            .as_ref()
            .expect("AgentIpcEndpoint listener is always present until Drop")
    }

    /// Waits up to `timeout` for QEMU to connect its `virtio-serial` client socket.
    pub fn accept_timeout(&self, timeout: Duration) -> Result<IpcStream, SandboxError> {
        self.listener().accept_timeout(timeout)
    }
}

impl Drop for AgentIpcEndpoint {
    fn drop(&mut self) {
        // Close listening socket handle before deleting the socket file (required on Windows).
        self.listener.take();
        let _ = fs::remove_file(&self.socket_path);
        if let Some(dir) = &self.owned_dir {
            let _ = fs::remove_dir(dir);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn validate_socket_path_enforces_length_utf8_parent_and_chardev_safety() {
        assert!(validate_socket_path(Path::new("/tmp/mp/a.sock")).is_ok());

        let exact_103 = format!("/tmp/{}/a.sock", "a".repeat(91));
        assert_eq!(exact_103.len(), 103);
        assert!(validate_socket_path(Path::new(&exact_103)).is_ok());

        let exact_104 = format!("/tmp/{}/a.sock", "a".repeat(92));
        assert_eq!(exact_104.len(), 104);
        assert!(matches!(
            validate_socket_path(Path::new(&exact_104)),
            Err(SandboxError::InvalidSpec(_))
        ));

        for bad in ["", "a.sock", "/tmp/a,b/s.sock", "/tmp/a\nb/s.sock"] {
            assert!(
                matches!(validate_socket_path(Path::new(bad)), Err(SandboxError::InvalidSpec(_))),
                "path '{bad}' should fail validation"
            );
        }
    }

    #[test]
    fn validate_pipe_name_rejects_traversal_and_separators() {
        assert!(validate_pipe_name("minipod-daemon.v1").is_ok());

        for bad in ["", r"a\b", "a/b", "..", "foo..bar", "a\0b"] {
            assert!(
                matches!(validate_pipe_name(bad), Err(SandboxError::InvalidSpec(_))),
                "pipe name '{bad}' should be rejected"
            );
        }
        let oversized = "x".repeat(247);
        assert!(matches!(
            validate_pipe_name(&oversized),
            Err(SandboxError::InvalidSpec(_))
        ));
    }

    #[test]
    fn agent_ipc_endpoint_roundtrip_timeout_and_drop_cleanup() {
        let endpoint = AgentIpcEndpoint::bind_temp("ipc-test").expect("bind temp IPC endpoint");
        let sock_path = endpoint.socket_path().to_path_buf();
        let runtime_dir = sock_path.parent().expect("runtime dir").to_path_buf();
        assert!(sock_path.exists());

        // Timeout returns Transport error instead of hanging forever.
        assert!(matches!(
            endpoint.accept_timeout(Duration::from_millis(25)),
            Err(SandboxError::Transport(_))
        ));

        let client_path = sock_path.clone();
        let client_thread = thread::spawn(move || {
            let mut client = IpcStream::connect(&client_path).expect("connect to listener");
            client.write_all(b"ping").expect("write ping");
            let mut reply = [0u8; 4];
            client.read_exact(&mut reply).expect("read pong");
            assert_eq!(&reply, b"pong");
        });

        let mut server = endpoint
            .accept_timeout(Duration::from_secs(2))
            .expect("accept client connection");
        let mut msg = [0u8; 4];
        server.read_exact(&mut msg).expect("read ping");
        assert_eq!(&msg, b"ping");
        server.write_all(b"pong").expect("write pong");
        drop(server);
        client_thread.join().expect("client thread completes");

        drop(endpoint);
        assert!(!sock_path.exists(), "socket file should be removed on drop");
        assert!(
            !runtime_dir.exists(),
            "owned temp runtime dir should be removed on drop"
        );
    }

    #[test]
    fn ipc_stream_read_timeout_does_not_hang_on_silent_peer() {
        let endpoint = AgentIpcEndpoint::bind_temp("ipc-timo").expect("bind temp endpoint");
        let client_path = endpoint.socket_path().to_path_buf();

        let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
        let client_thread = thread::spawn(move || {
            let _client = IpcStream::connect(&client_path).expect("connect silent client");
            let _ = done_rx.recv();
        });

        let mut server = endpoint
            .accept_timeout(Duration::from_secs(2))
            .expect("accept silent client");

        assert!(matches!(
            server.set_read_timeout(Some(Duration::ZERO)),
            Err(SandboxError::InvalidSpec(_))
        ));
        assert!(matches!(
            server.set_write_timeout(Some(Duration::ZERO)),
            Err(SandboxError::InvalidSpec(_))
        ));

        server
            .set_io_timeout(Some(Duration::from_millis(60)))
            .expect("set stream timeouts");
        let mut byte = [0u8; 1];
        let err = server
            .read(&mut byte)
            .expect_err("silent peer should trigger read timeout");
        assert!(
            matches!(err.kind(), io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock),
            "expected TimedOut or WouldBlock, got {err:?}"
        );

        server.set_io_timeout(None).expect("clear stream timeouts");
        let _ = done_tx.send(());
        drop(server);
        client_thread.join().expect("client thread completes");
    }
}
