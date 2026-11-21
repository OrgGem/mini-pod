//! Windows-specific local IPC security primitives: owner-only Named Pipe DACLs,
//! owner-only runtime directories, WinSock2 `AF_UNIX` transport for QEMU
//! `-chardev socket,...,server=off`, and SDDL inspection helpers.

use std::ffi::{c_void, OsStr};
use std::fs;
use std::io::{self, Read, Write};
use std::mem::{size_of, zeroed, ManuallyDrop};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::RawHandle;
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use std::sync::Once;
use std::time::Duration;

use sandbox_core::SandboxError;
use tokio::net::windows::named_pipe::NamedPipeServer;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, BOOL, ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS,
    ERROR_BROKEN_PIPE, ERROR_INSUFFICIENT_BUFFER, ERROR_NO_DATA, ERROR_PIPE_CONNECTED,
    GENERIC_READ, GENERIC_WRITE, HANDLE, HLOCAL, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Networking::WinSock::{
    accept, bind, closesocket, connect, listen, recv, select, send, setsockopt, shutdown, socket,
    WSAGetLastError, WSAStartup, AF_UNIX, FD_SET, INVALID_SOCKET, SD_BOTH, SOCKADDR, SOCKET,
    SOCKET_ERROR, SOCK_STREAM, SOL_SOCKET, SO_RCVTIMEO, SO_SNDTIMEO, TIMEVAL, WSADATA,
    WSAENOPROTOOPT, WSAEOPNOTSUPP,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW,
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
    SE_FILE_OBJECT, SE_KERNEL_OBJECT,
};
use windows_sys::Win32::Security::{
    CreateRestrictedToken, DuplicateTokenEx, GetTokenInformation, ImpersonateLoggedOnUser,
    RevertToSelf, SecurityImpersonation, TokenImpersonation, TokenUser, DACL_SECURITY_INFORMATION,
    OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES,
    SID_AND_ATTRIBUTES, TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, FindClose, FindFirstFileW, FlushFileBuffers,
    GetFileAttributesW, ReadFile, WriteFile, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL,
    FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_FIRST_PIPE_INSTANCE,
    FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_OVERLAPPED, FILE_SHARE_DELETE, FILE_SHARE_READ,
    FILE_SHARE_WRITE, INVALID_FILE_ATTRIBUTES, OPEN_EXISTING, PIPE_ACCESS_DUPLEX, READ_CONTROL,
    SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT, WIN32_FIND_DATAW,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS,
    PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::ipc::{validate_pipe_name, validate_socket_path};

/// Win32 `IO_REPARSE_TAG_AF_UNIX` reparse tag assigned to WinSock2 `AF_UNIX` socket files.
const IO_REPARSE_TAG_AF_UNIX: u32 = 0x8000_0023;
const PIPE_BUFFER_BYTES: u32 = 64 * 1024;

/// WinSock2 `SOCKADDR_UN` layout (`<afunix.h>`): `ADDRESS_FAMILY` + 108-byte `sun_path`.
#[repr(C)]
struct SockAddrUn {
    sun_family: u16,
    sun_path: [u8; 108],
}

pub(crate) struct OwnedHandle(HANDLE);

impl OwnedHandle {
    pub(crate) fn from_raw(handle: HANDLE) -> Result<Self, SandboxError> {
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            return Err(SandboxError::Transport(format!(
                "Win32 returned invalid handle: {}",
                io::Error::last_os_error()
            )));
        }
        Ok(Self(handle))
    }

    pub(crate) fn as_raw(&self) -> HANDLE {
        self.0
    }

    pub(crate) fn into_raw(self) -> HANDLE {
        let handle = ManuallyDrop::new(self);
        handle.0
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: `self.0` is an owned, non-null Win32 handle not yet closed.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

struct FindHandle(HANDLE);

impl Drop for FindHandle {
    fn drop(&mut self) {
        if !self.0.is_null() && self.0 != INVALID_HANDLE_VALUE {
            // SAFETY: `self.0` is a valid search handle returned by `FindFirstFileW`.
            unsafe {
                FindClose(self.0);
            }
        }
    }
}

struct LocalAllocGuard(*mut c_void);

impl LocalAllocGuard {
    fn as_ptr(&self) -> *mut c_void {
        self.0
    }
}

impl Drop for LocalAllocGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: `self.0` was allocated by a Win32 API using `LocalAlloc`.
            unsafe {
                LocalFree(self.0 as HLOCAL);
            }
        }
    }
}

struct OwnedSocket(SOCKET);

impl Drop for OwnedSocket {
    fn drop(&mut self) {
        if self.0 != INVALID_SOCKET {
            // SAFETY: `self.0` is an owned WinSock2 socket handle not yet closed.
            unsafe {
                closesocket(self.0);
            }
        }
    }
}

/// Owned Windows Named Pipe handle (server or connected client) supporting `Read` + `Write`.
pub struct OwnedNamedPipe {
    handle: OwnedHandle,
    pipe_path: String,
}

impl OwnedNamedPipe {
    /// Returns the full NT/Win32 named pipe path (`\\.\pipe\<name>`).
    pub fn pipe_path(&self) -> &str {
        &self.pipe_path
    }

    /// Waits for a client connection on a server-side Named Pipe instance.
    pub fn accept_client(&self) -> Result<(), SandboxError> {
        // SAFETY: `self.handle.as_raw()` is an open synchronous server Named Pipe handle.
        let ok = unsafe { ConnectNamedPipe(self.handle.as_raw(), ptr::null_mut()) };
        if ok != 0 {
            return Ok(());
        }
        // SAFETY: Reading thread-local Win32 last error after `ConnectNamedPipe` failure.
        let err = unsafe { GetLastError() };
        if err == ERROR_PIPE_CONNECTED {
            return Ok(());
        }
        Err(SandboxError::Transport(format!(
            "ConnectNamedPipe('{}') failed: {}",
            self.pipe_path,
            io::Error::from_raw_os_error(err as i32)
        )))
    }

    /// Returns the live DACL SDDL string currently enforced on this Named Pipe handle.
    pub fn inspect_pipe_sddl(&self) -> Result<String, SandboxError> {
        inspect_object_sddl(&self.handle)
    }
}

impl Read for OwnedNamedPipe {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let len = buf.len().min(u32::MAX as usize) as u32;
        let mut read_bytes: u32 = 0;
        // SAFETY: `self.handle` is valid; `buf` provides `len` writable bytes and `read_bytes` is valid stack storage.
        let ok: BOOL = unsafe {
            ReadFile(
                self.handle.as_raw(),
                buf.as_mut_ptr(),
                len,
                &mut read_bytes,
                ptr::null_mut(),
            )
        };
        if ok != 0 {
            return Ok(read_bytes as usize);
        }
        let err = io::Error::last_os_error();
        if matches!(
            err.raw_os_error(),
            Some(code) if code == ERROR_BROKEN_PIPE as i32 || code == ERROR_NO_DATA as i32
        ) {
            return Ok(0);
        }
        Err(err)
    }
}

impl Write for OwnedNamedPipe {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let len = buf.len().min(u32::MAX as usize) as u32;
        let mut written: u32 = 0;
        // SAFETY: `self.handle` is valid; `buf` provides `len` readable bytes and `written` is valid stack storage.
        let ok: BOOL = unsafe {
            WriteFile(
                self.handle.as_raw(),
                buf.as_ptr(),
                len,
                &mut written,
                ptr::null_mut(),
            )
        };
        if ok != 0 {
            return Ok(written as usize);
        }
        Err(io::Error::last_os_error())
    }

    fn flush(&mut self) -> io::Result<()> {
        // SAFETY: `self.handle` is a valid open pipe handle.
        let ok = unsafe { FlushFileBuffers(self.handle.as_raw()) };
        if ok != 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

/// Host-bound WinSock2 `AF_UNIX` stream listener for QEMU `-chardev socket,...,server=off`.
pub struct WindowsUnixListener {
    socket: OwnedSocket,
    path: PathBuf,
}

impl WindowsUnixListener {
    /// Ensures `socket_path`'s parent is an owner-only directory (`D:P(A;OICI;GA;;;{sid})`),
    /// removes any stale non-symlink `AF_UNIX` socket file, and binds + listens.
    pub fn bind(socket_path: &Path) -> Result<Self, SandboxError> {
        ensure_wsa_started()?;
        validate_socket_path(socket_path)?;
        let parent = socket_path.parent().ok_or_else(|| {
            SandboxError::InvalidSpec(format!(
                "socket path '{}' must have a parent runtime directory",
                socket_path.display()
            ))
        })?;
        create_owner_only_dir(parent)?;
        remove_stale_socket_if_safe(socket_path)?;

        // SAFETY: `WSAStartup` succeeded above; creates an unbound `AF_UNIX` stream socket.
        let raw = unsafe { socket(AF_UNIX as i32, SOCK_STREAM, 0) };
        if raw == INVALID_SOCKET {
            return Err(wsa_error("socket(AF_UNIX)"));
        }
        let sock = OwnedSocket(raw);

        let addr = build_sockaddr_un(socket_path)?;
        // SAFETY: `sock.0` is a valid socket and `addr` is a properly initialized `SockAddrUn`.
        let bind_rc = unsafe {
            bind(
                sock.0,
                (&addr as *const SockAddrUn).cast::<SOCKADDR>(),
                size_of::<SockAddrUn>() as i32,
            )
        };
        if bind_rc == SOCKET_ERROR {
            return Err(wsa_error(&format!(
                "bind('{}')",
                socket_path.display()
            )));
        }

        // SAFETY: `sock.0` is bound to `socket_path`.
        let listen_rc = unsafe { listen(sock.0, 16) };
        if listen_rc == SOCKET_ERROR {
            return Err(wsa_error(&format!(
                "listen('{}')",
                socket_path.display()
            )));
        }

        Ok(Self {
            socket: sock,
            path: socket_path.to_path_buf(),
        })
    }

    /// Returns the bound filesystem path for this listener.
    pub fn socket_path(&self) -> &Path {
        &self.path
    }

    /// Waits up to `timeout` using `select` and accepts an incoming QEMU connection.
    pub fn accept_timeout(&self, timeout: Duration) -> Result<WindowsUnixStream, SandboxError> {
        let ready = select_socket_ready(self.socket.0, false, timeout).map_err(|err| {
            SandboxError::Transport(format!("select('{}') failed: {err}", self.path.display()))
        })?;
        if !ready {
            return Err(SandboxError::Transport(format!(
                "timed out after {}ms waiting for connection on '{}'",
                timeout.as_millis(),
                self.path.display()
            )));
        }

        // SAFETY: `select` indicated readability on `self.socket.0`.
        let client = unsafe { accept(self.socket.0, ptr::null_mut(), ptr::null_mut()) };
        if client == INVALID_SOCKET {
            return Err(wsa_error(&format!(
                "accept('{}')",
                self.path.display()
            )));
        }
        Ok(WindowsUnixStream::new(OwnedSocket(client)))
    }
}

/// Connected WinSock2 `AF_UNIX` stream implementing `Read` + `Write` with timeout support.
pub struct WindowsUnixStream {
    socket: OwnedSocket,
    // Fallback millisecond timeouts used only if WinSock `afunix` rejects `SO_RCVTIMEO`/`SO_SNDTIMEO`.
    fallback_read_timeout_ms: AtomicU32,
    fallback_write_timeout_ms: AtomicU32,
}

impl WindowsUnixStream {
    fn new(socket: OwnedSocket) -> Self {
        Self {
            socket,
            fallback_read_timeout_ms: AtomicU32::new(0),
            fallback_write_timeout_ms: AtomicU32::new(0),
        }
    }

    /// Connects as a client to an existing `AF_UNIX` socket path.
    pub fn connect(socket_path: &Path) -> Result<Self, SandboxError> {
        ensure_wsa_started()?;
        validate_socket_path(socket_path)?;

        // SAFETY: `WSAStartup` succeeded above.
        let raw = unsafe { socket(AF_UNIX as i32, SOCK_STREAM, 0) };
        if raw == INVALID_SOCKET {
            return Err(wsa_error("socket(AF_UNIX)"));
        }
        let sock = OwnedSocket(raw);
        let addr = build_sockaddr_un(socket_path)?;

        // SAFETY: `sock.0` is valid and `addr` is a properly initialized `SockAddrUn`.
        let rc = unsafe {
            connect(
                sock.0,
                (&addr as *const SockAddrUn).cast::<SOCKADDR>(),
                size_of::<SockAddrUn>() as i32,
            )
        };
        if rc == SOCKET_ERROR {
            return Err(wsa_error(&format!(
                "connect('{}')",
                socket_path.display()
            )));
        }
        Ok(Self::new(sock))
    }

    /// Configures the socket receive timeout via `SO_RCVTIMEO` (`None` clears the timeout).
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> Result<(), SandboxError> {
        self.set_socket_timeout(
            SO_RCVTIMEO,
            timeout,
            "SO_RCVTIMEO",
            &self.fallback_read_timeout_ms,
        )
    }

    /// Configures the socket send timeout via `SO_SNDTIMEO` (`None` clears the timeout).
    pub fn set_write_timeout(&self, timeout: Option<Duration>) -> Result<(), SandboxError> {
        self.set_socket_timeout(
            SO_SNDTIMEO,
            timeout,
            "SO_SNDTIMEO",
            &self.fallback_write_timeout_ms,
        )
    }

    fn set_socket_timeout(
        &self,
        optname: i32,
        timeout: Option<Duration>,
        label: &str,
        fallback_ms: &AtomicU32,
    ) -> Result<(), SandboxError> {
        let ms = duration_to_win_timeout_ms(timeout)?;
        // SAFETY: `self.socket.0` is an open WinSock2 socket and `ms` is a 4-byte `DWORD` (`SO_RCVTIMEO`/`SO_SNDTIMEO`).
        let rc = unsafe {
            setsockopt(
                self.socket.0,
                SOL_SOCKET,
                optname,
                (&ms as *const u32).cast::<u8>(),
                size_of::<u32>() as i32,
            )
        };
        if rc == SOCKET_ERROR {
            // SAFETY: Thread-local WinSock error code immediately after failed `setsockopt`.
            let code = unsafe { WSAGetLastError() };
            if code == WSAENOPROTOOPT || code == WSAEOPNOTSUPP {
                fallback_ms.store(ms, Ordering::Release);
                return Ok(());
            }
            return Err(SandboxError::Transport(format!(
                "setsockopt({label}) failed with WinSock error {code}: {}",
                io::Error::from_raw_os_error(code)
            )));
        }
        fallback_ms.store(0, Ordering::Release);
        Ok(())
    }

    /// Reads bytes concurrently from a shared `&WindowsUnixStream` reference.
    pub fn read_shared(&self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let fallback_ms = self.fallback_read_timeout_ms.load(Ordering::Acquire);
        if fallback_ms > 0
            && !select_socket_ready(self.socket.0, false, Duration::from_millis(u64::from(fallback_ms)))?
        {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "WinSock AF_UNIX read timed out",
            ));
        }

        let len = buf.len().min(i32::MAX as usize) as i32;
        // SAFETY: `self.socket.0` is an open connected socket and `buf` has `len` writable bytes.
        let rc = unsafe { recv(self.socket.0, buf.as_mut_ptr(), len, 0) };
        if rc == SOCKET_ERROR {
            // SAFETY: Thread-local WinSock error code after `recv` failure.
            let code = unsafe { WSAGetLastError() };
            return Err(io::Error::from_raw_os_error(code));
        }
        Ok(rc as usize)
    }

    /// Writes bytes concurrently to a shared `&WindowsUnixStream` reference.
    pub fn write_shared(&self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let fallback_ms = self.fallback_write_timeout_ms.load(Ordering::Acquire);
        if fallback_ms > 0
            && !select_socket_ready(self.socket.0, true, Duration::from_millis(u64::from(fallback_ms)))?
        {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "WinSock AF_UNIX write timed out",
            ));
        }

        let len = buf.len().min(i32::MAX as usize) as i32;
        // SAFETY: `self.socket.0` is an open connected socket and `buf` has `len` readable bytes.
        let rc = unsafe { send(self.socket.0, buf.as_ptr(), len, 0) };
        if rc == SOCKET_ERROR {
            // SAFETY: Thread-local WinSock error code after `send` failure.
            let code = unsafe { WSAGetLastError() };
            return Err(io::Error::from_raw_os_error(code));
        }
        Ok(rc as usize)
    }

    /// Shuts down both read and write halves of the WinSock `AF_UNIX` stream.
    pub fn shutdown_both(&self) -> io::Result<()> {
        // SAFETY: `self.socket.0` is a valid socket owned by `self.socket` (`OwnedSocket`).
        let rc = unsafe { shutdown(self.socket.0, SD_BOTH) };
        if rc == SOCKET_ERROR {
            // SAFETY: Thread-local WinSock error code after `shutdown` failure.
            let code = unsafe { WSAGetLastError() };
            return Err(io::Error::from_raw_os_error(code));
        }
        Ok(())
    }
}

impl Read for WindowsUnixStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.read_shared(buf)
    }
}

impl Write for WindowsUnixStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.write_shared(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn duration_to_win_timeout_ms(timeout: Option<Duration>) -> Result<u32, SandboxError> {
    match timeout {
        None => Ok(0),
        Some(dur) if dur.is_zero() => Err(SandboxError::InvalidSpec(
            "IPC stream timeout must be greater than zero (use None to clear)".to_owned(),
        )),
        Some(dur) => {
            // WinSock SO_RCVTIMEO/SO_SNDTIMEO interprets 0 as infinite, so clamp sub-ms durations to 1ms.
            Ok(dur.as_millis().clamp(1, u32::MAX as u128) as u32)
        }
    }
}

fn select_socket_ready(sock: SOCKET, for_write: bool, timeout: Duration) -> io::Result<bool> {
    let mut fds = FD_SET {
        fd_count: 1,
        fd_array: [0; 64],
    };
    fds.fd_array[0] = sock;
    let tv = TIMEVAL {
        tv_sec: timeout.as_secs().min(i32::MAX as u64) as i32,
        tv_usec: timeout.subsec_micros() as i32,
    };
    let (readfds, writefds) = if for_write {
        (ptr::null_mut(), &mut fds as *mut FD_SET)
    } else {
        (&mut fds as *mut FD_SET, ptr::null_mut())
    };
    // SAFETY: `fds` holds one open socket and `tv` is valid stack storage.
    let ready = unsafe { select(0, readfds, writefds, ptr::null_mut(), &tv) };
    if ready == SOCKET_ERROR {
        // SAFETY: Thread-local WinSock error code immediately after failed `select`.
        let code = unsafe { WSAGetLastError() };
        return Err(io::Error::from_raw_os_error(code));
    }
    Ok(ready > 0)
}

fn query_token_user_buf(token: &OwnedHandle) -> Result<Vec<usize>, SandboxError> {
    let mut needed: u32 = 0;
    // SAFETY: Probing required buffer length with null buffer and zero length.
    unsafe {
        GetTokenInformation(token.as_raw(), TokenUser, ptr::null_mut(), 0, &mut needed);
    }
    // SAFETY: Reading thread-local Win32 last error after size query.
    let probe_err = unsafe { GetLastError() };
    if probe_err != ERROR_INSUFFICIENT_BUFFER || needed == 0 {
        return Err(SandboxError::Internal(format!(
            "GetTokenInformation(TokenUser) size probe failed: {}",
            io::Error::from_raw_os_error(probe_err as i32)
        )));
    }

    // Align backing buffer to `usize` so casting to `TOKEN_USER` (pointer-aligned) is well-aligned.
    let words = (needed as usize).div_ceil(size_of::<usize>());
    let mut buf = vec![0usize; words];
    let mut returned: u32 = 0;
    // SAFETY: `buf` has at least `needed` bytes and `usize` alignment for `TOKEN_USER`.
    let ok = unsafe {
        GetTokenInformation(
            token.as_raw(),
            TokenUser,
            buf.as_mut_ptr().cast(),
            needed,
            &mut returned,
        )
    };
    if ok == 0 {
        return Err(win32_error("GetTokenInformation(TokenUser)"));
    }
    if (returned as usize) < size_of::<TOKEN_USER>() {
        return Err(SandboxError::Internal(
            "GetTokenInformation(TokenUser) returned truncated buffer".to_owned(),
        ));
    }
    Ok(buf)
}

/// Returns the current process user's SID string (e.g. `S-1-5-21-...`).
pub fn current_user_sid_string() -> Result<String, SandboxError> {
    let mut raw_token: HANDLE = ptr::null_mut();
    // SAFETY: `GetCurrentProcess()` returns a pseudo-handle that does not need closing; `raw_token` receives the owned token handle.
    let ok = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw_token) };
    if ok == 0 {
        return Err(win32_error("OpenProcessToken"));
    }
    let token = OwnedHandle::from_raw(raw_token)?;
    let buf = query_token_user_buf(&token)?;
    // SAFETY: `query_token_user_buf` verified `returned >= size_of::<TOKEN_USER>()` and `usize` alignment.
    let token_user = unsafe { &*(buf.as_ptr().cast::<TOKEN_USER>()) };
    sid_to_string(token_user.User.Sid)
}

/// Builds a protected (`D:P`) owner-only SDDL string with optional `OICI` inheritance for directories.
pub fn owner_only_sddl(user_sid: &str, inherit: bool) -> String {
    if inherit {
        format!("D:P(A;OICI;GA;;;{user_sid})")
    } else {
        format!("D:P(A;;GA;;;{user_sid})")
    }
}

fn create_owner_only_named_pipe_raw(
    pipe_name: &str,
    open_mode_flags: u32,
    max_instances: u32,
) -> Result<(OwnedHandle, String), SandboxError> {
    validate_pipe_name(pipe_name)?;
    let user_sid = current_user_sid_string()?;
    let sddl = owner_only_sddl(&user_sid, false);
    let sd = sddl_to_security_descriptor(&sddl)?;
    let sa = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.as_ptr(),
        bInheritHandle: 0,
    };

    let pipe_path = format!(r"\\.\pipe\{pipe_name}");
    let wide_path = to_wide_null(OsStr::new(&pipe_path))?;

    // SAFETY: `wide_path` is NUL-terminated and `sa` points to a valid `SECURITY_DESCRIPTOR` kept alive through the call.
    let raw = unsafe {
        CreateNamedPipeW(
            wide_path.as_ptr(),
            PIPE_ACCESS_DUPLEX | open_mode_flags,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            max_instances,
            PIPE_BUFFER_BYTES,
            PIPE_BUFFER_BYTES,
            0,
            &sa,
        )
    };
    let handle = OwnedHandle::from_raw(raw).map_err(|err| {
        SandboxError::Transport(format!(
            "CreateNamedPipeW('{pipe_path}') failed: {err}"
        ))
    })?;

    Ok((handle, pipe_path))
}

/// Creates a server Named Pipe (`\\.\pipe\<pipe_name>`) with `FILE_FLAG_FIRST_PIPE_INSTANCE`
/// and a protected owner-only DACL (`D:P(A;;GA;;;{user_sid})`).
pub fn create_owner_only_named_pipe(pipe_name: &str) -> Result<OwnedNamedPipe, SandboxError> {
    let (handle, pipe_path) =
        create_owner_only_named_pipe_raw(pipe_name, FILE_FLAG_FIRST_PIPE_INSTANCE, 1)?;
    Ok(OwnedNamedPipe { handle, pipe_path })
}

/// Creates an asynchronous overlapped server Named Pipe instance (`\\.\pipe\<pipe_name>`)
/// bound with `PIPE_REJECT_REMOTE_CLIENTS`, `PIPE_UNLIMITED_INSTANCES` (255), and a protected
/// owner-only DACL (`D:P(A;;GA;;;{user_sid})`), wrapped as a Tokio [`NamedPipeServer`].
pub fn create_owner_only_async_named_pipe(
    pipe_name: &str,
    first_instance: bool,
) -> Result<NamedPipeServer, SandboxError> {
    validate_pipe_name(pipe_name)?;
    tokio::runtime::Handle::try_current().map_err(|err| {
        SandboxError::Transport(format!(
            "create_owner_only_async_named_pipe('{pipe_name}') requires an active Tokio runtime: {err}"
        ))
    })?;
    let open_flags = FILE_FLAG_OVERLAPPED
        | if first_instance {
            FILE_FLAG_FIRST_PIPE_INSTANCE
        } else {
            0
        };
    let (handle, pipe_path) =
        create_owner_only_named_pipe_raw(pipe_name, open_flags, PIPE_UNLIMITED_INSTANCES)?;
    let raw_handle = handle.into_raw();
    // SAFETY: `raw_handle` is a newly created, uniquely owned overlapped server Named Pipe handle
    // not yet registered with any I/O completion port. `NamedPipeServer::from_raw_handle`
    // unconditionally wraps `raw_handle` in `mio::windows::NamedPipe` (`Handle::new`) before
    // `PollEvented::new`, so it closes the handle even if Tokio registration returns `Err`.
    unsafe { NamedPipeServer::from_raw_handle(raw_handle as RawHandle) }.map_err(|err| {
        SandboxError::Transport(format!(
            "NamedPipeServer::from_raw_handle('{pipe_path}') failed: {err}"
        ))
    })
}

/// Verifies against the Windows kernel that a restricted token with the owner's user SID disabled
/// (while keeping all non-owner group SIDs active) receives `ERROR_ACCESS_DENIED` when opening
/// `\\.\pipe\<pipe_name>`.
///
/// Runs impersonation strictly on a dedicated ephemeral OS worker thread so the caller thread's
/// security token is never modified.
pub fn verify_non_owner_named_pipe_denied(pipe_name: &str) -> Result<(), SandboxError> {
    validate_pipe_name(pipe_name)?;
    let owned_name = pipe_name.to_owned();
    let handle = std::thread::Builder::new()
        .name("minipod-pipe-acl-probe".to_owned())
        .spawn(move || verify_non_owner_named_pipe_denied_on_worker(&owned_name))
        .map_err(|err| {
            SandboxError::Internal(format!(
                "failed to spawn Windows named pipe ACL probe thread: {err}"
            ))
        })?;

    handle.join().map_err(|_| {
        SandboxError::Internal("Windows named pipe ACL probe thread panicked".to_owned())
    })?
}

fn verify_non_owner_named_pipe_denied_on_worker(pipe_name: &str) -> Result<(), SandboxError> {
    struct RevertToSelfGuard;
    impl Drop for RevertToSelfGuard {
        fn drop(&mut self) {
            // SAFETY: Restores the worker thread's security context on every return/panic path.
            let _ = unsafe { RevertToSelf() };
        }
    }

    let mut raw_process_token: HANDLE = ptr::null_mut();
    // SAFETY: `GetCurrentProcess()` returns a pseudo-handle; `raw_process_token` receives an owned token handle.
    let ok = unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_DUPLICATE | TOKEN_QUERY,
            &mut raw_process_token,
        )
    };
    if ok == 0 {
        return Err(win32_error("OpenProcessToken(TOKEN_DUPLICATE | TOKEN_QUERY)"));
    }
    let process_token = OwnedHandle::from_raw(raw_process_token)?;
    let token_user_buf = query_token_user_buf(&process_token)?;
    // SAFETY: `query_token_user_buf` verified alignment and size for `TOKEN_USER`.
    let token_user = unsafe { &*(token_user_buf.as_ptr().cast::<TOKEN_USER>()) };
    let sids_to_disable = [SID_AND_ATTRIBUTES {
        Sid: token_user.User.Sid,
        Attributes: 0,
    }];

    let mut raw_restricted: HANDLE = ptr::null_mut();
    // SAFETY: `process_token` is valid; `sids_to_disable` points into `token_user_buf` which outlives this call.
    let ok = unsafe {
        CreateRestrictedToken(
            process_token.as_raw(),
            0,
            sids_to_disable.len() as u32,
            sids_to_disable.as_ptr(),
            0,
            ptr::null(),
            0,
            ptr::null(),
            &mut raw_restricted,
        )
    };
    if ok == 0 {
        return Err(win32_error("CreateRestrictedToken"));
    }
    let restricted_token = OwnedHandle::from_raw(raw_restricted)?;

    let mut raw_imp: HANDLE = ptr::null_mut();
    // SAFETY: `restricted_token` is an owned primary token duplicated into a `SecurityImpersonation` impersonation token.
    let ok = unsafe {
        DuplicateTokenEx(
            restricted_token.as_raw(),
            TOKEN_IMPERSONATE | TOKEN_QUERY,
            ptr::null(),
            SecurityImpersonation,
            TokenImpersonation,
            &mut raw_imp,
        )
    };
    if ok == 0 {
        return Err(win32_error("DuplicateTokenEx(TokenImpersonation)"));
    }
    let imp_token = OwnedHandle::from_raw(raw_imp)?;

    let pipe_path = format!(r"\\.\pipe\{pipe_name}");
    let wide_path = to_wide_null(OsStr::new(&pipe_path))?;

    // SAFETY: `imp_token` is an owned impersonation token; immediately guarded by `RevertToSelfGuard`.
    let ok = unsafe { ImpersonateLoggedOnUser(imp_token.as_raw()) };
    if ok == 0 {
        return Err(win32_error("ImpersonateLoggedOnUser"));
    }
    let _revert_guard = RevertToSelfGuard;

    // SAFETY: `wide_path` is NUL-terminated; handle is non-inheritable.
    let raw = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            ptr::null_mut(),
        )
    };
    if raw != INVALID_HANDLE_VALUE {
        if !raw.is_null() {
            // SAFETY: `raw` is a valid opened handle that must be closed immediately.
            unsafe {
                CloseHandle(raw);
            }
        }
        return Err(SandboxError::PolicyViolation(format!(
            "restricted non-owner token was unexpectedly permitted to open named pipe '{pipe_path}'"
        )));
    }

    // SAFETY: Reading thread-local Win32 error immediately after `CreateFileW` returned `INVALID_HANDLE_VALUE`.
    let err = unsafe { GetLastError() };
    if err == ERROR_ACCESS_DENIED {
        Ok(())
    } else {
        Err(SandboxError::Transport(format!(
            "expected ERROR_ACCESS_DENIED (5) probing named pipe '{pipe_path}' as restricted non-owner, got Win32 error {err}: {}",
            io::Error::from_raw_os_error(err as i32)
        )))
    }
}

/// Connects to an existing local Named Pipe (`\\.\pipe\<pipe_name>`) using `SECURITY_IDENTIFICATION`
/// to prevent server impersonation.
pub fn connect_named_pipe(pipe_name: &str) -> Result<OwnedNamedPipe, SandboxError> {
    validate_pipe_name(pipe_name)?;
    let pipe_path = format!(r"\\.\pipe\{pipe_name}");
    let wide_path = to_wide_null(OsStr::new(&pipe_path))?;

    // SAFETY: `wide_path` is NUL-terminated; handle is non-inheritable.
    let raw = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
            ptr::null_mut(),
        )
    };
    let handle = OwnedHandle::from_raw(raw).map_err(|err| {
        SandboxError::Transport(format!(
            "CreateFileW('{pipe_path}') failed: {err}"
        ))
    })?;

    Ok(OwnedNamedPipe { handle, pipe_path })
}

/// Creates `path` with an owner-only inheritable DACL (`D:P(A;OICI;GA;;;{user_sid})`),
/// or validates an existing directory (rejecting reparse points / symlinks / wrong owner / weak DACL).
pub fn create_owner_only_dir(path: &Path) -> Result<(), SandboxError> {
    create_owner_only_dir_inner(path, false)
}

/// Creates a new owner-only directory and rejects any existing path.
pub fn create_new_owner_only_dir(path: &Path) -> Result<(), SandboxError> {
    create_owner_only_dir_inner(path, true)
}

fn create_owner_only_dir_inner(path: &Path, exclusive: bool) -> Result<(), SandboxError> {
    let user_sid = current_user_sid_string()?;
    // Elevated tokens may otherwise assign the Administrators group as the owner.
    let sddl = format!("O:{user_sid}{}", owner_only_sddl(&user_sid, true));
    let sd = sddl_to_security_descriptor(&sddl)?;
    let sa = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.as_ptr(),
        bInheritHandle: 0,
    };
    let wide_path = to_wide_null(path.as_os_str())?;

    // SAFETY: `wide_path` is NUL-terminated and `sa` references a valid `SECURITY_DESCRIPTOR`.
    let created = unsafe { CreateDirectoryW(wide_path.as_ptr(), &sa) };
    if created == 0 {
        // SAFETY: Thread-local Win32 last error after `CreateDirectoryW` failure.
        let err = unsafe { GetLastError() };
        if err == ERROR_ALREADY_EXISTS && exclusive {
            return Err(SandboxError::PolicyViolation(format!(
                "owner-only directory '{}' already exists",
                path.display()
            )));
        }
        if err != ERROR_ALREADY_EXISTS {
            return Err(SandboxError::Transport(format!(
                "CreateDirectoryW('{}') failed: {}",
                path.display(),
                io::Error::from_raw_os_error(err as i32)
            )));
        }
    }

    // Verify attributes regardless of fresh creation or pre-existence to defeat reparse/symlink races.
    // SAFETY: `wide_path` is NUL-terminated.
    let attrs = unsafe { GetFileAttributesW(wide_path.as_ptr()) };
    if attrs == INVALID_FILE_ATTRIBUTES {
        return Err(win32_error(&format!(
            "GetFileAttributesW('{}')",
            path.display()
        )));
    }
    if (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
        return Err(SandboxError::PolicyViolation(format!(
            "refusing runtime directory '{}': reparse points/symlinks are not allowed",
            path.display()
        )));
    }
    if (attrs & FILE_ATTRIBUTE_DIRECTORY) == 0 {
        return Err(SandboxError::PolicyViolation(format!(
            "refusing runtime directory '{}': path exists and is not a directory",
            path.display()
        )));
    }

    let (owner, dacl_sddl) = inspect_path_owner_and_dacl(path)?;
    if owner != user_sid {
        return Err(SandboxError::PolicyViolation(format!(
            "runtime directory '{}' is owned by SID '{owner}', expected '{user_sid}'",
            path.display()
        )));
    }
    validate_owner_only_dacl(&dacl_sddl, &user_sid, true, &path.display().to_string())?;
    Ok(())
}

fn inspect_raw_handle_sddl(raw_handle: HANDLE) -> Result<String, SandboxError> {
    let mut raw_sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: `raw_handle` is an open Win32 kernel handle; `GetSecurityInfo` allocates `raw_sd` via `LocalAlloc`.
    let status = unsafe {
        GetSecurityInfo(
            raw_handle,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut raw_sd,
        )
    };
    if status != 0 {
        return Err(SandboxError::Internal(format!(
            "GetSecurityInfo failed: {}",
            io::Error::from_raw_os_error(status as i32)
        )));
    }
    let _sd_guard = LocalAllocGuard(raw_sd);
    sd_to_dacl_sddl(raw_sd)
}

fn inspect_object_sddl(handle: &OwnedHandle) -> Result<String, SandboxError> {
    inspect_raw_handle_sddl(handle.as_raw())
}

/// Inspects the DACL SDDL string for a filesystem path (including `AF_UNIX` socket files).
pub fn inspect_path_sddl(path: &Path) -> Result<String, SandboxError> {
    inspect_path_owner_and_dacl(path).map(|(_, dacl)| dacl)
}

/// Validates that a DACL SDDL string grants access strictly to `owner_sid` with zero world/group ACEs.
///
/// When `require_protected` is `true`, also asserts `D:P` and rejects inherited (`ID`) ACE flags.
pub fn validate_owner_only_dacl(
    dacl_sddl: &str,
    owner_sid: &str,
    require_protected: bool,
    target: &str,
) -> Result<(), SandboxError> {
    let body = dacl_sddl.strip_prefix("D:").ok_or_else(|| {
        SandboxError::PolicyViolation(format!(
            "missing DACL prefix in SDDL '{dacl_sddl}' for '{target}'"
        ))
    })?;
    let first_ace = body.find('(').ok_or_else(|| {
        SandboxError::PolicyViolation(format!(
            "DACL SDDL '{dacl_sddl}' for '{target}' contains no ACEs"
        ))
    })?;
    let flags = &body[..first_ace];
    if require_protected && !flags.contains('P') {
        return Err(SandboxError::PolicyViolation(format!(
            "DACL SDDL '{dacl_sddl}' for '{target}' is not protected (missing D:P)"
        )));
    }

    let mut rest = &body[first_ace..];
    let mut ace_count = 0usize;
    while !rest.is_empty() {
        let trimmed = rest.strip_prefix('(').ok_or_else(|| {
            SandboxError::PolicyViolation(format!(
                "malformed ACE list in SDDL '{dacl_sddl}' for '{target}'"
            ))
        })?;
        let end = trimmed.find(')').ok_or_else(|| {
            SandboxError::PolicyViolation(format!(
                "unclosed ACE in SDDL '{dacl_sddl}' for '{target}'"
            ))
        })?;
        let ace = &trimmed[..end];
        let fields: Vec<&str> = ace.split(';').collect();
        if fields.len() != 6 {
            return Err(SandboxError::PolicyViolation(format!(
                "unexpected ACE format '({ace})' in SDDL '{dacl_sddl}' for '{target}'"
            )));
        }
        let (ace_type, ace_flags, trustee) = (fields[0], fields[1], fields[5]);
        if ace_type != "A" {
            return Err(SandboxError::PolicyViolation(format!(
                "non-allow ACE '({ace})' in SDDL '{dacl_sddl}' for '{target}'"
            )));
        }
        if require_protected
            && (!ace_flags.len().is_multiple_of(2)
                || ace_flags
                    .as_bytes()
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .any(|flag| flag == b"ID"))
        {
            return Err(SandboxError::PolicyViolation(format!(
                "unexpected inherited ACE '({ace})' in protected SDDL '{dacl_sddl}' for '{target}'"
            )));
        }
        if trustee != owner_sid {
            return Err(SandboxError::PolicyViolation(format!(
                "unexpected trustee '{trustee}' in SDDL '{dacl_sddl}' for '{target}' (expected '{owner_sid}')"
            )));
        }
        ace_count += 1;
        rest = &trimmed[end + 1..];
    }

    if ace_count == 0 {
        return Err(SandboxError::PolicyViolation(format!(
            "DACL SDDL '{dacl_sddl}' for '{target}' contains zero ACEs"
        )));
    }
    Ok(())
}

fn inspect_path_owner_and_dacl(path: &Path) -> Result<(String, String), SandboxError> {
    let wide_path = to_wide_null(path.as_os_str())?;
    // Open with `FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT` so directories and
    // WinSock2 `AF_UNIX` socket reparse points are opened directly without invoking `afunix.sys`
    // or traversing symlinks.
    // SAFETY: `wide_path` is NUL-terminated; handle is closed via `OwnedHandle` on drop.
    let raw_handle = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            READ_CONTROL,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            ptr::null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            ptr::null_mut(),
        )
    };
    let handle = OwnedHandle::from_raw(raw_handle).map_err(|err| {
        SandboxError::Internal(format!(
            "CreateFileW(READ_CONTROL, '{}') failed: {err}",
            path.display()
        ))
    })?;

    let mut owner_sid: PSID = ptr::null_mut();
    let mut raw_sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: `handle` is an open Win32 file/directory handle; `GetSecurityInfo` allocates `raw_sd` via `LocalAlloc`.
    let status = unsafe {
        GetSecurityInfo(
            handle.as_raw(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner_sid,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut raw_sd,
        )
    };
    if status != 0 {
        return Err(SandboxError::Internal(format!(
            "GetSecurityInfo('{}') failed: {}",
            path.display(),
            io::Error::from_raw_os_error(status as i32)
        )));
    }
    let _sd_guard = LocalAllocGuard(raw_sd);
    let owner = sid_to_string(owner_sid)?;
    let dacl = sd_to_dacl_sddl(raw_sd)?;
    Ok((owner, dacl))
}

fn sid_to_string(sid: PSID) -> Result<String, SandboxError> {
    if sid.is_null() {
        return Err(SandboxError::Internal("null SID pointer".to_owned()));
    }
    let mut wide_sid: *mut u16 = ptr::null_mut();
    // SAFETY: `sid` is a valid non-null Win32 SID; `ConvertSidToStringSidW` allocates `wide_sid` via `LocalAlloc`.
    let ok = unsafe { ConvertSidToStringSidW(sid, &mut wide_sid) };
    if ok == 0 {
        return Err(win32_error("ConvertSidToStringSidW"));
    }
    let _sid_guard = LocalAllocGuard(wide_sid.cast());
    wide_ptr_to_string(wide_sid)
}

fn sd_to_dacl_sddl(sd: PSECURITY_DESCRIPTOR) -> Result<String, SandboxError> {
    if sd.is_null() {
        return Err(SandboxError::Internal(
            "null security descriptor pointer".to_owned(),
        ));
    }
    let mut wide_sddl: *mut u16 = ptr::null_mut();
    // SAFETY: `sd` is a valid security descriptor; `wide_sddl` is allocated via `LocalAlloc`.
    let ok = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            sd,
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            &mut wide_sddl,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(win32_error(
            "ConvertSecurityDescriptorToStringSecurityDescriptorW",
        ));
    }
    let _sddl_guard = LocalAllocGuard(wide_sddl.cast());
    wide_ptr_to_string(wide_sddl)
}

fn sddl_to_security_descriptor(sddl: &str) -> Result<LocalAllocGuard, SandboxError> {
    let wide_sddl = to_wide_null(OsStr::new(sddl))?;
    let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: `wide_sddl` is NUL-terminated; `sd` receives a `LocalAlloc` security descriptor.
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            wide_sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            ptr::null_mut(),
        )
    };
    if ok == 0 || sd.is_null() {
        return Err(win32_error(
            "ConvertStringSecurityDescriptorToSecurityDescriptorW",
        ));
    }
    Ok(LocalAllocGuard(sd))
}

fn remove_stale_socket_if_safe(socket_path: &Path) -> Result<(), SandboxError> {
    let wide_path = to_wide_null(socket_path.as_os_str())?;
    // SAFETY: `wide_path` is NUL-terminated; avoids `FindFirstFileW` wildcard interpretation if path does not exist.
    let attrs = unsafe { GetFileAttributesW(wide_path.as_ptr()) };
    if attrs == INVALID_FILE_ATTRIBUTES {
        return Ok(());
    }
    if (attrs & FILE_ATTRIBUTE_DIRECTORY) != 0 {
        return Err(SandboxError::PolicyViolation(format!(
            "refusing to remove directory at socket path '{}'",
            socket_path.display()
        )));
    }
    if (attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
        let mut find_data: WIN32_FIND_DATAW = unsafe { zeroed() };
        // SAFETY: `wide_path` is NUL-terminated and `find_data` is writable stack storage.
        let raw_find = unsafe { FindFirstFileW(wide_path.as_ptr(), &mut find_data) };
        if raw_find == INVALID_HANDLE_VALUE {
            return Err(win32_error(&format!(
                "FindFirstFileW('{}')",
                socket_path.display()
            )));
        }
        let _find_guard = FindHandle(raw_find);
        if find_data.dwReserved0 != IO_REPARSE_TAG_AF_UNIX {
            return Err(SandboxError::PolicyViolation(format!(
                "refusing to remove symlink or reparse point at socket path '{}'",
                socket_path.display()
            )));
        }
    }

    fs::remove_file(socket_path).map_err(|err| {
        SandboxError::Transport(format!(
            "failed to remove stale socket '{}': {err}",
            socket_path.display()
        ))
    })
}

fn build_sockaddr_un(socket_path: &Path) -> Result<SockAddrUn, SandboxError> {
    validate_socket_path(socket_path)?;
    let path_str = socket_path.to_str().ok_or_else(|| {
        SandboxError::InvalidSpec(format!(
            "socket path '{}' is not valid UTF-8",
            socket_path.display()
        ))
    })?;
    let bytes = path_str.as_bytes();
    let mut addr = SockAddrUn {
        sun_family: AF_UNIX,
        sun_path: [0u8; 108],
    };
    addr.sun_path[..bytes.len()].copy_from_slice(bytes);
    Ok(addr)
}

fn ensure_wsa_started() -> Result<(), SandboxError> {
    static WSA_ONCE: Once = Once::new();
    static WSA_INIT_ERR: AtomicI32 = AtomicI32::new(0);

    // Do NOT call `WSACleanup` globally because library callers may hold unrelated sockets.
    WSA_ONCE.call_once(|| {
        // SAFETY: `WSADATA` is plain old data initialized by `WSAStartup`.
        let mut data: WSADATA = unsafe { zeroed() };
        // SAFETY: Requests WinSock 2.2 initialization with valid `WSADATA` storage.
        let rc = unsafe { WSAStartup(0x0202, &mut data) };
        if rc != 0 {
            WSA_INIT_ERR.store(rc, Ordering::Release);
        }
    });

    let err = WSA_INIT_ERR.load(Ordering::Acquire);
    if err != 0 {
        return Err(SandboxError::Transport(format!(
            "WSAStartup(2.2) failed with WinSock error {err}: {}",
            io::Error::from_raw_os_error(err)
        )));
    }
    Ok(())
}

pub(crate) fn to_wide_null(s: &OsStr) -> Result<Vec<u16>, SandboxError> {
    let mut wide: Vec<u16> = s.encode_wide().collect();
    if wide.contains(&0) {
        return Err(SandboxError::InvalidSpec(
            "path or pipe name contains an interior NUL character".to_owned(),
        ));
    }
    wide.push(0);
    Ok(wide)
}

fn wide_ptr_to_string(ptr: *const u16) -> Result<String, SandboxError> {
    if ptr.is_null() {
        return Err(SandboxError::Internal("null UTF-16 string pointer".to_owned()));
    }
    // SAFETY: Caller guarantees `ptr` is a valid NUL-terminated UTF-16 string from Win32.
    let mut len = 0usize;
    unsafe {
        while *ptr.add(len) != 0 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(ptr, len);
        String::from_utf16(slice).map_err(|err| {
            SandboxError::Internal(format!("invalid UTF-16 string from Win32 API: {err}"))
        })
    }
}

pub(crate) fn win32_error(context: &str) -> SandboxError {
    SandboxError::Internal(format!("{context} failed: {}", io::Error::last_os_error()))
}

fn wsa_error(context: &str) -> SandboxError {
    // SAFETY: Reading thread-local WinSock error code immediately after failed call.
    let code = unsafe { WSAGetLastError() };
    SandboxError::Transport(format!(
        "{context} failed with WinSock error {code}: {}",
        io::Error::from_raw_os_error(code)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::IpcListener;
    use std::sync::atomic::AtomicU64;
    use std::thread;

    struct CleanupDir(PathBuf);

    impl CleanupDir {
        fn unique_path(prefix: &str) -> PathBuf {
            static SEQ: AtomicU64 = AtomicU64::new(0);
            let seq = SEQ.fetch_add(1, Ordering::Relaxed);
            std::env::temp_dir().join(format!("mpw-{prefix}-{}-{seq}", std::process::id()))
        }
    }

    impl Drop for CleanupDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn unique_pipe_name(tag: &str) -> String {
        static PIPE_SEQ: AtomicU64 = AtomicU64::new(0);
        let seq = PIPE_SEQ.fetch_add(1, Ordering::Relaxed);
        format!("minipod-test-{tag}-{}-{seq}", std::process::id())
    }

    #[test]
    fn current_user_sid_and_sddl_builders_are_well_formed() {
        let sid = current_user_sid_string().expect("resolve current user SID");
        assert!(sid.starts_with("S-1-"), "unexpected SID format: {sid}");
        assert_eq!(owner_only_sddl(&sid, false), format!("D:P(A;;GA;;;{sid})"));
        assert_eq!(
            owner_only_sddl(&sid, true),
            format!("D:P(A;OICI;GA;;;{sid})")
        );
    }

    #[test]
    fn validate_owner_only_dacl_rejects_world_builtin_system_and_unprotected_dacl() {
        let owner = "S-1-5-21-1000-2000-3000-1001";
        assert!(validate_owner_only_dacl(&format!("D:P(A;;FA;;;{owner})"), owner, true, "pipe").is_ok());
        assert!(validate_owner_only_dacl(&format!("D:P(A;OICI;FA;;;{owner})"), owner, true, "dir").is_ok());
        assert!(validate_owner_only_dacl(&format!("D:AI(A;ID;FA;;;{owner})"), owner, false, "sock").is_ok());

        for bad in [
            format!("D:(A;;FA;;;{owner})"),
            format!("D:P(A;OICIID;FA;;;{owner})"),
            "D:P(A;;FR;;;WD)".to_owned(),
            "D:P(A;;FR;;;AN)".to_owned(),
            format!("D:P(A;;FA;;;{owner})(A;;FR;;;WD)"),
            format!("D:P(A;;FA;;;{owner})(A;;FA;;;SY)"),
            format!("D:P(A;;FA;;;{owner})(A;;FR;;;BU)"),
            format!("D:P(A;;FA;;;{owner})(A;;FR;;;AU)"),
            format!("D:P(A;;FA;;;{owner})(A;;FA;;;BA)"),
            "D:P(A;;FA;;;S-1-5-21-999-999-999-1002)".to_owned(),
        ] {
            assert!(
                matches!(
                    validate_owner_only_dacl(&bad, owner, true, "target"),
                    Err(SandboxError::PolicyViolation(_))
                ),
                "expected SDDL '{bad}' to be rejected"
            );
        }
    }

    #[test]
    fn named_pipe_enforces_strict_owner_only_dacl_first_instance_and_roundtrip() {
        let user_sid = current_user_sid_string().expect("current user SID");
        let pipe_name = unique_pipe_name("dacl");
        let mut server =
            create_owner_only_named_pipe(&pipe_name).expect("create owner-only named pipe");

        let sddl = server.inspect_pipe_sddl().expect("inspect pipe SDDL");
        assert!(
            sddl.starts_with("D:P"),
            "pipe SDDL must be protected D:P, got: {sddl}"
        );
        validate_owner_only_dacl(&sddl, &user_sid, true, server.pipe_path())
            .expect("pipe DACL must grant access strictly to owner SID");
        for forbidden in ["WD", "AN", "BU", "AU", "SY", "BA"] {
            assert!(
                !sddl.contains(forbidden),
                "pipe SDDL '{sddl}' must not contain '{forbidden}'"
            );
        }

        // FILE_FLAG_FIRST_PIPE_INSTANCE must block duplicate servers on the same name.
        assert!(matches!(
            create_owner_only_named_pipe(&pipe_name),
            Err(SandboxError::Transport(_))
        ));

        let client_name = pipe_name.clone();
        let client_thread = thread::spawn(move || {
            let mut client = connect_named_pipe(&client_name).expect("connect to named pipe");
            client.write_all(b"hello").expect("write to pipe");
            client.flush().expect("flush pipe");
            let mut buf = [0u8; 5];
            client.read_exact(&mut buf).expect("read from pipe");
            assert_eq!(&buf, b"world");
        });

        server.accept_client().expect("accept client on named pipe");
        let mut req = [0u8; 5];
        server.read_exact(&mut req).expect("read client request");
        assert_eq!(&req, b"hello");
        server.write_all(b"world").expect("write response");
        server.flush().expect("flush server pipe");
        drop(server);
        client_thread.join().expect("client thread completes");
    }

    #[test]
    fn owner_only_dir_and_unix_socket_enforce_strict_owner_sddl_and_reject_weak_dirs() {
        let user_sid = current_user_sid_string().expect("current user SID");
        let dir_path = CleanupDir::unique_path("acl");
        let _cleanup = CleanupDir(dir_path.clone());

        create_owner_only_dir(&dir_path).expect("create owner-only runtime dir");
        let dir_sddl = inspect_path_sddl(&dir_path).expect("inspect runtime dir SDDL");
        validate_owner_only_dacl(&dir_sddl, &user_sid, true, &dir_path.display().to_string())
            .expect("runtime dir must have protected owner-only DACL");

        // Re-running on an already-valid owner-only dir must succeed idempotently.
        create_owner_only_dir(&dir_path).expect("idempotent validation of owner-only dir");

        let sock_path = dir_path.join("agent.sock");
        let listener = IpcListener::bind(&sock_path).expect("bind WinSock AF_UNIX listener");
        let sock_sddl = inspect_path_sddl(&sock_path).expect("inspect socket SDDL");
        validate_owner_only_dacl(
            &sock_sddl,
            &user_sid,
            false,
            &sock_path.display().to_string(),
        )
        .expect("socket file must inherit only owner SID ACE from parent dir");
        for forbidden in ["WD", "AN", "BU", "AU", "SY", "BA"] {
            assert!(
                !sock_sddl.contains(forbidden),
                "socket SDDL '{sock_sddl}' must not contain '{forbidden}'"
            );
        }
        drop(listener);
        // Re-binding without deleting `sock_path` first verifies stale `IO_REPARSE_TAG_AF_UNIX` cleanup.
        let rebound = IpcListener::bind(&sock_path)
            .expect("re-bind WinSock AF_UNIX listener over stale AF_UNIX socket reparse point");
        drop(rebound);
        let _ = fs::remove_file(&sock_path);

        // Pre-existing directory or junction at socket path must still be rejected.
        let dir_as_sock = dir_path.join("dir.sock");
        fs::create_dir(&dir_as_sock).expect("create directory at socket path");
        assert!(matches!(
            IpcListener::bind(&dir_as_sock),
            Err(SandboxError::PolicyViolation(_))
        ));
        let _ = fs::remove_dir(&dir_as_sock);

        // Pre-existing permissive directory (inheriting %TEMP%'s SYSTEM/Admin/Users ACEs) must be rejected.
        let insecure_dir = CleanupDir::unique_path("weak");
        let _weak_cleanup = CleanupDir(insecure_dir.clone());
        fs::create_dir(&insecure_dir).expect("create standard inherited temp dir");
        assert!(matches!(
            create_owner_only_dir(&insecure_dir),
            Err(SandboxError::PolicyViolation(_))
        ));
    }

    #[tokio::test]
    async fn async_named_pipe_supports_multiple_clients_blocks_squatting_and_denies_restricted_non_owner(
    ) {
        use std::os::windows::io::AsRawHandle;
        use std::sync::Arc;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeServer};
        use tokio::sync::Barrier;

        let user_sid = current_user_sid_string().expect("current user SID");
        let pipe_name = unique_pipe_name("async");
        let pipe_path = format!(r"\\.\pipe\{pipe_name}");

        let server1 =
            create_owner_only_async_named_pipe(&pipe_name, true).expect("create first pipe instance");

        let sddl = inspect_raw_handle_sddl(server1.as_raw_handle().cast())
            .expect("inspect async pipe SDDL");
        validate_owner_only_dacl(&sddl, &user_sid, true, &pipe_path)
            .expect("async pipe DACL must grant access strictly to owner SID");
        for forbidden in ["WD", "AN", "BU", "AU", "SY", "BA"] {
            assert!(
                !sddl.contains(forbidden),
                "async pipe SDDL '{sddl}' must not contain '{forbidden}'"
            );
        }

        // Duplicate first_instance=true must fail to block squatting / replacement servers.
        assert!(matches!(
            create_owner_only_async_named_pipe(&pipe_name, true),
            Err(SandboxError::Transport(_))
        ));

        // Second concurrent instance with first_instance=false must succeed.
        let server2 = create_owner_only_async_named_pipe(&pipe_name, false)
            .expect("create second pipe instance");

        // Kernel must reject a restricted non-owner token with ERROR_ACCESS_DENIED (5).
        verify_non_owner_named_pipe_denied(&pipe_name)
            .expect("kernel must deny restricted non-owner token");

        let mut client1 = ClientOptions::new()
            .security_qos_flags(SECURITY_IDENTIFICATION)
            .open(&pipe_path)
            .expect("open async pipe client 1");
        let mut client2 = ClientOptions::new()
            .security_qos_flags(SECURITY_IDENTIFICATION)
            .open(&pipe_path)
            .expect("open async pipe client 2");

        let barrier = Arc::new(Barrier::new(2));
        async fn serve_echo(
            mut server: NamedPipeServer,
            barrier: Arc<Barrier>,
        ) -> io::Result<()> {
            server.connect().await?;
            let mut req = [0u8; 8];
            server.read_exact(&mut req).await?;
            // Ensure both server instances hold live concurrent client sessions simultaneously.
            barrier.wait().await;
            let mut resp = [0u8; 13];
            resp[..5].copy_from_slice(b"echo:");
            resp[5..].copy_from_slice(&req);
            server.write_all(&resp).await?;
            server.flush().await
        }

        let s1 = tokio::spawn(serve_echo(server1, Arc::clone(&barrier)));
        let s2 = tokio::spawn(serve_echo(server2, barrier));

        let c1 = tokio::spawn(async move {
            client1.write_all(b"client-1").await?;
            let mut resp = [0u8; 13];
            client1.read_exact(&mut resp).await?;
            assert_eq!(&resp, b"echo:client-1");
            io::Result::Ok(())
        });
        let c2 = tokio::spawn(async move {
            client2.write_all(b"client-2").await?;
            let mut resp = [0u8; 13];
            client2.read_exact(&mut resp).await?;
            assert_eq!(&resp, b"echo:client-2");
            io::Result::Ok(())
        });

        let (r_s1, r_s2, r_c1, r_c2) = tokio::join!(s1, s2, c1, c2);
        r_s1.expect("server task 1 join").expect("server task 1 io");
        r_s2.expect("server task 2 join").expect("server task 2 io");
        r_c1.expect("client task 1 join").expect("client task 1 io");
        r_c2.expect("client task 2 join").expect("client task 2 io");
    }

    #[test]
    fn async_named_pipe_closes_handle_if_tokio_registration_fails() {
        let pipe_name = unique_pipe_name("no-rt");
        // Calling outside any Tokio runtime must return a clean Transport error without panicking.
        assert!(matches!(
            create_owner_only_async_named_pipe(&pipe_name, true),
            Err(SandboxError::Transport(_))
        ));

        // Inside a Tokio runtime without an I/O driver (`enable_io` omitted), CreateNamedPipeW
        // succeeds and NamedPipeServer::from_raw_handle unwinds inside PollEvented::new;
        // mio's OwnedHandle drop must still close the pipe handle without leaking.
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("build Tokio runtime without IO driver");
        let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = rt.enter();
            create_owner_only_async_named_pipe(&pipe_name, true)
        }));
        assert!(
            matches!(res, Err(_) | Ok(Err(SandboxError::Transport(_)))),
            "expected registration failure without Tokio IO driver"
        );
        let _sync_server = create_owner_only_named_pipe(&pipe_name)
            .expect("handle must not leak when NamedPipeServer::from_raw_handle fails");
    }

    #[test]
    fn verify_non_owner_named_pipe_denied_detects_permissive_dacl_and_missing_pipe() {
        let missing_name = unique_pipe_name("missing");
        assert!(matches!(
            verify_non_owner_named_pipe_denied(&missing_name),
            Err(SandboxError::Transport(_))
        ));

        let weak_name = unique_pipe_name("weak-wd");
        let pipe_path = format!(r"\\.\pipe\{weak_name}");
        let wide_path = to_wide_null(OsStr::new(&pipe_path)).expect("wide pipe path");
        let sd = sddl_to_security_descriptor("D:P(A;;GA;;;WD)").expect("world-allow SDDL");
        let sa = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.as_ptr(),
            bInheritHandle: 0,
        };
        // SAFETY: `wide_path` is NUL-terminated and `sa` points to a valid `SECURITY_DESCRIPTOR`.
        let raw = unsafe {
            CreateNamedPipeW(
                wide_path.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                PIPE_BUFFER_BYTES,
                PIPE_BUFFER_BYTES,
                0,
                &sa,
            )
        };
        let _weak_pipe = OwnedHandle::from_raw(raw).expect("create weak test pipe");

        assert!(matches!(
            verify_non_owner_named_pipe_denied(&weak_name),
            Err(SandboxError::PolicyViolation(_))
        ));
    }
}
