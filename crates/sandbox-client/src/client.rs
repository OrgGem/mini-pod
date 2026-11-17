//! Lightweight async `SandboxClient` SDK, `ControlEndpoint` parser, and `ClientExecStream`.

use std::future::Future;
use std::path::{Component, Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use sandbox_core::{
    DestroyStatus, ExecExitStatus, ExecRequest, SandboxError, SandboxId, SandboxLease, SandboxSpec,
};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::safe_tar::{extract_tar_bytes_safely, pack_path_to_tar_bytes};
use crate::wire::{
    read_control_frame, write_control_frame, ControlRequest, ControlResponse, DaemonStatusInfo,
    ExecWireClientMsg, ExecWireEvent, SandboxSummaryInfo, MAX_CONTROL_FRAME_BYTES,
};

/// Default client-side tar archive byte budget (16 MiB).
pub const DEFAULT_MAX_COPY_BYTES: u64 = 16 * 1024 * 1024;
/// Default client-side extracted tar entry limit.
pub const DEFAULT_MAX_COPY_ENTRIES: usize = 4096;

const MAX_GUEST_PATH_BYTES: usize = 4096;
const MAX_WINDOWS_PIPE_NAME_BYTES: usize = 246;
const STDIN_CHANNEL_CAPACITY: usize = 64;
const OUTPUT_CHANNEL_CAPACITY: usize = 256;
const CANCEL_CHANNEL_CAPACITY: usize = 1;
const MAX_WIRE_STDIN_CHUNK_BYTES: usize = 4 * 1024 * 1024;

#[cfg(windows)]
const SECURITY_IDENTIFICATION_QOS: u32 = 0x0001_0000;
#[cfg(windows)]
const ERROR_PIPE_BUSY: i32 = 231;
#[cfg(windows)]
const PIPE_BUSY_MAX_RETRIES: usize = 20;
#[cfg(windows)]
const PIPE_BUSY_RETRY_DELAY: Duration = Duration::from_millis(25);

/// Marker trait for bidirectional async streams accepted by [`SandboxClient`].
pub trait ControlStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> ControlStream for T {}

/// Type-erased async control transport stream.
pub type BoxedControlStream = Box<dyn ControlStream>;

type ConnectorFn = Arc<
    dyn Fn(&ControlEndpoint) -> Pin<Box<dyn Future<Output = Result<BoxedControlStream, SandboxError>> + Send>>
        + Send
        + Sync,
>;

/// Local-only daemon control endpoint (`UnixSocket` on Unix or `NamedPipe` on Windows).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ControlEndpoint {
    UnixSocket(PathBuf),
    NamedPipe(String),
}

impl ControlEndpoint {
    /// Parses a local IPC endpoint string (`unix://...`, `/path`, `npipe://...`, `\\.\pipe\...`).
    ///
    /// Explicitly rejects network/plaintext schemes (`tcp://`, `http://`, `https://`, TLS-less URLs)
    /// and remote UNC pipe paths with [`SandboxError::PolicyViolation`].
    pub fn parse(raw: &str) -> Result<Self, SandboxError> {
        if raw.trim().is_empty() {
            return Err(SandboxError::InvalidSpec(
                "control endpoint must not be empty".to_owned(),
            ));
        }
        if raw.contains('\0') || raw.contains('\r') || raw.contains('\n') {
            return Err(SandboxError::PolicyViolation(
                "control endpoint must not contain NUL or newline characters".to_owned(),
            ));
        }

        let lower = raw.to_ascii_lowercase();
        if lower.starts_with("tcp://")
            || lower.starts_with("http://")
            || lower.starts_with("https://")
            || lower.starts_with("ws://")
            || lower.starts_with("wss://")
            || lower.starts_with("tls://")
        {
            return Err(SandboxError::PolicyViolation(format!(
                "insecure or unsupported network control endpoint '{raw}' is forbidden; use local Unix socket or Windows Named Pipe"
            )));
        }

        if let Some(rest) = strip_prefix_ascii_ci(raw, "unix://") {
            let path = validate_unix_socket_path(rest)?;
            return Ok(Self::UnixSocket(path));
        }

        if let Some(rest) = strip_prefix_ascii_ci(raw, "npipe://") {
            let normalized = normalize_npipe_url_remainder(rest)?;
            return Ok(Self::NamedPipe(normalized));
        }

        if raw.starts_with(r"\\") || raw.starts_with("//") {
            let normalized = normalize_named_pipe_path(raw)?;
            return Ok(Self::NamedPipe(normalized));
        }

        if raw.starts_with('/') {
            let path = validate_unix_socket_path(raw)?;
            return Ok(Self::UnixSocket(path));
        }

        if let Some((scheme, _)) = raw.split_once("://") {
            if !scheme.is_empty() {
                return Err(SandboxError::PolicyViolation(format!(
                    "unsupported control endpoint scheme '{scheme}://'; use unix:// or npipe://"
                )));
            }
        }

        Err(SandboxError::PolicyViolation(format!(
            "unrecognized or non-local control endpoint '{raw}'; expected unix://..., /path, npipe://..., or \\\\.\\pipe\\..."
        )))
    }

    /// Validates that this endpoint represents a safe local Unix socket or Named Pipe path.
    pub fn validate(&self) -> Result<(), SandboxError> {
        match self {
            Self::UnixSocket(path) => {
                let raw = path.to_str().ok_or_else(|| {
                    SandboxError::InvalidSpec(format!(
                        "Unix socket path '{}' is not valid UTF-8",
                        path.display()
                    ))
                })?;
                validate_unix_socket_path(raw)?;
                Ok(())
            }
            Self::NamedPipe(name) => {
                normalize_named_pipe_path(name)?;
                Ok(())
            }
        }
    }
}

fn strip_prefix_ascii_ci<'a>(input: &'a str, prefix: &str) -> Option<&'a str> {
    let head = input.get(..prefix.len())?;
    if head.eq_ignore_ascii_case(prefix) {
        Some(&input[prefix.len()..])
    } else {
        None
    }
}

fn validate_unix_socket_path(raw: &str) -> Result<PathBuf, SandboxError> {
    if raw.is_empty() || raw == "/" {
        return Err(SandboxError::InvalidSpec(
            "Unix socket path must not be empty or '/'".to_owned(),
        ));
    }
    if raw.contains('\0') {
        return Err(SandboxError::PolicyViolation(
            "Unix socket path must not contain NUL bytes".to_owned(),
        ));
    }
    let path = PathBuf::from(raw);
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(SandboxError::PolicyViolation(format!(
            "Unix socket path '{raw}' must not contain '..'"
        )));
    }
    Ok(path)
}

fn normalize_npipe_url_remainder(rest: &str) -> Result<String, SandboxError> {
    if rest.is_empty() {
        return Err(SandboxError::InvalidSpec(
            "named pipe endpoint after npipe:// must not be empty".to_owned(),
        ));
    }
    if rest.starts_with("//./pipe/") || rest.starts_with(r"\\.\pipe\") {
        return normalize_named_pipe_path(rest);
    }
    if rest.contains('/') || rest.contains('\\') {
        return Err(SandboxError::PolicyViolation(format!(
            "invalid npipe:// endpoint '{rest}'; expected npipe://<name> or npipe:////./pipe/<name>"
        )));
    }
    validate_pipe_name(rest)?;
    Ok(format!(r"\\.\pipe\{rest}"))
}

fn normalize_named_pipe_path(raw: &str) -> Result<String, SandboxError> {
    if raw.is_empty() {
        return Err(SandboxError::InvalidSpec(
            "named pipe path must not be empty".to_owned(),
        ));
    }
    if raw.contains('\0') || raw.contains('\r') || raw.contains('\n') {
        return Err(SandboxError::PolicyViolation(
            "named pipe path must not contain NUL or control characters".to_owned(),
        ));
    }
    let name = if let Some(rest) = strip_prefix_ascii_ci(raw, r"\\.\pipe\") {
        rest
    } else if let Some(rest) = strip_prefix_ascii_ci(raw, "//./pipe/") {
        rest
    } else if raw.starts_with(r"\\") || raw.starts_with("//") {
        return Err(SandboxError::PolicyViolation(format!(
            "remote or non-local UNC pipe path '{raw}' is forbidden; expected \\\\.\\pipe\\<name>"
        )));
    } else {
        raw
    };
    validate_pipe_name(name)?;
    Ok(format!(r"\\.\pipe\{name}"))
}

fn validate_pipe_name(pipe_name: &str) -> Result<(), SandboxError> {
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
            "named pipe name '{pipe_name}' contains forbidden characters ('\\', '/', '..', or NUL)"
        )));
    }
    Ok(())
}

/// Output stream origin for a [`ClientOutputChunk`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClientOutputKind {
    Stdout,
    Stderr,
}

/// Incremental `stdout` or `stderr` chunk emitted by [`ClientExecStream`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientOutputChunk {
    pub stream: ClientOutputKind,
    pub data: Vec<u8>,
}

/// Buffered output and terminal exit status collected from [`ClientExecStream::collect`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientExecOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit: ExecExitStatus,
}

/// Caller-side streaming handle for an active remote execution on `sandboxd`.
#[derive(Debug)]
pub struct ClientExecStream {
    pub stream_id: u32,
    stdin_tx: Option<mpsc::Sender<Vec<u8>>>,
    output_rx: mpsc::Receiver<ClientOutputChunk>,
    cancel_tx: mpsc::Sender<()>,
    exit_rx: Option<oneshot::Receiver<Result<ExecExitStatus, SandboxError>>>,
    cached_exit: Option<Result<ExecExitStatus, SandboxError>>,
    closed: Arc<AtomicBool>,
    reader_handle: JoinHandle<()>,
    _writer_handle: JoinHandle<()>,
}

impl ClientExecStream {
    fn from_stream(stream_id: u32, stream: BoxedControlStream) -> Self {
        let (mut read_half, mut write_half) = tokio::io::split(stream);
        let (stdin_tx, mut stdin_rx) = mpsc::channel::<Vec<u8>>(STDIN_CHANNEL_CAPACITY);
        let (output_tx, output_rx) = mpsc::channel::<ClientOutputChunk>(OUTPUT_CHANNEL_CAPACITY);
        let (cancel_tx, mut cancel_rx) = mpsc::channel::<()>(CANCEL_CHANNEL_CAPACITY);
        let (exit_tx, exit_rx) = oneshot::channel();
        let (done_tx, mut done_rx) = oneshot::channel::<()>();
        let closed = Arc::new(AtomicBool::new(false));
        let reader_closed = Arc::clone(&closed);

        let writer_handle = tokio::spawn(async move {
            let mut stdin_closed = false;
            let mut cancel_closed = false;

            loop {
                if stdin_closed && cancel_closed {
                    break;
                }
                tokio::select! {
                    biased;
                    _ = &mut done_rx => break,
                    maybe_cancel = cancel_rx.recv(), if !cancel_closed => {
                        match maybe_cancel {
                            Some(()) => {
                                let Ok(bytes) = ExecWireClientMsg::Cancel.to_json_bytes() else {
                                    break;
                                };
                                if write_control_frame(&mut write_half, &bytes).await.is_err() {
                                    break;
                                }
                            }
                            None => cancel_closed = true,
                        }
                    }
                    maybe_stdin = stdin_rx.recv(), if !stdin_closed => {
                        match maybe_stdin {
                            Some(data) => {
                                let Ok(bytes) = (ExecWireClientMsg::Stdin { data }).to_json_bytes() else {
                                    break;
                                };
                                if write_control_frame(&mut write_half, &bytes).await.is_err() {
                                    break;
                                }
                            }
                            None => {
                                stdin_closed = true;
                                let Ok(bytes) = ExecWireClientMsg::StdinEof.to_json_bytes() else {
                                    break;
                                };
                                if write_control_frame(&mut write_half, &bytes).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        });

        let reader_handle = tokio::spawn(async move {
            let terminal: Result<ExecExitStatus, SandboxError> = loop {
                match read_control_frame(&mut read_half).await {
                    Ok(Some(raw)) => match ExecWireEvent::from_json_bytes(&raw) {
                        Ok(ExecWireEvent::Stdout { data }) => {
                            if output_tx
                                .send(ClientOutputChunk {
                                    stream: ClientOutputKind::Stdout,
                                    data,
                                })
                                .await
                                .is_err()
                            {
                                break Err(SandboxError::Transport(
                                    "execution output receiver dropped".to_owned(),
                                ));
                            }
                        }
                        Ok(ExecWireEvent::Stderr { data }) => {
                            if output_tx
                                .send(ClientOutputChunk {
                                    stream: ClientOutputKind::Stderr,
                                    data,
                                })
                                .await
                                .is_err()
                            {
                                break Err(SandboxError::Transport(
                                    "execution output receiver dropped".to_owned(),
                                ));
                            }
                        }
                        Ok(ExecWireEvent::Exit(status)) => break Ok(status),
                        Ok(ExecWireEvent::Error(wire_err)) => break Err(wire_err.into()),
                        Err(err) => break Err(err),
                    },
                    Ok(None) => {
                        break Err(SandboxError::Transport(
                            "execution stream terminated before reporting exit status".to_owned(),
                        ));
                    }
                    Err(err) => break Err(err),
                }
            };

            reader_closed.store(true, Ordering::Release);
            drop(output_tx);
            let _ = exit_tx.send(terminal);
            let _ = done_tx.send(());
        });

        Self {
            stream_id,
            stdin_tx: Some(stdin_tx),
            output_rx,
            cancel_tx,
            exit_rx: Some(exit_rx),
            cached_exit: None,
            closed,
            reader_handle,
            _writer_handle: writer_handle,
        }
    }

    /// Sends a chunk of bytes to the execution's `stdin`, splitting oversized inputs to stay within
    /// [`MAX_CONTROL_FRAME_BYTES`].
    pub async fn write_stdin(&self, data: Vec<u8>) -> Result<(), SandboxError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(SandboxError::Transport(
                "execution stream already closed".to_owned(),
            ));
        }
        let Some(tx) = &self.stdin_tx else {
            return Err(SandboxError::Transport(
                "execution stdin stream is already closed".to_owned(),
            ));
        };
        if data.len() <= MAX_WIRE_STDIN_CHUNK_BYTES {
            return tx
                .send(data)
                .await
                .map_err(|_| SandboxError::Transport("execution stdin receiver closed".to_owned()));
        }
        for chunk in data.chunks(MAX_WIRE_STDIN_CHUNK_BYTES) {
            tx.send(chunk.to_vec())
                .await
                .map_err(|_| {
                    SandboxError::Transport("execution stdin receiver closed".to_owned())
                })?;
        }
        Ok(())
    }

    /// Closes the caller's `stdin` sender, transmitting `ExecWireClientMsg::StdinEof`.
    pub fn close_stdin(&mut self) {
        self.stdin_tx = None;
    }

    /// Receives the next incremental `stdout` or `stderr` chunk, or `None` once output closes.
    pub async fn next_output(&mut self) -> Option<ClientOutputChunk> {
        self.output_rx.recv().await
    }

    /// Signals cancellation so the background writer transmits `ExecWireClientMsg::Cancel`.
    pub fn cancel(&self) -> Result<(), SandboxError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(SandboxError::Transport(
                "execution stream already closed".to_owned(),
            ));
        }
        match self.cancel_tx.try_send(()) {
            Ok(()) | Err(mpsc::error::TrySendError::Full(())) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(())) => Err(SandboxError::Transport(
                "execution stream already closed".to_owned(),
            )),
        }
    }

    /// Awaits the execution's terminal [`ExecExitStatus`] (idempotent across repeated calls).
    pub async fn wait_exit(&mut self) -> Result<ExecExitStatus, SandboxError> {
        if let Some(res) = &self.cached_exit {
            return res.clone();
        }
        let Some(mut rx) = self.exit_rx.take() else {
            return Err(SandboxError::Internal(
                "execution exit status receiver unavailable".to_owned(),
            ));
        };

        let exit_res = loop {
            tokio::select! {
                biased;
                res = &mut rx => {
                    break match res {
                        Ok(status) => status,
                        Err(_) => Err(SandboxError::Transport(
                            "execution stream terminated before reporting exit status".to_owned(),
                        )),
                    };
                }
                chunk = self.output_rx.recv() => {
                    if chunk.is_none() {
                        break match rx.await {
                            Ok(status) => status,
                            Err(_) => Err(SandboxError::Transport(
                                "execution stream terminated before reporting exit status".to_owned(),
                            )),
                        };
                    }
                }
            }
        };

        self.cached_exit = Some(exit_res.clone());
        exit_res
    }

    /// Closes `stdin`, drains all remaining `stdout`/`stderr` chunks, and awaits exit status.
    pub async fn collect(mut self) -> Result<ClientExecOutput, SandboxError> {
        self.close_stdin();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();

        while let Some(chunk) = self.next_output().await {
            match chunk.stream {
                ClientOutputKind::Stdout => stdout.extend_from_slice(&chunk.data),
                ClientOutputKind::Stderr => stderr.extend_from_slice(&chunk.data),
            }
        }

        let exit = self.wait_exit().await?;
        Ok(ClientExecOutput {
            stdout,
            stderr,
            exit,
        })
    }
}

impl Drop for ClientExecStream {
    fn drop(&mut self) {
        self.reader_handle.abort();
    }
}

/// Async client SDK communicating with a local `sandboxd` instance over Unix socket or Named Pipe.
#[derive(Clone)]
pub struct SandboxClient {
    endpoint: ControlEndpoint,
    max_copy_bytes: u64,
    max_copy_entries: usize,
    connector: ConnectorFn,
}

impl std::fmt::Debug for SandboxClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SandboxClient")
            .field("endpoint", &self.endpoint)
            .field("max_copy_bytes", &self.max_copy_bytes)
            .field("max_copy_entries", &self.max_copy_entries)
            .finish()
    }
}

impl SandboxClient {
    /// Creates a [`SandboxClient`] targeting `endpoint` using the OS local IPC connector.
    pub fn new(endpoint: ControlEndpoint) -> Self {
        Self::with_connector(endpoint, |ep| {
            let ep = ep.clone();
            async move { connect_os_endpoint(&ep).await }
        })
    }

    /// Creates a [`SandboxClient`] with an explicit stream connector (useful for deterministic duplex tests).
    pub fn with_connector<F, Fut, S>(endpoint: ControlEndpoint, connector: F) -> Self
    where
        F: Fn(&ControlEndpoint) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<S, SandboxError>> + Send + 'static,
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let wrapped: ConnectorFn = Arc::new(move |ep: &ControlEndpoint| {
            let fut = connector(ep);
            Box::pin(async move {
                let stream = fut.await?;
                Ok(Box::new(stream) as BoxedControlStream)
            })
        });
        Self {
            endpoint,
            max_copy_bytes: DEFAULT_MAX_COPY_BYTES,
            max_copy_entries: DEFAULT_MAX_COPY_ENTRIES,
            connector: wrapped,
        }
    }

    /// Overrides client-side safe tar byte and entry limits.
    pub fn with_copy_limits(
        mut self,
        max_copy_bytes: u64,
        max_copy_entries: usize,
    ) -> Result<Self, SandboxError> {
        if max_copy_bytes == 0 || max_copy_entries == 0 {
            return Err(SandboxError::InvalidSpec(
                "max_copy_bytes and max_copy_entries must be greater than zero".to_owned(),
            ));
        }
        self.max_copy_bytes = max_copy_bytes;
        self.max_copy_entries = max_copy_entries;
        Ok(self)
    }

    /// Returns the configured [`ControlEndpoint`].
    pub fn endpoint(&self) -> &ControlEndpoint {
        &self.endpoint
    }

    /// Returns the client-side tar byte limit.
    pub fn max_copy_bytes(&self) -> u64 {
        self.max_copy_bytes
    }

    /// Returns the client-side tar entry limit.
    pub fn max_copy_entries(&self) -> usize {
        self.max_copy_entries
    }

    /// Opens a raw control transport connection using the configured endpoint and connector.
    pub async fn connect_with_connector(&self) -> Result<BoxedControlStream, SandboxError> {
        self.endpoint.validate()?;
        (self.connector)(&self.endpoint).await
    }

    /// Queries daemon runtime counters and version metadata.
    pub async fn status(&self) -> Result<DaemonStatusInfo, SandboxError> {
        match self.rpc(ControlRequest::Status).await? {
            ControlResponse::Status(info) => Ok(info),
            other => Err(unexpected_response("Status", &other)),
        }
    }

    /// Lists live metadata for all active sandboxes owned by `sandboxd`.
    pub async fn list_sandboxes(&self) -> Result<Vec<SandboxSummaryInfo>, SandboxError> {
        match self.rpc(ControlRequest::ListSandboxes).await? {
            ControlResponse::SandboxList { sandboxes } => Ok(sandboxes),
            other => Err(unexpected_response("ListSandboxes", &other)),
        }
    }

    /// Spawns a new sandbox instance satisfying `spec`.
    pub async fn spawn(&self, spec: SandboxSpec) -> Result<SandboxLease, SandboxError> {
        match self.rpc(ControlRequest::Spawn { spec }).await? {
            ControlResponse::Spawned(lease) => Ok(lease),
            other => Err(unexpected_response("Spawn", &other)),
        }
    }

    /// Extends the lease TTL of an active sandbox by `ttl`.
    pub async fn renew_lease(&self, id: &SandboxId, ttl: Duration) -> Result<(), SandboxError> {
        if ttl.is_zero() {
            return Err(SandboxError::InvalidSpec(
                "lease ttl must be greater than zero".to_owned(),
            ));
        }
        let ttl_ms = u64::try_from(ttl.as_millis())
            .map_err(|_| SandboxError::InvalidSpec("lease ttl exceeds u64 milliseconds".to_owned()))?
            .max(1);
        match self
            .rpc(ControlRequest::RenewLease {
                id: id.clone(),
                ttl_ms,
            })
            .await?
        {
            ControlResponse::Ack => Ok(()),
            other => Err(unexpected_response("RenewLease", &other)),
        }
    }

    /// Starts a streaming execution inside `id` and upgrades the connection into [`ClientExecStream`].
    pub async fn exec_stream(
        &self,
        id: &SandboxId,
        req: ExecRequest,
    ) -> Result<ClientExecStream, SandboxError> {
        let mut stream = self.connect_with_connector().await?;
        let payload = ControlRequest::ExecStart {
            id: id.clone(),
            req,
        }
        .to_json_bytes()?;
        write_control_frame(&mut stream, &payload).await?;

        match read_control_response(&mut stream).await? {
            ControlResponse::ExecStarted { stream_id } => {
                Ok(ClientExecStream::from_stream(stream_id, stream))
            }
            other => Err(unexpected_response("ExecStart", &other)),
        }
    }

    /// Runs a command inside `id`, collects all `stdout`/`stderr`, and awaits its exit status.
    pub async fn exec_collect(
        &self,
        id: &SandboxId,
        req: ExecRequest,
    ) -> Result<ClientExecOutput, SandboxError> {
        self.exec_stream(id, req).await?.collect().await
    }

    /// Uploads a pre-packed tar archive to `dst_guest` inside sandbox `id`.
    pub async fn copy_in_tar_bytes(
        &self,
        id: &SandboxId,
        dst_guest: impl AsRef<str>,
        tar_bytes: Vec<u8>,
    ) -> Result<(), SandboxError> {
        let dst_guest = dst_guest.as_ref();
        validate_guest_path(dst_guest, "dst_guest")?;
        if (tar_bytes.len() as u64) > self.max_copy_bytes {
            return Err(SandboxError::BudgetExceeded(format!(
                "copy_in tar archive {} bytes exceeds max_copy_bytes ({})",
                tar_bytes.len(),
                self.max_copy_bytes
            )));
        }
        if tar_bytes.len() > MAX_CONTROL_FRAME_BYTES {
            return Err(SandboxError::BudgetExceeded(format!(
                "copy_in tar archive {} bytes exceeds wire frame limit",
                tar_bytes.len()
            )));
        }

        match self
            .rpc(ControlRequest::CopyInTar {
                id: id.clone(),
                dst_guest: dst_guest.to_owned(),
                tar_bytes,
            })
            .await?
        {
            ControlResponse::Ack => Ok(()),
            other => Err(unexpected_response("CopyInTar", &other)),
        }
    }

    /// Safely packs `src_host` into a bounded tar archive and copies it to `dst_guest`.
    pub async fn copy_in_path(
        &self,
        id: &SandboxId,
        src_host: impl AsRef<Path>,
        dst_guest: impl AsRef<str>,
    ) -> Result<(), SandboxError> {
        let dst_guest = dst_guest.as_ref();
        validate_guest_path(dst_guest, "dst_guest")?;

        let src_owned = src_host.as_ref().to_path_buf();
        let max_bytes = self.max_copy_bytes;
        let tar_bytes =
            tokio::task::spawn_blocking(move || pack_path_to_tar_bytes(&src_owned, max_bytes))
                .await
                .map_err(|err| SandboxError::Internal(format!("tar pack task failed: {err}")))??;

        self.copy_in_tar_bytes(id, dst_guest, tar_bytes).await
    }

    /// Downloads raw tar bytes for `src_guest` from sandbox `id`.
    pub async fn copy_out_tar_bytes(
        &self,
        id: &SandboxId,
        src_guest: impl AsRef<str>,
    ) -> Result<Vec<u8>, SandboxError> {
        let src_guest = src_guest.as_ref();
        validate_guest_path(src_guest, "src_guest")?;

        match self
            .rpc(ControlRequest::CopyOutTar {
                id: id.clone(),
                src_guest: src_guest.to_owned(),
            })
            .await?
        {
            ControlResponse::CopyOutData { tar_bytes } => Ok(tar_bytes),
            other => Err(unexpected_response("CopyOutTar", &other)),
        }
    }

    /// Downloads `src_guest` from sandbox `id` and safely extracts it into `dst_host`.
    pub async fn copy_out_to_path(
        &self,
        id: &SandboxId,
        src_guest: impl AsRef<str>,
        dst_host: impl AsRef<Path>,
    ) -> Result<u64, SandboxError> {
        let tar_bytes = self.copy_out_tar_bytes(id, src_guest).await?;
        let dst_owned = dst_host.as_ref().to_path_buf();
        let max_bytes = self.max_copy_bytes;
        let max_entries = self.max_copy_entries;

        tokio::task::spawn_blocking(move || {
            extract_tar_bytes_safely(&tar_bytes, &dst_owned, max_bytes, max_entries)
        })
        .await
        .map_err(|err| SandboxError::Internal(format!("tar extract task failed: {err}")))?
    }

    /// Enables the Docker compatibility endpoint for `id` and returns its local endpoint URI.
    pub async fn enable_docker_compat(
        &self,
        id: &SandboxId,
        allow_reaper_socket: bool,
    ) -> Result<String, SandboxError> {
        match self
            .rpc(ControlRequest::EnableDockerCompat {
                id: id.clone(),
                allow_reaper_socket,
            })
            .await?
        {
            ControlResponse::DockerCompatEndpoint { uri } => Ok(uri),
            other => Err(unexpected_response("EnableDockerCompat", &other)),
        }
    }

    /// Destroys sandbox `id` idempotently and returns host resource cleanup status.
    pub async fn destroy(&self, id: &SandboxId) -> Result<DestroyStatus, SandboxError> {
        match self
            .rpc(ControlRequest::Destroy { id: id.clone() })
            .await?
        {
            ControlResponse::Destroyed(status) => Ok(status),
            other => Err(unexpected_response("Destroy", &other)),
        }
    }

    /// Requests graceful daemon shutdown over the authenticated local control endpoint.
    pub async fn shutdown(&self) -> Result<(), SandboxError> {
        match self.rpc(ControlRequest::Shutdown).await? {
            ControlResponse::Ack => Ok(()),
            other => Err(unexpected_response("Shutdown", &other)),
        }
    }

    async fn rpc(&self, req: ControlRequest) -> Result<ControlResponse, SandboxError> {
        let mut stream = self.connect_with_connector().await?;
        let payload = req.to_json_bytes()?;
        write_control_frame(&mut stream, &payload).await?;
        let _ = stream.shutdown().await;
        read_control_response(&mut stream).await
    }
}

async fn read_control_response<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<ControlResponse, SandboxError> {
    let raw = read_control_frame(reader).await?.ok_or_else(|| {
        SandboxError::Transport("daemon closed connection before sending control response".to_owned())
    })?;
    let resp = ControlResponse::from_json_bytes(&raw)?;
    if let ControlResponse::Error(wire_err) = resp {
        return Err(wire_err.into());
    }
    Ok(resp)
}

fn unexpected_response(op: &str, resp: &ControlResponse) -> SandboxError {
    SandboxError::Transport(format!("unexpected control response for {op}: {resp:?}"))
}

fn validate_guest_path(path: &str, field: &str) -> Result<(), SandboxError> {
    if path.is_empty() {
        return Err(SandboxError::InvalidSpec(format!("{field} cannot be empty")));
    }
    if path.len() > MAX_GUEST_PATH_BYTES {
        return Err(SandboxError::InvalidSpec(format!(
            "{field} exceeds maximum length of {MAX_GUEST_PATH_BYTES} bytes"
        )));
    }
    if path.contains('\0') {
        return Err(SandboxError::InvalidSpec(format!(
            "{field} cannot contain NUL bytes"
        )));
    }
    Ok(())
}

async fn connect_os_endpoint(endpoint: &ControlEndpoint) -> Result<BoxedControlStream, SandboxError> {
    endpoint.validate()?;
    match endpoint {
        ControlEndpoint::UnixSocket(path) => connect_unix_socket(path).await,
        ControlEndpoint::NamedPipe(name) => connect_named_pipe(name).await,
    }
}

#[cfg(unix)]
async fn connect_unix_socket(path: &Path) -> Result<BoxedControlStream, SandboxError> {
    let stream = tokio::net::UnixStream::connect(path).await.map_err(|err| {
        SandboxError::Transport(format!(
            "failed to connect to Unix socket '{}': {err}",
            path.display()
        ))
    })?;
    Ok(Box::new(stream))
}

#[cfg(not(unix))]
async fn connect_unix_socket(path: &Path) -> Result<BoxedControlStream, SandboxError> {
    Err(SandboxError::Transport(format!(
        "Unix socket control endpoint '{}' is not supported on this host OS; use a Windows Named Pipe",
        path.display()
    )))
}

#[cfg(windows)]
async fn connect_named_pipe(raw_pipe: &str) -> Result<BoxedControlStream, SandboxError> {
    use tokio::net::windows::named_pipe::ClientOptions;

    let pipe_path = normalize_named_pipe_path(raw_pipe)?;
    for attempt in 0..=PIPE_BUSY_MAX_RETRIES {
        match ClientOptions::new()
            .security_qos_flags(SECURITY_IDENTIFICATION_QOS)
            .open(&pipe_path)
        {
            Ok(client) => return Ok(Box::new(client)),
            Err(err)
                if err.raw_os_error() == Some(ERROR_PIPE_BUSY)
                    && attempt < PIPE_BUSY_MAX_RETRIES =>
            {
                tokio::time::sleep(PIPE_BUSY_RETRY_DELAY).await;
            }
            Err(err) => {
                return Err(SandboxError::Transport(format!(
                    "failed to connect to Windows Named Pipe '{pipe_path}': {err}"
                )));
            }
        }
    }
    Err(SandboxError::Transport(format!(
        "timed out waiting for busy Windows Named Pipe '{pipe_path}'"
    )))
}

#[cfg(not(windows))]
async fn connect_named_pipe(raw_pipe: &str) -> Result<BoxedControlStream, SandboxError> {
    Err(SandboxError::Transport(format!(
        "Windows Named Pipe control endpoint '{raw_pipe}' is not supported on non-Windows hosts"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::WireError;
    use sandbox_core::{
        AccelerationPolicy, CapabilityReport, EnforcementLevel, ExecTarget, IsolationMode,
        NetworkPolicy, ResourceBudget,
    };
    use std::collections::BTreeMap;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
    use std::sync::Mutex;
    use tokio::io::{duplex, DuplexStream};

    static TEST_SEQ: AtomicU64 = AtomicU64::new(0);

    struct TestTempDir(PathBuf);

    impl TestTempDir {
        fn new(label: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "minipod-client-test-{label}-{}-{}",
                std::process::id(),
                TEST_SEQ.fetch_add(1, AtomicOrdering::Relaxed)
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

    fn test_spec() -> SandboxSpec {
        SandboxSpec {
            isolation: IsolationMode::VmRequired,
            acceleration: AccelerationPolicy::Preferred,
            network: NetworkPolicy::Isolated,
            budget: ResourceBudget {
                guest_vcpus: 1,
                host_cpu_quota_Millicores: Some(1000),
                guest_ram_mb: 256,
                host_rss_budget_mb: Some(512),
                virtual_disk_mb: 1024,
                host_storage_budget_mb: 2048,
            },
            lease_ttl: Duration::from_secs(60),
        }
    }

    fn test_exec_req() -> ExecRequest {
        ExecRequest {
            target: ExecTarget::Guest,
            argv: vec!["/bin/sh".to_owned(), "-c".to_owned(), "cat".to_owned()],
            env: BTreeMap::new(),
            cwd: Some("/workspace".to_owned()),
            user: None,
            deadline: Duration::from_secs(10),
            stdout_budget_bytes: 64 * 1024,
            stderr_budget_bytes: 64 * 1024,
        }
    }

    #[test]
    fn control_endpoint_parse_accepts_local_and_rejects_tcp_http_and_remote_unc() {
        assert_eq!(
            ControlEndpoint::parse("unix:///run/minipod/daemon.sock").unwrap(),
            ControlEndpoint::UnixSocket(PathBuf::from("/run/minipod/daemon.sock"))
        );
        assert_eq!(
            ControlEndpoint::parse("/tmp/minipod.sock").unwrap(),
            ControlEndpoint::UnixSocket(PathBuf::from("/tmp/minipod.sock"))
        );
        assert_eq!(
            ControlEndpoint::parse(r"\\.\pipe\minipod-ctl").unwrap(),
            ControlEndpoint::NamedPipe(r"\\.\pipe\minipod-ctl".to_owned())
        );
        assert_eq!(
            ControlEndpoint::parse("npipe://minipod-ctl").unwrap(),
            ControlEndpoint::NamedPipe(r"\\.\pipe\minipod-ctl".to_owned())
        );
        assert_eq!(
            ControlEndpoint::parse("npipe:////./pipe/minipod-ctl").unwrap(),
            ControlEndpoint::NamedPipe(r"\\.\pipe\minipod-ctl".to_owned())
        );
        assert_eq!(
            ControlEndpoint::parse(r"npipe://\\.\pipe\minipod-ctl").unwrap(),
            ControlEndpoint::NamedPipe(r"\\.\pipe\minipod-ctl".to_owned())
        );

        let rejected_policy = [
            "tcp://127.0.0.1:2375",
            "TCP://localhost:8080",
            "http://127.0.0.1:8080",
            "https://127.0.0.1:8443",
            "ws://127.0.0.1:8080",
            "wss://127.0.0.1:8443",
            "tls://127.0.0.1:8443",
            "ssh://host/var/run/sock",
            "127.0.0.1:8080",
            r"\\remote-server\pipe\minipod",
            "//remote-server/pipe/minipod",
            "/tmp/../etc/sock",
            "unix:///tmp/../escape.sock",
            "npipe://host/pipe/bad",
            "unix:///tmp/bad\0.sock",
        ];
        for raw in rejected_policy {
            assert!(
                matches!(
                    ControlEndpoint::parse(raw),
                    Err(SandboxError::PolicyViolation(_))
                ),
                "expected PolicyViolation for '{raw}'"
            );
        }

        for empty_or_bad in ["", "   ", "unix://", "/", r"\\.\pipe\", "npipe://", r"\\.\pipe\a\b"]
        {
            assert!(
                matches!(
                    ControlEndpoint::parse(empty_or_bad),
                    Err(SandboxError::InvalidSpec(_))
                ),
                "expected InvalidSpec for '{empty_or_bad}'"
            );
        }
    }

    fn make_mock_client<H, Fut>(handler: H) -> (SandboxClient, Arc<Mutex<Vec<JoinHandle<()>>>>)
    where
        H: Fn(DuplexStream) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let handler = Arc::new(handler);
        let tasks = Arc::new(Mutex::new(Vec::new()));
        let tasks_ref = Arc::clone(&tasks);
        let client = SandboxClient::with_connector(
            ControlEndpoint::NamedPipe(r"\\.\pipe\mock-minipod".to_owned()),
            move |_| {
                let handler = Arc::clone(&handler);
                let tasks_ref = Arc::clone(&tasks_ref);
                async move {
                    let (client_end, server_end) = duplex(1024 * 1024);
                    let handle = tokio::spawn(async move {
                        handler(server_end).await;
                    });
                    tasks_ref.lock().unwrap().push(handle);
                    Ok(client_end)
                }
            },
        );
        (client, tasks)
    }

    async fn join_server_tasks(tasks: Arc<Mutex<Vec<JoinHandle<()>>>>) {
        let handles: Vec<_> = tasks.lock().unwrap().drain(..).collect();
        for h in handles {
            h.await.unwrap();
        }
    }

    #[tokio::test]
    async fn client_rpc_methods_copy_in_out_and_error_propagation() {
        let stored_tar: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
        let stored_tar_srv = Arc::clone(&stored_tar);

        let (client, tasks) = make_mock_client(move |mut stream| {
            let stored_tar_srv = Arc::clone(&stored_tar_srv);
            async move {
                let raw = read_control_frame(&mut stream).await.unwrap().unwrap();
                let req = ControlRequest::from_json_bytes(&raw).unwrap();
                let resp = match req {
                    ControlRequest::Status => ControlResponse::Status(DaemonStatusInfo {
                        active_sandboxes: 1,
                        warm_ready_vms: 2,
                        effective_host_rss_mb: 384,
                        reserved_host_storage_mb: 2048,
                        version: "0.1.0-test".to_owned(),
                    }),
                    ControlRequest::ListSandboxes => ControlResponse::SandboxList {
                        sandboxes: vec![SandboxSummaryInfo {
                            id: SandboxId::new("sb-test-1"),
                            pid: 9001,
                            alive: true,
                            network: NetworkPolicy::Isolated,
                            remaining_ttl_ms: 59_000,
                            live_rss_bytes: Some(256 * 1024 * 1024),
                            reserved_rss_mb: 320,
                            host_rss_budget_mb: Some(512),
                            host_storage_budget_mb: 2048,
                            docker_endpoint: None,
                            allow_reaper_socket: false,
                        }],
                    },
                    ControlRequest::Spawn { spec } => {
                        assert_eq!(spec.budget.guest_vcpus, 1);
                        ControlResponse::Spawned(SandboxLease {
                            id: SandboxId::new("sb-test-1"),
                            ttl: spec.lease_ttl,
                            capabilities: CapabilityReport {
                                cpu_quota: EnforcementLevel::HardLimit,
                                host_rss: EnforcementLevel::BestEffort,
                                host_storage: EnforcementLevel::HardLimit,
                                egress_filter: EnforcementLevel::HardLimit,
                            },
                        })
                    }
                    ControlRequest::RenewLease { id, ttl_ms } => {
                        if id.as_str() == "missing" {
                            ControlResponse::Error(WireError::from(SandboxError::NotFound(
                                "missing".to_owned(),
                            )))
                        } else {
                            assert_eq!(ttl_ms, 120_000);
                            ControlResponse::Ack
                        }
                    }
                    ControlRequest::CopyInTar {
                        id,
                        dst_guest,
                        tar_bytes,
                    } => {
                        assert_eq!(id.as_str(), "sb-test-1");
                        assert_eq!(dst_guest, "/workspace");
                        *stored_tar_srv.lock().unwrap() = Some(tar_bytes);
                        ControlResponse::Ack
                    }
                    ControlRequest::CopyOutTar { id, src_guest } => {
                        assert_eq!(id.as_str(), "sb-test-1");
                        assert_eq!(src_guest, "/workspace");
                        let tar_bytes = stored_tar_srv.lock().unwrap().clone().unwrap();
                        ControlResponse::CopyOutData { tar_bytes }
                    }
                    ControlRequest::EnableDockerCompat {
                        id,
                        allow_reaper_socket,
                    } => {
                        assert_eq!(id.as_str(), "sb-test-1");
                        assert!(allow_reaper_socket);
                        ControlResponse::DockerCompatEndpoint {
                            uri: r"\\.\pipe\docker-sb-test-1".to_owned(),
                        }
                    }
                    ControlRequest::Destroy { id } => {
                        assert_eq!(id.as_str(), "sb-test-1");
                        ControlResponse::Destroyed(DestroyStatus::AllResourcesCleaned)
                    }
                    ControlRequest::Shutdown => ControlResponse::Ack,
                    other => panic!("unexpected request: {other:?}"),
                };
                write_control_frame(&mut stream, &resp.to_json_bytes().unwrap())
                    .await
                    .unwrap();
            }
        });

        let status = client.status().await.unwrap();
        assert_eq!(status.active_sandboxes, 1);
        assert_eq!(status.warm_ready_vms, 2);
        assert_eq!(status.version, "0.1.0-test");

        let sandboxes = client.list_sandboxes().await.unwrap();
        assert_eq!(sandboxes.len(), 1);
        assert_eq!(sandboxes[0].id, SandboxId::new("sb-test-1"));
        assert_eq!(sandboxes[0].pid, 9001);

        let lease = client.spawn(test_spec()).await.unwrap();
        assert_eq!(lease.id, SandboxId::new("sb-test-1"));

        client
            .renew_lease(&lease.id, Duration::from_secs(120))
            .await
            .unwrap();
        assert!(matches!(
            client
                .renew_lease(&SandboxId::new("missing"), Duration::from_secs(5))
                .await,
            Err(SandboxError::NotFound(_))
        ));

        let tmp = TestTempDir::new("copy-rpc");
        let src = tmp.path().join("src");
        fs::create_dir_all(src.join("sub")).unwrap();
        fs::write(src.join("sub").join("data.txt"), b"hello-workspace").unwrap();

        client
            .copy_in_path(&lease.id, &src, "/workspace")
            .await
            .unwrap();

        let dst = tmp.path().join("dst");
        let extracted = client
            .copy_out_to_path(&lease.id, "/workspace", &dst)
            .await
            .unwrap();
        assert_eq!(extracted, b"hello-workspace".len() as u64);
        assert_eq!(
            fs::read(dst.join("sub").join("data.txt")).unwrap(),
            b"hello-workspace"
        );

        let uri = client.enable_docker_compat(&lease.id, true).await.unwrap();
        assert_eq!(uri, r"\\.\pipe\docker-sb-test-1");

        let destroyed = client.destroy(&lease.id).await.unwrap();
        assert_eq!(destroyed, DestroyStatus::AllResourcesCleaned);

        client.shutdown().await.unwrap();

        join_server_tasks(tasks).await;
    }

    #[tokio::test]
    async fn client_exec_stream_stdin_stdout_stderr_and_collect() {
        let (client, tasks) = make_mock_client(|mut stream| async move {
            let raw = read_control_frame(&mut stream).await.unwrap().unwrap();
            let req = ControlRequest::from_json_bytes(&raw).unwrap();
            assert!(matches!(req, ControlRequest::ExecStart { .. }));

            write_control_frame(
                &mut stream,
                &ControlResponse::ExecStarted { stream_id: 9 }
                    .to_json_bytes()
                    .unwrap(),
            )
            .await
            .unwrap();

            let mut received_stdin = Vec::new();
            while let Some(frame) = read_control_frame(&mut stream).await.unwrap() {
                match ExecWireClientMsg::from_json_bytes(&frame).unwrap() {
                    ExecWireClientMsg::Stdin { data } => received_stdin.extend_from_slice(&data),
                    ExecWireClientMsg::StdinEof => break,
                    ExecWireClientMsg::Cancel => panic!("unexpected cancel"),
                }
            }
            assert_eq!(received_stdin, b"abc123");

            for evt in [
                ExecWireEvent::Stdout {
                    data: b"out:".to_vec(),
                },
                ExecWireEvent::Stderr {
                    data: b"warn".to_vec(),
                },
                ExecWireEvent::Stdout {
                    data: received_stdin,
                },
                ExecWireEvent::Exit(ExecExitStatus {
                    code: Some(0),
                    timed_out: false,
                    stdout_truncated: false,
                    stderr_truncated: false,
                }),
            ] {
                write_control_frame(&mut stream, &evt.to_json_bytes().unwrap())
                    .await
                    .unwrap();
            }
        });

        let mut exec = client
            .exec_stream(&SandboxId::new("sb-1"), test_exec_req())
            .await
            .unwrap();
        assert_eq!(exec.stream_id, 9);

        exec.write_stdin(b"abc".to_vec()).await.unwrap();
        exec.write_stdin(b"123".to_vec()).await.unwrap();
        exec.close_stdin();
        assert!(matches!(
            exec.write_stdin(b"after-close".to_vec()).await,
            Err(SandboxError::Transport(_))
        ));

        let first = exec.next_output().await.unwrap();
        assert_eq!(first.stream, ClientOutputKind::Stdout);
        assert_eq!(first.data, b"out:");

        let rest = exec.collect().await.unwrap();
        assert_eq!(rest.stdout, b"abc123");
        assert_eq!(rest.stderr, b"warn");
        assert_eq!(rest.exit.code, Some(0));

        join_server_tasks(tasks).await;
    }

    #[tokio::test]
    async fn client_exec_stream_cancel_and_collect_helper() {
        let (client, tasks) = make_mock_client(|mut stream| async move {
            let raw = read_control_frame(&mut stream).await.unwrap().unwrap();
            let ControlRequest::ExecStart { req, .. } =
                ControlRequest::from_json_bytes(&raw).unwrap()
            else {
                panic!("expected ExecStart");
            };

            write_control_frame(
                &mut stream,
                &ControlResponse::ExecStarted { stream_id: 3 }
                    .to_json_bytes()
                    .unwrap(),
            )
            .await
            .unwrap();

            if req.argv.first().map(String::as_str) == Some("sleep") {
                loop {
                    let frame = read_control_frame(&mut stream).await.unwrap().unwrap();
                    if matches!(
                        ExecWireClientMsg::from_json_bytes(&frame).unwrap(),
                        ExecWireClientMsg::Cancel
                    ) {
                        write_control_frame(
                            &mut stream,
                            &ExecWireEvent::Exit(ExecExitStatus {
                                code: None,
                                timed_out: false,
                                stdout_truncated: false,
                                stderr_truncated: false,
                            })
                            .to_json_bytes()
                            .unwrap(),
                        )
                        .await
                        .unwrap();
                        break;
                    }
                }
            } else {
                write_control_frame(
                    &mut stream,
                    &ExecWireEvent::Stdout {
                        data: b"collected".to_vec(),
                    }
                    .to_json_bytes()
                    .unwrap(),
                )
                .await
                .unwrap();
                write_control_frame(
                    &mut stream,
                    &ExecWireEvent::Exit(ExecExitStatus {
                        code: Some(0),
                        timed_out: false,
                        stdout_truncated: false,
                        stderr_truncated: false,
                    })
                    .to_json_bytes()
                    .unwrap(),
                )
                .await
                .unwrap();
            }
        });

        let mut cancel_req = test_exec_req();
        cancel_req.argv = vec!["sleep".to_owned(), "60".to_owned()];
        let mut exec = client
            .exec_stream(&SandboxId::new("sb-1"), cancel_req)
            .await
            .unwrap();
        exec.cancel().unwrap();
        let status = exec.wait_exit().await.unwrap();
        assert_eq!(status.code, None);
        assert_eq!(exec.wait_exit().await.unwrap(), status);
        assert!(matches!(exec.cancel(), Err(SandboxError::Transport(_))));

        let collected = client
            .exec_collect(&SandboxId::new("sb-1"), test_exec_req())
            .await
            .unwrap();
        assert_eq!(collected.stdout, b"collected");
        assert_eq!(collected.exit.code, Some(0));

        join_server_tasks(tasks).await;
    }

    #[tokio::test]
    async fn client_enforces_copy_limits_before_sending() {
        let client = SandboxClient::new(ControlEndpoint::NamedPipe("unused".to_owned()))
            .with_copy_limits(16, 4)
            .unwrap();

        assert!(matches!(
            client
                .copy_in_tar_bytes(&SandboxId::new("sb-1"), "/workspace", vec![0u8; 32])
                .await,
            Err(SandboxError::BudgetExceeded(_))
        ));
        assert!(matches!(
            client
                .copy_in_tar_bytes(&SandboxId::new("sb-1"), "", vec![])
                .await,
            Err(SandboxError::InvalidSpec(_))
        ));
        assert!(matches!(
            client
                .renew_lease(&SandboxId::new("sb-1"), Duration::ZERO)
                .await,
            Err(SandboxError::InvalidSpec(_))
        ));
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn windows_named_pipe_client_connects_and_retries_pipe_busy() {
        use tokio::net::windows::named_pipe::ServerOptions;

        let pipe_name = format!(
            "minipod-client-test-{}-{}",
            std::process::id(),
            TEST_SEQ.fetch_add(1, AtomicOrdering::Relaxed)
        );
        let pipe_path = format!(r"\\.\pipe\{pipe_name}");
        let server1 = ServerOptions::new()
            .first_pipe_instance(true)
            .create(&pipe_path)
            .expect("create first pipe instance");

        // Hold one connected instance without a second listening instance yet so a second
        // concurrent client observes ERROR_PIPE_BUSY (231) and succeeds once server2 appears.
        let (hold_tx, hold_rx) = oneshot::channel::<()>();
        let server_task = tokio::spawn({
            let pipe_path = pipe_path.clone();
            async move {
                server1.connect().await.unwrap();
                let mut s1 = server1;
                let _ = hold_rx.await;
                let server2 = ServerOptions::new().create(&pipe_path).unwrap();
                server2.connect().await.unwrap();
                let mut s2 = server2;
                let raw = read_control_frame(&mut s2).await.unwrap().unwrap();
                assert_eq!(
                    ControlRequest::from_json_bytes(&raw).unwrap(),
                    ControlRequest::Status
                );
                let resp = ControlResponse::Status(DaemonStatusInfo {
                    active_sandboxes: 0,
                    warm_ready_vms: 0,
                    effective_host_rss_mb: 0,
                    reserved_host_storage_mb: 0,
                    version: "win-pipe".to_owned(),
                });
                write_control_frame(&mut s2, &resp.to_json_bytes().unwrap())
                    .await
                    .unwrap();
                let _ = s1.shutdown().await;
            }
        });

        let endpoint = ControlEndpoint::parse(&pipe_path).unwrap();
        let client = SandboxClient::new(endpoint.clone());
        // Occupy the sole initial instance.
        let _holder = connect_named_pipe(&pipe_name).await.unwrap();

        let status_fut = tokio::spawn(async move { client.status().await });
        tokio::time::sleep(Duration::from_millis(40)).await;
        let _ = hold_tx.send(());

        let status = status_fut.await.unwrap().unwrap();
        assert_eq!(status.version, "win-pipe");
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn client_exec_stream_handles_server_error_eof_and_high_volume_wait_exit() {
        let (client, tasks) = make_mock_client(|mut stream| async move {
            let raw = read_control_frame(&mut stream).await.unwrap().unwrap();
            let ControlRequest::ExecStart { req, .. } =
                ControlRequest::from_json_bytes(&raw).unwrap()
            else {
                panic!("expected ExecStart");
            };
            write_control_frame(
                &mut stream,
                &ControlResponse::ExecStarted { stream_id: 12 }
                    .to_json_bytes()
                    .unwrap(),
            )
            .await
            .unwrap();

            match req.argv.first().map(String::as_str) {
                Some("err") => {
                    write_control_frame(
                        &mut stream,
                        &ExecWireEvent::Error(WireError::from(SandboxError::BudgetExceeded(
                            "stdout limit".to_owned(),
                        )))
                        .to_json_bytes()
                        .unwrap(),
                    )
                    .await
                    .unwrap();
                }
                Some("eof") => {
                    // Close immediately without Exit or Error.
                }
                Some("flood") => {
                    // Exceed OUTPUT_CHANNEL_CAPACITY (256) to verify wait_exit does not deadlock.
                    let chunk = ExecWireEvent::Stdout {
                        data: b"line\n".to_vec(),
                    }
                    .to_json_bytes()
                    .unwrap();
                    for _ in 0..320 {
                        write_control_frame(&mut stream, &chunk).await.unwrap();
                    }
                    write_control_frame(
                        &mut stream,
                        &ExecWireEvent::Exit(ExecExitStatus {
                            code: Some(0),
                            timed_out: false,
                            stdout_truncated: false,
                            stderr_truncated: false,
                        })
                        .to_json_bytes()
                        .unwrap(),
                    )
                    .await
                    .unwrap();
                }
                other => panic!("unexpected mode {other:?}"),
            }
        });

        let mut err_req = test_exec_req();
        err_req.argv = vec!["err".to_owned()];
        assert!(matches!(
            client.exec_collect(&SandboxId::new("sb-1"), err_req).await,
            Err(SandboxError::BudgetExceeded(_))
        ));

        let mut eof_req = test_exec_req();
        eof_req.argv = vec!["eof".to_owned()];
        let mut eof_stream = client
            .exec_stream(&SandboxId::new("sb-1"), eof_req)
            .await
            .unwrap();
        assert!(matches!(
            eof_stream.wait_exit().await,
            Err(SandboxError::Transport(_))
        ));

        let mut flood_req = test_exec_req();
        flood_req.argv = vec!["flood".to_owned()];
        let mut flood_stream = client
            .exec_stream(&SandboxId::new("sb-1"), flood_req)
            .await
            .unwrap();
        let exit = flood_stream.wait_exit().await.unwrap();
        assert_eq!(exit.code, Some(0));

        join_server_tasks(tasks).await;
    }
}
