//! Daemon composition root: runtime wiring, owner-only local IPC listener, Docker compat
//! endpoint registry, streaming execution bridge, and graceful shutdown.

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
#[cfg(any(unix, test))]
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use sandbox_client::{
    read_control_frame, write_control_frame, ControlEndpoint, ControlRequest, ControlResponse,
    DaemonStatusInfo, ExecWireClientMsg, ExecWireEvent, WireError,
};
use sandbox_core::{DestroyStatus, NetworkPolicy, SandboxError, SandboxId};
#[cfg(windows)]
use sandbox_docker_compat::NamedPipeServerHandle;
#[cfg(unix)]
use sandbox_docker_compat::UnixServerHandle;
use sandbox_docker_compat::{DockerCompatPolicy, DockerCompatServer, ReaperSocketPolicy};
use sandbox_image::{verify_installed_bundle, BundleOverlayStore, HelperCommandOutput};
use sandbox_runtime::{
    ExecStream, LocalRuntimeManager, OutputStreamKind, RuntimeManager, SandboxTunnelPort,
};
use sandbox_vmm::{
    discover_qemu_binary_for_arch, discover_qemu_img_binary, run_confined_command_bounded,
    QemuDriverConfig, QemuVmDriver,
};
use serde_json::json;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use crate::config::ServeConfig;

const CONTAINER_EGRESS_PROXY_URL: &str = "http://10.88.0.1:3128";
const EXEC_CLIENT_MSG_QUEUE_DEPTH: usize = 32;

static NEXT_DOCKER_COMPAT_SEQ: AtomicU64 = AtomicU64::new(1);

enum DockerListenerHandle {
    #[cfg(windows)]
    NamedPipe(NamedPipeServerHandle),
    #[cfg(unix)]
    Unix(UnixServerHandle),
}

impl DockerListenerHandle {
    async fn shutdown(self) {
        match self {
            #[cfg(windows)]
            Self::NamedPipe(handle) => handle.shutdown().await,
            #[cfg(unix)]
            Self::Unix(handle) => handle.shutdown().await,
        }
    }
}

struct CachedDockerCompat {
    allow_reaper_socket: bool,
    uri: String,
    #[cfg(test)]
    proxy_url: Option<String>,
    compat: Arc<DockerCompatServer>,
    handle: Option<DockerListenerHandle>,
}

impl CachedDockerCompat {
    async fn shutdown(mut self) {
        self.compat.registry().release_all();
        if let Some(handle) = self.handle.take() {
            handle.shutdown().await;
        }
    }
}

impl Drop for CachedDockerCompat {
    fn drop(&mut self) {
        self.compat.registry().release_all();
    }
}

/// Shared runtime and Docker compatibility state served by `sandboxd`.
pub struct DaemonState {
    runtime: Arc<LocalRuntimeManager>,
    docker_compat: Arc<Mutex<HashMap<SandboxId, CachedDockerCompat>>>,
    shutdown_tx: Option<watch::Sender<bool>>,
}

impl DaemonState {
    /// Wraps an initialized [`LocalRuntimeManager`] in [`DaemonState`].
    pub fn new(runtime: Arc<LocalRuntimeManager>) -> Self {
        Self::build_inner(runtime, None)
    }

    /// Wraps an initialized [`LocalRuntimeManager`] with a daemon shutdown signal sender.
    pub fn with_shutdown(
        runtime: Arc<LocalRuntimeManager>,
        shutdown_tx: watch::Sender<bool>,
    ) -> Self {
        Self::build_inner(runtime, Some(shutdown_tx))
    }

    fn build_inner(
        runtime: Arc<LocalRuntimeManager>,
        shutdown_tx: Option<watch::Sender<bool>>,
    ) -> Self {
        let docker_compat = Arc::new(Mutex::new(HashMap::<SandboxId, CachedDockerCompat>::new()));
        let listener_map = Arc::clone(&docker_compat);
        runtime.register_destroy_listener(move |sandbox_id| {
            let removed = listener_map
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(sandbox_id);
            if let Some(entry) = removed {
                if let Ok(rt) = tokio::runtime::Handle::try_current() {
                    rt.spawn(async move {
                        entry.shutdown().await;
                    });
                }
            }
        });
        Self {
            runtime,
            docker_compat,
            shutdown_tx,
        }
    }

    /// Signals the daemon control listener to stop accepting new connections and shut down cleanly.
    pub fn request_shutdown(&self) {
        if let Some(tx) = &self.shutdown_tx {
            let _ = tx.send(true);
        }
    }

    /// Returns current active sandbox, warm pool, and host budget counters.
    pub fn status(&self) -> DaemonStatusInfo {
        daemon_status_info(&self.runtime)
    }

    /// Lazily binds (or returns the cached) owner-only local IPC Docker compatibility listener
    /// (`npipe://` with owner-only DACL on Windows; `unix://` `0600` in `0700` dir on Unix).
    pub async fn enable_docker_compat(
        &self,
        id: &SandboxId,
        allow_reaper_socket: bool,
    ) -> Result<String, SandboxError> {
        let network = self.runtime.active_sandbox_network(id)?;

        let previous = {
            let mut map = self
                .docker_compat
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if let Some(existing) = map.get(id) {
                if existing.allow_reaper_socket == allow_reaper_socket {
                    return Ok(existing.uri.clone());
                }
            }
            map.remove(id)
        };
        if let Some(prev) = previous {
            prev.shutdown().await;
        }

        let container_proxy_http_url = match network {
            NetworkPolicy::Isolated => None,
            NetworkPolicy::InternetOnly
            | NetworkPolicy::DomainAllowList { .. }
            | NetworkPolicy::Unrestricted => Some(CONTAINER_EGRESS_PROXY_URL.to_owned()),
        };
        let reaper_socket = if allow_reaper_socket {
            ReaperSocketPolicy::MapGuestPodmanSocket
        } else {
            ReaperSocketPolicy::Deny
        };

        let compat = Arc::new(DockerCompatServer::new(
            Arc::clone(&self.runtime) as Arc<dyn SandboxTunnelPort>,
            id.clone(),
            DockerCompatPolicy {
                reaper_socket,
                container_proxy_http_url: container_proxy_http_url.clone(),
            },
        ));
        let (uri, handle) = bind_owner_only_docker_listener(
            &compat,
            &self.runtime.config().state_dir,
        )
        .await?;

        // Re-check liveness so a concurrent destroy during listener bind never leaks an orphan entry.
        if let Err(err) = self.runtime.active_sandbox_network(id) {
            compat.registry().release_all();
            handle.shutdown().await;
            return Err(err);
        }

        let displaced = {
            let mut map = self
                .docker_compat
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            map.insert(
                id.clone(),
                CachedDockerCompat {
                    allow_reaper_socket,
                    uri: uri.clone(),
                    #[cfg(test)]
                    proxy_url: container_proxy_http_url,
                    compat,
                    handle: Some(handle),
                },
            )
        };
        if let Some(old) = displaced {
            old.shutdown().await;
        }

        Ok(uri)
    }

    /// Tears down any cached Docker compatibility server for `id` and idempotently destroys `id`.
    pub async fn destroy_sandbox(&self, id: &SandboxId) -> Result<DestroyStatus, SandboxError> {
        let removed = self
            .docker_compat
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(id);
        if let Some(entry) = removed {
            entry.shutdown().await;
        }
        self.runtime.destroy(id).await
    }

    /// Shuts down all cached Docker compatibility listeners, drains the Warm Pool, and destroys
    /// all remaining active sandboxes.
    pub async fn shutdown_all(&self) {
        let handles: Vec<CachedDockerCompat> = {
            let mut map = self
                .docker_compat
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            map.drain().map(|(_, entry)| entry).collect()
        };
        for entry in handles {
            entry.shutdown().await;
        }

        if let Err(err) = self.runtime.drain_warm_pool().await {
            eprintln!("[sandboxd] warm pool drain error during shutdown: {err}");
        }

        for id in self.runtime.active_sandbox_ids() {
            if let Err(err) = self.runtime.destroy(&id).await {
                eprintln!("[sandboxd] failed destroying sandbox '{id}' during shutdown: {err}");
            }
        }
    }
}

#[cfg(windows)]
async fn bind_owner_only_docker_listener(
    compat: &Arc<DockerCompatServer>,
    _state_dir: &Path,
) -> Result<(String, DockerListenerHandle), SandboxError> {
    let seq = NEXT_DOCKER_COMPAT_SEQ.fetch_add(1, Ordering::Relaxed);
    let pipe_name = format!("minipod-docker-{}-{seq}", std::process::id());
    let handle = compat.bind_named_pipe_with_factory(
        &pipe_name,
        sandbox_vmm::create_owner_only_async_named_pipe,
    )?;
    let uri = handle.uri().to_owned();
    Ok((uri, DockerListenerHandle::NamedPipe(handle)))
}

#[cfg(unix)]
async fn bind_owner_only_docker_listener(
    compat: &Arc<DockerCompatServer>,
    state_dir: &Path,
) -> Result<(String, DockerListenerHandle), SandboxError> {
    use std::os::unix::fs::MetadataExt;
    use sandbox_vmm::validate_socket_path;

    let seq = NEXT_DOCKER_COMPAT_SEQ.fetch_add(1, Ordering::Relaxed);
    let state_candidate = state_dir.join("dck").join(format!("d-{seq}.sock"));
    let sock_path = if validate_socket_path(&state_candidate).is_ok() {
        state_candidate
    } else {
        let uid = fs::metadata("/proc/self")
            .or_else(|_| fs::symlink_metadata(state_dir))
            .map(|m| m.uid())
            .unwrap_or(0);
        PathBuf::from("/tmp")
            .join(format!("mpd-{uid}-{}", std::process::id()))
            .join(format!("d-{seq}.sock"))
    };
    validate_socket_path(&sock_path)?;
    let handle = compat.bind_unix_owner_only(&sock_path).await?;
    let uri = format!("unix://{}", handle.socket_path().display());
    Ok((uri, DockerListenerHandle::Unix(handle)))
}

/// Computes a [`DaemonStatusInfo`] snapshot from a [`LocalRuntimeManager`].
pub fn daemon_status_info(runtime: &LocalRuntimeManager) -> DaemonStatusInfo {
    let usage = runtime.current_admission_usage();
    let warm = runtime.warm_pool_stats();
    DaemonStatusInfo {
        active_sandboxes: runtime.active_sandbox_ids().len(),
        warm_ready_vms: warm.ready_vms,
        effective_host_rss_mb: usage.effective_host_rss_mb,
        reserved_host_storage_mb: usage.reserved_host_storage_mb,
        version: env!("CARGO_PKG_VERSION").to_owned(),
    }
}

/// Wires adapters into [`LocalRuntimeManager`], reconciles crash journals, starts the lease
/// sweeper, and optionally pre-warms the Warm Pool.
pub async fn build_runtime(cfg: &ServeConfig) -> Result<Arc<LocalRuntimeManager>, SandboxError> {
    let verifier = cfg.pub_key.load_verifier()?;
    let bundle_dir = cfg.bundle_dir.clone();
    let verifier_for_check = verifier.clone();
    let _installed = tokio::task::spawn_blocking(move || {
        verify_installed_bundle(&bundle_dir, &verifier_for_check)
    })
    .await
    .map_err(|err| SandboxError::Internal(format!("bundle verification task failed: {err}")))??;

    let qemu_img_bin = discover_qemu_img_binary(cfg.qemu_img_bin.as_deref())?;
    let qemu_bin = discover_qemu_binary_for_arch(cfg.arch, cfg.qemu_bin.as_deref())?;

    let helper_runner = Arc::new(|prog: &Path, args: &[std::ffi::OsString], timeout: Duration| {
        let out = run_confined_command_bounded(prog, args, timeout, 1024 * 1024)?;
        Ok(HelperCommandOutput {
            success: out.status.success(),
            status_label: out.status.to_string(),
            stdout: out.stdout,
            stderr: out.stderr,
        })
    });
    let overlay =
        BundleOverlayStore::with_command_runner(&cfg.bundle_dir, verifier, qemu_img_bin, helper_runner)?;
    let driver = QemuVmDriver::new(QemuDriverConfig {
        arch: cfg.arch,
        qemu_bin: Some(qemu_bin),
        ..QemuDriverConfig::default()
    })?;

    let rt_cfg = cfg.to_runtime_config()?;
    let runtime = Arc::new(LocalRuntimeManager::new(
        rt_cfg,
        Arc::new(overlay),
        Arc::new(driver),
    )?);

    let report = runtime.reconcile_startup().await?;
    if report.records_seen > 0 {
        eprintln!(
            "[sandboxd] reconciled startup journals: seen={}, orphans_killed={}, cleaned={}, remaining={}",
            report.records_seen, report.orphans_killed, report.cleaned, report.remaining
        );
    }

    let _sweeper = runtime.spawn_lease_sweeper();

    if cfg.warm_pool_size > 0 {
        let ready = runtime.warm_up().await?;
        eprintln!("[sandboxd] warm pool pre-warmed {ready} VM(s)");
        let _replenisher = runtime.spawn_warm_pool_replenisher();
    }

    Ok(runtime)
}

/// Runs the local owner-only control daemon until SIGINT (`Ctrl-C`), `SIGTERM`, or `ControlRequest::Shutdown`.
pub async fn run_serve(cfg: ServeConfig) -> Result<(), SandboxError> {
    cfg.endpoint.validate()?;

    let runtime = build_runtime(&cfg).await?;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let state = Arc::new(DaemonState::with_shutdown(runtime, shutdown_tx.clone()));

    let signal_tx = shutdown_tx;
    let signal_handle = tokio::spawn(async move {
        wait_for_shutdown_signal().await;
        let _ = signal_tx.send(true);
    });
    struct SignalAbortGuard(JoinHandle<()>);
    impl Drop for SignalAbortGuard {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let _signal_guard = SignalAbortGuard(signal_handle);

    let serve_res = serve_endpoint_with_shutdown(
        &cfg.endpoint,
        cfg.ready_file.as_deref(),
        Arc::clone(&state),
        shutdown_rx,
    )
    .await;

    state.shutdown_all().await;
    serve_res
}

/// Binds the owner-only local control endpoint (`NamedPipe` or `UnixSocket`), optionally emits
/// `ready_file` atomically, and serves requests until `shutdown_rx` becomes `true`.
pub async fn serve_endpoint_with_shutdown(
    endpoint: &ControlEndpoint,
    ready_file: Option<&Path>,
    state: Arc<DaemonState>,
    shutdown_rx: watch::Receiver<bool>,
) -> Result<(), SandboxError> {
    endpoint.validate()?;
    match endpoint {
        ControlEndpoint::NamedPipe(pipe_path) => {
            #[cfg(windows)]
            {
                run_windows_named_pipe_server(pipe_path, ready_file, state, shutdown_rx).await
            }
            #[cfg(not(windows))]
            {
                let _ = (pipe_path, ready_file, state, shutdown_rx);
                Err(SandboxError::PolicyViolation(
                    "Windows Named Pipe listener is not supported on non-Windows hosts; use Unix socket"
                        .to_owned(),
                ))
            }
        }
        ControlEndpoint::UnixSocket(sock_path) => {
            #[cfg(unix)]
            {
                run_unix_socket_server(sock_path, ready_file, state, shutdown_rx).await
            }
            #[cfg(not(unix))]
            {
                let _ = (sock_path, ready_file, state, shutdown_rx);
                Err(SandboxError::PolicyViolation(
                    "Unix socket control listener is not supported on Windows; use Named Pipe"
                        .to_owned(),
                ))
            }
        }
    }
}

#[cfg(windows)]
async fn run_windows_named_pipe_server(
    pipe_path: &str,
    ready_file: Option<&Path>,
    state: Arc<DaemonState>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<(), SandboxError> {
    use sandbox_vmm::create_owner_only_async_named_pipe;

    let pipe_name = strip_named_pipe_prefix(pipe_path)?;
    let mut server = create_owner_only_async_named_pipe(pipe_name, true)?;

    if let Some(path) = ready_file {
        write_ready_file_atomic(path, pipe_path)?;
    }
    eprintln!("[sandboxd] listening on owner-only Named Pipe {pipe_path}");

    loop {
        let accepted = tokio::select! {
            biased;
            _ = shutdown_rx.wait_for(|done| *done) => break,
            res = server.connect() => res,
        };

        match accepted {
            Ok(()) => {
                // Create the NEXT server pipe instance BEFORE spawning the connection task
                // so clients never observe a gap with zero listening pipe instances.
                let next_server = match create_owner_only_async_named_pipe(pipe_name, false) {
                    Ok(next) => next,
                    Err(err) => {
                        eprintln!(
                            "[sandboxd] failed creating next Named Pipe instance '{pipe_path}': {err}"
                        );
                        let conn_state = Arc::clone(&state);
                        tokio::spawn(async move {
                            if let Err(conn_err) = serve_connection(server, conn_state).await {
                                eprintln!("[sandboxd] control connection error: {conn_err}");
                            }
                        });
                        break;
                    }
                };
                let connected = std::mem::replace(&mut server, next_server);
                let conn_state = Arc::clone(&state);
                tokio::spawn(async move {
                    if let Err(err) = serve_connection(connected, conn_state).await {
                        eprintln!("[sandboxd] control connection error: {err}");
                    }
                });
            }
            Err(err) => {
                eprintln!("[sandboxd] Named Pipe accept error on '{pipe_path}': {err}");
                break;
            }
        }
    }

    Ok(())
}

#[cfg(windows)]
fn strip_named_pipe_prefix(pipe_path: &str) -> Result<&str, SandboxError> {
    const WIN_PREFIX: &str = r"\\.\pipe\";
    if pipe_path.len() > WIN_PREFIX.len()
        && pipe_path[..WIN_PREFIX.len()].eq_ignore_ascii_case(WIN_PREFIX)
    {
        Ok(&pipe_path[WIN_PREFIX.len()..])
    } else {
        Err(SandboxError::InvalidSpec(format!(
            "invalid Windows Named Pipe endpoint '{pipe_path}'"
        )))
    }
}

#[cfg(unix)]
async fn run_unix_socket_server(
    socket_path: &Path,
    ready_file: Option<&Path>,
    state: Arc<DaemonState>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<(), SandboxError> {
    use std::io::ErrorKind;
    use std::os::unix::fs::PermissionsExt;

    use sandbox_vmm::os::unix::ensure_owner_only_dir;
    use sandbox_vmm::validate_socket_path;

    struct SocketCleanup(PathBuf);
    impl Drop for SocketCleanup {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    validate_socket_path(socket_path)?;
    let parent = socket_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .ok_or_else(|| {
            SandboxError::InvalidSpec(format!(
                "Unix socket path '{}' must have a parent directory",
                socket_path.display()
            ))
        })?;

    ensure_owner_only_dir(parent)?;
    remove_stale_socket_if_safe(socket_path, parent)?;

    let listener = tokio::net::UnixListener::bind(socket_path).map_err(|err| {
        SandboxError::Transport(format!(
            "failed to bind Unix socket '{}': {err}",
            socket_path.display()
        ))
    })?;
    let _cleanup = SocketCleanup(socket_path.to_path_buf());

    fs::set_permissions(socket_path, fs::Permissions::from_mode(0o600)).map_err(|err| {
        SandboxError::Transport(format!(
            "failed to enforce 0600 permissions on Unix socket '{}': {err}",
            socket_path.display()
        ))
    })?;

    if let Some(path) = ready_file {
        let uri = format!("unix://{}", socket_path.display());
        write_ready_file_atomic(path, &uri)?;
    }
    eprintln!(
        "[sandboxd] listening on owner-only Unix socket {}",
        socket_path.display()
    );

    loop {
        let accepted = tokio::select! {
            biased;
            _ = shutdown_rx.wait_for(|done| *done) => break,
            res = listener.accept() => res,
        };

        match accepted {
            Ok((stream, _)) => {
                let conn_state = Arc::clone(&state);
                tokio::spawn(async move {
                    if let Err(err) = serve_connection(stream, conn_state).await {
                        eprintln!("[sandboxd] control connection error: {err}");
                    }
                });
            }
            Err(err) => {
                if matches!(
                    err.kind(),
                    ErrorKind::ConnectionAborted
                        | ErrorKind::ConnectionReset
                        | ErrorKind::Interrupted
                ) {
                    continue;
                }
                eprintln!(
                    "[sandboxd] Unix socket accept error on '{}': {err}",
                    socket_path.display()
                );
                break;
            }
        }
    }

    Ok(())
}

#[cfg(unix)]
fn remove_stale_socket_if_safe(socket_path: &Path, verified_parent: &Path) -> Result<(), SandboxError> {
    use std::io::ErrorKind;
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    let meta = match fs::symlink_metadata(socket_path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == ErrorKind::NotFound => return Ok(()),
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

    let parent_meta = fs::symlink_metadata(verified_parent).map_err(|err| {
        SandboxError::Transport(format!(
            "failed to inspect socket parent '{}': {err}",
            verified_parent.display()
        ))
    })?;
    if meta.uid() != parent_meta.uid() {
        return Err(SandboxError::PolicyViolation(format!(
            "refusing to remove stale socket '{}' owned by uid {} (expected {})",
            socket_path.display(),
            meta.uid(),
            parent_meta.uid()
        )));
    }

    if std::os::unix::net::UnixStream::connect(socket_path).is_ok() {
        return Err(SandboxError::Transport(format!(
            "control socket '{}' is already actively in use by another process",
            socket_path.display()
        )));
    }

    fs::remove_file(socket_path).map_err(|err| {
        SandboxError::Transport(format!(
            "failed to remove stale socket '{}': {err}",
            socket_path.display()
        ))
    })
}

fn write_ready_file_atomic(path: &Path, endpoint_uri: &str) -> Result<(), SandboxError> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|err| {
        SandboxError::Transport(format!(
            "failed to create ready-file parent directory '{}': {err}",
            parent.display()
        ))
    })?;

    if let Ok(meta) = fs::symlink_metadata(path) {
        if meta.file_type().is_symlink() {
            return Err(SandboxError::PolicyViolation(format!(
                "refusing symlink ready-file target '{}'",
                path.display()
            )));
        }
    }

    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| {
            SandboxError::InvalidSpec(format!(
                "ready-file '{}' must have a valid UTF-8 file name",
                path.display()
            ))
        })?;
    let tmp_path = parent.join(format!(".{file_name}.tmp.{}", std::process::id()));
    let payload = serde_json::to_vec(&json!({
        "endpoint": endpoint_uri,
        "pid": std::process::id(),
        "version": env!("CARGO_PKG_VERSION"),
    }))
    .map_err(|err| SandboxError::Internal(format!("failed serializing ready-file JSON: {err}")))?;

    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&tmp_path)
        .map_err(|err| {
            SandboxError::Transport(format!(
                "failed to open temporary ready-file '{}': {err}",
                tmp_path.display()
            ))
        })?;
    file.write_all(&payload).map_err(|err| {
        let _ = fs::remove_file(&tmp_path);
        SandboxError::Transport(format!(
            "failed to write temporary ready-file '{}': {err}",
            tmp_path.display()
        ))
    })?;
    file.sync_all().map_err(|err| {
        let _ = fs::remove_file(&tmp_path);
        SandboxError::Transport(format!(
            "failed to sync temporary ready-file '{}': {err}",
            tmp_path.display()
        ))
    })?;
    drop(file);

    fs::rename(&tmp_path, path).map_err(|err| {
        let _ = fs::remove_file(&tmp_path);
        SandboxError::Transport(format!(
            "failed to rename ready-file '{}' -> '{}': {err}",
            tmp_path.display(),
            path.display()
        ))
    })?;
    Ok(())
}

/// Serves a single control transport stream (unary RPC or upgraded `ExecStart` stream).
pub async fn serve_connection<S>(mut stream: S, state: Arc<DaemonState>) -> Result<(), SandboxError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let raw = match read_control_frame(&mut stream).await {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return Ok(()),
        Err(err) => {
            let resp = ControlResponse::Error(WireError::from(err));
            if let Ok(bytes) = resp.to_json_bytes() {
                let _ = write_control_frame(&mut stream, &bytes).await;
            }
            let _ = stream.shutdown().await;
            return Ok(());
        }
    };

    let req = match ControlRequest::from_json_bytes(&raw) {
        Ok(req) => req,
        Err(err) => {
            let resp = ControlResponse::Error(WireError::from(err));
            let bytes = resp.to_json_bytes()?;
            let _ = write_control_frame(&mut stream, &bytes).await;
            let _ = stream.shutdown().await;
            return Ok(());
        }
    };

    if let ControlRequest::ExecStart { id, req } = req {
        return handle_exec_connection(stream, &state, &id, req).await;
    }

    let is_shutdown = matches!(req, ControlRequest::Shutdown);
    let resp = dispatch_unary_request(&state, req).await;
    let bytes = resp.to_json_bytes()?;
    write_control_frame(&mut stream, &bytes).await?;
    let _ = stream.shutdown().await;
    if is_shutdown {
        state.request_shutdown();
    }
    Ok(())
}

async fn dispatch_unary_request(state: &DaemonState, req: ControlRequest) -> ControlResponse {
    match req {
        ControlRequest::Status => ControlResponse::Status(state.status()),
        ControlRequest::Spawn { spec } => match state.runtime.spawn(spec).await {
            Ok(lease) => ControlResponse::Spawned(lease),
            Err(err) => ControlResponse::Error(WireError::from(err)),
        },
        ControlRequest::RenewLease { id, ttl_ms } => {
            match state
                .runtime
                .renew_lease(&id, Duration::from_millis(ttl_ms))
                .await
            {
                Ok(()) => ControlResponse::Ack,
                Err(err) => ControlResponse::Error(WireError::from(err)),
            }
        }
        ControlRequest::CopyInTar {
            id,
            dst_guest,
            tar_bytes,
        } => match state
            .runtime
            .copy_in_tar_bytes(&id, dst_guest, tar_bytes)
            .await
        {
            Ok(()) => ControlResponse::Ack,
            Err(err) => ControlResponse::Error(WireError::from(err)),
        },
        ControlRequest::CopyOutTar { id, src_guest } => {
            match state.runtime.copy_out_tar_bytes(&id, src_guest).await {
                Ok(tar_bytes) => ControlResponse::CopyOutData { tar_bytes },
                Err(err) => ControlResponse::Error(WireError::from(err)),
            }
        }
        ControlRequest::EnableDockerCompat {
            id,
            allow_reaper_socket,
        } => match state.enable_docker_compat(&id, allow_reaper_socket).await {
            Ok(uri) => ControlResponse::DockerCompatEndpoint { uri },
            Err(err) => ControlResponse::Error(WireError::from(err)),
        },
        ControlRequest::Destroy { id } => match state.destroy_sandbox(&id).await {
            Ok(status) => ControlResponse::Destroyed(status),
            Err(err) => ControlResponse::Error(WireError::from(err)),
        },
        ControlRequest::Shutdown => ControlResponse::Ack,
        ControlRequest::ExecStart { .. } => {
            ControlResponse::Error(WireError::from(SandboxError::Internal(
                "ExecStart must be dispatched on streaming connection handler".to_owned(),
            )))
        }
    }
}

async fn handle_exec_connection<S>(
    mut stream: S,
    state: &DaemonState,
    id: &SandboxId,
    req: sandbox_core::ExecRequest,
) -> Result<(), SandboxError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut exec_stream = match state.runtime.exec_stream(id, req).await {
        Ok(s) => s,
        Err(err) => {
            let bytes = ControlResponse::Error(WireError::from(err)).to_json_bytes()?;
            let _ = write_control_frame(&mut stream, &bytes).await;
            let _ = stream.shutdown().await;
            return Ok(());
        }
    };

    let started = ControlResponse::ExecStarted {
        stream_id: exec_stream.stream_id.0,
    }
    .to_json_bytes()?;
    if let Err(err) = write_control_frame(&mut stream, &started).await {
        let _ = exec_stream.cancel();
        return Err(err);
    }

    pump_exec_stream(stream, &mut exec_stream).await
}

async fn pump_exec_stream<S>(
    stream: S,
    exec_stream: &mut ExecStream,
) -> Result<(), SandboxError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    struct AbortOnDrop(JoinHandle<()>);
    impl Drop for AbortOnDrop {
        fn drop(&mut self) {
            self.0.abort();
        }
    }

    let (mut read_half, mut write_half) = tokio::io::split(stream);
    let (client_tx, mut client_rx) =
        mpsc::channel::<Result<ExecWireClientMsg, ()>>(EXEC_CLIENT_MSG_QUEUE_DEPTH);

    // Isolate `read_control_frame` inside a dedicated task so `tokio::select!` only polls
    // cancellation-safe `mpsc::Receiver::recv()` branches.
    let _reader_guard = AbortOnDrop(tokio::spawn(async move {
        loop {
            match read_control_frame(&mut read_half).await {
                Ok(Some(raw)) => match ExecWireClientMsg::from_json_bytes(&raw) {
                    Ok(msg) => {
                        if client_tx.send(Ok(msg)).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => {
                        let _ = client_tx.send(Err(())).await;
                        break;
                    }
                },
                Ok(None) => break,
                Err(_) => {
                    let _ = client_tx.send(Err(())).await;
                    break;
                }
            }
        }
    }));

    let mut client_open = true;
    let mut output_open = true;

    while output_open {
        tokio::select! {
            biased;
            maybe_client = client_rx.recv(), if client_open => {
                match maybe_client {
                    Some(Ok(ExecWireClientMsg::Stdin { data })) => {
                        let _ = exec_stream.write_stdin(data).await;
                    }
                    Some(Ok(ExecWireClientMsg::StdinEof)) => {
                        exec_stream.close_stdin();
                    }
                    Some(Ok(ExecWireClientMsg::Cancel)) => {
                        let _ = exec_stream.cancel();
                    }
                    Some(Err(())) => {
                        let _ = exec_stream.cancel();
                        client_open = false;
                    }
                    None => {
                        exec_stream.close_stdin();
                        client_open = false;
                    }
                }
            }
            maybe_chunk = exec_stream.next_output() => {
                match maybe_chunk {
                    Some(chunk) => {
                        let event = match chunk.stream {
                            OutputStreamKind::Stdout => ExecWireEvent::Stdout { data: chunk.data },
                            OutputStreamKind::Stderr => ExecWireEvent::Stderr { data: chunk.data },
                        };
                        let bytes = event.to_json_bytes()?;
                        if write_control_frame(&mut write_half, &bytes).await.is_err() {
                            let _ = exec_stream.cancel();
                            return Ok(());
                        }
                    }
                    None => {
                        output_open = false;
                    }
                }
            }
        }
    }

    let terminal = match exec_stream.wait_exit().await {
        Ok(status) => ExecWireEvent::Exit(status),
        Err(err) => ExecWireEvent::Error(WireError::from(err)),
    };
    let bytes = terminal.to_json_bytes()?;
    let _ = write_control_frame(&mut write_half, &bytes).await;
    let _ = write_half.shutdown().await;
    Ok(())
}

async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        if let Ok(mut sigterm) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = sigterm.recv() => {}
            }
            return;
        }
    }
    #[cfg(windows)]
    {
        use tokio::signal::windows::{ctrl_break, ctrl_c};
        if let (Ok(mut c), Ok(mut b)) = (ctrl_c(), ctrl_break()) {
            tokio::select! {
                _ = c.recv() => {}
                _ = b.recv() => {}
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Mutex;

    use sandbox_client::{ClientOutputKind, SandboxClient};
    use sandbox_core::{
        AccelerationPolicy, CapabilityReport, EnforcementLevel, ExecExitStatus, ExecRequest,
        ExecTarget, IsolationMode, ResourceBudget, SandboxSpec,
    };
    use sandbox_protocol::{StreamId, StreamTargetWire};
    use sandbox_runtime::{
        AdmissionLimits, DiskOverlayPort, ExecOutputChunk, ExecStream, PreparedOverlay,
        RuntimeManagerConfig, TunnelStream, VmBootConfig, VmBootOutcome, VmRuntimePort,
        VmSessionPort, WarmPoolConfig,
    };
    use tokio::io::duplex;

    static TEST_SEQ: AtomicU64 = AtomicU64::new(0);

    struct TestTempDir(PathBuf);

    impl TestTempDir {
        fn new(label: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "minipod-daemon-test-{label}-{}-{}",
                std::process::id(),
                TEST_SEQ.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&dir).unwrap();
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

    struct StubOverlay;

    #[async_trait::async_trait]
    impl DiskOverlayPort for StubOverlay {
        async fn prepare_overlay(
            &self,
            _sandbox_id: &SandboxId,
            spec: &SandboxSpec,
            work_dir: &Path,
        ) -> Result<PreparedOverlay, SandboxError> {
            let overlay_path = work_dir.join("overlay.qcow2");
            fs::write(&overlay_path, b"qcow2").unwrap();
            Ok(PreparedOverlay {
                overlay_path,
                kernel_path: PathBuf::from("/vmlinuz"),
                initramfs_path: PathBuf::from("/initrd"),
                rootfs_path: PathBuf::from("/rootfs.qcow2"),
                kernel_cmdline: "quiet".to_owned(),
                virtual_disk_mb: spec.budget.virtual_disk_mb,
                provisioned_host_bytes: 5,
            })
        }

        async fn remove_overlay(&self, overlay_path: &Path) -> Result<(), SandboxError> {
            if overlay_path.exists() {
                let _ = fs::remove_file(overlay_path);
            }
            Ok(())
        }
    }

    struct StubSession {
        pid: u32,
        start_token: u64,
        artifacts: Vec<PathBuf>,
        alive: AtomicBool,
        copied_in: Mutex<Option<Vec<u8>>>,
        cancel_seen: Arc<AtomicBool>,
    }

    #[async_trait::async_trait]
    impl VmSessionPort for StubSession {
        fn pid(&self) -> u32 {
            self.pid
        }
        fn start_token(&self) -> u64 {
            self.start_token
        }
        fn artifact_paths(&self) -> &[PathBuf] {
            &self.artifacts
        }
        fn is_alive(&self) -> bool {
            self.alive.load(Ordering::Acquire)
        }
        fn current_rss_bytes(&self) -> Option<u64> {
            Some(64 * 1024 * 1024)
        }

        async fn exec_stream(&self, req: ExecRequest) -> Result<ExecStream, SandboxError> {
            let (stream, mut handle) = ExecStream::channel(StreamId(7));
            let cancel_seen = Arc::clone(&self.cancel_seen);
            tokio::spawn(async move {
                if req.argv.first().map(String::as_str) == Some("sleep") {
                    if handle.recv_cancel().await.is_some() {
                        cancel_seen.store(true, Ordering::Release);
                    }
                    let _ = handle
                        .send_output(ExecOutputChunk {
                            stream: OutputStreamKind::Stderr,
                            data: b"cancelled\n".to_vec(),
                        })
                        .await;
                    handle.finish(Ok(ExecExitStatus {
                        code: None,
                        timed_out: false,
                        stdout_truncated: false,
                        stderr_truncated: false,
                    }));
                    return;
                }

                let mut stdin_buf = Vec::new();
                while let Some(chunk) = handle.recv_stdin().await {
                    stdin_buf.extend_from_slice(&chunk);
                }
                let _ = handle
                    .send_output(ExecOutputChunk {
                        stream: OutputStreamKind::Stdout,
                        data: [b"argv=".as_slice(), req.argv.join(" ").as_bytes(), b";stdin=", &stdin_buf].concat(),
                    })
                    .await;
                let _ = handle
                    .send_output(ExecOutputChunk {
                        stream: OutputStreamKind::Stderr,
                        data: b"err-ok".to_vec(),
                    })
                    .await;
                handle.finish(Ok(ExecExitStatus {
                    code: Some(0),
                    timed_out: false,
                    stdout_truncated: false,
                    stderr_truncated: false,
                }));
            });
            Ok(stream)
        }

        async fn open_tunnel(&self, _target: StreamTargetWire) -> Result<TunnelStream, SandboxError> {
            let (client, _handle) = TunnelStream::channel(StreamId(9));
            Ok(client)
        }

        async fn enable_egress_proxy(
            &self,
            _proxy_port: u16,
        ) -> Result<mpsc::Receiver<TunnelStream>, SandboxError> {
            let (_tx, rx) = mpsc::channel(4);
            Ok(rx)
        }

        async fn copy_in_tar(
            &self,
            _dst_guest: &str,
            tar_bytes: Vec<u8>,
            _max_bytes: u64,
        ) -> Result<u64, SandboxError> {
            let len = tar_bytes.len() as u64;
            *self.copied_in.lock().unwrap() = Some(tar_bytes);
            Ok(len)
        }

        async fn copy_out_tar(
            &self,
            _src_guest: &str,
            _max_bytes: u64,
        ) -> Result<Vec<u8>, SandboxError> {
            Ok(self.copied_in.lock().unwrap().clone().unwrap_or_default())
        }

        async fn graceful_shutdown(&self, _timeout: Duration) -> Result<bool, SandboxError> {
            self.alive.store(false, Ordering::Release);
            Ok(true)
        }

        async fn force_kill(&self) -> Result<(), SandboxError> {
            self.alive.store(false, Ordering::Release);
            Ok(())
        }
    }

    struct StubVmRuntime {
        next_pid: AtomicU64,
        cancel_seen: Arc<AtomicBool>,
    }

    #[async_trait::async_trait]
    impl VmRuntimePort for StubVmRuntime {
        async fn boot_vm(&self, config: VmBootConfig) -> Result<VmBootOutcome, SandboxError> {
            let pid = self.next_pid.fetch_add(1, Ordering::Relaxed) as u32;
            let egress_rx = if config.spec.network == NetworkPolicy::Isolated {
                None
            } else {
                let (_tx, rx) = mpsc::channel(4);
                Some(rx)
            };
            Ok(VmBootOutcome {
                session: Box::new(StubSession {
                    pid,
                    start_token: 1,
                    artifacts: Vec::new(),
                    alive: AtomicBool::new(true),
                    copied_in: Mutex::new(None),
                    cancel_seen: Arc::clone(&self.cancel_seen),
                }),
                pid,
                start_token: 1,
                artifact_paths: Vec::new(),
                hardware_accelerated: true,
                capabilities: CapabilityReport {
                    cpu_quota: EnforcementLevel::HardLimit,
                    host_rss: EnforcementLevel::BestEffort,
                    host_storage: EnforcementLevel::HardLimit,
                    egress_filter: EnforcementLevel::HardLimit,
                },
                egress_rx,
            })
        }

        async fn kill_orphan_process(
            &self,
            _pid: u32,
            _expected_start_token: u64,
        ) -> Result<bool, SandboxError> {
            Ok(false)
        }
    }

    fn build_test_state(tmp: &TestTempDir) -> (Arc<DaemonState>, Arc<AtomicBool>) {
        let cancel_seen = Arc::new(AtomicBool::new(false));
        let rt_cfg = RuntimeManagerConfig {
            state_dir: tmp.path().join("state"),
            sweep_interval: Duration::from_secs(10),
            graceful_shutdown_timeout: Duration::from_millis(50),
            max_copy_bytes: 8 * 1024 * 1024,
            max_copy_entries: 1024,
            cleanup_max_attempts: 3,
            cleanup_initial_delay: Duration::from_millis(5),
            admission: AdmissionLimits::default(),
            warm_pool: WarmPoolConfig::default(),
        };
        let runtime = Arc::new(
            LocalRuntimeManager::new(
                rt_cfg,
                Arc::new(StubOverlay),
                Arc::new(StubVmRuntime {
                    next_pid: AtomicU64::new(100),
                    cancel_seen: Arc::clone(&cancel_seen),
                }),
            )
            .unwrap(),
        );
        (Arc::new(DaemonState::new(runtime)), cancel_seen)
    }

    fn test_client(state: Arc<DaemonState>) -> SandboxClient {
        let ep = if cfg!(windows) {
            ControlEndpoint::NamedPipe(r"\\.\pipe\test-duplex".to_owned())
        } else {
            ControlEndpoint::UnixSocket(PathBuf::from("/tmp/test-duplex.sock"))
        };
        SandboxClient::with_connector(ep, move |_| {
            let state = Arc::clone(&state);
            async move {
                let (client_end, server_end) = duplex(1024 * 1024);
                tokio::spawn(async move {
                    let _ = serve_connection(server_end, state).await;
                });
                Ok(client_end)
            }
        })
    }

    fn sample_spec(network: NetworkPolicy) -> SandboxSpec {
        SandboxSpec {
            isolation: IsolationMode::VmRequired,
            acceleration: AccelerationPolicy::Preferred,
            network,
            budget: ResourceBudget {
                guest_vcpus: 1,
                host_cpu_quota_Millicores: None,
                guest_ram_mb: 256,
                host_rss_budget_mb: Some(512),
                virtual_disk_mb: 256,
                host_storage_budget_mb: 512,
            },
            lease_ttl: Duration::from_secs(60),
        }
    }

    #[tokio::test]
    async fn serve_connection_roundtrips_status_spawn_exec_cancel_docker_and_destroy() {
        let tmp = TestTempDir::new("rpc");
        let (state, cancel_seen) = build_test_state(&tmp);
        let client = test_client(Arc::clone(&state));

        let status0 = client.status().await.unwrap();
        assert_eq!(status0.active_sandboxes, 0);

        let lease = client
            .spawn(sample_spec(NetworkPolicy::InternetOnly))
            .await
            .unwrap();
        let status1 = client.status().await.unwrap();
        assert_eq!(status1.active_sandboxes, 1);

        client
            .renew_lease(&lease.id, Duration::from_secs(120))
            .await
            .unwrap();

        // Streaming exec with stdin + stdout + stderr.
        let exec = client
            .exec_stream(
                &lease.id,
                ExecRequest {
                    target: ExecTarget::Guest,
                    argv: vec!["cat".to_owned()],
                    env: BTreeMap::new(),
                    cwd: None,
                    user: None,
                    deadline: Duration::from_secs(10),
                    stdout_budget_bytes: 64 * 1024,
                    stderr_budget_bytes: 64 * 1024,
                },
            )
            .await
            .unwrap();
        exec.write_stdin(b"hello-wire".to_vec()).await.unwrap();
        let out = exec.collect().await.unwrap();
        assert_eq!(out.exit.code, Some(0));
        assert_eq!(out.stdout, b"argv=cat;stdin=hello-wire");
        assert_eq!(out.stderr, b"err-ok");

        // Streaming exec cancellation propagates to VmSessionPort.
        let mut sleep_exec = client
            .exec_stream(
                &lease.id,
                ExecRequest {
                    target: ExecTarget::Guest,
                    argv: vec!["sleep".to_owned(), "60".to_owned()],
                    env: BTreeMap::new(),
                    cwd: None,
                    user: None,
                    deadline: Duration::from_secs(10),
                    stdout_budget_bytes: 64 * 1024,
                    stderr_budget_bytes: 64 * 1024,
                },
            )
            .await
            .unwrap();
        sleep_exec.cancel().unwrap();
        let first_chunk = sleep_exec.next_output().await.unwrap();
        assert_eq!(first_chunk.stream, ClientOutputKind::Stderr);
        assert_eq!(first_chunk.data, b"cancelled\n");
        let sleep_exit = sleep_exec.wait_exit().await.unwrap();
        assert_eq!(sleep_exit.code, None);
        assert!(cancel_seen.load(Ordering::Acquire));

        // Copy-in and copy-out via tar bytes.
        let src_dir = tmp.path().join("upload");
        fs::create_dir_all(&src_dir).unwrap();
        fs::write(src_dir.join("data.txt"), b"payload-123").unwrap();
        client
            .copy_in_path(&lease.id, &src_dir, "/workspace")
            .await
            .unwrap();
        let download_dir = tmp.path().join("download");
        let extracted = client
            .copy_out_to_path(&lease.id, "/workspace", &download_dir)
            .await
            .unwrap();
        assert_eq!(extracted, b"payload-123".len() as u64);
        assert_eq!(fs::read(download_dir.join("data.txt")).unwrap(), b"payload-123");

        // EnableDockerCompat binds owner-only IPC endpoint, caches same policy, and cleans up on destroy.
        let docker_uri_1 = client.enable_docker_compat(&lease.id, false).await.unwrap();
        #[cfg(windows)]
        assert!(
            docker_uri_1.starts_with("npipe:////./pipe/minipod-docker-"),
            "unexpected Windows Docker IPC URI: {docker_uri_1}"
        );
        #[cfg(unix)]
        assert!(
            docker_uri_1.starts_with("unix:///"),
            "unexpected Unix Docker IPC URI: {docker_uri_1}"
        );
        let docker_uri_2 = client.enable_docker_compat(&lease.id, false).await.unwrap();
        assert_eq!(docker_uri_1, docker_uri_2);
        {
            let map = state.docker_compat.lock().unwrap();
            let entry = map.get(&lease.id).unwrap();
            assert_eq!(entry.proxy_url.as_deref(), Some(CONTAINER_EGRESS_PROXY_URL));
        }

        // Isolated sandbox must configure container_proxy_http_url = None.
        let iso_lease = client
            .spawn(sample_spec(NetworkPolicy::Isolated))
            .await
            .unwrap();
        let _iso_uri = client.enable_docker_compat(&iso_lease.id, true).await.unwrap();
        {
            let map = state.docker_compat.lock().unwrap();
            assert_eq!(map.get(&iso_lease.id).unwrap().proxy_url, None);
        }
        client.destroy(&iso_lease.id).await.unwrap();

        let destroyed = client.destroy(&lease.id).await.unwrap();
        assert_eq!(destroyed, DestroyStatus::AllResourcesCleaned);
        {
            let map = state.docker_compat.lock().unwrap();
            assert!(!map.contains_key(&lease.id));
        }

        // Enabling DockerCompat on destroyed sandbox must fail with NotFound.
        assert!(matches!(
            client.enable_docker_compat(&lease.id, false).await,
            Err(SandboxError::NotFound(_))
        ));

        // TTL expiry via RuntimeManager::destroy must also evict cached Docker compat listeners (#16).
        let mut short_spec = sample_spec(NetworkPolicy::Isolated);
        short_spec.lease_ttl = Duration::from_millis(30);
        let ttl_lease = client.spawn(short_spec).await.unwrap();
        let _ttl_docker_uri = client.enable_docker_compat(&ttl_lease.id, false).await.unwrap();
        assert!(state.docker_compat.lock().unwrap().contains_key(&ttl_lease.id));
        tokio::time::sleep(Duration::from_millis(60)).await;
        // Direct runtime.destroy (the same path invoked by the TTL sweeper) must trigger listener cleanup.
        state.runtime.destroy(&ttl_lease.id).await.unwrap();
        assert!(!state.docker_compat.lock().unwrap().contains_key(&ttl_lease.id));
    }

    #[tokio::test]
    async fn os_local_ipc_listener_serves_multiple_requests_and_writes_ready_file() {
        let tmp = TestTempDir::new("os-ipc");
        let (state, _) = build_test_state(&tmp);
        let ready_file = tmp.path().join("ready.json");
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        #[cfg(windows)]
        let (endpoint, server_task) = {
            let pipe_path = format!(
                r"\\.\pipe\minipod-daemon-test-{}-{}",
                std::process::id(),
                TEST_SEQ.fetch_add(1, Ordering::Relaxed)
            );
            let ep = ControlEndpoint::NamedPipe(pipe_path.clone());
            let srv_state = Arc::clone(&state);
            let ready = ready_file.clone();
            let task = tokio::spawn(async move {
                run_windows_named_pipe_server(&pipe_path, Some(&ready), srv_state, shutdown_rx)
                    .await
            });
            (ep, task)
        };

        #[cfg(unix)]
        let (endpoint, server_task) = {
            let sock_dir = tmp.path().join("sockdir");
            let sock_path = sock_dir.join("ctl.sock");
            let ep = ControlEndpoint::UnixSocket(sock_path.clone());
            let srv_state = Arc::clone(&state);
            let ready = ready_file.clone();
            let task = tokio::spawn(async move {
                run_unix_socket_server(&sock_path, Some(&ready), srv_state, shutdown_rx).await
            });
            (ep, task)
        };

        for _ in 0..100 {
            if ready_file.is_file() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(ready_file.is_file(), "ready-file must be created atomically");
        let ready_json: serde_json::Value =
            serde_json::from_slice(&fs::read(&ready_file).unwrap()).unwrap();
        assert!(ready_json["endpoint"].as_str().is_some());

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let ControlEndpoint::UnixSocket(ref sock_path) = endpoint else {
                unreachable!()
            };
            let dir_mode = fs::symlink_metadata(sock_path.parent().unwrap())
                .unwrap()
                .mode()
                & 0o777;
            let sock_mode = fs::symlink_metadata(sock_path).unwrap().mode() & 0o777;
            assert_eq!(dir_mode, 0o700);
            assert_eq!(sock_mode, 0o600);
        }

        let client = SandboxClient::new(endpoint);
        let (s1, s2, s3) = tokio::join!(client.status(), client.status(), client.status());
        assert_eq!(s1.unwrap().active_sandboxes, 0);
        assert_eq!(s2.unwrap().active_sandboxes, 0);
        assert_eq!(s3.unwrap().active_sandboxes, 0);

        let _ = shutdown_tx.send(true);
        server_task.await.unwrap().unwrap();
    }
}
