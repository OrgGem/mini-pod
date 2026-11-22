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
    DaemonStatusInfo, ExecWireClientMsg, ExecWireEvent, SandboxSummaryInfo, WireError,
    MAX_CONTROL_FRAME_BYTES,
};
use sandbox_core::safe_tar::{apply_open_no_follow, ensure_safe_dir_path, reject_symlink_or_reparse};
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
use tokio::sync::{mpsc, watch, Semaphore};
use tokio::task::JoinHandle;

use crate::config::ServeConfig;
use crate::doctor::{self, DoctorInputs};
use crate::spawn_registry::SpawnRegistry;

const CONTAINER_EGRESS_PROXY_URL: &str = "http://10.88.0.1:3128";
const EXEC_CLIENT_MSG_QUEUE_DEPTH: usize = 32;
// shortcut: fixed 256 concurrent control connections and 30s unary frame I/O timeout, expose ServeConfig knobs if multi-agent daemon load exceeds 256 concurrent streams
const MAX_CONCURRENT_CONTROL_CONNECTIONS: usize = 256;
const CONTROL_REQUEST_IO_TIMEOUT: Duration = Duration::from_secs(30);
const ACCEPT_RETRY_BACKOFF: Duration = Duration::from_millis(25);

static NEXT_DOCKER_COMPAT_SEQ: AtomicU64 = AtomicU64::new(1);
static NEXT_READY_TMP_SEQ: AtomicU64 = AtomicU64::new(1);

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
    spawn_registry: SpawnRegistry,
    docker_compat: Arc<Mutex<HashMap<SandboxId, CachedDockerCompat>>>,
    docker_compat_locks: Arc<Mutex<HashMap<SandboxId, Arc<tokio::sync::Mutex<()>>>>>,
    shutdown_tx: Option<watch::Sender<bool>>,
    doctor_inputs: Option<DoctorInputs>,
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
        let docker_compat_locks = Arc::new(Mutex::new(HashMap::<
            SandboxId,
            Arc<tokio::sync::Mutex<()>>,
        >::new()));
        let listener_map = Arc::clone(&docker_compat);
        let lock_map = Arc::clone(&docker_compat_locks);
        runtime.register_destroy_listener(move |sandbox_id| {
            let removed = listener_map
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(sandbox_id);
            lock_map
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
            spawn_registry: SpawnRegistry::new(Arc::clone(&runtime)),
            runtime,
            docker_compat,
            docker_compat_locks,
            shutdown_tx,
            doctor_inputs: None,
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

    /// Returns a live snapshot of all active sandboxes enriched with any bound Docker compat URI.
    pub fn list_sandboxes(&self) -> Vec<SandboxSummaryInfo> {
        let active = self.runtime.list_active_sandboxes();
        let docker_snapshot: HashMap<SandboxId, (String, bool)> = {
            let map = self
                .docker_compat
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            map.iter()
                .map(|(id, entry)| (id.clone(), (entry.uri.clone(), entry.allow_reaper_socket)))
                .collect()
        };

        active
            .into_iter()
            .map(|entry| {
                let (docker_endpoint, allow_reaper_socket) = docker_snapshot
                    .get(&entry.id)
                    .map(|(uri, reaper)| (Some(uri.clone()), *reaper))
                    .unwrap_or((None, false));
                SandboxSummaryInfo {
                    id: entry.id,
                    pid: entry.pid,
                    alive: entry.alive,
                    network: entry.network,
                    remaining_ttl_ms: entry.remaining_ttl_ms,
                    live_rss_bytes: entry.live_rss_bytes,
                    reserved_rss_mb: entry.reserved_rss_mb,
                    host_rss_budget_mb: entry.host_rss_budget_mb,
                    host_storage_budget_mb: entry.host_storage_budget_mb,
                    docker_endpoint,
                    allow_reaper_socket,
                }
            })
            .collect()
    }

    /// Lazily binds (or returns the cached) owner-only local IPC Docker compatibility listener
    /// (`npipe://` with owner-only DACL on Windows; `unix://` `0600` in `0700` dir on Unix).
    pub async fn enable_docker_compat(
        &self,
        id: &SandboxId,
        allow_reaper_socket: bool,
    ) -> Result<String, SandboxError> {
        let _network_initial = self.runtime.active_sandbox_network(id)?;
        let per_sandbox_lock = {
            let mut locks = self
                .docker_compat_locks
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            Arc::clone(
                locks
                    .entry(id.clone())
                    .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(()))),
            )
        };
        let _enable_guard = per_sandbox_lock.lock().await;
        let network = self.runtime.active_sandbox_network(id)?;
        let reaper_socket = if allow_reaper_socket {
            ReaperSocketPolicy::MapGuestPodmanSocket
        } else {
            ReaperSocketPolicy::Deny
        };

        {
            let mut map = self
                .docker_compat
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if let Some(existing) = map.get_mut(id) {
                existing.allow_reaper_socket = allow_reaper_socket;
                existing.compat.set_reaper_socket_policy(reaper_socket);
                return Ok(existing.uri.clone());
            }
        }

        let container_proxy_http_url = match network {
            NetworkPolicy::Isolated => None,
            NetworkPolicy::InternetOnly
            | NetworkPolicy::DomainAllowList { .. }
            | NetworkPolicy::Unrestricted => Some(CONTAINER_EGRESS_PROXY_URL.to_owned()),
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

        // Re-check liveness AFTER publishing into `docker_compat` (paired with `destroy` removing
        // from `active` BEFORE `notify_destroy_listeners`) so concurrent destroy never leaks an entry.
        if let Err(err) = self.runtime.active_sandbox_network(id) {
            let raced = self
                .docker_compat
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(id);
            if let Some(leaked) = raced {
                leaked.shutdown().await;
            }
            return Err(err);
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
    Ok(build_runtime_with_doctor(cfg).await?.0)
}

async fn build_runtime_with_doctor(
    cfg: &ServeConfig,
) -> Result<(Arc<LocalRuntimeManager>, DoctorInputs), SandboxError> {
    let verifier = cfg.pub_key.load_verifier()?;
    let bundle_dir = cfg.bundle_dir.clone();
    let verifier_for_check = verifier.clone();
    let installed = tokio::task::spawn_blocking(move || {
        verify_installed_bundle(&bundle_dir, &verifier_for_check)
    })
    .await
    .map_err(|err| SandboxError::Internal(format!("bundle verification task failed: {err}")))??;
    installed
        .manifest()
        .ensure_compatible_host_os(std::env::consts::OS)?;
    if installed.manifest().guest_arch != cfg.arch {
        return Err(SandboxError::InvalidSpec(format!(
            "installed bundle guest_arch '{}' differs from configured daemon arch '{}'",
            installed.manifest().guest_arch,
            cfg.arch
        )));
    }

    let qemu_img_bin = discover_qemu_img_binary(cfg.qemu_img_bin.as_deref())?;
    let qemu_bin = discover_qemu_binary_for_arch(cfg.arch, cfg.qemu_bin.as_deref())?;
    let doctor_inputs = DoctorInputs {
        bundle_dir: cfg.bundle_dir.clone(),
        verifier: verifier.clone(),
        qemu_bin: qemu_bin.clone(),
        qemu_img_bin: qemu_img_bin.clone(),
        arch: cfg.arch,
    };

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

    Ok((runtime, doctor_inputs))
}

/// Runs the local owner-only control daemon until SIGINT (`Ctrl-C`), `SIGTERM`, or `ControlRequest::Shutdown`.
pub async fn run_serve(cfg: ServeConfig) -> Result<(), SandboxError> {
    cfg.endpoint.validate()?;

    let (runtime, doctor_inputs) = build_runtime_with_doctor(&cfg).await?;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut daemon = DaemonState::with_shutdown(runtime, shutdown_tx.clone());
    daemon.doctor_inputs = Some(doctor_inputs);
    let state = Arc::new(daemon);

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
    shutdown_rx: watch::Receiver<bool>,
) -> Result<(), SandboxError> {
    run_windows_named_pipe_server_with_factory(
        pipe_path,
        ready_file,
        state,
        shutdown_rx,
        sandbox_vmm::create_owner_only_async_named_pipe,
    )
    .await
}

#[cfg(windows)]
async fn run_windows_named_pipe_server_with_factory<F>(
    pipe_path: &str,
    ready_file: Option<&Path>,
    state: Arc<DaemonState>,
    mut shutdown_rx: watch::Receiver<bool>,
    mut create_pipe: F,
) -> Result<(), SandboxError>
where
    F: FnMut(
        &str,
        bool,
    ) -> Result<tokio::net::windows::named_pipe::NamedPipeServer, SandboxError>,
{
    let pipe_name = strip_named_pipe_prefix(pipe_path)?;
    let mut server = create_pipe(pipe_name, true)?;
    let conn_sem = Arc::new(Semaphore::new(MAX_CONCURRENT_CONTROL_CONNECTIONS));

    if let Some(path) = ready_file {
        write_ready_file_atomic(path, pipe_path)?;
    }
    eprintln!("[sandboxd] listening on owner-only Named Pipe {pipe_path}");

    loop {
        let permit = tokio::select! {
            biased;
            _ = shutdown_rx.wait_for(|done| *done) => break,
            res = Arc::clone(&conn_sem).acquire_owned() => match res {
                Ok(p) => p,
                Err(_) => break,
            },
        };

        let accepted = tokio::select! {
            biased;
            _ = shutdown_rx.wait_for(|done| *done) => break,
            res = server.connect() => res,
        };

        match accepted {
            Ok(()) => {
                // Create the NEXT server pipe instance BEFORE spawning the connection task
                // so clients never observe a gap with zero listening pipe instances.
                match create_pipe(pipe_name, false) {
                    Ok(next_server) => {
                        let connected = std::mem::replace(&mut server, next_server);
                        let conn_state = Arc::clone(&state);
                        tokio::spawn(async move {
                            let _permit = permit;
                            if let Err(err) = serve_connection(connected, conn_state).await {
                                eprintln!("[sandboxd] control connection error: {err}");
                            }
                        });
                    }
                    Err(err) => {
                        eprintln!(
                            "[sandboxd] transient failure creating next Named Pipe instance '{pipe_path}' (preserving active VMs): {err}"
                        );
                        let connected = server;
                        let conn_state = Arc::clone(&state);
                        tokio::spawn(async move {
                            let _permit = permit;
                            if let Err(conn_err) = serve_connection(connected, conn_state).await {
                                eprintln!("[sandboxd] control connection error: {conn_err}");
                            }
                        });
                        let Some(recovered) =
                            reopen_named_pipe_with_backoff(pipe_name, pipe_path, &mut create_pipe, &mut shutdown_rx).await
                        else {
                            break;
                        };
                        server = recovered;
                    }
                }
            }
            Err(err) => {
                drop(permit);
                eprintln!(
                    "[sandboxd] transient Named Pipe accept error on '{pipe_path}' (preserving active VMs): {err}"
                );
                // Create replacement while holding `server` open so instance count never hits 0.
                match create_pipe(pipe_name, false) {
                    Ok(next_server) => {
                        server = next_server;
                    }
                    Err(open_err) => {
                        eprintln!(
                            "[sandboxd] transient failure replacing Named Pipe instance '{pipe_path}': {open_err}"
                        );
                        drop(server);
                        let Some(recovered) =
                            reopen_named_pipe_with_backoff(pipe_name, pipe_path, &mut create_pipe, &mut shutdown_rx).await
                        else {
                            break;
                        };
                        server = recovered;
                    }
                }
            }
        }
    }

    Ok(())
}

#[cfg(windows)]
async fn reopen_named_pipe_with_backoff<F>(
    pipe_name: &str,
    pipe_path: &str,
    create_pipe: &mut F,
    shutdown_rx: &mut watch::Receiver<bool>,
) -> Option<tokio::net::windows::named_pipe::NamedPipeServer>
where
    F: FnMut(
        &str,
        bool,
    ) -> Result<tokio::net::windows::named_pipe::NamedPipeServer, SandboxError>,
{
    let mut delay = ACCEPT_RETRY_BACKOFF;
    loop {
        tokio::select! {
            biased;
            _ = shutdown_rx.wait_for(|done| *done) => return None,
            _ = tokio::time::sleep(delay) => {}
        }
        if let Ok(next) = create_pipe(pipe_name, false).or_else(|_| create_pipe(pipe_name, true)) {
            return Some(next);
        }
        eprintln!("[sandboxd] retrying Named Pipe listener creation for '{pipe_path}'...");
        delay = (delay * 2).min(Duration::from_millis(250));
    }
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

    let conn_sem = Arc::new(Semaphore::new(MAX_CONCURRENT_CONTROL_CONNECTIONS));

    loop {
        let permit = tokio::select! {
            biased;
            _ = shutdown_rx.wait_for(|done| *done) => break,
            res = Arc::clone(&conn_sem).acquire_owned() => match res {
                Ok(p) => p,
                Err(_) => break,
            },
        };

        let accepted = tokio::select! {
            biased;
            _ = shutdown_rx.wait_for(|done| *done) => break,
            res = listener.accept() => res,
        };

        match accepted {
            Ok((stream, _)) => {
                let conn_state = Arc::clone(&state);
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Err(err) = serve_connection(stream, conn_state).await {
                        eprintln!("[sandboxd] control connection error: {err}");
                    }
                });
            }
            Err(err) => {
                drop(permit);
                if matches!(
                    err.kind(),
                    ErrorKind::ConnectionAborted
                        | ErrorKind::ConnectionReset
                        | ErrorKind::Interrupted
                ) {
                    continue;
                }
                eprintln!(
                    "[sandboxd] transient Unix socket accept error on '{}' (preserving active VMs): {err}",
                    socket_path.display()
                );
                tokio::select! {
                    biased;
                    _ = shutdown_rx.wait_for(|done| *done) => break,
                    _ = tokio::time::sleep(ACCEPT_RETRY_BACKOFF) => {}
                }
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
    struct TempFileGuard(Option<std::path::PathBuf>);
    impl TempFileGuard {
        fn disarm(&mut self) {
            self.0 = None;
        }
    }
    impl Drop for TempFileGuard {
        fn drop(&mut self) {
            if let Some(p) = &self.0 {
                let _ = fs::remove_file(p);
            }
        }
    }

    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    ensure_safe_dir_path(parent, true)?;

    if let Ok(meta) = fs::symlink_metadata(path) {
        reject_symlink_or_reparse(path, &meta)?;
        if meta.is_dir() {
            return Err(SandboxError::PolicyViolation(format!(
                "ready-file '{}' must not be a directory",
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
    let seq = NEXT_READY_TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let tmp_path = parent.join(format!(".{file_name}.tmp.{}.{seq}", std::process::id()));
    let mut guard = TempFileGuard(Some(tmp_path.clone()));

    let payload = serde_json::to_vec(&json!({
        "endpoint": endpoint_uri,
        "pid": std::process::id(),
        "version": env!("CARGO_PKG_VERSION"),
    }))
    .map_err(|err| SandboxError::Internal(format!("failed serializing ready-file JSON: {err}")))?;

    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    apply_open_no_follow(&mut opts);
    let mut file = opts.open(&tmp_path).map_err(|err| {
        SandboxError::Transport(format!(
            "failed to open temporary ready-file '{}': {err}",
            tmp_path.display()
        ))
    })?;
    let open_meta = file.metadata().map_err(|err| {
        SandboxError::Transport(format!(
            "failed to inspect temporary ready-file '{}': {err}",
            tmp_path.display()
        ))
    })?;
    reject_symlink_or_reparse(&tmp_path, &open_meta)?;
    file.write_all(&payload).map_err(|err| {
        SandboxError::Transport(format!(
            "failed to write temporary ready-file '{}': {err}",
            tmp_path.display()
        ))
    })?;
    file.sync_all().map_err(|err| {
        SandboxError::Transport(format!(
            "failed to sync temporary ready-file '{}': {err}",
            tmp_path.display()
        ))
    })?;
    drop(file);

    if let Ok(meta) = fs::symlink_metadata(path) {
        reject_symlink_or_reparse(path, &meta)?;
        if meta.is_dir() {
            return Err(SandboxError::PolicyViolation(format!(
                "ready-file '{}' must not be a directory",
                path.display()
            )));
        }
    }

    fs::rename(&tmp_path, path).map_err(|err| {
        SandboxError::Transport(format!(
            "failed to rename ready-file '{}' -> '{}': {err}",
            tmp_path.display(),
            path.display()
        ))
    })?;
    guard.disarm();
    Ok(())
}

/// Serves a single control transport stream (unary RPC or upgraded `ExecStart` stream).
pub async fn serve_connection<S>(stream: S, state: Arc<DaemonState>) -> Result<(), SandboxError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    serve_connection_with_timeout(stream, state, CONTROL_REQUEST_IO_TIMEOUT).await
}

async fn serve_connection_with_timeout<S>(
    mut stream: S,
    state: Arc<DaemonState>,
    io_timeout: Duration,
) -> Result<(), SandboxError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let frame_res = match tokio::time::timeout(io_timeout, read_control_frame(&mut stream)).await {
        Ok(res) => res,
        Err(_) => Err(SandboxError::Transport(format!(
            "timed out after {} ms waiting for initial control frame",
            io_timeout.as_millis()
        ))),
    };
    let raw = match frame_res {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return Ok(()),
        Err(err) => {
            let resp = ControlResponse::Error(WireError::from(err));
            if let Ok(bytes) = resp.to_json_bytes() {
                let _ = tokio::time::timeout(
                    io_timeout,
                    write_control_frame(&mut stream, &bytes),
                )
                .await;
            }
            let _ = tokio::time::timeout(io_timeout, stream.shutdown()).await;
            return Ok(());
        }
    };

    let req = match ControlRequest::from_json_bytes(&raw) {
        Ok(req) => req,
        Err(err) => {
            let resp = ControlResponse::Error(WireError::from(err));
            let bytes = resp.to_json_bytes()?;
            let _ = tokio::time::timeout(
                io_timeout,
                write_control_frame(&mut stream, &bytes),
            )
            .await;
            let _ = tokio::time::timeout(io_timeout, stream.shutdown()).await;
            return Ok(());
        }
    };

    if let ControlRequest::ExecStart { id, req } = req {
        return handle_exec_connection(stream, &state, &id, req, io_timeout).await;
    }

    let is_shutdown = matches!(req, ControlRequest::Shutdown);
    let spawned_unkeyed = matches!(req, ControlRequest::Spawn { .. });
    let resp = dispatch_unary_request(&state, req).await;
    let unkeyed_spawned_id = match &resp {
        ControlResponse::Spawned(lease) if spawned_unkeyed => Some(lease.id.clone()),
        _ => None,
    };
    let frame_bytes = match resp.to_json_bytes() {
        Ok(bytes) if bytes.len() <= MAX_CONTROL_FRAME_BYTES => bytes,
        Ok(bytes) => {
            if let Some(id) = unkeyed_spawned_id.as_ref() {
                let _ = state.destroy_sandbox(id).await;
            }
            ControlResponse::Error(WireError::from(SandboxError::BudgetExceeded(format!(
                "control response frame {} bytes exceeds MAX_CONTROL_FRAME_BYTES ({MAX_CONTROL_FRAME_BYTES})",
                bytes.len()
            ))))
            .to_json_bytes()?
        }
        Err(err) => {
            if let Some(id) = unkeyed_spawned_id.as_ref() {
                let _ = state.destroy_sandbox(id).await;
            }
            ControlResponse::Error(WireError::from(err)).to_json_bytes()?
        }
    };
    let send_res: Result<(), SandboxError> = async {
        tokio::time::timeout(io_timeout, write_control_frame(&mut stream, &frame_bytes))
            .await
            .map_err(|_| {
                SandboxError::Transport(format!(
                    "timed out after {} ms writing control response",
                    io_timeout.as_millis()
                ))
            })??;
        Ok(())
    }
    .await;
    if let Err(err) = send_res {
        if let Some(id) = unkeyed_spawned_id {
            let _ = state.destroy_sandbox(&id).await;
        }
        return Err(err);
    }
    let _ = tokio::time::timeout(io_timeout, stream.shutdown()).await;
    if is_shutdown {
        state.request_shutdown();
    }
    Ok(())
}

async fn dispatch_unary_request(state: &DaemonState, req: ControlRequest) -> ControlResponse {
    match req {
        ControlRequest::Status => ControlResponse::Status(state.status()),
        ControlRequest::Doctor => {
            let Some(inputs) = state.doctor_inputs.clone() else {
                return ControlResponse::Doctor {
                    report: doctor::unknown(),
                };
            };
            match tokio::task::spawn_blocking(move || inputs.collect()).await {
                Ok(report) => ControlResponse::Doctor { report },
                Err(error) => ControlResponse::Error(WireError::from(SandboxError::Internal(
                    format!("doctor task failed: {error}"),
                ))),
            }
        }
        ControlRequest::GetAccelerator { id } => match state.runtime.sandbox_accelerator(&id) {
            Ok(name) => ControlResponse::Accelerator {
                name: name.map(str::to_owned),
            },
            Err(error) => ControlResponse::Error(WireError::from(error)),
        },
        ControlRequest::ListSandboxes => ControlResponse::SandboxList {
            sandboxes: state.list_sandboxes(),
        },
        ControlRequest::Spawn { spec } => match state.runtime.spawn(spec).await {
            Ok(lease) => ControlResponse::Spawned(lease),
            Err(err) => ControlResponse::Error(WireError::from(err)),
        },
        ControlRequest::SpawnKeyed { operation_id, spec } => match state.spawn_registry.spawn(operation_id, spec).await {
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
    io_timeout: Duration,
) -> Result<(), SandboxError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut exec_stream = match state.runtime.exec_stream(id, req).await {
        Ok(s) => s,
        Err(err) => {
            let bytes = ControlResponse::Error(WireError::from(err)).to_json_bytes()?;
            let _ = tokio::time::timeout(io_timeout, write_control_frame(&mut stream, &bytes)).await;
            let _ = tokio::time::timeout(io_timeout, stream.shutdown()).await;
            return Ok(());
        }
    };

    let started = ControlResponse::ExecStarted {
        stream_id: exec_stream.stream_id.0,
    }
    .to_json_bytes()?;
    match tokio::time::timeout(io_timeout, write_control_frame(&mut stream, &started)).await {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            let _ = exec_stream.cancel();
            return Err(err);
        }
        Err(_) => {
            let _ = exec_stream.cancel();
            return Err(SandboxError::Transport(format!(
                "timed out after {} ms writing ExecStarted response",
                io_timeout.as_millis()
            )));
        }
    }

    pump_exec_stream(stream, &mut exec_stream, io_timeout).await
}

async fn pump_exec_stream<S>(
    stream: S,
    exec_stream: &mut ExecStream,
    io_timeout: Duration,
) -> Result<(), SandboxError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    enum ExecClientCtrl {
        Cancel,
        Disconnected,
    }

    struct AbortOnDrop(JoinHandle<()>);
    impl Drop for AbortOnDrop {
        fn drop(&mut self) {
            self.0.abort();
        }
    }

    let (mut read_half, mut write_half) = tokio::io::split(stream);
    let mut stdin_writer = exec_stream.take_stdin_writer();
    let (stdin_tx, mut stdin_rx) =
        mpsc::channel::<Option<Vec<u8>>>(EXEC_CLIENT_MSG_QUEUE_DEPTH);
    let (ctrl_tx, mut ctrl_rx) =
        mpsc::channel::<ExecClientCtrl>(EXEC_CLIENT_MSG_QUEUE_DEPTH);

    let mut stdin_guard = Some(AbortOnDrop(tokio::spawn(async move {
        while let Some(item) = stdin_rx.recv().await {
            match item {
                Some(data) => {
                    if stdin_writer.write(data).await.is_err() {
                        stdin_writer.close();
                        break;
                    }
                }
                None => {
                    stdin_writer.close();
                    break;
                }
            }
        }
        stdin_writer.close();
    })));

    // Isolate `read_control_frame` and `stdin` writes inside dedicated tasks so blocked guest stdin
    // never starves cancellation, output draining, or host deadline enforcement.
    let _reader_guard = AbortOnDrop(tokio::spawn(async move {
        loop {
            match read_control_frame(&mut read_half).await {
                Ok(Some(raw)) => match ExecWireClientMsg::from_json_bytes(&raw) {
                    Ok(ExecWireClientMsg::Stdin { data }) => {
                        if stdin_tx.send(Some(data)).await.is_err() {
                            break;
                        }
                    }
                    Ok(ExecWireClientMsg::StdinEof) => {
                        let _ = stdin_tx.send(None).await;
                    }
                    Ok(ExecWireClientMsg::Cancel) | Err(_) => {
                        let _ = ctrl_tx.send(ExecClientCtrl::Cancel).await;
                        break;
                    }
                },
                Ok(None) => {
                    let _ = ctrl_tx.send(ExecClientCtrl::Disconnected).await;
                    break;
                }
                Err(_) => {
                    let _ = ctrl_tx.send(ExecClientCtrl::Cancel).await;
                    break;
                }
            }
        }
    }));

    let mut ctrl_open = true;
    let mut output_open = true;

    while output_open {
        tokio::select! {
            biased;
            maybe_ctrl = ctrl_rx.recv(), if ctrl_open => {
                match maybe_ctrl {
                    Some(ExecClientCtrl::Cancel) | Some(ExecClientCtrl::Disconnected) | None => {
                        drop(stdin_guard.take());
                        let _ = exec_stream.cancel();
                        ctrl_open = false;
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
                        match tokio::time::timeout(
                            io_timeout,
                            write_control_frame(&mut write_half, &bytes),
                        )
                        .await
                        {
                            Ok(Ok(())) => {}
                            Ok(Err(_)) | Err(_) => {
                                drop(stdin_guard.take());
                                let _ = exec_stream.cancel();
                                return Ok(());
                            }
                        }
                    }
                    None => {
                        output_open = false;
                    }
                }
            }
        }
    }

    drop(stdin_guard.take());
    let terminal = match exec_stream.wait_exit().await {
        Ok(status) => ExecWireEvent::Exit(status),
        Err(err) => ExecWireEvent::Error(WireError::from(err)),
    };
    let bytes = terminal.to_json_bytes()?;
    let _ = tokio::time::timeout(io_timeout, write_control_frame(&mut write_half, &bytes)).await;
    let _ = tokio::time::timeout(io_timeout, write_half.shutdown()).await;
    Ok(())
}

pub(crate) async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        if let (Ok(mut sigterm), Ok(mut sighup)) = (
            signal(SignalKind::terminate()),
            signal(SignalKind::hangup()),
        ) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = sigterm.recv() => {}
                _ = sighup.recv() => {}
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
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
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
                guest_arch: None,
                virtual_disk_mb: spec.budget.virtual_disk_mb,
                provisioned_host_bytes: 5,
                bundle_guard: None,
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
        alive: Arc<AtomicBool>,
        exit_probe: Option<Arc<AtomicU8>>,
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
        fn confirmed_exited(&self) -> Result<bool, SandboxError> {
            match self.exit_probe.as_ref().map(|probe| probe.load(Ordering::Acquire)) {
                Some(1) => Ok(false),
                Some(2) => Ok(true),
                Some(_) | None => Err(SandboxError::Internal(
                    "stub process exit confirmation is unavailable".to_owned(),
                )),
            }
        }
        fn current_rss_bytes(&self) -> Option<u64> {
            Some(64 * 1024 * 1024)
        }

        async fn exec_stream(&self, req: ExecRequest) -> Result<ExecStream, SandboxError> {
            let (stream, mut handle) = ExecStream::channel(StreamId(7));
            let cancel_seen = Arc::clone(&self.cancel_seen);
            tokio::spawn(async move {
                if req.argv.first().map(String::as_str) == Some("block-stdin") {
                    let _ = handle
                        .send_output(ExecOutputChunk {
                            stream: OutputStreamKind::Stdout,
                            data: b"blocked-stdin-started\n".to_vec(),
                        })
                        .await;
                    if handle.recv_cancel().await.is_some() {
                        cancel_seen.store(true, Ordering::Release);
                    }
                    handle.finish(Ok(ExecExitStatus {
                        code: None,
                        timed_out: false,
                        stdout_truncated: false,
                        stderr_truncated: false,
                    }));
                    return;
                }
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
            src_guest: &str,
            _max_bytes: u64,
        ) -> Result<Vec<u8>, SandboxError> {
            if src_guest == "/oversized-frame" {
                let payload_len = 19 * 1024 * 1024usize;
                let mut hdr = [0u8; 512];
                hdr[..7].copy_from_slice(b"big.bin");
                hdr[100..108].copy_from_slice(b"0000644\0");
                hdr[108..116].copy_from_slice(b"0000000\0");
                hdr[116..124].copy_from_slice(b"0000000\0");
                hdr[124..136].copy_from_slice(format!("{payload_len:011o}\0").as_bytes());
                hdr[136..148].copy_from_slice(b"00000000000\0");
                hdr[148..156].copy_from_slice(b"        ");
                hdr[156] = b'0';
                hdr[257..263].copy_from_slice(b"ustar\0");
                hdr[263..265].copy_from_slice(b"00");
                let cksum: u32 = hdr.iter().map(|&b| u32::from(b)).sum();
                hdr[148..156].copy_from_slice(format!("{cksum:06o}\0 ").as_bytes());
                let mut archive = vec![0u8; 512 + payload_len + 1024];
                archive[..512].copy_from_slice(&hdr);
                return Ok(archive);
            }
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
        alive_override: Option<Arc<AtomicBool>>,
        exit_probe: Option<Arc<AtomicU8>>,
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
                    alive: self.alive_override.as_ref().map(Arc::clone).unwrap_or_else(|| Arc::new(AtomicBool::new(true))),
                    exit_probe: self.exit_probe.as_ref().map(Arc::clone),
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
            max_copy_bytes: 20 * 1024 * 1024,
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
                    alive_override: None,
                    exit_probe: None,
                }),
            )
            .unwrap(),
        );
        (Arc::new(DaemonState::new(runtime)), cancel_seen)
    }

    fn build_exit_probe_test_state(
        tmp: &TestTempDir,
        alive: Arc<AtomicBool>,
        exit_probe: Option<Arc<AtomicU8>>,
    ) -> Arc<DaemonState> {
        let rt_cfg = RuntimeManagerConfig {
            state_dir: tmp.path().join("state"),
            sweep_interval: Duration::from_secs(10),
            graceful_shutdown_timeout: Duration::from_millis(50),
            max_copy_bytes: 20 * 1024 * 1024,
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
                    next_pid: AtomicU64::new(300),
                    cancel_seen: Arc::new(AtomicBool::new(false)),
                    alive_override: Some(alive),
                    exit_probe,
                }),
            )
            .unwrap(),
        );
        Arc::new(DaemonState::new(runtime))
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
        let listed = client.list_sandboxes().await.unwrap();
        assert_eq!(listed.len(), 2);
        let listed_main = listed.iter().find(|s| s.id == lease.id).unwrap();
        assert_eq!(listed_main.docker_endpoint.as_deref(), Some(docker_uri_1.as_str()));
        assert!(!listed_main.allow_reaper_socket);
        let listed_iso = listed.iter().find(|s| s.id == iso_lease.id).unwrap();
        assert!(listed_iso.docker_endpoint.is_some());
        assert!(listed_iso.allow_reaper_socket);

        client.destroy(&iso_lease.id).await.unwrap();

        let destroyed = client.destroy(&lease.id).await.unwrap();
        assert_eq!(destroyed, DestroyStatus::AllResourcesCleaned);
        assert!(client.list_sandboxes().await.unwrap().is_empty());
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

    #[tokio::test]
    async fn serve_connection_times_out_stalled_slowloris_frame_and_returns_error() {
        let tmp = TestTempDir::new("slowloris-frame");
        let (state, _) = build_test_state(&tmp);

        let (mut client, server) = tokio::io::duplex(1024);
        let state_conn = Arc::clone(&state);
        let conn_task = tokio::spawn(async move {
            serve_connection_with_timeout(server, state_conn, Duration::from_millis(60)).await
        });

        // Claim a 1 MiB frame and stall after 3 bytes of payload.
        client
            .write_all(&(1024u32 * 1024).to_be_bytes())
            .await
            .unwrap();
        client.write_all(b"{\"a").await.unwrap();

        tokio::time::timeout(Duration::from_secs(2), conn_task)
            .await
            .expect("stalled control connection must time out promptly")
            .unwrap()
            .unwrap();

        let err_raw = read_control_frame(&mut client).await.unwrap().unwrap();
        let resp = ControlResponse::from_json_bytes(&err_raw).unwrap();
        assert!(matches!(resp, ControlResponse::Error(_)));
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn named_pipe_server_survives_transient_next_instance_and_connect_errors() {
        use std::sync::atomic::AtomicUsize;

        let tmp = TestTempDir::new("pipe-resilience");
        let (state, _) = build_test_state(&tmp);
        let lease = state
            .runtime
            .spawn(sample_spec(NetworkPolicy::Isolated))
            .await
            .unwrap();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let pipe_path = format!(
            r"\\.\pipe\minipod-resilient-test-{}-{}",
            std::process::id(),
            TEST_SEQ.fetch_add(1, Ordering::Relaxed)
        );
        let ready_file = tmp.path().join("ready-resilient.json");
        let calls = Arc::new(AtomicUsize::new(0));
        let calls_factory = Arc::clone(&calls);

        let srv_pipe = pipe_path.clone();
        let srv_ready = ready_file.clone();
        let srv_state = Arc::clone(&state);
        let server_task = tokio::spawn(async move {
            run_windows_named_pipe_server_with_factory(
                &srv_pipe,
                Some(&srv_ready),
                srv_state,
                shutdown_rx,
                move |name, first| {
                    let n = calls_factory.fetch_add(1, Ordering::AcqRel);
                    // Fail the very first replacement pipe creation (`n == 1`) to simulate transient OS pool pressure.
                    if n == 1 {
                        return Err(SandboxError::Transport(
                            "simulated transient CreateNamedPipeW failure".to_owned(),
                        ));
                    }
                    sandbox_vmm::create_owner_only_async_named_pipe(name, first)
                },
            )
            .await
        });

        for _ in 0..100 {
            if ready_file.is_file() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(ready_file.is_file());

        let ep = ControlEndpoint::NamedPipe(pipe_path.clone());
        let client = SandboxClient::new(ep);

        // Request 1 triggers `n == 1` transient failure, yet must succeed AND keep the listener & VM alive.
        let s1 = client.status().await.unwrap();
        assert_eq!(s1.active_sandboxes, 1);

        // Give the listener's 25ms backoff tick to reopen the next pipe instance, then send more RPCs.
        tokio::time::sleep(Duration::from_millis(60)).await;
        let s2 = client.status().await.unwrap();
        assert_eq!(s2.active_sandboxes, 1);
        assert!(
            state.runtime.active_sandbox_network(&lease.id).is_ok(),
            "active VM must survive transient Named Pipe listener errors"
        );

        let _ = shutdown_tx.send(true);
        server_task.await.unwrap().unwrap();
    }

    struct PausedVmRuntime {
        inner: StubVmRuntime,
        boot_started: Arc<tokio::sync::Semaphore>,
        allow_boot: Arc<tokio::sync::Semaphore>,
    }

    #[async_trait::async_trait]
    impl VmRuntimePort for PausedVmRuntime {
        async fn boot_vm(&self, config: VmBootConfig) -> Result<VmBootOutcome, SandboxError> {
            self.boot_started.add_permits(1);
            self.allow_boot
                .acquire()
                .await
                .map_err(|error| SandboxError::Internal(error.to_string()))?
                .forget();
            <StubVmRuntime as VmRuntimePort>::boot_vm(&self.inner, config).await
        }

        async fn kill_orphan_process(
            &self,
            pid: u32,
            expected_start_token: u64,
        ) -> Result<bool, SandboxError> {
            <StubVmRuntime as VmRuntimePort>::kill_orphan_process(
                &self.inner,
                pid,
                expected_start_token,
            )
            .await
        }
    }

    fn build_paused_test_state(
        tmp: &TestTempDir,
        boot_started: Arc<tokio::sync::Semaphore>,
        allow_boot: Arc<tokio::sync::Semaphore>,
    ) -> Arc<DaemonState> {
        let rt_cfg = RuntimeManagerConfig {
            state_dir: tmp.path().join("state"),
            sweep_interval: Duration::from_secs(10),
            graceful_shutdown_timeout: Duration::from_millis(50),
            max_copy_bytes: 20 * 1024 * 1024,
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
                Arc::new(PausedVmRuntime {
                    inner: StubVmRuntime {
                        next_pid: AtomicU64::new(200),
                        cancel_seen: Arc::new(AtomicBool::new(false)),
                        alive_override: None,
                        exit_probe: None,
                    },
                    boot_started,
                    allow_boot,
                }),
            )
            .unwrap(),
        );
        Arc::new(DaemonState::new(runtime))
    }

    fn test_client_with_connect_counter(
        state: Arc<DaemonState>,
        connections: Arc<AtomicU64>,
    ) -> SandboxClient {
        let ep = if cfg!(windows) {
            ControlEndpoint::NamedPipe(r"\\.\pipe\test-keyed-spawn".to_owned())
        } else {
            ControlEndpoint::UnixSocket(PathBuf::from("/tmp/test-keyed-spawn.sock"))
        };
        SandboxClient::with_connector(ep, move |_| {
            connections.fetch_add(1, Ordering::AcqRel);
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

    #[tokio::test]
    async fn keyed_spawn_replay_after_lost_response_reuses_its_lease_and_preserves_foreign_lease() {
        let tmp = TestTempDir::new("keyed-spawn-lost-response");
        let (state, _) = build_test_state(&tmp);
        let client = test_client(Arc::clone(&state));
        let foreign = client
            .spawn(sample_spec(NetworkPolicy::InternetOnly))
            .await
            .unwrap();
        let operation_id = "00000000-0000-4000-8000-000000000001".to_owned();
        let spec = sample_spec(NetworkPolicy::Isolated);
        let request = ControlRequest::SpawnKeyed {
            operation_id: operation_id.clone(),
            spec: spec.clone(),
        };
        let payload = request.to_json_bytes().unwrap();
        let (mut client_end, server_end) = duplex(1024 * 1024);
        let server_state = Arc::clone(&state);
        let server_task = tokio::spawn(async move { serve_connection(server_end, server_state).await });

        write_control_frame(&mut client_end, &payload).await.unwrap();
        drop(client_end); // The daemon completes creation, but the client no longer receives its lease.
        let _ = server_task.await.unwrap();

        assert_eq!(state.list_sandboxes().len(), 2);
        let keyed = client.spawn_keyed(operation_id.clone(), spec.clone()).await.unwrap();
        let replay = client.spawn_keyed(operation_id.clone(), spec).await.unwrap();
        assert_eq!(replay.id, keyed.id);
        assert_ne!(keyed.id, foreign.id);
        assert_eq!(
            state.runtime.active_sandbox_network(&foreign.id).unwrap(),
            NetworkPolicy::InternetOnly,
            "keyed replay must leave an unrelated live lease unchanged"
        );
        assert_eq!(state.list_sandboxes().len(), 2);
    }

    #[tokio::test]
    async fn concurrent_keyed_replays_wait_for_creation_and_share_one_lease() {
        let tmp = TestTempDir::new("keyed-spawn-concurrent");
        let boot_started = Arc::new(tokio::sync::Semaphore::new(0));
        let allow_boot = Arc::new(tokio::sync::Semaphore::new(0));
        let state = build_paused_test_state(&tmp, Arc::clone(&boot_started), Arc::clone(&allow_boot));
        let connections = Arc::new(AtomicU64::new(0));
        let client = test_client_with_connect_counter(Arc::clone(&state), Arc::clone(&connections));
        let operation_id = "00000000-0000-4000-8000-000000000002".to_owned();
        let spec = sample_spec(NetworkPolicy::Isolated);

        let first_client = client.clone();
        let first_id = operation_id.clone();
        let first_spec = spec.clone();
        let first = tokio::spawn(async move { first_client.spawn_keyed(first_id, first_spec).await });
        tokio::time::timeout(Duration::from_secs(2), boot_started.acquire())
            .await
            .expect("first keyed spawn did not begin VM creation")
            .unwrap()
            .forget();

        let mut retries = Vec::new();
        for _ in 0..7 {
            let retry_client = client.clone();
            let retry_id = operation_id.clone();
            let retry_spec = spec.clone();
            retries.push(tokio::spawn(async move {
                retry_client.spawn_keyed(retry_id, retry_spec).await
            }));
        }
        tokio::time::timeout(Duration::from_secs(2), async {
            while connections.load(Ordering::Acquire) < 8 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("all keyed retries did not connect while creation was in progress");
        tokio::time::sleep(Duration::from_millis(15)).await;
        assert!(state.list_sandboxes().is_empty());

        allow_boot.add_permits(1);
        let first_lease = first.await.unwrap().unwrap();
        for retry in retries {
            let retry_lease = retry.await.unwrap().unwrap();
            assert_eq!(first_lease.id, retry_lease.id);
        }
        assert_eq!(state.list_sandboxes().len(), 1);
        assert!(boot_started.try_acquire().is_err(), "the duplicate key must not boot another VM");
    }

    #[tokio::test]
    async fn keyed_spawn_rejects_spec_conflict_without_adopting_an_existing_lease() {
        let tmp = TestTempDir::new("keyed-spawn-spec-conflict");
        let (state, _) = build_test_state(&tmp);
        let client = test_client(Arc::clone(&state));
        let foreign = client.spawn(sample_spec(NetworkPolicy::InternetOnly)).await.unwrap();
        let operation_id = "00000000-0000-4000-8000-000000000003".to_owned();
        let original_spec = sample_spec(NetworkPolicy::Isolated);
        let keyed = client
            .spawn_keyed(operation_id.clone(), original_spec.clone())
            .await
            .unwrap();
        assert_ne!(keyed.id, foreign.id);

        let mut changed_spec = original_spec;
        changed_spec.network = NetworkPolicy::InternetOnly;
        assert!(matches!(
            client.spawn_keyed(operation_id, changed_spec).await,
            Err(SandboxError::PolicyViolation(_))
        ));
        assert_eq!(state.list_sandboxes().len(), 2);
        assert!(state.runtime.active_sandbox_network(&foreign.id).is_ok());
        assert!(state.runtime.active_sandbox_network(&keyed.id).is_ok());
    }

    #[tokio::test]
    async fn keyed_spawn_keeps_lease_when_transport_failure_is_not_confirmed_as_exit() {
        let tmp = TestTempDir::new("keyed-spawn-transient-exit-probe");
        let alive = Arc::new(AtomicBool::new(false));
        let exit_probe = Arc::new(AtomicU8::new(1)); // Process query confirms it is still running.
        let state = build_exit_probe_test_state(&tmp, Arc::clone(&alive), Some(exit_probe));
        let client = test_client(Arc::clone(&state));
        let operation_id = "00000000-0000-4000-8000-000000000008".to_owned();
        let spec = sample_spec(NetworkPolicy::Isolated);

        assert!(matches!(
            client.spawn_keyed(operation_id.clone(), spec.clone()).await,
            Err(SandboxError::Transport(_))
        ));
        assert_eq!(state.list_sandboxes().len(), 1);
        assert!(!state.list_sandboxes()[0].alive);
        assert!(matches!(
            client.spawn_keyed(operation_id, spec).await,
            Err(SandboxError::Transport(_))
        ));
        assert_eq!(state.list_sandboxes().len(), 1, "retry must not create a second VM");
    }

    #[tokio::test]
    async fn keyed_spawn_fails_closed_when_process_exit_cannot_be_confirmed() {
        let tmp = TestTempDir::new("keyed-spawn-exit-probe-unavailable");
        let alive = Arc::new(AtomicBool::new(false));
        let state = build_exit_probe_test_state(&tmp, alive, None);
        let client = test_client(Arc::clone(&state));
        let operation_id = "00000000-0000-4000-8000-000000000009".to_owned();

        assert!(matches!(
            client.spawn_keyed(operation_id, sample_spec(NetworkPolicy::Isolated)).await,
            Err(SandboxError::Internal(_))
        ));
        assert_eq!(state.list_sandboxes().len(), 1, "unknown process state must preserve the lease");
    }

    #[tokio::test]
    async fn keyed_spawn_tombstone_survives_dead_on_spawn_and_daemon_restart() {
        let tmp = TestTempDir::new("keyed-spawn-dead-on-spawn-restart");
        let alive = Arc::new(AtomicBool::new(false));
        let exit_probe = Arc::new(AtomicU8::new(2)); // Process exit is confirmed immediately after boot.
        let state_before_restart =
            build_exit_probe_test_state(&tmp, alive, Some(Arc::clone(&exit_probe)));
        let client_before_restart = test_client(Arc::clone(&state_before_restart));
        let operation_id = "00000000-0000-4000-8000-000000000010".to_owned();
        let spec = sample_spec(NetworkPolicy::Isolated);

        assert!(matches!(
            client_before_restart
                .spawn_keyed(operation_id.clone(), spec.clone())
                .await,
            Err(SandboxError::LeaseExpired(_))
        ));
        let result_path = state_before_restart
            .runtime
            .config()
            .state_dir
            .join("spawn-operations")
            .join(format!("{operation_id}.result"));
        let result: serde_json::Value = serde_json::from_slice(&fs::read(result_path).unwrap()).unwrap();
        let old_id = result["response"]["lease"]["id"].as_str().unwrap().to_owned();
        assert_eq!(result["response"]["type"], "Spawned");
        assert_eq!(state_before_restart.list_sandboxes().len(), 0);
        drop(client_before_restart);
        drop(state_before_restart);

        let (state_after_restart, _) = build_test_state(&tmp);
        let client_after_restart = test_client(Arc::clone(&state_after_restart));
        assert!(matches!(
            client_after_restart
                .spawn_keyed(operation_id.clone(), spec.clone())
                .await,
            Err(SandboxError::LeaseExpired(_))
        ));
        assert_eq!(state_after_restart.list_sandboxes().len(), 0);

        let new_lease = client_after_restart
            .spawn_keyed("00000000-0000-4000-8000-000000000011".to_owned(), spec)
            .await
            .unwrap();
        assert_eq!(new_lease.id.as_str(), old_id, "the stub models PID-derived ID reuse");
        assert!(matches!(
            client_after_restart
                .spawn_keyed(operation_id, sample_spec(NetworkPolicy::Isolated))
                .await,
            Err(SandboxError::LeaseExpired(_))
        ));
        assert_eq!(state_after_restart.list_sandboxes().len(), 1);
    }

    #[tokio::test]
    async fn keyed_spawn_expiry_requires_a_new_operation_id_before_recreation() {
        let tmp = TestTempDir::new("keyed-spawn-expiry");
        let (state, _) = build_test_state(&tmp);
        let client = test_client(Arc::clone(&state));
        let operation_id = "00000000-0000-4000-8000-000000000004".to_owned();
        let mut spec = sample_spec(NetworkPolicy::Isolated);
        spec.lease_ttl = Duration::from_millis(250);
        let expired = client.spawn_keyed(operation_id.clone(), spec.clone()).await.unwrap();

        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(state.runtime.sweep_expired_leases().await, 1);
        assert!(state.list_sandboxes().is_empty());
        assert!(matches!(
            client.spawn_keyed(operation_id, spec.clone()).await,
            Err(SandboxError::LeaseExpired(_))
        ));

        let replacement = client
            .spawn_keyed("00000000-0000-4000-8000-000000000005".to_owned(), spec)
            .await
            .unwrap();
        assert_ne!(replacement.id, expired.id);
        assert_eq!(state.list_sandboxes().len(), 1);
    }

    #[tokio::test]
    async fn keyed_spawn_result_survives_daemon_restart_and_reconciles_before_new_key() {
        let tmp = TestTempDir::new("keyed-spawn-daemon-restart");
        let (state_before_restart, _) = build_test_state(&tmp);
        let client_before_restart = test_client(Arc::clone(&state_before_restart));
        let operation_id = "00000000-0000-4000-8000-000000000006".to_owned();
        let spec = sample_spec(NetworkPolicy::Isolated);
        let old_lease = client_before_restart
            .spawn_keyed(operation_id.clone(), spec.clone())
            .await
            .unwrap();
        drop(client_before_restart);
        drop(state_before_restart); // Keep the active journal but drop daemon and registry memory.

        let (state_after_restart, _) = build_test_state(&tmp);
        let client_after_restart = test_client(Arc::clone(&state_after_restart));
        assert_eq!(state_after_restart.status().active_sandboxes, 0);
        assert!(matches!(
            client_after_restart
                .spawn_keyed(operation_id.clone(), spec.clone())
                .await,
            Err(SandboxError::LeaseExpired(_))
        ));

        let new_lease = client_after_restart
            .spawn_keyed("00000000-0000-4000-8000-000000000007".to_owned(), spec)
            .await
            .unwrap();
        // The stub runtime derives IDs from its PID counter, which is reset on
        // daemon reconstruction. This models OS PID reuse: a fresh operation
        // may get the same printable ID, but an old receipt must stay expired.
        assert_eq!(new_lease.id, old_lease.id);
        assert!(matches!(
            client_after_restart
                .spawn_keyed(operation_id, sample_spec(NetworkPolicy::Isolated))
                .await,
            Err(SandboxError::LeaseExpired(_))
        ));
        assert!(state_after_restart.runtime.active_sandbox_network(&new_lease.id).is_ok());
        assert_eq!(state_after_restart.list_sandboxes().len(), 1);
        let journal_dir = state_after_restart.runtime.config().state_dir.join("journals");
        let journals = fs::read_dir(journal_dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.path().extension().is_some_and(|extension| extension == "journal"))
            .count();
        assert_eq!(journals, 1, "startup reconciliation must clean the old lease before spawning a new key");
    }

    #[tokio::test]
    async fn unkeyed_spawn_destroys_leaked_vm_when_client_disconnects_before_reply() {
        let tmp = TestTempDir::new("unkeyed-spawn-disconnect");
        let (state, _) = build_test_state(&tmp);
        let payload = ControlRequest::Spawn {
            spec: sample_spec(NetworkPolicy::Isolated),
        }
        .to_json_bytes()
        .unwrap();

        let (mut client_end, server_end) = duplex(1024 * 1024);
        write_control_frame(&mut client_end, &payload).await.unwrap();
        // Drop client read half immediately so writing `Spawned` response hits BrokenPipe.
        drop(client_end);

        let err = serve_connection(server_end, Arc::clone(&state))
            .await
            .expect_err("disconnected client must fail response write");
        assert!(matches!(err, SandboxError::Transport(_)));
        assert_eq!(
            state.list_sandboxes().len(),
            0,
            "unkeyed spawn must destroy VM if Spawned reply could not be delivered"
        );
    }

    #[tokio::test]
    async fn keyed_spawn_rejects_invalid_spec_before_writing_record_and_blocks_crashed_pending_retry() {
        let tmp = TestTempDir::new("keyed-spawn-pending-recovery");
        let (state, _) = build_test_state(&tmp);
        let client = test_client(Arc::clone(&state));
        let op_bad = "00000000-0000-4000-8000-000000000091".to_owned();
        let mut bad_spec = sample_spec(NetworkPolicy::Isolated);
        bad_spec.lease_ttl = Duration::ZERO;
        assert!(matches!(
            client.spawn_keyed(op_bad.clone(), bad_spec).await,
            Err(SandboxError::InvalidSpec(_))
        ));
        assert!(
            !state
                .runtime
                .config()
                .state_dir
                .join("spawn-operations")
                .join(format!("{op_bad}.spec"))
                .exists(),
            "invalid spec must be rejected before creating .spec on disk"
        );

        // Simulate a daemon crash between writing `<uuid>.pending` and writing `<uuid>.result`.
        let op_crashed = "00000000-0000-4000-8000-000000000092".to_owned();
        let dir = state.runtime.config().state_dir.join("spawn-operations");
        #[cfg(windows)]
        sandbox_vmm::os::windows::create_owner_only_dir(&dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::create_dir_all(&dir).unwrap();
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let spec = sample_spec(NetworkPolicy::Isolated);
        fs::write(
            dir.join(format!("{op_crashed}.spec")),
            ControlRequest::Spawn { spec: spec.clone() }.to_json_bytes().unwrap(),
        )
        .unwrap();
        fs::write(
            dir.join(format!("{op_crashed}.pending")),
            br#"{"incarnation":"previous-crashed-incarnation"}"#,
        )
        .unwrap();

        assert!(matches!(
            client.spawn_keyed(op_crashed, spec).await,
            Err(SandboxError::LeaseExpired(_))
        ));
        assert_eq!(state.list_sandboxes().len(), 0);
    }

    #[tokio::test]
    async fn enable_docker_compat_updates_reaper_policy_in_place_and_serializes_concurrent_calls() {
        let tmp = TestTempDir::new("docker-compat-in-place");
        let (state, _) = build_test_state(&tmp);
        let client = test_client(Arc::clone(&state));
        let lease = client
            .spawn(sample_spec(NetworkPolicy::Isolated))
            .await
            .unwrap();

        let (uri_a, uri_b) = tokio::join!(
            state.enable_docker_compat(&lease.id, false),
            state.enable_docker_compat(&lease.id, false),
        );
        let uri1 = uri_a.unwrap();
        assert_eq!(uri1, uri_b.unwrap());

        let server_ptr_1 = {
            let map = state.docker_compat.lock().unwrap();
            let entry = &map[&lease.id];
            assert_eq!(
                entry.compat.policy().reaper_socket,
                ReaperSocketPolicy::Deny
            );
            Arc::clone(&entry.compat)
        };

        let uri2 = state.enable_docker_compat(&lease.id, true).await.unwrap();
        assert_eq!(uri1, uri2, "toggling reaper policy must preserve the bound URI");
        {
            let map = state.docker_compat.lock().unwrap();
            let entry = &map[&lease.id];
            assert!(
                Arc::ptr_eq(&server_ptr_1, &entry.compat),
                "toggling reaper policy must update DockerCompatServer in-place without listener teardown"
            );
            assert_eq!(
                entry.compat.policy().reaper_socket,
                ReaperSocketPolicy::MapGuestPodmanSocket
            );
            assert!(entry.allow_reaper_socket);
        }

        let uri3 = state.enable_docker_compat(&lease.id, false).await.unwrap();
        assert_eq!(uri1, uri3);
        assert_eq!(
            server_ptr_1.policy().reaper_socket,
            ReaperSocketPolicy::Deny
        );

        let _ = client.destroy(&lease.id).await.unwrap();
        assert!(state.docker_compat_locks.lock().unwrap().get(&lease.id).is_none());
    }

    #[tokio::test]
    async fn pump_exec_stream_decouples_blocked_stdin_and_cancels_on_client_disconnect() {
        use tokio::sync::Notify;

        let tmp = TestTempDir::new("exec-blocked-stdin");
        let (state, cancel_seen) = build_test_state(&tmp);
        let client = test_client(Arc::clone(&state));
        let lease = client
            .spawn(sample_spec(NetworkPolicy::Isolated))
            .await
            .unwrap();

        // 1. Flood stdin against a guest that never reads stdin; host deadline must not starve.
        let mut exec = client
            .exec_stream(
                &lease.id,
                ExecRequest {
                    target: ExecTarget::Guest,
                    argv: vec!["block-stdin".to_owned()],
                    env: BTreeMap::new(),
                    cwd: None,
                    user: None,
                    deadline: Duration::from_millis(150),
                    stdout_budget_bytes: 64 * 1024,
                    stderr_budget_bytes: 64 * 1024,
                },
            )
            .await
            .unwrap();
        for _ in 0..120 {
            if exec.write_stdin(vec![b'x'; 256]).await.is_err() {
                break;
            }
        }
        let first_chunk = exec.next_output().await.expect("initial stdout");
        assert_eq!(first_chunk.data, b"blocked-stdin-started\n");
        let exit = exec.wait_exit().await.unwrap();
        assert!(exit.timed_out);
        assert!(cancel_seen.load(Ordering::Acquire));

        // 2. Client raw disconnect while `sleep` runs must cancel execution immediately.
        cancel_seen.store(false, Ordering::Release);
        let req_bytes = ControlRequest::ExecStart {
            id: lease.id.clone(),
            req: ExecRequest {
                target: ExecTarget::Guest,
                argv: vec!["sleep".to_owned(), "60".to_owned()],
                env: BTreeMap::new(),
                cwd: None,
                user: None,
                deadline: Duration::from_secs(30),
                stdout_budget_bytes: 64 * 1024,
                stderr_budget_bytes: 64 * 1024,
            },
        }
        .to_json_bytes()
        .unwrap();
        let (mut cli_end, srv_end) = duplex(64 * 1024);
        let done = Arc::new(Notify::new());
        let done_tx = Arc::clone(&done);
        let st_clone = Arc::clone(&state);
        tokio::spawn(async move {
            let _ = serve_connection(srv_end, st_clone).await;
            done_tx.notify_one();
        });
        write_control_frame(&mut cli_end, &req_bytes).await.unwrap();
        let started_raw = read_control_frame(&mut cli_end).await.unwrap().unwrap();
        assert!(matches!(
            ControlResponse::from_json_bytes(&started_raw).unwrap(),
            ControlResponse::ExecStarted { .. }
        ));
        drop(cli_end);
        tokio::time::timeout(Duration::from_secs(2), done.notified())
            .await
            .expect("disconnect must cancel sleep exec promptly");
        assert!(cancel_seen.load(Ordering::Acquire));
    }

    #[tokio::test]
    async fn oversized_control_response_returns_budget_exceeded_and_ready_file_rejects_symlinks() {
        let tmp = TestTempDir::new("wire-budget-and-ready");
        let (state, _) = build_test_state(&tmp);
        let client = test_client(Arc::clone(&state));
        let lease = client
            .spawn(sample_spec(NetworkPolicy::Isolated))
            .await
            .unwrap();

        let err = client
            .copy_out_tar_bytes(&lease.id, "/oversized-frame")
            .await
            .expect_err("response > MAX_CONTROL_FRAME_BYTES must fail cleanly");
        assert!(
            matches!(err, SandboxError::BudgetExceeded(_)),
            "expected BudgetExceeded error instead of transport EOF, got {err:?}"
        );

        let dir_target = tmp.path().join("ready-dir");
        fs::create_dir_all(&dir_target).unwrap();
        assert!(matches!(
            write_ready_file_atomic(&dir_target, "npipe://test"),
            Err(SandboxError::PolicyViolation(_))
        ));

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let real = tmp.path().join("real-ready.json");
            fs::write(&real, b"{}").unwrap();
            let sym = tmp.path().join("sym-ready.json");
            symlink(&real, &sym).unwrap();
            assert!(matches!(
                write_ready_file_atomic(&sym, "unix:///tmp/test.sock"),
                Err(SandboxError::PolicyViolation(_))
            ));
        }
    }
}
