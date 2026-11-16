//! Layer 3 VMM driver adapter implementing [`VmRuntimePort`] and [`VmSessionPort`]
//! over confined QEMU processes and multiplexed `virtio-serial` protocol frames.

use std::collections::HashMap;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use sandbox_core::{
    CapabilityReport, EnforcementLevel, ExecExitStatus, ExecRequest, ExecTarget, GuestArch,
    NetworkPolicy, SandboxError,
};
use sandbox_protocol::{
    is_guest_stream_id, read_frame, write_frame, ExecTargetWire, Frame, Message,
    PriorityFrameQueue, StreamChannel, StreamId, StreamTargetWire, HOST_STREAM_ID_MAX,
};
use sandbox_runtime::{
    validate_guest_path, ExecOutputChunk, ExecStream, OutputStreamKind, TunnelStream,
    TunnelStreamHandle, VmBootConfig, VmBootOutcome, VmRuntimePort, VmSessionPort,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf};
use tokio::sync::{mpsc, oneshot};

use crate::accel::{
    discover_qemu_binary_for_arch, probe_available_accelerators_for_arch, Accelerator,
};
use crate::ipc::{
    validate_socket_path, AgentIpcEndpoint, IpcReadHalf, IpcStream, IpcWriteHalf,
};
use crate::launch::QemuLaunchConfig;
use crate::process::{
    kill_verified_orphan_process, ConfinedProcess, ProcessLaunchSpec, ProcessStdio,
};
use crate::spike::{
    build_candidate_attempts, combine_fallback_error, is_retryable_boot_error, perform_handshake,
    protocol_err, read_attempt_diagnostics, send_protocol_message, ACCEPT_POLL_SLICE,
};

const MAX_HOST_STREAM_CHUNK_BYTES: usize = 64 * 1024;
const TUNNEL_INBOUND_CHANNEL_CAPACITY: usize = 256;
const EGRESS_ACCEPT_CHANNEL_CAPACITY: usize = 128;
const DEFAULT_EGRESS_PROXY_PORT: u16 = 3128;

/// Configuration for [`QemuVmDriver`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuDriverConfig {
    pub arch: GuestArch,
    pub qemu_bin: Option<PathBuf>,
    pub boot_timeout: Duration,
    pub io_timeout: Duration,
    pub runtime_parent_dir: Option<PathBuf>,
}

impl Default for QemuDriverConfig {
    fn default() -> Self {
        Self {
            arch: GuestArch::host_native().unwrap_or(GuestArch::X86_64),
            qemu_bin: None,
            boot_timeout: Duration::from_secs(45),
            io_timeout: Duration::from_secs(30),
            runtime_parent_dir: None,
        }
    }
}

impl QemuDriverConfig {
    /// Validates nonzero timeout invariants and explicit QEMU override paths.
    pub fn validate(&self) -> Result<(), SandboxError> {
        if self.boot_timeout.is_zero() {
            return Err(SandboxError::InvalidSpec(
                "QEMU boot_timeout must be greater than zero".to_owned(),
            ));
        }
        if self.io_timeout.is_zero() {
            return Err(SandboxError::InvalidSpec(
                "QEMU io_timeout must be greater than zero".to_owned(),
            ));
        }
        if let Some(bin) = &self.qemu_bin {
            if bin.as_os_str().is_empty() {
                return Err(SandboxError::InvalidSpec(
                    "qemu_bin override path cannot be empty".to_owned(),
                ));
            }
        }
        Ok(())
    }
}

/// Layer 3 [`VmRuntimePort`] driving headless QEMU instances with `virtio-serial` multiplexing.
#[derive(Clone, Debug)]
pub struct QemuVmDriver {
    config: QemuDriverConfig,
}

impl QemuVmDriver {
    /// Creates a [`QemuVmDriver`] after validating driver timeouts and overrides.
    pub fn new(config: QemuDriverConfig) -> Result<Self, SandboxError> {
        config.validate()?;
        Ok(Self { config })
    }

    pub fn config(&self) -> &QemuDriverConfig {
        &self.config
    }
}

#[async_trait::async_trait]
impl VmRuntimePort for QemuVmDriver {
    async fn boot_vm(&self, config: VmBootConfig) -> Result<VmBootOutcome, SandboxError> {
        validate_boot_config(&config)?;

        let driver_cfg = self.config.clone();
        tokio::task::spawn_blocking(move || boot_vm_blocking(&driver_cfg, &config))
            .await
            .map_err(|err| SandboxError::Internal(format!("QEMU boot task failed: {err}")))?
    }

    async fn kill_orphan_process(
        &self,
        pid: u32,
        expected_start_token: u64,
    ) -> Result<bool, SandboxError> {
        tokio::task::spawn_blocking(move || {
            kill_verified_orphan_process(pid, expected_start_token)
        })
        .await
        .map_err(|err| SandboxError::Internal(format!("kill_orphan_process task failed: {err}")))?
    }
}

fn validate_boot_config(config: &VmBootConfig) -> Result<(), SandboxError> {
    config.spec.validate_for_host_os(std::env::consts::OS)?;

    for (label, path) in [
        ("guest kernel", &config.overlay.kernel_path),
        ("guest initramfs", &config.overlay.initramfs_path),
        ("QCOW2 root overlay", &config.overlay.overlay_path),
    ] {
        if !path.is_file() {
            return Err(SandboxError::NotFound(format!(
                "{label} '{}' does not exist or is not a file",
                path.display()
            )));
        }
    }
    Ok(())
}

fn boot_vm_blocking(
    driver_cfg: &QemuDriverConfig,
    boot_cfg: &VmBootConfig,
) -> Result<VmBootOutcome, SandboxError> {
    let qemu_bin =
        discover_qemu_binary_for_arch(driver_cfg.arch, driver_cfg.qemu_bin.as_deref())?;
    let available = probe_available_accelerators_for_arch(&qemu_bin, driver_cfg.arch)?;
    let attempts = build_candidate_attempts(boot_cfg.spec.acceleration, &available)?;

    let mut primary_failure: Option<(Accelerator, SandboxError)> = None;
    for (idx, &accel) in attempts.iter().enumerate() {
        match boot_single_attempt(driver_cfg, boot_cfg, &qemu_bin, accel) {
            Ok(outcome) => return Ok(outcome),
            Err(err) => {
                let has_fallback = idx + 1 < attempts.len();
                if !has_fallback || !is_retryable_boot_error(&err) {
                    return Err(match primary_failure {
                        Some((prev_accel, prev_err)) => {
                            combine_fallback_error(prev_accel, prev_err, accel, err)
                        }
                        None => err,
                    });
                }
                primary_failure = Some((accel, err));
            }
        }
    }

    Err(SandboxError::AccelerationUnavailable(
        "no QEMU accelerator attempts were available".to_owned(),
    ))
}

fn bind_agent_endpoint(
    driver_cfg: &QemuDriverConfig,
    work_dir: &Path,
) -> Result<(AgentIpcEndpoint, Vec<PathBuf>), SandboxError> {
    if driver_cfg.runtime_parent_dir.is_none() {
        let ipc_dir = work_dir.join("ipc");
        let candidate = ipc_dir.join("a.sock");
        if validate_socket_path(&candidate).is_ok() {
            if let Some(s) = candidate.to_str() {
                if !s.contains(',') {
                    let endpoint = AgentIpcEndpoint::bind(&candidate)?;
                    return Ok((endpoint, vec![candidate, ipc_dir]));
                }
            }
        }
    }

    let endpoint = AgentIpcEndpoint::bind_temp_in(driver_cfg.runtime_parent_dir.as_deref(), "mp")?;
    let sock_path = endpoint.socket_path().to_path_buf();
    let mut paths = vec![sock_path.clone()];
    if let Some(parent) = sock_path.parent() {
        if parent != work_dir {
            paths.push(parent.to_path_buf());
        }
    }
    Ok((endpoint, paths))
}

fn boot_single_attempt(
    driver_cfg: &QemuDriverConfig,
    boot_cfg: &VmBootConfig,
    qemu_bin: &Path,
    accel: Accelerator,
) -> Result<VmBootOutcome, SandboxError> {
    let (endpoint, mut artifact_paths) = bind_agent_endpoint(driver_cfg, &boot_cfg.work_dir)?;
    let socket_path = endpoint.socket_path().to_path_buf();

    let serial_log_path = boot_cfg.work_dir.join("serial.log");
    let stderr_log_path = boot_cfg.work_dir.join("qemu-stderr.log");
    artifact_paths.push(serial_log_path.clone());
    artifact_paths.push(stderr_log_path.clone());

    let launch_cfg = QemuLaunchConfig {
        qemu_bin: qemu_bin.to_path_buf(),
        arch: driver_cfg.arch,
        accelerator: accel,
        kernel_path: boot_cfg.overlay.kernel_path.clone(),
        initrd_path: Some(boot_cfg.overlay.initramfs_path.clone()),
        kernel_cmdline: boot_cfg.overlay.kernel_cmdline.clone(),
        root_disk_qcow2: Some(boot_cfg.overlay.overlay_path.clone()),
        vcpus: boot_cfg.spec.budget.guest_vcpus,
        ram_mb: boot_cfg.spec.budget.guest_ram_mb,
        agent_socket_path: socket_path,
        serial_log_path: Some(serial_log_path.clone()),
        network: boot_cfg.spec.network.clone(),
    };
    let args = launch_cfg.build_args()?;

    let stderr_file = File::create(&stderr_log_path).map_err(|err| {
        SandboxError::Transport(format!(
            "failed to create QEMU stderr log '{}': {err}",
            stderr_log_path.display()
        ))
    })?;

    let mut launch_spec = ProcessLaunchSpec::new(qemu_bin, args);
    launch_spec.stderr = ProcessStdio::File(stderr_file);
    launch_spec.cpu_quota_millicores = boot_cfg.spec.budget.host_cpu_quota_Millicores;
    launch_spec.memory_limit_bytes = boot_cfg
        .spec
        .budget
        .host_rss_budget_mb
        .map(|mb| u64::from(mb) * 1024 * 1024);
    let mut process = ConfinedProcess::spawn(launch_spec)?;

    let boot_deadline = Instant::now() + driver_cfg.boot_timeout;
    let mut stream = loop {
        if let Some(status) = process.try_wait()? {
            let diag = read_attempt_diagnostics(&serial_log_path, &stderr_log_path);
            let msg = format!(
                "QEMU ({}) exited with {status} before virtio-serial IPC connected{diag}",
                accel.as_qemu_arg()
            );
            return Err(if accel.is_hardware() {
                SandboxError::AccelerationUnavailable(msg)
            } else {
                SandboxError::Transport(msg)
            });
        }

        let now = Instant::now();
        if now >= boot_deadline {
            let _ = process.kill_and_wait();
            let diag = read_attempt_diagnostics(&serial_log_path, &stderr_log_path);
            return Err(SandboxError::Transport(format!(
                "timed out after {}ms waiting for QEMU ({}) to connect virtio-serial IPC{diag}",
                driver_cfg.boot_timeout.as_millis(),
                accel.as_qemu_arg()
            )));
        }

        let slice = boot_deadline
            .saturating_duration_since(now)
            .min(ACCEPT_POLL_SLICE);
        let attempt_start = Instant::now();
        match endpoint.accept_timeout(slice) {
            Ok(connected) => break connected,
            Err(SandboxError::Transport(_)) => {
                if attempt_start.elapsed() < slice / 2 {
                    thread::sleep(Duration::from_millis(10));
                }
            }
            Err(err) => {
                let _ = process.kill_and_wait();
                return Err(err);
            }
        }
    };

    stream.set_io_timeout(Some(driver_cfg.boot_timeout))?;
    if let Err(err) = perform_handshake(&mut stream) {
        let exited_early = process.try_wait().ok().flatten().is_some();
        let _ = process.kill_and_wait();
        let diag = read_attempt_diagnostics(&serial_log_path, &stderr_log_path);
        return Err(match err {
            SandboxError::Transport(msg) => {
                let full = format!("{msg} ({}){diag}", accel.as_qemu_arg());
                if accel.is_hardware() && exited_early {
                    SandboxError::AccelerationUnavailable(full)
                } else {
                    SandboxError::Transport(full)
                }
            }
            other => other,
        });
    }

    let (egress_tx, egress_rx) = if boot_cfg.spec.network != NetworkPolicy::Isolated {
        if let Err(err) = configure_guest_network(&mut stream, DEFAULT_EGRESS_PROXY_PORT) {
            let _ = process.kill_and_wait();
            let diag = read_attempt_diagnostics(&serial_log_path, &stderr_log_path);
            return Err(match err {
                SandboxError::Transport(msg) => {
                    SandboxError::Transport(format!("{msg} ({}){diag}", accel.as_qemu_arg()))
                }
                other => other,
            });
        }
        let (tx, rx) = mpsc::channel(EGRESS_ACCEPT_CHANNEL_CAPACITY);
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };

    let identity = process.start_identity();
    let proc_caps = process.resource_capabilities();
    let session = QemuVmSession::start(
        Some(process),
        Some(endpoint),
        stream,
        artifact_paths.clone(),
        driver_cfg.io_timeout,
        identity.pid,
        identity.start_token,
        egress_tx,
    )?;

    Ok(VmBootOutcome {
        session: Box::new(session),
        pid: identity.pid,
        start_token: identity.start_token,
        artifact_paths,
        hardware_accelerated: accel.is_hardware(),
        capabilities: CapabilityReport {
            cpu_quota: proc_caps.cpu_quota,
            host_rss: proc_caps.host_rss,
            host_storage: EnforcementLevel::BestEffort,
            egress_filter: EnforcementLevel::HardLimit,
        },
        egress_rx,
    })
}

fn configure_guest_network(stream: &mut IpcStream, proxy_port: u16) -> Result<u16, SandboxError> {
    send_protocol_message(
        stream,
        StreamId(0),
        &Message::ConfigureNetwork {
            enable_egress_proxy: true,
            proxy_port,
        },
    )?;

    let ack_frame = read_frame(stream)
        .map_err(|err| protocol_err("waiting for guest ConfigureNetworkAck", err))?;
    if ack_frame.header.stream_id != StreamId(0) {
        return Err(SandboxError::Transport(format!(
            "expected guest ConfigureNetworkAck on stream 0, got {}",
            ack_frame.header.stream_id
        )));
    }
    match ack_frame
        .decode_message()
        .map_err(|err| protocol_err("decoding guest ConfigureNetworkAck", err))?
    {
        Message::ConfigureNetworkAck { proxy_port: 0 } => Err(SandboxError::Transport(
            "guest egress proxy listener reported unbound port 0".to_owned(),
        )),
        Message::ConfigureNetworkAck { proxy_port } => Ok(proxy_port),
        other => Err(SandboxError::Transport(format!(
            "expected guest ConfigureNetworkAck message, got {:?}",
            other.kind()
        ))),
    }
}

struct OutboundQueueState {
    queue: PriorityFrameQueue,
    closed: bool,
    error: Option<String>,
}

struct OutboundQueue {
    state: Mutex<OutboundQueueState>,
    cv: Condvar,
}

impl OutboundQueue {
    fn new() -> Self {
        Self {
            state: Mutex::new(OutboundQueueState {
                queue: PriorityFrameQueue::new(),
                closed: false,
                error: None,
            }),
            cv: Condvar::new(),
        }
    }

    fn enqueue(&self, frame: Frame) -> Result<(), SandboxError> {
        let mut guard = lock_unpoisoned(&self.state);
        if guard.closed {
            return Err(SandboxError::Transport(
                guard
                    .error
                    .clone()
                    .unwrap_or_else(|| "QEMU IPC transport is closed".to_owned()),
            ));
        }
        guard.queue.push(frame);
        self.cv.notify_one();
        Ok(())
    }

    fn close(&self, reason: Option<String>) {
        let mut guard = lock_unpoisoned(&self.state);
        guard.closed = true;
        if guard.error.is_none() {
            guard.error = reason;
        }
        self.cv.notify_all();
    }

    fn pop_blocking(&self) -> Option<Frame> {
        let mut guard = lock_unpoisoned(&self.state);
        loop {
            if let Some(frame) = guard.queue.pop() {
                return Some(frame);
            }
            if guard.closed {
                return None;
            }
            guard = self
                .cv
                .wait(guard)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
    }
}

enum TunnelInbound {
    Data { data: Vec<u8>, eof: bool },
    RemoteClose,
}

enum StreamHandler {
    Exec {
        output_tx: mpsc::Sender<ExecOutputChunk>,
        exit_tx: Option<oneshot::Sender<Result<ExecExitStatus, SandboxError>>>,
        done_tx: Option<oneshot::Sender<()>>,
    },
    CopyIn {
        reply_tx: Option<oneshot::Sender<Result<u64, SandboxError>>>,
    },
    CopyOut {
        max_bytes: u64,
        buffer: Vec<u8>,
        reply_tx: Option<oneshot::Sender<Result<Vec<u8>, SandboxError>>>,
    },
    Tunnel {
        connect_tx: Option<oneshot::Sender<Result<(), SandboxError>>>,
        inbound_tx: mpsc::Sender<TunnelInbound>,
    },
}

/// Active multiplexed QEMU `virtio-serial` session implementing [`VmSessionPort`].
pub struct QemuVmSession {
    pid: u32,
    start_token: u64,
    io_timeout: Duration,
    artifact_paths: Vec<PathBuf>,
    process: Mutex<Option<ConfinedProcess>>,
    endpoint: Mutex<Option<AgentIpcEndpoint>>,
    stream_shutdown: Mutex<Option<IpcReadHalf>>,
    reader_thread: Mutex<Option<JoinHandle<()>>>,
    writer_thread: Mutex<Option<JoinHandle<()>>>,
    outbound: Arc<OutboundQueue>,
    ops: Arc<Mutex<HashMap<StreamId, StreamHandler>>>,
    transport_closed: Arc<AtomicBool>,
    alive: AtomicBool,
    next_stream_id: AtomicU32,
}

impl Drop for QemuVmSession {
    fn drop(&mut self) {
        self.alive.store(false, Ordering::Release);
        self.outbound.close(Some("session dropped".to_owned()));
        if let Some(shutdown_half) = lock_unpoisoned(&self.stream_shutdown).as_ref() {
            let _ = shutdown_half.shutdown();
        }
        if let Some(mut process) = lock_unpoisoned(&self.process).take() {
            let _ = process.kill_and_wait();
        }
        self.teardown_ipc_and_threads();
    }
}

impl QemuVmSession {
    #[allow(clippy::too_many_arguments)]
    fn start(
        process: Option<ConfinedProcess>,
        endpoint: Option<AgentIpcEndpoint>,
        stream: IpcStream,
        artifact_paths: Vec<PathBuf>,
        io_timeout: Duration,
        pid: u32,
        start_token: u64,
        egress_tx: Option<mpsc::Sender<TunnelStream>>,
    ) -> Result<Self, SandboxError> {
        // Blocking reader waits indefinitely for async guest output; bounded writes guard against stalls.
        stream.set_read_timeout(None)?;
        stream.set_write_timeout(Some(io_timeout))?;

        let (read_half, write_half) = stream.into_split();
        let stream_shutdown = read_half.clone();
        let outbound = Arc::new(OutboundQueue::new());
        let ops: Arc<Mutex<HashMap<StreamId, StreamHandler>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let transport_closed = Arc::new(AtomicBool::new(false));
        let tokio_handle = tokio::runtime::Handle::try_current().ok();

        let writer_outbound = Arc::clone(&outbound);
        let writer_ops = Arc::clone(&ops);
        let writer_closed = Arc::clone(&transport_closed);
        let writer_thread = thread::Builder::new()
            .name(format!("minipod-vmm-tx-{pid}"))
            .spawn(move || {
                run_writer_loop(write_half, writer_outbound, writer_ops, writer_closed);
            })
            .map_err(|err| SandboxError::Internal(format!("spawn VMM writer thread: {err}")))?;

        let reader_outbound = Arc::clone(&outbound);
        let reader_ops = Arc::clone(&ops);
        let reader_closed = Arc::clone(&transport_closed);
        let reader_thread = thread::Builder::new()
            .name(format!("minipod-vmm-rx-{pid}"))
            .spawn(move || {
                run_reader_loop(
                    read_half,
                    reader_outbound,
                    reader_ops,
                    reader_closed,
                    egress_tx,
                    tokio_handle,
                );
            })
            .map_err(|err| SandboxError::Internal(format!("spawn VMM reader thread: {err}")))?;

        Ok(Self {
            pid,
            start_token,
            io_timeout,
            artifact_paths,
            process: Mutex::new(process),
            endpoint: Mutex::new(endpoint),
            stream_shutdown: Mutex::new(Some(stream_shutdown)),
            reader_thread: Mutex::new(Some(reader_thread)),
            writer_thread: Mutex::new(Some(writer_thread)),
            outbound,
            ops,
            transport_closed,
            alive: AtomicBool::new(true),
            next_stream_id: AtomicU32::new(1),
        })
    }

    #[cfg(test)]
    pub(crate) fn from_test_stream(
        stream: IpcStream,
        io_timeout: Duration,
    ) -> Result<Self, SandboxError> {
        Self::start(None, None, stream, Vec::new(), io_timeout, 0, 0, None)
    }

    #[cfg(test)]
    pub(crate) fn from_test_stream_with_egress(
        stream: IpcStream,
        io_timeout: Duration,
    ) -> Result<(Self, mpsc::Receiver<TunnelStream>), SandboxError> {
        let (tx, rx) = mpsc::channel(EGRESS_ACCEPT_CHANNEL_CAPACITY);
        let session = Self::start(None, None, stream, Vec::new(), io_timeout, 0, 0, Some(tx))?;
        Ok((session, rx))
    }

    fn allocate_stream_id(&self) -> Result<StreamId, SandboxError> {
        loop {
            let current = self.next_stream_id.load(Ordering::Acquire);
            if current == 0 || current > HOST_STREAM_ID_MAX {
                return Err(SandboxError::Internal(
                    "QEMU session host stream IDs exhausted".to_owned(),
                ));
            }
            if self
                .next_stream_id
                .compare_exchange(current, current + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Ok(StreamId(current));
            }
        }
    }

    fn enqueue_message(&self, stream_id: StreamId, msg: &Message) -> Result<(), SandboxError> {
        let frame = Frame::from_message(stream_id, msg)
            .map_err(|err| protocol_err("encoding protocol frame", err))?;
        self.outbound.enqueue(frame)
    }

    fn ensure_transport_ready(&self) -> Result<(), SandboxError> {
        if self.transport_closed.load(Ordering::Acquire) || !self.is_alive() {
            return Err(SandboxError::Transport(
                "QEMU VM session is closed or exited".to_owned(),
            ));
        }
        Ok(())
    }

    fn teardown_ipc_and_threads(&self) {
        self.outbound.close(None);
        if let Some(shutdown_half) = lock_unpoisoned(&self.stream_shutdown).take() {
            let _ = shutdown_half.shutdown();
            drop(shutdown_half);
        }
        if let Some(handle) = lock_unpoisoned(&self.writer_thread).take() {
            let _ = handle.join();
        }
        if let Some(handle) = lock_unpoisoned(&self.reader_thread).take() {
            let _ = handle.join();
        }
        drop(lock_unpoisoned(&self.endpoint).take());
        fail_all_pending_ops(&self.ops, "QEMU VM session terminated");
    }
}

#[async_trait::async_trait]
impl VmSessionPort for QemuVmSession {
    fn pid(&self) -> u32 {
        self.pid
    }

    fn start_token(&self) -> u64 {
        self.start_token
    }

    fn artifact_paths(&self) -> &[PathBuf] {
        &self.artifact_paths
    }

    fn is_alive(&self) -> bool {
        if !self.alive.load(Ordering::Acquire) {
            return false;
        }
        let mut proc_guard = lock_unpoisoned(&self.process);
        if let Some(proc_ref) = proc_guard.as_mut() {
            match proc_ref.try_wait() {
                Ok(Some(_)) => {
                    self.alive.store(false, Ordering::Release);
                    false
                }
                Ok(None) => true,
                Err(_) => false,
            }
        } else {
            !self.transport_closed.load(Ordering::Acquire)
        }
    }

    fn current_rss_bytes(&self) -> Option<u64> {
        if !self.alive.load(Ordering::Acquire) {
            return None;
        }
        let proc_guard = lock_unpoisoned(&self.process);
        proc_guard
            .as_ref()
            .and_then(ConfinedProcess::current_rss_bytes)
    }

    async fn exec_stream(&self, req: ExecRequest) -> Result<ExecStream, SandboxError> {
        if req.argv.is_empty() {
            return Err(SandboxError::InvalidSpec(
                "exec argv cannot be empty".to_owned(),
            ));
        }
        if req.deadline.is_zero() {
            return Err(SandboxError::InvalidSpec(
                "exec deadline must be greater than zero".to_owned(),
            ));
        }

        let wire_target = match req.target {
            ExecTarget::Guest => ExecTargetWire::Guest,
            ExecTarget::Container { id_or_name } => {
                if id_or_name.is_empty()
                    || id_or_name.len() > 128
                    || id_or_name.starts_with('-')
                    || !id_or_name
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
                {
                    return Err(SandboxError::InvalidSpec(
                        "container exec target id_or_name must be 1..=128 ASCII [a-zA-Z0-9_.-] and cannot start with '-'".to_owned(),
                    ));
                }
                ExecTargetWire::Container { id_or_name }
            }
        };
        self.ensure_transport_ready()?;
        let deadline_ms = u64::try_from(req.deadline.as_millis())
            .unwrap_or(u64::MAX)
            .max(1);

        let stream_id = self.allocate_stream_id()?;
        let (exec_stream, handle) = ExecStream::channel(stream_id);
        let (done_tx, done_rx) = oneshot::channel();

        {
            let mut ops = lock_unpoisoned(&self.ops);
            ops.insert(
                stream_id,
                StreamHandler::Exec {
                    output_tx: handle.output_tx,
                    exit_tx: handle.exit_tx,
                    done_tx: Some(done_tx),
                },
            );
        }

        let start_msg = Message::ExecStart {
            target: wire_target,
            argv: req.argv,
            env: req.env,
            cwd: req.cwd,
            user: req.user,
            deadline_ms,
            stdout_budget_bytes: req.stdout_budget_bytes,
            stderr_budget_bytes: req.stderr_budget_bytes,
        };
        if let Err(err) = self.enqueue_message(stream_id, &start_msg) {
            lock_unpoisoned(&self.ops).remove(&stream_id);
            return Err(err);
        }

        let outbound = Arc::clone(&self.outbound);
        let mut stdin_rx = handle.stdin_rx;
        let mut cancel_rx = handle.cancel_rx;
        tokio::spawn(async move {
            pump_exec_stdin_and_cancel(stream_id, outbound, &mut stdin_rx, &mut cancel_rx, done_rx)
                .await;
        });

        Ok(exec_stream)
    }

    async fn open_tunnel(&self, target: StreamTargetWire) -> Result<TunnelStream, SandboxError> {
        if let StreamTargetWire::GuestLoopbackTcp { port: 0 } = target {
            return Err(SandboxError::InvalidSpec(
                "guest_port must be greater than zero".to_owned(),
            ));
        }
        self.ensure_transport_ready()?;

        let stream_id = self.allocate_stream_id()?;
        let (tunnel_stream, tunnel_handle) = TunnelStream::channel(stream_id);
        let (connect_tx, connect_rx) = oneshot::channel();
        let (inbound_tx, inbound_rx) = mpsc::channel(TUNNEL_INBOUND_CHANNEL_CAPACITY);

        {
            let mut ops = lock_unpoisoned(&self.ops);
            ops.insert(
                stream_id,
                StreamHandler::Tunnel {
                    connect_tx: Some(connect_tx),
                    inbound_tx,
                },
            );
        }

        if let Err(err) = self.enqueue_message(stream_id, &Message::ConnectStart { target }) {
            lock_unpoisoned(&self.ops).remove(&stream_id);
            return Err(err);
        }

        let mut connect_guard = TunnelConnectGuard {
            stream_id,
            ops: &self.ops,
            outbound: &self.outbound,
            armed: true,
        };

        match tokio::time::timeout(self.io_timeout, connect_rx).await {
            Ok(Ok(Ok(()))) => {
                connect_guard.armed = false;
            }
            Ok(Ok(Err(err))) => {
                // Reader already removed stream_id on ConnectError; avoid sending StreamClose.
                connect_guard.armed = false;
                lock_unpoisoned(&self.ops).remove(&stream_id);
                return Err(err);
            }
            Ok(Err(_)) => {
                connect_guard.armed = false;
                lock_unpoisoned(&self.ops).remove(&stream_id);
                return Err(SandboxError::Transport(
                    "tunnel connection closed before guest ConnectAck".to_owned(),
                ));
            }
            Err(_) => {
                drop(connect_guard);
                return Err(SandboxError::Transport(format!(
                    "timed out after {}ms waiting for guest ConnectAck on stream {stream_id}",
                    self.io_timeout.as_millis()
                )));
            }
        }

        spawn_tunnel_pumps(
            &tokio::runtime::Handle::current(),
            stream_id,
            Arc::clone(&self.outbound),
            Arc::clone(&self.ops),
            inbound_rx,
            tunnel_handle,
        );

        Ok(tunnel_stream)
    }

    async fn copy_in_tar(
        &self,
        dst_guest: &str,
        tar_bytes: Vec<u8>,
        max_bytes: u64,
    ) -> Result<u64, SandboxError> {
        validate_guest_path(dst_guest, "dst_guest")?;
        if (tar_bytes.len() as u64) > max_bytes {
            return Err(SandboxError::BudgetExceeded(format!(
                "tar payload size ({} bytes) exceeds max_bytes ({max_bytes})",
                tar_bytes.len()
            )));
        }
        self.ensure_transport_ready()?;

        let stream_id = self.allocate_stream_id()?;
        let (reply_tx, reply_rx) = oneshot::channel();
        {
            let mut ops = lock_unpoisoned(&self.ops);
            ops.insert(
                stream_id,
                StreamHandler::CopyIn {
                    reply_tx: Some(reply_tx),
                },
            );
        }

        if let Err(err) = self.enqueue_message(
            stream_id,
            &Message::CopyInStart {
                dst_guest: dst_guest.to_owned(),
                max_bytes,
            },
        ) {
            lock_unpoisoned(&self.ops).remove(&stream_id);
            return Err(err);
        }

        if tar_bytes.is_empty() {
            if let Err(err) = self.enqueue_message(
                stream_id,
                &Message::StreamData {
                    channel: StreamChannel::Stdin,
                    eof: true,
                    data: Vec::new(),
                },
            ) {
                lock_unpoisoned(&self.ops).remove(&stream_id);
                return Err(err);
            }
        } else {
            let total_chunks = tar_bytes.chunks(MAX_HOST_STREAM_CHUNK_BYTES).len();
            for (idx, chunk) in tar_bytes.chunks(MAX_HOST_STREAM_CHUNK_BYTES).enumerate() {
                let eof = idx + 1 == total_chunks;
                if let Err(err) = self.enqueue_message(
                    stream_id,
                    &Message::StreamData {
                        channel: StreamChannel::Stdin,
                        eof,
                        data: chunk.to_vec(),
                    },
                ) {
                    lock_unpoisoned(&self.ops).remove(&stream_id);
                    return Err(err);
                }
            }
        }

        reply_rx.await.unwrap_or_else(|_| {
            Err(SandboxError::Transport(
                "copy_in interrupted before guest CopyDone".to_owned(),
            ))
        })
    }

    async fn copy_out_tar(
        &self,
        src_guest: &str,
        max_bytes: u64,
    ) -> Result<Vec<u8>, SandboxError> {
        validate_guest_path(src_guest, "src_guest")?;
        if max_bytes == 0 {
            return Err(SandboxError::InvalidSpec(
                "copy_out max_bytes must be greater than zero".to_owned(),
            ));
        }
        self.ensure_transport_ready()?;

        let stream_id = self.allocate_stream_id()?;
        let (reply_tx, reply_rx) = oneshot::channel();
        {
            let mut ops = lock_unpoisoned(&self.ops);
            ops.insert(
                stream_id,
                StreamHandler::CopyOut {
                    max_bytes,
                    buffer: Vec::new(),
                    reply_tx: Some(reply_tx),
                },
            );
        }

        if let Err(err) = self.enqueue_message(
            stream_id,
            &Message::CopyOutStart {
                src_guest: src_guest.to_owned(),
                max_bytes,
            },
        ) {
            lock_unpoisoned(&self.ops).remove(&stream_id);
            return Err(err);
        }

        reply_rx.await.unwrap_or_else(|_| {
            Err(SandboxError::Transport(
                "copy_out interrupted before guest CopyDone".to_owned(),
            ))
        })
    }

    async fn graceful_shutdown(&self, timeout: Duration) -> Result<bool, SandboxError> {
        if !self.alive.load(Ordering::Acquire) {
            self.teardown_ipc_and_threads();
            return Ok(true);
        }

        let _ = self.enqueue_message(StreamId(0), &Message::Shutdown);

        let maybe_process = lock_unpoisoned(&self.process).take();
        let Some(mut process) = maybe_process else {
            self.alive.store(false, Ordering::Release);
            self.teardown_ipc_and_threads();
            return Ok(true);
        };

        let wait_result = tokio::task::spawn_blocking(move || {
            let status = process.wait_timeout(timeout);
            (process, status)
        })
        .await
        .map_err(|err| SandboxError::Internal(format!("graceful_shutdown wait failed: {err}")))?;

        let (process, exit_res) = wait_result;
        match exit_res {
            Ok(Some(_)) => {
                self.alive.store(false, Ordering::Release);
                drop(process);
                self.teardown_ipc_and_threads();
                Ok(true)
            }
            Ok(None) => {
                *lock_unpoisoned(&self.process) = Some(process);
                Ok(false)
            }
            Err(err) => {
                *lock_unpoisoned(&self.process) = Some(process);
                Err(err)
            }
        }
    }

    async fn force_kill(&self) -> Result<(), SandboxError> {
        self.alive.store(false, Ordering::Release);
        self.outbound.close(Some("force_kill invoked".to_owned()));
        if let Some(shutdown_half) = lock_unpoisoned(&self.stream_shutdown).as_ref() {
            let _ = shutdown_half.shutdown();
        }

        let maybe_process = lock_unpoisoned(&self.process).take();
        let kill_res = if let Some(mut process) = maybe_process {
            tokio::task::spawn_blocking(move || process.kill_and_wait())
                .await
                .map_err(|err| SandboxError::Internal(format!("force_kill task failed: {err}")))?
        } else {
            Ok(())
        };

        let shutdown_half = lock_unpoisoned(&self.stream_shutdown).take();
        let writer = lock_unpoisoned(&self.writer_thread).take();
        let reader = lock_unpoisoned(&self.reader_thread).take();
        let endpoint = lock_unpoisoned(&self.endpoint).take();
        let ops = Arc::clone(&self.ops);

        tokio::task::spawn_blocking(move || {
            if let Some(half) = shutdown_half {
                let _ = half.shutdown();
                drop(half);
            }
            if let Some(handle) = writer {
                let _ = handle.join();
            }
            if let Some(handle) = reader {
                let _ = handle.join();
            }
            drop(endpoint);
            fail_all_pending_ops(&ops, "QEMU process killed");
        })
        .await
        .map_err(|err| SandboxError::Internal(format!("force_kill cleanup failed: {err}")))?;

        kill_res
    }
}

struct TunnelConnectGuard<'a> {
    stream_id: StreamId,
    ops: &'a Mutex<HashMap<StreamId, StreamHandler>>,
    outbound: &'a OutboundQueue,
    armed: bool,
}

impl Drop for TunnelConnectGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            lock_unpoisoned(self.ops).remove(&self.stream_id);
            if let Ok(frame) = Frame::from_message(self.stream_id, &Message::StreamClose) {
                let _ = self.outbound.enqueue(frame);
            }
        }
    }
}

fn spawn_tunnel_pumps(
    rt: &tokio::runtime::Handle,
    stream_id: StreamId,
    outbound: Arc<OutboundQueue>,
    ops: Arc<Mutex<HashMap<StreamId, StreamHandler>>>,
    inbound_rx: mpsc::Receiver<TunnelInbound>,
    tunnel_handle: TunnelStreamHandle,
) {
    let (remote_eof_tx, remote_eof_rx) = oneshot::channel();
    let (remote_abort_tx, remote_abort_rx) = oneshot::channel();

    rt.spawn(async move {
        pump_tunnel_inbound(
            inbound_rx,
            tunnel_handle.write_half,
            remote_eof_tx,
            remote_abort_tx,
        )
        .await;
    });
    rt.spawn(async move {
        pump_tunnel_outbound(
            stream_id,
            outbound,
            ops,
            tunnel_handle.read_half,
            tunnel_handle.drop_rx,
            remote_eof_rx,
            remote_abort_rx,
        )
        .await;
    });
}

async fn pump_tunnel_inbound(
    mut inbound_rx: mpsc::Receiver<TunnelInbound>,
    mut write_half: WriteHalf<DuplexStream>,
    remote_eof_tx: oneshot::Sender<()>,
    remote_abort_tx: oneshot::Sender<()>,
) {
    let mut remote_eof_tx = Some(remote_eof_tx);
    while let Some(item) = inbound_rx.recv().await {
        match item {
            TunnelInbound::Data { data, eof } => {
                if !data.is_empty() && write_half.write_all(&data).await.is_err() {
                    break;
                }
                if eof {
                    if let Some(tx) = remote_eof_tx.take() {
                        let _ = tx.send(());
                    }
                    let _ = write_half.shutdown().await;
                }
            }
            TunnelInbound::RemoteClose => {
                let _ = remote_abort_tx.send(());
                let _ = write_half.shutdown().await;
                return;
            }
        }
    }
    let _ = write_half.shutdown().await;
    if remote_eof_tx.is_some() {
        let _ = remote_abort_tx.send(());
    }
}

async fn pump_tunnel_outbound(
    stream_id: StreamId,
    outbound: Arc<OutboundQueue>,
    ops: Arc<Mutex<HashMap<StreamId, StreamHandler>>>,
    mut read_half: ReadHalf<DuplexStream>,
    drop_rx: oneshot::Receiver<bool>,
    remote_eof_rx: oneshot::Receiver<()>,
    mut remote_abort_rx: oneshot::Receiver<()>,
) {
    let mut buf = vec![0u8; MAX_HOST_STREAM_CHUNK_BYTES];
    let mut stdin_eof = false;
    let mut remote_eof = false;
    let mut drop_rx = Some(drop_rx);
    let mut remote_eof_rx = Some(remote_eof_rx);

    while !(stdin_eof && remote_eof) {
        tokio::select! {
            biased;
            _ = &mut remote_abort_rx => {
                break;
            }
            _ = async {
                match remote_eof_rx.as_mut() {
                    Some(rx) => {
                        let _ = rx.await;
                    }
                    None => std::future::pending::<()>().await,
                }
            }, if remote_eof_rx.is_some() => {
                remote_eof_rx = None;
                remote_eof = true;
            }
            res = async {
                match drop_rx.as_mut() {
                    Some(rx) => rx.await,
                    None => std::future::pending::<Result<bool, oneshot::error::RecvError>>().await,
                }
            }, if drop_rx.is_some() => {
                drop_rx = None;
                let graceful_write = matches!(res, Ok(true));
                if !(graceful_write && remote_eof) {
                    if let Ok(frame) = Frame::from_message(stream_id, &Message::StreamClose) {
                        let _ = outbound.enqueue(frame);
                    }
                    break;
                }
            }
            read_res = read_half.read(&mut buf), if !stdin_eof => {
                match read_res {
                    Ok(0) => {
                        if let Ok(frame) = Frame::from_message(
                            stream_id,
                            &Message::StreamData {
                                channel: StreamChannel::Stdin,
                                eof: true,
                                data: Vec::new(),
                            },
                        ) {
                            let _ = outbound.enqueue(frame);
                        }
                        stdin_eof = true;
                    }
                    Ok(n) => {
                        if let Ok(frame) = Frame::from_message(
                            stream_id,
                            &Message::StreamData {
                                channel: StreamChannel::Stdin,
                                eof: false,
                                data: buf[..n].to_vec(),
                            },
                        ) {
                            if outbound.enqueue(frame).is_err() {
                                break;
                            }
                        }
                    }
                    Err(_) => break,
                }
            }
        }
    }

    lock_unpoisoned(&ops).remove(&stream_id);
}

async fn pump_exec_stdin_and_cancel(
    stream_id: StreamId,
    outbound: Arc<OutboundQueue>,
    stdin_rx: &mut mpsc::Receiver<Vec<u8>>,
    cancel_rx: &mut mpsc::Receiver<()>,
    mut done_rx: oneshot::Receiver<()>,
) {
    let mut stdin_open = true;
    let mut cancel_open = true;
    loop {
        tokio::select! {
            _ = &mut done_rx => break,
            maybe_stdin = stdin_rx.recv(), if stdin_open => {
                match maybe_stdin {
                    Some(data) => {
                        for chunk in data.chunks(MAX_HOST_STREAM_CHUNK_BYTES) {
                            let Ok(frame) = Frame::from_message(
                                stream_id,
                                &Message::StreamData {
                                    channel: StreamChannel::Stdin,
                                    eof: false,
                                    data: chunk.to_vec(),
                                },
                            ) else {
                                return;
                            };
                            if outbound.enqueue(frame).is_err() {
                                return;
                            }
                        }
                    }
                    None => {
                        stdin_open = false;
                        if let Ok(frame) = Frame::from_message(
                            stream_id,
                            &Message::StreamData {
                                channel: StreamChannel::Stdin,
                                eof: true,
                                data: Vec::new(),
                            },
                        ) {
                            let _ = outbound.enqueue(frame);
                        }
                        if !cancel_open {
                            break;
                        }
                    }
                }
            }
            maybe_cancel = cancel_rx.recv(), if cancel_open => {
                match maybe_cancel {
                    Some(()) => {
                        if let Ok(frame) = Frame::from_message(stream_id, &Message::ExecCancel) {
                            if outbound.enqueue(frame).is_err() {
                                return;
                            }
                        }
                    }
                    None => {
                        cancel_open = false;
                        if !stdin_open {
                            break;
                        }
                    }
                }
            }
        }
    }
}

fn run_writer_loop(
    mut write_half: IpcWriteHalf,
    outbound: Arc<OutboundQueue>,
    ops: Arc<Mutex<HashMap<StreamId, StreamHandler>>>,
    transport_closed: Arc<AtomicBool>,
) {
    while let Some(frame) = outbound.pop_blocking() {
        if let Err(err) = write_frame(&mut write_half, &frame) {
            let msg = format!("writing protocol frame failed: {err}");
            transport_closed.store(true, Ordering::Release);
            outbound.close(Some(msg.clone()));
            let _ = write_half.shutdown();
            fail_all_pending_ops(&ops, &msg);
            return;
        }
    }
}

fn run_reader_loop(
    mut read_half: IpcReadHalf,
    outbound: Arc<OutboundQueue>,
    ops: Arc<Mutex<HashMap<StreamId, StreamHandler>>>,
    transport_closed: Arc<AtomicBool>,
    egress_tx: Option<mpsc::Sender<TunnelStream>>,
    tokio_handle: Option<tokio::runtime::Handle>,
) {
    loop {
        let frame = match read_frame(&mut read_half) {
            Ok(frame) => frame,
            Err(err) => {
                let msg = format!("reading protocol frame failed: {err}");
                transport_closed.store(true, Ordering::Release);
                outbound.close(Some(msg.clone()));
                fail_all_pending_ops(&ops, &msg);
                return;
            }
        };

        let stream_id = frame.header.stream_id;
        let msg = match frame.decode_message() {
            Ok(msg) => msg,
            Err(err) => {
                let reason = format!("decoding protocol frame failed: {err}");
                transport_closed.store(true, Ordering::Release);
                outbound.close(Some(reason.clone()));
                fail_all_pending_ops(&ops, &reason);
                return;
            }
        };

        match msg {
            Message::StreamData { channel, eof, data } => {
                enum DataDispatch {
                    Exec(mpsc::Sender<ExecOutputChunk>, OutputStreamKind),
                    Tunnel(mpsc::Sender<TunnelInbound>),
                }

                let dispatch = {
                    let mut map = lock_unpoisoned(&ops);
                    match map.get_mut(&stream_id) {
                        Some(StreamHandler::Exec { output_tx, .. }) => {
                            let kind = match channel {
                                StreamChannel::Stdout => Some(OutputStreamKind::Stdout),
                                StreamChannel::Stderr => Some(OutputStreamKind::Stderr),
                                StreamChannel::Stdin => None,
                            };
                            kind.filter(|_| !data.is_empty())
                                .map(|stream_kind| DataDispatch::Exec(output_tx.clone(), stream_kind))
                        }
                        Some(StreamHandler::CopyOut {
                            max_bytes,
                            buffer,
                            ..
                        }) if channel == StreamChannel::Stdout => {
                            let limit = *max_bytes;
                            let new_len = (buffer.len() as u64).saturating_add(data.len() as u64);
                            if new_len > limit {
                                if let Some(StreamHandler::CopyOut { mut reply_tx, .. }) =
                                    map.remove(&stream_id)
                                {
                                    if let Some(tx) = reply_tx.take() {
                                        let _ = tx.send(Err(SandboxError::BudgetExceeded(
                                            format!(
                                                "copy_out payload exceeded max_bytes ({limit})"
                                            ),
                                        )));
                                    }
                                }
                            } else {
                                buffer.extend_from_slice(&data);
                            }
                            None
                        }
                        Some(StreamHandler::Tunnel { inbound_tx, .. })
                            if channel == StreamChannel::Stdout =>
                        {
                            if !data.is_empty() || eof {
                                Some(DataDispatch::Tunnel(inbound_tx.clone()))
                            } else {
                                None
                            }
                        }
                        _ => None,
                    }
                };
                match dispatch {
                    Some(DataDispatch::Exec(tx, stream_kind)) => {
                        let _ = tx.blocking_send(ExecOutputChunk {
                            stream: stream_kind,
                            data,
                        });
                    }
                    Some(DataDispatch::Tunnel(tx)) => {
                        let _ = tx.blocking_send(TunnelInbound::Data { data, eof });
                    }
                    None => {}
                }
            }
            Message::ExecExit {
                code,
                timed_out,
                stdout_truncated,
                stderr_truncated,
            } => {
                let removed = lock_unpoisoned(&ops).remove(&stream_id);
                if let Some(StreamHandler::Exec {
                    output_tx,
                    mut exit_tx,
                    mut done_tx,
                }) = removed
                {
                    if let Some(tx) = exit_tx.take() {
                        let _ = tx.send(Ok(ExecExitStatus {
                            code,
                            timed_out,
                            stdout_truncated,
                            stderr_truncated,
                        }));
                    }
                    if let Some(tx) = done_tx.take() {
                        let _ = tx.send(());
                    }
                    drop(output_tx);
                }
            }
            Message::CopyDone { bytes_transferred } => {
                let removed = lock_unpoisoned(&ops).remove(&stream_id);
                match removed {
                    Some(StreamHandler::CopyIn { mut reply_tx }) => {
                        if let Some(tx) = reply_tx.take() {
                            let _ = tx.send(Ok(bytes_transferred));
                        }
                    }
                    Some(StreamHandler::CopyOut {
                        max_bytes,
                        buffer,
                        mut reply_tx,
                    }) => {
                        if let Some(tx) = reply_tx.take() {
                            if bytes_transferred != buffer.len() as u64
                                || bytes_transferred > max_bytes
                            {
                                let _ = tx.send(Err(SandboxError::Transport(format!(
                                    "copy_out byte count mismatch (reported {bytes_transferred}, received {})",
                                    buffer.len()
                                ))));
                            } else {
                                let _ = tx.send(Ok(buffer));
                            }
                        }
                    }
                    _ => {}
                }
            }
            Message::CopyError { message } => {
                let removed = lock_unpoisoned(&ops).remove(&stream_id);
                let err = map_guest_copy_error(&message);
                match removed {
                    Some(StreamHandler::CopyIn { mut reply_tx }) => {
                        if let Some(tx) = reply_tx.take() {
                            let _ = tx.send(Err(err));
                        }
                    }
                    Some(StreamHandler::CopyOut { mut reply_tx, .. }) => {
                        if let Some(tx) = reply_tx.take() {
                            let _ = tx.send(Err(err));
                        }
                    }
                    _ => {}
                }
            }
            Message::ConnectAck => {
                let mut map = lock_unpoisoned(&ops);
                if let Some(StreamHandler::Tunnel { connect_tx, .. }) = map.get_mut(&stream_id) {
                    if let Some(tx) = connect_tx.take() {
                        let _ = tx.send(Ok(()));
                    }
                }
            }
            Message::ConnectError { message } => {
                let removed = lock_unpoisoned(&ops).remove(&stream_id);
                if let Some(StreamHandler::Tunnel {
                    mut connect_tx,
                    inbound_tx,
                }) = removed
                {
                    if let Some(tx) = connect_tx.take() {
                        let _ = tx.send(Err(SandboxError::Transport(message)));
                    } else {
                        let _ = inbound_tx.blocking_send(TunnelInbound::RemoteClose);
                    }
                }
            }
            Message::StreamClose => {
                let removed = lock_unpoisoned(&ops).remove(&stream_id);
                if let Some(StreamHandler::Tunnel {
                    mut connect_tx,
                    inbound_tx,
                }) = removed
                {
                    if let Some(tx) = connect_tx.take() {
                        let _ = tx.send(Err(SandboxError::Transport(
                            "guest closed tunnel stream before ConnectAck".to_owned(),
                        )));
                    } else {
                        let _ = inbound_tx.blocking_send(TunnelInbound::RemoteClose);
                    }
                }
            }
            Message::EgressOpen => {
                handle_egress_open(stream_id, &egress_tx, &tokio_handle, &outbound, &ops);
            }
            Message::Ping { seq } => {
                if let Ok(frame) = Frame::from_message(stream_id, &Message::Pong { seq }) {
                    let _ = outbound.enqueue(frame);
                }
            }
            Message::Shutdown => {
                transport_closed.store(true, Ordering::Release);
                outbound.close(Some("guest VM shut down".to_owned()));
                fail_all_pending_ops(&ops, "guest VM shut down");
                return;
            }
            Message::StreamCredit { .. } | Message::Pong { .. } => {}
            other => {
                let reason = format!(
                    "unexpected guest message {:?} on stream {stream_id}",
                    other.kind()
                );
                transport_closed.store(true, Ordering::Release);
                outbound.close(Some(reason.clone()));
                fail_all_pending_ops(&ops, &reason);
                return;
            }
        }
    }
}

fn handle_egress_open(
    stream_id: StreamId,
    egress_tx: &Option<mpsc::Sender<TunnelStream>>,
    tokio_handle: &Option<tokio::runtime::Handle>,
    outbound: &Arc<OutboundQueue>,
    ops: &Arc<Mutex<HashMap<StreamId, StreamHandler>>>,
) {
    let reject = |msg: String| {
        if let Ok(frame) = Frame::from_message(stream_id, &Message::ConnectError { message: msg }) {
            let _ = outbound.enqueue(frame);
        }
    };

    if !is_guest_stream_id(stream_id) {
        reject(format!(
            "EgressOpen requires guest stream ID with high bit set, got {stream_id}"
        ));
        return;
    }

    let (Some(tx), Some(rt)) = (egress_tx.as_ref(), tokio_handle.as_ref()) else {
        reject("host egress proxy is disabled for this sandbox".to_owned());
        return;
    };

    if lock_unpoisoned(ops).contains_key(&stream_id) {
        reject(format!("duplicate guest egress stream_id {stream_id}"));
        return;
    }

    let (client_stream, tunnel_handle) = TunnelStream::channel(stream_id);
    let (inbound_tx, inbound_rx) = mpsc::channel(TUNNEL_INBOUND_CHANNEL_CAPACITY);

    match tx.try_send(client_stream) {
        Ok(()) => {
            lock_unpoisoned(ops).insert(
                stream_id,
                StreamHandler::Tunnel {
                    connect_tx: None,
                    inbound_tx,
                },
            );
            if let Ok(frame) = Frame::from_message(stream_id, &Message::ConnectAck) {
                if outbound.enqueue(frame).is_err() {
                    lock_unpoisoned(ops).remove(&stream_id);
                    return;
                }
            }
            spawn_tunnel_pumps(
                rt,
                stream_id,
                Arc::clone(outbound),
                Arc::clone(ops),
                inbound_rx,
                tunnel_handle,
            );
        }
        Err(mpsc::error::TrySendError::Full(_)) => {
            reject("host egress proxy accept queue is full".to_owned());
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            reject("host egress proxy receiver is closed".to_owned());
        }
    }
}

fn fail_all_pending_ops(ops: &Mutex<HashMap<StreamId, StreamHandler>>, reason: &str) {
    let drained: Vec<StreamHandler> = {
        let mut map = lock_unpoisoned(ops);
        map.drain().map(|(_, handler)| handler).collect()
    };

    for handler in drained {
        match handler {
            StreamHandler::Exec {
                output_tx,
                mut exit_tx,
                mut done_tx,
            } => {
                if let Some(tx) = exit_tx.take() {
                    let _ = tx.send(Err(SandboxError::Transport(reason.to_owned())));
                }
                if let Some(tx) = done_tx.take() {
                    let _ = tx.send(());
                }
                drop(output_tx);
            }
            StreamHandler::CopyIn { mut reply_tx } => {
                if let Some(tx) = reply_tx.take() {
                    let _ = tx.send(Err(SandboxError::Transport(reason.to_owned())));
                }
            }
            StreamHandler::CopyOut { mut reply_tx, .. } => {
                if let Some(tx) = reply_tx.take() {
                    let _ = tx.send(Err(SandboxError::Transport(reason.to_owned())));
                }
            }
            StreamHandler::Tunnel {
                mut connect_tx,
                inbound_tx,
            } => {
                if let Some(tx) = connect_tx.take() {
                    let _ = tx.send(Err(SandboxError::Transport(reason.to_owned())));
                }
                drop(inbound_tx);
            }
        }
    }
}

fn map_guest_copy_error(message: &str) -> SandboxError {
    if message.contains("exceeds") || message.contains("budget") {
        SandboxError::BudgetExceeded(message.to_owned())
    } else {
        SandboxError::PolicyViolation(message.to_owned())
    }
}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;

    #[test]
    fn driver_config_validates_timeouts_and_override_paths() {
        let valid = QemuDriverConfig::default();
        assert!(QemuVmDriver::new(valid).is_ok());

        let zero_boot = QemuDriverConfig {
            boot_timeout: Duration::ZERO,
            ..Default::default()
        };
        assert!(matches!(
            QemuVmDriver::new(zero_boot),
            Err(SandboxError::InvalidSpec(_))
        ));

        let zero_io = QemuDriverConfig {
            io_timeout: Duration::ZERO,
            ..Default::default()
        };
        assert!(matches!(
            QemuVmDriver::new(zero_io),
            Err(SandboxError::InvalidSpec(_))
        ));

        let empty_bin = QemuDriverConfig {
            qemu_bin: Some(PathBuf::new()),
            ..Default::default()
        };
        assert!(matches!(
            QemuVmDriver::new(empty_bin),
            Err(SandboxError::InvalidSpec(_))
        ));
    }

    #[tokio::test]
    async fn multiplexed_session_handles_exec_cancel_copy_in_copy_out_and_shutdown() {
        let listener = AgentIpcEndpoint::bind_temp("drv-mux").unwrap();
        let sock_path = listener.socket_path().to_path_buf();

        let guest_thread = thread::spawn(move || {
            let mut client = IpcStream::connect(&sock_path).unwrap();
            let mut copy_in_buf: HashMap<StreamId, Vec<u8>> = HashMap::new();

            while let Ok(frame) = read_frame(&mut client) {
                let sid = frame.header.stream_id;
                match frame.decode_message().unwrap() {
                    Message::ExecStart { argv, .. } => {
                        if argv.first().map(String::as_str) == Some("echo") {
                            let out = format!("out:{}", argv[1..].join(" ")).into_bytes();
                            write_frame(
                                &mut client,
                                &Frame::from_message(
                                    sid,
                                    &Message::StreamData {
                                        channel: StreamChannel::Stdout,
                                        eof: true,
                                        data: out,
                                    },
                                )
                                .unwrap(),
                            )
                            .unwrap();
                            write_frame(
                                &mut client,
                                &Frame::from_message(
                                    sid,
                                    &Message::ExecExit {
                                        code: Some(0),
                                        timed_out: false,
                                        stdout_truncated: false,
                                        stderr_truncated: false,
                                    },
                                )
                                .unwrap(),
                            )
                            .unwrap();
                        }
                    }
                    Message::ExecCancel => {
                        write_frame(
                            &mut client,
                            &Frame::from_message(
                                sid,
                                &Message::ExecExit {
                                    code: Some(130),
                                    timed_out: false,
                                    stdout_truncated: false,
                                    stderr_truncated: false,
                                },
                            )
                            .unwrap(),
                        )
                        .unwrap();
                    }
                    Message::CopyInStart { .. } => {
                        copy_in_buf.insert(sid, Vec::new());
                    }
                    Message::StreamData {
                        channel: StreamChannel::Stdin,
                        eof,
                        data,
                    } => {
                        if let Some(buf) = copy_in_buf.get_mut(&sid) {
                            buf.extend_from_slice(&data);
                            if eof {
                                let total = buf.len() as u64;
                                write_frame(
                                    &mut client,
                                    &Frame::from_message(
                                        sid,
                                        &Message::CopyDone {
                                            bytes_transferred: total,
                                        },
                                    )
                                    .unwrap(),
                                )
                                .unwrap();
                                copy_in_buf.remove(&sid);
                            }
                        }
                    }
                    Message::CopyOutStart { src_guest, .. } => {
                        if src_guest == "/bad" {
                            write_frame(
                                &mut client,
                                &Frame::from_message(
                                    sid,
                                    &Message::CopyError {
                                        message: "symlink traversal rejected".to_owned(),
                                    },
                                )
                                .unwrap(),
                            )
                            .unwrap();
                        } else {
                            let tar_payload = b"mock-tar-bytes".to_vec();
                            write_frame(
                                &mut client,
                                &Frame::from_message(
                                    sid,
                                    &Message::StreamData {
                                        channel: StreamChannel::Stdout,
                                        eof: true,
                                        data: tar_payload.clone(),
                                    },
                                )
                                .unwrap(),
                            )
                            .unwrap();
                            write_frame(
                                &mut client,
                                &Frame::from_message(
                                    sid,
                                    &Message::CopyDone {
                                        bytes_transferred: tar_payload.len() as u64,
                                    },
                                )
                                .unwrap(),
                            )
                            .unwrap();
                        }
                    }
                    Message::Shutdown => {
                        write_frame(
                            &mut client,
                            &Frame::from_message(StreamId(0), &Message::Shutdown).unwrap(),
                        )
                        .unwrap();
                        break;
                    }
                    _ => {}
                }
            }
        });

        let host_stream = listener.accept_timeout(Duration::from_secs(2)).unwrap();
        let session = QemuVmSession::from_test_stream(host_stream, Duration::from_secs(2)).unwrap();

        let stream_a = session
            .exec_stream(ExecRequest {
                target: ExecTarget::Guest,
                argv: vec!["echo".into(), "hello".into()],
                env: BTreeMap::new(),
                cwd: None,
                user: None,
                deadline: Duration::from_secs(5),
                stdout_budget_bytes: 1024,
                stderr_budget_bytes: 1024,
            })
            .await
            .unwrap();
        let out_a = stream_a.collect().await.unwrap();
        assert_eq!(out_a.stdout, b"out:hello");
        assert_eq!(out_a.exit.code, Some(0));

        // Concurrent cancelable exec + copy_in + copy_out + policy CopyError.
        let mut cancel_stream = session
            .exec_stream(ExecRequest {
                target: ExecTarget::Container {
                    id_or_name: "app".into(),
                },
                argv: vec!["sleep".into(), "60".into()],
                env: BTreeMap::new(),
                cwd: None,
                user: None,
                deadline: Duration::from_secs(5),
                stdout_budget_bytes: 1024,
                stderr_budget_bytes: 1024,
            })
            .await
            .unwrap();
        cancel_stream.cancel().unwrap();

        let (copy_in_res, copy_out_ok, copy_out_err, canceled_exit) = tokio::join!(
            session.copy_in_tar("/workspace", vec![7u8; 70_000], 128 * 1024),
            session.copy_out_tar("/workspace/out", 4096),
            session.copy_out_tar("/bad", 4096),
            cancel_stream.wait_exit(),
        );
        assert_eq!(copy_in_res.unwrap(), 70_000);
        assert_eq!(copy_out_ok.unwrap(), b"mock-tar-bytes");
        assert!(matches!(copy_out_err, Err(SandboxError::PolicyViolation(_))));
        assert_eq!(canceled_exit.unwrap().code, Some(130));

        assert!(session
            .graceful_shutdown(Duration::from_millis(500))
            .await
            .unwrap());
        assert_eq!(session.current_rss_bytes(), None);
        guest_thread.join().unwrap();
    }

    #[tokio::test]
    async fn kill_orphan_process_returns_false_for_missing_or_mismatched_pid() {
        let driver = QemuVmDriver::new(QemuDriverConfig::default()).unwrap();
        let killed = driver
            .kill_orphan_process(std::process::id(), u64::MAX - 1)
            .await
            .unwrap();
        assert!(!killed);
    }

    #[test]
    fn bind_agent_endpoint_creates_owner_only_ipc_subdir_inside_standard_work_dir() {
        struct CleanDir(PathBuf);
        impl Drop for CleanDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        let work_dir = std::env::temp_dir().join(format!("mpb-{}", std::process::id()));
        let _clean = CleanDir(work_dir.clone());
        std::fs::create_dir_all(&work_dir).unwrap();

        let cfg = QemuDriverConfig::default();
        let (endpoint, artifacts) = bind_agent_endpoint(&cfg, &work_dir).unwrap();
        let sock = endpoint.socket_path().to_path_buf();
        if validate_socket_path(&work_dir.join("ipc").join("a.sock")).is_ok() {
            assert_eq!(sock, work_dir.join("ipc").join("a.sock"));
            assert!(artifacts.contains(&work_dir.join("ipc")));
        }
        assert!(sock.exists());
        drop(endpoint);
        assert!(!sock.exists());
    }

    #[tokio::test]
    async fn tunnel_supports_duplex_independent_half_closes_connect_errors_and_drop_close() {
        use sandbox_protocol::Lane;

        let listener = AgentIpcEndpoint::bind_temp("drv-tunnel").unwrap();
        let sock_path = listener.socket_path().to_path_buf();

        let (drop_observed_tx, mut drop_observed_rx) = mpsc::unbounded_channel();
        let (guest_half_close_rx_tx, guest_half_close_rx_rx) = oneshot::channel();

        let mut guest_half_close_rx_tx = Some(guest_half_close_rx_tx);

        let guest_thread = thread::spawn(move || {
            let mut client = IpcStream::connect(&sock_path).unwrap();
            let mut targets: HashMap<StreamId, StreamTargetWire> = HashMap::new();
            let mut stdin_bufs: HashMap<StreamId, Vec<u8>> = HashMap::new();
            let mut saw_unexpected_close_after_remote = false;

            while let Ok(frame) = read_frame(&mut client) {
                let sid = frame.header.stream_id;
                match frame.decode_message().unwrap() {
                    Message::ConnectStart { target } => {
                        match target {
                            StreamTargetWire::GuestLoopbackTcp { port: 9999 } => {
                                write_frame(
                                    &mut client,
                                    &Frame::from_message(
                                        sid,
                                        &Message::ConnectError {
                                            message: "connection refused on 127.0.0.1:9999"
                                                .to_owned(),
                                        },
                                    )
                                    .unwrap(),
                                )
                                .unwrap();
                            }
                            StreamTargetWire::GuestLoopbackTcp { port: 7001 } => {
                                // Guest immediately sends ConnectAck + early banner + Stdout EOF.
                                targets.insert(sid, target);
                                stdin_bufs.insert(sid, Vec::new());
                                write_frame(
                                    &mut client,
                                    &Frame::from_message(sid, &Message::ConnectAck).unwrap(),
                                )
                                .unwrap();
                                write_frame(
                                    &mut client,
                                    &Frame::from_message(
                                        sid,
                                        &Message::StreamData {
                                            channel: StreamChannel::Stdout,
                                            eof: true,
                                            data: b"early-banner".to_vec(),
                                        },
                                    )
                                    .unwrap(),
                                )
                                .unwrap();
                            }
                            StreamTargetWire::GuestLoopbackTcp { port: 7003 } => {
                                targets.insert(sid, target);
                                stdin_bufs.insert(sid, Vec::new());
                                write_frame(
                                    &mut client,
                                    &Frame::from_message(sid, &Message::ConnectAck).unwrap(),
                                )
                                .unwrap();
                                // Guest immediately aborts with StreamClose after sending partial data.
                                write_frame(
                                    &mut client,
                                    &Frame::from_message(
                                        sid,
                                        &Message::StreamData {
                                            channel: StreamChannel::Stdout,
                                            eof: false,
                                            data: b"partial".to_vec(),
                                        },
                                    )
                                    .unwrap(),
                                )
                                .unwrap();
                                write_frame(
                                    &mut client,
                                    &Frame::from_message(sid, &Message::StreamClose).unwrap(),
                                )
                                .unwrap();
                            }
                            other => {
                                targets.insert(sid, other);
                                stdin_bufs.insert(sid, Vec::new());
                                write_frame(
                                    &mut client,
                                    &Frame::from_message(sid, &Message::ConnectAck).unwrap(),
                                )
                                .unwrap();
                            }
                        }
                    }
                    Message::StreamData {
                        channel: StreamChannel::Stdin,
                        eof,
                        data,
                    } => {
                        if let Some(buf) = stdin_bufs.get_mut(&sid) {
                            buf.extend_from_slice(&data);
                            if eof {
                                let received = stdin_bufs.remove(&sid).unwrap_or_default();
                                match targets.remove(&sid) {
                                    Some(StreamTargetWire::PodmanUnixSocket) => {
                                        // Host-to-guest half-close finished; reply in multiple chunks.
                                        let mid = received.len() / 2;
                                        write_frame(
                                            &mut client,
                                            &Frame::from_message(
                                                sid,
                                                &Message::StreamData {
                                                    channel: StreamChannel::Stdout,
                                                    eof: false,
                                                    data: received[..mid].to_vec(),
                                                },
                                            )
                                            .unwrap(),
                                        )
                                        .unwrap();
                                        write_frame(
                                            &mut client,
                                            &Frame::from_message(
                                                sid,
                                                &Message::StreamData {
                                                    channel: StreamChannel::Stdout,
                                                    eof: true,
                                                    data: received[mid..].to_vec(),
                                                },
                                            )
                                            .unwrap(),
                                        )
                                        .unwrap();
                                    }
                                    Some(StreamTargetWire::GuestLoopbackTcp { port: 7001 }) => {
                                        if let Some(tx) = guest_half_close_rx_tx.take() {
                                            tx.send(received).unwrap();
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                    Message::StreamClose => {
                        assert_eq!(frame.header.lane, Lane::Control);
                        if targets.get(&sid) == Some(&StreamTargetWire::GuestLoopbackTcp { port: 7002 })
                        {
                            let _ = drop_observed_tx.send(sid);
                        } else if targets.get(&sid)
                            == Some(&StreamTargetWire::GuestLoopbackTcp { port: 7003 })
                        {
                            saw_unexpected_close_after_remote = true;
                        }
                        targets.remove(&sid);
                        stdin_bufs.remove(&sid);
                    }
                    Message::Shutdown => {
                        write_frame(
                            &mut client,
                            &Frame::from_message(StreamId(0), &Message::Shutdown).unwrap(),
                        )
                        .unwrap();
                        break;
                    }
                    _ => {}
                }
            }
            saw_unexpected_close_after_remote
        });

        let host_stream = listener.accept_timeout(Duration::from_secs(2)).unwrap();
        let session = QemuVmSession::from_test_stream(host_stream, Duration::from_secs(2)).unwrap();

        // 1. Port 0 rejected upfront without sending ConnectStart.
        assert!(matches!(
            session
                .open_tunnel(StreamTargetWire::GuestLoopbackTcp { port: 0 })
                .await,
            Err(SandboxError::InvalidSpec(_))
        ));

        // 2. Guest ConnectError propagates as Transport error.
        let err = session
            .open_tunnel(StreamTargetWire::GuestLoopbackTcp { port: 9999 })
            .await
            .unwrap_err();
        assert!(matches!(err, SandboxError::Transport(msg) if msg.contains("connection refused")));

        // 3. PodmanUnixSocket full-duplex >64 KiB + host-to-guest half-close while guest writes back.
        let mut podman = session
            .open_tunnel(StreamTargetWire::PodmanUnixSocket)
            .await
            .unwrap();
        let big_payload = vec![0x5Au8; 90_000];
        podman.write_all(&big_payload).await.unwrap();
        podman.shutdown().await.unwrap();

        let mut echoed = Vec::new();
        podman.read_to_end(&mut echoed).await.unwrap();
        assert_eq!(echoed, big_payload);
        drop(podman);

        // 4. Guest-to-host half-close (early banner + Stdout EOF) while host keeps writing Stdin.
        let mut guest_closed = session
            .open_tunnel(StreamTargetWire::GuestLoopbackTcp { port: 7001 })
            .await
            .unwrap();
        let mut banner = Vec::new();
        guest_closed.read_to_end(&mut banner).await.unwrap();
        assert_eq!(banner, b"early-banner");

        guest_closed.write_all(b"after-guest-eof").await.unwrap();
        guest_closed.shutdown().await.unwrap();
        drop(guest_closed);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), guest_half_close_rx_rx)
                .await
                .unwrap()
                .unwrap(),
            b"after-guest-eof"
        );

        // 5. Early drop without shutdown sends Message::StreamClose on Lane::Control.
        let early_drop = session
            .open_tunnel(StreamTargetWire::GuestLoopbackTcp { port: 7002 })
            .await
            .unwrap();
        let expected_sid = early_drop.stream_id();
        drop(early_drop);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), drop_observed_rx.recv())
                .await
                .unwrap()
                .unwrap(),
            expected_sid
        );

        // 6. Remote StreamClose closes host reader cleanly after buffered partial data without echo.
        let mut remote_closed = session
            .open_tunnel(StreamTargetWire::GuestLoopbackTcp { port: 7003 })
            .await
            .unwrap();
        let mut partial = Vec::new();
        remote_closed.read_to_end(&mut partial).await.unwrap();
        assert_eq!(partial, b"partial");
        drop(remote_closed);
        tokio::task::yield_now().await;

        assert!(session
            .graceful_shutdown(Duration::from_millis(500))
            .await
            .unwrap());
        assert!(!guest_thread.join().unwrap());
    }

    #[tokio::test]
    async fn egress_open_accepts_guest_stream_delivers_duplex_and_half_close_on_egress_rx() {
        use sandbox_protocol::GUEST_STREAM_ID_BIT;

        let listener = AgentIpcEndpoint::bind_temp("drv-egress-ok").unwrap();
        let sock_path = listener.socket_path().to_path_buf();
        let (guest_done_tx, guest_done_rx) = oneshot::channel();

        let guest_thread = thread::spawn(move || {
            let mut client = IpcStream::connect(&sock_path).unwrap();
            let guest_sid = StreamId(GUEST_STREAM_ID_BIT | 1);

            write_frame(
                &mut client,
                &Frame::from_message(guest_sid, &Message::EgressOpen).unwrap(),
            )
            .unwrap();

            let ack = read_frame(&mut client).unwrap();
            assert_eq!(ack.header.stream_id, guest_sid);
            assert_eq!(ack.decode_message().unwrap(), Message::ConnectAck);

            // Guest writes >64 KiB request via Stdout and half-closes its write side.
            let mut req = vec![b'Q'; 70_000];
            req.extend_from_slice(b"-REQ");
            for (idx, chunk) in req.chunks(64 * 1024).enumerate() {
                let eof = idx == 1;
                write_frame(
                    &mut client,
                    &Frame::from_message(
                        guest_sid,
                        &Message::StreamData {
                            channel: StreamChannel::Stdout,
                            eof,
                            data: chunk.to_vec(),
                        },
                    )
                    .unwrap(),
                )
                .unwrap();
            }

            // Read Host proxy response via Stdin until eof=true.
            let mut resp = Vec::new();
            loop {
                let f = read_frame(&mut client).unwrap();
                match f.decode_message().unwrap() {
                    Message::StreamData {
                        channel: StreamChannel::Stdin,
                        eof,
                        data,
                    } if f.header.stream_id == guest_sid => {
                        resp.extend_from_slice(&data);
                        if eof {
                            break;
                        }
                    }
                    other => panic!("unexpected frame on guest side: {other:?}"),
                }
            }
            let _ = guest_done_tx.send(resp);
            while let Ok(frame) = read_frame(&mut client) {
                if matches!(frame.decode_message(), Ok(Message::Shutdown)) {
                    let _ = write_frame(
                        &mut client,
                        &Frame::from_message(StreamId(0), &Message::Shutdown).unwrap(),
                    );
                    break;
                }
            }
        });

        let host_stream = listener.accept_timeout(Duration::from_secs(2)).unwrap();
        let (session, mut egress_rx) =
            QemuVmSession::from_test_stream_with_egress(host_stream, Duration::from_secs(2))
                .unwrap();

        // Host stream ID allocation stays strictly within 1..=HOST_STREAM_ID_MAX.
        assert_eq!(session.allocate_stream_id().unwrap(), StreamId(1));
        session
            .next_stream_id
            .store(HOST_STREAM_ID_MAX, Ordering::Release);
        assert_eq!(
            session.allocate_stream_id().unwrap(),
            StreamId(HOST_STREAM_ID_MAX)
        );
        assert!(matches!(
            session.allocate_stream_id(),
            Err(SandboxError::Internal(_))
        ));

        let mut egress_stream = tokio::time::timeout(Duration::from_secs(2), egress_rx.recv())
            .await
            .expect("egress_rx receives stream")
            .expect("egress_rx open");
        assert_eq!(
            egress_stream.stream_id(),
            StreamId(GUEST_STREAM_ID_BIT | 1)
        );

        let mut got_req = Vec::new();
        egress_stream.read_to_end(&mut got_req).await.unwrap();
        assert_eq!(got_req.len(), 70_004);
        assert!(got_req[..70_000].iter().all(|&b| b == b'Q'));
        assert_eq!(&got_req[70_000..], b"-REQ");

        egress_stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
        egress_stream.shutdown().await.unwrap();
        drop(egress_stream);

        let guest_resp = tokio::time::timeout(Duration::from_secs(2), guest_done_rx)
            .await
            .expect("guest receives response")
            .expect("guest channel alive");
        assert_eq!(guest_resp, b"HTTP/1.1 200 OK\r\n\r\n");

        assert!(session
            .graceful_shutdown(Duration::from_millis(500))
            .await
            .unwrap());
        guest_thread.join().unwrap();
    }

    #[tokio::test]
    async fn egress_open_rejects_when_egress_disabled_or_invalid_stream_id() {
        use sandbox_protocol::GUEST_STREAM_ID_BIT;

        // 1. Egress disabled (Isolated): EgressOpen receives ConnectError.
        let listener = AgentIpcEndpoint::bind_temp("drv-egress-off").unwrap();
        let sock_path = listener.socket_path().to_path_buf();
        let (done1_tx, done1_rx) = oneshot::channel();

        let guest_thread = thread::spawn(move || {
            let mut client = IpcStream::connect(&sock_path).unwrap();
            let guest_sid = StreamId(GUEST_STREAM_ID_BIT | 1);
            write_frame(
                &mut client,
                &Frame::from_message(guest_sid, &Message::EgressOpen).unwrap(),
            )
            .unwrap();

            let reply = read_frame(&mut client).unwrap();
            assert_eq!(reply.header.stream_id, guest_sid);
            assert!(matches!(
                reply.decode_message().unwrap(),
                Message::ConnectError { message } if message.contains("disabled")
            ));
            let _ = done1_tx.send(());

            while let Ok(frame) = read_frame(&mut client) {
                if matches!(frame.decode_message(), Ok(Message::Shutdown)) {
                    let _ = write_frame(
                        &mut client,
                        &Frame::from_message(StreamId(0), &Message::Shutdown).unwrap(),
                    );
                    break;
                }
            }
        });

        let host_stream = listener.accept_timeout(Duration::from_secs(2)).unwrap();
        let session = QemuVmSession::from_test_stream(host_stream, Duration::from_secs(2)).unwrap();
        tokio::time::timeout(Duration::from_secs(2), done1_rx)
            .await
            .expect("guest receives ConnectError")
            .expect("done1 channel alive");
        assert!(session
            .graceful_shutdown(Duration::from_millis(500))
            .await
            .unwrap());
        guest_thread.join().unwrap();

        // 2. Egress enabled, but guest sends non-high-bit StreamId(1): ConnectError.
        let listener2 = AgentIpcEndpoint::bind_temp("drv-egress-bad-sid").unwrap();
        let sock_path2 = listener2.socket_path().to_path_buf();
        let (done2_tx, done2_rx) = oneshot::channel();
        let guest_thread2 = thread::spawn(move || {
            let mut client = IpcStream::connect(&sock_path2).unwrap();
            write_frame(
                &mut client,
                &Frame::from_message(StreamId(1), &Message::EgressOpen).unwrap(),
            )
            .unwrap();
            let reply = read_frame(&mut client).unwrap();
            assert_eq!(reply.header.stream_id, StreamId(1));
            assert!(matches!(
                reply.decode_message().unwrap(),
                Message::ConnectError { message } if message.contains("high bit")
            ));
            let _ = done2_tx.send(());

            while let Ok(frame) = read_frame(&mut client) {
                if matches!(frame.decode_message(), Ok(Message::Shutdown)) {
                    let _ = write_frame(
                        &mut client,
                        &Frame::from_message(StreamId(0), &Message::Shutdown).unwrap(),
                    );
                    break;
                }
            }
        });

        let host_stream2 = listener2.accept_timeout(Duration::from_secs(2)).unwrap();
        let (session2, mut egress_rx2) =
            QemuVmSession::from_test_stream_with_egress(host_stream2, Duration::from_secs(2))
                .unwrap();
        tokio::time::timeout(Duration::from_secs(2), done2_rx)
            .await
            .expect("guest receives ConnectError for invalid stream id")
            .expect("done2 channel alive");
        assert!(session2
            .graceful_shutdown(Duration::from_millis(500))
            .await
            .unwrap());
        guest_thread2.join().unwrap();
        assert!(egress_rx2.try_recv().is_err());
    }

    #[test]
    fn configure_guest_network_accepts_nonzero_port_and_rejects_zero_port() {
        let listener = AgentIpcEndpoint::bind_temp("drv-cfg-net").unwrap();
        let sock_path = listener.socket_path().to_path_buf();

        let guest = thread::spawn(move || {
            for reply_port in [3128u16, 0u16] {
                let mut client = IpcStream::connect(&sock_path).unwrap();
                let req = read_frame(&mut client).unwrap();
                assert_eq!(req.header.stream_id, StreamId(0));
                assert_eq!(
                    req.decode_message().unwrap(),
                    Message::ConfigureNetwork {
                        enable_egress_proxy: true,
                        proxy_port: DEFAULT_EGRESS_PROXY_PORT,
                    }
                );
                write_frame(
                    &mut client,
                    &Frame::from_message(
                        StreamId(0),
                        &Message::ConfigureNetworkAck {
                            proxy_port: reply_port,
                        },
                    )
                    .unwrap(),
                )
                .unwrap();
            }
        });

        let mut host1 = listener.accept_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(
            configure_guest_network(&mut host1, DEFAULT_EGRESS_PROXY_PORT).unwrap(),
            3128
        );

        let mut host2 = listener.accept_timeout(Duration::from_secs(2)).unwrap();
        assert!(matches!(
            configure_guest_network(&mut host2, DEFAULT_EGRESS_PROXY_PORT),
            Err(SandboxError::Transport(msg)) if msg.contains("port 0")
        ));

        guest.join().unwrap();
    }
}
