//! Layer 3 VMM driver adapter implementing [`VmRuntimePort`] and [`VmSessionPort`]
//! over confined QEMU processes and multiplexed `virtio-serial` protocol frames.

use std::collections::HashMap;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use sandbox_core::{
    CapabilityReport, EnforcementLevel, ExecExitStatus, ExecRequest, ExecTarget, GuestArch,
    NetworkPolicy, SandboxError,
};
use sandbox_protocol::{
    is_guest_stream_id, read_frame, stream_frame_credit_cost, write_frame, ExecTargetWire, Frame,
    Lane, Message, PriorityFrameQueue, StreamChannel, StreamId, StreamTargetWire,
    HOST_STREAM_ID_MAX, INITIAL_STREAM_CREDIT_BYTES, STREAM_FRAME_OVERHEAD_BYTES,
};
use sandbox_runtime::{
    validate_guest_path, ExecOutputChunk, ExecStream, OutputStreamKind, TunnelStream,
    TunnelStreamHandle, VmBootConfig, VmBootOutcome, VmRuntimePort, VmSessionPort,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf};
use tokio::sync::{mpsc, oneshot, watch, Mutex as AsyncMutex, Notify};

use crate::accel::{
    discover_qemu_binary_for_arch, probe_available_accelerators_for_arch, Accelerator,
};
use crate::ipc::{
    validate_socket_path, AgentIpcEndpoint, IpcReadHalf, IpcStream, IpcWriteHalf,
};
use crate::launch::QemuLaunchConfig;
use crate::process::{
    kill_verified_orphan_process, spawn_bounded_pipe_file_sink, ConfinedProcess, ProcessLaunchSpec,
    ProcessStdio,
};
use crate::spike::{
    build_candidate_attempts, combine_fallback_error, is_retryable_boot_error, perform_handshake,
    protocol_err, read_attempt_diagnostics, send_protocol_message, ACCEPT_POLL_SLICE,
};

const MAX_HOST_STREAM_CHUNK_BYTES: usize = 64 * 1024;
// shortcut: fixed 4096-frame / 4 MiB host->guest control lane cap closes session on overflow, add async caller backpressure on control enqueue if legit burst exceeds 4096 queued control frames
const MAX_OUTBOUND_CONTROL_FRAMES: usize = 4096;
const MAX_OUTBOUND_CONTROL_QUEUE_BYTES: usize = 4 * 1024 * 1024;
const MAX_OUTBOUND_DATA_QUEUE_BYTES: usize = 4 * 1024 * 1024;
const MAX_STREAM_INBOUND_BUFFER_BYTES: usize = 2 * 1024 * 1024;
const MAX_ACTIVE_GUEST_EGRESS_STREAMS: usize = 64;
const EGRESS_ACCEPT_CHANNEL_CAPACITY: usize = 64;
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
        validate_boot_config(&self.config, &config)?;

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

fn validate_boot_config(
    driver_cfg: &QemuDriverConfig,
    config: &VmBootConfig,
) -> Result<(), SandboxError> {
    config.spec.validate_for_host_os(std::env::consts::OS)?;
    if let Some(bundle_arch) = config.overlay.guest_arch {
        if bundle_arch != driver_cfg.arch {
            return Err(SandboxError::InvalidSpec(format!(
                "bundle guest_arch '{}' does not match configured QEMU driver arch '{}'",
                bundle_arch, driver_cfg.arch
            )));
        }
    }

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
    // Check cancellation before binding sockets or directories (especially before fallback attempts).
    boot_cfg.record_boot_progress(None, &[])?;

    let (endpoint, mut artifact_paths) = bind_agent_endpoint(driver_cfg, &boot_cfg.work_dir)?;
    let socket_path = endpoint.socket_path().to_path_buf();

    let serial_log_path = boot_cfg.work_dir.join("serial.log");
    let stderr_log_path = boot_cfg.work_dir.join("qemu-stderr.log");
    artifact_paths.push(stderr_log_path.clone());

    // Persist any external IPC artifact paths in the crash journal before spawning QEMU.
    boot_cfg.record_boot_progress(None, &artifact_paths)?;

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
        serial_log_path: None,
        network: boot_cfg.spec.network.clone(),
    };
    let args = launch_cfg.build_args()?;

    let stderr_file = File::create(&stderr_log_path).map_err(|err| {
        SandboxError::Transport(format!(
            "failed to create QEMU stderr log '{}': {err}",
            stderr_log_path.display()
        ))
    })?;
    let (stderr_rx, stderr_tx) = std::io::pipe().map_err(|err| {
        SandboxError::Transport(format!("failed to create QEMU stderr pipe: {err}"))
    })?;
    spawn_bounded_pipe_file_sink(stderr_rx, stderr_file, 512 * 1024);

    let mut launch_spec = ProcessLaunchSpec::new(qemu_bin, args);
    launch_spec.stderr = ProcessStdio::PipeWriter(stderr_tx);
    launch_spec.cpu_quota_millicores = boot_cfg.spec.budget.host_cpu_quota_Millicores;
    launch_spec.memory_limit_bytes = boot_cfg
        .spec
        .budget
        .host_rss_budget_mb
        .map(|mb| u64::from(mb) * 1024 * 1024);
    let mut process = ConfinedProcess::spawn(launch_spec)?;
    let identity = process.start_identity();
    if let Err(err) = boot_cfg.record_boot_progress(
        Some((identity.pid, identity.start_token)),
        &artifact_paths,
    ) {
        let _ = process.kill_and_wait();
        return Err(err);
    }

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

    let proc_caps = process.resource_capabilities();
    let mut session = QemuVmSession::start(
        Some(process),
        Some(endpoint),
        stream,
        artifact_paths.clone(),
        driver_cfg.io_timeout,
        identity.pid,
        identity.start_token,
        egress_tx,
    )?;
    session.accelerator = Some(accel);

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
            egress_filter: if matches!(boot_cfg.spec.network, NetworkPolicy::Unrestricted) {
                EnforcementLevel::Unsupported
            } else {
                EnforcementLevel::HardLimit
            },
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
    data_queued_by_stream: HashMap<StreamId, usize>,
    closed: bool,
    error: Option<String>,
}

struct OutboundQueue {
    state: Mutex<OutboundQueueState>,
    closed_flag: AtomicBool,
    cv: Condvar,
    space_notify: Notify,
}

impl OutboundQueue {
    fn new() -> Self {
        Self {
            state: Mutex::new(OutboundQueueState {
                queue: PriorityFrameQueue::new(),
                data_queued_by_stream: HashMap::new(),
                closed: false,
                error: None,
            }),
            closed_flag: AtomicBool::new(false),
            cv: Condvar::new(),
            space_notify: Notify::new(),
        }
    }

    fn is_closed(&self) -> bool {
        self.closed_flag.load(Ordering::Acquire)
    }

    fn enqueue_control(&self, frame: Frame) -> Result<(), SandboxError> {
        debug_assert_eq!(frame.header.lane, Lane::Control);
        let mut guard = lock_unpoisoned(&self.state);
        if guard.closed {
            return Err(SandboxError::Transport(
                guard
                    .error
                    .clone()
                    .unwrap_or_else(|| "QEMU IPC transport is closed".to_owned()),
            ));
        }
        if guard.queue.control_len() >= MAX_OUTBOUND_CONTROL_FRAMES
            || guard.queue.control_bytes() >= MAX_OUTBOUND_CONTROL_QUEUE_BYTES
        {
            let reason = format!(
                "QEMU IPC outbound control queue exceeded capacity (frames={}, bytes={})",
                guard.queue.control_len(),
                guard.queue.control_bytes()
            );
            guard.closed = true;
            if guard.error.is_none() {
                guard.error = Some(reason.clone());
            }
            self.closed_flag.store(true, Ordering::Release);
            self.cv.notify_all();
            self.space_notify.notify_waiters();
            return Err(SandboxError::Transport(reason));
        }
        guard.queue.push(frame);
        self.cv.notify_one();
        Ok(())
    }

    async fn enqueue_data(&self, frame: Frame) -> Result<(), SandboxError> {
        debug_assert_eq!(frame.header.lane, Lane::Data);
        let mut pending = Some(frame);
        loop {
            let notified = self.space_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut guard = lock_unpoisoned(&self.state);
                if guard.closed {
                    return Err(SandboxError::Transport(
                        guard
                            .error
                            .clone()
                            .unwrap_or_else(|| "QEMU IPC transport is closed".to_owned()),
                    ));
                }
                if guard.queue.data_len() == 0
                    || guard.queue.data_bytes() < MAX_OUTBOUND_DATA_QUEUE_BYTES
                {
                    let frame = pending.take().expect("frame present");
                    *guard
                        .data_queued_by_stream
                        .entry(frame.header.stream_id)
                        .or_insert(0) += 1;
                    guard.queue.push(frame);
                    self.cv.notify_one();
                    return Ok(());
                }
            }
            notified.await;
        }
    }

    async fn wait_stream_data_flushed(&self, stream_id: StreamId) {
        loop {
            let notified = self.space_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let guard = lock_unpoisoned(&self.state);
                if guard.closed
                    || guard
                        .data_queued_by_stream
                        .get(&stream_id)
                        .copied()
                        .unwrap_or(0)
                        == 0
                {
                    return;
                }
            }
            notified.await;
        }
    }

    fn close(&self, reason: Option<String>) {
        let mut guard = lock_unpoisoned(&self.state);
        guard.closed = true;
        if guard.error.is_none() {
            guard.error = reason;
        }
        self.closed_flag.store(true, Ordering::Release);
        self.cv.notify_all();
        self.space_notify.notify_waiters();
    }

    fn pop_blocking(&self) -> Option<Frame> {
        let mut guard = lock_unpoisoned(&self.state);
        loop {
            if let Some(frame) = guard.queue.pop() {
                let was_data = frame.header.lane == Lane::Data;
                if was_data {
                    let sid = frame.header.stream_id;
                    if let Some(count) = guard.data_queued_by_stream.get_mut(&sid) {
                        *count = count.saturating_sub(1);
                        if *count == 0 {
                            guard.data_queued_by_stream.remove(&sid);
                        }
                    }
                }
                drop(guard);
                if was_data {
                    self.space_notify.notify_waiters();
                }
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

struct StdinCreditState {
    available: u64,
    closed: bool,
}

struct StdinCreditWindow {
    state: Mutex<StdinCreditState>,
    notify: Notify,
}

impl StdinCreditWindow {
    fn new(initial_bytes: u32) -> Self {
        Self {
            state: Mutex::new(StdinCreditState {
                available: u64::from(initial_bytes),
                closed: false,
            }),
            notify: Notify::new(),
        }
    }

    fn grant(&self, bytes: u32) {
        if bytes == 0 {
            return;
        }
        let mut guard = lock_unpoisoned(&self.state);
        if !guard.closed {
            guard.available = guard.available.saturating_add(u64::from(bytes));
            self.notify.notify_waiters();
        }
    }

    fn close(&self) {
        let mut guard = lock_unpoisoned(&self.state);
        guard.closed = true;
        self.notify.notify_waiters();
    }

    /// Cancel-safe wait for at least 1 payload byte of `Stdin` credit (excluding frame overhead)
    /// without deducting it yet.
    async fn wait_available(&self, max_chunk: usize) -> Option<usize> {
        if max_chunk == 0 {
            return Some(0);
        }
        let overhead = STREAM_FRAME_OVERHEAD_BYTES as u64;
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let guard = lock_unpoisoned(&self.state);
                if guard.closed {
                    return None;
                }
                if guard.available > overhead {
                    let allowed = usize::try_from(guard.available - overhead).unwrap_or(usize::MAX);
                    return Some(max_chunk.min(allowed));
                }
            }
            notified.await;
        }
    }

    fn consume(&self, bytes: usize) {
        if bytes == 0 {
            return;
        }
        let cost = stream_frame_credit_cost(bytes) as u64;
        let mut guard = lock_unpoisoned(&self.state);
        guard.available = guard.available.saturating_sub(cost);
    }
}

struct GuestEgressPermit {
    counter: Arc<AtomicUsize>,
}

impl GuestEgressPermit {
    fn try_acquire(counter: &Arc<AtomicUsize>, limit: usize) -> Option<Arc<Self>> {
        let mut cur = counter.load(Ordering::Acquire);
        loop {
            if cur >= limit {
                return None;
            }
            match counter.compare_exchange_weak(
                cur,
                cur + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(Arc::new(Self {
                        counter: Arc::clone(counter),
                    }));
                }
                Err(actual) => cur = actual,
            }
        }
    }
}

impl Drop for GuestEgressPermit {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::AcqRel);
    }
}

enum ExecInbound {
    Output {
        channel: StreamChannel,
        chunk: ExecOutputChunk,
    },
    Exit(ExecExitStatus),
    Abort(SandboxError),
}

enum TunnelInbound {
    Data { data: Vec<u8>, eof: bool },
    RemoteClose,
}

enum StreamHandler {
    Exec {
        inbound_tx: mpsc::UnboundedSender<ExecInbound>,
        queued_bytes: Arc<AtomicUsize>,
        stdin_credits: Arc<StdinCreditWindow>,
        done_tx: Option<oneshot::Sender<()>>,
    },
    CopyIn {
        stdin_credits: Arc<StdinCreditWindow>,
        reply_tx: Option<oneshot::Sender<Result<u64, SandboxError>>>,
    },
    CopyOut {
        max_bytes: u64,
        buffer: Vec<u8>,
        eof_seen: bool,
        activity: Arc<Notify>,
        reply_tx: Option<oneshot::Sender<Result<Vec<u8>, SandboxError>>>,
    },
    Tunnel {
        connect_tx: Option<oneshot::Sender<Result<(), SandboxError>>>,
        inbound_tx: mpsc::UnboundedSender<TunnelInbound>,
        queued_bytes: Arc<AtomicUsize>,
        stdin_credits: Arc<StdinCreditWindow>,
        stdout_eof_seen: bool,
        _egress_permit: Option<Arc<GuestEgressPermit>>,
    },
}

struct CopyStreamGuard<'a> {
    stream_id: StreamId,
    ops: &'a Mutex<HashMap<StreamId, StreamHandler>>,
    outbound: &'a OutboundQueue,
    armed: bool,
}

impl<'a> CopyStreamGuard<'a> {
    fn new(
        stream_id: StreamId,
        ops: &'a Mutex<HashMap<StreamId, StreamHandler>>,
        outbound: &'a OutboundQueue,
    ) -> Self {
        Self {
            stream_id,
            ops,
            outbound,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for CopyStreamGuard<'_> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let removed = lock_unpoisoned(self.ops).remove(&self.stream_id);
        if let Some(StreamHandler::CopyIn { stdin_credits, .. }) = removed {
            stdin_credits.close();
        }
        if !self.outbound.is_closed() {
            if let Ok(frame) = Frame::from_message(self.stream_id, &Message::StreamClose) {
                let _ = self.outbound.enqueue_control(frame);
            }
        }
    }
}

type NetworkAckSlot = Mutex<Option<oneshot::Sender<Result<u16, SandboxError>>>>;

/// Active multiplexed QEMU `virtio-serial` session implementing [`VmSessionPort`].
pub struct QemuVmSession {
    pid: u32,
    accelerator: Option<Accelerator>,
    start_token: u64,
    has_process: bool,
    io_timeout: Duration,
    artifact_paths: Vec<PathBuf>,
    process: Arc<Mutex<Option<ConfinedProcess>>>,
    endpoint: Mutex<Option<AgentIpcEndpoint>>,
    stream_shutdown: Mutex<Option<IpcReadHalf>>,
    reader_thread: Mutex<Option<JoinHandle<()>>>,
    writer_thread: Mutex<Option<JoinHandle<()>>>,
    outbound: Arc<OutboundQueue>,
    ops: Arc<Mutex<HashMap<StreamId, StreamHandler>>>,
    egress_tx: Arc<Mutex<Option<mpsc::Sender<TunnelStream>>>>,
    #[cfg(test)]
    active_guest_egress: Arc<AtomicUsize>,
    pending_network_ack: Arc<NetworkAckSlot>,
    network_cfg_lock: AsyncMutex<()>,
    shutdown_lock: Arc<AsyncMutex<()>>,
    session_closed_tx: watch::Sender<Option<String>>,
    transport_closed: Arc<AtomicBool>,
    alive: Arc<AtomicBool>,
    next_stream_id: AtomicU32,
}

impl Drop for QemuVmSession {
    fn drop(&mut self) {
        let was_alive = self.alive.swap(false, Ordering::AcqRel);
        self.outbound.close(Some("session dropped".to_owned()));
        let _ = self
            .session_closed_tx
            .send(Some("session dropped".to_owned()));
        fail_all_pending_ops(&self.ops, &self.pending_network_ack, "session dropped");
        if let Some(shutdown_half) = lock_unpoisoned(&self.stream_shutdown).as_ref() {
            let _ = shutdown_half.shutdown();
        }
        if let Some(mut process) = lock_unpoisoned(&self.process).take() {
            let _ = process.kill_and_wait();
        } else if self.has_process && was_alive {
            // Wake any detached `graceful_shutdown` blocking wait if the session dropped mid-flight.
            let _ = kill_verified_orphan_process(self.pid, self.start_token);
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
        let has_process = process.is_some();
        // Blocking reader waits indefinitely for async guest output; bounded writes guard against stalls.
        stream.set_read_timeout(None)?;
        stream.set_write_timeout(Some(io_timeout))?;

        let (read_half, write_half) = stream.into_split();
        let stream_shutdown = read_half.clone();
        let outbound = Arc::new(OutboundQueue::new());
        let ops: Arc<Mutex<HashMap<StreamId, StreamHandler>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let egress_tx = Arc::new(Mutex::new(egress_tx));
        let active_guest_egress = Arc::new(AtomicUsize::new(0));
        let reader_active_guest_egress = Arc::clone(&active_guest_egress);
        let pending_network_ack: Arc<NetworkAckSlot> = Arc::new(Mutex::new(None));
        let (session_closed_tx, _) = watch::channel(None);
        let transport_closed = Arc::new(AtomicBool::new(false));
        let tokio_handle = tokio::runtime::Handle::try_current().ok();

        let writer_outbound = Arc::clone(&outbound);
        let writer_ops = Arc::clone(&ops);
        let writer_pending_ack = Arc::clone(&pending_network_ack);
        let writer_closed = Arc::clone(&transport_closed);
        let writer_session_closed = session_closed_tx.clone();
        let writer_thread = thread::Builder::new()
            .name(format!("minipod-vmm-tx-{pid}"))
            .spawn(move || {
                run_writer_loop(
                    write_half,
                    writer_outbound,
                    writer_ops,
                    writer_pending_ack,
                    writer_closed,
                    writer_session_closed,
                );
            })
            .map_err(|err| SandboxError::Internal(format!("spawn VMM writer thread: {err}")))?;

        let reader_outbound = Arc::clone(&outbound);
        let reader_ops = Arc::clone(&ops);
        let reader_pending_ack = Arc::clone(&pending_network_ack);
        let reader_closed = Arc::clone(&transport_closed);
        let reader_egress_tx = Arc::clone(&egress_tx);
        let reader_session_closed = session_closed_tx.clone();
        let reader_thread = thread::Builder::new()
            .name(format!("minipod-vmm-rx-{pid}"))
            .spawn(move || {
                run_reader_loop(
                    read_half,
                    reader_outbound,
                    reader_ops,
                    reader_pending_ack,
                    reader_closed,
                    reader_egress_tx,
                    reader_active_guest_egress,
                    reader_session_closed,
                    tokio_handle,
                    io_timeout,
                );
            })
            .map_err(|err| SandboxError::Internal(format!("spawn VMM reader thread: {err}")))?;

        Ok(Self {
            pid,
            accelerator: None,
            start_token,
            has_process,
            io_timeout,
            artifact_paths,
            process: Arc::new(Mutex::new(process)),
            endpoint: Mutex::new(endpoint),
            stream_shutdown: Mutex::new(Some(stream_shutdown)),
            reader_thread: Mutex::new(Some(reader_thread)),
            writer_thread: Mutex::new(Some(writer_thread)),
            outbound,
            ops,
            egress_tx,
            #[cfg(test)]
            active_guest_egress,
            pending_network_ack,
            network_cfg_lock: AsyncMutex::new(()),
            shutdown_lock: Arc::new(AsyncMutex::new(())),
            session_closed_tx,
            transport_closed,
            alive: Arc::new(AtomicBool::new(true)),
            next_stream_id: AtomicU32::new(1),
        })
    }

    #[cfg(test)]
    pub(crate) fn active_guest_egress_count(&self) -> usize {
        self.active_guest_egress.load(Ordering::Acquire)
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

    fn enqueue_control_message(&self, stream_id: StreamId, msg: &Message) -> Result<(), SandboxError> {
        let frame = Frame::from_message(stream_id, msg)
            .map_err(|err| protocol_err("encoding protocol frame", err))?;
        self.outbound.enqueue_control(frame)
    }

    async fn enqueue_data_message(
        &self,
        stream_id: StreamId,
        msg: &Message,
    ) -> Result<(), SandboxError> {
        let frame = Frame::from_message(stream_id, msg)
            .map_err(|err| protocol_err("encoding protocol frame", err))?;
        self.outbound.enqueue_data(frame).await
    }

    fn ensure_transport_ready(&self) -> Result<(), SandboxError> {
        if self.transport_closed.load(Ordering::Acquire) || !self.is_alive() {
            return Err(SandboxError::Transport(
                "QEMU VM session is closed or exited".to_owned(),
            ));
        }
        Ok(())
    }

    fn copy_total_timeout(&self) -> Duration {
        self.io_timeout
            .saturating_mul(10)
            .min(Duration::from_secs(300))
    }

    fn teardown_ipc_and_threads(&self) {
        self.outbound.close(None);
        let _ = self
            .session_closed_tx
            .send(Some("QEMU VM session terminated".to_owned()));
        fail_all_pending_ops(
            &self.ops,
            &self.pending_network_ack,
            "QEMU VM session terminated",
        );
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
    }
}

#[async_trait::async_trait]
impl VmSessionPort for QemuVmSession {
    fn pid(&self) -> u32 {
        self.pid
    }

    fn accelerator_name(&self) -> Option<&'static str> {
        self.accelerator.map(|accelerator| accelerator.as_qemu_arg())
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
                Ok(None) | Err(_) => true,
            }
        } else if self.has_process {
            // Process handle is temporarily checked out under `shutdown_lock` and not confirmed exited yet.
            true
        } else {
            !self.transport_closed.load(Ordering::Acquire)
        }
    }

    fn confirmed_exited(&self) -> Result<bool, SandboxError> {
        if !self.has_process {
            return Err(SandboxError::Internal(
                "VM process handle is unavailable".to_owned(),
            ));
        }
        if !self.alive.load(Ordering::Acquire) {
            return Ok(true);
        }
        let mut process = lock_unpoisoned(&self.process);
        match process.as_mut() {
            Some(proc_ref) => {
                let exited = proc_ref.try_wait()?.is_some();
                if exited {
                    self.alive.store(false, Ordering::Release);
                }
                Ok(exited)
            }
            None => Ok(!self.alive.load(Ordering::Acquire)),
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
        let deadline = req.deadline;
        let stdout_budget_bytes = req.stdout_budget_bytes;
        let stderr_budget_bytes = req.stderr_budget_bytes;
        let deadline_ms = u64::try_from(deadline.as_millis())
            .unwrap_or(u64::MAX)
            .max(1);

        let stream_id = self.allocate_stream_id()?;
        let (exec_stream, handle) = ExecStream::channel(stream_id);
        let exec_stream =
            exec_stream.with_limits(deadline, stdout_budget_bytes, stderr_budget_bytes);
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
        let queued_bytes = Arc::new(AtomicUsize::new(0));
        let stdin_credits = Arc::new(StdinCreditWindow::new(INITIAL_STREAM_CREDIT_BYTES));
        let (done_tx, done_rx) = oneshot::channel();

        {
            let mut ops = lock_unpoisoned(&self.ops);
            ops.insert(
                stream_id,
                StreamHandler::Exec {
                    inbound_tx,
                    queued_bytes: Arc::clone(&queued_bytes),
                    stdin_credits: Arc::clone(&stdin_credits),
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
            stdout_budget_bytes,
            stderr_budget_bytes,
        };
        if let Err(err) = self.enqueue_control_message(stream_id, &start_msg) {
            lock_unpoisoned(&self.ops).remove(&stream_id);
            return Err(err);
        }

        let out_outbound = Arc::clone(&self.outbound);
        let out_ops = Arc::clone(&self.ops);
        let session_closed_rx = self.session_closed_tx.subscribe();
        let output_tx = handle.output_tx;
        let exit_tx = handle.exit_tx;
        tokio::spawn(async move {
            pump_exec_output(
                stream_id,
                out_outbound,
                out_ops,
                inbound_rx,
                queued_bytes,
                output_tx,
                exit_tx,
                session_closed_rx,
            )
            .await;
        });

        let outbound = Arc::clone(&self.outbound);
        let mut stdin_rx = handle.stdin_rx;
        let mut cancel_rx = handle.cancel_rx;
        tokio::spawn(async move {
            pump_exec_stdin_and_cancel(
                stream_id,
                outbound,
                stdin_credits,
                &mut stdin_rx,
                &mut cancel_rx,
                done_rx,
            )
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
        let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
        let queued_bytes = Arc::new(AtomicUsize::new(0));
        let stdin_credits = Arc::new(StdinCreditWindow::new(INITIAL_STREAM_CREDIT_BYTES));

        {
            let mut ops = lock_unpoisoned(&self.ops);
            ops.insert(
                stream_id,
                StreamHandler::Tunnel {
                    connect_tx: Some(connect_tx),
                    inbound_tx,
                    queued_bytes: Arc::clone(&queued_bytes),
                    stdin_credits: Arc::clone(&stdin_credits),
                    stdout_eof_seen: false,
                    _egress_permit: None,
                },
            );
        }

        if let Err(err) = self.enqueue_control_message(stream_id, &Message::ConnectStart { target }) {
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
            queued_bytes,
            stdin_credits,
            tunnel_handle,
            self.session_closed_tx.subscribe(),
            self.io_timeout,
        );

        Ok(tunnel_stream)
    }

    async fn enable_egress_proxy(
        &self,
        proxy_port: u16,
    ) -> Result<mpsc::Receiver<TunnelStream>, SandboxError> {
        if proxy_port == 0 {
            return Err(SandboxError::InvalidSpec(
                "egress proxy_port must be greater than zero".to_owned(),
            ));
        }
        self.ensure_transport_ready()?;

        let _cfg_guard = self.network_cfg_lock.lock().await;
        self.ensure_transport_ready()?;

        let (tx, rx) = mpsc::channel(EGRESS_ACCEPT_CHANNEL_CAPACITY);
        let (ack_tx, ack_rx) = oneshot::channel();
        {
            let mut egress_guard = lock_unpoisoned(&self.egress_tx);
            if egress_guard.is_some() {
                return Err(SandboxError::InvalidSpec(
                    "egress proxy is already enabled on this session".to_owned(),
                ));
            }
            *egress_guard = Some(tx);
        }
        *lock_unpoisoned(&self.pending_network_ack) = Some(ack_tx);
        let mut rollback = NetworkConfigureGuard {
            egress_tx: &self.egress_tx,
            pending_network_ack: &self.pending_network_ack,
            armed: true,
        };

        self.ensure_transport_ready()?;
        self.enqueue_control_message(
            StreamId(0),
            &Message::ConfigureNetwork {
                enable_egress_proxy: true,
                proxy_port,
            },
        )?;

        let ack_res = match tokio::time::timeout(self.io_timeout, ack_rx).await {
            Ok(Ok(res)) => res,
            Ok(Err(_)) => Err(SandboxError::Transport(
                "QEMU IPC transport closed before guest ConfigureNetworkAck".to_owned(),
            )),
            Err(_) => Err(SandboxError::Transport(format!(
                "timed out after {}ms waiting for guest ConfigureNetworkAck",
                self.io_timeout.as_millis()
            ))),
        };

        match ack_res {
            Ok(0) => Err(SandboxError::Transport(
                "guest egress proxy listener reported unbound port 0".to_owned(),
            )),
            Ok(_actual_port) => {
                rollback.armed = false;
                *lock_unpoisoned(&self.pending_network_ack) = None;
                Ok(rx)
            }
            Err(err) => Err(err),
        }
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
        let stdin_credits = Arc::new(StdinCreditWindow::new(INITIAL_STREAM_CREDIT_BYTES));
        let (reply_tx, reply_rx) = oneshot::channel();
        {
            let mut ops = lock_unpoisoned(&self.ops);
            ops.insert(
                stream_id,
                StreamHandler::CopyIn {
                    stdin_credits: Arc::clone(&stdin_credits),
                    reply_tx: Some(reply_tx),
                },
            );
        }

        if let Err(err) = self.enqueue_control_message(
            stream_id,
            &Message::CopyInStart {
                dst_guest: dst_guest.to_owned(),
                max_bytes,
            },
        ) {
            lock_unpoisoned(&self.ops).remove(&stream_id);
            return Err(err);
        }
        let mut stream_guard = CopyStreamGuard::new(stream_id, &self.ops, &self.outbound);

        let total_deadline = tokio::time::Instant::now() + self.copy_total_timeout();
        let mut all_sent = false;
        if tar_bytes.is_empty() {
            let remaining = total_deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(SandboxError::Transport(
                    "copy_in exceeded total duration budget".to_owned(),
                ));
            }
            match tokio::time::timeout(
                self.io_timeout.min(remaining),
                self.enqueue_data_message(
                    stream_id,
                    &Message::StreamData {
                        channel: StreamChannel::Stdin,
                        eof: true,
                        data: Vec::new(),
                    },
                ),
            )
            .await
            {
                Ok(Ok(())) => all_sent = true,
                Ok(Err(err)) => return Err(err),
                Err(_) => {
                    return Err(SandboxError::Transport(format!(
                        "copy_in stalled for {} ms writing empty tar EOF",
                        self.io_timeout.as_millis()
                    )));
                }
            }
        } else {
            let mut offset = 0usize;
            while offset < tar_bytes.len() {
                let remaining = total_deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    return Err(SandboxError::Transport(
                        "copy_in exceeded total duration budget".to_owned(),
                    ));
                }
                let maybe_allowance = tokio::time::timeout(
                    self.io_timeout.min(remaining),
                    stdin_credits.wait_available(MAX_HOST_STREAM_CHUNK_BYTES),
                )
                .await
                .map_err(|_| {
                    SandboxError::Transport(format!(
                        "copy_in stalled for {} ms waiting for guest stream credit",
                        self.io_timeout.as_millis()
                    ))
                })?;
                let Some(allowance) = maybe_allowance else {
                    break;
                };
                let take = (tar_bytes.len() - offset).min(allowance);
                stdin_credits.consume(take);
                let end = offset + take;
                let eof = end == tar_bytes.len();
                let remaining = total_deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() {
                    return Err(SandboxError::Transport(
                        "copy_in exceeded total duration budget".to_owned(),
                    ));
                }
                match tokio::time::timeout(
                    self.io_timeout.min(remaining),
                    self.enqueue_data_message(
                        stream_id,
                        &Message::StreamData {
                            channel: StreamChannel::Stdin,
                            eof,
                            data: tar_bytes[offset..end].to_vec(),
                        },
                    ),
                )
                .await
                {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => return Err(err),
                    Err(_) => {
                        return Err(SandboxError::Transport(format!(
                            "copy_in stalled for {} ms writing tar chunk",
                            self.io_timeout.as_millis()
                        )));
                    }
                }
                offset = end;
                if eof {
                    all_sent = true;
                }
            }
        }

        let remaining = total_deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(SandboxError::Transport(
                "copy_in exceeded total duration budget".to_owned(),
            ));
        }
        match tokio::time::timeout(self.io_timeout.min(remaining), reply_rx).await {
            Ok(Ok(outcome)) => {
                stream_guard.disarm();
                let bytes_transferred = outcome?;
                if !all_sent || bytes_transferred != tar_bytes.len() as u64 {
                    return Err(SandboxError::Transport(format!(
                        "copy_in byte count mismatch (sent {} bytes, all_sent={all_sent}, guest reported {bytes_transferred})",
                        tar_bytes.len()
                    )));
                }
                Ok(bytes_transferred)
            }
            Ok(Err(_)) => Err(SandboxError::Transport(
                "copy_in interrupted before guest CopyDone".to_owned(),
            )),
            Err(_) => Err(SandboxError::Transport(format!(
                "copy_in timed out after {} ms waiting for guest CopyDone",
                self.io_timeout.as_millis()
            ))),
        }
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
        let activity = Arc::new(Notify::new());
        let (reply_tx, mut reply_rx) = oneshot::channel();
        {
            let mut ops = lock_unpoisoned(&self.ops);
            ops.insert(
                stream_id,
                StreamHandler::CopyOut {
                    max_bytes,
                    buffer: Vec::new(),
                    eof_seen: false,
                    activity: Arc::clone(&activity),
                    reply_tx: Some(reply_tx),
                },
            );
        }

        if let Err(err) = self.enqueue_control_message(
            stream_id,
            &Message::CopyOutStart {
                src_guest: src_guest.to_owned(),
                max_bytes,
            },
        ) {
            lock_unpoisoned(&self.ops).remove(&stream_id);
            return Err(err);
        }
        let mut stream_guard = CopyStreamGuard::new(stream_id, &self.ops, &self.outbound);
        let total_deadline = tokio::time::Instant::now() + self.copy_total_timeout();

        loop {
            let remaining = total_deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Err(SandboxError::Transport(
                    "copy_out exceeded total duration budget".to_owned(),
                ));
            }
            tokio::select! {
                biased;
                res = &mut reply_rx => {
                    return match res {
                        Ok(outcome) => {
                            stream_guard.disarm();
                            outcome
                        }
                        Err(_) => Err(SandboxError::Transport(
                            "copy_out interrupted before guest CopyDone".to_owned(),
                        )),
                    };
                }
                _ = activity.notified() => {}
                _ = tokio::time::sleep(self.io_timeout.min(remaining)) => {
                    if tokio::time::Instant::now() >= total_deadline {
                        return Err(SandboxError::Transport(
                            "copy_out exceeded total duration budget".to_owned(),
                        ));
                    }
                    return Err(SandboxError::Transport(format!(
                        "copy_out timed out after {} ms without guest progress",
                        self.io_timeout.as_millis()
                    )));
                }
            }
        }
    }

    async fn graceful_shutdown(&self, timeout: Duration) -> Result<bool, SandboxError> {
        let guard = Arc::clone(&self.shutdown_lock).lock_owned().await;
        if !self.alive.load(Ordering::Acquire) {
            drop(guard);
            self.teardown_ipc_and_threads();
            return Ok(true);
        }

        let mut closed_rx = self.session_closed_tx.subscribe();
        let _ = self.enqueue_control_message(StreamId(0), &Message::Shutdown);

        if !self.has_process {
            if closed_rx.borrow().is_none() {
                let _ = tokio::time::timeout(timeout, closed_rx.changed()).await;
            }
            self.alive.store(false, Ordering::Release);
            drop(guard);
            self.teardown_ipc_and_threads();
            return Ok(true);
        }

        let proc_slot = Arc::clone(&self.process);
        let alive_flag = Arc::clone(&self.alive);
        // Move `guard` into `spawn_blocking` so cancelling this future still serializes any
        // subsequent `graceful_shutdown` / `force_kill` until `wait_timeout` returns the handle.
        let exited = tokio::task::spawn_blocking(move || {
            let _shutdown_guard = guard;
            let Some(mut process) = lock_unpoisoned(&proc_slot).take() else {
                alive_flag.store(false, Ordering::Release);
                return Ok(true);
            };
            match process.wait_timeout(timeout) {
                Ok(Some(_)) => {
                    alive_flag.store(false, Ordering::Release);
                    drop(process);
                    Ok(true)
                }
                Ok(None) => {
                    if alive_flag.load(Ordering::Acquire) {
                        *lock_unpoisoned(&proc_slot) = Some(process);
                        Ok(false)
                    } else {
                        let _ = process.kill_and_wait();
                        Ok(true)
                    }
                }
                Err(err) => {
                    if alive_flag.load(Ordering::Acquire) {
                        *lock_unpoisoned(&proc_slot) = Some(process);
                        Err(err)
                    } else {
                        let _ = process.kill_and_wait();
                        Ok(true)
                    }
                }
            }
        })
        .await
        .map_err(|err| SandboxError::Internal(format!("graceful_shutdown wait failed: {err}")))??;

        if exited {
            self.teardown_ipc_and_threads();
        }
        Ok(exited)
    }

    async fn force_kill(&self) -> Result<(), SandboxError> {
        self.outbound.close(Some("force_kill invoked".to_owned()));
        let _ = self
            .session_closed_tx
            .send(Some("QEMU process killed".to_owned()));
        fail_all_pending_ops(&self.ops, &self.pending_network_ack, "QEMU process killed");
        if let Some(shutdown_half) = lock_unpoisoned(&self.stream_shutdown).as_ref() {
            let _ = shutdown_half.shutdown();
        }

        let guard = match Arc::clone(&self.shutdown_lock).try_lock_owned() {
            Ok(guard) => guard,
            Err(_) => {
                // Wake any hung `graceful_shutdown::wait_timeout` immediately before waiting for `shutdown_lock`.
                if self.has_process && self.alive.load(Ordering::Acquire) {
                    let pid = self.pid;
                    let start_token = self.start_token;
                    let _ = tokio::task::spawn_blocking(move || {
                        kill_verified_orphan_process(pid, start_token)
                    })
                    .await;
                }
                Arc::clone(&self.shutdown_lock).lock_owned().await
            }
        };
        let (kill_res, exited) = if self.has_process {
            let proc_slot = Arc::clone(&self.process);
            let alive_flag = Arc::clone(&self.alive);
            tokio::task::spawn_blocking(move || {
                let _shutdown_guard = guard;
                let Some(mut process) = lock_unpoisoned(&proc_slot).take() else {
                    alive_flag.store(false, Ordering::Release);
                    return (Ok(()), true);
                };
                let res = process.kill_and_wait();
                let exited = res.is_ok() || matches!(process.try_wait(), Ok(Some(_)));
                if exited {
                    alive_flag.store(false, Ordering::Release);
                    drop(process);
                } else {
                    *lock_unpoisoned(&proc_slot) = Some(process);
                }
                (res, exited)
            })
            .await
            .map_err(|err| SandboxError::Internal(format!("force_kill task failed: {err}")))?
        } else {
            self.alive.store(false, Ordering::Release);
            drop(guard);
            (Ok(()), true)
        };

        if !exited {
            return kill_res;
        }

        let shutdown_half = lock_unpoisoned(&self.stream_shutdown).take();
        let writer = lock_unpoisoned(&self.writer_thread).take();
        let reader = lock_unpoisoned(&self.reader_thread).take();
        let endpoint = lock_unpoisoned(&self.endpoint).take();

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
                let _ = self.outbound.enqueue_control(frame);
            }
        }
    }
}

struct NetworkConfigureGuard<'a> {
    egress_tx: &'a Mutex<Option<mpsc::Sender<TunnelStream>>>,
    pending_network_ack: &'a NetworkAckSlot,
    armed: bool,
}

impl Drop for NetworkConfigureGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            *lock_unpoisoned(self.pending_network_ack) = None;
            *lock_unpoisoned(self.egress_tx) = None;
        }
    }
}

fn send_stream_credit(
    outbound: &OutboundQueue,
    stream_id: StreamId,
    channel: StreamChannel,
    mut bytes: usize,
) {
    while bytes > 0 {
        let chunk = bytes.min(u32::MAX as usize);
        if let Ok(frame) = Frame::from_message(
            stream_id,
            &Message::StreamCredit {
                channel,
                bytes: chunk as u32,
            },
        ) {
            if outbound.enqueue_control(frame).is_err() {
                break;
            }
        }
        bytes -= chunk;
    }
}

#[allow(clippy::too_many_arguments)]
async fn pump_exec_output(
    stream_id: StreamId,
    outbound: Arc<OutboundQueue>,
    ops: Arc<Mutex<HashMap<StreamId, StreamHandler>>>,
    mut inbound_rx: mpsc::UnboundedReceiver<ExecInbound>,
    queued_bytes: Arc<AtomicUsize>,
    output_tx: mpsc::Sender<ExecOutputChunk>,
    mut exit_tx: Option<oneshot::Sender<Result<ExecExitStatus, SandboxError>>>,
    mut session_closed_rx: watch::Receiver<Option<String>>,
) {
    let mut output_tx = Some(output_tx);
    loop {
        if let Some(reason) = session_closed_rx.borrow().clone() {
            if let Some(tx) = exit_tx.take() {
                let _ = tx.send(Err(SandboxError::Transport(reason)));
            }
            return;
        }

        let item = tokio::select! {
            biased;
            changed = session_closed_rx.changed() => {
                let reason = changed
                    .ok()
                    .and_then(|()| session_closed_rx.borrow().clone())
                    .unwrap_or_else(|| "QEMU VM session terminated".to_owned());
                if let Some(tx) = exit_tx.take() {
                    let _ = tx.send(Err(SandboxError::Transport(reason)));
                }
                return;
            }
            _ = async {
                match exit_tx.as_mut() {
                    Some(tx) => tx.closed().await,
                    None => std::future::pending::<()>().await,
                }
            } => {
                cancel_and_cleanup_abandoned_exec(stream_id, &ops, &outbound);
                return;
            }
            maybe_item = inbound_rx.recv() => match maybe_item {
                Some(item) => item,
                None => {
                    if let Some(tx) = exit_tx.take() {
                        let _ = tx.send(Err(SandboxError::Transport(
                            "execution stream closed before reporting exit status".to_owned(),
                        )));
                    }
                    return;
                }
            }
        };

        match item {
            ExecInbound::Output { channel, chunk } => {
                let len = chunk.data.len();
                let cost = stream_frame_credit_cost(len);
                if let Some(tx) = output_tx.as_ref() {
                    let send_res = tokio::select! {
                        biased;
                        changed = session_closed_rx.changed() => {
                            queued_bytes.fetch_sub(cost, Ordering::AcqRel);
                            let reason = changed
                                .ok()
                                .and_then(|()| session_closed_rx.borrow().clone())
                                .unwrap_or_else(|| "QEMU VM session terminated".to_owned());
                            if let Some(exit) = exit_tx.take() {
                                let _ = exit.send(Err(SandboxError::Transport(reason)));
                            }
                            return;
                        }
                        _ = async {
                            match exit_tx.as_mut() {
                                Some(exit) => exit.closed().await,
                                None => std::future::pending::<()>().await,
                            }
                        } => {
                            queued_bytes.fetch_sub(cost, Ordering::AcqRel);
                            cancel_and_cleanup_abandoned_exec(stream_id, &ops, &outbound);
                            return;
                        }
                        res = tx.send(chunk) => res,
                    };
                    if send_res.is_err() {
                        output_tx = None;
                    }
                }
                queued_bytes.fetch_sub(cost, Ordering::AcqRel);
                send_stream_credit(&outbound, stream_id, channel, cost);
            }
            ExecInbound::Exit(status) => {
                drop(output_tx.take());
                if let Some(tx) = exit_tx.take() {
                    let _ = tx.send(Ok(status));
                }
                return;
            }
            ExecInbound::Abort(err) => {
                drop(output_tx.take());
                if let Some(tx) = exit_tx.take() {
                    let _ = tx.send(Err(err));
                }
                return;
            }
        }
    }
}

fn cancel_and_cleanup_abandoned_exec(
    stream_id: StreamId,
    ops: &Mutex<HashMap<StreamId, StreamHandler>>,
    outbound: &OutboundQueue,
) {
    let removed = lock_unpoisoned(ops).remove(&stream_id);
    if let Some(StreamHandler::Exec {
        stdin_credits,
        mut done_tx,
        ..
    }) = removed
    {
        stdin_credits.close();
        if let Some(tx) = done_tx.take() {
            let _ = tx.send(());
        }
        if let Ok(cancel) = Frame::from_message(stream_id, &Message::ExecCancel) {
            let _ = outbound.enqueue_control(cancel);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn spawn_tunnel_pumps(
    rt: &tokio::runtime::Handle,
    stream_id: StreamId,
    outbound: Arc<OutboundQueue>,
    ops: Arc<Mutex<HashMap<StreamId, StreamHandler>>>,
    inbound_rx: mpsc::UnboundedReceiver<TunnelInbound>,
    queued_bytes: Arc<AtomicUsize>,
    stdin_credits: Arc<StdinCreditWindow>,
    tunnel_handle: TunnelStreamHandle,
    session_closed_rx: watch::Receiver<Option<String>>,
    io_timeout: Duration,
) {
    let (remote_eof_tx, remote_eof_rx) = oneshot::channel();
    let (remote_abort_tx, remote_abort_rx) = oneshot::channel();

    let inbound_outbound = Arc::clone(&outbound);
    let inbound_session_closed = session_closed_rx.clone();
    rt.spawn(async move {
        pump_tunnel_inbound(
            stream_id,
            inbound_outbound,
            inbound_rx,
            queued_bytes,
            tunnel_handle.write_half,
            remote_eof_tx,
            remote_abort_tx,
            inbound_session_closed,
        )
        .await;
    });
    rt.spawn(async move {
        pump_tunnel_outbound(
            stream_id,
            outbound,
            ops,
            stdin_credits,
            tunnel_handle.read_half,
            tunnel_handle.drop_rx,
            remote_eof_rx,
            remote_abort_rx,
            session_closed_rx,
            io_timeout,
        )
        .await;
    });
}

#[allow(clippy::too_many_arguments)]
async fn pump_tunnel_inbound(
    stream_id: StreamId,
    outbound: Arc<OutboundQueue>,
    mut inbound_rx: mpsc::UnboundedReceiver<TunnelInbound>,
    queued_bytes: Arc<AtomicUsize>,
    mut write_half: WriteHalf<DuplexStream>,
    remote_eof_tx: oneshot::Sender<()>,
    remote_abort_tx: oneshot::Sender<bool>,
    mut session_closed_rx: watch::Receiver<Option<String>>,
) {
    let mut remote_eof_tx = Some(remote_eof_tx);
    let mut write_broken = false;
    loop {
        if session_closed_rx.borrow().is_some() {
            break;
        }
        let item = tokio::select! {
            biased;
            _ = session_closed_rx.changed() => break,
            maybe_item = inbound_rx.recv() => match maybe_item {
                Some(item) => item,
                None => break,
            }
        };
        match item {
            TunnelInbound::Data { data, eof } => {
                let len = data.len();
                if len > 0 {
                    let cost = stream_frame_credit_cost(len);
                    let write_res = tokio::select! {
                        biased;
                        _ = session_closed_rx.changed() => {
                            queued_bytes.fetch_sub(cost, Ordering::AcqRel);
                            break;
                        }
                        res = write_half.write_all(&data) => res,
                    };
                    queued_bytes.fetch_sub(cost, Ordering::AcqRel);
                    if write_res.is_err() {
                        write_broken = true;
                        break;
                    }
                    send_stream_credit(&outbound, stream_id, StreamChannel::Stdout, cost);
                }
                if eof {
                    if let Some(tx) = remote_eof_tx.take() {
                        let _ = tx.send(());
                    }
                    let _ = write_half.shutdown().await;
                }
            }
            TunnelInbound::RemoteClose => {
                let _ = remote_abort_tx.send(false);
                let _ = write_half.shutdown().await;
                return;
            }
        }
    }
    let _ = write_half.shutdown().await;
    if remote_eof_tx.is_some() {
        let _ = remote_abort_tx.send(write_broken);
    }
}

#[allow(clippy::too_many_arguments)]
async fn pump_tunnel_outbound(
    stream_id: StreamId,
    outbound: Arc<OutboundQueue>,
    ops: Arc<Mutex<HashMap<StreamId, StreamHandler>>>,
    stdin_credits: Arc<StdinCreditWindow>,
    mut read_half: ReadHalf<DuplexStream>,
    drop_rx: oneshot::Receiver<bool>,
    remote_eof_rx: oneshot::Receiver<()>,
    mut remote_abort_rx: oneshot::Receiver<bool>,
    mut session_closed_rx: watch::Receiver<Option<String>>,
    io_timeout: Duration,
) {
    let mut buf = vec![0u8; MAX_HOST_STREAM_CHUNK_BYTES];
    let mut stdin_eof = false;
    let mut remote_eof = false;
    let mut need_stream_close = false;
    let mut remote_abort_done = false;
    let mut linger_deadline: Option<tokio::time::Instant> = None;
    let linger_duration = io_timeout.min(Duration::from_secs(5));
    let mut drop_rx = Some(drop_rx);
    let mut remote_eof_rx = Some(remote_eof_rx);

    while !(stdin_eof && remote_eof) {
        if session_closed_rx.borrow().is_some() {
            break;
        }
        tokio::select! {
            biased;
            _ = session_closed_rx.changed() => {
                break;
            }
            res = &mut remote_abort_rx, if !remote_abort_done => {
                remote_abort_done = true;
                match res {
                    Ok(true) => {
                        need_stream_close = true;
                        remote_eof = true;
                        if stdin_eof {
                            break;
                        }
                    }
                    Ok(false) | Err(_) => break,
                }
            }
            _ = async {
                match linger_deadline {
                    Some(dl) => tokio::time::sleep_until(dl).await,
                    None => std::future::pending::<()>().await,
                }
            }, if linger_deadline.is_some() => {
                need_stream_close = true;
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
                // Only abort with `StreamClose` immediately on ungraceful drop without write
                // `shutdown()`. On graceful write shutdown, drain remaining `read_half` data and
                // bound waiting for remote EOF so abandoned connections release egress permits.
                if !graceful_write {
                    stdin_credits.close();
                    lock_unpoisoned(&ops).remove(&stream_id);
                    if let Ok(frame) = Frame::from_message(stream_id, &Message::StreamClose) {
                        let _ = outbound.enqueue_control(frame);
                    }
                    return;
                }
                linger_deadline = Some(tokio::time::Instant::now() + linger_duration);
            }
            read_res = async {
                let cap = stdin_credits.wait_available(MAX_HOST_STREAM_CHUNK_BYTES).await?;
                Some(read_half.read(&mut buf[..cap]).await)
            }, if !stdin_eof => {
                match read_res {
                    None => break,
                    Some(Ok(0)) => {
                        if let Ok(frame) = Frame::from_message(
                            stream_id,
                            &Message::StreamData {
                                channel: StreamChannel::Stdin,
                                eof: true,
                                data: Vec::new(),
                            },
                        ) {
                            let _ = outbound.enqueue_data(frame).await;
                        }
                        stdin_eof = true;
                        if need_stream_close {
                            break;
                        }
                    }
                    Some(Ok(n)) => {
                        stdin_credits.consume(n);
                        if let Ok(frame) = Frame::from_message(
                            stream_id,
                            &Message::StreamData {
                                channel: StreamChannel::Stdin,
                                eof: false,
                                data: buf[..n].to_vec(),
                            },
                        ) {
                            if outbound.enqueue_data(frame).await.is_err() {
                                break;
                            }
                        }
                    }
                    Some(Err(_)) => break,
                }
            }
        }
    }

    stdin_credits.close();
    if need_stream_close {
        // Wait for queued `Lane::Data` Stdin frames to hit the wire before sending `StreamClose`,
        // bounded by the linger deadline so a wedged transport cannot stall permit cleanup.
        let flush_deadline =
            linger_deadline.unwrap_or_else(|| tokio::time::Instant::now() + linger_duration);
        let _ = tokio::time::timeout_at(
            flush_deadline,
            outbound.wait_stream_data_flushed(stream_id),
        )
        .await;
    }
    lock_unpoisoned(&ops).remove(&stream_id);
    if need_stream_close {
        if let Ok(frame) = Frame::from_message(stream_id, &Message::StreamClose) {
            let _ = outbound.enqueue_control(frame);
        }
    }
}

async fn enqueue_exec_stdin_frame(
    stream_id: StreamId,
    outbound: &OutboundQueue,
    frame: Frame,
    cancel_rx: &mut mpsc::Receiver<()>,
    cancel_open: &mut bool,
    done_rx: &mut oneshot::Receiver<()>,
) -> bool {
    let mut enqueue_fut = std::pin::pin!(outbound.enqueue_data(frame));
    loop {
        tokio::select! {
            biased;
            _ = &mut *done_rx => return false,
            maybe_cancel = cancel_rx.recv(), if *cancel_open => {
                match maybe_cancel {
                    Some(()) => {
                        if let Ok(cancel) = Frame::from_message(stream_id, &Message::ExecCancel) {
                            if outbound.enqueue_control(cancel).is_err() {
                                return false;
                            }
                        }
                    }
                    None => *cancel_open = false,
                }
            }
            res = &mut enqueue_fut => return res.is_ok(),
        }
    }
}

async fn pump_exec_stdin_and_cancel(
    stream_id: StreamId,
    outbound: Arc<OutboundQueue>,
    stdin_credits: Arc<StdinCreditWindow>,
    stdin_rx: &mut mpsc::Receiver<Vec<u8>>,
    cancel_rx: &mut mpsc::Receiver<()>,
    mut done_rx: oneshot::Receiver<()>,
) {
    let mut stdin_open = true;
    let mut cancel_open = true;
    loop {
        tokio::select! {
            biased;
            _ = &mut done_rx => break,
            maybe_cancel = cancel_rx.recv(), if cancel_open => {
                match maybe_cancel {
                    Some(()) => {
                        if let Ok(frame) = Frame::from_message(stream_id, &Message::ExecCancel) {
                            if outbound.enqueue_control(frame).is_err() {
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
            maybe_stdin = stdin_rx.recv(), if stdin_open => {
                match maybe_stdin {
                    Some(data) => {
                        let mut offset = 0usize;
                        while offset < data.len() {
                            let allowance = tokio::select! {
                                biased;
                                _ = &mut done_rx => return,
                                maybe_cancel = cancel_rx.recv(), if cancel_open => {
                                    match maybe_cancel {
                                        Some(()) => {
                                            if let Ok(frame) = Frame::from_message(stream_id, &Message::ExecCancel) {
                                                if outbound.enqueue_control(frame).is_err() {
                                                    return;
                                                }
                                            }
                                            continue;
                                        }
                                        None => {
                                            cancel_open = false;
                                            continue;
                                        }
                                    }
                                }
                                cap = stdin_credits.wait_available(MAX_HOST_STREAM_CHUNK_BYTES) => {
                                    match cap {
                                        Some(cap) => cap,
                                        None => return,
                                    }
                                }
                            };
                            let take = (data.len() - offset).min(allowance);
                            stdin_credits.consume(take);
                            let end = offset + take;
                            let Ok(frame) = Frame::from_message(
                                stream_id,
                                &Message::StreamData {
                                    channel: StreamChannel::Stdin,
                                    eof: false,
                                    data: data[offset..end].to_vec(),
                                },
                            ) else {
                                return;
                            };
                            if !enqueue_exec_stdin_frame(
                                stream_id,
                                &outbound,
                                frame,
                                cancel_rx,
                                &mut cancel_open,
                                &mut done_rx,
                            )
                            .await
                            {
                                return;
                            }
                            offset = end;
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
                            if !enqueue_exec_stdin_frame(
                                stream_id,
                                &outbound,
                                frame,
                                cancel_rx,
                                &mut cancel_open,
                                &mut done_rx,
                            )
                            .await
                            {
                                return;
                            }
                        }
                        if !cancel_open {
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
    pending_network_ack: Arc<NetworkAckSlot>,
    transport_closed: Arc<AtomicBool>,
    session_closed_tx: watch::Sender<Option<String>>,
) {
    while let Some(frame) = outbound.pop_blocking() {
        if let Err(err) = write_frame(&mut write_half, &frame) {
            let msg = format!("writing protocol frame failed: {err}");
            transport_closed.store(true, Ordering::Release);
            outbound.close(Some(msg.clone()));
            let _ = session_closed_tx.send(Some(msg.clone()));
            let _ = write_half.shutdown();
            fail_all_pending_ops(&ops, &pending_network_ack, &msg);
            return;
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn run_reader_loop(
    mut read_half: IpcReadHalf,
    outbound: Arc<OutboundQueue>,
    ops: Arc<Mutex<HashMap<StreamId, StreamHandler>>>,
    pending_network_ack: Arc<NetworkAckSlot>,
    transport_closed: Arc<AtomicBool>,
    egress_tx: Arc<Mutex<Option<mpsc::Sender<TunnelStream>>>>,
    active_guest_egress: Arc<AtomicUsize>,
    session_closed_tx: watch::Sender<Option<String>>,
    tokio_handle: Option<tokio::runtime::Handle>,
    io_timeout: Duration,
) {
    loop {
        let frame = match read_frame(&mut read_half) {
            Ok(frame) => frame,
            Err(err) => {
                let msg = format!("reading protocol frame failed: {err}");
                transport_closed.store(true, Ordering::Release);
                outbound.close(Some(msg.clone()));
                let _ = session_closed_tx.send(Some(msg.clone()));
                fail_all_pending_ops(&ops, &pending_network_ack, &msg);
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
                let _ = session_closed_tx.send(Some(reason.clone()));
                fail_all_pending_ops(&ops, &pending_network_ack, &reason);
                return;
            }
        };

        match msg {
            Message::StreamData { channel, eof, data } => {
                let mut map = lock_unpoisoned(&ops);
                match map.get_mut(&stream_id) {
                    Some(StreamHandler::Exec {
                        inbound_tx,
                        queued_bytes,
                        ..
                    }) => {
                        let kind = match channel {
                            StreamChannel::Stdout => Some(OutputStreamKind::Stdout),
                            StreamChannel::Stderr => Some(OutputStreamKind::Stderr),
                            StreamChannel::Stdin => None,
                        };
                        if let Some(stream_kind) = kind.filter(|_| !data.is_empty()) {
                            let len = data.len();
                            let cost = stream_frame_credit_cost(len);
                            let prev = queued_bytes.fetch_add(cost, Ordering::AcqRel);
                            if prev.saturating_add(cost) > MAX_STREAM_INBOUND_BUFFER_BYTES {
                                queued_bytes.fetch_sub(cost, Ordering::AcqRel);
                                if let Some(StreamHandler::Exec {
                                    inbound_tx,
                                    stdin_credits,
                                    mut done_tx,
                                    ..
                                }) = map.remove(&stream_id)
                                {
                                    stdin_credits.close();
                                    if let Some(tx) = done_tx.take() {
                                        let _ = tx.send(());
                                    }
                                    let _ = inbound_tx.send(ExecInbound::Abort(
                                        SandboxError::Transport(format!(
                                            "guest exceeded stream credit window on stream {stream_id}"
                                        )),
                                    ));
                                }
                                drop(map);
                                if let Ok(cancel) =
                                    Frame::from_message(stream_id, &Message::ExecCancel)
                                {
                                    let _ = outbound.enqueue_control(cancel);
                                }
                            } else if inbound_tx
                                .send(ExecInbound::Output {
                                    channel,
                                    chunk: ExecOutputChunk {
                                        stream: stream_kind,
                                        data,
                                    },
                                })
                                .is_err()
                            {
                                queued_bytes.fetch_sub(cost, Ordering::AcqRel);
                            }
                        }
                    }
                    Some(StreamHandler::CopyOut {
                        max_bytes,
                        buffer,
                        eof_seen,
                        activity,
                        ..
                    }) if channel == StreamChannel::Stdout => {
                        if *eof_seen {
                            if let Some(StreamHandler::CopyOut { mut reply_tx, .. }) =
                                map.remove(&stream_id)
                            {
                                if let Some(tx) = reply_tx.take() {
                                    let _ = tx.send(Err(SandboxError::Transport(
                                        "guest sent CopyOut data after EOF".to_owned(),
                                    )));
                                }
                            }
                            drop(map);
                            if let Ok(close_frame) =
                                Frame::from_message(stream_id, &Message::StreamClose)
                            {
                                let _ = outbound.enqueue_control(close_frame);
                            }
                        } else {
                            let limit = *max_bytes;
                            let chunk_len = data.len();
                            let new_len = (buffer.len() as u64).saturating_add(chunk_len as u64);
                            if new_len > limit {
                                if let Some(StreamHandler::CopyOut { mut reply_tx, .. }) =
                                    map.remove(&stream_id)
                                {
                                    if let Some(tx) = reply_tx.take() {
                                        let _ = tx.send(Err(SandboxError::BudgetExceeded(format!(
                                            "copy_out payload exceeded max_bytes ({limit})"
                                        ))));
                                    }
                                }
                                drop(map);
                                if let Ok(close_frame) =
                                    Frame::from_message(stream_id, &Message::StreamClose)
                                {
                                    let _ = outbound.enqueue_control(close_frame);
                                }
                            } else {
                                if eof {
                                    *eof_seen = true;
                                }
                                buffer.extend_from_slice(&data);
                                if !data.is_empty() || eof {
                                    let notify = Arc::clone(activity);
                                    drop(map);
                                    notify.notify_one();
                                } else {
                                    drop(map);
                                }
                                send_stream_credit(
                                    &outbound,
                                    stream_id,
                                    StreamChannel::Stdout,
                                    stream_frame_credit_cost(chunk_len),
                                );
                            }
                        }
                    }
                    Some(StreamHandler::Tunnel {
                        inbound_tx,
                        queued_bytes,
                        stdout_eof_seen,
                        ..
                    }) if channel == StreamChannel::Stdout => {
                        if *stdout_eof_seen {
                            if let Some(StreamHandler::Tunnel {
                                inbound_tx,
                                stdin_credits,
                                _egress_permit: egress_permit,
                                ..
                            }) = map.remove(&stream_id)
                            {
                                drop(egress_permit);
                                stdin_credits.close();
                                let _ = inbound_tx.send(TunnelInbound::RemoteClose);
                            }
                            drop(map);
                            if let Ok(close_frame) =
                                Frame::from_message(stream_id, &Message::StreamClose)
                            {
                                let _ = outbound.enqueue_control(close_frame);
                            }
                        } else if !data.is_empty() || eof {
                            if eof {
                                *stdout_eof_seen = true;
                            }
                            let len = data.len();
                            let cost = stream_frame_credit_cost(len);
                            let prev = queued_bytes.fetch_add(cost, Ordering::AcqRel);
                            if prev.saturating_add(cost) > MAX_STREAM_INBOUND_BUFFER_BYTES {
                                queued_bytes.fetch_sub(cost, Ordering::AcqRel);
                                if let Some(StreamHandler::Tunnel {
                                    inbound_tx,
                                    stdin_credits,
                                    _egress_permit: egress_permit,
                                    ..
                                }) = map.remove(&stream_id)
                                {
                                    drop(egress_permit);
                                    stdin_credits.close();
                                    let _ = inbound_tx.send(TunnelInbound::RemoteClose);
                                }
                                drop(map);
                                if let Ok(close_frame) =
                                    Frame::from_message(stream_id, &Message::StreamClose)
                                {
                                    let _ = outbound.enqueue_control(close_frame);
                                }
                            } else if inbound_tx
                                .send(TunnelInbound::Data { data, eof })
                                .is_err()
                            {
                                queued_bytes.fetch_sub(cost, Ordering::AcqRel);
                            }
                        }
                    }
                    _ => {}
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
                    inbound_tx,
                    stdin_credits,
                    mut done_tx,
                    ..
                }) = removed
                {
                    stdin_credits.close();
                    if let Some(tx) = done_tx.take() {
                        let _ = tx.send(());
                    }
                    let _ = inbound_tx.send(ExecInbound::Exit(ExecExitStatus {
                        code,
                        timed_out,
                        stdout_truncated,
                        stderr_truncated,
                    }));
                }
            }
            Message::CopyDone { bytes_transferred } => {
                let removed = lock_unpoisoned(&ops).remove(&stream_id);
                match removed {
                    Some(StreamHandler::CopyIn {
                        stdin_credits,
                        mut reply_tx,
                    }) => {
                        stdin_credits.close();
                        if let Some(tx) = reply_tx.take() {
                            let _ = tx.send(Ok(bytes_transferred));
                        }
                    }
                    Some(StreamHandler::CopyOut {
                        max_bytes,
                        buffer,
                        mut reply_tx,
                        ..
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
                    Some(StreamHandler::CopyIn {
                        stdin_credits,
                        mut reply_tx,
                    }) => {
                        stdin_credits.close();
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
                    stdin_credits,
                    _egress_permit: egress_permit,
                    ..
                }) = removed
                {
                    drop(egress_permit);
                    stdin_credits.close();
                    if let Some(tx) = connect_tx.take() {
                        let _ = tx.send(Err(SandboxError::Transport(message)));
                    } else {
                        let _ = inbound_tx.send(TunnelInbound::RemoteClose);
                    }
                }
            }
            Message::StreamClose => {
                let removed = lock_unpoisoned(&ops).remove(&stream_id);
                if let Some(StreamHandler::Tunnel {
                    mut connect_tx,
                    inbound_tx,
                    stdin_credits,
                    _egress_permit: egress_permit,
                    ..
                }) = removed
                {
                    drop(egress_permit);
                    stdin_credits.close();
                    if let Some(tx) = connect_tx.take() {
                        let _ = tx.send(Err(SandboxError::Transport(
                            "guest closed tunnel stream before ConnectAck".to_owned(),
                        )));
                    } else {
                        let _ = inbound_tx.send(TunnelInbound::RemoteClose);
                    }
                }
            }
            Message::EgressOpen => {
                handle_egress_open(
                    stream_id,
                    &egress_tx,
                    &active_guest_egress,
                    &session_closed_tx,
                    &tokio_handle,
                    &outbound,
                    &ops,
                    io_timeout,
                );
            }
            Message::ConfigureNetworkAck { proxy_port } if stream_id == StreamId(0) => {
                let ack_tx = lock_unpoisoned(&pending_network_ack).take();
                if let Some(tx) = ack_tx {
                    let _ = tx.send(Ok(proxy_port));
                }
            }
            Message::Ping { seq } => {
                if let Ok(frame) = Frame::from_message(stream_id, &Message::Pong { seq }) {
                    let _ = outbound.enqueue_control(frame);
                }
            }
            Message::Shutdown => {
                transport_closed.store(true, Ordering::Release);
                outbound.close(Some("guest VM shut down".to_owned()));
                let _ = session_closed_tx.send(Some("guest VM shut down".to_owned()));
                fail_all_pending_ops(&ops, &pending_network_ack, "guest VM shut down");
                return;
            }
            Message::StreamCredit {
                channel: StreamChannel::Stdin,
                bytes,
            } => {
                let map = lock_unpoisoned(&ops);
                match map.get(&stream_id) {
                    Some(StreamHandler::Exec { stdin_credits, .. })
                    | Some(StreamHandler::CopyIn { stdin_credits, .. })
                    | Some(StreamHandler::Tunnel { stdin_credits, .. }) => {
                        stdin_credits.grant(bytes);
                    }
                    _ => {}
                }
            }
            Message::StreamCredit { .. } | Message::Pong { .. } => {}
            other => {
                let reason = format!(
                    "unexpected guest message {:?} on stream {stream_id}",
                    other.kind()
                );
                transport_closed.store(true, Ordering::Release);
                outbound.close(Some(reason.clone()));
                let _ = session_closed_tx.send(Some(reason.clone()));
                fail_all_pending_ops(&ops, &pending_network_ack, &reason);
                return;
            }
        }

        if outbound.is_closed() {
            let reason = "QEMU IPC outbound queue closed".to_owned();
            transport_closed.store(true, Ordering::Release);
            let _ = session_closed_tx.send(Some(reason.clone()));
            let _ = read_half.shutdown();
            fail_all_pending_ops(&ops, &pending_network_ack, &reason);
            return;
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn handle_egress_open(
    stream_id: StreamId,
    egress_tx: &Mutex<Option<mpsc::Sender<TunnelStream>>>,
    active_guest_egress: &Arc<AtomicUsize>,
    session_closed_tx: &watch::Sender<Option<String>>,
    tokio_handle: &Option<tokio::runtime::Handle>,
    outbound: &Arc<OutboundQueue>,
    ops: &Arc<Mutex<HashMap<StreamId, StreamHandler>>>,
    io_timeout: Duration,
) {
    let reject = |msg: String| {
        if let Ok(frame) = Frame::from_message(stream_id, &Message::ConnectError { message: msg }) {
            let _ = outbound.enqueue_control(frame);
        }
    };

    if !is_guest_stream_id(stream_id) {
        reject(format!(
            "EgressOpen requires guest stream ID with high bit set, got {stream_id}"
        ));
        return;
    }

    let maybe_tx = lock_unpoisoned(egress_tx).clone();
    let (Some(tx), Some(rt)) = (maybe_tx, tokio_handle.as_ref()) else {
        reject("host egress proxy is disabled for this sandbox".to_owned());
        return;
    };

    if lock_unpoisoned(ops).contains_key(&stream_id) {
        reject(format!("duplicate guest egress stream_id {stream_id}"));
        return;
    }

    let Some(permit) =
        GuestEgressPermit::try_acquire(active_guest_egress, MAX_ACTIVE_GUEST_EGRESS_STREAMS)
    else {
        reject("too many concurrent guest egress streams".to_owned());
        return;
    };

    let (mut client_stream, tunnel_handle) = TunnelStream::channel(stream_id);
    // Keep the egress concurrency permit held across both the reader stream handler and the Host
    // proxy TunnelStream so guest StreamClose cannot free a slot before Host forwarding finishes.
    client_stream.attach_guard(Arc::clone(&permit) as Arc<dyn std::any::Any + Send + Sync>);
    let (inbound_tx, inbound_rx) = mpsc::unbounded_channel();
    let queued_bytes = Arc::new(AtomicUsize::new(0));
    let stdin_credits = Arc::new(StdinCreditWindow::new(INITIAL_STREAM_CREDIT_BYTES));

    match tx.try_send(client_stream) {
        Ok(()) => {
            lock_unpoisoned(ops).insert(
                stream_id,
                StreamHandler::Tunnel {
                    connect_tx: None,
                    inbound_tx,
                    queued_bytes: Arc::clone(&queued_bytes),
                    stdin_credits: Arc::clone(&stdin_credits),
                    stdout_eof_seen: false,
                    _egress_permit: Some(permit),
                },
            );
            if let Ok(frame) = Frame::from_message(stream_id, &Message::ConnectAck) {
                if outbound.enqueue_control(frame).is_err() {
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
                queued_bytes,
                stdin_credits,
                tunnel_handle,
                session_closed_tx.subscribe(),
                io_timeout,
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

fn fail_all_pending_ops(
    ops: &Mutex<HashMap<StreamId, StreamHandler>>,
    pending_network_ack: &NetworkAckSlot,
    reason: &str,
) {
    let ack_tx = lock_unpoisoned(pending_network_ack).take();
    if let Some(tx) = ack_tx {
        let _ = tx.send(Err(SandboxError::Transport(reason.to_owned())));
    }

    let drained: Vec<StreamHandler> = {
        let mut map = lock_unpoisoned(ops);
        map.drain().map(|(_, handler)| handler).collect()
    };

    for handler in drained {
        match handler {
            StreamHandler::Exec {
                inbound_tx,
                stdin_credits,
                mut done_tx,
                ..
            } => {
                stdin_credits.close();
                if let Some(tx) = done_tx.take() {
                    let _ = tx.send(());
                }
                let _ = inbound_tx.send(ExecInbound::Abort(SandboxError::Transport(
                    reason.to_owned(),
                )));
            }
            StreamHandler::CopyIn {
                stdin_credits,
                mut reply_tx,
            } => {
                stdin_credits.close();
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
                stdin_credits,
                _egress_permit: egress_permit,
                ..
            } => {
                drop(egress_permit);
                stdin_credits.close();
                if let Some(tx) = connect_tx.take() {
                    let _ = tx.send(Err(SandboxError::Transport(reason.to_owned())));
                } else {
                    let _ = inbound_tx.send(TunnelInbound::RemoteClose);
                }
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
                    Message::StreamCredit {
                        channel: StreamChannel::Stdout,
                        ..
                    } => {}
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
    async fn egress_graceful_shutdown_drop_drains_response_before_remote_eof() {
        use sandbox_protocol::GUEST_STREAM_ID_BIT;

        let listener = AgentIpcEndpoint::bind_temp("drv-egress-http").unwrap();
        let sock_path = listener.socket_path().to_path_buf();
        let (guest_done_tx, guest_done_rx) = oneshot::channel();

        let guest_thread = thread::spawn(move || {
            let mut client = IpcStream::connect(&sock_path).unwrap();
            let guest_sid = StreamId(GUEST_STREAM_ID_BIT | 2);

            write_frame(
                &mut client,
                &Frame::from_message(guest_sid, &Message::EgressOpen).unwrap(),
            )
            .unwrap();
            let ack = read_frame(&mut client).unwrap();
            assert_eq!(ack.decode_message().unwrap(), Message::ConnectAck);

            // Send HTTP request WITHOUT closing write side (eof: false), like real `wget`.
            write_frame(
                &mut client,
                &Frame::from_message(
                    guest_sid,
                    &Message::StreamData {
                        channel: StreamChannel::Stdout,
                        eof: false,
                        data: b"GET http://allowed.test/ok HTTP/1.1\r\n\r\n".to_vec(),
                    },
                )
                .unwrap(),
            )
            .unwrap();

            // Must receive full HTTP response + Stdin eof:true without premature StreamClose.
            let mut resp = Vec::new();
            loop {
                let f = read_frame(&mut client).unwrap();
                assert_eq!(f.header.stream_id, guest_sid);
                match f.decode_message().unwrap() {
                    Message::StreamData {
                        channel: StreamChannel::Stdin,
                        eof,
                        data,
                    } => {
                        resp.extend_from_slice(&data);
                        if eof {
                            break;
                        }
                    }
                    Message::StreamCredit {
                        channel: StreamChannel::Stdout,
                        ..
                    } => {}
                    other => panic!("expected Stdin StreamData, got {other:?}"),
                }
            }

            // Now guest closes its TCP socket (Stdout eof: true).
            write_frame(
                &mut client,
                &Frame::from_message(
                    guest_sid,
                    &Message::StreamData {
                        channel: StreamChannel::Stdout,
                        eof: true,
                        data: Vec::new(),
                    },
                )
                .unwrap(),
            )
            .unwrap();
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

        let mut egress_stream = tokio::time::timeout(Duration::from_secs(2), egress_rx.recv())
            .await
            .unwrap()
            .unwrap();
        let mut req_buf = [0u8; 128];
        let n = egress_stream.read(&mut req_buf).await.unwrap();
        assert_eq!(&req_buf[..n], b"GET http://allowed.test/ok HTTP/1.1\r\n\r\n");

        // Write response, call shutdown(), and drop immediately BEFORE guest sends Stdout EOF.
        egress_stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .await
            .unwrap();
        egress_stream.shutdown().await.unwrap();
        drop(egress_stream);

        let guest_resp = tokio::time::timeout(Duration::from_secs(2), guest_done_rx)
            .await
            .expect("guest receives full HTTP response")
            .unwrap();
        assert_eq!(guest_resp, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");

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

    #[tokio::test]
    async fn dynamic_enable_egress_proxy_activates_egress_open_and_rejects_duplicate_or_port_zero()
    {
        use sandbox_protocol::GUEST_STREAM_ID_BIT;

        let listener = AgentIpcEndpoint::bind_temp("drv-dyn-egress").unwrap();
        let sock_path = listener.socket_path().to_path_buf();
        let (pre_rejected_tx, pre_rejected_rx) = oneshot::channel();
        let (guest_done_tx, guest_done_rx) = oneshot::channel();

        let guest_thread = thread::spawn(move || {
            let mut client = IpcStream::connect(&sock_path).unwrap();

            // 1. Before enable_egress_proxy, guest EgressOpen must be rejected as disabled.
            let pre_sid = StreamId(GUEST_STREAM_ID_BIT | 1);
            write_frame(
                &mut client,
                &Frame::from_message(pre_sid, &Message::EgressOpen).unwrap(),
            )
            .unwrap();
            let pre_reply = read_frame(&mut client).unwrap();
            assert_eq!(pre_reply.header.stream_id, pre_sid);
            assert!(matches!(
                pre_reply.decode_message().unwrap(),
                Message::ConnectError { message } if message.contains("disabled")
            ));
            let _ = pre_rejected_tx.send(());

            // 2. Receive ConfigureNetwork on StreamId(0), reply ConfigureNetworkAck, then immediately open EgressOpen.
            let cfg_frame = read_frame(&mut client).unwrap();
            assert_eq!(cfg_frame.header.stream_id, StreamId(0));
            assert_eq!(
                cfg_frame.decode_message().unwrap(),
                Message::ConfigureNetwork {
                    enable_egress_proxy: true,
                    proxy_port: 3128,
                }
            );
            write_frame(
                &mut client,
                &Frame::from_message(
                    StreamId(0),
                    &Message::ConfigureNetworkAck { proxy_port: 3128 },
                )
                .unwrap(),
            )
            .unwrap();

            let egress_sid = StreamId(GUEST_STREAM_ID_BIT | 2);
            write_frame(
                &mut client,
                &Frame::from_message(egress_sid, &Message::EgressOpen).unwrap(),
            )
            .unwrap();

            let ack = read_frame(&mut client).unwrap();
            assert_eq!(ack.header.stream_id, egress_sid);
            assert_eq!(ack.decode_message().unwrap(), Message::ConnectAck);

            // Exchange full-duplex + half-close bytes.
            write_frame(
                &mut client,
                &Frame::from_message(
                    egress_sid,
                    &Message::StreamData {
                        channel: StreamChannel::Stdout,
                        eof: true,
                        data: b"GET http://warm.test/ HTTP/1.1\r\n\r\n".to_vec(),
                    },
                )
                .unwrap(),
            )
            .unwrap();

            let mut resp = Vec::new();
            loop {
                let f = read_frame(&mut client).unwrap();
                match f.decode_message().unwrap() {
                    Message::StreamData {
                        channel: StreamChannel::Stdin,
                        eof,
                        data,
                    } if f.header.stream_id == egress_sid => {
                        resp.extend_from_slice(&data);
                        if eof {
                            break;
                        }
                    }
                    Message::StreamCredit {
                        channel: StreamChannel::Stdout,
                        ..
                    } => {}
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
        let session = QemuVmSession::from_test_stream(host_stream, Duration::from_secs(2)).unwrap();

        // Port 0 rejected immediately before talking to guest.
        assert!(matches!(
            session.enable_egress_proxy(0).await,
            Err(SandboxError::InvalidSpec(_))
        ));

        tokio::time::timeout(Duration::from_secs(2), pre_rejected_rx)
            .await
            .expect("guest observes initial disabled EgressOpen rejection")
            .unwrap();

        let mut egress_rx = session.enable_egress_proxy(3128).await.unwrap();

        // Enabling twice on the same session returns InvalidSpec.
        assert!(matches!(
            session.enable_egress_proxy(3128).await,
            Err(SandboxError::InvalidSpec(msg)) if msg.contains("already enabled")
        ));

        let mut egress_stream = tokio::time::timeout(Duration::from_secs(2), egress_rx.recv())
            .await
            .expect("egress_rx receives guest stream")
            .expect("egress_rx open");
        assert_eq!(
            egress_stream.stream_id(),
            StreamId(GUEST_STREAM_ID_BIT | 2)
        );

        let mut got_req = Vec::new();
        egress_stream.read_to_end(&mut got_req).await.unwrap();
        assert_eq!(got_req, b"GET http://warm.test/ HTTP/1.1\r\n\r\n");

        egress_stream
            .write_all(b"HTTP/1.1 200 OK\r\n\r\nwarm-ok")
            .await
            .unwrap();
        egress_stream.shutdown().await.unwrap();
        drop(egress_stream);

        let guest_resp = tokio::time::timeout(Duration::from_secs(2), guest_done_rx)
            .await
            .expect("guest receives response")
            .unwrap();
        assert_eq!(guest_resp, b"HTTP/1.1 200 OK\r\n\r\nwarm-ok");

        assert!(session
            .graceful_shutdown(Duration::from_millis(500))
            .await
            .unwrap());
        guest_thread.join().unwrap();
    }

    #[tokio::test]
    async fn enable_egress_proxy_rejects_ack_port_zero_and_cleans_up_on_transport_close() {
        use sandbox_protocol::GUEST_STREAM_ID_BIT;

        // 1. Guest returns ConfigureNetworkAck { proxy_port: 0 } -> Transport error + full rollback,
        //    so subsequent EgressOpen is still rejected and a retry succeeds cleanly.
        let listener = AgentIpcEndpoint::bind_temp("drv-dyn-zero").unwrap();
        let sock_path = listener.socket_path().to_path_buf();
        let (zero_checked_tx, zero_checked_rx) = oneshot::channel();
        let (egress_rejected_tx, egress_rejected_rx) = oneshot::channel();

        let guest_thread = thread::spawn(move || {
            let mut client = IpcStream::connect(&sock_path).unwrap();

            let cfg1 = read_frame(&mut client).unwrap();
            assert_eq!(cfg1.header.stream_id, StreamId(0));
            assert_eq!(
                cfg1.decode_message().unwrap(),
                Message::ConfigureNetwork {
                    enable_egress_proxy: true,
                    proxy_port: 3128,
                }
            );
            write_frame(
                &mut client,
                &Frame::from_message(
                    StreamId(0),
                    &Message::ConfigureNetworkAck { proxy_port: 0 },
                )
                .unwrap(),
            )
            .unwrap();

            // Wait for host to confirm rollback before sending EgressOpen.
            let _ = zero_checked_rx.blocking_recv();
            let sid = StreamId(GUEST_STREAM_ID_BIT | 1);
            write_frame(
                &mut client,
                &Frame::from_message(sid, &Message::EgressOpen).unwrap(),
            )
            .unwrap();
            let rej = read_frame(&mut client).unwrap();
            assert!(matches!(
                rej.decode_message().unwrap(),
                Message::ConnectError { message } if message.contains("disabled")
            ));
            let _ = egress_rejected_tx.send(());

            // Subsequent retry succeeds cleanly.
            let cfg2 = read_frame(&mut client).unwrap();
            assert_eq!(
                cfg2.decode_message().unwrap(),
                Message::ConfigureNetwork {
                    enable_egress_proxy: true,
                    proxy_port: 3129,
                }
            );
            write_frame(
                &mut client,
                &Frame::from_message(
                    StreamId(0),
                    &Message::ConfigureNetworkAck { proxy_port: 3129 },
                )
                .unwrap(),
            )
            .unwrap();

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

        let err = session.enable_egress_proxy(3128).await.unwrap_err();
        assert!(matches!(err, SandboxError::Transport(msg) if msg.contains("port 0")));
        assert!(lock_unpoisoned(&session.egress_tx).is_none());
        assert!(lock_unpoisoned(&session.pending_network_ack).is_none());
        let _ = zero_checked_tx.send(());
        tokio::time::timeout(Duration::from_secs(2), egress_rejected_rx)
            .await
            .expect("guest receives disabled EgressOpen rejection after rollback")
            .unwrap();

        let _rx = session.enable_egress_proxy(3129).await.unwrap();
        assert!(session
            .graceful_shutdown(Duration::from_millis(500))
            .await
            .unwrap());
        guest_thread.join().unwrap();

        // 2. Transport closes while enable_egress_proxy awaits ConfigureNetworkAck -> returns promptly
        //    with Transport error (without waiting for the 5s io_timeout) and cleans up state.
        let listener2 = AgentIpcEndpoint::bind_temp("drv-dyn-close").unwrap();
        let sock_path2 = listener2.socket_path().to_path_buf();
        let guest_thread2 = thread::spawn(move || {
            let mut client = IpcStream::connect(&sock_path2).unwrap();
            let cfg = read_frame(&mut client).unwrap();
            assert!(matches!(
                cfg.decode_message().unwrap(),
                Message::ConfigureNetwork { .. }
            ));
            // Drop client immediately to close transport before sending ConfigureNetworkAck.
        });

        let host_stream2 = listener2.accept_timeout(Duration::from_secs(2)).unwrap();
        let session2 =
            QemuVmSession::from_test_stream(host_stream2, Duration::from_secs(5)).unwrap();

        let err2 = tokio::time::timeout(
            Duration::from_secs(1),
            session2.enable_egress_proxy(3128),
        )
        .await
        .expect("transport close must fail pending enable_egress_proxy immediately")
        .unwrap_err();
        assert!(matches!(err2, SandboxError::Transport(_)));
        assert!(lock_unpoisoned(&session2.egress_tx).is_none());
        assert!(lock_unpoisoned(&session2.pending_network_ack).is_none());

        guest_thread2.join().unwrap();
    }

    #[tokio::test]
    async fn stalled_exec_stream_does_not_block_sibling_exec_or_force_kill() {
        let listener = AgentIpcEndpoint::bind_temp("drv-stall").unwrap();
        let sock_path = listener.socket_path().to_path_buf();

        let guest_thread = thread::spawn(move || {
            let mut client = IpcStream::connect(&sock_path).unwrap();
            while let Ok(frame) = read_frame(&mut client) {
                let sid = frame.header.stream_id;
                if let Message::ExecStart { argv, .. } = frame.decode_message().unwrap() {
                    if argv.first().map(String::as_str) == Some("flood") {
                        // Emit 300 chunks without waiting so caller's 256-slot output_rx fills up.
                        for _ in 0..300 {
                            if write_frame(
                                &mut client,
                                &Frame::from_message(
                                    sid,
                                    &Message::StreamData {
                                        channel: StreamChannel::Stdout,
                                        eof: false,
                                        data: vec![b'F'; 256],
                                    },
                                )
                                .unwrap(),
                            )
                            .is_err()
                            {
                                return;
                            }
                        }
                    } else {
                        let _ = write_frame(
                            &mut client,
                            &Frame::from_message(
                                sid,
                                &Message::StreamData {
                                    channel: StreamChannel::Stdout,
                                    eof: true,
                                    data: b"fast-ok".to_vec(),
                                },
                            )
                            .unwrap(),
                        );
                        let _ = write_frame(
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
                        );
                    }
                }
            }
        });

        let host_stream = listener.accept_timeout(Duration::from_secs(2)).unwrap();
        let session = QemuVmSession::from_test_stream(host_stream, Duration::from_secs(2)).unwrap();

        // 1. Start stalled stream and intentionally NEVER read `stalled.next_output()`.
        let mut stalled = session
            .exec_stream(ExecRequest {
                target: ExecTarget::Guest,
                argv: vec!["flood".into()],
                env: BTreeMap::new(),
                cwd: None,
                user: None,
                deadline: Duration::from_secs(10),
                stdout_budget_bytes: 1024 * 1024,
                stderr_budget_bytes: 4096,
            })
            .await
            .unwrap();

        // Give guest time to push all 300 chunks past OUTPUT_CHANNEL_CAPACITY (256).
        tokio::time::sleep(Duration::from_millis(50)).await;

        // 2. Sibling exec on the same session must still complete promptly without transport stall.
        let sibling = tokio::time::timeout(
            Duration::from_secs(2),
            session.exec_stream(ExecRequest {
                target: ExecTarget::Guest,
                argv: vec!["echo".into()],
                env: BTreeMap::new(),
                cwd: None,
                user: None,
                deadline: Duration::from_secs(5),
                stdout_budget_bytes: 4096,
                stderr_budget_bytes: 4096,
            }),
        )
        .await
        .expect("sibling exec_stream must not stall")
        .unwrap();
        let sibling_out = tokio::time::timeout(Duration::from_secs(2), sibling.collect())
            .await
            .expect("sibling collect must not stall")
            .unwrap();
        assert_eq!(sibling_out.stdout, b"fast-ok");
        assert_eq!(sibling_out.exit.code, Some(0));

        // 3. `force_kill` must unblock immediately even while `stalled` has full unread channels.
        tokio::time::timeout(Duration::from_secs(2), session.force_kill())
            .await
            .expect("force_kill must not hang on stalled stream")
            .unwrap();

        let stalled_exit = tokio::time::timeout(Duration::from_secs(1), stalled.wait_exit())
            .await
            .expect("stalled wait_exit must resolve immediately after force_kill");
        assert!(matches!(stalled_exit, Err(SandboxError::Transport(_))));

        guest_thread.join().unwrap();
    }

    #[tokio::test]
    async fn egress_open_caps_concurrent_guest_streams_and_releases_permits_on_close() {
        use sandbox_protocol::GUEST_STREAM_ID_BIT;

        let listener = AgentIpcEndpoint::bind_temp("drv-egress-cap").unwrap();
        let sock_path = listener.socket_path().to_path_buf();
        let (over_cap_tx, over_cap_rx) = oneshot::channel();
        let (reopened_tx, reopened_rx) = oneshot::channel();
        let (close_first_tx, close_first_rx) = oneshot::channel();

        let guest_thread = thread::spawn(move || {
            let mut client = IpcStream::connect(&sock_path).unwrap();

            for seq in 1..=(MAX_ACTIVE_GUEST_EGRESS_STREAMS as u32) {
                let sid = StreamId(GUEST_STREAM_ID_BIT | seq);
                write_frame(
                    &mut client,
                    &Frame::from_message(sid, &Message::EgressOpen).unwrap(),
                )
                .unwrap();
                let ack = read_frame(&mut client).unwrap();
                assert_eq!(ack.header.stream_id, sid);
                assert_eq!(ack.decode_message().unwrap(), Message::ConnectAck);
            }

            // Stream #65 must be rejected immediately with ConnectError.
            let extra_sid =
                StreamId(GUEST_STREAM_ID_BIT | (MAX_ACTIVE_GUEST_EGRESS_STREAMS as u32 + 1));
            write_frame(
                &mut client,
                &Frame::from_message(extra_sid, &Message::EgressOpen).unwrap(),
            )
            .unwrap();
            let rej = read_frame(&mut client).unwrap();
            assert_eq!(rej.header.stream_id, extra_sid);
            assert!(matches!(
                rej.decode_message().unwrap(),
                Message::ConnectError { message } if message.contains("too many concurrent")
            ));
            let _ = over_cap_tx.send(());

            // Wait for host to drop one stream, then verify a new EgressOpen succeeds.
            let _ = close_first_rx.blocking_recv();
            loop {
                let frame = read_frame(&mut client).unwrap();
                if matches!(frame.decode_message().unwrap(), Message::StreamClose) {
                    break;
                }
            }
            let retry_sid =
                StreamId(GUEST_STREAM_ID_BIT | (MAX_ACTIVE_GUEST_EGRESS_STREAMS as u32 + 2));
            write_frame(
                &mut client,
                &Frame::from_message(retry_sid, &Message::EgressOpen).unwrap(),
            )
            .unwrap();
            let ack2 = read_frame(&mut client).unwrap();
            assert_eq!(ack2.header.stream_id, retry_sid);
            assert_eq!(ack2.decode_message().unwrap(), Message::ConnectAck);
            let _ = reopened_tx.send(());
        });

        let host_stream = listener.accept_timeout(Duration::from_secs(2)).unwrap();
        let (session, mut egress_rx) =
            QemuVmSession::from_test_stream_with_egress(host_stream, Duration::from_secs(2))
                .unwrap();

        let mut held = Vec::new();
        for _ in 0..MAX_ACTIVE_GUEST_EGRESS_STREAMS {
            held.push(egress_rx.recv().await.unwrap());
        }
        tokio::time::timeout(Duration::from_secs(2), over_cap_rx)
            .await
            .unwrap()
            .unwrap();

        // Drop one held TunnelStream and confirm its permit is released so retry_sid is accepted.
        drop(held.pop());
        let _ = close_first_tx.send(());
        tokio::time::timeout(Duration::from_secs(2), reopened_rx)
            .await
            .unwrap()
            .unwrap();

        session.force_kill().await.unwrap();
        guest_thread.join().unwrap();
    }

    #[tokio::test]
    async fn egress_permit_stays_reserved_after_guest_stream_close_until_host_tunnel_drops() {
        use sandbox_protocol::GUEST_STREAM_ID_BIT;
        use tokio::io::AsyncReadExt;

        let listener = AgentIpcEndpoint::bind_temp("drv-egress-permit-hold").unwrap();
        let sock_path = listener.socket_path().to_path_buf();
        let (close_ack_tx, close_ack_rx) = oneshot::channel::<()>();

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

            // Immediately close the guest stream handler while the Host proxy TunnelStream stays open.
            write_frame(
                &mut client,
                &Frame::from_message(guest_sid, &Message::StreamClose).unwrap(),
            )
            .unwrap();
            let _ = close_ack_tx.send(());

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

        let mut egress_stream = tokio::time::timeout(Duration::from_secs(2), egress_rx.recv())
            .await
            .unwrap()
            .expect("expected accepted egress tunnel stream");
        tokio::time::timeout(Duration::from_secs(2), close_ack_rx)
            .await
            .unwrap()
            .unwrap();

        // Reading EOF proves the reader loop processed Message::StreamClose and removed StreamHandler::Tunnel.
        let mut eof_buf = [0u8; 8];
        let n = tokio::time::timeout(Duration::from_secs(2), egress_stream.read(&mut eof_buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(n, 0);

        assert_eq!(
            session.active_guest_egress_count(),
            1,
            "permit must stay reserved while Host TunnelStream is still alive"
        );

        drop(egress_stream);
        assert_eq!(
            session.active_guest_egress_count(),
            0,
            "permit must release once Host TunnelStream drops"
        );

        session.force_kill().await.unwrap();
        guest_thread.join().unwrap();
    }

    #[test]
    fn outbound_queue_control_lane_cap_closes_queue_on_overflow() {
        let queue = OutboundQueue::new();
        let pong = Frame::from_message(StreamId(0), &Message::Pong { seq: 1 }).unwrap();

        for _ in 0..MAX_OUTBOUND_CONTROL_FRAMES {
            queue.enqueue_control(pong.clone()).unwrap();
        }
        assert!(!queue.is_closed());

        let err = queue
            .enqueue_control(pong)
            .expect_err("4097th queued control frame must trip capacity ceiling");
        assert!(matches!(err, SandboxError::Transport(msg) if msg.contains("exceeded capacity")));
        assert!(queue.is_closed());
    }

    #[tokio::test]
    async fn tunnel_preserves_stdin_half_close_after_stdout_eof_and_rejects_duplicate_eof() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = AgentIpcEndpoint::bind_temp("drv-tunnel-eof").unwrap();
        let sock_path = listener.socket_path().to_path_buf();
        let (stdin_received_tx, stdin_received_rx) = oneshot::channel::<Vec<u8>>();
        let (send_dup_eof_tx, send_dup_eof_rx) = oneshot::channel::<()>();
        let (close_frame_tx, close_frame_rx) = oneshot::channel::<()>();

        let guest_thread = thread::spawn(move || {
            let mut client = IpcStream::connect(&sock_path).unwrap();

            // 1. Accept first tunnel: send Stdout data + EOF immediately, THEN read Host Stdin!
            let start1 = read_frame(&mut client).unwrap();
            let sid1 = start1.header.stream_id;
            assert!(matches!(
                start1.decode_message().unwrap(),
                Message::ConnectStart { .. }
            ));
            write_frame(
                &mut client,
                &Frame::from_message(sid1, &Message::ConnectAck).unwrap(),
            )
            .unwrap();
            write_frame(
                &mut client,
                &Frame::from_message(
                    sid1,
                    &Message::StreamData {
                        channel: StreamChannel::Stdout,
                        eof: true,
                        data: b"guest-reply-eof".to_vec(),
                    },
                )
                .unwrap(),
            )
            .unwrap();

            // Host must STILL be able to stream Stdin + Stdin EOF after Guest Stdout EOF!
            let mut collected_stdin = Vec::new();
            loop {
                let frame = read_frame(&mut client).unwrap();
                assert_eq!(frame.header.stream_id, sid1);
                if let Message::StreamData {
                    channel: StreamChannel::Stdin,
                    eof,
                    data,
                } = frame.decode_message().unwrap()
                {
                    collected_stdin.extend_from_slice(&data);
                    if eof {
                        break;
                    }
                }
            }
            let _ = stdin_received_tx.send(collected_stdin);

            // 2. Accept second tunnel: send duplicate 0-byte Stdout EOFs and verify Host aborts it.
            let start2 = read_frame(&mut client).unwrap();
            let sid2 = start2.header.stream_id;
            write_frame(
                &mut client,
                &Frame::from_message(sid2, &Message::ConnectAck).unwrap(),
            )
            .unwrap();
            write_frame(
                &mut client,
                &Frame::from_message(
                    sid2,
                    &Message::StreamData {
                        channel: StreamChannel::Stdout,
                        eof: true,
                        data: Vec::new(),
                    },
                )
                .unwrap(),
            )
            .unwrap();
            let _ = send_dup_eof_rx.blocking_recv();
            write_frame(
                &mut client,
                &Frame::from_message(
                    sid2,
                    &Message::StreamData {
                        channel: StreamChannel::Stdout,
                        eof: true,
                        data: Vec::new(),
                    },
                )
                .unwrap(),
            )
            .unwrap();

            loop {
                let frame = read_frame(&mut client).unwrap();
                if frame.header.stream_id == sid2
                    && matches!(frame.decode_message().unwrap(), Message::StreamClose)
                {
                    let _ = close_frame_tx.send(());
                    break;
                }
            }
        });

        let host_stream = listener.accept_timeout(Duration::from_secs(2)).unwrap();
        let session = QemuVmSession::from_test_stream(host_stream, Duration::from_secs(2)).unwrap();

        let mut t1 = session
            .open_tunnel(StreamTargetWire::PodmanUnixSocket)
            .await
            .unwrap();
        let mut out_buf = Vec::new();
        t1.read_to_end(&mut out_buf).await.unwrap();
        assert_eq!(out_buf, b"guest-reply-eof");

        // Write host -> guest payload AFTER guest -> host reached EOF (Docker hijack half-close).
        t1.write_all(b"host-after-guest-eof").await.unwrap();
        t1.shutdown().await.unwrap();
        let guest_got = tokio::time::timeout(Duration::from_secs(2), stdin_received_rx)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(guest_got, b"host-after-guest-eof");
        drop(t1);

        // Second tunnel: duplicate post-EOF 0-byte Stdout frame aborts and removes stream from ops.
        let mut t2 = session
            .open_tunnel(StreamTargetWire::PodmanUnixSocket)
            .await
            .unwrap();
        let mut tmp = [0u8; 8];
        assert_eq!(t2.read(&mut tmp).await.unwrap(), 0);
        let _ = send_dup_eof_tx.send(());

        tokio::time::timeout(Duration::from_secs(2), close_frame_rx)
            .await
            .expect("duplicate post-EOF Stdout frame must emit StreamClose")
            .unwrap();
        assert!(
            !lock_unpoisoned(&session.ops).contains_key(&t2.stream_id()),
            "duplicate post-EOF tunnel must be removed from ops"
        );
        drop(t2);

        session.force_kill().await.unwrap();
        guest_thread.join().unwrap();
    }

    #[tokio::test]
    async fn session_exec_stream_enforces_host_budget_and_reaps_abandoned_ops_entry() {
        let listener = AgentIpcEndpoint::bind_temp("drv-rogue-exec").unwrap();
        let sock_path = listener.socket_path().to_path_buf();
        let (cancel_seen_tx, cancel_seen_rx) = oneshot::channel::<()>();

        let guest_thread = thread::spawn(move || {
            let mut client = IpcStream::connect(&sock_path).unwrap();
            let start = read_frame(&mut client).unwrap();
            let sid = start.header.stream_id;
            assert!(matches!(
                start.decode_message().unwrap(),
                Message::ExecStart { .. }
            ));

            // Rogue guest ignores stdout_budget_bytes (12) and sends 1024 bytes without ExecExit.
            write_frame(
                &mut client,
                &Frame::from_message(
                    sid,
                    &Message::StreamData {
                        channel: StreamChannel::Stdout,
                        eof: false,
                        data: vec![b'R'; 1024],
                    },
                )
                .unwrap(),
            )
            .unwrap();

            while let Ok(frame) = read_frame(&mut client) {
                if frame.header.stream_id == sid
                    && matches!(frame.decode_message().unwrap(), Message::ExecCancel)
                {
                    let _ = cancel_seen_tx.send(());
                    break;
                }
            }
            // Stay silent without ever sending ExecExit until socket closes.
            while read_frame(&mut client).is_ok() {}
        });

        let host_stream = listener.accept_timeout(Duration::from_secs(2)).unwrap();
        let session = QemuVmSession::from_test_stream(host_stream, Duration::from_secs(2)).unwrap();

        let stream = session
            .exec_stream(ExecRequest {
                target: ExecTarget::Guest,
                argv: vec!["rogue".into()],
                env: BTreeMap::new(),
                cwd: None,
                user: None,
                deadline: Duration::from_millis(120),
                stdout_budget_bytes: 12,
                stderr_budget_bytes: 12,
            })
            .await
            .unwrap();
        let sid = stream.stream_id;

        let out = tokio::time::timeout(Duration::from_secs(2), stream.collect())
            .await
            .expect("host budget enforcement must complete even when guest never sends ExecExit")
            .unwrap();
        assert_eq!(out.stdout, b"RRRRRRRRRRRR");
        assert!(out.exit.stdout_truncated);
        assert_eq!(out.exit.code, None);

        tokio::time::timeout(Duration::from_secs(2), cancel_seen_rx)
            .await
            .expect("guest must receive ExecCancel")
            .unwrap();

        // Give `pump_exec_output` a brief tick after `exit_rx` dropped to reap `ops`.
        for _ in 0..40 {
            if !lock_unpoisoned(&session.ops).contains_key(&sid) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(
            !lock_unpoisoned(&session.ops).contains_key(&sid),
            "abandoned exec stream must be removed from session.ops"
        );

        session.force_kill().await.unwrap();
        guest_thread.join().unwrap();
    }

    #[tokio::test]
    async fn boot_vm_rejects_bundle_guest_arch_mismatch_before_spawning_qemu() {
        use sandbox_core::{
            AccelerationPolicy, IsolationMode, ResourceBudget, SandboxId, SandboxSpec,
        };
        use std::fs;

        let dir = std::env::temp_dir().join(format!(
            "minipod-driver-arch-mismatch-{}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        let kernel = dir.join("vmlinuz");
        let initrd = dir.join("initrd");
        let overlay = dir.join("overlay.qcow2");
        fs::write(&kernel, b"k").unwrap();
        fs::write(&initrd, b"i").unwrap();
        fs::write(&overlay, b"o").unwrap();

        let driver = QemuVmDriver::new(QemuDriverConfig {
            arch: GuestArch::X86_64,
            ..QemuDriverConfig::default()
        })
        .unwrap();

        let res = driver
            .boot_vm(VmBootConfig {
                sandbox_id: SandboxId::new("sb-arch"),
                spec: SandboxSpec {
                    isolation: IsolationMode::VmRequired,
                    acceleration: AccelerationPolicy::Preferred,
                    network: NetworkPolicy::Isolated,
                    budget: ResourceBudget {
                        guest_vcpus: 1,
                        host_cpu_quota_Millicores: None,
                        guest_ram_mb: 256,
                        host_rss_budget_mb: Some(512),
                        virtual_disk_mb: 512,
                        host_storage_budget_mb: 1024,
                    },
                    lease_ttl: Duration::from_secs(30),
                },
                overlay: sandbox_runtime::PreparedOverlay {
                    overlay_path: overlay,
                    kernel_path: kernel,
                    initramfs_path: initrd,
                    rootfs_path: dir.join("base.qcow2"),
                    kernel_cmdline: "quiet".to_owned(),
                    guest_arch: Some(GuestArch::Aarch64),
                    virtual_disk_mb: 512,
                    provisioned_host_bytes: 1,
                    bundle_guard: None,
                },
                work_dir: dir.clone(),
                on_boot_progress: None,
            })
            .await;
        let _ = fs::remove_dir_all(&dir);
        let err = res.expect_err("guest_arch mismatch must fail before launching QEMU");
        assert!(matches!(err, SandboxError::InvalidSpec(_)));
    }

    #[tokio::test]
    async fn stalled_copy_in_and_copy_out_time_out_reap_ops_and_emit_stream_close() {
        let listener = AgentIpcEndpoint::bind_temp("drv-stalled-copy").unwrap();
        let sock_path = listener.socket_path().to_path_buf();
        let (closed_sids_tx, closed_sids_rx) = oneshot::channel::<(StreamId, StreamId)>();

        let guest_thread = thread::spawn(move || {
            let mut client = IpcStream::connect(&sock_path).unwrap();

            // 1. CopyInStart arrives, followed by Stdin EOF; guest stalls without sending CopyDone.
            let in_start = read_frame(&mut client).unwrap();
            let in_sid = in_start.header.stream_id;
            assert!(matches!(
                in_start.decode_message().unwrap(),
                Message::CopyInStart { .. }
            ));
            let in_close = loop {
                let frame = read_frame(&mut client).unwrap();
                if frame.header.stream_id == in_sid
                    && matches!(frame.decode_message().unwrap(), Message::StreamClose)
                {
                    break in_sid;
                }
            };

            // 2. CopyOutStart arrives; guest stalls without sending any StreamData or CopyDone.
            let out_start = read_frame(&mut client).unwrap();
            let out_sid = out_start.header.stream_id;
            assert!(matches!(
                out_start.decode_message().unwrap(),
                Message::CopyOutStart { .. }
            ));
            let out_close = loop {
                let frame = read_frame(&mut client).unwrap();
                if frame.header.stream_id == out_sid
                    && matches!(frame.decode_message().unwrap(), Message::StreamClose)
                {
                    break out_sid;
                }
            };

            let _ = closed_sids_tx.send((in_close, out_close));
            while read_frame(&mut client).is_ok() {}
        });

        let host_stream = listener.accept_timeout(Duration::from_secs(2)).unwrap();
        let session =
            QemuVmSession::from_test_stream(host_stream, Duration::from_millis(80)).unwrap();

        let in_err = session
            .copy_in_tar("/workspace", b"tar".to_vec(), 4096)
            .await
            .expect_err("stalled copy_in must time out");
        assert!(matches!(in_err, SandboxError::Transport(_)), "got {in_err:?}");
        assert!(
            lock_unpoisoned(&session.ops).is_empty(),
            "timed-out copy_in must remove stream from session.ops"
        );

        let out_err = session
            .copy_out_tar("/workspace", 4096)
            .await
            .expect_err("stalled copy_out must time out");
        assert!(matches!(out_err, SandboxError::Transport(_)), "got {out_err:?}");
        assert!(
            lock_unpoisoned(&session.ops).is_empty(),
            "timed-out copy_out must remove stream from session.ops"
        );

        let (in_sid, out_sid) = tokio::time::timeout(Duration::from_secs(2), closed_sids_rx)
            .await
            .expect("guest must observe StreamClose for both stalled copy operations")
            .unwrap();
        assert_ne!(in_sid, out_sid);

        session.force_kill().await.unwrap();
        guest_thread.join().unwrap();
    }

    #[tokio::test]
    async fn copy_in_rejects_mismatched_copy_done_and_empty_copy_out_frames_do_not_prevent_timeout() {
        let listener = AgentIpcEndpoint::bind_temp("drv-copy-hardening").unwrap();
        let sock_path = listener.socket_path().to_path_buf();

        let guest_thread = thread::spawn(move || {
            let mut client = IpcStream::connect(&sock_path).unwrap();

            // 1. CopyIn receives 3 bytes + EOF, guest lies and replies CopyDone(1).
            let in_start = read_frame(&mut client).unwrap();
            let in_sid = in_start.header.stream_id;
            loop {
                let frame = read_frame(&mut client).unwrap();
                if frame.header.stream_id == in_sid {
                    if let Message::StreamData { eof: true, .. } = frame.decode_message().unwrap() {
                        break;
                    }
                }
            }
            write_frame(
                &mut client,
                &Frame::from_message(in_sid, &Message::CopyDone { bytes_transferred: 1 }).unwrap(),
            )
            .unwrap();

            // 2. CopyOut receives CopyOutStart, guest spams 0-byte non-EOF heartbeats.
            let out_start = read_frame(&mut client).unwrap();
            let out_sid = out_start.header.stream_id;
            for _ in 0..4 {
                thread::sleep(Duration::from_millis(25));
                if write_frame(
                    &mut client,
                    &Frame::from_message(
                        out_sid,
                        &Message::StreamData {
                            channel: StreamChannel::Stdout,
                            eof: false,
                            data: Vec::new(),
                        },
                    )
                    .unwrap(),
                )
                .is_err()
                {
                    break;
                }
            }
            while read_frame(&mut client).is_ok() {}
        });

        let host_stream = listener.accept_timeout(Duration::from_secs(2)).unwrap();
        let session =
            QemuVmSession::from_test_stream(host_stream, Duration::from_millis(75)).unwrap();

        let err_in = session
            .copy_in_tar("/workspace", b"abc".to_vec(), 4096)
            .await
            .expect_err("copy_in with mismatched CopyDone count must fail");
        assert!(matches!(err_in, SandboxError::Transport(_)), "got {err_in:?}");

        let err_out = session
            .copy_out_tar("/workspace", 4096)
            .await
            .expect_err("0-byte CopyOut heartbeats must not defeat io_timeout");
        assert!(matches!(err_out, SandboxError::Transport(_)), "got {err_out:?}");

        session.force_kill().await.unwrap();
        guest_thread.join().unwrap();
    }

    #[tokio::test]
    async fn one_byte_exec_stream_frames_are_bounded_by_per_frame_overhead() {
        let listener = AgentIpcEndpoint::bind_temp("drv-small-frame-cap").unwrap();
        let sock_path = listener.socket_path().to_path_buf();

        let guest_thread = thread::spawn(move || {
            let mut client = IpcStream::connect(&sock_path).unwrap();
            let start = read_frame(&mut client).unwrap();
            let sid = start.header.stream_id;
            // Flood ~34,000 1-byte frames (~34 KiB payload, > 2 MiB with 64B overhead each).
            for _ in 0..34_000 {
                if write_frame(
                    &mut client,
                    &Frame::from_message(
                        sid,
                        &Message::StreamData {
                            channel: StreamChannel::Stdout,
                            eof: false,
                            data: vec![b'x'],
                        },
                    )
                    .unwrap(),
                )
                .is_err()
                {
                    break;
                }
            }
            while read_frame(&mut client).is_ok() {}
        });

        let host_stream = listener.accept_timeout(Duration::from_secs(2)).unwrap();
        let session = QemuVmSession::from_test_stream(host_stream, Duration::from_secs(2)).unwrap();
        let mut exec = session
            .exec_stream(ExecRequest {
                target: ExecTarget::Guest,
                argv: vec!["/bin/sh".into()],
                env: Default::default(),
                cwd: None,
                user: None,
                deadline: Duration::from_secs(2),
                stdout_budget_bytes: 16 * 1024 * 1024,
                stderr_budget_bytes: 16 * 1024 * 1024,
            })
            .await
            .unwrap();

        let status = tokio::time::timeout(Duration::from_secs(4), exec.wait_exit())
            .await
            .expect("small-frame flood must abort promptly");
        assert!(status.is_err(), "expected Transport abort on small-frame flood, got {status:?}");

        session.force_kill().await.unwrap();
        guest_thread.join().unwrap();
    }

    #[tokio::test]
    async fn copy_out_rejects_repeated_eof_and_enforces_total_duration_budget() {
        let listener = AgentIpcEndpoint::bind_temp("drv-copy-out-cap").unwrap();
        let sock_path = listener.socket_path().to_path_buf();

        let guest_thread = thread::spawn(move || {
            let mut client = IpcStream::connect(&sock_path).unwrap();

            // 1. CopyOut #1: guest spams 0-byte `eof: true` frames. Second frame must abort immediately.
            let first = read_frame(&mut client).unwrap();
            let sid1 = first.header.stream_id;
            for _ in 0..3 {
                if write_frame(
                    &mut client,
                    &Frame::from_message(
                        sid1,
                        &Message::StreamData {
                            channel: StreamChannel::Stdout,
                            eof: true,
                            data: Vec::new(),
                        },
                    )
                    .unwrap(),
                )
                .is_err()
                {
                    break;
                }
            }

            // 2. CopyOut #2: skip `sid1` credit/close frames until the new `CopyOutStart` arrives,
            // then drip 1 byte every 10ms (<< io_timeout=80ms) until total duration budget expires.
            let sid2 = loop {
                let frame = read_frame(&mut client).unwrap();
                if matches!(frame.decode_message(), Ok(Message::CopyOutStart { .. })) {
                    break frame.header.stream_id;
                }
            };
            for _ in 0..200 {
                thread::sleep(Duration::from_millis(10));
                if write_frame(
                    &mut client,
                    &Frame::from_message(
                        sid2,
                        &Message::StreamData {
                            channel: StreamChannel::Stdout,
                            eof: false,
                            data: vec![b'a'],
                        },
                    )
                    .unwrap(),
                )
                .is_err()
                {
                    break;
                }
            }
            while read_frame(&mut client).is_ok() {}
        });

        let host_stream = listener.accept_timeout(Duration::from_secs(2)).unwrap();
        let session =
            QemuVmSession::from_test_stream(host_stream, Duration::from_millis(80)).unwrap();

        let err_eof = session
            .copy_out_tar("/workspace", 4096)
            .await
            .expect_err("second CopyOut EOF frame must fail cleanly");
        assert!(matches!(err_eof, SandboxError::Transport(_)), "got {err_eof:?}");

        let err_total = session
            .copy_out_tar("/workspace", 4096)
            .await
            .expect_err("1-byte CopyOut slow drip must hit total duration cap");
        assert!(
            matches!(err_total, SandboxError::Transport(ref msg) if msg.contains("total duration")),
            "got {err_total:?}"
        );

        session.force_kill().await.unwrap();
        guest_thread.join().unwrap();
    }

    #[tokio::test]
    async fn stdin_credit_window_accounts_for_frame_overhead() {
        let initial = STREAM_FRAME_OVERHEAD_BYTES as u32 + 136;
        let win = StdinCreditWindow::new(initial);
        assert_eq!(win.wait_available(1024).await, Some(136));

        // Each 1-byte frame consumes `STREAM_FRAME_OVERHEAD_BYTES + 1` (= 65) credit bytes.
        win.consume(1);
        win.consume(1);
        win.consume(1);
        // 200 - 195 = 5 bytes remaining (< STREAM_FRAME_OVERHEAD_BYTES + 1): must wait.
        assert!(
            tokio::time::timeout(Duration::from_millis(30), win.wait_available(1))
                .await
                .is_err(),
            "remaining credit <= overhead must block further Stdin sends"
        );

        win.grant(STREAM_FRAME_OVERHEAD_BYTES as u32);
        // Now 5 + 64 = 69 bytes available -> allows 5 payload bytes.
        assert_eq!(win.wait_available(64).await, Some(5));
        win.consume(5);
    }

    #[tokio::test]
    async fn cancelled_graceful_shutdown_serializes_with_force_kill_and_preserves_liveness() {
        #[cfg(windows)]
        let launch = ProcessLaunchSpec::new(
            "cmd.exe",
            vec![
                std::ffi::OsString::from("/C"),
                std::ffi::OsString::from("ping -n 10 127.0.0.1 >NUL"),
            ],
        );
        #[cfg(unix)]
        let launch = ProcessLaunchSpec::new(
            "/bin/sh",
            vec![
                std::ffi::OsString::from("-c"),
                std::ffi::OsString::from("sleep 10"),
            ],
        );
        let proc_handle = ConfinedProcess::spawn(launch).expect("spawn sleeping child");
        let pid = proc_handle.id();
        let start_token = proc_handle.start_identity().start_token;

        let listener = AgentIpcEndpoint::bind_temp("drv-shutdown-race").unwrap();
        let sock_path = listener.socket_path().to_path_buf();
        let peer_thread = thread::spawn(move || {
            let mut client = IpcStream::connect(&sock_path).unwrap();
            while read_frame(&mut client).is_ok() {}
        });

        let host_stream = listener.accept_timeout(Duration::from_secs(2)).unwrap();
        let session = QemuVmSession::start(
            Some(proc_handle),
            None,
            host_stream,
            Vec::new(),
            Duration::from_secs(2),
            pid,
            start_token,
            None,
        )
        .unwrap();

        // Cancel `graceful_shutdown` while `wait_timeout(350ms)` is mid-flight inside `spawn_blocking`.
        let cancelled = tokio::time::timeout(
            Duration::from_millis(40),
            session.graceful_shutdown(Duration::from_millis(350)),
        )
        .await;
        assert!(cancelled.is_err(), "graceful_shutdown should be cancelled mid-wait");

        // While the process handle is checked out under `shutdown_lock`, status must stay consistent.
        assert!(session.is_alive(), "session must still report alive mid-shutdown");
        assert!(
            matches!(session.confirmed_exited(), Ok(false)),
            "confirmed_exited must not error or report true before exit"
        );

        // Concurrent/subsequent `force_kill` waits for `shutdown_lock`, reclaims handle, and kills it.
        session.force_kill().await.expect("force_kill succeeds after cancelled graceful_shutdown");
        assert!(!session.is_alive());
        assert!(matches!(session.confirmed_exited(), Ok(true)));
        assert!(
            !kill_verified_orphan_process(pid, start_token).unwrap_or(false),
            "process must already be dead after force_kill"
        );

        peer_thread.join().unwrap();
    }

    #[tokio::test]
    async fn force_kill_wakes_hung_graceful_shutdown_promptly() {
        #[cfg(windows)]
        let launch = ProcessLaunchSpec::new(
            "cmd.exe",
            vec![
                std::ffi::OsString::from("/C"),
                std::ffi::OsString::from("ping -n 15 127.0.0.1 >NUL"),
            ],
        );
        #[cfg(unix)]
        let launch = ProcessLaunchSpec::new(
            "/bin/sh",
            vec![
                std::ffi::OsString::from("-c"),
                std::ffi::OsString::from("sleep 15"),
            ],
        );
        let proc_handle = ConfinedProcess::spawn(launch).expect("spawn sleeping child");
        let pid = proc_handle.id();
        let start_token = proc_handle.start_identity().start_token;

        let listener = AgentIpcEndpoint::bind_temp("drv-force-kill-wake").unwrap();
        let sock_path = listener.socket_path().to_path_buf();
        let peer_thread = thread::spawn(move || {
            let mut client = IpcStream::connect(&sock_path).unwrap();
            while read_frame(&mut client).is_ok() {}
        });

        let host_stream = listener.accept_timeout(Duration::from_secs(2)).unwrap();
        let session = QemuVmSession::start(
            Some(proc_handle),
            None,
            host_stream,
            Vec::new(),
            Duration::from_secs(2),
            pid,
            start_token,
            None,
        )
        .unwrap();

        let cancelled = tokio::time::timeout(
            Duration::from_millis(40),
            session.graceful_shutdown(Duration::from_secs(5)),
        )
        .await;
        assert!(cancelled.is_err());

        let start = Instant::now();
        session.force_kill().await.unwrap();
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "force_kill must wake hung 5s graceful_shutdown wait immediately, elapsed={:?}",
            start.elapsed()
        );
        peer_thread.join().unwrap();
    }

    #[tokio::test]
    async fn egress_graceful_drop_reaps_permit_on_abandoned_and_flooding_guest_streams() {
        use sandbox_protocol::GUEST_STREAM_ID_BIT;

        let listener = AgentIpcEndpoint::bind_temp("drv-egress-reap").unwrap();
        let sock_path = listener.socket_path().to_path_buf();
        let (phase2_tx, phase2_rx) = std::sync::mpsc::channel::<()>();
        let (sid2_done_tx, sid2_done_rx) = oneshot::channel::<()>();

        let guest_thread = thread::spawn(move || {
            let mut client = IpcStream::connect(&sock_path).unwrap();

            // 1. Abandoned guest socket: never sends Stdout EOF after host drops TunnelStream.
            let sid1 = StreamId(GUEST_STREAM_ID_BIT | 1);
            write_frame(&mut client, &Frame::from_message(sid1, &Message::EgressOpen).unwrap())
                .unwrap();
            assert_eq!(read_frame(&mut client).unwrap().decode_message().unwrap(), Message::ConnectAck);
            // Expect StreamClose once host linger deadline elapses.
            loop {
                let f = read_frame(&mut client).unwrap();
                match f.decode_message().unwrap() {
                    Message::StreamClose => {
                        assert_eq!(f.header.stream_id, sid1);
                        break;
                    }
                    Message::StreamData { channel: StreamChannel::Stdin, .. } => {}
                    other => panic!("unexpected frame on sid1: {other:?}"),
                }
            }

            phase2_rx.recv().unwrap();

            // 2. Guest keeps flooding data after host writes response + graceful shutdown + drop ->
            //    receives buffered response bytes BEFORE StreamClose.
            let sid2 = StreamId(GUEST_STREAM_ID_BIT | 2);
            write_frame(&mut client, &Frame::from_message(sid2, &Message::EgressOpen).unwrap())
                .unwrap();
            assert_eq!(read_frame(&mut client).unwrap().decode_message().unwrap(), Message::ConnectAck);
            for _ in 0..8 {
                if write_frame(
                    &mut client,
                    &Frame::from_message(
                        sid2,
                        &Message::StreamData {
                            channel: StreamChannel::Stdout,
                            eof: false,
                            data: vec![b'y'; 4096],
                        },
                    )
                    .unwrap(),
                )
                .is_err()
                {
                    break;
                }
                thread::sleep(Duration::from_millis(10));
            }
            let mut sid2_resp = Vec::new();
            loop {
                let f = read_frame(&mut client).unwrap();
                match f.decode_message().unwrap() {
                    Message::StreamData {
                        channel: StreamChannel::Stdin,
                        data,
                        ..
                    } => {
                        assert_eq!(f.header.stream_id, sid2);
                        sid2_resp.extend_from_slice(&data);
                    }
                    Message::StreamCredit {
                        channel: StreamChannel::Stdout,
                        ..
                    } => {}
                    Message::StreamClose => {
                        assert_eq!(f.header.stream_id, sid2);
                        break;
                    }
                    other => panic!("unexpected frame on sid2: {other:?}"),
                }
            }
            assert_eq!(sid2_resp, b"HTTP/1.1 403 Forbidden\r\n\r\n");
            let _ = sid2_done_tx.send(());
            while read_frame(&mut client).is_ok() {}
        });

        let host_stream = listener.accept_timeout(Duration::from_secs(2)).unwrap();
        let (session, mut egress_rx) =
            QemuVmSession::from_test_stream_with_egress(host_stream, Duration::from_millis(150))
                .unwrap();

        // Stream 1: call shutdown() and drop immediately without reading/closing remotely.
        let mut s1 = tokio::time::timeout(Duration::from_secs(2), egress_rx.recv())
            .await
            .unwrap()
            .unwrap();
        s1.shutdown().await.unwrap();
        drop(s1);

        tokio::time::timeout(Duration::from_secs(2), async {
            while session.active_guest_egress_count() != 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("abandoned egress permit must be reaped after graceful shutdown+drop");

        phase2_tx.send(()).unwrap();

        // Stream 2: write response, call shutdown(), and drop while guest writes to trigger abort path.
        let mut s2 = tokio::time::timeout(Duration::from_secs(2), egress_rx.recv())
            .await
            .unwrap()
            .unwrap();
        s2.write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n").await.unwrap();
        s2.shutdown().await.unwrap();
        drop(s2);

        tokio::time::timeout(Duration::from_secs(2), async {
            while session.active_guest_egress_count() != 0 {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("flooding egress permit must be reaped after host drop");

        tokio::time::timeout(Duration::from_secs(2), sid2_done_rx)
            .await
            .expect("guest must receive response and StreamClose before force_kill")
            .unwrap();

        session.force_kill().await.unwrap();
        guest_thread.join().unwrap();
    }

    #[tokio::test]
    async fn exec_cancel_preempts_full_outbound_data_queue() {
        let outbound = Arc::new(OutboundQueue::new());
        // Fill Data lane above MAX_OUTBOUND_DATA_QUEUE_BYTES so the next enqueue_data waits.
        let filler = Frame::from_message(
            StreamId(1),
            &Message::StreamData {
                channel: StreamChannel::Stdin,
                eof: false,
                data: vec![b'd'; 1024 * 1024 - 2],
            },
        )
        .unwrap();
        for _ in 0..4 {
            outbound.enqueue_data(filler.clone()).await.unwrap();
        }
        assert!(lock_unpoisoned(&outbound.state).queue.data_bytes() >= MAX_OUTBOUND_DATA_QUEUE_BYTES);

        let stdin_credits = Arc::new(StdinCreditWindow::new(INITIAL_STREAM_CREDIT_BYTES));
        let (stdin_tx, mut stdin_rx) = mpsc::channel(4);
        let (cancel_tx, mut cancel_rx) = mpsc::channel(4);
        let (_done_tx, done_rx) = oneshot::channel();
        let pump_outbound = Arc::clone(&outbound);
        let pump = tokio::spawn(async move {
            pump_exec_stdin_and_cancel(
                StreamId(2),
                pump_outbound,
                stdin_credits,
                &mut stdin_rx,
                &mut cancel_rx,
                done_rx,
            )
            .await;
        });

        stdin_tx.send(vec![b'z'; 32]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
        cancel_tx.send(()).await.unwrap();

        tokio::time::timeout(Duration::from_secs(2), async {
            while lock_unpoisoned(&outbound.state).queue.control_len() == 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("ExecCancel must be enqueued on control lane while data lane is full");

        let popped = tokio::task::spawn_blocking(move || outbound.pop_blocking().unwrap())
            .await
            .unwrap();
        assert_eq!(popped.header.stream_id, StreamId(2));
        assert_eq!(popped.decode_message().unwrap(), Message::ExecCancel);
        pump.abort();
    }
}
