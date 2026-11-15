//! End-to-end Phase 1 QEMU `virtio-serial` boot, protocol handshake, exec, and teardown session.

use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use sandbox_core::{AccelerationPolicy, GuestArch, NetworkPolicy, SandboxError};
use sandbox_protocol::{
    read_frame, write_frame, ExecTargetWire, Frame, Message, ProtocolError, StreamChannel,
    StreamId, PROTOCOL_VERSION,
};

use crate::accel::{
    discover_qemu_binary_for_arch, probe_available_accelerators_for_arch, select_accelerator,
    Accelerator,
};
use crate::ipc::{AgentIpcEndpoint, IpcStream};
use crate::launch::{validate_isolated_network, QemuLaunchConfig};
use crate::process::{ConfinedProcess, ProcessLaunchSpec, ProcessStartIdentity, ProcessStdio};

const ACCEPT_POLL_SLICE: Duration = Duration::from_millis(150);
const SHUTDOWN_ACK_TIMEOUT: Duration = Duration::from_secs(2);
const POWEROFF_WAIT_TIMEOUT: Duration = Duration::from_secs(5);
const DIAGNOSTIC_TAIL_BYTES: usize = 4096;

/// Configuration for launching and communicating with a Phase 1/2 QEMU spike guest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpikeBootConfig {
    pub qemu_bin: Option<PathBuf>,
    pub arch: GuestArch,
    pub kernel_path: PathBuf,
    pub initrd_path: PathBuf,
    pub root_disk_qcow2: Option<PathBuf>,
    pub kernel_cmdline_extra: Option<String>,
    pub acceleration: AccelerationPolicy,
    pub network: NetworkPolicy,
    pub vcpus: u8,
    pub ram_mb: u32,
    pub boot_timeout: Duration,
    pub exec_timeout: Duration,
    pub runtime_parent_dir: Option<PathBuf>,
}

impl Default for SpikeBootConfig {
    fn default() -> Self {
        Self {
            qemu_bin: None,
            arch: GuestArch::X86_64,
            kernel_path: PathBuf::new(),
            initrd_path: PathBuf::new(),
            root_disk_qcow2: None,
            kernel_cmdline_extra: None,
            acceleration: AccelerationPolicy::Preferred,
            network: NetworkPolicy::Isolated,
            vcpus: 1,
            ram_mb: 256,
            boot_timeout: Duration::from_secs(30),
            exec_timeout: Duration::from_secs(15),
            runtime_parent_dir: None,
        }
    }
}

impl SpikeBootConfig {
    /// Creates a [`SpikeBootConfig`] with isolated defaults for the given Linux kernel and initrd.
    pub fn new(kernel_path: impl Into<PathBuf>, initrd_path: impl Into<PathBuf>) -> Self {
        Self {
            kernel_path: kernel_path.into(),
            initrd_path: initrd_path.into(),
            ..Self::default()
        }
    }
}

/// Collected command exit code and stdout/stderr payloads from [`SpikeSession::exec`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpikeExecOutput {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Active QEMU VM session connected to `sandbox-agent` over a host-bound `AF_UNIX` `virtio-serial` socket.
pub struct SpikeSession {
    process: Option<ConfinedProcess>,
    stream: Option<IpcStream>,
    endpoint: Option<AgentIpcEndpoint>,
    runtime_dir: PathBuf,
    accelerator_used: Accelerator,
    exec_timeout: Duration,
    next_stream_id: u32,
    cleaned: bool,
}

impl SpikeSession {
    /// Boots an isolated Linux guest under QEMU, waits for `virtio-serial` connection, and
    /// completes the `Hello`/`HelloAck` protocol handshake.
    ///
    /// When `config.acceleration` is [`AccelerationPolicy::Preferred`], falls back from hardware
    /// acceleration to QEMU `TCG` only if hardware initialization or pre-handshake boot fails;
    /// never suppresses [`SandboxError::BinaryExecutionBlocked`] and never relaxes VM isolation.
    pub fn boot(config: &SpikeBootConfig) -> Result<Self, SandboxError> {
        validate_isolated_network(&config.network)?;
        if !config.kernel_path.is_file() {
            return Err(SandboxError::NotFound(format!(
                "guest kernel '{}' does not exist or is not a file",
                config.kernel_path.display()
            )));
        }
        if !config.initrd_path.is_file() {
            return Err(SandboxError::NotFound(format!(
                "guest initrd '{}' does not exist or is not a file",
                config.initrd_path.display()
            )));
        }
        if let Some(disk_path) = &config.root_disk_qcow2 {
            if !disk_path.is_file() {
                return Err(SandboxError::NotFound(format!(
                    "guest root disk '{}' does not exist or is not a file",
                    disk_path.display()
                )));
            }
        }
        if config.boot_timeout.is_zero() || config.exec_timeout.is_zero() {
            return Err(SandboxError::InvalidSpec(
                "boot_timeout and exec_timeout must be greater than zero".to_owned(),
            ));
        }

        let qemu_bin = discover_qemu_binary_for_arch(config.arch, config.qemu_bin.as_deref())?;
        let available = probe_available_accelerators_for_arch(&qemu_bin, config.arch)?;
        let attempts = build_candidate_attempts(config.acceleration, &available)?;

        let mut primary_failure: Option<(Accelerator, SandboxError)> = None;
        for (idx, &accel) in attempts.iter().enumerate() {
            match boot_attempt(config, &qemu_bin, accel) {
                Ok(session) => return Ok(session),
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

    /// Returns the QEMU accelerator actively running this guest VM.
    pub fn accelerator_used(&self) -> Accelerator {
        self.accelerator_used
    }

    /// Returns the owner-only host runtime directory holding the IPC socket and QEMU logs.
    pub fn runtime_dir(&self) -> &Path {
        &self.runtime_dir
    }

    /// Returns the confined QEMU process identity (`pid` and OS start-time token) if still held.
    pub fn process_identity(&self) -> Option<ProcessStartIdentity> {
        self.process.as_ref().map(ConfinedProcess::start_identity)
    }

    /// Sends a liveness `Ping` on `StreamId(0)` and validates the matching `Pong`.
    pub fn ping(&mut self, seq: u64) -> Result<(), SandboxError> {
        let stream = self.active_stream_mut()?;
        send_protocol_message(stream, StreamId(0), &Message::Ping { seq })?;
        let frame =
            read_frame(stream).map_err(|err| protocol_err("reading Pong response", err))?;
        if frame.header.stream_id != StreamId(0) {
            return Err(SandboxError::Transport(format!(
                "expected Pong on stream 0, got {}",
                frame.header.stream_id
            )));
        }
        match frame
            .decode_message()
            .map_err(|err| protocol_err("decoding Pong response", err))?
        {
            Message::Pong { seq: got_seq } if got_seq == seq => Ok(()),
            Message::Pong { seq: got_seq } => Err(SandboxError::Transport(format!(
                "Pong sequence mismatch: expected {seq}, got {got_seq}"
            ))),
            other => Err(SandboxError::Transport(format!(
                "expected Pong message, got {:?}",
                other.kind()
            ))),
        }
    }

    /// Executes `argv` inside the guest VM and collects exit code, stdout, and stderr.
    pub fn exec(&mut self, argv: Vec<String>) -> Result<SpikeExecOutput, SandboxError> {
        if argv.is_empty() {
            return Err(SandboxError::InvalidSpec(
                "exec argv must not be empty".to_owned(),
            ));
        }

        let stream_id = StreamId(self.next_stream_id);
        self.next_stream_id = self
            .next_stream_id
            .checked_add(1)
            .ok_or_else(|| SandboxError::Internal("spike session stream IDs exhausted".to_owned()))?;

        let deadline_ms = u64::try_from(self.exec_timeout.as_millis()).unwrap_or(u64::MAX);
        let stream = self.active_stream_mut()?;
        send_protocol_message(
            stream,
            stream_id,
            &Message::ExecStart {
                target: ExecTargetWire::Guest,
                argv,
                env: BTreeMap::new(),
                cwd: None,
                user: None,
                deadline_ms,
                stdout_budget_bytes: 64 * 1024 * 1024,
                stderr_budget_bytes: 64 * 1024 * 1024,
            },
        )?;

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        loop {
            let frame = read_frame(stream)
                .map_err(|err| protocol_err("reading exec response frame", err))?;
            if frame.header.stream_id != stream_id {
                return Err(SandboxError::Transport(format!(
                    "expected exec frame on stream {stream_id}, got {}",
                    frame.header.stream_id
                )));
            }
            match frame
                .decode_message()
                .map_err(|err| protocol_err("decoding exec response frame", err))?
            {
                Message::StreamData {
                    channel: StreamChannel::Stdout,
                    data,
                    ..
                } => stdout.extend_from_slice(&data),
                Message::StreamData {
                    channel: StreamChannel::Stderr,
                    data,
                    ..
                } => stderr.extend_from_slice(&data),
                Message::StreamData {
                    channel: StreamChannel::Stdin,
                    ..
                } => {
                    return Err(SandboxError::Transport(
                        "unexpected Stdin StreamData frame from guest".to_owned(),
                    ));
                }
                Message::ExecExit {
                    code,
                    timed_out,
                    stdout_truncated,
                    stderr_truncated,
                } => {
                    if timed_out {
                        return Err(SandboxError::BudgetExceeded(
                            "guest execution timed out".to_owned(),
                        ));
                    }
                    if stdout_truncated || stderr_truncated {
                        return Err(SandboxError::BudgetExceeded(format!(
                            "guest execution output truncated (stdout={stdout_truncated}, stderr={stderr_truncated})"
                        )));
                    }
                    return Ok(SpikeExecOutput {
                        exit_code: code.unwrap_or(-1),
                        stdout,
                        stderr,
                    });
                }
                other => {
                    return Err(SandboxError::Transport(format!(
                        "unexpected message {:?} during exec on stream {stream_id}",
                        other.kind()
                    )));
                }
            }
        }
    }

    /// Gracefully requests guest shutdown, waits up to 5s for QEMU poweroff (killing if stalled),
    /// closes the host IPC endpoint, and removes the temporary runtime directory.
    pub fn shutdown_and_cleanup(mut self) -> Result<(), SandboxError> {
        if let Some(stream) = self.stream.as_mut() {
            let _ = stream.set_io_timeout(Some(SHUTDOWN_ACK_TIMEOUT));
            if send_protocol_message(stream, StreamId(0), &Message::Shutdown).is_ok() {
                // Best-effort read of guest Shutdown ack; clean EOF/disconnect is expected during poweroff.
                let _ = read_frame(stream);
            }
        }
        let res = self.teardown(Some(POWEROFF_WAIT_TIMEOUT));
        self.cleaned = true;
        res
    }

    fn active_stream_mut(&mut self) -> Result<&mut IpcStream, SandboxError> {
        self.stream.as_mut().ok_or_else(|| {
            SandboxError::Transport("spike session IPC stream is no longer active".to_owned())
        })
    }

    fn kill_child_now(&mut self) {
        if let Some(mut process) = self.process.take() {
            let _ = process.kill_and_wait();
        }
    }

    fn teardown(&mut self, graceful_wait: Option<Duration>) -> Result<(), SandboxError> {
        let child_res = if let Some(mut process) = self.process.take() {
            wait_or_kill_process(&mut process, graceful_wait)
        } else {
            Ok(())
        };
        // Kill/wait QEMU before dropping IPC handles and removing the runtime directory.
        self.stream.take();
        self.endpoint.take();
        let dir_res = remove_dir_all_with_retry(&self.runtime_dir);
        child_res.and(dir_res)
    }
}

impl Drop for SpikeSession {
    fn drop(&mut self) {
        if !self.cleaned {
            let _ = self.teardown(None);
            self.cleaned = true;
        }
    }
}

fn build_kernel_cmdline(config: &SpikeBootConfig) -> String {
    let mut cmdline = match config.arch {
        GuestArch::X86_64 => "console=ttyS0 panic=1".to_owned(),
        GuestArch::Aarch64 => "console=ttyAMA0 panic=1".to_owned(),
    };
    if config.root_disk_qcow2.is_some() {
        cmdline.push_str(" minipod.root=/dev/vda");
    }
    if let Some(extra) = &config.kernel_cmdline_extra {
        let trimmed = extra.trim();
        if !trimmed.is_empty() {
            cmdline.push(' ');
            cmdline.push_str(trimmed);
        }
    }
    cmdline
}

fn boot_attempt(
    config: &SpikeBootConfig,
    qemu_bin: &Path,
    accel: Accelerator,
) -> Result<SpikeSession, SandboxError> {
    let endpoint = AgentIpcEndpoint::bind_temp_in(config.runtime_parent_dir.as_deref(), "mp")?;
    let socket_path = endpoint.socket_path().to_path_buf();
    let runtime_dir = socket_path
        .parent()
        .expect("AgentIpcEndpoint always binds inside an owner-only parent dir")
        .to_path_buf();

    let mut session = SpikeSession {
        process: None,
        stream: None,
        endpoint: Some(endpoint),
        runtime_dir: runtime_dir.clone(),
        accelerator_used: accel,
        exec_timeout: config.exec_timeout,
        next_stream_id: 1,
        cleaned: false,
    };

    let serial_log_path = runtime_dir.join("serial.log");
    let stderr_log_path = runtime_dir.join("qemu-stderr.log");
    let launch_cfg = QemuLaunchConfig {
        qemu_bin: qemu_bin.to_path_buf(),
        arch: config.arch,
        accelerator: accel,
        kernel_path: config.kernel_path.clone(),
        initrd_path: Some(config.initrd_path.clone()),
        kernel_cmdline: build_kernel_cmdline(config),
        root_disk_qcow2: config.root_disk_qcow2.clone(),
        vcpus: config.vcpus,
        ram_mb: config.ram_mb,
        agent_socket_path: socket_path,
        serial_log_path: Some(serial_log_path.clone()),
        network: config.network.clone(),
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
    session.process = Some(ConfinedProcess::spawn(launch_spec)?);

    let boot_deadline = Instant::now() + config.boot_timeout;
    let stream = loop {
        let process = session.process.as_mut().expect("QEMU process is spawned");
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
            session.kill_child_now();
            let diag = read_attempt_diagnostics(&serial_log_path, &stderr_log_path);
            return Err(SandboxError::Transport(format!(
                "timed out after {}ms waiting for QEMU ({}) to connect virtio-serial IPC{diag}",
                config.boot_timeout.as_millis(),
                accel.as_qemu_arg()
            )));
        }

        let slice = boot_deadline
            .saturating_duration_since(now)
            .min(ACCEPT_POLL_SLICE);
        let attempt_start = Instant::now();
        let endpoint = session.endpoint.as_ref().expect("endpoint is active");
        // shortcut: polls process.try_wait() every 150ms around accept_timeout for spike boot; Task 3.5/3.6 uses async process waiter
        match endpoint.accept_timeout(slice) {
            Ok(stream) => break stream,
            Err(SandboxError::Transport(_)) => {
                if attempt_start.elapsed() < slice / 2 {
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
            Err(err) => return Err(err),
        }
    };

    stream.set_io_timeout(Some(config.boot_timeout))?;
    session.stream = Some(stream);

    if let Err(err) = perform_handshake(session.stream.as_mut().expect("stream is set")) {
        let exited_early = session
            .process
            .as_mut()
            .and_then(|p| p.try_wait().ok().flatten())
            .is_some();
        session.kill_child_now();
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

    session
        .stream
        .as_ref()
        .expect("stream is set")
        .set_io_timeout(Some(config.exec_timeout))?;
    Ok(session)
}

fn perform_handshake(stream: &mut IpcStream) -> Result<(), SandboxError> {
    let hello_frame =
        read_frame(stream).map_err(|err| protocol_err("waiting for guest Hello", err))?;
    if hello_frame.header.stream_id != StreamId(0) {
        return Err(SandboxError::Transport(format!(
            "expected guest Hello on stream 0, got {}",
            hello_frame.header.stream_id
        )));
    }
    match hello_frame
        .decode_message()
        .map_err(|err| protocol_err("decoding guest Hello", err))?
    {
        Message::Hello { version } if version == PROTOCOL_VERSION => {}
        Message::Hello { version } => {
            return Err(SandboxError::Transport(format!(
                "unsupported guest protocol version {version} (expected {PROTOCOL_VERSION})"
            )));
        }
        other => {
            return Err(SandboxError::Transport(format!(
                "expected guest Hello message, got {:?}",
                other.kind()
            )));
        }
    }

    send_protocol_message(
        stream,
        StreamId(0),
        &Message::HelloAck {
            version: PROTOCOL_VERSION,
            features: 0,
        },
    )
}

fn build_candidate_attempts(
    policy: AccelerationPolicy,
    available: &[Accelerator],
) -> Result<Vec<Accelerator>, SandboxError> {
    let selected = select_accelerator(policy, available)?;
    let mut attempts = vec![selected];
    if policy == AccelerationPolicy::Preferred
        && selected.is_hardware()
        && available.contains(&Accelerator::Tcg)
    {
        attempts.push(Accelerator::Tcg);
    }
    Ok(attempts)
}

fn is_retryable_boot_error(err: &SandboxError) -> bool {
    !matches!(
        err,
        SandboxError::BinaryExecutionBlocked(_)
            | SandboxError::PolicyViolation(_)
            | SandboxError::InvalidSpec(_)
            | SandboxError::NotFound(_)
    )
}

fn combine_fallback_error(
    primary_accel: Accelerator,
    primary_err: SandboxError,
    fallback_accel: Accelerator,
    fallback_err: SandboxError,
) -> SandboxError {
    let msg = format!(
        "{} failed ({primary_err}); fallback {} failed ({fallback_err})",
        primary_accel.as_qemu_arg(),
        fallback_accel.as_qemu_arg()
    );
    match fallback_err {
        SandboxError::AccelerationUnavailable(_) => SandboxError::AccelerationUnavailable(msg),
        SandboxError::Internal(_) => SandboxError::Internal(msg),
        _ => SandboxError::Transport(msg),
    }
}

fn send_protocol_message(
    stream: &mut IpcStream,
    stream_id: StreamId,
    msg: &Message,
) -> Result<(), SandboxError> {
    let frame = Frame::from_message(stream_id, msg)
        .map_err(|err| protocol_err("encoding protocol frame", err))?;
    write_frame(stream, &frame).map_err(|err| protocol_err("writing protocol frame", err))
}

fn protocol_err(context: &str, err: ProtocolError) -> SandboxError {
    SandboxError::Transport(format!("{context}: {err}"))
}

fn wait_or_kill_process(
    process: &mut ConfinedProcess,
    graceful_wait: Option<Duration>,
) -> Result<(), SandboxError> {
    if let Some(wait_dur) = graceful_wait {
        if process.wait_timeout(wait_dur)?.is_some() {
            return Ok(());
        }
    } else if process.try_wait()?.is_some() {
        return Ok(());
    }
    process.kill_and_wait()
}

fn remove_dir_all_with_retry(dir: &Path) -> Result<(), SandboxError> {
    // shortcut: retries remove_dir_all up to 10 times (50ms step) for Windows handle release; Phase 3 reconciler uses exponential backoff
    let mut last_err = None;
    for attempt in 0..10 {
        match fs::remove_dir_all(dir) {
            Ok(()) => return Ok(()),
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(err) => {
                last_err = Some(err);
                if attempt < 9 {
                    std::thread::sleep(Duration::from_millis(50));
                }
            }
        }
    }
    Err(SandboxError::Internal(format!(
        "failed to remove spike runtime directory '{}': {}",
        dir.display(),
        last_err.expect("retry loop runs at least once")
    )))
}

fn read_attempt_diagnostics(serial_log_path: &Path, stderr_log_path: &Path) -> String {
    let mut parts = Vec::new();
    if let Some(stderr_tail) = read_tail(stderr_log_path, DIAGNOSTIC_TAIL_BYTES) {
        parts.push(format!("qemu stderr tail:\n{stderr_tail}"));
    }
    if let Some(serial_tail) = read_tail(serial_log_path, DIAGNOSTIC_TAIL_BYTES) {
        parts.push(format!("guest serial tail:\n{serial_tail}"));
    }
    if parts.is_empty() {
        String::new()
    } else {
        format!("\n--- diagnostics ---\n{}", parts.join("\n---\n"))
    }
}

fn read_tail(path: &Path, max_bytes: usize) -> Option<String> {
    let mut file = File::open(path).ok()?;
    let len = file.metadata().ok()?.len();
    if len == 0 {
        return None;
    }
    let start = len.saturating_sub(max_bytes as u64);
    file.seek(SeekFrom::Start(start)).ok()?;
    let mut buf = Vec::with_capacity((len - start) as usize);
    file.read_to_end(&mut buf).ok()?;
    let text = String::from_utf8_lossy(&buf);
    let trimmed = text.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sandbox_core::EgressRule;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct TestTempDir(PathBuf);

    impl TestTempDir {
        fn new(prefix: &str) -> Self {
            static SEQ: AtomicU64 = AtomicU64::new(0);
            let seq = SEQ.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!(
                "mp-spike-unit-{prefix}-{}-{seq}",
                std::process::id()
            ));
            fs::create_dir_all(&dir).expect("create temp test dir");
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

    #[test]
    fn build_candidate_attempts_respects_policy_and_never_falls_back_when_required() {
        let hw_and_tcg = [Accelerator::Tcg, Accelerator::Whpx];
        assert_eq!(
            build_candidate_attempts(AccelerationPolicy::Preferred, &hw_and_tcg),
            Ok(vec![Accelerator::Whpx, Accelerator::Tcg])
        );
        assert_eq!(
            build_candidate_attempts(AccelerationPolicy::Required, &hw_and_tcg),
            Ok(vec![Accelerator::Whpx])
        );
        assert_eq!(
            build_candidate_attempts(AccelerationPolicy::SoftwareOnly, &hw_and_tcg),
            Ok(vec![Accelerator::Tcg])
        );

        let kvm_only = [Accelerator::Kvm];
        assert_eq!(
            build_candidate_attempts(AccelerationPolicy::Preferred, &kvm_only),
            Ok(vec![Accelerator::Kvm])
        );

        let tcg_only = [Accelerator::Tcg];
        assert_eq!(
            build_candidate_attempts(AccelerationPolicy::Preferred, &tcg_only),
            Ok(vec![Accelerator::Tcg])
        );
    }

    #[test]
    fn retry_gate_never_masks_binary_blocked_policy_spec_or_not_found() {
        assert!(!is_retryable_boot_error(&SandboxError::BinaryExecutionBlocked(
            "blocked".to_owned()
        )));
        assert!(!is_retryable_boot_error(&SandboxError::PolicyViolation(
            "policy".to_owned()
        )));
        assert!(!is_retryable_boot_error(&SandboxError::InvalidSpec(
            "spec".to_owned()
        )));
        assert!(!is_retryable_boot_error(&SandboxError::NotFound(
            "missing".to_owned()
        )));

        assert!(is_retryable_boot_error(&SandboxError::AccelerationUnavailable(
            "whpx init failed".to_owned()
        )));
        assert!(is_retryable_boot_error(&SandboxError::Transport(
            "qemu exited".to_owned()
        )));
    }

    #[test]
    fn spike_boot_rejects_non_isolated_network_and_missing_artifacts() {
        let dir = TestTempDir::new("cfg");
        let kernel = dir.path().join("vmlinuz");
        let initrd = dir.path().join("initrd");
        fs::write(&kernel, b"k").expect("write dummy kernel");
        fs::write(&initrd, b"i").expect("write dummy initrd");

        for policy in [
            NetworkPolicy::InternetOnly,
            NetworkPolicy::DomainAllowList {
                rules: vec![EgressRule {
                    domain: "example.com".to_owned(),
                    port: 443,
                }],
            },
            NetworkPolicy::Unrestricted,
        ] {
            let mut cfg = SpikeBootConfig::new(&kernel, &initrd);
            cfg.network = policy;
            assert!(matches!(
                SpikeSession::boot(&cfg),
                Err(SandboxError::PolicyViolation(_))
            ));
        }

        let mut missing_kernel = SpikeBootConfig::new(dir.path().join("no-kernel"), &initrd);
        missing_kernel.network = NetworkPolicy::Isolated;
        assert!(matches!(
            SpikeSession::boot(&missing_kernel),
            Err(SandboxError::NotFound(_))
        ));

        let mut missing_disk = SpikeBootConfig::new(&kernel, &initrd);
        missing_disk.root_disk_qcow2 = Some(dir.path().join("no-root.qcow2"));
        assert!(matches!(
            SpikeSession::boot(&missing_disk),
            Err(SandboxError::NotFound(_))
        ));

        let mut zero_timeout = SpikeBootConfig::new(&kernel, &initrd);
        zero_timeout.exec_timeout = Duration::ZERO;
        assert!(matches!(
            SpikeSession::boot(&zero_timeout),
            Err(SandboxError::InvalidSpec(_))
        ));
    }

    #[test]
    fn build_kernel_cmdline_selects_console_root_and_extra() {
        let mut x64 = SpikeBootConfig::new("vmlinuz", "initrd");
        assert_eq!(build_kernel_cmdline(&x64), "console=ttyS0 panic=1");

        x64.root_disk_qcow2 = Some(PathBuf::from("root.qcow2"));
        assert_eq!(
            build_kernel_cmdline(&x64),
            "console=ttyS0 panic=1 minipod.root=/dev/vda"
        );

        x64.kernel_cmdline_extra = Some("   \t  ".to_owned());
        assert_eq!(
            build_kernel_cmdline(&x64),
            "console=ttyS0 panic=1 minipod.root=/dev/vda"
        );

        x64.kernel_cmdline_extra = Some("  quiet rdinit=/init  ".to_owned());
        assert_eq!(
            build_kernel_cmdline(&x64),
            "console=ttyS0 panic=1 minipod.root=/dev/vda quiet rdinit=/init"
        );

        let mut arm64 = SpikeBootConfig::new("Image", "initrd");
        arm64.arch = GuestArch::Aarch64;
        assert_eq!(build_kernel_cmdline(&arm64), "console=ttyAMA0 panic=1");

        arm64.root_disk_qcow2 = Some(PathBuf::from("root.qcow2"));
        arm64.kernel_cmdline_extra = Some("minipod.agent=/bin/agent".to_owned());
        assert_eq!(
            build_kernel_cmdline(&arm64),
            "console=ttyAMA0 panic=1 minipod.root=/dev/vda minipod.agent=/bin/agent"
        );
    }

    #[test]
    fn read_tail_truncates_to_last_bytes() {
        let dir = TestTempDir::new("tail");
        let log = dir.path().join("serial.log");
        fs::write(&log, b"0123456789abcdef\n").expect("write log");

        assert_eq!(read_tail(&log, 7).as_deref(), Some("abcdef"));
        assert_eq!(
            read_tail(&log, 1024).as_deref(),
            Some("0123456789abcdef")
        );
        assert_eq!(read_tail(&dir.path().join("missing.log"), 64), None);
    }
}
