#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sandbox_client::{
    extract_tar_bytes_safely, pack_path_to_tar_bytes, read_control_frame, write_control_frame,
    ControlEndpoint, ControlRequest, ControlResponse, ExecWireClientMsg, ExecWireEvent,
};
use sandbox_core::{
    CapabilityReport, DestroyStatus, EnforcementLevel, ExecExitStatus, ExecRequest, ExecTarget,
    IsolationMode, NetworkPolicy, SandboxId, SandboxLease, SandboxSpec,
};
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::{oneshot, watch};

static TEST_SEQ: AtomicU64 = AtomicU64::new(1);

struct TestTempDir {
    path: PathBuf,
}

impl TestTempDir {
    fn new(prefix: &str) -> Self {
        let seq = TEST_SEQ.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = std::env::temp_dir()
            .join(format!("{prefix}-{}-{seq}-{nanos}", std::process::id()));
        fs::create_dir_all(&path).expect("create test temp directory");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TestTempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

#[cfg(unix)]
struct UnixCleanupGuard {
    socket_path: PathBuf,
    short_dir: Option<PathBuf>,
}

#[cfg(unix)]
impl Drop for UnixCleanupGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.socket_path);
        if let Some(dir) = &self.short_dir {
            let _ = fs::remove_dir_all(dir);
        }
    }
}

#[derive(Clone, Copy)]
enum CleanupResponse {
    AllResourcesCleaned,
    ProcessExited,
}

struct MockRunConfig {
    exit: ExecExitStatus,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    output_tar: Vec<u8>,
    cleanup: CleanupResponse,
    create_destination_during_copy_out: Option<PathBuf>,
    wait_for_cancel: bool,
    disconnect_after_spawn: bool,
    stall_spawn: bool,
    stall_copy_out: bool,
    never_reply_after_cancel: bool,
    observe_cancel_after_output: bool,
    renewal_error: bool,
}

impl MockRunConfig {
    fn success(output_tar: Vec<u8>) -> Self {
        Self {
            exit: ExecExitStatus {
                code: Some(0),
                timed_out: false,
                stdout_truncated: false,
                stderr_truncated: false,
            },
            stdout: b"hello from guest\n".to_vec(),
            stderr: b"guest diagnostic\n".to_vec(),
            output_tar,
            cleanup: CleanupResponse::AllResourcesCleaned,
            create_destination_during_copy_out: None,
            wait_for_cancel: false,
            disconnect_after_spawn: false,
            stall_spawn: false,
            stall_copy_out: false,
            never_reply_after_cancel: false,
            observe_cancel_after_output: false,
            renewal_error: false,
        }
    }
}

struct MockRunState {
    config: MockRunConfig,
    requests: Vec<&'static str>,
    sandbox_spec: Option<SandboxSpec>,
    copied_in: Option<(String, Vec<u8>)>,
    exec_request: Option<ExecRequest>,
    copy_out_source: Option<String>,
    destroyed_ids: Vec<String>,
    exec_observed: Option<oneshot::Sender<()>>,
    exec_started: Option<oneshot::Sender<()>>,
    release_exec: Option<oneshot::Receiver<()>>,
    renewed: Option<oneshot::Sender<u64>>,
    spawn_observed: Option<oneshot::Sender<()>>,
    release_spawn: Option<oneshot::Receiver<()>>,
    copy_out_observed: Option<oneshot::Sender<()>>,
    release_copy_out: Option<oneshot::Receiver<()>>,
    cancel_observed: Option<oneshot::Sender<()>>,
    release_cancel: Option<oneshot::Receiver<()>>,
}

impl MockRunState {
    fn new(config: MockRunConfig) -> Self {
        Self {
            config,
            requests: Vec::new(),
            sandbox_spec: None,
            copied_in: None,
            exec_request: None,
            copy_out_source: None,
            destroyed_ids: Vec::new(),
            exec_observed: None,
            exec_started: None,
            release_exec: None,
            renewed: None,
            spawn_observed: None,
            release_spawn: None,
            copy_out_observed: None,
            release_copy_out: None,
            cancel_observed: None,
            release_cancel: None,
        }
    }
}

async fn handle_mock_connection<S>(mut stream: S, state: Arc<Mutex<MockRunState>>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let Ok(Some(raw)) = read_control_frame(&mut stream).await else {
        return;
    };
    let req = ControlRequest::from_json_bytes(&raw).expect("valid ControlRequest wire frame");

    if let ControlRequest::ExecStart { id, req } = req {
        assert_eq!(id.as_str(), "sb-run-e2e-1");
        let (config, observed, release) = {
            let mut st = state.lock().expect("mock state lock");
            st.requests.push("exec");
            st.exec_request = Some(req);
            (
                MockRunConfig {
                    exit: st.config.exit,
                    stdout: st.config.stdout.clone(),
                    stderr: st.config.stderr.clone(),
                    output_tar: st.config.output_tar.clone(),
                    cleanup: st.config.cleanup,
                    create_destination_during_copy_out: None,
                    wait_for_cancel: st.config.wait_for_cancel,
                    disconnect_after_spawn: st.config.disconnect_after_spawn,
                    stall_spawn: st.config.stall_spawn,
                    stall_copy_out: st.config.stall_copy_out,
                    never_reply_after_cancel: st.config.never_reply_after_cancel,
                    observe_cancel_after_output: st.config.observe_cancel_after_output,
                    renewal_error: st.config.renewal_error,
                },
                st.exec_observed.take(),
                st.release_exec.take(),
            )
        };
        if let Some(observed) = observed {
            let _ = observed.send(());
        }
        if let Some(release) = release {
            let _ = release.await;
        }

        let started = ControlResponse::ExecStarted { stream_id: 1 }
            .to_json_bytes()
            .expect("serialize ExecStarted");
        if write_control_frame(&mut stream, &started).await.is_err() {
            return;
        }
        let exec_started = state
            .lock()
            .expect("mock state lock")
            .exec_started
            .take();
        if let Some(exec_started) = exec_started {
            let _ = exec_started.send(());
        }
        if config.wait_for_cancel {
            loop {
                let Ok(Some(frame)) = read_control_frame(&mut stream).await else {
                    return;
                };
                if matches!(
                    ExecWireClientMsg::from_json_bytes(&frame),
                    Ok(ExecWireClientMsg::Cancel)
                ) {
                    let (observed, release) = {
                        let mut st = state.lock().expect("mock state lock");
                        st.requests.push("cancel");
                        (st.cancel_observed.take(), st.release_cancel.take())
                    };
                    if let Some(observed) = observed {
                        let _ = observed.send(());
                    }
                    if config.never_reply_after_cancel {
                        if let Some(release) = release {
                            let _ = release.await;
                        }
                        let _ = stream.shutdown().await;
                        return;
                    }
                    break;
                }
            }
            let exit = ExecWireEvent::Exit(ExecExitStatus {
                code: None,
                timed_out: false,
                stdout_truncated: false,
                stderr_truncated: false,
            })
            .to_json_bytes()
            .expect("serialize cancelled ExecExit");
            let _ = write_control_frame(&mut stream, &exit).await;
            let _ = stream.shutdown().await;
            return;
        }
        let output_events = [
            ExecWireEvent::Stdout {
                data: config.stdout,
            },
            ExecWireEvent::Stderr {
                data: config.stderr,
            },
        ];
        for event in output_events {
            let bytes = event.to_json_bytes().expect("serialize ExecWireEvent");
            if write_control_frame(&mut stream, &bytes).await.is_err() {
                return;
            }
        }
        if config.observe_cancel_after_output {
            loop {
                let Ok(Some(frame)) = read_control_frame(&mut stream).await else {
                    return;
                };
                if matches!(
                    ExecWireClientMsg::from_json_bytes(&frame),
                    Ok(ExecWireClientMsg::Cancel)
                ) {
                    let observed = {
                        let mut st = state.lock().expect("mock state lock");
                        st.requests.push("cancel");
                        st.cancel_observed.take()
                    };
                    if let Some(observed) = observed {
                        let _ = observed.send(());
                    }
                    break;
                }
            }
        }
        let exit = ExecWireEvent::Exit(config.exit)
            .to_json_bytes()
            .expect("serialize successful guest exit");
        if write_control_frame(&mut stream, &exit).await.is_err() {
            return;
        }
        let _ = stream.shutdown().await;
        let _ = tokio::time::timeout(Duration::from_secs(1), read_control_frame(&mut stream)).await;
        return;
    }

    if let ControlRequest::Spawn { spec } = req {
        let (disconnect, stall, observed, release, lease) = {
            let mut st = state.lock().expect("mock state lock");
            st.requests.push("spawn");
            st.sandbox_spec = Some(spec.clone());
            let lease = SandboxLease {
                id: SandboxId::new("sb-run-e2e-1"),
                ttl: spec.lease_ttl,
                capabilities: CapabilityReport {
                    cpu_quota: EnforcementLevel::HardLimit,
                    host_rss: EnforcementLevel::BestEffort,
                    host_storage: EnforcementLevel::HardLimit,
                    egress_filter: EnforcementLevel::HardLimit,
                },
            };
            (
                st.config.disconnect_after_spawn,
                st.config.stall_spawn,
                st.spawn_observed.take(),
                st.release_spawn.take(),
                lease,
            )
        };
        if disconnect {
            return;
        }
        if stall {
            if let Some(observed) = observed {
                let _ = observed.send(());
            }
            if let Some(release) = release {
                let _ = release.await;
            }
            return;
        }
        let bytes = ControlResponse::Spawned(lease)
            .to_json_bytes()
            .expect("serialize Spawned response");
        if write_control_frame(&mut stream, &bytes).await.is_ok() {
            let _ = stream.shutdown().await;
        }
        return;
    }

    if let ControlRequest::CopyOutTar { id, src_guest } = req {
        assert_eq!(id.as_str(), "sb-run-e2e-1");
        let (stall, observed, release, tar_bytes) = {
            let mut st = state.lock().expect("mock state lock");
            st.requests.push("copy-out");
            st.copy_out_source = Some(src_guest);
            if let Some(path) = &st.config.create_destination_during_copy_out {
                fs::create_dir_all(path).expect("create raced copy-out destination");
                fs::write(path.join("sentinel.txt"), b"keep this destination")
                    .expect("write raced destination sentinel");
            }
            (
                st.config.stall_copy_out,
                st.copy_out_observed.take(),
                st.release_copy_out.take(),
                st.config.output_tar.clone(),
            )
        };
        if stall {
            if let Some(observed) = observed {
                let _ = observed.send(());
            }
            if let Some(release) = release {
                let _ = release.await;
            }
            return;
        }
        let bytes = ControlResponse::CopyOutData { tar_bytes }
            .to_json_bytes()
            .expect("serialize CopyOutData response");
        if write_control_frame(&mut stream, &bytes).await.is_ok() {
            let _ = stream.shutdown().await;
        }
        return;
    }

    let response = {
        let mut st = state.lock().expect("mock state lock");
        match req {
            ControlRequest::CopyInTar {
                id,
                dst_guest,
                tar_bytes,
            } => {
                assert_eq!(id.as_str(), "sb-run-e2e-1");
                st.requests.push("copy-in");
                st.copied_in = Some((dst_guest, tar_bytes));
                ControlResponse::Ack
            }
            ControlRequest::RenewLease { id, ttl_ms } => {
                assert_eq!(id.as_str(), "sb-run-e2e-1");
                st.requests.push("renew");
                if let Some(renewed) = st.renewed.take() {
                    let _ = renewed.send(ttl_ms);
                }
                if st.config.renewal_error {
                    ControlResponse::Error(sandbox_client::wire::WireError {
                        kind: "LeaseExpired".to_owned(),
                        message: "test lease renewal failure".to_owned(),
                    })
                } else {
                    ControlResponse::Ack
                }
            }
            ControlRequest::Destroy { id } => {
                assert_eq!(id.as_str(), "sb-run-e2e-1");
                st.requests.push("destroy");
                st.destroyed_ids.push(id.0);
                let status = match st.config.cleanup {
                    CleanupResponse::AllResourcesCleaned => DestroyStatus::AllResourcesCleaned,
                    CleanupResponse::ProcessExited => DestroyStatus::ProcessExited {
                        remaining_artifacts: vec![PathBuf::from("state/sb-run-e2e-1/overlay.qcow2")],
                    },
                };
                ControlResponse::Destroyed(status)
            }
            other => panic!("unexpected mock CLI request: {other:?}"),
        }
    };

    let bytes = response.to_json_bytes().expect("serialize ControlResponse");
    if write_control_frame(&mut stream, &bytes).await.is_ok() {
        let _ = stream.shutdown().await;
        let _ = tokio::time::timeout(Duration::from_secs(1), read_control_frame(&mut stream)).await;
    }
}

struct MockDaemon {
    endpoint: String,
    shutdown: watch::Sender<bool>,
    task: tokio::task::JoinHandle<()>,
    #[cfg(unix)]
    _cleanup: UnixCleanupGuard,
}

impl MockDaemon {
    fn start(_temp: &TestTempDir, state: Arc<Mutex<MockRunState>>) -> Self {
        let seq = TEST_SEQ.fetch_add(1, Ordering::Relaxed);
        let (shutdown, mut shutdown_rx) = watch::channel(false);

        #[cfg(windows)]
        let (endpoint, task) = {
            use tokio::net::windows::named_pipe::ServerOptions;

            let pipe_path = format!(r"\\.\pipe\minipod-run-{}-{seq}", std::process::id());
            let srv_pipe = pipe_path.clone();
            let mut server = ServerOptions::new()
                .first_pipe_instance(true)
                .create(&srv_pipe)
                .expect("bind mock Windows Named Pipe");
            let task = tokio::spawn(async move {
                loop {
                    let result = tokio::select! {
                        biased;
                        _ = shutdown_rx.wait_for(|done| *done) => break,
                        result = server.connect() => result,
                    };
                    match result {
                        Ok(()) => {
                            let next = ServerOptions::new()
                                .create(&srv_pipe)
                                .expect("create next mock pipe instance");
                            let connected = std::mem::replace(&mut server, next);
                            tokio::spawn(handle_mock_connection(connected, Arc::clone(&state)));
                        }
                        Err(err) => panic!("mock pipe accept error: {err}"),
                    }
                }
            });
            (pipe_path, task)
        };

        #[cfg(unix)]
        let (endpoint, task, cleanup) = {
            let candidate = _temp.path().join("control.sock");
            let (socket_path, short_dir) = if candidate.to_str().is_some_and(|s| s.len() <= 103) {
                (candidate, None)
            } else {
                let dir = PathBuf::from(format!("/tmp/mp-run-{}-{seq}", std::process::id()));
                fs::create_dir_all(&dir).expect("create short socket dir");
                (dir.join("c.sock"), Some(dir))
            };
            let _ = fs::remove_file(&socket_path);
            let listener = tokio::net::UnixListener::bind(&socket_path)
                .expect("bind mock Unix socket");
            let endpoint = format!("unix://{}", socket_path.display());
            let cleanup = UnixCleanupGuard {
                socket_path,
                short_dir,
            };
            let task = tokio::spawn(async move {
                loop {
                    let result = tokio::select! {
                        biased;
                        _ = shutdown_rx.wait_for(|done| *done) => break,
                        result = listener.accept() => result,
                    };
                    match result {
                        Ok((stream, _)) => {
                            tokio::spawn(handle_mock_connection(stream, Arc::clone(&state)));
                        }
                        Err(err) => panic!("mock Unix socket accept error: {err}"),
                    }
                }
            });
            (endpoint, task, cleanup)
        };

        ControlEndpoint::parse(&endpoint).expect("valid mock daemon endpoint");
        Self {
            endpoint,
            shutdown,
            task,
            #[cfg(unix)]
            _cleanup: cleanup,
        }
    }

    async fn stop(self) {
        let _ = self.shutdown.send(true);
        self.task.await.expect("join mock daemon server");
    }
}

async fn run_cli(args: Vec<String>) -> Output {
    tokio::task::spawn_blocking(move || {
        Command::new(env!("CARGO_BIN_EXE_sandbox-cli"))
            .args(&args)
            .output()
            .expect("execute sandbox-cli subprocess")
    })
    .await
    .expect("join sandbox-cli task")
}

fn spawn_interruptible_cli(args: &[String]) -> std::process::Child {
    let mut command = Command::new(env!("CARGO_BIN_EXE_sandbox-cli"));
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        command.creation_flags(CREATE_NEW_PROCESS_GROUP);
    }
    command.spawn().expect("spawn isolated sandbox-cli child")
}

fn send_console_interrupt(pid: u32) -> bool {
    #[cfg(unix)]
    {
        Command::new("kill")
            .args(["-INT", &pid.to_string()])
            .status()
            .is_ok_and(|status| status.success())
    }
    #[cfg(windows)]
    {
        let script = format!(
            "$src = 'using System; using System.Runtime.InteropServices; public static class MiniPodCtrl {{ [DllImport(\"Kernel32.dll\", SetLastError=true)] public static extern bool GenerateConsoleCtrlEvent(uint eventType, uint groupId); }}'; Add-Type -TypeDefinition $src; if (![MiniPodCtrl]::GenerateConsoleCtrlEvent(1, {pid})) {{ exit 1 }}"
        );
        Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .status()
            .is_ok_and(|status| status.success())
    }
}

fn kill_isolated_cli(pid: u32) {
    #[cfg(unix)]
    let _ = Command::new("kill")
        .args(["-KILL", &pid.to_string()])
        .status();
    #[cfg(windows)]
    let _ = Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/T", "/F"])
        .status();
}

async fn wait_for_cli_output(
    child: std::process::Child,
    max_wait: Duration,
) -> Output {
    let pid = child.id();
    let mut waiter = tokio::task::spawn_blocking(move || child.wait_with_output());
    match tokio::time::timeout(max_wait, &mut waiter).await {
        Ok(joined) => joined
            .expect("join interrupted CLI process")
            .expect("read interrupted CLI output"),
        Err(_) => {
            kill_isolated_cli(pid);
            let _ = waiter.await;
            panic!("sandbox-cli did not exit within {max_wait:?}");
        }
    }
}

fn plain_run_args(endpoint: &str) -> Vec<String> {
    vec!["--endpoint".into(), endpoint.into(), "run".into()]
}

fn output_archive(temp: &TestTempDir) -> Vec<u8> {
    let source = temp.path().join("guest-result");
    fs::create_dir_all(&source).expect("create guest result fixture");
    fs::write(source.join("artifact.txt"), b"generated in guest")
        .expect("write guest result fixture");
    pack_path_to_tar_bytes(&source, 1024 * 1024).expect("pack output tar fixture")
}

fn json_output(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|err| {
        panic!(
            "expected JSON stdout, got parse error {err}: {}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

fn run_args(endpoint: &str) -> Vec<String> {
    vec![
        "--endpoint".into(),
        endpoint.into(),
        "--json".into(),
        "run".into(),
    ]
}

#[tokio::test]
async fn run_copies_selected_input_executes_argv_and_publishes_output_before_destroy() {
    let temp = TestTempDir::new("mp-run-success");
    let output_tar = output_archive(&temp);
    let state = Arc::new(Mutex::new(MockRunState::new(MockRunConfig::success(
        output_tar,
    ))));
    let daemon = MockDaemon::start(&temp, Arc::clone(&state));

    let input = temp.path().join("input workspace");
    fs::create_dir_all(&input).expect("create input workspace");
    fs::write(input.join("source file.txt"), b"input stays on host")
        .expect("write input fixture");
    let destination = temp.path().join("output workspace");
    let mut args = run_args(&daemon.endpoint);
    args.extend([
        "--input".into(),
        input.display().to_string(),
        "/work".into(),
        "--output".into(),
        "/work/generated".into(),
        destination.display().to_string(),
        "--cwd".into(),
        "/work".into(),
        "--user".into(),
        "1000:1000".into(),
        "--env".into(),
        "BUILD_LABEL=hello world".into(),
        "--deadline-secs".into(),
        "17".into(),
        "--stdout-budget-bytes".into(),
        "512".into(),
        "--stderr-budget-bytes".into(),
        "256".into(),
        "--".into(),
        "/bin/echo".into(),
        "argument with spaces".into(),
    ]);
    let output = run_cli(args).await;

    assert_eq!(
        output.status.code(),
        Some(0),
        "run failed. stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let result = json_output(&output);
    assert_eq!(result["workload"]["status"], "completed");
    assert_eq!(result["workload"]["exit_code"], 0);
    assert_eq!(result["workload"]["stdout"], "hello from guest\n");
    assert_eq!(result["workload"]["stderr"], "guest diagnostic\n");
    assert_eq!(result["copy_out"]["status"], "copied");
    assert_eq!(result["cleanup"]["status"], "AllResourcesCleaned");
    assert_eq!(result["id"], "sb-run-e2e-1");
    assert_eq!(
        fs::read(destination.join("artifact.txt")).expect("read copied output"),
        b"generated in guest"
    );
    assert_eq!(
        fs::read(input.join("source file.txt")).expect("read original input"),
        b"input stays on host"
    );

    let (requests, spec, copied_in, exec, copy_out, destroyed) = {
        let st = state.lock().expect("mock state lock");
        (
            st.requests.clone(),
            st.sandbox_spec.clone().expect("spawn spec"),
            st.copied_in.clone().expect("copy-in request"),
            st.exec_request.clone().expect("exec request"),
            st.copy_out_source.clone().expect("copy-out request"),
            st.destroyed_ids.clone(),
        )
    };
    assert_eq!(requests, ["spawn", "copy-in", "exec", "copy-out", "destroy"]);
    assert_eq!(spec.isolation, IsolationMode::VmRequired);
    assert_eq!(spec.network, NetworkPolicy::Isolated);
    assert_eq!(copied_in.0, "/work");
    let unpacked = temp.path().join("uploaded-input");
    extract_tar_bytes_safely(&copied_in.1, &unpacked, 1024 * 1024, 128)
        .expect("validate copied input tar");
    assert_eq!(
        fs::read(unpacked.join("source file.txt")).expect("read uploaded input"),
        b"input stays on host"
    );
    assert_eq!(exec.target, ExecTarget::Guest);
    assert_eq!(exec.argv, ["/bin/echo", "argument with spaces"]);
    assert_eq!(exec.cwd.as_deref(), Some("/work"));
    assert_eq!(exec.user.as_deref(), Some("1000:1000"));
    assert_eq!(exec.env.get("BUILD_LABEL").map(String::as_str), Some("hello world"));
    assert_eq!(exec.deadline, Duration::from_secs(17));
    assert_eq!(exec.stdout_budget_bytes, 512);
    assert_eq!(exec.stderr_budget_bytes, 256);
    assert_eq!(copy_out, "/work/generated");
    assert_eq!(destroyed, ["sb-run-e2e-1"]);
    daemon.stop().await;
}

#[tokio::test]
async fn run_propagates_nonzero_exit_skips_copy_out_and_still_destroys() {
    let temp = TestTempDir::new("mp-run-nonzero");
    let mut config = MockRunConfig::success(output_archive(&temp));
    config.exit.code = Some(37);
    config.stdout = b"partial result\n".to_vec();
    config.stderr = b"task failed\n".to_vec();
    let state = Arc::new(Mutex::new(MockRunState::new(config)));
    let daemon = MockDaemon::start(&temp, Arc::clone(&state));
    let destination = temp.path().join("result");

    let mut args = run_args(&daemon.endpoint);
    args.extend([
        "--output".into(),
        "/work/result".into(),
        destination.display().to_string(),
        "--".into(),
        "/bin/false".into(),
    ]);
    let output = run_cli(args).await;

    assert_eq!(output.status.code(), Some(37));
    let result = json_output(&output);
    assert_eq!(result["workload"]["status"], "failed");
    assert_eq!(result["workload"]["exit_code"], 37);
    assert_eq!(result["copy_out"]["status"], "skipped");
    assert_eq!(result["cleanup"]["status"], "AllResourcesCleaned");
    assert!(!destination.exists(), "failed workload must not publish output");
    {
        let st = state.lock().expect("mock state lock");
        assert_eq!(st.requests, ["spawn", "exec", "destroy"]);
        assert_eq!(st.destroyed_ids, ["sb-run-e2e-1"]);
    }
    daemon.stop().await;
}

#[tokio::test]
async fn run_reports_timeout_and_output_budget_flags_and_cleans_up() {
    let temp = TestTempDir::new("mp-run-timeout");
    let mut config = MockRunConfig::success(Vec::new());
    config.exit = ExecExitStatus {
        code: None,
        timed_out: true,
        stdout_truncated: true,
        stderr_truncated: true,
    };
    let state = Arc::new(Mutex::new(MockRunState::new(config)));
    let daemon = MockDaemon::start(&temp, Arc::clone(&state));

    let output = run_cli([
        run_args(&daemon.endpoint),
        vec!["--".into(), "/bin/sleep".into(), "60".into()],
    ]
    .concat())
    .await;

    assert_ne!(output.status.code(), Some(0));
    let result = json_output(&output);
    assert_eq!(result["workload"]["timed_out"], true);
    assert_eq!(result["workload"]["stdout_truncated"], true);
    assert_eq!(result["workload"]["stderr_truncated"], true);
    assert_eq!(result["cleanup"]["status"], "AllResourcesCleaned");
    assert_eq!(
        state.lock().expect("mock state lock").requests,
        ["spawn", "exec", "destroy"]
    );
    daemon.stop().await;
}

#[tokio::test]
async fn run_preflights_existing_output_before_spawning_a_sandbox() {
    let temp = TestTempDir::new("mp-run-existing-output");
    let state = Arc::new(Mutex::new(MockRunState::new(MockRunConfig::success(
        Vec::new(),
    ))));
    let daemon = MockDaemon::start(&temp, Arc::clone(&state));
    let destination = temp.path().join("existing-result");
    fs::create_dir_all(&destination).expect("create existing output");
    fs::write(destination.join("sentinel.txt"), b"existing contents")
        .expect("write existing output sentinel");

    let mut args = run_args(&daemon.endpoint);
    args.extend([
        "--output".into(),
        "/work/result".into(),
        destination.display().to_string(),
        "--".into(),
        "/bin/true".into(),
    ]);
    let output = run_cli(args).await;

    assert_ne!(output.status.code(), Some(0));
    assert_eq!(
        fs::read(destination.join("sentinel.txt")).expect("read preserved sentinel"),
        b"existing contents"
    );
    assert!(
        state.lock().expect("mock state lock").requests.is_empty(),
        "existing output must be rejected before sandbox allocation"
    );
    daemon.stop().await;
}

#[tokio::test]
async fn run_refuses_destination_created_during_copy_out_and_still_destroys() {
    let temp = TestTempDir::new("mp-run-copyout-race");
    let destination = temp.path().join("race-result");
    let mut config = MockRunConfig::success(output_archive(&temp));
    config.create_destination_during_copy_out = Some(destination.clone());
    let state = Arc::new(Mutex::new(MockRunState::new(config)));
    let daemon = MockDaemon::start(&temp, Arc::clone(&state));

    let mut args = run_args(&daemon.endpoint);
    args.extend([
        "--output".into(),
        "/work/result".into(),
        destination.display().to_string(),
        "--".into(),
        "/bin/true".into(),
    ]);
    let output = run_cli(args).await;

    assert_ne!(output.status.code(), Some(0));
    let result = json_output(&output);
    assert_eq!(result["workload"]["status"], "completed");
    assert_eq!(result["copy_out"]["status"], "failed");
    assert_eq!(result["cleanup"]["status"], "AllResourcesCleaned");
    assert_eq!(
        fs::read(destination.join("sentinel.txt")).expect("read raced destination sentinel"),
        b"keep this destination"
    );
    assert!(
        !destination.join("artifact.txt").exists(),
        "copy-out must not publish into the directory created by another process"
    );
    assert_eq!(
        state.lock().expect("mock state lock").requests,
        ["spawn", "exec", "copy-out", "destroy"]
    );
    daemon.stop().await;
}

#[tokio::test]
async fn run_reports_incomplete_cleanup_as_failure_after_successful_workload() {
    let temp = TestTempDir::new("mp-run-cleanup-incomplete");
    let mut config = MockRunConfig::success(Vec::new());
    config.cleanup = CleanupResponse::ProcessExited;
    let state = Arc::new(Mutex::new(MockRunState::new(config)));
    let daemon = MockDaemon::start(&temp, Arc::clone(&state));

    let output = run_cli([
        run_args(&daemon.endpoint),
        vec!["--".into(), "/bin/true".into()],
    ]
    .concat())
    .await;

    assert_ne!(output.status.code(), Some(0));
    let result = json_output(&output);
    assert_eq!(result["workload"]["status"], "completed");
    assert_eq!(result["cleanup"]["status"], "ProcessExited");
    assert_eq!(
        result["cleanup"]["remaining_artifacts"][0],
        "state/sb-run-e2e-1/overlay.qcow2"
    );
    assert_eq!(
        state.lock().expect("mock state lock").requests,
        ["spawn", "exec", "destroy"]
    );
    daemon.stop().await;
}

#[tokio::test]
async fn run_renews_short_lease_while_exec_start_is_pending() {
    let temp = TestTempDir::new("mp-run-renewal");
    let config = MockRunConfig::success(Vec::new());
    let state = Arc::new(Mutex::new(MockRunState::new(config)));
    let (exec_observed_tx, exec_observed_rx) = oneshot::channel();
    let (renewed_tx, renewed_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    {
        let mut st = state.lock().expect("mock state lock");
        st.exec_observed = Some(exec_observed_tx);
        st.release_exec = Some(release_rx);
        st.renewed = Some(renewed_tx);
    }
    let daemon = MockDaemon::start(&temp, Arc::clone(&state));
    let mut args = run_args(&daemon.endpoint);
    args.extend([
        "--ttl-secs".into(),
        "1".into(),
        "--".into(),
        "/bin/sleep".into(),
        "60".into(),
    ]);
    let cli_task = tokio::spawn(run_cli(args));

    tokio::time::timeout(Duration::from_secs(3), exec_observed_rx)
        .await
        .expect("run reached pending exec start")
        .expect("mock daemon signaled exec request");
    let renewed_ttl_ms = tokio::time::timeout(Duration::from_secs(3), renewed_rx)
        .await
        .expect("run renewed its lease before it expired")
        .expect("mock daemon recorded renewal");
    assert_eq!(renewed_ttl_ms, 1_000);
    let _ = release_tx.send(());

    let output = tokio::time::timeout(Duration::from_secs(5), cli_task)
        .await
        .expect("run completed after exec start was released")
        .expect("join CLI process task");
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(
        state.lock().expect("mock state lock").requests,
        ["spawn", "exec", "renew", "destroy"]
    );
    daemon.stop().await;
}

#[tokio::test]
async fn run_handles_console_interrupt_by_cancelling_exec_and_destroying_sandbox() {
    let temp = TestTempDir::new("mp-run-interrupt");
    let mut config = MockRunConfig::success(Vec::new());
    config.wait_for_cancel = true;
    let state = Arc::new(Mutex::new(MockRunState::new(config)));
    let (exec_started_tx, exec_started_rx) = oneshot::channel();
    state.lock().expect("mock state lock").exec_started = Some(exec_started_tx);
    let daemon = MockDaemon::start(&temp, Arc::clone(&state));
    let mut args = run_args(&daemon.endpoint);
    args.extend(["--".into(), "/bin/sleep".into(), "60".into()]);
    let mut command = Command::new(env!("CARGO_BIN_EXE_sandbox-cli"));
    command
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;
        command.creation_flags(CREATE_NEW_PROCESS_GROUP);
    }
    let mut child = command.spawn().expect("spawn isolated sandbox-cli child");

    tokio::time::timeout(Duration::from_secs(5), exec_started_rx)
        .await
        .expect("run entered active exec")
        .expect("mock daemon signaled ExecStarted");

    #[cfg(unix)]
    let interrupt = Command::new("kill")
        .args(["-INT", &child.id().to_string()])
        .status()
        .expect("send SIGINT to sandbox-cli child");
    #[cfg(windows)]
    let interrupt = {
        let pid = child.id();
        let script = format!(
            "$src = 'using System; using System.Runtime.InteropServices; public static class MiniPodCtrl {{ [DllImport(\"Kernel32.dll\", SetLastError=true)] public static extern bool GenerateConsoleCtrlEvent(uint eventType, uint groupId); }}'; Add-Type -TypeDefinition $src; if (![MiniPodCtrl]::GenerateConsoleCtrlEvent(1, {pid})) {{ exit 1 }}"
        );
        Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
            .status()
            .expect("send CTRL_BREAK_EVENT to isolated sandbox-cli process group")
    };

    if !interrupt.success() {
        let _ = child.kill();
        let _ = tokio::task::spawn_blocking(move || child.wait_with_output())
            .await
            .expect("join fallback child wait");
        eprintln!("[skip] no supported console interrupt mechanism in this test environment");
        daemon.stop().await;
        return;
    }

    let output = tokio::time::timeout(
        Duration::from_secs(8),
        tokio::task::spawn_blocking(move || child.wait_with_output()),
    )
    .await
    .expect("sandbox-cli handled interrupt")
    .expect("join interrupted CLI process")
    .expect("read interrupted CLI output");
    assert_eq!(output.status.code(), Some(130));
    let result = json_output(&output);
    assert_eq!(result["interrupted"], true);
    assert_eq!(result["workload"]["status"], "interrupted");
    assert_eq!(result["cleanup"]["status"], "AllResourcesCleaned");
    assert_eq!(
        state.lock().expect("mock state lock").requests,
        ["spawn", "exec", "cancel", "destroy"]
    );
    daemon.stop().await;
}

#[tokio::test]
async fn run_interrupt_during_stalled_copy_out_destroys_without_copy_reply() {
    let temp = TestTempDir::new("mp-run-copyout-interrupt");
    let mut config = MockRunConfig::success(output_archive(&temp));
    config.stall_copy_out = true;
    let state = Arc::new(Mutex::new(MockRunState::new(config)));
    let (copy_out_observed_tx, copy_out_observed_rx) = oneshot::channel();
    let (release_copy_out_tx, release_copy_out_rx) = oneshot::channel();
    {
        let mut st = state.lock().expect("mock state lock");
        st.copy_out_observed = Some(copy_out_observed_tx);
        st.release_copy_out = Some(release_copy_out_rx);
    }
    let daemon = MockDaemon::start(&temp, Arc::clone(&state));
    let destination = temp.path().join("stalled-copy-out-result");
    let mut args = run_args(&daemon.endpoint);
    args.extend([
        "--output".into(),
        "/work/result".into(),
        destination.display().to_string(),
        "--".into(),
        "/bin/true".into(),
    ]);
    let mut child = spawn_interruptible_cli(&args);
    let pid = child.id();

    if tokio::time::timeout(Duration::from_secs(5), copy_out_observed_rx)
        .await
        .is_err()
    {
        kill_isolated_cli(pid);
        let _ = tokio::task::spawn_blocking(move || child.wait()).await;
        panic!("run did not issue CopyOutTar");
    }
    assert!(send_console_interrupt(pid), "send Ctrl+C to isolated CLI group");
    let output = wait_for_cli_output(child, Duration::from_secs(8)).await;
    let _ = release_copy_out_tx.send(());

    assert_eq!(output.status.code(), Some(130));
    let result = json_output(&output);
    assert_eq!(result["interrupted"], true);
    assert_eq!(result["workload"]["status"], "completed");
    assert_eq!(result["copy_out"]["status"], "failed");
    assert_eq!(result["cleanup"]["status"], "AllResourcesCleaned");
    assert!(!destination.exists(), "no output should publish without a copy-out reply");
    assert_eq!(
        state.lock().expect("mock state lock").requests,
        ["spawn", "exec", "copy-out", "destroy"]
    );
    daemon.stop().await;
}

#[tokio::test]
async fn run_failed_lease_renewal_during_stalled_copy_out_still_destroys() {
    let temp = TestTempDir::new("mp-run-copyout-renewal-failure");
    let mut config = MockRunConfig::success(output_archive(&temp));
    config.stall_copy_out = true;
    config.renewal_error = true;
    let state = Arc::new(Mutex::new(MockRunState::new(config)));
    let (copy_out_observed_tx, copy_out_observed_rx) = oneshot::channel();
    let (release_copy_out_tx, release_copy_out_rx) = oneshot::channel();
    let (renewal_tx, renewal_rx) = oneshot::channel();
    {
        let mut st = state.lock().expect("mock state lock");
        st.copy_out_observed = Some(copy_out_observed_tx);
        st.release_copy_out = Some(release_copy_out_rx);
        st.renewed = Some(renewal_tx);
    }
    let daemon = MockDaemon::start(&temp, Arc::clone(&state));
    let destination = temp.path().join("renewal-failed-copy-out");
    let mut args = run_args(&daemon.endpoint);
    args.extend([
        "--ttl-secs".into(),
        "1".into(),
        "--output".into(),
        "/work/result".into(),
        destination.display().to_string(),
        "--".into(),
        "/bin/true".into(),
    ]);
    let child = spawn_interruptible_cli(&args);

    tokio::time::timeout(Duration::from_secs(5), copy_out_observed_rx)
        .await
        .expect("run entered stalled CopyOutTar")
        .expect("mock daemon signaled CopyOutTar");
    tokio::time::timeout(Duration::from_secs(5), renewal_rx)
        .await
        .expect("short lease renewal was attempted during copy-out")
        .expect("mock daemon recorded renewal attempt");
    let output = wait_for_cli_output(child, Duration::from_secs(8)).await;
    let _ = release_copy_out_tx.send(());

    assert_eq!(output.status.code(), Some(1));
    let result = json_output(&output);
    assert_eq!(result["copy_out"]["status"], "failed");
    assert!(result["copy_out"]["error"].as_str().unwrap().contains("test lease renewal failure"));
    assert_eq!(result["cleanup"]["status"], "AllResourcesCleaned");
    assert!(!destination.exists(), "copy-out must not publish without a response");
    assert_eq!(
        state.lock().expect("mock state lock").requests,
        ["spawn", "exec", "copy-out", "renew", "destroy"]
    );
    daemon.stop().await;
}

#[tokio::test]
async fn run_interrupt_during_stalled_spawn_reports_unknown_cleanup_without_id() {
    let temp = TestTempDir::new("mp-run-spawn-interrupt");
    let mut config = MockRunConfig::success(Vec::new());
    config.stall_spawn = true;
    let state = Arc::new(Mutex::new(MockRunState::new(config)));
    let (spawn_observed_tx, spawn_observed_rx) = oneshot::channel();
    let (release_spawn_tx, release_spawn_rx) = oneshot::channel();
    {
        let mut st = state.lock().expect("mock state lock");
        st.spawn_observed = Some(spawn_observed_tx);
        st.release_spawn = Some(release_spawn_rx);
    }
    let daemon = MockDaemon::start(&temp, Arc::clone(&state));
    let mut args = run_args(&daemon.endpoint);
    args.extend(["--".into(), "/bin/true".into()]);
    let mut child = spawn_interruptible_cli(&args);
    let pid = child.id();

    if tokio::time::timeout(Duration::from_secs(5), spawn_observed_rx)
        .await
        .is_err()
    {
        kill_isolated_cli(pid);
        let _ = tokio::task::spawn_blocking(move || child.wait()).await;
        panic!("mock daemon did not receive Spawn");
    }
    assert!(send_console_interrupt(pid), "send Ctrl+C to isolated CLI group");
    let output = wait_for_cli_output(child, Duration::from_secs(8)).await;
    let _ = release_spawn_tx.send(());

    assert_eq!(output.status.code(), Some(130));
    let result = json_output(&output);
    assert_eq!(result["interrupted"], true);
    assert!(result["id"].is_null());
    assert_eq!(result["cleanup"]["status"], "unknown");
    assert_ne!(result["cleanup"]["status"], "AllResourcesCleaned");
    assert_eq!(state.lock().expect("mock state lock").requests, ["spawn"]);
    daemon.stop().await;
}

#[tokio::test]
async fn run_host_watchdog_times_out_stalled_exec_without_guest_exit() {
    let temp = TestTempDir::new("mp-run-host-watchdog");
    let mut config = MockRunConfig::success(Vec::new());
    config.wait_for_cancel = true;
    config.never_reply_after_cancel = true;
    let state = Arc::new(Mutex::new(MockRunState::new(config)));
    let (exec_started_tx, exec_started_rx) = oneshot::channel();
    let (cancel_observed_tx, cancel_observed_rx) = oneshot::channel();
    let (release_cancel_tx, release_cancel_rx) = oneshot::channel();
    {
        let mut st = state.lock().expect("mock state lock");
        st.exec_started = Some(exec_started_tx);
        st.cancel_observed = Some(cancel_observed_tx);
        st.release_cancel = Some(release_cancel_rx);
    }
    let daemon = MockDaemon::start(&temp, Arc::clone(&state));
    let mut args = run_args(&daemon.endpoint);
    args.extend([
        "--deadline-secs".into(),
        "1".into(),
        "--".into(),
        "/bin/sleep".into(),
        "60".into(),
    ]);
    let child = spawn_interruptible_cli(&args);

    tokio::time::timeout(Duration::from_secs(5), exec_started_rx)
        .await
        .expect("watchdog case reached active guest execution")
        .expect("mock daemon signaled ExecStarted");
    let output = wait_for_cli_output(child, Duration::from_secs(6)).await;
    let cancel_seen = tokio::time::timeout(Duration::from_secs(2), cancel_observed_rx)
        .await
        .is_ok_and(|result| result.is_ok());
    let _ = release_cancel_tx.send(());

    assert!(cancel_seen, "host watchdog must send Cancel to the stalled guest");
    assert_eq!(output.status.code(), Some(124));
    let result = json_output(&output);
    assert_eq!(result["workload"]["timed_out"], true);
    assert_ne!(result["workload"]["exit_code"], 0);
    assert_eq!(result["cleanup"]["status"], "AllResourcesCleaned");
    {
        let state = state.lock().expect("mock state lock");
        assert_eq!(state.requests, ["spawn", "exec", "cancel", "destroy"]);
        assert_eq!(
            state.exec_request.as_ref().expect("exec request").deadline,
            Duration::from_secs(1)
        );
    }
    daemon.stop().await;
}

#[tokio::test]
async fn run_host_watchdog_bounds_pending_exec_start_without_stream_id() {
    let temp = TestTempDir::new("mp-run-pending-exec-start-watchdog");
    let config = MockRunConfig::success(Vec::new());
    let state = Arc::new(Mutex::new(MockRunState::new(config)));
    let (exec_observed_tx, exec_observed_rx) = oneshot::channel();
    let (release_exec_tx, release_exec_rx) = oneshot::channel();
    {
        let mut st = state.lock().expect("mock state lock");
        st.exec_observed = Some(exec_observed_tx);
        st.release_exec = Some(release_exec_rx);
    }
    let daemon = MockDaemon::start(&temp, Arc::clone(&state));
    let mut args = run_args(&daemon.endpoint);
    args.extend([
        "--deadline-secs".into(),
        "1".into(),
        "--".into(),
        "/bin/sleep".into(),
        "60".into(),
    ]);
    let child = spawn_interruptible_cli(&args);

    tokio::time::timeout(Duration::from_secs(5), exec_observed_rx)
        .await
        .expect("run entered pending ExecStart")
        .expect("mock daemon observed ExecStart request");
    let output = wait_for_cli_output(child, Duration::from_secs(6)).await;
    let _ = release_exec_tx.send(());

    assert_eq!(output.status.code(), Some(124));
    let result = json_output(&output);
    assert_eq!(result["workload"]["timed_out"], true);
    assert!(result["workload"]["exit_code"].is_null());
    assert_eq!(result["cleanup"]["status"], "AllResourcesCleaned");
    assert_eq!(
        state.lock().expect("mock state lock").requests,
        ["spawn", "exec", "destroy"]
    );
    daemon.stop().await;
}

#[tokio::test]
async fn run_json_mode_flags_malicious_output_even_when_guest_claims_success() {
    let temp = TestTempDir::new("mp-run-json-output-budget");
    let mut config = MockRunConfig::success(Vec::new());
    config.stdout = vec![b'J'; 256];
    config.observe_cancel_after_output = true;
    let state = Arc::new(Mutex::new(MockRunState::new(config)));
    let (cancel_observed_tx, cancel_observed_rx) = oneshot::channel();
    state.lock().expect("mock state lock").cancel_observed = Some(cancel_observed_tx);
    let daemon = MockDaemon::start(&temp, Arc::clone(&state));
    let mut args = run_args(&daemon.endpoint);
    args.extend([
        "--stdout-budget-bytes".into(),
        "8".into(),
        "--".into(),
        "/bin/true".into(),
    ]);

    let output = run_cli(args).await;
    let cancel_seen = tokio::time::timeout(Duration::from_secs(2), cancel_observed_rx)
        .await
        .is_ok_and(|result| result.is_ok());
    assert!(cancel_seen, "host output cap must cancel the over-budget guest");
    assert_eq!(output.status.code(), Some(1));
    let result = json_output(&output);
    assert_eq!(result["workload"]["stdout"].as_str().unwrap().len(), 8);
    assert_eq!(result["workload"]["stdout_truncated"], true);
    assert!(
        result["workload"]["exit_code"].is_null(),
        "the host output cap must supersede the guest's later success status"
    );
    assert_eq!(result["copy_out"]["status"], "skipped");
    assert_eq!(result["cleanup"]["status"], "AllResourcesCleaned");
    assert_eq!(
        state.lock().expect("mock state lock").requests,
        ["spawn", "exec", "cancel", "destroy"]
    );
    daemon.stop().await;
}

#[tokio::test]
async fn run_json_mode_flags_malicious_guest_stderr_even_when_guest_claims_success() {
    let temp = TestTempDir::new("mp-run-json-stderr-budget");
    let mut config = MockRunConfig::success(Vec::new());
    config.stdout = b"ok".to_vec();
    config.stderr = vec![b'E'; 256];
    config.observe_cancel_after_output = true;
    let state = Arc::new(Mutex::new(MockRunState::new(config)));
    let (cancel_observed_tx, cancel_observed_rx) = oneshot::channel();
    state.lock().expect("mock state lock").cancel_observed = Some(cancel_observed_tx);
    let daemon = MockDaemon::start(&temp, Arc::clone(&state));
    let mut args = run_args(&daemon.endpoint);
    args.extend([
        "--stderr-budget-bytes".into(),
        "8".into(),
        "--".into(),
        "/bin/true".into(),
    ]);

    let output = run_cli(args).await;
    let cancel_seen = tokio::time::timeout(Duration::from_secs(2), cancel_observed_rx)
        .await
        .is_ok_and(|result| result.is_ok());
    assert!(cancel_seen, "host stderr cap must cancel the over-budget guest");
    assert_eq!(output.status.code(), Some(1));
    let result = json_output(&output);
    assert_eq!(result["workload"]["stdout"], "ok");
    assert_eq!(result["workload"]["stdout_truncated"], false);
    assert_eq!(result["workload"]["stderr"].as_str().unwrap().len(), 8);
    assert_eq!(result["workload"]["stderr_truncated"], true);
    assert!(result["workload"]["exit_code"].is_null());
    assert_eq!(result["copy_out"]["status"], "skipped");
    assert_eq!(result["cleanup"]["status"], "AllResourcesCleaned");
    assert_eq!(
        state.lock().expect("mock state lock").requests,
        ["spawn", "exec", "cancel", "destroy"]
    );
    daemon.stop().await;
}

#[tokio::test]
async fn run_plain_mode_caps_malicious_guest_stdout_before_writing() {
    let temp = TestTempDir::new("mp-run-plain-output-budget");
    let mut config = MockRunConfig::success(Vec::new());
    config.stdout = vec![b'P'; 256];
    config.observe_cancel_after_output = true;
    let state = Arc::new(Mutex::new(MockRunState::new(config)));
    let (cancel_observed_tx, cancel_observed_rx) = oneshot::channel();
    state.lock().expect("mock state lock").cancel_observed = Some(cancel_observed_tx);
    let daemon = MockDaemon::start(&temp, Arc::clone(&state));
    let mut args = plain_run_args(&daemon.endpoint);
    args.extend([
        "--stdout-budget-bytes".into(),
        "8".into(),
        "--".into(),
        "/bin/true".into(),
    ]);

    let output = run_cli(args).await;
    let cancel_seen = tokio::time::timeout(Duration::from_secs(2), cancel_observed_rx)
        .await
        .is_ok_and(|result| result.is_ok());
    assert!(cancel_seen, "plain output cap must cancel the over-budget guest");
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(output.stdout, vec![b'P'; 8], "guest stdout must not exceed its budget");
    assert!(String::from_utf8_lossy(&output.stderr).contains("stdout truncated at budget limit"));
    assert_eq!(
        state.lock().expect("mock state lock").requests,
        ["spawn", "exec", "cancel", "destroy"]
    );
    daemon.stop().await;
}

#[tokio::test]
async fn run_reports_unknown_cleanup_when_spawn_response_is_lost() {
    let temp = TestTempDir::new("mp-run-spawn-disconnect");
    let mut config = MockRunConfig::success(Vec::new());
    config.disconnect_after_spawn = true;
    let state = Arc::new(Mutex::new(MockRunState::new(config)));
    let daemon = MockDaemon::start(&temp, Arc::clone(&state));

    let output = run_cli([
        run_args(&daemon.endpoint),
        vec!["--".into(), "/bin/true".into()],
    ]
    .concat())
    .await;

    assert_ne!(output.status.code(), Some(0));
    let result = json_output(&output);
    assert!(result["id"].is_null());
    assert_eq!(result["cleanup"]["status"], "unknown");
    assert!(result["error"].as_str().is_some_and(|error| !error.is_empty()));
    assert_eq!(
        state.lock().expect("mock state lock").requests,
        ["spawn"]
    );
    daemon.stop().await;
}

#[tokio::test]
async fn run_copy_out_failure_keeps_destination_absent_and_still_destroys() {
    let temp = TestTempDir::new("mp-run-copyout-invalid");
    let config = MockRunConfig::success(b"not a tar archive".to_vec());
    let state = Arc::new(Mutex::new(MockRunState::new(config)));
    let daemon = MockDaemon::start(&temp, Arc::clone(&state));
    let destination = temp.path().join("invalid-result");

    let mut args = run_args(&daemon.endpoint);
    args.extend([
        "--output".into(),
        "/work/result".into(),
        destination.display().to_string(),
        "--".into(),
        "/bin/true".into(),
    ]);
    let output = run_cli(args).await;

    assert_ne!(output.status.code(), Some(0));
    let result = json_output(&output);
    assert_eq!(result["workload"]["status"], "completed");
    assert_eq!(result["copy_out"]["status"], "failed");
    assert_eq!(result["cleanup"]["status"], "AllResourcesCleaned");
    assert!(!destination.exists(), "failed extraction must not publish partial output");
    assert_eq!(
        state.lock().expect("mock state lock").requests,
        ["spawn", "exec", "copy-out", "destroy"]
    );
    daemon.stop().await;
}

#[tokio::test]
async fn hard_killed_run_does_not_send_client_side_destroy() {
    let temp = TestTempDir::new("mp-run-hard-kill");
    let config = MockRunConfig::success(Vec::new());
    let state = Arc::new(Mutex::new(MockRunState::new(config)));
    let (observed_tx, observed_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    {
        let mut st = state.lock().expect("mock state lock");
        st.exec_observed = Some(observed_tx);
        st.release_exec = Some(release_rx);
    }
    let daemon = MockDaemon::start(&temp, Arc::clone(&state));
    let mut args = run_args(&daemon.endpoint);
    args.extend([
        "--ttl-secs".into(),
        "1".into(),
        "--".into(),
        "/bin/sleep".into(),
        "60".into(),
    ]);
    let mut child = Command::new(env!("CARGO_BIN_EXE_sandbox-cli"))
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn sandbox-cli process");

    tokio::time::timeout(Duration::from_secs(10), observed_rx)
        .await
        .expect("run reached exec before hard kill")
        .expect("mock daemon signaled exec request");
    child.kill().expect("hard kill sandbox-cli process");
    let _ = tokio::task::spawn_blocking(move || child.wait())
        .await
        .expect("join child wait")
        .expect("wait for hard-killed sandbox-cli");
    let _ = release_tx.send(());

    {
        let st = state.lock().expect("mock state lock");
        assert_eq!(st.requests, ["spawn", "exec"]);
        assert!(st.destroyed_ids.is_empty());
        assert_eq!(st.sandbox_spec.as_ref().unwrap().lease_ttl, Duration::from_secs(1));
    }
    daemon.stop().await;
}
