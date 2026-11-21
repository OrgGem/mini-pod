use std::fs;
use std::path::PathBuf;
#[cfg(unix)]
use std::path::Path;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use sandbox_core::{
    AccelerationPolicy, CapabilityReport, DestroyStatus, EnforcementLevel, ExecExitStatus,
    IsolationMode, NetworkPolicy, SandboxId, SandboxLease, SandboxSpec,
};
use sandbox_client::wire::{
    read_control_frame, write_control_frame, ControlRequest, ControlResponse, DaemonStatusInfo,
    ExecWireEvent, ExecWireClientMsg, WireError,
};
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::watch;

static TEST_SEQ: AtomicU64 = AtomicU64::new(0);

struct TestTempDir(PathBuf);

impl TestTempDir {
    fn new(label: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "mp-doctor-smoke-{label}-{}-{}",
            std::process::id(),
            TEST_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).expect("create test temp dir");
        Self(dir)
    }

    #[cfg(unix)]
    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestTempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
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
            let _ = fs::remove_dir(dir);
        }
    }
}

#[derive(Clone)]
struct MockConfig {
    spawn_error: bool,
    accelerator_error: bool,
    accelerator: Option<String>,
    exec_error: bool,
    exit: ExecExitStatus,
    destroy_status: DestroyStatus,
}

impl Default for MockConfig {
    fn default() -> Self {
        Self {
            spawn_error: false,
            accelerator_error: false,
            accelerator: Some("tcg".to_owned()),
            exec_error: false,
            exit: ExecExitStatus {
                code: Some(0),
                timed_out: false,
                stdout_truncated: false,
                stderr_truncated: false,
            },
            destroy_status: DestroyStatus::AllResourcesCleaned,
        }
    }
}

struct MockState {
    config: MockConfig,
    requests: Vec<&'static str>,
    spawned_spec: Option<SandboxSpec>,
}

async fn send_response<S: AsyncWrite + Unpin>(stream: &mut S, response: ControlResponse) {
    let bytes = response.to_json_bytes().expect("serialize response");
    write_control_frame(stream, &bytes)
        .await
        .expect("write response");
    let _ = stream.shutdown().await;
}

async fn handle_connection<S>(mut stream: S, state: Arc<Mutex<MockState>>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let Ok(Some(raw)) = read_control_frame(&mut stream).await else {
        return;
    };
    let request = ControlRequest::from_json_bytes(&raw).expect("valid request frame");
    match request {
        ControlRequest::Status => {
            state.lock().expect("mock state lock").requests.push("status");
            send_response(
                &mut stream,
                ControlResponse::Status(DaemonStatusInfo {
                    active_sandboxes: 0,
                    warm_ready_vms: 0,
                    effective_host_rss_mb: 0,
                    reserved_host_storage_mb: 0,
                    version: "0.1.0-smoke-test".to_owned(),
                }),
            )
            .await;
        }
        ControlRequest::Doctor => {
            state.lock().expect("mock state lock").requests.push("doctor");
            let report = json!({
                "guest_arch": "x86_64",
                "qemu": { "status": "ok", "path": "C:/qemu/qemu-system-x86_64.exe", "detail": "QEMU test" },
                "qemu_img": { "status": "ok", "path": "C:/qemu/qemu-img.exe", "detail": "qemu-img test" },
                "bundle": { "status": "ok", "path": "C:/bundle", "detail": "verified" },
                "accelerators": { "status": "ok", "candidates": ["tcg"], "detail": "candidate only" }
            });
            send_response(&mut stream, ControlResponse::Doctor { report }).await;
        }
        ControlRequest::Spawn { spec } => {
            let lease = {
                let mut state = state.lock().expect("mock state lock");
                state.requests.push("spawn");
                state.spawned_spec = Some(spec.clone());
                (!state.config.spawn_error).then(|| SandboxLease {
                    id: SandboxId::new("sb-doctor-smoke-1"),
                    ttl: spec.lease_ttl,
                    capabilities: CapabilityReport {
                        cpu_quota: EnforcementLevel::Unsupported,
                        host_rss: EnforcementLevel::BestEffort,
                        host_storage: EnforcementLevel::BestEffort,
                        egress_filter: EnforcementLevel::HardLimit,
                    },
                })
            };
            if let Some(lease) = lease {
                send_response(&mut stream, ControlResponse::Spawned(lease)).await;
            } else {
                send_response(
                    &mut stream,
                    ControlResponse::Error(WireError {
                        kind: "AccelerationUnavailable".to_owned(),
                        message: "test spawn failure".to_owned(),
                    }),
                )
                .await;
            }
        }
        ControlRequest::GetAccelerator { id } => {
            assert_eq!(id.as_str(), "sb-doctor-smoke-1");
            let response = {
                let mut state = state.lock().expect("mock state lock");
                state.requests.push("accelerator");
                if state.config.accelerator_error {
                    ControlResponse::Error(WireError {
                        kind: "Transport".to_owned(),
                        message: "test accelerator query failure".to_owned(),
                    })
                } else {
                    ControlResponse::Accelerator {
                        name: state.config.accelerator.clone(),
                    }
                }
            };
            send_response(&mut stream, response).await;
        }
        ControlRequest::ExecStart { id, .. } => {
            assert_eq!(id.as_str(), "sb-doctor-smoke-1");
            let (exec_error, exit) = {
                let mut state = state.lock().expect("mock state lock");
                state.requests.push("exec");
                (state.config.exec_error, state.config.exit.clone())
            };
            if exec_error {
                send_response(
                    &mut stream,
                    ControlResponse::Error(WireError {
                        kind: "Internal".to_owned(),
                        message: "test exec start failure".to_owned(),
                    }),
                )
                .await;
                return;
            }

            let started = ControlResponse::ExecStarted { stream_id: 77 }
                .to_json_bytes()
                .expect("serialize ExecStarted");
            if write_control_frame(&mut stream, &started).await.is_err() {
                return;
            }

            // Wait until the client closes stdin before delivering the terminal event.
            loop {
                match read_control_frame(&mut stream).await {
                    Ok(Some(frame)) => {
                        if matches!(
                            ExecWireClientMsg::from_json_bytes(&frame),
                            Ok(ExecWireClientMsg::StdinEof)
                        ) {
                            break;
                        }
                    }
                    Ok(None) | Err(_) => return,
                }
            }

            for event in [
                ExecWireEvent::Stdout {
                    data: b"doctor-smoke-ok\n".to_vec(),
                },
                ExecWireEvent::Exit(exit),
            ] {
                if write_control_frame(&mut stream, &event.to_json_bytes().expect("serialize event"))
                    .await
                    .is_err()
                {
                    return;
                }
            }
            let _ = stream.shutdown().await;
        }
        ControlRequest::Destroy { id } => {
            assert_eq!(id.as_str(), "sb-doctor-smoke-1");
            let status = {
                let mut state = state.lock().expect("mock state lock");
                state.requests.push("destroy");
                state.config.destroy_status.clone()
            };
            send_response(&mut stream, ControlResponse::Destroyed(status)).await;
        }
        other => panic!("unexpected smoke request: {other:?}"),
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
    fn start(_temp: &TestTempDir, state: Arc<Mutex<MockState>>) -> Self {
        let seq = TEST_SEQ.fetch_add(1, Ordering::Relaxed);
        let (shutdown, mut shutdown_rx) = watch::channel(false);

        #[cfg(windows)]
        let (endpoint, task) = {
            use tokio::net::windows::named_pipe::ServerOptions;

            let pipe_path = format!(r"\\.\pipe\minipod-doctor-smoke-{}-{seq}", std::process::id());
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
                            tokio::spawn(handle_connection(connected, Arc::clone(&state)));
                        }
                        Err(err) => panic!("mock pipe accept error: {err}"),
                    }
                }
            });
            (pipe_path, task)
        };

        #[cfg(unix)]
        let (endpoint, task, cleanup) = {
            let candidate = _temp.path().join(format!("doctor-smoke-{seq}.sock"));
            let (socket_path, short_dir) = if candidate.to_str().is_some_and(|s| s.len() <= 103) {
                (candidate, None)
            } else {
                let dir = PathBuf::from(format!("/tmp/mp-doctor-smoke-{}-{seq}", std::process::id()));
                fs::create_dir_all(&dir).expect("create short socket directory");
                (dir.join("d.sock"), Some(dir))
            };
            let listener = tokio::net::UnixListener::bind(&socket_path).expect("bind mock socket");
            let endpoint = format!("unix://{}", socket_path.display());
            let cleanup = UnixCleanupGuard { socket_path, short_dir };
            let task = tokio::spawn(async move {
                loop {
                    let result = tokio::select! {
                        biased;
                        _ = shutdown_rx.wait_for(|done| *done) => break,
                        result = listener.accept() => result,
                    };
                    match result {
                        Ok((stream, _)) => {
                            tokio::spawn(handle_connection(stream, Arc::clone(&state)));
                        }
                        Err(err) => panic!("mock Unix socket accept error: {err}"),
                    }
                }
            });
            (endpoint, task, cleanup)
        };

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
        self.task.await.expect("join mock daemon task");
    }
}

fn new_state(config: MockConfig) -> Arc<Mutex<MockState>> {
    Arc::new(Mutex::new(MockState {
        config,
        requests: Vec::new(),
        spawned_spec: None,
    }))
}

async fn run_cli(endpoint: &str, extra: &[&str]) -> Output {
    let endpoint = endpoint.to_owned();
    let extra = extra.iter().map(|arg| arg.to_string()).collect::<Vec<_>>();
    tokio::task::spawn_blocking(move || {
        Command::new(env!("CARGO_BIN_EXE_sandbox-cli"))
            .args(["--endpoint", &endpoint, "--json", "doctor", "--smoke"])
            .args(extra)
            .output()
            .expect("execute sandbox-cli subprocess")
    })
    .await
    .expect("join sandbox-cli task")
}

async fn run_cli_plain(endpoint: &str, extra: &[&str]) -> Output {
    let endpoint = endpoint.to_owned();
    let extra = extra.iter().map(|arg| arg.to_string()).collect::<Vec<_>>();
    tokio::task::spawn_blocking(move || {
        Command::new(env!("CARGO_BIN_EXE_sandbox-cli"))
            .args(["--endpoint", &endpoint, "doctor", "--smoke"])
            .args(extra)
            .output()
            .expect("execute plain sandbox-cli doctor subprocess")
    })
    .await
    .expect("join plain sandbox-cli task")
}

fn parse_json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|err| {
        panic!(
            "expected JSON stdout, got parse error {err}: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

#[tokio::test]
async fn doctor_smoke_runs_isolated_vm_and_reports_driver_accelerator() {
    let temp = TestTempDir::new("success");
    let state = new_state(MockConfig::default());
    let daemon = MockDaemon::start(&temp, Arc::clone(&state));

    let output = run_cli(&daemon.endpoint, &[]).await;

    assert_eq!(output.status.code(), Some(0), "{}", String::from_utf8_lossy(&output.stderr));
    let report = parse_json(&output);
    assert_eq!(report["smoke"]["status"], "ok");
    assert_eq!(report["smoke"]["boot_handshake"]["status"], "ok");
    assert_eq!(report["smoke"]["accelerator"]["status"], "ok");
    assert_eq!(report["smoke"]["accelerator"]["used"], "tcg");
    assert_eq!(report["smoke"]["workload"]["status"], "completed");
    assert_eq!(report["smoke"]["workload"]["exit_code"], 0);
    assert_eq!(report["smoke"]["workload"]["stdout"], "doctor-smoke-ok\n");
    assert_eq!(report["smoke"]["cleanup"]["status"], "AllResourcesCleaned");

    let state = state.lock().expect("mock state lock");
    assert_eq!(state.requests, ["status", "doctor", "spawn", "accelerator", "exec", "destroy"]);
    let spec = state.spawned_spec.as_ref().expect("smoke spawn spec");
    assert_eq!(spec.isolation, IsolationMode::VmRequired);
    assert_eq!(spec.acceleration, AccelerationPolicy::Preferred);
    assert_eq!(spec.network, NetworkPolicy::Isolated);
    assert_eq!(spec.budget.guest_vcpus, 1);
    drop(state);
    daemon.stop().await;
}

#[tokio::test]
async fn doctor_smoke_plain_output_shows_the_active_accelerator() {
    let temp = TestTempDir::new("plain-accelerator");
    let state = new_state(MockConfig::default());
    let daemon = MockDaemon::start(&temp, Arc::clone(&state));

    let output = run_cli_plain(&daemon.endpoint, &[]).await;

    assert_eq!(output.status.code(), Some(0), "{}", String::from_utf8_lossy(&output.stderr));
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        text.contains("smoke accelerator: ok tcg"),
        "plain doctor output must expose the active accelerator, got: {text}"
    );
    assert_eq!(
        state.lock().expect("mock state lock").requests,
        ["status", "doctor", "spawn", "accelerator", "exec", "destroy"]
    );
    daemon.stop().await;
}

#[tokio::test]
async fn doctor_smoke_exec_failure_still_destroys_sandbox() {
    let temp = TestTempDir::new("exec-failure");
    let mut config = MockConfig::default();
    config.exit.code = Some(23);
    let state = new_state(config);
    let daemon = MockDaemon::start(&temp, Arc::clone(&state));

    let output = run_cli(&daemon.endpoint, &[]).await;

    assert_eq!(output.status.code(), Some(1), "{}", String::from_utf8_lossy(&output.stderr));
    let report = parse_json(&output);
    assert_eq!(report["smoke"]["status"], "error");
    assert_eq!(report["smoke"]["workload"]["exit_code"], 23);
    assert_eq!(report["smoke"]["cleanup"]["status"], "AllResourcesCleaned");
    assert_eq!(
        state.lock().expect("mock state lock").requests,
        ["status", "doctor", "spawn", "accelerator", "exec", "destroy"]
    );
    daemon.stop().await;
}

#[tokio::test]
async fn doctor_smoke_reports_unknown_accelerator_and_fails_readiness() {
    let temp = TestTempDir::new("unknown-accelerator");
    let mut config = MockConfig::default();
    config.accelerator = None;
    let state = new_state(config);
    let daemon = MockDaemon::start(&temp, Arc::clone(&state));

    let output = run_cli(&daemon.endpoint, &[]).await;

    assert_eq!(output.status.code(), Some(1), "{}", String::from_utf8_lossy(&output.stderr));
    let report = parse_json(&output);
    assert_eq!(report["smoke"]["status"], "unknown");
    assert_eq!(report["smoke"]["accelerator"]["status"], "unknown");
    assert!(report["smoke"]["accelerator"]["used"].is_null());
    assert_eq!(report["smoke"]["cleanup"]["status"], "AllResourcesCleaned");
    assert_eq!(
        state.lock().expect("mock state lock").requests,
        ["status", "doctor", "spawn", "accelerator", "exec", "destroy"]
    );
    daemon.stop().await;
}

#[tokio::test]
async fn doctor_smoke_marks_process_exited_cleanup_as_failure() {
    let temp = TestTempDir::new("process-exited");
    let mut config = MockConfig::default();
    config.destroy_status = DestroyStatus::ProcessExited {
        remaining_artifacts: vec![PathBuf::from("test-overlay.qcow2")],
    };
    let state = new_state(config);
    let daemon = MockDaemon::start(&temp, Arc::clone(&state));

    let output = run_cli(&daemon.endpoint, &[]).await;

    assert_eq!(output.status.code(), Some(1), "{}", String::from_utf8_lossy(&output.stderr));
    let report = parse_json(&output);
    assert_eq!(report["smoke"]["status"], "error");
    assert_eq!(report["smoke"]["cleanup"]["status"], "ProcessExited");
    assert_eq!(
        report["smoke"]["cleanup"]["remaining_artifacts"][0],
        "test-overlay.qcow2"
    );
    daemon.stop().await;
}

#[tokio::test]
async fn doctor_smoke_spawn_failure_does_not_claim_boot_or_destroy() {
    let temp = TestTempDir::new("spawn-failure");
    let mut config = MockConfig::default();
    config.spawn_error = true;
    let state = new_state(config);
    let daemon = MockDaemon::start(&temp, Arc::clone(&state));

    let output = run_cli(&daemon.endpoint, &[]).await;

    assert_eq!(output.status.code(), Some(1), "{}", String::from_utf8_lossy(&output.stderr));
    let report = parse_json(&output);
    assert_eq!(report["smoke"]["status"], "error");
    assert_eq!(report["smoke"]["id"], Value::Null);
    assert_eq!(report["smoke"]["boot_handshake"]["status"], "error");
    assert_eq!(report["smoke"]["cleanup"]["status"], "not_started");
    assert_eq!(state.lock().expect("mock state lock").requests, ["status", "doctor", "spawn"]);
    daemon.stop().await;
}

#[tokio::test]
async fn doctor_smoke_exec_start_failure_still_destroys_sandbox() {
    let temp = TestTempDir::new("exec-start-failure");
    let mut config = MockConfig::default();
    config.exec_error = true;
    let state = new_state(config);
    let daemon = MockDaemon::start(&temp, Arc::clone(&state));

    let output = run_cli(&daemon.endpoint, &[]).await;

    assert_eq!(output.status.code(), Some(1), "{}", String::from_utf8_lossy(&output.stderr));
    let report = parse_json(&output);
    assert_eq!(report["smoke"]["status"], "error");
    assert_eq!(report["smoke"]["boot_handshake"]["status"], "ok");
    assert_eq!(report["smoke"]["workload"]["status"], "failed");
    assert_eq!(report["smoke"]["cleanup"]["status"], "AllResourcesCleaned");
    assert_eq!(
        state.lock().expect("mock state lock").requests,
        ["status", "doctor", "spawn", "accelerator", "exec", "destroy"]
    );
    daemon.stop().await;
}

#[tokio::test]
async fn doctor_smoke_rejects_actual_accelerator_that_violates_policy() {
    let temp = TestTempDir::new("acceleration-policy-mismatch");
    let state = new_state(MockConfig::default());
    let daemon = MockDaemon::start(&temp, Arc::clone(&state));

    let output = run_cli(&daemon.endpoint, &["--accel", "required"]).await;

    assert_eq!(output.status.code(), Some(1), "{}", String::from_utf8_lossy(&output.stderr));
    let report = parse_json(&output);
    assert_eq!(report["smoke"]["status"], "error");
    assert_eq!(report["smoke"]["accelerator"]["status"], "error");
    assert_eq!(report["smoke"]["accelerator"]["used"], "tcg");
    assert_eq!(report["smoke"]["workload"]["status"], "not_started");
    assert_eq!(report["smoke"]["cleanup"]["status"], "AllResourcesCleaned");
    let state = state.lock().expect("mock state lock");
    assert_eq!(state.requests, ["status", "doctor", "spawn", "accelerator", "destroy"]);
    assert_eq!(
        state.spawned_spec.as_ref().expect("smoke spawn spec").acceleration,
        AccelerationPolicy::Required
    );
    drop(state);
    daemon.stop().await;
}
