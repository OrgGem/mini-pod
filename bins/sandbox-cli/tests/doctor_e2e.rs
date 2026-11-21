#![forbid(unsafe_code)]

use std::fs;
use std::path::PathBuf;
#[cfg(unix)]
use std::path::Path;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sandbox_client::{
    read_control_frame, write_control_frame, ControlEndpoint, ControlRequest, ControlResponse,
    DaemonStatusInfo, WireError,
};
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::watch;

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

    #[cfg(unix)]
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

#[derive(Clone)]
enum DoctorReply {
    Report(Value),
    Unsupported,
}

struct MockState {
    doctor_reply: DoctorReply,
    requests: Vec<&'static str>,
}

async fn handle_connection<S>(mut stream: S, state: Arc<Mutex<MockState>>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let Ok(Some(raw)) = read_control_frame(&mut stream).await else {
        return;
    };
    let request = ControlRequest::from_json_bytes(&raw).expect("valid ControlRequest frame");
    let response = match request {
        ControlRequest::Status => {
            state.lock().expect("mock state lock").requests.push("status");
            ControlResponse::Status(DaemonStatusInfo {
                active_sandboxes: 0,
                warm_ready_vms: 0,
                effective_host_rss_mb: 0,
                reserved_host_storage_mb: 0,
                version: "0.1.0-doctor-test".to_owned(),
            })
        }
        ControlRequest::Doctor => {
            let mut state = state.lock().expect("mock state lock");
            state.requests.push("doctor");
            match state.doctor_reply.clone() {
                DoctorReply::Report(report) => ControlResponse::Doctor { report },
                DoctorReply::Unsupported => ControlResponse::Error(WireError {
                    kind: "Transport".to_owned(),
                    message: "unknown request type 'Doctor'".to_owned(),
                }),
            }
        }
        other => panic!("unexpected doctor request: {other:?}"),
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
    fn start(_temp: &TestTempDir, state: Arc<Mutex<MockState>>) -> Self {
        let seq = TEST_SEQ.fetch_add(1, Ordering::Relaxed);
        let (shutdown, mut shutdown_rx) = watch::channel(false);

        #[cfg(windows)]
        let (endpoint, task) = {
            use tokio::net::windows::named_pipe::ServerOptions;

            let pipe_path = format!(r"\\.\pipe\minipod-doctor-{}-{seq}", std::process::id());
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
            let candidate = _temp.path().join("doctor.sock");
            let (socket_path, short_dir) = if candidate.to_str().is_some_and(|s| s.len() <= 103) {
                (candidate, None)
            } else {
                let dir = PathBuf::from(format!("/tmp/mp-doctor-{}-{seq}", std::process::id()));
                fs::create_dir_all(&dir).expect("create short Unix socket directory");
                (dir.join("d.sock"), Some(dir))
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
                            tokio::spawn(handle_connection(stream, Arc::clone(&state)));
                        }
                        Err(err) => panic!("mock Unix socket accept error: {err}"),
                    }
                }
            });
            (endpoint, task, cleanup)
        };

        ControlEndpoint::parse(&endpoint).expect("valid mock endpoint");
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

fn all_ok_report() -> Value {
    json!({
        "guest_arch": "x86_64",
        "qemu": { "status": "ok", "path": "C:/qemu/qemu-system-x86_64.exe", "detail": "QEMU version 10.1" },
        "qemu_img": { "status": "ok", "path": "C:/qemu/qemu-img.exe", "detail": "qemu-img version 10.1" },
        "bundle": { "status": "ok", "path": "C:/bundle", "detail": "Signature and bundle contents verified." },
        "accelerators": { "status": "ok", "candidates": ["whpx", "tcg"], "detail": "QEMU accelerator probe succeeded." }
    })
}

fn unknown_report() -> Value {
    json!({
        "guest_arch": null,
        "qemu": { "status": "unknown", "detail": "Daemon diagnostics are unavailable." },
        "qemu_img": { "status": "unknown", "detail": "Daemon diagnostics are unavailable." },
        "bundle": { "status": "unknown", "detail": "Daemon diagnostics are unavailable." },
        "accelerators": { "status": "unknown", "candidates": [], "detail": "Daemon diagnostics are unavailable." }
    })
}

fn offline_endpoint(temp: &TestTempDir) -> String {
    #[cfg(windows)]
    {
        let _ = temp;
        format!(r"\\.\pipe\minipod-doctor-offline-{}", std::process::id())
    }
    #[cfg(unix)]
    {
        format!("unix://{}", temp.path().join("offline.sock").display())
    }
}

fn doctor_args(endpoint: &str) -> Vec<String> {
    vec![
        "--endpoint".to_owned(),
        endpoint.to_owned(),
        "--json".to_owned(),
        "doctor".to_owned(),
    ]
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
async fn doctor_reports_local_daemon_connection_failure_with_unknown_checks() {
    let temp = TestTempDir::new("mp-doctor-offline");
    let output = run_cli(doctor_args(&offline_endpoint(&temp))).await;

    assert_eq!(output.status.code(), Some(1));
    let report = parse_json(&output);
    assert_eq!(report["daemon"]["status"], "error");
    assert!(report["daemon"]["detail"].as_str().is_some_and(|s| !s.is_empty()));
    assert_eq!(report["qemu"]["status"], "unknown");
    assert_eq!(report["qemu_img"]["status"], "unknown");
    assert_eq!(report["bundle"]["status"], "unknown");
    assert_eq!(report["accelerators"]["status"], "unknown");
    assert_eq!(report["smoke"]["status"], "not_run");
}

#[tokio::test]
async fn doctor_reports_all_basic_checks_from_daemon_and_keeps_smoke_unrun() {
    let temp = TestTempDir::new("mp-doctor-success");
    let state = Arc::new(Mutex::new(MockState {
        doctor_reply: DoctorReply::Report(all_ok_report()),
        requests: Vec::new(),
    }));
    let daemon = MockDaemon::start(&temp, Arc::clone(&state));

    let output = run_cli(doctor_args(&daemon.endpoint)).await;

    assert_eq!(output.status.code(), Some(0), "{}", String::from_utf8_lossy(&output.stderr));
    let report = parse_json(&output);
    assert_eq!(report["daemon"]["status"], "ok");
    assert_eq!(report["daemon"]["version"], "0.1.0-doctor-test");
    assert_eq!(report["guest_arch"], "x86_64");
    assert_eq!(report["qemu"]["status"], "ok");
    assert_eq!(report["qemu_img"]["status"], "ok");
    assert_eq!(report["bundle"]["status"], "ok");
    assert_eq!(report["accelerators"]["candidates"][0], "whpx");
    assert_eq!(report["smoke"]["status"], "not_run");
    assert_eq!(
        state.lock().expect("mock state lock").requests,
        ["status", "doctor"]
    );
    daemon.stop().await;
}

#[tokio::test]
async fn doctor_reports_unsupported_rpc_and_unknown_daemon_configuration() {
    let temp = TestTempDir::new("mp-doctor-old-daemon");
    let state = Arc::new(Mutex::new(MockState {
        doctor_reply: DoctorReply::Unsupported,
        requests: Vec::new(),
    }));
    let daemon = MockDaemon::start(&temp, Arc::clone(&state));

    let output = run_cli(doctor_args(&daemon.endpoint)).await;

    assert_eq!(output.status.code(), Some(1));
    let report = parse_json(&output);
    assert_eq!(report["daemon"]["status"], "ok");
    assert!(report["diagnostic_error"].as_str().is_some_and(|s| s.contains("Doctor")));
    assert_eq!(report["qemu"]["status"], "unknown");
    assert_eq!(report["qemu_img"]["status"], "unknown");
    assert_eq!(report["bundle"]["status"], "unknown");
    assert_eq!(report["accelerators"]["status"], "unknown");
    assert_eq!(report["smoke"]["status"], "not_run");
    daemon.stop().await;
}

#[tokio::test]
async fn doctor_returns_nonzero_if_any_check_failed_or_is_unknown() {
    for (name, report, expected_status) in [
        (
            "failed",
            json!({
                "guest_arch": "x86_64",
                "qemu": { "status": "error", "detail": "QEMU was blocked by policy." },
                "qemu_img": { "status": "ok", "path": "qemu-img.exe" },
                "bundle": { "status": "ok", "path": "C:/bundle" },
                "accelerators": { "status": "ok", "candidates": ["tcg"] }
            }),
            "error",
        ),
        ("unknown", unknown_report(), "unknown"),
    ] {
        let temp = TestTempDir::new(&format!("mp-doctor-{name}"));
        let state = Arc::new(Mutex::new(MockState {
            doctor_reply: DoctorReply::Report(report),
            requests: Vec::new(),
        }));
        let daemon = MockDaemon::start(&temp, Arc::clone(&state));

        let output = run_cli(doctor_args(&daemon.endpoint)).await;

        assert_eq!(output.status.code(), Some(1));
        let report = parse_json(&output);
        assert_eq!(report["qemu"]["status"], expected_status);
        assert_eq!(report["smoke"]["status"], "not_run");
        daemon.stop().await;
    }
}
