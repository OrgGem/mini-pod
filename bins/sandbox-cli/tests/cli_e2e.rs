#![forbid(unsafe_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use sandbox_client::{
    read_control_frame, write_control_frame, ControlEndpoint, ControlRequest, ControlResponse,
    DaemonStatusInfo, ExecWireEvent, SandboxSummaryInfo,
};
use sandbox_core::{
    CapabilityReport, DestroyStatus, EnforcementLevel, ExecExitStatus, NetworkPolicy, SandboxId,
    SandboxLease,
};
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
        let path =
            std::env::temp_dir().join(format!("{prefix}-{}-{seq}-{nanos}", std::process::id()));
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

#[derive(Default)]
struct MockDaemonState {
    active_sandboxes: usize,
    stored_tar: Option<Vec<u8>>,
    destroyed_ids: Vec<String>,
}

async fn handle_mock_connection<S>(mut stream: S, state: Arc<Mutex<MockDaemonState>>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let Ok(Some(raw)) = read_control_frame(&mut stream).await else {
        return;
    };
    let req = ControlRequest::from_json_bytes(&raw).expect("valid ControlRequest wire frame");

    if let ControlRequest::ExecStart { id, req } = req {
        assert_eq!(id.as_str(), "sb-cli-e2e-1");
        let started = ControlResponse::ExecStarted { stream_id: 1 }
            .to_json_bytes()
            .expect("serialize ExecStarted");
        write_control_frame(&mut stream, &started)
            .await
            .expect("write ExecStarted");

        let is_fail = req.argv.first().map(String::as_str) == Some("fail-cmd");
        let (stdout_bytes, stderr_bytes, exit_code) = if is_fail {
            (b"partial-out\n".to_vec(), b"fatal-err\n".to_vec(), Some(42))
        } else {
            let line = format!("{}\n", req.argv.get(1).map(String::as_str).unwrap_or(""));
            (line.into_bytes(), b"diag:ok\n".to_vec(), Some(0))
        };

        let events = [
            ExecWireEvent::Stdout { data: stdout_bytes },
            ExecWireEvent::Stderr { data: stderr_bytes },
            ExecWireEvent::Exit(ExecExitStatus {
                code: exit_code,
                timed_out: false,
                stdout_truncated: false,
                stderr_truncated: false,
            }),
        ];
        for evt in events {
            let bytes = evt.to_json_bytes().expect("serialize ExecWireEvent");
            write_control_frame(&mut stream, &bytes)
                .await
                .expect("write ExecWireEvent");
        }
        let _ = stream.shutdown().await;
        // Hold stream until client finishes draining Exit frame.
        let _ = tokio::time::timeout(Duration::from_secs(1), read_control_frame(&mut stream)).await;
        return;
    }

    let resp = {
        let mut st = state.lock().expect("mock state lock");
        match req {
            ControlRequest::Status => ControlResponse::Status(DaemonStatusInfo {
                active_sandboxes: st.active_sandboxes,
                warm_ready_vms: 1,
                effective_host_rss_mb: 256,
                reserved_host_storage_mb: 1024,
                version: "0.1.0-mock".to_owned(),
            }),
            ControlRequest::ListSandboxes => {
                let sandboxes = if st.active_sandboxes == 0 {
                    Vec::new()
                } else {
                    vec![SandboxSummaryInfo {
                        id: SandboxId::new("sb-cli-e2e-1"),
                        pid: 7777,
                        alive: true,
                        network: NetworkPolicy::Isolated,
                        remaining_ttl_ms: 295_000,
                        live_rss_bytes: Some(256 * 1024 * 1024),
                        reserved_rss_mb: 320,
                        host_rss_budget_mb: Some(512),
                        host_storage_budget_mb: 1024,
                        docker_endpoint: None,
                        allow_reaper_socket: false,
                    }]
                };
                ControlResponse::SandboxList { sandboxes }
            }
            ControlRequest::Spawn { spec } => {
                st.active_sandboxes += 1;
                ControlResponse::Spawned(SandboxLease {
                    id: SandboxId::new("sb-cli-e2e-1"),
                    ttl: spec.lease_ttl,
                    capabilities: CapabilityReport {
                        cpu_quota: EnforcementLevel::HardLimit,
                        host_rss: EnforcementLevel::BestEffort,
                        host_storage: EnforcementLevel::HardLimit,
                        egress_filter: EnforcementLevel::HardLimit,
                    },
                })
            }
            ControlRequest::CopyInTar {
                id,
                dst_guest,
                tar_bytes,
            } => {
                assert_eq!(id.as_str(), "sb-cli-e2e-1");
                assert_eq!(dst_guest, "/tmp/in");
                st.stored_tar = Some(tar_bytes);
                ControlResponse::Ack
            }
            ControlRequest::CopyOutTar { id, src_guest } => {
                assert_eq!(id.as_str(), "sb-cli-e2e-1");
                assert_eq!(src_guest, "/tmp/out");
                let tar_bytes = st
                    .stored_tar
                    .clone()
                    .expect("copy-in must populate stored_tar before copy-out");
                ControlResponse::CopyOutData { tar_bytes }
            }
            ControlRequest::EnableDockerCompat { id, .. } => {
                assert_eq!(id.as_str(), "sb-cli-e2e-1");
                ControlResponse::DockerCompatEndpoint {
                    uri: "http://127.0.0.1:41234".to_owned(),
                }
            }
            ControlRequest::Destroy { id } => {
                assert_eq!(id.as_str(), "sb-cli-e2e-1");
                st.active_sandboxes = st.active_sandboxes.saturating_sub(1);
                st.destroyed_ids.push(id.0);
                ControlResponse::Destroyed(DestroyStatus::AllResourcesCleaned)
            }
            other => panic!("unexpected mock CLI request: {other:?}"),
        }
    };

    let bytes = resp.to_json_bytes().expect("serialize ControlResponse");
    write_control_frame(&mut stream, &bytes)
        .await
        .expect("write ControlResponse");
    let _ = stream.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(1), read_control_frame(&mut stream)).await;
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

#[tokio::test]
async fn e2e_sandbox_cli_full_command_suite_and_tcp_rejection() {
    let temp = TestTempDir::new("mp-cli-e2e");
    let seq = TEST_SEQ.fetch_add(1, Ordering::Relaxed);
    let state = Arc::new(Mutex::new(MockDaemonState::default()));
    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

    #[cfg(windows)]
    let (endpoint_arg, server_task) = {
        use tokio::net::windows::named_pipe::ServerOptions;

        let pipe_path = format!(r"\\.\pipe\minipod-cli-e2e-{}-{seq}", std::process::id());
        let srv_pipe = pipe_path.clone();
        let srv_state = Arc::clone(&state);
        let mut server = ServerOptions::new()
            .first_pipe_instance(true)
            .create(&srv_pipe)
            .expect("bind mock Windows Named Pipe");

        let task = tokio::spawn(async move {
            loop {
                let res = tokio::select! {
                    biased;
                    _ = shutdown_rx.wait_for(|done| *done) => break,
                    res = server.connect() => res,
                };
                match res {
                    Ok(()) => {
                        let next = ServerOptions::new()
                            .create(&srv_pipe)
                            .expect("create next mock pipe instance");
                        let connected = std::mem::replace(&mut server, next);
                        let conn_state = Arc::clone(&srv_state);
                        tokio::spawn(handle_mock_connection(connected, conn_state));
                    }
                    Err(err) => panic!("mock pipe accept error: {err}"),
                }
            }
        });
        (pipe_path, task)
    };

    #[cfg(unix)]
    let (endpoint_arg, _unix_guard, server_task) = {
        let candidate = temp.path().join("c.sock");
        let (sock_path, short_dir) = if candidate.to_str().is_some_and(|s| s.len() <= 103) {
            (candidate, None)
        } else {
            let dir = PathBuf::from(format!("/tmp/mp-cli-{}-{seq}", std::process::id()));
            fs::create_dir_all(&dir).expect("create short socket dir");
            (dir.join("c.sock"), Some(dir))
        };
        let _ = fs::remove_file(&sock_path);
        let listener = tokio::net::UnixListener::bind(&sock_path).expect("bind mock Unix socket");
        let guard = UnixCleanupGuard {
            socket_path: sock_path.clone(),
            short_dir,
        };
        let ep_str = format!("unix://{}", sock_path.display());
        let srv_state = Arc::clone(&state);

        let task = tokio::spawn(async move {
            loop {
                let res = tokio::select! {
                    biased;
                    _ = shutdown_rx.wait_for(|done| *done) => break,
                    res = listener.accept() => res,
                };
                match res {
                    Ok((stream, _)) => {
                        let conn_state = Arc::clone(&srv_state);
                        tokio::spawn(handle_mock_connection(stream, conn_state));
                    }
                    Err(err) => panic!("mock unix accept error: {err}"),
                }
            }
        });
        (ep_str, guard, task)
    };

    ControlEndpoint::parse(&endpoint_arg).expect("valid test endpoint");

    // 1. status --json
    let out = run_cli(vec![
        "--endpoint".into(),
        endpoint_arg.clone(),
        "--json".into(),
        "status".into(),
    ])
    .await;
    assert!(
        out.status.success(),
        "status failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let status_json: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("parse status JSON");
    assert_eq!(status_json["active_sandboxes"].as_u64(), Some(0));
    assert_eq!(status_json["warm_ready_vms"].as_u64(), Some(1));
    assert_eq!(status_json["version"].as_str(), Some("0.1.0-mock"));

    // 2. spawn
    let out = run_cli(vec![
        "--endpoint".into(),
        endpoint_arg.clone(),
        "--json".into(),
        "spawn".into(),
    ])
    .await;
    assert!(
        out.status.success(),
        "spawn failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let spawn_json: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("parse spawn JSON");
    let sandbox_id = spawn_json["id"]
        .as_str()
        .expect("spawn id string")
        .to_owned();
    assert_eq!(sandbox_id, "sb-cli-e2e-1");

    // 2b. list (--json)
    let out = run_cli(vec![
        "--endpoint".into(),
        endpoint_arg.clone(),
        "--json".into(),
        "list".into(),
    ])
    .await;
    assert!(
        out.status.success(),
        "list failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let list_json: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("parse list JSON");
    assert_eq!(list_json["sandboxes"][0]["id"].as_str(), Some("sb-cli-e2e-1"));
    assert_eq!(list_json["sandboxes"][0]["pid"].as_u64(), Some(7777));

    // 3. exec (exit 0 + stdout + stderr)
    let out = run_cli(vec![
        "--endpoint".into(),
        endpoint_arg.clone(),
        "exec".into(),
        sandbox_id.clone(),
        "--".into(),
        "/bin/echo".into(),
        "hi".into(),
    ])
    .await;
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(String::from_utf8_lossy(&out.stdout), "hi\n");
    assert_eq!(String::from_utf8_lossy(&out.stderr), "diag:ok\n");

    // 4. exec (non-zero exit code 42 propagation + stdout + stderr)
    let out = run_cli(vec![
        "--endpoint".into(),
        endpoint_arg.clone(),
        "exec".into(),
        sandbox_id.clone(),
        "--".into(),
        "fail-cmd".into(),
        "arg".into(),
    ])
    .await;
    assert_eq!(
        out.status.code(),
        Some(42),
        "expected propagated exit code 42, got {:?} (stderr={})",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), "partial-out\n");
    assert_eq!(String::from_utf8_lossy(&out.stderr), "fatal-err\n");

    // 5. copy-in & copy-out
    let host_src = temp.path().join("src_ws");
    let host_dst = temp.path().join("dst_ws");
    fs::create_dir_all(host_src.join("nested")).expect("create src_ws/nested");
    fs::write(host_src.join("nested").join("payload.txt"), b"cli-copy-roundtrip\n")
        .expect("write payload.txt");

    let out = run_cli(vec![
        "--endpoint".into(),
        endpoint_arg.clone(),
        "copy-in".into(),
        sandbox_id.clone(),
        host_src.display().to_string(),
        "/tmp/in".into(),
    ])
    .await;
    assert!(
        out.status.success(),
        "copy-in failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let out = run_cli(vec![
        "--endpoint".into(),
        endpoint_arg.clone(),
        "copy-out".into(),
        sandbox_id.clone(),
        "/tmp/out".into(),
        host_dst.display().to_string(),
    ])
    .await;
    assert!(
        out.status.success(),
        "copy-out failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        fs::read(host_dst.join("nested").join("payload.txt")).expect("read copied-out file"),
        b"cli-copy-roundtrip\n"
    );

    // 6. docker-endpoint
    let out = run_cli(vec![
        "--endpoint".into(),
        endpoint_arg.clone(),
        "docker-endpoint".into(),
        sandbox_id.clone(),
    ])
    .await;
    assert!(
        out.status.success(),
        "docker-endpoint failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "http://127.0.0.1:41234"
    );

    // 7. destroy
    let out = run_cli(vec![
        "--endpoint".into(),
        endpoint_arg.clone(),
        "destroy".into(),
        sandbox_id.clone(),
    ])
    .await;
    assert!(
        out.status.success(),
        "destroy failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        String::from_utf8_lossy(&out.stdout).contains("AllResourcesCleaned"),
        "expected AllResourcesCleaned in destroy stdout: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert_eq!(
        state.lock().expect("mock state lock").destroyed_ids,
        vec!["sb-cli-e2e-1".to_owned()]
    );

    // 8. Plain TCP endpoint must fail non-zero cleanly without connecting.
    let bad_out = run_cli(vec![
        "--endpoint".into(),
        "tcp://127.0.0.1:2375".into(),
        "status".into(),
    ])
    .await;
    assert!(
        !bad_out.status.success(),
        "plain tcp:// endpoint must be rejected with non-zero exit status"
    );
    let bad_err = String::from_utf8_lossy(&bad_out.stderr);
    assert!(
        bad_err.contains("forbidden") || bad_err.contains("PolicyViolation"),
        "expected policy diagnostic on plain tcp rejection, got: {bad_err}"
    );

    // 9. Interactive TUI invoked without a TTY must fail fast cleanly without hanging.
    let non_tty_tui = run_cli(vec![
        "--endpoint".into(),
        endpoint_arg.clone(),
        "tui".into(),
    ])
    .await;
    assert!(
        !non_tty_tui.status.success(),
        "tui without TTY must exit non-zero"
    );
    assert!(
        String::from_utf8_lossy(&non_tty_tui.stderr).contains("interactive terminal"),
        "expected interactive terminal diagnostic, got: {}",
        String::from_utf8_lossy(&non_tty_tui.stderr)
    );

    let _ = shutdown_tx.send(true);
    server_task.await.expect("join mock server task");
}
