#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sandbox_client::{ControlEndpoint, SandboxClient};
use sandbox_core::{
    AccelerationPolicy, CapabilityReport, DestroyStatus, EnforcementLevel, ExecExitStatus,
    ExecRequest, ExecTarget, GuestArch, IsolationMode, NetworkPolicy, ResourceBudget, SandboxError,
    SandboxId, SandboxSpec,
};
use sandbox_image::{decode_hex_exact, install_bundle_atomic, BundleVerifier};
use sandbox_protocol::{StreamId, StreamTargetWire};
use sandbox_runtime::{
    AdmissionLimits, DiskOverlayPort, ExecOutputChunk, ExecStream, JournalStore,
    LocalRuntimeManager, OutputStreamKind, PreparedOverlay, RuntimeManagerConfig, TunnelStream,
    VmBootConfig, VmBootOutcome, VmRuntimePort, VmSessionPort, WarmPoolConfig,
};
use sandbox_vmm::{
    discover_qemu_binary_for_arch, discover_qemu_img_binary, kill_verified_orphan_process,
};
use sandboxd::server::{serve_endpoint_with_shutdown, DaemonState};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};

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

/// RAII guard ensuring spawned daemon/MCP child processes are always terminated and reaped,
/// preventing leaked `sandboxd` or `qemu` processes on assertion failures or panics.
struct ChildProcessGuard {
    label: String,
    child: Option<Child>,
}

impl ChildProcessGuard {
    fn new(label: impl Into<String>, child: Child) -> Self {
        Self {
            label: label.into(),
            child: Some(child),
        }
    }

    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        let Some(child) = self.child.as_mut() else {
            return Ok(None);
        };
        let status = child.try_wait()?;
        if status.is_some() {
            self.child = None;
        }
        Ok(status)
    }

    fn wait_timeout(&mut self, timeout: Duration) -> io::Result<Option<ExitStatus>> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.try_wait()? {
                return Ok(Some(status));
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    }

    fn kill_and_wait(&mut self) -> io::Result<ExitStatus> {
        let mut child = self
            .child
            .take()
            .ok_or_else(|| io::Error::other(format!("child '{}' already reaped", self.label)))?;
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        let _ = child.kill();
        child.wait()
    }

    fn child_mut(&mut self) -> Option<&mut Child> {
        self.child.as_mut()
    }
}

impl Drop for ChildProcessGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            if let Ok(None) = child.try_wait() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
}

struct EndpointHandle {
    endpoint: ControlEndpoint,
    #[cfg(windows)]
    pipe_name: String,
    #[cfg(unix)]
    socket_path: PathBuf,
    #[cfg(unix)]
    _socket_dir_guard: Option<ShortDirGuard>,
}

#[cfg(unix)]
struct ShortDirGuard(PathBuf);

#[cfg(unix)]
impl Drop for ShortDirGuard {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn allocate_unique_endpoint(base_dir: &Path, label: &str) -> EndpointHandle {
    let seq = TEST_SEQ.fetch_add(1, Ordering::Relaxed);
    #[cfg(windows)]
    {
        let _ = base_dir;
        let pipe_name = format!("minipod-p7-{label}-{}-{seq}", std::process::id());
        let endpoint = ControlEndpoint::NamedPipe(format!(r"\\.\pipe\{pipe_name}"));
        EndpointHandle {
            endpoint,
            pipe_name,
        }
    }
    #[cfg(unix)]
    {
        let candidate = base_dir.join(format!("s-{label}-{seq}")).join("c.sock");
        let (socket_path, guard) = if candidate
            .to_str()
            .is_some_and(|s| s.len() <= sandbox_vmm::MAX_UNIX_SOCKET_PATH_BYTES)
        {
            (candidate, None)
        } else {
            let short_dir = PathBuf::from(format!("/tmp/mp7-{}-{seq}", std::process::id()));
            let sock = short_dir.join("c.sock");
            (sock, Some(ShortDirGuard(short_dir)))
        };
        let endpoint = ControlEndpoint::UnixSocket(socket_path.clone());
        EndpointHandle {
            endpoint,
            socket_path,
            _socket_dir_guard: guard,
        }
    }
}

fn endpoint_cli_uri(endpoint: &ControlEndpoint) -> String {
    match endpoint {
        ControlEndpoint::NamedPipe(p) => p.clone(),
        ControlEndpoint::UnixSocket(p) => format!("unix://{}", p.display()),
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
        fs::write(&overlay_path, b"qcow2").expect("write stub overlay");
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

    async fn exec_stream(&self, _req: ExecRequest) -> Result<ExecStream, SandboxError> {
        let (stream, handle) = ExecStream::channel(StreamId(1));
        tokio::spawn(async move {
            let _ = handle
                .send_output(ExecOutputChunk {
                    stream: OutputStreamKind::Stdout,
                    data: b"stub-ok\n".to_vec(),
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
        let (client, _server) = TunnelStream::channel(StreamId(3));
        Ok(client)
    }

    async fn enable_egress_proxy(
        &self,
        _proxy_port: u16,
    ) -> Result<mpsc::Receiver<TunnelStream>, SandboxError> {
        let (_tx, rx) = mpsc::channel(2);
        Ok(rx)
    }

    async fn copy_in_tar(
        &self,
        _dst_guest: &str,
        tar_bytes: Vec<u8>,
        _max_bytes: u64,
    ) -> Result<u64, SandboxError> {
        Ok(tar_bytes.len() as u64)
    }

    async fn copy_out_tar(
        &self,
        _src_guest: &str,
        _max_bytes: u64,
    ) -> Result<Vec<u8>, SandboxError> {
        Ok(Vec::new())
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
}

#[async_trait::async_trait]
impl VmRuntimePort for StubVmRuntime {
    async fn boot_vm(&self, config: VmBootConfig) -> Result<VmBootOutcome, SandboxError> {
        let pid = self.next_pid.fetch_add(1, Ordering::Relaxed) as u32;
        let artifacts = vec![config.overlay.overlay_path.clone()];
        Ok(VmBootOutcome {
            session: Box::new(StubSession {
                pid,
                start_token: u64::from(pid),
                artifacts: artifacts.clone(),
                alive: AtomicBool::new(true),
            }),
            pid,
            start_token: u64::from(pid),
            artifact_paths: artifacts,
            hardware_accelerated: false,
            capabilities: CapabilityReport {
                cpu_quota: EnforcementLevel::BestEffort,
                host_rss: EnforcementLevel::BestEffort,
                host_storage: EnforcementLevel::BestEffort,
                egress_filter: EnforcementLevel::HardLimit,
            },
            egress_rx: None,
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

#[tokio::test]
async fn e2e_gate4_second_os_user_denied_access_to_control_ipc() {
    let temp = TestTempDir::new("mp-p7-gate4");
    let state_dir = temp.path().join("state");
    let ready_file = temp.path().join("ready.json");
    let ep_handle = allocate_unique_endpoint(temp.path(), "gate4");

    let rt_cfg = RuntimeManagerConfig {
        state_dir,
        sweep_interval: Duration::from_secs(30),
        graceful_shutdown_timeout: Duration::from_millis(50),
        max_copy_bytes: 4 * 1024 * 1024,
        max_copy_entries: 512,
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
                next_pid: AtomicU64::new(500),
            }),
        )
        .expect("construct mock runtime"),
    );

    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let state = Arc::new(DaemonState::with_shutdown(runtime, shutdown_tx.clone()));

    let server_ep = ep_handle.endpoint.clone();
    let server_ready = ready_file.clone();
    let server_state = Arc::clone(&state);
    let server_task = tokio::spawn(async move {
        serve_endpoint_with_shutdown(&server_ep, Some(&server_ready), server_state, shutdown_rx)
            .await
    });

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while !ready_file.is_file() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for gate4 ready_file '{}'",
            ready_file.display()
        );
        tokio::time::sleep(Duration::from_millis(15)).await;
    }

    let owner_client = SandboxClient::new(ep_handle.endpoint.clone());
    let owner_status = owner_client
        .status()
        .await
        .expect("owner must be permitted to query sandboxd status()");
    assert_eq!(owner_status.active_sandboxes, 0);

    #[cfg(windows)]
    {
        sandbox_vmm::verify_non_owner_named_pipe_denied(&ep_handle.pipe_name).expect(
            "NT kernel must deny ERROR_ACCESS_DENIED to non-owner restricted token on sandboxd Named Pipe",
        );
    }

    #[cfg(unix)]
    {
        use sandbox_vmm::CrossUserIpcCheck;

        let check = sandbox_vmm::verify_non_owner_unix_socket_denied(
            &ep_handle.socket_path,
            65534,
            65534,
        )
        .expect("Unix socket permissions & cross-user probe must succeed");

        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::MetadataExt;
            if let Ok(meta) = fs::metadata("/proc/self") {
                if meta.uid() == 0 {
                    assert_eq!(
                        check,
                        CrossUserIpcCheck::KernelRejectedAccess,
                        "root process on Linux (e.g. rust:alpine Docker) must enforce EACCES via fork+setuid(65534)"
                    );
                }
            }
        }
        match check {
            CrossUserIpcCheck::KernelRejectedAccess => {}
            CrossUserIpcCheck::SkippedUnprivilegedNoSetuid { reason } => {
                assert!(
                    !reason.contains("effective uid is 0"),
                    "unexpected skip while running as root: {reason}"
                );
                eprintln!("[gate4] non-root Unix host verified 0700/0600 ownership: {reason}");
            }
        }
    }

    // Confirm owner channel remains healthy after non-owner denial.
    let post_status = owner_client
        .status()
        .await
        .expect("owner control channel must remain operational after cross-user denial");
    assert_eq!(post_status.active_sandboxes, 0);

    let _ = shutdown_tx.send(true);
    server_task
        .await
        .expect("join gate4 listener task")
        .expect("gate4 listener clean shutdown");
}

struct RcFixtures {
    arch: GuestArch,
    src_bundle_dir: PathBuf,
    pub_key_path: PathBuf,
    public_key: [u8; 32],
    qemu_bin: PathBuf,
    qemu_img_bin: PathBuf,
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("resolve repository root")
        .to_path_buf()
}

fn require_qemu_tests() -> bool {
    match std::env::var("MINIPOD_REQUIRE_QEMU_TESTS") {
        Ok(val) => !val.trim().is_empty() && val.trim() != "0",
        Err(_) => false,
    }
}

fn discover_rc_fixtures(test_name: &str) -> Option<RcFixtures> {
    let arch = GuestArch::host_native().unwrap_or(GuestArch::X86_64);
    let root = repo_root();
    let src_bundle_dir = root.join(".cache").join("bundles-src").join(arch.as_str());
    let pub_key_path = root.join(".cache").join("keys").join("dev-bundle.pub");
    let qemu_bin = discover_qemu_binary_for_arch(arch, None).ok();
    let qemu_img_bin = discover_qemu_img_binary(None).ok();

    let mut missing = Vec::new();
    if !src_bundle_dir.join("manifest.v1").is_file() {
        missing.push(src_bundle_dir.join("manifest.v1").display().to_string());
    }
    if !pub_key_path.is_file() {
        missing.push(pub_key_path.display().to_string());
    }
    if qemu_bin.is_none() {
        missing.push("qemu-system binary".to_owned());
    }
    if qemu_img_bin.is_none() {
        missing.push("qemu-img binary".to_owned());
    }

    if !missing.is_empty() {
        let msg = format!(
            "skipping {test_name}: missing Phase 7 RC QEMU fixtures ({})",
            missing.join(", ")
        );
        if require_qemu_tests() {
            panic!("{msg} (MINIPOD_REQUIRE_QEMU_TESTS is enabled)");
        } else {
            eprintln!("[skip] {msg}");
            return None;
        }
    }

    let pub_hex = fs::read_to_string(&pub_key_path).expect("read dev-bundle.pub");
    let public_key = decode_hex_exact::<32>(pub_hex.trim()).expect("valid 32-byte Ed25519 pubkey");

    Some(RcFixtures {
        arch,
        src_bundle_dir,
        pub_key_path,
        public_key,
        qemu_bin: qemu_bin.expect("checked"),
        qemu_img_bin: qemu_img_bin.expect("checked"),
    })
}

fn warm_matching_spec() -> SandboxSpec {
    SandboxSpec {
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
        lease_ttl: Duration::from_secs(300),
    }
}

fn spawn_sandboxd_serve(
    fixtures: &RcFixtures,
    bundle_dir: &Path,
    state_dir: &Path,
    endpoint: &ControlEndpoint,
    ready_file: &Path,
    log_path: &Path,
) -> ChildProcessGuard {
    let log_out = File::create(log_path).expect("create sandboxd log file");
    let log_err = log_out.try_clone().expect("clone sandboxd log handle");
    let ep_uri = endpoint_cli_uri(endpoint);

    let child = Command::new(env!("CARGO_BIN_EXE_sandboxd"))
        .arg("serve")
        .arg("--bundle-dir")
        .arg(bundle_dir)
        .arg("--pub-key-file")
        .arg(&fixtures.pub_key_path)
        .arg("--state-dir")
        .arg(state_dir)
        .arg("--endpoint")
        .arg(&ep_uri)
        .arg("--ready-file")
        .arg(ready_file)
        .arg("--qemu-bin")
        .arg(&fixtures.qemu_bin)
        .arg("--qemu-img-bin")
        .arg(&fixtures.qemu_img_bin)
        .arg("--arch")
        .arg(fixtures.arch.as_str())
        .arg("--warm-pool-size")
        .arg("1")
        .stdin(Stdio::null())
        .stdout(Stdio::from(log_out))
        .stderr(Stdio::from(log_err))
        .spawn()
        .expect("spawn sandboxd serve process");

    ChildProcessGuard::new("sandboxd-serve", child)
}

async fn wait_for_daemon_ready(
    guard: &mut ChildProcessGuard,
    ready_file: &Path,
    log_path: &Path,
    timeout: Duration,
) {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if ready_file.is_file() {
            let raw = fs::read_to_string(ready_file).expect("read ready_file");
            if let Ok(val) = serde_json::from_str::<Value>(&raw) {
                if val["endpoint"].as_str().is_some() {
                    return;
                }
            }
        }
        if let Some(status) = guard.try_wait().expect("poll sandboxd child") {
            let log = fs::read_to_string(log_path).unwrap_or_default();
            panic!("sandboxd exited prematurely with {status} before ready_file:\n{log}");
        }
        if tokio::time::Instant::now() >= deadline {
            let log = fs::read_to_string(log_path).unwrap_or_default();
            panic!(
                "timed out after {}s waiting for sandboxd ready_file '{}'; log:\n{log}",
                timeout.as_secs(),
                ready_file.display()
            );
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn wait_for_daemon_status(
    client: &SandboxClient,
    expected_active: usize,
    expected_warm: usize,
    timeout: Duration,
) {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let status = client.status().await.expect("poll daemon status");
        if status.active_sandboxes == expected_active && status.warm_ready_vms == expected_warm {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for status active={expected_active}, warm={expected_warm}; last={status:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn http_get_ping(docker_uri: &str) -> String {
    let host_port = docker_uri
        .strip_prefix("http://")
        .expect("docker_uri must start with http://");
    let addr: SocketAddr = host_port
        .parse()
        .expect("docker_uri must bind loopback ip:port");
    assert!(addr.ip().is_loopback(), "docker_uri must bind loopback");

    let mut stream = TcpStream::connect(addr)
        .await
        .expect("connect to Docker compat loopback HTTP endpoint");
    stream
        .write_all(b"GET /_ping HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .expect("write /_ping request");
    let mut buf = Vec::new();
    stream
        .read_to_end(&mut buf)
        .await
        .expect("read /_ping response");
    String::from_utf8_lossy(&buf).into_owned()
}

fn run_mcp_stdio_session(ep_uri: &str, mcp_log_path: &Path) {
    let log_err = File::create(mcp_log_path).expect("create mcp stderr log");
    let mut mcp = ChildProcessGuard::new(
        "sandboxd-mcp",
        Command::new(env!("CARGO_BIN_EXE_sandboxd"))
            .arg("mcp")
            .arg("--connect")
            .arg(ep_uri)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::from(log_err))
            .spawn()
            .expect("spawn sandboxd mcp --connect"),
    );

    let child_ref = mcp.child_mut().expect("mcp child alive");
    let mut stdin = child_ref.stdin.take().expect("mcp stdin");
    let stdout = child_ref.stdout.take().expect("mcp stdout");
    let mut reader = BufReader::new(stdout);

    let mut read_rpc_line = |expected_id: u64| -> Value {
        let mut line = String::new();
        let n = reader.read_line(&mut line).expect("read MCP stdout line");
        assert!(n > 0, "MCP stdout closed prematurely before id={expected_id}");
        let val: Value = serde_json::from_str(line.trim()).unwrap_or_else(|err| {
            panic!("MCP stdout emitted non-JSON-RPC line ({err}): {line:?}");
        });
        assert_eq!(val["jsonrpc"].as_str(), Some("2.0"));
        assert_eq!(val["id"].as_u64(), Some(expected_id));
        val
    };

    let mut send_line = |msg: Value| {
        let text = serde_json::to_string(&msg).expect("serialize MCP JSON-RPC");
        writeln!(stdin, "{text}").expect("write MCP request line");
        stdin.flush().expect("flush MCP stdin");
    };

    // 1. initialize
    send_line(json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": { "name": "phase7-rc-e2e", "version": "0.1.0" }
        }
    }));
    let init_resp = read_rpc_line(1);
    assert_eq!(
        init_resp["result"]["protocolVersion"].as_str(),
        Some("2024-11-05")
    );
    assert_eq!(
        init_resp["result"]["serverInfo"]["name"].as_str(),
        Some("minipod-sandboxd")
    );

    // 2. notifications/initialized (must produce zero stdout lines)
    send_line(json!({
        "jsonrpc": "2.0",
        "method": "notifications/initialized"
    }));

    // 3. tools/list
    send_line(json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list"
    }));
    let list_resp = read_rpc_line(2);
    let tool_names: BTreeSet<String> = list_resp["result"]["tools"]
        .as_array()
        .expect("tools array")
        .iter()
        .filter_map(|t| t["name"].as_str().map(str::to_owned))
        .collect();
    for required in [
        "sandbox_status",
        "sandbox_spawn",
        "sandbox_exec",
        "sandbox_destroy",
    ] {
        assert!(
            tool_names.contains(required),
            "tools/list missing '{required}': {tool_names:?}"
        );
    }

    // 4. tools/call sandbox_status
    send_line(json!({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": { "name": "sandbox_status", "arguments": {} }
    }));
    let status_resp = read_rpc_line(3);
    assert_eq!(status_resp["result"]["isError"].as_bool(), Some(false));
    let status_payload: Value = serde_json::from_str(
        status_resp["result"]["content"][0]["text"]
            .as_str()
            .expect("status text"),
    )
    .expect("parse sandbox_status JSON");
    assert_eq!(status_payload["active_sandboxes"].as_u64(), Some(1));

    // 5. tools/call sandbox_spawn (matches daemon warm pool template)
    send_line(json!({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "sandbox_spawn",
            "arguments": {
                "network": "isolated",
                "vcpus": 1,
                "ram_mb": 256,
                "rss_mb": 512,
                "disk_mb": 512,
                "storage_mb": 1024,
                "ttl_secs": 120
            }
        }
    }));
    let spawn_resp = read_rpc_line(4);
    assert_eq!(spawn_resp["result"]["isError"].as_bool(), Some(false));
    let spawn_payload: Value = serde_json::from_str(
        spawn_resp["result"]["content"][0]["text"]
            .as_str()
            .expect("spawn text"),
    )
    .expect("parse sandbox_spawn JSON");
    let mcp_sandbox_id = spawn_payload["id"]
        .as_str()
        .expect("spawned sandbox id")
        .to_owned();

    // 6. tools/call sandbox_exec
    send_line(json!({
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {
            "name": "sandbox_exec",
            "arguments": {
                "sandbox_id": mcp_sandbox_id,
                "argv": ["/bin/echo", "mcp-rc-ok"]
            }
        }
    }));
    let exec_resp = read_rpc_line(5);
    assert_eq!(exec_resp["result"]["isError"].as_bool(), Some(false));
    let exec_payload: Value = serde_json::from_str(
        exec_resp["result"]["content"][0]["text"]
            .as_str()
            .expect("exec text"),
    )
    .expect("parse sandbox_exec JSON");
    assert_eq!(exec_payload["exit_code"].as_i64(), Some(0));
    assert_eq!(exec_payload["stdout"].as_str(), Some("mcp-rc-ok\n"));

    // 7. tools/call sandbox_destroy
    send_line(json!({
        "jsonrpc": "2.0",
        "id": 6,
        "method": "tools/call",
        "params": {
            "name": "sandbox_destroy",
            "arguments": {
                "sandbox_id": mcp_sandbox_id
            }
        }
    }));
    let destroy_resp = read_rpc_line(6);
    assert_eq!(destroy_resp["result"]["isError"].as_bool(), Some(false));
    let destroy_payload: Value = serde_json::from_str(
        destroy_resp["result"]["content"][0]["text"]
            .as_str()
            .expect("destroy text"),
    )
    .expect("parse sandbox_destroy JSON");
    assert_eq!(
        destroy_payload["status"].as_str(),
        Some("AllResourcesCleaned")
    );

    // 8. Close stdin (EOF) and verify pure EOF on stdout + clean exit.
    drop(stdin);
    let mut trailing = String::new();
    reader
        .read_to_string(&mut trailing)
        .expect("drain remaining MCP stdout");
    assert!(
        trailing.trim().is_empty(),
        "MCP stdout emitted unexpected trailing data after final response: {trailing:?}"
    );
    drop(reader);

    let exit = mcp
        .wait_timeout(Duration::from_secs(10))
        .expect("wait for sandboxd mcp exit")
        .expect("sandboxd mcp must exit cleanly on stdin EOF");
    assert!(
        exit.success(),
        "sandboxd mcp exited with non-zero status: {exit}"
    );
}

#[tokio::test]
async fn e2e_rc_daemon_sdk_cli_mcp_and_incident_recovery_drill() {
    let Some(fixtures) = discover_rc_fixtures("e2e_rc_daemon_sdk_cli_mcp_and_incident_recovery_drill")
    else {
        return;
    };

    // Declare `temp` BEFORE child process guards so Rust drops guards (killing processes) before removing dirs.
    let temp = TestTempDir::new("mp-p7-rc");
    let install_parent = temp.path().join("bundles");
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&install_parent).expect("create bundles parent");
    fs::create_dir_all(&state_dir).expect("create state dir");

    let verifier =
        BundleVerifier::with_public_key(fixtures.public_key).expect("verifier from dev pubkey");
    let installed = install_bundle_atomic(&fixtures.src_bundle_dir, &install_parent, &verifier)
        .expect("atomically install signed bundle");

    let ep1 = allocate_unique_endpoint(temp.path(), "rc1");
    let ready1 = temp.path().join("ready-1.json");
    let log1 = temp.path().join("daemon-1.log");

    let mut daemon1 = spawn_sandboxd_serve(
        &fixtures,
        installed.root_dir(),
        &state_dir,
        &ep1.endpoint,
        &ready1,
        &log1,
    );
    wait_for_daemon_ready(&mut daemon1, &ready1, &log1, Duration::from_secs(60)).await;

    let client1 = SandboxClient::new(ep1.endpoint.clone());

    // 1. SDK roundtrip on Daemon #1 (warm checkout -> copy_in -> exec -> copy_out -> renew -> docker compat).
    let status0 = client1.status().await.expect("initial daemon1 status");
    assert_eq!(status0.active_sandboxes, 0);
    assert_eq!(status0.warm_ready_vms, 1);

    let t_spawn = Instant::now();
    let lease1 = client1
        .spawn(warm_matching_spec())
        .await
        .expect("warm pool checkout spawn");
    let spawn_elapsed = t_spawn.elapsed();
    eprintln!(
        "[phase7-rc] warm checkout spawn took {:.2} ms (id={})",
        spawn_elapsed.as_secs_f64() * 1000.0,
        lease1.id
    );
    assert!(
        spawn_elapsed < Duration::from_secs(2),
        "warm pool checkout unexpectedly slow: {spawn_elapsed:?}"
    );
    assert_eq!(lease1.capabilities.egress_filter, EnforcementLevel::HardLimit);

    let host_in = temp.path().join("sdk_in");
    let host_out = temp.path().join("sdk_out");
    fs::create_dir_all(&host_in).expect("create sdk_in");
    fs::write(host_in.join("hello.txt"), b"mini-pod rc phase 7\n").expect("write hello.txt");

    client1
        .copy_in_path(&lease1.id, &host_in, "/tmp/rc_in")
        .await
        .expect("copy_in_path");

    let exec_out = client1
        .exec_collect(
            &lease1.id,
            ExecRequest {
                target: ExecTarget::Guest,
                argv: vec![
                    "/bin/sh".to_owned(),
                    "-c".to_owned(),
                    "mkdir -p /tmp/rc_out && tr a-z A-Z < /tmp/rc_in/hello.txt > /tmp/rc_out/upper.txt && cat /tmp/rc_out/upper.txt".to_owned(),
                ],
                env: BTreeMap::new(),
                cwd: None,
                user: None,
                deadline: Duration::from_secs(15),
                stdout_budget_bytes: 256 * 1024,
                stderr_budget_bytes: 64 * 1024,
            },
        )
        .await
        .expect("exec_collect transform");
    assert_eq!(exec_out.exit.code, Some(0));
    assert_eq!(exec_out.stdout, b"MINI-POD RC PHASE 7\n");

    let copied_bytes = client1
        .copy_out_to_path(&lease1.id, "/tmp/rc_out", &host_out)
        .await
        .expect("copy_out_to_path");
    assert_eq!(copied_bytes, b"MINI-POD RC PHASE 7\n".len() as u64);
    assert_eq!(
        fs::read(host_out.join("upper.txt")).expect("read upper.txt"),
        b"MINI-POD RC PHASE 7\n"
    );

    client1
        .renew_lease(&lease1.id, Duration::from_secs(360))
        .await
        .expect("renew_lease");

    let docker_uri = client1
        .enable_docker_compat(&lease1.id, false)
        .await
        .expect("enable_docker_compat");
    assert!(
        docker_uri.starts_with("http://127.0.0.1:"),
        "expected loopback Docker compat URI, got {docker_uri}"
    );
    let ping_resp = http_get_ping(&docker_uri).await;
    assert!(
        ping_resp.starts_with("HTTP/1.1 200 OK"),
        "expected /_ping 200 OK, got: {ping_resp:?}"
    );
    assert!(
        ping_resp.ends_with("OK") || ping_resp.contains("\r\n\r\nOK"),
        "expected OK body in /_ping response: {ping_resp:?}"
    );

    // 2. Wait for warm pool replenisher to restore warm_ready_vms == 1, then exercise MCP over stdio.
    wait_for_daemon_status(&client1, 1, 1, Duration::from_secs(30)).await;
    let ep1_uri = endpoint_cli_uri(&ep1.endpoint);
    let mcp_log = temp.path().join("mcp.log");
    tokio::task::spawn_blocking(move || run_mcp_stdio_session(&ep1_uri, &mcp_log))
        .await
        .expect("join MCP stdio test task");

    // 3. Incident Recovery Drill: ensure active + warm VMs exist on disk, then abruptly kill Daemon #1!
    wait_for_daemon_status(&client1, 1, 1, Duration::from_secs(30)).await;

    let journal_store = JournalStore::new(state_dir.join("journals")).expect("open journals dir");
    let crash1_records = journal_store.load_records().expect("load crash1 journals");
    assert!(
        crash1_records.len() >= 2,
        "expected at least 2 live VMs (1 active + 1 warm) in journals/, got: {crash1_records:?}"
    );
    let crash1_ids: Vec<SandboxId> = crash1_records
        .iter()
        .map(|r| r.sandbox_id.clone())
        .collect();
    let crash1_pids: Vec<(u32, u64)> = crash1_records
        .iter()
        .filter_map(|r| Some((r.pid?, r.start_token?)))
        .collect();
    assert_eq!(
        crash1_pids.len(),
        crash1_records.len(),
        "every live VM journal must record pid and start_token"
    );
    for id in &crash1_ids {
        let overlay = state_dir
            .join("sandboxes")
            .join(id.as_str())
            .join("overlay.qcow2");
        assert!(
            overlay.is_file(),
            "expected overlay.qcow2 for '{id}' at '{}'",
            overlay.display()
        );
    }

    let _ = daemon1.kill_and_wait().expect("abruptly kill daemon1");

    // Confirm stale .journal and .qcow2 artifacts remain on disk immediately after abrupt crash.
    for id in &crash1_ids {
        assert!(
            journal_store
                .load_record(id)
                .expect("reload stale journal")
                .is_some(),
            "stale .journal for '{id}' should remain on disk after abrupt crash"
        );
        let overlay = state_dir
            .join("sandboxes")
            .join(id.as_str())
            .join("overlay.qcow2");
        assert!(
            overlay.is_file(),
            "stale overlay.qcow2 for '{id}' should remain on disk after abrupt crash"
        );
    }

    // 4. Start Daemon #2 on the SAME --state-dir -> startup reconciler reaps crash #1 leftovers!
    let ep2 = allocate_unique_endpoint(temp.path(), "rc2");
    let ready2 = temp.path().join("ready-2.json");
    let log2 = temp.path().join("daemon-2.log");
    let mut daemon2 = spawn_sandboxd_serve(
        &fixtures,
        installed.root_dir(),
        &state_dir,
        &ep2.endpoint,
        &ready2,
        &log2,
    );
    wait_for_daemon_ready(&mut daemon2, &ready2, &log2, Duration::from_secs(60)).await;

    let client2 = SandboxClient::new(ep2.endpoint.clone());
    let status2 = client2.status().await.expect("daemon2 post-recovery status");
    assert_eq!(
        status2.active_sandboxes, 0,
        "recovered daemon2 must report 0 active sandboxes"
    );
    assert_eq!(
        status2.warm_ready_vms, 1,
        "recovered daemon2 must have 1 fresh warm VM"
    );

    for old_id in &crash1_ids {
        assert!(
            journal_store
                .load_record(old_id)
                .expect("check old journal removed")
                .is_none(),
            "startup reconciler left behind stale journal for '{old_id}'"
        );
        let old_dir = state_dir.join("sandboxes").join(old_id.as_str());
        assert!(
            !old_dir.exists(),
            "startup reconciler left behind stale sandbox dir '{}'",
            old_dir.display()
        );
    }
    for &(pid, token) in &crash1_pids {
        let killed = kill_verified_orphan_process(pid, token).expect("verify old pid dead");
        assert!(
            !killed,
            "QEMU process pid={pid} from crash #1 survived startup reconciliation"
        );
    }

    // 5. Post-recovery end-to-end spawn + exec + destroy on Daemon #2.
    let lease2 = client2
        .spawn(warm_matching_spec())
        .await
        .expect("post-recovery spawn");
    let out2 = client2
        .exec_collect(
            &lease2.id,
            ExecRequest {
                target: ExecTarget::Guest,
                argv: vec!["/bin/echo".to_owned(), "post-recovery-ok".to_owned()],
                env: BTreeMap::new(),
                cwd: None,
                user: None,
                deadline: Duration::from_secs(10),
                stdout_budget_bytes: 64 * 1024,
                stderr_budget_bytes: 64 * 1024,
            },
        )
        .await
        .expect("post-recovery exec");
    assert_eq!(out2.exit.code, Some(0));
    assert_eq!(out2.stdout, b"post-recovery-ok\n");

    let destroyed2 = client2
        .destroy(&lease2.id)
        .await
        .expect("post-recovery destroy");
    assert_eq!(destroyed2, DestroyStatus::AllResourcesCleaned);

    // Wait for daemon2's warm pool replenisher to finish stabilizing so we can capture its PIDs before graceful shutdown.
    wait_for_daemon_status(&client2, 0, 1, Duration::from_secs(30)).await;
    let daemon2_records = journal_store.load_records().expect("load daemon2 journals");
    let daemon2_pids: Vec<(u32, u64)> = daemon2_records
        .iter()
        .filter_map(|r| Some((r.pid?, r.start_token?)))
        .collect();

    // 6. Terminate Daemon #2 cleanly and verify 0 orphan processes and 0 leftover sandbox/journal files.
    client2
        .shutdown()
        .await
        .expect("request graceful shutdown of daemon2");
    let exit2 = daemon2
        .wait_timeout(Duration::from_secs(30))
        .expect("wait for daemon2 shutdown")
        .expect("daemon2 did not exit within 30s after graceful shutdown");
    assert!(
        exit2.success(),
        "daemon2 exited with non-zero status: {exit2}"
    );

    let remaining_journals = journal_store
        .load_records()
        .expect("check journals after clean shutdown");
    assert!(
        remaining_journals.is_empty(),
        "expected 0 leftover journals after clean daemon2 shutdown, found: {remaining_journals:?}"
    );
    let remaining_sandbox_dirs: Vec<_> = fs::read_dir(state_dir.join("sandboxes"))
        .expect("read sandboxes dir")
        .collect::<Result<Vec<_>, _>>()
        .expect("collect sandboxes entries");
    assert!(
        remaining_sandbox_dirs.is_empty(),
        "expected 0 leftover sandbox dirs after clean daemon2 shutdown, found {} entries",
        remaining_sandbox_dirs.len()
    );
    for &(pid, token) in &daemon2_pids {
        let alive = kill_verified_orphan_process(pid, token).expect("verify daemon2 qemu dead");
        assert!(
            !alive,
            "daemon2 QEMU process pid={pid} lingered after graceful shutdown"
        );
    }

    #[cfg(unix)]
    assert!(
        !ep2.socket_path.exists(),
        "daemon2 Unix socket '{}' remained after clean shutdown",
        ep2.socket_path.display()
    );
}
