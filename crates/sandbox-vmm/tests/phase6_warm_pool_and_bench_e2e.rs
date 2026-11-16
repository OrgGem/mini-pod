#![forbid(unsafe_code)]

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bollard::container::{
    Config, CreateContainerOptions, RemoveContainerOptions, StartContainerOptions,
    StopContainerOptions,
};
use bollard::image::ImportImageOptions;
use bollard::models::PortBinding;
use bollard::Docker;
use bytes::Bytes;
use futures_util::StreamExt;
use sandbox_core::{
    AccelerationPolicy, DestroyStatus, EgressRule, ExecRequest, ExecTarget, GuestArch,
    IsolationMode, NetworkPolicy, ResourceBudget, SandboxError, SandboxId, SandboxSpec,
};
use sandbox_docker_compat::{DockerCompatPolicy, DockerCompatServer};
use sandbox_image::{
    decode_hex_exact, install_bundle_atomic, BundleOverlayStore, BundleVerifier, InstalledBundle,
};
use sandbox_runtime::benchmark::{
    DEFAULT_SNAPSHOT_DEFERRED_REASON, DEFAULT_WARM_POOL_TARGET_MS,
};
use sandbox_runtime::{
    is_forbidden_ip, AdmissionLimits, AdmissionUsage, BenchmarkMetricStatus, BoxedUpstreamStream,
    CollectedExecOutput, HostDnsResolver, JournalLifecycleState, JournalStore, LocalRuntimeManager,
    PlatformBenchmarkReport, RuntimeManager, RuntimeManagerConfig, SandboxTunnelPort,
    UpstreamDialer, WarmPoolConfig,
};
use sandbox_vmm::{
    discover_qemu_binary_for_arch, discover_qemu_img_binary, kill_verified_orphan_process,
    probe_available_accelerators_for_arch, QemuDriverConfig, QemuVmDriver,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(1);

struct TestTempDir {
    path: PathBuf,
}

impl TestTempDir {
    fn new(prefix: &str) -> Self {
        let seq = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
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

struct Phase6Fixtures {
    arch: GuestArch,
    src_bundle_dir: PathBuf,
    public_key: [u8; 32],
    qemu_bin: PathBuf,
    qemu_img_bin: PathBuf,
    echo_image_tar: PathBuf,
}

struct Phase6Harness {
    _temp: TestTempDir,
    _installed: InstalledBundle,
    state_dir: PathBuf,
    manager: Arc<LocalRuntimeManager>,
}

struct MockTcpServer {
    addr: SocketAddr,
    task: JoinHandle<()>,
}

impl MockTcpServer {
    fn port(&self) -> u16 {
        self.addr.port()
    }
}

impl Drop for MockTcpServer {
    fn drop(&mut self) {
        self.task.abort();
    }
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

fn discover_phase6_fixtures(test_name: &str, require_echo_image: bool) -> Option<Phase6Fixtures> {
    let arch = GuestArch::host_native().unwrap_or(GuestArch::X86_64);
    let root = repo_root();
    let src_bundle_dir = root.join(".cache").join("bundles-src").join(arch.as_str());
    let pub_key_path = root.join(".cache").join("keys").join("dev-bundle.pub");
    let echo_image_tar = root.join(".cache").join("test-images").join("echo-http.tar");

    let qemu_bin = discover_qemu_binary_for_arch(arch, None).ok();
    let qemu_img_bin = discover_qemu_img_binary(None).ok();

    let mut missing = Vec::new();
    if !src_bundle_dir.join("manifest.v1").is_file() {
        missing.push(src_bundle_dir.join("manifest.v1").display().to_string());
    }
    if !pub_key_path.is_file() {
        missing.push(pub_key_path.display().to_string());
    }
    if require_echo_image && !echo_image_tar.is_file() {
        missing.push(echo_image_tar.display().to_string());
    }
    if qemu_bin.is_none() {
        missing.push("qemu-system binary".to_owned());
    }
    if qemu_img_bin.is_none() {
        missing.push("qemu-img binary".to_owned());
    }

    if !missing.is_empty() {
        let msg = format!(
            "skipping {test_name}: missing Phase 6 E2E fixtures ({})",
            missing.join(", ")
        );
        if require_qemu_tests() {
            panic!("{msg} (MINIPOD_REQUIRE_QEMU_TESTS is enabled)");
        } else {
            eprintln!("[skip] {msg}");
            return None;
        }
    }

    let pub_key_hex = fs::read_to_string(&pub_key_path).expect("read dev-bundle.pub");
    let public_key = decode_hex_exact::<32>(pub_key_hex.trim()).expect("valid 32-byte dev pub key");
    Some(Phase6Fixtures {
        arch,
        src_bundle_dir,
        public_key,
        qemu_bin: qemu_bin.expect("checked"),
        qemu_img_bin: qemu_img_bin.expect("checked"),
        echo_image_tar,
    })
}

fn build_phase6_runtime(
    fixtures: &Phase6Fixtures,
    prefix: &str,
    admission: AdmissionLimits,
    warm_pool: WarmPoolConfig,
    dns_resolver: Option<Arc<dyn HostDnsResolver>>,
    dialer: Option<Arc<dyn UpstreamDialer>>,
) -> Phase6Harness {
    let temp = TestTempDir::new(prefix);
    let install_parent = temp.path().join("bundles");
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&install_parent).expect("create bundle install parent");
    fs::create_dir_all(&state_dir).expect("create runtime state dir");

    let verifier =
        BundleVerifier::with_public_key(fixtures.public_key).expect("verifier from pubkey");
    let installed = install_bundle_atomic(&fixtures.src_bundle_dir, &install_parent, &verifier)
        .expect("install signed bundle atomically");
    let overlay = BundleOverlayStore::new(
        installed.root_dir().to_path_buf(),
        verifier,
        &fixtures.qemu_img_bin,
    )
    .expect("build BundleOverlayStore");

    let driver = QemuVmDriver::new(QemuDriverConfig {
        arch: fixtures.arch,
        qemu_bin: Some(fixtures.qemu_bin.clone()),
        boot_timeout: Duration::from_secs(60),
        io_timeout: Duration::from_secs(60),
        runtime_parent_dir: None,
    })
    .expect("build QemuVmDriver");

    let config = RuntimeManagerConfig {
        state_dir: state_dir.clone(),
        sweep_interval: Duration::from_millis(500),
        graceful_shutdown_timeout: Duration::from_secs(3),
        max_copy_bytes: 16 * 1024 * 1024,
        max_copy_entries: 4096,
        cleanup_max_attempts: 8,
        cleanup_initial_delay: Duration::from_millis(50),
        admission,
        warm_pool,
    };

    let manager = match (dns_resolver, dialer) {
        (Some(dns), Some(d)) => LocalRuntimeManager::with_egress_hooks(
            config,
            Arc::new(overlay),
            Arc::new(driver),
            dns,
            d,
        ),
        _ => LocalRuntimeManager::new(config, Arc::new(overlay), Arc::new(driver)),
    }
    .expect("build LocalRuntimeManager");

    Phase6Harness {
        _temp: temp,
        _installed: installed,
        state_dir,
        manager: Arc::new(manager),
    }
}

fn small_vm_budget() -> ResourceBudget {
    ResourceBudget {
        guest_vcpus: 1,
        host_cpu_quota_Millicores: None,
        guest_ram_mb: 256,
        host_rss_budget_mb: Some(512),
        virtual_disk_mb: 256,
        host_storage_budget_mb: 512,
    }
}

fn isolated_small_spec(lease_ttl: Duration) -> SandboxSpec {
    SandboxSpec {
        isolation: IsolationMode::VmRequired,
        acceleration: AccelerationPolicy::Preferred,
        network: NetworkPolicy::Isolated,
        budget: small_vm_budget(),
        lease_ttl,
    }
}

fn container_vm_spec(lease_ttl: Duration) -> SandboxSpec {
    SandboxSpec {
        isolation: IsolationMode::VmRequired,
        acceleration: AccelerationPolicy::Preferred,
        network: NetworkPolicy::Isolated,
        budget: ResourceBudget {
            guest_vcpus: 2,
            host_cpu_quota_Millicores: None,
            guest_ram_mb: 768,
            host_rss_budget_mb: Some(1024),
            virtual_disk_mb: 512,
            host_storage_budget_mb: 1024,
        },
        lease_ttl,
    }
}

async fn spawn_canary_http_server(hits: Arc<AtomicUsize>) -> MockTcpServer {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind canary server");
    let addr = listener.local_addr().expect("canary local_addr");
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            let hits = Arc::clone(&hits);
            tokio::spawn(async move {
                hits.fetch_add(1, Ordering::SeqCst);
                let mut buf = [0u8; 2048];
                let _ = stream.read(&mut buf).await;
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nSECRET",
                    )
                    .await;
                let _ = stream.shutdown().await;
            });
        }
    });
    MockTcpServer { addr, task }
}

async fn spawn_public_http_fixture() -> MockTcpServer {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind public HTTP fixture");
    let addr = listener.local_addr().expect("public HTTP local_addr");
    let task = tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut req = Vec::with_capacity(512);
                let mut buf = [0u8; 1024];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            req.extend_from_slice(&buf[..n]);
                            if req.windows(4).any(|w| w == b"\r\n\r\n") || req.len() >= 8192 {
                                break;
                            }
                        }
                    }
                }
                let head = String::from_utf8_lossy(&req);
                let target = head
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or("/");
                let resp = match target {
                    "/ok" => "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 14\r\nConnection: close\r\n\r\npublic-ok-body",
                    _ => "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\nConnection: close\r\n\r\nnot-found",
                };
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.flush().await;
                let _ = stream.shutdown().await;
            });
        }
    });
    MockTcpServer { addr, task }
}

struct ControlledDnsResolver;

#[async_trait::async_trait]
impl HostDnsResolver for ControlledDnsResolver {
    async fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        let lower = host.to_ascii_lowercase();
        let public_ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        match lower.as_str() {
            "allowed.test" => Ok(vec![SocketAddr::new(public_ip, port)]),
            _ => Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("unexpected DNS lookup for '{lower}'"),
            )),
        }
    }
}

struct ControlledUpstreamDialer {
    http_port: u16,
    forbidden_dials: AtomicUsize,
}

impl ControlledUpstreamDialer {
    fn new(http_port: u16) -> Arc<Self> {
        Arc::new(Self {
            http_port,
            forbidden_dials: AtomicUsize::new(0),
        })
    }

    fn forbidden_dial_count(&self) -> usize {
        self.forbidden_dials.load(Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl UpstreamDialer for ControlledUpstreamDialer {
    async fn connect(&self, addr: SocketAddr) -> io::Result<BoxedUpstreamStream> {
        if is_forbidden_ip(addr.ip()) {
            self.forbidden_dials.fetch_add(1, Ordering::SeqCst);
            panic!("SECURITY INVARIANT VIOLATED: UpstreamDialer::connect called with forbidden {addr}");
        }
        let public_ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        if addr == SocketAddr::new(public_ip, 80) {
            let stream = TcpStream::connect(("127.0.0.1", self.http_port)).await?;
            let _ = stream.set_nodelay(true);
            return Ok(Box::pin(stream));
        }
        Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!("unexpected upstream SocketAddr {addr}"),
        ))
    }
}

async fn run_guest_sh(
    mgr: &LocalRuntimeManager,
    id: &SandboxId,
    script: &str,
) -> Result<CollectedExecOutput, SandboxError> {
    let stream = mgr
        .exec_stream(
            id,
            ExecRequest {
                target: ExecTarget::Guest,
                argv: vec!["/bin/sh".to_owned(), "-c".to_owned(), script.to_owned()],
                env: BTreeMap::new(),
                cwd: None,
                user: None,
                deadline: Duration::from_secs(15),
                stdout_budget_bytes: 512 * 1024,
                stderr_budget_bytes: 256 * 1024,
            },
        )
        .await?;
    stream.collect().await
}

async fn run_guest_echo_ok(mgr: &LocalRuntimeManager, id: &SandboxId) -> CollectedExecOutput {
    let stream = mgr
        .exec_stream(
            id,
            ExecRequest {
                target: ExecTarget::Guest,
                argv: vec!["/bin/echo".to_owned(), "ok".to_owned()],
                env: BTreeMap::new(),
                cwd: None,
                user: None,
                deadline: Duration::from_secs(15),
                stdout_budget_bytes: 64 * 1024,
                stderr_budget_bytes: 64 * 1024,
            },
        )
        .await
        .expect("exec_stream /bin/echo ok");
    stream.collect().await.expect("collect /bin/echo ok output")
}

async fn guest_proxy_http_get(
    mgr: &LocalRuntimeManager,
    id: &SandboxId,
    url: &str,
    host_header: &str,
) -> String {
    let payload = format!("GET {url} HTTP/1.1\\r\\nHost: {host_header}\\r\\nConnection: close\\r\\n\\r\\n");
    let script = format!("printf '{payload}' | /bin/busybox nc 127.0.0.1 3128");
    let out = run_guest_sh(mgr, id, &script)
        .await
        .expect("exec raw HTTP proxy GET inside guest");
    assert_eq!(
        out.exit.code,
        Some(0),
        "raw HTTP proxy script failed for {url}: stderr={:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn load_journals(state_dir: &Path) -> Vec<sandbox_runtime::JournalRecord> {
    JournalStore::new(state_dir.join("journals"))
        .expect("open JournalStore")
        .load_records()
        .expect("load journal records")
}

fn load_journal_pid(state_dir: &Path, id: &SandboxId) -> (u32, u64) {
    let rec = JournalStore::new(state_dir.join("journals"))
        .expect("open JournalStore")
        .load_record(id)
        .expect("load journal record")
        .unwrap_or_else(|| panic!("expected journal record for {id}"));
    assert_eq!(
        rec.state,
        JournalLifecycleState::Active,
        "expected Active journal state for {id}, got {:?}",
        rec.state
    );
    (
        rec.pid.expect("journal pid must be present"),
        rec.start_token
            .expect("journal start_token must be present"),
    )
}

fn assert_rss_within_cap(mgr: &LocalRuntimeManager, active_ids: &[&SandboxId], cap_mb: u64) {
    let usage = mgr.current_admission_usage();
    assert!(
        usage.effective_host_rss_mb <= cap_mb,
        "effective_host_rss_mb ({}) exceeded cap ({cap_mb} MiB)",
        usage.effective_host_rss_mb
    );
    let mut sum_bytes = 0u64;
    for id in active_ids {
        let rss = mgr
            .sandbox_current_rss_bytes(id)
            .unwrap_or_else(|| panic!("expected live RSS bytes for {id}"));
        assert!(rss > 0, "expected nonzero live RSS for {id}");
        sum_bytes = sum_bytes.saturating_add(rss);
    }
    assert!(
        sum_bytes <= cap_mb * 1024 * 1024,
        "sum of live sandbox RSS ({sum_bytes} bytes) exceeded {cap_mb} MiB cap"
    );
}

fn assert_pids_not_running(pids: &[(u32, u64)], context: &str) {
    for &(pid, start_token) in pids {
        let still_alive = kill_verified_orphan_process(pid, start_token)
            .expect("verify QEMU PID is no longer running");
        assert!(
            !still_alive,
            "{context}: QEMU PID {pid} (start_token={start_token}) was still running"
        );
    }
}

async fn import_tar_image(docker: &Docker, tar_path: &Path) {
    let raw = fs::read(tar_path).expect("read image tarball");
    let mut stream = docker.import_image(
        ImportImageOptions { quiet: false },
        Bytes::from(raw),
        None,
    );
    while let Some(item) = stream.next().await {
        let info = item.expect("import_image stream chunk");
        if let Some(err) = info.error {
            panic!("import_image failed for {}: {err}", tar_path.display());
        }
    }
}

async fn create_and_start_echo_http(docker: &Docker) -> (String, u16) {
    let exposed_ports = HashMap::from([("8080/tcp".to_owned(), HashMap::new())]);
    let port_bindings = HashMap::from([(
        "8080/tcp".to_owned(),
        Some(vec![PortBinding {
            host_ip: Some("127.0.0.1".to_owned()),
            host_port: Some(String::new()),
        }]),
    )]);
    let created = docker
        .create_container(
            None::<CreateContainerOptions<String>>,
            Config {
                image: Some("minipod-e2e/echo-http:1.0".to_owned()),
                exposed_ports: Some(exposed_ports),
                host_config: Some(bollard::models::HostConfig {
                    port_bindings: Some(port_bindings),
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .await
        .expect("create echo-http container");
    let cid = created.id;

    docker
        .start_container(&cid, None::<StartContainerOptions<String>>)
        .await
        .expect("start echo-http container");

    let inspected = docker
        .inspect_container(&cid, None)
        .await
        .expect("inspect running echo-http container");
    let bindings = inspected
        .network_settings
        .as_ref()
        .and_then(|ns| ns.ports.as_ref())
        .and_then(|ports| ports.get("8080/tcp"))
        .and_then(|v| v.as_ref())
        .expect("8080/tcp port mapping in NetworkSettings.Ports");
    assert_eq!(bindings[0].host_ip.as_deref(), Some("127.0.0.1"));
    let host_port: u16 = bindings[0]
        .host_port
        .as_deref()
        .expect("host_port string")
        .parse()
        .expect("numeric host_port");
    assert_ne!(host_port, 0);
    (cid, host_port)
}

async fn http_get_loopback(port: u16) -> String {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        match TcpStream::connect(("127.0.0.1", port)).await {
            Ok(mut stream) => {
                stream
                    .write_all(
                        b"GET /hello HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
                    )
                    .await
                    .expect("write HTTP request");
                let mut buf = Vec::new();
                stream
                    .read_to_end(&mut buf)
                    .await
                    .expect("read HTTP response");
                if !buf.is_empty() {
                    return String::from_utf8_lossy(&buf).into_owned();
                }
            }
            Err(_) if tokio::time::Instant::now() < deadline => {}
            Err(err) => panic!("failed connecting to forwarded port 127.0.0.1:{port}: {err}"),
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("timed out waiting for HTTP 200 on forwarded port 127.0.0.1:{port}");
        }
        tokio::time::sleep(Duration::from_millis(40)).await;
    }
}

async fn assert_loopback_port_closed(port: u16) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        match TcpStream::connect(("127.0.0.1", port)).await {
            Err(_) => return,
            Ok(mut stream) => {
                let mut probe = [0u8; 16];
                if matches!(stream.read(&mut probe).await, Ok(0) | Err(_)) {
                    return;
                }
            }
        }
        if tokio::time::Instant::now() >= deadline {
            panic!("forwarded port 127.0.0.1:{port} remained open after container stop");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn stop_and_remove_container(docker: &Docker, cid: &str, host_port: u16) {
    docker
        .stop_container(cid, Some(StopContainerOptions { t: 2 }))
        .await
        .expect("stop container");
    assert_loopback_port_closed(host_port).await;
    docker
        .remove_container(
            cid,
            Some(RemoveContainerOptions {
                force: true,
                v: true,
                ..Default::default()
            }),
        )
        .await
        .expect("remove container");
}

async fn detect_active_accelerator(
    fixtures: &Phase6Fixtures,
    mgr: &LocalRuntimeManager,
    state_dir: &Path,
    id: &SandboxId,
) -> String {
    let stderr_path = state_dir
        .join("sandboxes")
        .join(id.as_str())
        .join("qemu-stderr.log");
    let stderr_text = fs::read_to_string(&stderr_path).unwrap_or_default();
    let lower_err = stderr_text.to_ascii_lowercase();
    if lower_err.contains("windows hypervisor platform accelerator is operational") {
        return "whpx".to_owned();
    }

    let guest_probe = run_guest_sh(
        mgr,
        id,
        "if grep -qw hypervisor /proc/cpuinfo 2>/dev/null; then echo hw; else echo tcg; fi",
    )
    .await
    .ok()
    .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
    .unwrap_or_default();

    if guest_probe == "hw" {
        let available = probe_available_accelerators_for_arch(&fixtures.qemu_bin, fixtures.arch)
            .unwrap_or_default();
        if let Some(hw) = available.into_iter().find(|a| a.is_hardware()) {
            return hw.as_qemu_arg().to_owned();
        }
    }
    "tcg".to_owned()
}

fn write_file_atomic(path: &Path, content: &str) {
    let parent = path.parent().expect("report path must have parent directory");
    fs::create_dir_all(parent).expect("create benchmark report directory");
    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .expect("valid UTF-8 benchmark report filename");
    let tmp_path = parent.join(format!(".{file_name}.tmp.{}", std::process::id()));
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&tmp_path)
            .expect("open temporary benchmark report file");
        file.write_all(content.as_bytes())
            .expect("write temporary benchmark report file");
        file.sync_all().expect("sync temporary benchmark report file");
    }
    fs::rename(&tmp_path, path).expect("atomically replace benchmark report file");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_warm_pool_overload_backpressure_dirty_disposal_and_rss_cap() {
    let Some(fixtures) = discover_phase6_fixtures(
        "e2e_warm_pool_overload_backpressure_dirty_disposal_and_rss_cap",
        false,
    ) else {
        return;
    };

    let canary_hits = Arc::new(AtomicUsize::new(0));
    let canary_srv = spawn_canary_http_server(Arc::clone(&canary_hits)).await;
    let canary_port = canary_srv.port();

    let public_http = spawn_public_http_fixture().await;
    let dns = Arc::new(ControlledDnsResolver);
    let dialer = ControlledUpstreamDialer::new(public_http.port());

    let template_spec = isolated_small_spec(Duration::from_secs(180));
    let warm_pool = WarmPoolConfig {
        target_size: 2,
        template_spec: Some(template_spec.clone()),
        max_idle_age: Duration::from_secs(300),
        replenish_retry_delay: Duration::from_millis(100),
    };
    let admission = AdmissionLimits {
        max_concurrent_sandboxes: Some(2),
        max_total_host_rss_mb: Some(1150),
        max_total_host_storage_mb: None,
        max_total_host_cpu_millicores: None,
        admission_queue_timeout: Duration::from_secs(30),
        max_admission_queue_depth: 2,
    };

    let harness = build_phase6_runtime(
        &fixtures,
        "minipod-p6-warm-overload",
        admission,
        warm_pool,
        Some(dns as Arc<dyn HostDnsResolver>),
        Some(Arc::clone(&dialer) as Arc<dyn UpstreamDialer>),
    );
    let mgr = &harness.manager;

    // 1. Pre-warm 2 idle VMs and start background replenisher.
    let warmed = mgr.warm_up().await.expect("warm_up target_size=2");
    assert_eq!(warmed, 2);
    assert_eq!(mgr.warm_pool_stats().ready_vms, 2);

    let replenisher = mgr.spawn_warm_pool_replenisher();

    let initial_records = load_journals(&harness.state_dir);
    assert_eq!(
        initial_records.len(),
        2,
        "expected 2 warm journal records after warm_up, got: {initial_records:?}"
    );
    let mut initial_warm_by_id = HashMap::new();
    let mut initial_warm_pids = HashSet::new();
    let mut initial_warm_pairs = Vec::new();
    for rec in initial_records {
        assert_eq!(rec.state, JournalLifecycleState::Warm);
        let pid = rec.pid.expect("warm record pid");
        let tok = rec.start_token.expect("warm record start_token");
        initial_warm_by_id.insert(rec.sandbox_id, (pid, tok));
        initial_warm_pids.insert(pid);
        initial_warm_pairs.push((pid, tok));
    }
    assert_eq!(initial_warm_pids.len(), 2);

    // 2. Execute 5-request burst against target_size=2:
    //    #1 (Isolated) & #2 (DomainAllowList for allowed.test:80) consume both warm VMs.
    let lease1 = mgr
        .spawn(template_spec.clone())
        .await
        .expect("warm checkout #1 (Isolated)");

    let mut allowlist_spec = template_spec.clone();
    allowlist_spec.network = NetworkPolicy::DomainAllowList {
        rules: vec![EgressRule {
            domain: "allowed.test".to_owned(),
            port: 80,
        }],
    };
    let lease2 = mgr
        .spawn(allowlist_spec)
        .await
        .expect("warm checkout #2 (DomainAllowList)");

    let stats_after_checkouts = mgr.warm_pool_stats();
    assert_eq!(stats_after_checkouts.total_checkouts, 2);
    assert_eq!(stats_after_checkouts.ready_vms, 0);
    assert_eq!(stats_after_checkouts.total_cold_spawns, 0);

    let (pid1, tok1) = load_journal_pid(&harness.state_dir, &lease1.id);
    let (pid2, tok2) = load_journal_pid(&harness.state_dir, &lease2.id);
    assert_eq!(
        initial_warm_by_id.get(&lease1.id).copied(),
        Some((pid1, tok1)),
        "checkout #1 must reuse initial warm VM PID"
    );
    assert_eq!(
        initial_warm_by_id.get(&lease2.id).copied(),
        Some((pid2, tok2)),
        "checkout #2 must reuse initial warm VM PID"
    );

    // Verify dynamic egress activation on warm-checked-out #2.
    let wget_ok = run_guest_sh(mgr, &lease2.id, "/bin/busybox wget -qO- http://allowed.test/ok")
        .await
        .expect("wget http://allowed.test/ok on checked-out VM #2");
    assert_eq!(
        wget_ok.exit.code,
        Some(0),
        "wget failed inside checked-out VM #2: stderr={:?}",
        String::from_utf8_lossy(&wget_ok.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&wget_ok.stdout), "public-ok-body");

    let canary_url = format!("http://127.0.0.1:{canary_port}/");
    let canary_hdr = format!("127.0.0.1:{canary_port}");
    let blocked_resp = guest_proxy_http_get(mgr, &lease2.id, &canary_url, &canary_hdr).await;
    assert!(
        blocked_resp.starts_with("HTTP/1.1 403 Forbidden"),
        "expected 403 Forbidden for loopback target on #2, got: {blocked_resp:?}"
    );
    assert_eq!(canary_hits.load(Ordering::SeqCst), 0);
    assert_eq!(dialer.forbidden_dial_count(), 0);

    assert_rss_within_cap(mgr, &[&lease1.id, &lease2.id], 1150);

    // 3. Queue #3 and #4 in FIFO admission queue (depth == 2), then assert #5 rejects immediately.
    let mgr_for_3 = Arc::clone(mgr);
    let spec_for_3 = template_spec.clone();
    let task3 = tokio::spawn(async move { mgr_for_3.spawn(spec_for_3).await });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mgr_for_4 = Arc::clone(mgr);
    let spec_for_4 = template_spec.clone();
    let task4 = tokio::spawn(async move { mgr_for_4.spawn(spec_for_4).await });
    tokio::time::sleep(Duration::from_millis(200)).await;

    assert!(!task3.is_finished(), "request #3 must block in FIFO queue");
    assert!(!task4.is_finished(), "request #4 must block in FIFO queue");
    assert_rss_within_cap(mgr, &[&lease1.id, &lease2.id], 1150);

    let req5_start = Instant::now();
    let err5 = mgr
        .spawn(template_spec.clone())
        .await
        .expect_err("request #5 must fail immediately when queue depth == 2");
    assert!(
        matches!(err5, SandboxError::AdmissionRejected(_)),
        "expected AdmissionRejected for #5, got: {err5:?}"
    );
    assert!(
        req5_start.elapsed() < Duration::from_secs(2),
        "request #5 queue-overflow rejection took too long: {:?}",
        req5_start.elapsed()
    );
    assert_rss_within_cap(mgr, &[&lease1.id, &lease2.id], 1150);

    // 4. Destroy #1 and #2 -> one-way dirty disposal kills initial warm PIDs; #3 and #4 wake and cold-boot.
    assert_eq!(
        mgr.destroy(&lease1.id).await.expect("destroy #1"),
        DestroyStatus::AllResourcesCleaned
    );
    assert_eq!(
        mgr.destroy(&lease2.id).await.expect("destroy #2"),
        DestroyStatus::AllResourcesCleaned
    );
    assert!(
        mgr.warm_pool_stats().total_disposed_dirty >= 2,
        "expected total_disposed_dirty >= 2, got {:?}",
        mgr.warm_pool_stats()
    );
    assert_pids_not_running(&initial_warm_pairs, "after destroying #1 and #2");

    let lease3 = tokio::time::timeout(Duration::from_secs(60), task3)
        .await
        .expect("timed out waiting for queued request #3")
        .expect("join task #3")
        .expect("queued request #3 must succeed");
    let lease4 = tokio::time::timeout(Duration::from_secs(60), task4)
        .await
        .expect("timed out waiting for queued request #4")
        .expect("join task #4")
        .expect("queued request #4 must succeed");

    let stats_34 = mgr.warm_pool_stats();
    assert!(
        stats_34.total_cold_spawns >= 2,
        "expected #3 and #4 to cold-spawn, stats={stats_34:?}"
    );
    assert_eq!(
        stats_34.ready_vms, 0,
        "background replenisher must yield while FIFO queue / active requests saturate capacity"
    );
    assert_eq!(
        stats_34.replenishing_vms, 0,
        "background replenisher must not be booting while capacity is full"
    );

    let (pid3, tok3) = load_journal_pid(&harness.state_dir, &lease3.id);
    let (pid4, tok4) = load_journal_pid(&harness.state_dir, &lease4.id);
    assert_ne!(pid3, pid4, "#3 and #4 must have distinct QEMU PIDs");
    assert!(
        !initial_warm_pids.contains(&pid3) && !initial_warm_pids.contains(&pid4),
        "cold-spawned #3 ({pid3}) and #4 ({pid4}) must not reuse initial warm PIDs {initial_warm_pids:?}"
    );
    assert_rss_within_cap(mgr, &[&lease3.id, &lease4.id], 1150);

    for (label, id) in [("#3", &lease3.id), ("#4", &lease4.id)] {
        let uname = run_guest_sh(mgr, id, "/bin/uname")
            .await
            .unwrap_or_else(|err| panic!("exec /bin/uname in {label}: {err:?}"));
        assert_eq!(uname.exit.code, Some(0));
        assert_eq!(String::from_utf8_lossy(&uname.stdout).trim(), "Linux");
    }

    // 5. Destroy #3 and #4 -> wait up to 20s for background replenisher to reach ready_vms == 2
    //    with brand-new PIDs -> drain_warm_pool -> verify zero leftovers.
    assert_eq!(
        mgr.destroy(&lease3.id).await.expect("destroy #3"),
        DestroyStatus::AllResourcesCleaned
    );
    assert_eq!(
        mgr.destroy(&lease4.id).await.expect("destroy #4"),
        DestroyStatus::AllResourcesCleaned
    );
    assert_pids_not_running(&[(pid3, tok3), (pid4, tok4)], "after destroying #3 and #4");

    let replenish_deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let st = mgr.warm_pool_stats();
        if st.ready_vms == 2 && st.replenishing_vms == 0 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < replenish_deadline,
            "timed out waiting for replenisher to restore ready_vms == 2 (stats={st:?})"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let replenished_records = load_journals(&harness.state_dir);
    assert_eq!(
        replenished_records.len(),
        2,
        "expected 2 replenished warm journal records, got: {replenished_records:?}"
    );
    let mut replenished_pairs = Vec::with_capacity(2);
    for rec in replenished_records {
        assert_eq!(rec.state, JournalLifecycleState::Warm);
        let pid = rec.pid.expect("replenished warm pid");
        let tok = rec.start_token.expect("replenished warm start_token");
        assert!(
            !initial_warm_pids.contains(&pid) && pid != pid3 && pid != pid4,
            "replenished warm PID {pid} must be brand-new (initial={initial_warm_pids:?}, cold=[{pid3}, {pid4}])"
        );
        replenished_pairs.push((pid, tok));
    }

    let drained = mgr.drain_warm_pool().await.expect("drain_warm_pool");
    assert_eq!(drained, 2);
    let _ = replenisher.await;

    assert_eq!(mgr.warm_pool_stats().ready_vms, 0);
    assert_eq!(mgr.current_admission_usage(), AdmissionUsage::default());
    assert!(
        load_journals(&harness.state_dir).is_empty(),
        "expected empty journals after drain_warm_pool"
    );
    assert_pids_not_running(&replenished_pairs, "after drain_warm_pool");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_separated_four_metric_benchmark_cold_warm_snapshot_container_ready() {
    let Some(fixtures) = discover_phase6_fixtures(
        "e2e_separated_four_metric_benchmark_cold_warm_snapshot_container_ready",
        true,
    ) else {
        return;
    };

    const SAMPLES: usize = 3;
    let vm_spec = isolated_small_spec(Duration::from_secs(180));
    let container_spec = container_vm_spec(Duration::from_secs(180));

    // 1. Cold Boot (WarmPool disabled): cold_boot_spawn & cold_boot_first_exec.
    let cold_harness = build_phase6_runtime(
        &fixtures,
        "minipod-p6-bench-cold",
        AdmissionLimits::default(),
        WarmPoolConfig::default(),
        None,
        None,
    );
    let mut cold_boot_spawn_durs = Vec::with_capacity(SAMPLES);
    let mut cold_boot_first_exec_durs = Vec::with_capacity(SAMPLES);
    let mut detected_accel = String::new();

    for idx in 0..SAMPLES {
        let spawn_t0 = Instant::now();
        let lease = cold_harness
            .manager
            .spawn(vm_spec.clone())
            .await
            .expect("cold boot spawn");
        let spawn_dur = spawn_t0.elapsed();

        let exec_t0 = Instant::now();
        let out = run_guest_echo_ok(&cold_harness.manager, &lease.id).await;
        let first_exec_dur = exec_t0.elapsed();
        assert_eq!(out.exit.code, Some(0));
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "ok");

        if idx == 0 {
            detected_accel = detect_active_accelerator(
                &fixtures,
                &cold_harness.manager,
                &cold_harness.state_dir,
                &lease.id,
            )
            .await;
        }

        assert_eq!(
            cold_harness
                .manager
                .destroy(&lease.id)
                .await
                .expect("destroy cold boot VM"),
            DestroyStatus::AllResourcesCleaned
        );
        cold_boot_spawn_durs.push(spawn_dur);
        cold_boot_first_exec_durs.push(first_exec_dur);
    }
    assert_eq!(
        cold_harness.manager.current_admission_usage(),
        AdmissionUsage::default()
    );

    // 2. Warm Checkout (WarmPool pre-warmed cleanly before each sample).
    let warm_harness = build_phase6_runtime(
        &fixtures,
        "minipod-p6-bench-warm",
        AdmissionLimits::default(),
        WarmPoolConfig {
            target_size: 1,
            template_spec: Some(vm_spec.clone()),
            max_idle_age: Duration::from_secs(300),
            replenish_retry_delay: Duration::from_millis(100),
        },
        None,
        None,
    );
    let mut warm_checkout_spawn_durs = Vec::with_capacity(SAMPLES);
    let mut warm_checkout_first_exec_durs = Vec::with_capacity(SAMPLES);

    for _ in 0..SAMPLES {
        let ready = warm_harness
            .manager
            .warm_up()
            .await
            .expect("pre-warm 1 VM for warm checkout benchmark");
        assert_eq!(ready, 1);

        let spawn_t0 = Instant::now();
        let lease = warm_harness
            .manager
            .spawn(vm_spec.clone())
            .await
            .expect("warm checkout spawn");
        let spawn_dur = spawn_t0.elapsed();

        let exec_t0 = Instant::now();
        let out = run_guest_echo_ok(&warm_harness.manager, &lease.id).await;
        let first_exec_dur = exec_t0.elapsed();
        assert_eq!(out.exit.code, Some(0));
        assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), "ok");

        assert_eq!(
            warm_harness
                .manager
                .destroy(&lease.id)
                .await
                .expect("destroy warm checkout VM"),
            DestroyStatus::AllResourcesCleaned
        );
        warm_checkout_spawn_durs.push(spawn_dur);
        warm_checkout_first_exec_durs.push(first_exec_dur);
    }
    let warm_stats = warm_harness.manager.warm_pool_stats();
    assert_eq!(warm_stats.total_checkouts, SAMPLES as u64);
    assert_eq!(warm_stats.total_cold_spawns, 0);
    assert_eq!(
        warm_harness
            .manager
            .drain_warm_pool()
            .await
            .expect("drain warm bench pool"),
        0
    );
    assert_eq!(
        warm_harness.manager.current_admission_usage(),
        AdmissionUsage::default()
    );

    // 3. Container-Ready: cold Podman (3 fresh VMs) + warm Podman VM (3 container iterations).
    let container_harness = build_phase6_runtime(
        &fixtures,
        "minipod-p6-bench-ctr",
        AdmissionLimits::default(),
        WarmPoolConfig::default(),
        None,
        None,
    );
    let mut container_cold_podman_durs = Vec::with_capacity(SAMPLES);
    let mut container_warm_vm_durs = Vec::with_capacity(SAMPLES);

    for idx in 0..SAMPLES {
        let lease = container_harness
            .manager
            .spawn(container_spec.clone())
            .await
            .expect("spawn fresh VM for Container-Ready benchmark");

        let compat = Arc::new(DockerCompatServer::new(
            Arc::clone(&container_harness.manager) as Arc<dyn SandboxTunnelPort>,
            lease.id.clone(),
            DockerCompatPolicy::default(),
        ));
        let server = compat
            .bind_loopback_http("127.0.0.1:0".parse().expect("loopback addr"))
            .await
            .expect("bind DockerCompatServer");
        let docker = Docker::connect_with_http(
            &format!("http://{}", server.local_addr()),
            60,
            bollard::API_DEFAULT_VERSION,
        )
        .expect("connect bollard HTTP client");

        let cold_t0 = Instant::now();
        import_tar_image(&docker, &fixtures.echo_image_tar).await;
        let (cid, host_port) = create_and_start_echo_http(&docker).await;
        let resp = http_get_loopback(host_port).await;
        assert!(
            resp.starts_with("HTTP/1.1 200 OK") && resp.contains("hello-minipod"),
            "unexpected cold container HTTP response: {resp:?}"
        );
        container_cold_podman_durs.push(cold_t0.elapsed());

        stop_and_remove_container(&docker, &cid, host_port).await;

        if idx + 1 == SAMPLES {
            for _ in 0..SAMPLES {
                let warm_t0 = Instant::now();
                let (wcid, whost_port) = create_and_start_echo_http(&docker).await;
                let wresp = http_get_loopback(whost_port).await;
                assert!(
                    wresp.starts_with("HTTP/1.1 200 OK") && wresp.contains("hello-minipod"),
                    "unexpected warm container HTTP response: {wresp:?}"
                );
                container_warm_vm_durs.push(warm_t0.elapsed());

                stop_and_remove_container(&docker, &wcid, whost_port).await;
            }
        }

        server.shutdown().await;
        assert_eq!(
            container_harness
                .manager
                .destroy(&lease.id)
                .await
                .expect("destroy container VM"),
            DestroyStatus::AllResourcesCleaned
        );
    }
    assert_eq!(
        container_harness.manager.current_admission_usage(),
        AdmissionUsage::default()
    );

    let report = PlatformBenchmarkReport {
        platform: format!("{}-{}", std::env::consts::OS, fixtures.arch.as_str()),
        arch: fixtures.arch.as_str().to_owned(),
        accelerator: detected_accel,
        warm_pool_target_ms: DEFAULT_WARM_POOL_TARGET_MS,
        cold_boot_spawn: BenchmarkMetricStatus::measured_durations(&cold_boot_spawn_durs)
            .expect("cold_boot_spawn summary"),
        cold_boot_first_exec: BenchmarkMetricStatus::measured_durations(&cold_boot_first_exec_durs)
            .expect("cold_boot_first_exec summary"),
        warm_checkout_spawn: BenchmarkMetricStatus::measured_durations(&warm_checkout_spawn_durs)
            .expect("warm_checkout_spawn summary"),
        warm_checkout_first_exec: BenchmarkMetricStatus::measured_durations(
            &warm_checkout_first_exec_durs,
        )
        .expect("warm_checkout_first_exec summary"),
        snapshot_restore: BenchmarkMetricStatus::deferred_post_mvp(
            DEFAULT_SNAPSHOT_DEFERRED_REASON,
        ),
        container_ready_cold_podman: BenchmarkMetricStatus::measured_durations(
            &container_cold_podman_durs,
        )
        .expect("container_ready_cold_podman summary"),
        container_ready_warm_vm: BenchmarkMetricStatus::measured_durations(&container_warm_vm_durs)
            .expect("container_ready_warm_vm summary"),
    };

    assert_eq!(
        report.warm_checkout_within_target(),
        Some(true),
        "warm_checkout_spawn p50 must be <= {:.1} ms: {}",
        report.warm_pool_target_ms,
        report.to_markdown()
    );

    let full_markdown = format!(
        "{}\n## Measurement Notes & Scope\n\n\
        - **Suite:** `crates/sandbox-vmm/tests/phase6_warm_pool_and_bench_e2e.rs`\n\
        - **Cold Boot (`cold_boot_spawn`, `cold_boot_first_exec`):** `WarmPoolConfig` disabled (`target_size = 0`); VM spec = 1 vCPU, 256 MiB guest RAM, 512 MiB host RSS cap, 256 MiB disk / 512 MiB host storage (`NetworkPolicy::Isolated`, `AccelerationPolicy::Preferred`). `cold_boot_spawn` times `RuntimeManager::spawn()`; `cold_boot_first_exec` times from `spawn()` return until the first guest `exec_stream` (`/bin/echo ok`) completes.\n\
        - **Warm Checkout (`warm_checkout_spawn`, `warm_checkout_first_exec`):** Pool pre-warmed cleanly to `ready_vms = 1` before each sample (`1 vCPU / 256 MiB RAM`). `warm_checkout_spawn` times `RuntimeManager::spawn()` checkout; `warm_checkout_first_exec` times from `spawn()` return until `/bin/echo ok` completes.\n\
        - **Snapshot Restore (`snapshot_restore`):** Explicitly marked `DeferredPostMvp` per `BRD.md` Section 4.1 & Section 6.\n\
        - **Container-Ready (`container_ready_cold_podman`, `container_ready_warm_vm`):** VM spec = 2 vCPU, 768 MiB guest RAM, 1024 MiB host RSS cap, 512 MiB disk / 1024 MiB host storage, attached to `DockerCompatServer` on loopback HTTP (`bollard`). `container_ready_cold_podman` measures the first container start on a fresh VM (`podman system service` lazy cold boot + `import_image(echo-http.tar)` + `create_container` + `start_container` + `inspect_container` + Host HTTP `GET 127.0.0.1:<port>/hello` returning `200 OK`); `container_ready_warm_vm` measures subsequent `create_container` + `start_container` + `inspect_container` + Host HTTP `GET 127.0.0.1:<port>/hello` `200 OK` iterations on the Podman-warm VM with `echo-http` pre-imported (stopping and removing each prior container cleanly between iterations).\n",
        report.to_markdown()
    );

    println!("{full_markdown}");

    if std::env::var_os("MINIPOD_WRITE_BENCH_REPORT").is_some() {
        let report_path = repo_root()
            .join("docs")
            .join("benchmarks")
            .join(format!("phase6-{}-{}.md", std::env::consts::OS, fixtures.arch.as_str()));
        write_file_atomic(&report_path, &full_markdown);
        println!("Wrote benchmark report to {}", report_path.display());
    }
}
