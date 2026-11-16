#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bollard::container::{
    Config, CreateContainerOptions, ListContainersOptions, LogOutput, RemoveContainerOptions,
    StartContainerOptions, StopContainerOptions,
};
use bollard::exec::{CreateExecOptions, StartExecOptions, StartExecResults};
use bollard::image::ImportImageOptions;
use bollard::Docker;
use bytes::Bytes;
use futures_util::StreamExt;
use sandbox_core::{
    AccelerationPolicy, DestroyStatus, EgressRule, EnforcementLevel, ExecRequest, ExecTarget,
    GuestArch, IsolationMode, NetworkPolicy, ResourceBudget, SandboxError, SandboxId, SandboxSpec,
};
use sandbox_docker_compat::{DockerCompatPolicy, DockerCompatServer, ReaperSocketPolicy};
use sandbox_image::{
    decode_hex_exact, install_bundle_atomic, BundleOverlayStore, BundleVerifier, InstalledBundle,
};
use sandbox_runtime::{
    is_forbidden_ip, AdmissionLimits, AdmissionUsage, BoxedUpstreamStream, CollectedExecOutput,
    HostDnsResolver, LocalRuntimeManager, RuntimeManager, RuntimeManagerConfig, SandboxTunnelPort,
    UpstreamDialer, WarmPoolConfig,
};
use sandbox_vmm::{
    discover_qemu_binary_for_arch, discover_qemu_img_binary, QemuDriverConfig, QemuVmDriver,
};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
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

struct Phase5Fixtures {
    arch: GuestArch,
    src_bundle_dir: PathBuf,
    public_key: [u8; 32],
    qemu_bin: PathBuf,
    qemu_img_bin: PathBuf,
    echo_image_tar: PathBuf,
}

struct Phase5Harness {
    _temp: TestTempDir,
    _installed: InstalledBundle,
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

fn discover_phase5_fixtures(test_name: &str, require_echo_image: bool) -> Option<Phase5Fixtures> {
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
            "skipping {test_name}: missing Phase 5 E2E fixtures ({})",
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
    Some(Phase5Fixtures {
        arch,
        src_bundle_dir,
        public_key,
        qemu_bin: qemu_bin.expect("checked"),
        qemu_img_bin: qemu_img_bin.expect("checked"),
        echo_image_tar,
    })
}

fn build_phase5_runtime(
    fixtures: &Phase5Fixtures,
    prefix: &str,
    admission: AdmissionLimits,
    dns_resolver: Option<Arc<dyn HostDnsResolver>>,
    dialer: Option<Arc<dyn UpstreamDialer>>,
) -> Phase5Harness {
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
        state_dir,
        sweep_interval: Duration::from_millis(500),
        graceful_shutdown_timeout: Duration::from_secs(3),
        max_copy_bytes: 16 * 1024 * 1024,
        max_copy_entries: 4096,
        cleanup_max_attempts: 8,
        cleanup_initial_delay: Duration::from_millis(50),
        admission,
        warm_pool: WarmPoolConfig::default(),
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

    Phase5Harness {
        _temp: temp,
        _installed: installed,
        manager: Arc::new(manager),
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

async fn spawn_public_http_fixture(canary_port: u16) -> MockTcpServer {
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
                let first_line = head.lines().next().unwrap_or_default();
                let target = first_line.split_whitespace().nth(1).unwrap_or("/");
                let resp = match target {
                    "/ok" => "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 14\r\nConnection: close\r\n\r\npublic-ok-body".to_owned(),
                    "/redir-loopback" => format!(
                        "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{canary_port}/secret\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    ),
                    "/redir-v6mapped" => {
                        "HTTP/1.1 302 Found\r\nLocation: http://[::ffff:10.0.0.1]/secret\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned()
                    }
                    "/redir-disallowed" => {
                        "HTTP/1.1 302 Found\r\nLocation: http://evil.blocked.test/exfil\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned()
                    }
                    _ => "HTTP/1.1 404 Not Found\r\nContent-Length: 9\r\nConnection: close\r\n\r\nnot-found".to_owned(),
                };
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.flush().await;
                let _ = stream.shutdown().await;
            });
        }
    });
    MockTcpServer { addr, task }
}

async fn spawn_public_connect_fixture() -> MockTcpServer {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind public CONNECT fixture");
    let addr = listener.local_addr().expect("public CONNECT local_addr");
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let (rx, mut tx) = stream.into_split();
                if tx.write_all(b"MINIPOD-TLS-MOCK\n").await.is_err() {
                    return;
                }
                let _ = tx.flush().await;
                let mut reader = BufReader::new(rx);
                let mut line = String::new();
                if matches!(
                    tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line)).await,
                    Ok(Ok(n)) if n > 0
                ) {
                    let reply = format!("CONNECT-ECHO:{}\n", line.trim_end_matches(['\r', '\n']));
                    let _ = tx.write_all(reply.as_bytes()).await;
                    let _ = tx.flush().await;
                }
                let _ = tx.shutdown().await;
            });
        }
    });
    MockTcpServer { addr, task }
}

struct ControlledDnsResolver {
    queries: Arc<Mutex<Vec<String>>>,
    rebind_lookups: AtomicUsize,
}

impl ControlledDnsResolver {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            queries: Arc::new(Mutex::new(Vec::new())),
            rebind_lookups: AtomicUsize::new(0),
        })
    }

    fn queried_domains(&self) -> Vec<String> {
        self.queries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

#[async_trait::async_trait]
impl HostDnsResolver for ControlledDnsResolver {
    async fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        let lower = host.to_ascii_lowercase();
        self.queries
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(lower.clone());

        let public_ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        match lower.as_str() {
            "allowed.test" | "api.allowed.test" => Ok(vec![SocketAddr::new(public_ip, port)]),
            "rebind.allowed.test" => {
                let step = self.rebind_lookups.fetch_add(1, Ordering::SeqCst);
                let ip = match step {
                    0 => public_ip,
                    1 => IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                    _ => IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x0001)),
                };
                Ok(vec![SocketAddr::new(ip, port)])
            }
            _ => Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("unexpected DNS lookup for '{lower}'"),
            )),
        }
    }
}

struct ControlledUpstreamDialer {
    http_port: u16,
    connect_port: u16,
    dialed_addrs: Arc<Mutex<Vec<SocketAddr>>>,
    forbidden_dials: Arc<AtomicUsize>,
}

impl ControlledUpstreamDialer {
    fn new(http_port: u16, connect_port: u16) -> Arc<Self> {
        Arc::new(Self {
            http_port,
            connect_port,
            dialed_addrs: Arc::new(Mutex::new(Vec::new())),
            forbidden_dials: Arc::new(AtomicUsize::new(0)),
        })
    }

    fn forbidden_dial_count(&self) -> usize {
        self.forbidden_dials.load(Ordering::SeqCst)
    }

    fn dialed_addrs(&self) -> Vec<SocketAddr> {
        self.dialed_addrs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

#[async_trait::async_trait]
impl UpstreamDialer for ControlledUpstreamDialer {
    async fn connect(&self, addr: SocketAddr) -> io::Result<BoxedUpstreamStream> {
        if is_forbidden_ip(addr.ip()) {
            self.forbidden_dials.fetch_add(1, Ordering::SeqCst);
            panic!("SECURITY INVARIANT VIOLATED: UpstreamDialer::connect called with forbidden {addr}");
        }
        self.dialed_addrs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(addr);

        let public_ip = IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34));
        if addr == SocketAddr::new(public_ip, 80) {
            let stream = TcpStream::connect(("127.0.0.1", self.http_port)).await?;
            let _ = stream.set_nodelay(true);
            return Ok(Box::pin(stream));
        }
        if addr == SocketAddr::new(public_ip, 443) {
            let stream = TcpStream::connect(("127.0.0.1", self.connect_port)).await?;
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

async fn run_container_sh_via_docker(docker: &Docker, cid: &str, script: &str) -> (i64, String) {
    let exec_created = docker
        .create_exec(
            cid,
            CreateExecOptions {
                attach_stdout: Some(true),
                attach_stderr: Some(true),
                cmd: Some(vec!["/bin/sh", "-c", script]),
                ..Default::default()
            },
        )
        .await
        .expect("create container exec");

    let start_res = docker
        .start_exec(
            &exec_created.id,
            Some(StartExecOptions {
                detach: false,
                ..Default::default()
            }),
        )
        .await
        .expect("start container exec");

    let StartExecResults::Attached { mut output, .. } = start_res else {
        panic!("expected StartExecResults::Attached");
    };

    let out = tokio::time::timeout(Duration::from_secs(15), async {
        let mut acc = String::new();
        while let Some(chunk) = output.next().await {
            match chunk.expect("container exec output chunk") {
                LogOutput::StdOut { message }
                | LogOutput::StdErr { message }
                | LogOutput::Console { message }
                | LogOutput::StdIn { message } => {
                    acc.push_str(&String::from_utf8_lossy(&message));
                }
            }
        }
        acc
    })
    .await
    .expect("timeout waiting for container exec output");

    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let info = docker
            .inspect_exec(&exec_created.id)
            .await
            .expect("inspect container exec");
        if info.running == Some(false) {
            return (info.exit_code.unwrap_or(-1), out);
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "container exec did not finish promptly"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

/// Sends a raw HTTP/1.1 wire payload directly to `proxy_host:proxy_port` using BusyBox `nc`.
fn build_raw_proxy_nc_script(proxy_host: &str, proxy_port: u16, printf_escaped_http: &str) -> String {
    format!(
        "printf '{printf_escaped_http}' | /bin/busybox nc {proxy_host} {proxy_port}"
    )
}

async fn guest_proxy_http_get(
    mgr: &LocalRuntimeManager,
    id: &SandboxId,
    url: &str,
    host_header: &str,
) -> String {
    let payload = format!("GET {url} HTTP/1.1\\r\\nHost: {host_header}\\r\\nConnection: close\\r\\n\\r\\n");
    let script = build_raw_proxy_nc_script("127.0.0.1", 3128, &payload);
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

async fn container_proxy_http_get_via_docker(
    docker: &Docker,
    cid: &str,
    url: &str,
    host_header: &str,
) -> String {
    let payload = format!("GET {url} HTTP/1.1\\r\\nHost: {host_header}\\r\\nConnection: close\\r\\n\\r\\n");
    let script = build_raw_proxy_nc_script("10.88.0.1", 3128, &payload);
    let (code, out) = run_container_sh_via_docker(docker, cid, &script).await;
    assert_eq!(
        code, 0,
        "raw HTTP proxy script failed inside container for {url}: out={out:?}"
    );
    out
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_egress_proxy_blocks_private_ips_ipv6_mapped_dns_rebinding_and_redirects() {
    let Some(fixtures) = discover_phase5_fixtures(
        "e2e_egress_proxy_blocks_private_ips_ipv6_mapped_dns_rebinding_and_redirects",
        true,
    ) else {
        return;
    };

    let canary_hits = Arc::new(AtomicUsize::new(0));
    let canary_srv = spawn_canary_http_server(Arc::clone(&canary_hits)).await;
    let canary_port = canary_srv.port();

    let public_http = spawn_public_http_fixture(canary_port).await;
    let public_connect = spawn_public_connect_fixture().await;

    let dns = ControlledDnsResolver::new();
    let dialer = ControlledUpstreamDialer::new(public_http.port(), public_connect.port());

    let harness = build_phase5_runtime(
        &fixtures,
        "minipod-p5-egress",
        AdmissionLimits::default(),
        Some(Arc::clone(&dns) as Arc<dyn HostDnsResolver>),
        Some(Arc::clone(&dialer) as Arc<dyn UpstreamDialer>),
    );

    let spec = SandboxSpec {
        isolation: IsolationMode::VmRequired,
        acceleration: AccelerationPolicy::Preferred,
        network: NetworkPolicy::DomainAllowList {
            rules: vec![
                EgressRule {
                    domain: "allowed.test".to_owned(),
                    port: 80,
                },
                EgressRule {
                    domain: "allowed.test".to_owned(),
                    port: 443,
                },
                EgressRule {
                    domain: "*.allowed.test".to_owned(),
                    port: 80,
                },
                EgressRule {
                    domain: "*.allowed.test".to_owned(),
                    port: 443,
                },
                EgressRule {
                    domain: "rebind.allowed.test".to_owned(),
                    port: 80,
                },
            ],
        },
        budget: ResourceBudget {
            guest_vcpus: 2,
            host_cpu_quota_Millicores: None,
            guest_ram_mb: 768,
            host_rss_budget_mb: Some(1024),
            virtual_disk_mb: 512,
            host_storage_budget_mb: 1024,
        },
        lease_ttl: Duration::from_secs(180),
    };

    let lease = harness
        .manager
        .spawn(spec)
        .await
        .expect("spawn VM with DomainAllowList egress proxy");
    assert_eq!(lease.capabilities.egress_filter, EnforcementLevel::HardLimit);

    // 1. ExecTarget::Guest automatic proxy environment injection.
    let env_out = run_guest_sh(
        &harness.manager,
        &lease.id,
        "printf '%s|%s|%s|%s|%s|%s|%s|%s' \"$HTTP_PROXY\" \"$HTTPS_PROXY\" \"$ALL_PROXY\" \"$NO_PROXY\" \"$http_proxy\" \"$https_proxy\" \"$all_proxy\" \"$no_proxy\"",
    )
    .await
    .expect("query guest proxy env");
    assert_eq!(env_out.exit.code, Some(0));
    assert_eq!(
        String::from_utf8_lossy(&env_out.stdout),
        "http://127.0.0.1:3128|http://127.0.0.1:3128|http://127.0.0.1:3128|localhost,127.0.0.1,::1,10.88.0.1|http://127.0.0.1:3128|http://127.0.0.1:3128|http://127.0.0.1:3128|localhost,127.0.0.1,::1,10.88.0.1"
    );

    // 2. Plain HTTP GET via automatically injected HTTP_PROXY (`wget` inside guest).
    let wget_ok = run_guest_sh(
        &harness.manager,
        &lease.id,
        "/bin/busybox wget -qO- http://allowed.test/ok",
    )
    .await
    .expect("wget via injected HTTP_PROXY");
    assert_eq!(
        wget_ok.exit.code,
        Some(0),
        "wget failed: {:?}",
        String::from_utf8_lossy(&wget_ok.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&wget_ok.stdout), "public-ok-body");

    let wildcard_ok = run_guest_sh(
        &harness.manager,
        &lease.id,
        "/bin/busybox wget -qO- http://api.allowed.test/ok",
    )
    .await
    .expect("wget wildcard subdomain via injected HTTP_PROXY");
    assert_eq!(wildcard_ok.exit.code, Some(0));
    assert_eq!(String::from_utf8_lossy(&wildcard_ok.stdout), "public-ok-body");

    // 3. HTTP CONNECT tunnel through 127.0.0.1:3128 to mock TLS-like upstream on port 443.
    let connect_script = build_raw_proxy_nc_script(
        "127.0.0.1",
        3128,
        "CONNECT allowed.test:443 HTTP/1.1\\r\\nHost: allowed.test:443\\r\\n\\r\\ntls-like-hello\\n",
    );
    let connect_out = run_guest_sh(&harness.manager, &lease.id, &connect_script)
        .await
        .expect("CONNECT allowed.test:443 through proxy");
    assert_eq!(connect_out.exit.code, Some(0));
    let connect_resp = String::from_utf8_lossy(&connect_out.stdout);
    assert!(
        connect_resp.starts_with("HTTP/1.1 200 Connection Established\r\n\r\n")
            && connect_resp.contains("MINIPOD-TLS-MOCK")
            && connect_resp.contains("CONNECT-ECHO:tls-like-hello"),
        "unexpected CONNECT response: {connect_resp:?}"
    );

    // 4. Disallowed domain returns 403 and triggers ZERO host DNS lookups.
    let blocked_resp = guest_proxy_http_get(
        &harness.manager,
        &lease.id,
        "http://evil.blocked.test/",
        "evil.blocked.test",
    )
    .await;
    assert!(
        blocked_resp.starts_with("HTTP/1.1 403 Forbidden"),
        "expected 403 for evil.blocked.test, got: {blocked_resp:?}"
    );
    assert!(
        !dns.queried_domains()
            .iter()
            .any(|d| d == "evil.blocked.test"),
        "evil.blocked.test must be rejected before DNS lookup: {:?}",
        dns.queried_domains()
    );

    // 5. Raw forbidden IP targets (loopback, IMDS, RFC1918, IPv6 loopback, IPv4-mapped IPv6).
    let forbidden_targets = [
        (
            format!("http://127.0.0.1:{canary_port}/"),
            format!("127.0.0.1:{canary_port}"),
        ),
        (
            "http://169.254.169.254/latest/meta-data/".to_owned(),
            "169.254.169.254".to_owned(),
        ),
        ("http://10.0.0.1/".to_owned(), "10.0.0.1".to_owned()),
        (
            format!("http://[::1]:{canary_port}/"),
            format!("[::1]:{canary_port}"),
        ),
        (
            format!("http://[::ffff:127.0.0.1]:{canary_port}/"),
            format!("[::ffff:127.0.0.1]:{canary_port}"),
        ),
    ];
    for (url, host_hdr) in &forbidden_targets {
        let resp = guest_proxy_http_get(&harness.manager, &lease.id, url, host_hdr).await;
        assert!(
            resp.starts_with("HTTP/1.1 403 Forbidden"),
            "expected 403 Forbidden for {url}, got: {resp:?}"
        );
    }
    assert_eq!(canary_hits.load(Ordering::SeqCst), 0);
    assert_eq!(dialer.forbidden_dial_count(), 0);

    // 6. DNS Rebinding: 1st lookup -> public IP (200), 2nd -> 127.0.0.1 (403), 3rd -> [::ffff:127.0.0.1] (403).
    let rebind_1 = guest_proxy_http_get(
        &harness.manager,
        &lease.id,
        "http://rebind.allowed.test/ok",
        "rebind.allowed.test",
    )
    .await;
    assert!(
        rebind_1.starts_with("HTTP/1.1 200 OK") && rebind_1.contains("public-ok-body"),
        "expected 200 OK on 1st rebind lookup, got: {rebind_1:?}"
    );

    let rebind_2 = guest_proxy_http_get(
        &harness.manager,
        &lease.id,
        "http://rebind.allowed.test/ok",
        "rebind.allowed.test",
    )
    .await;
    assert!(
        rebind_2.starts_with("HTTP/1.1 403 Forbidden"),
        "expected 403 Forbidden on 2nd rebind lookup (127.0.0.1), got: {rebind_2:?}"
    );

    let rebind_3 = guest_proxy_http_get(
        &harness.manager,
        &lease.id,
        "http://rebind.allowed.test/ok",
        "rebind.allowed.test",
    )
    .await;
    assert!(
        rebind_3.starts_with("HTTP/1.1 403 Forbidden"),
        "expected 403 Forbidden on 3rd rebind lookup ([::ffff:127.0.0.1]), got: {rebind_3:?}"
    );
    assert_eq!(dialer.forbidden_dial_count(), 0);

    // 7. HTTP Redirect SSRF against allowed.test.
    for path in ["/redir-loopback", "/redir-v6mapped", "/redir-disallowed"] {
        let url = format!("http://allowed.test{path}");
        let resp = guest_proxy_http_get(&harness.manager, &lease.id, &url, "allowed.test").await;
        assert!(
            resp.starts_with("HTTP/1.1 403 Forbidden"),
            "expected 403 Forbidden for redirect SSRF {url}, got: {resp:?}"
        );
    }
    assert_eq!(canary_hits.load(Ordering::SeqCst), 0);
    assert_eq!(dialer.forbidden_dial_count(), 0);
    assert!(
        !dns.queried_domains()
            .iter()
            .any(|d| d == "evil.blocked.test"),
        "redirect to evil.blocked.test must be blocked before DNS lookup: {:?}",
        dns.queried_domains()
    );

    // 8. Raw non-proxy TCP/UDP connect inside guest fails (-nic none).
    let net_ifaces = run_guest_sh(
        &harness.manager,
        &lease.id,
        "ls -1 /sys/class/net && echo ===ROUTE=== && awk 'NR>1{print $1}' /proc/net/route",
    )
    .await
    .expect("query guest interfaces");
    assert_eq!(net_ifaces.exit.code, Some(0));
    let iface_stdout = String::from_utf8_lossy(&net_ifaces.stdout);
    let (ifaces, routes) = iface_stdout
        .split_once("===ROUTE===")
        .expect("network check delimiter");
    assert_eq!(ifaces.trim(), "lo");
    assert_eq!(routes.trim(), "");

    let raw_tcp = run_guest_sh(
        &harness.manager,
        &lease.id,
        "env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u http_proxy -u https_proxy -u all_proxy /bin/busybox nc -w 2 93.184.216.34 80",
    )
    .await
    .expect("run raw direct TCP connect");
    assert_ne!(
        raw_tcp.exit.code,
        Some(0),
        "raw direct TCP connect must fail under -nic none"
    );

    let raw_udp = run_guest_sh(
        &harness.manager,
        &lease.id,
        "env -u HTTP_PROXY -u HTTPS_PROXY -u ALL_PROXY -u http_proxy -u https_proxy -u all_proxy /bin/sh -c 'printf hi | /bin/busybox nc -u -w 1 93.184.216.34 53'",
    )
    .await
    .expect("run raw direct UDP connect");
    assert_ne!(
        raw_udp.exit.code,
        Some(0),
        "raw direct UDP connect must fail under -nic none"
    );

    // 9. Podman Container (`DockerCompatServer` + `ExecTarget::Container`) proxy injection & egress filtering.
    let compat = Arc::new(DockerCompatServer::new(
        Arc::clone(&harness.manager) as Arc<dyn SandboxTunnelPort>,
        lease.id.clone(),
        DockerCompatPolicy {
            reaper_socket: ReaperSocketPolicy::Deny,
            container_proxy_http_url: Some("http://10.88.0.1:3128".to_owned()),
        },
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

    import_tar_image(&docker, &fixtures.echo_image_tar).await;

    let created = docker
        .create_container(
            None::<CreateContainerOptions<String>>,
            Config {
                image: Some("minipod-e2e/echo-http:1.0".to_owned()),
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
        .expect("inspect container");
    let container_env = inspected
        .config
        .as_ref()
        .and_then(|c| c.env.as_ref())
        .expect("container Config.Env");
    assert!(
        container_env
            .iter()
            .any(|e| e == "HTTP_PROXY=http://10.88.0.1:3128"),
        "expected HTTP_PROXY=http://10.88.0.1:3128 in container Config.Env: {container_env:?}"
    );

    // Verify inside container via Docker API exec (inherits container creation env from DockerCompatPolicy).
    let (c_env_code, c_env_out) = run_container_sh_via_docker(
        &docker,
        &cid,
        "printf '%s|%s|%s|%s' \"$HTTP_PROXY\" \"$HTTPS_PROXY\" \"$ALL_PROXY\" \"$NO_PROXY\"",
    )
    .await;
    assert_eq!(c_env_code, 0);
    assert_eq!(
        c_env_out,
        "http://10.88.0.1:3128|http://10.88.0.1:3128|http://10.88.0.1:3128|localhost,127.0.0.1,::1,10.88.0.1"
    );

    let (c_wget_code, c_wget_out) = run_container_sh_via_docker(
        &docker,
        &cid,
        "/bin/busybox wget -qO- http://allowed.test/ok",
    )
    .await;
    assert_eq!(
        c_wget_code, 0,
        "container wget to http://allowed.test/ok failed: {c_wget_out:?}"
    );
    assert_eq!(c_wget_out, "public-ok-body");

    // Verify ExecTarget::Container direct RuntimeManager::exec_stream reaches allowed.test too.
    let direct_stream = harness
        .manager
        .exec_stream(
            &lease.id,
            ExecRequest {
                target: ExecTarget::Container {
                    id_or_name: cid.clone(),
                },
                argv: vec![
                    "/bin/sh".to_owned(),
                    "-c".to_owned(),
                    "printf '%s|' \"$HTTP_PROXY\" && /bin/busybox wget -qO- http://allowed.test/ok"
                        .to_owned(),
                ],
                env: BTreeMap::new(),
                cwd: None,
                user: None,
                deadline: Duration::from_secs(15),
                stdout_budget_bytes: 64 * 1024,
                stderr_budget_bytes: 64 * 1024,
            },
        )
        .await
        .expect("exec_stream ExecTarget::Container");
    let direct_out = direct_stream
        .collect()
        .await
        .expect("collect ExecTarget::Container output");
    assert_eq!(direct_out.exit.code, Some(0));
    assert_eq!(
        String::from_utf8_lossy(&direct_out.stdout),
        "http://10.88.0.1:3128|public-ok-body"
    );

    // Container blocked on loopback & IPv4-mapped IPv6 targets via Host Egress Proxy.
    let c_block_v4 = container_proxy_http_get_via_docker(
        &docker,
        &cid,
        &format!("http://127.0.0.1:{canary_port}/"),
        &format!("127.0.0.1:{canary_port}"),
    )
    .await;
    assert!(
        c_block_v4.starts_with("HTTP/1.1 403 Forbidden"),
        "expected 403 inside container for 127.0.0.1, got: {c_block_v4:?}"
    );

    let c_block_v6 = container_proxy_http_get_via_docker(
        &docker,
        &cid,
        &format!("http://[::ffff:127.0.0.1]:{canary_port}/"),
        &format!("[::ffff:127.0.0.1]:{canary_port}"),
    )
    .await;
    assert!(
        c_block_v6.starts_with("HTTP/1.1 403 Forbidden"),
        "expected 403 inside container for [::ffff:127.0.0.1], got: {c_block_v6:?}"
    );

    assert_eq!(canary_hits.load(Ordering::SeqCst), 0);
    assert_eq!(dialer.forbidden_dial_count(), 0);
    let dialed = dialer.dialed_addrs();
    assert!(!dialed.is_empty());
    assert!(dialed.iter().all(|addr| !is_forbidden_ip(addr.ip())));

    docker
        .stop_container(&cid, Some(StopContainerOptions { t: 2 }))
        .await
        .expect("stop container");
    docker
        .remove_container(
            &cid,
            Some(RemoveContainerOptions {
                force: true,
                v: true,
                ..Default::default()
            }),
        )
        .await
        .expect("remove container");
    let listed = docker
        .list_containers(Some(ListContainersOptions::<String> {
            all: true,
            ..Default::default()
        }))
        .await
        .expect("list containers after remove");
    assert!(!listed.iter().any(|c| c.id.as_deref() == Some(cid.as_str())));

    server.shutdown().await;
    let status = harness
        .manager
        .destroy(&lease.id)
        .await
        .expect("destroy sandbox");
    assert_eq!(status, DestroyStatus::AllResourcesCleaned);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_admission_control_os_resource_caps_and_capability_report() {
    let Some(fixtures) = discover_phase5_fixtures(
        "e2e_admission_control_os_resource_caps_and_capability_report",
        false,
    ) else {
        return;
    };

    let spec = SandboxSpec {
        isolation: IsolationMode::VmRequired,
        acceleration: AccelerationPolicy::Preferred,
        network: NetworkPolicy::Isolated,
        budget: ResourceBudget {
            guest_vcpus: 1,
            host_cpu_quota_Millicores: Some(500),
            guest_ram_mb: 256,
            host_rss_budget_mb: Some(512),
            virtual_disk_mb: 256,
            host_storage_budget_mb: 512,
        },
        lease_ttl: Duration::from_secs(60),
    };

    // (a) Immediate rejection when admission_queue_timeout == ZERO and RSS inspection/CapabilityReport accuracy.
    let harness_a = build_phase5_runtime(
        &fixtures,
        "minipod-p5-adm-reject",
        AdmissionLimits {
            max_total_host_rss_mb: Some(600),
            admission_queue_timeout: Duration::ZERO,
            ..Default::default()
        },
        None,
        None,
    );

    let lease_a = harness_a
        .manager
        .spawn(spec.clone())
        .await
        .expect("spawn VM under 600 MiB RSS admission cap");

    #[cfg(windows)]
    {
        assert_eq!(lease_a.capabilities.cpu_quota, EnforcementLevel::HardLimit);
        assert_eq!(lease_a.capabilities.host_rss, EnforcementLevel::HardLimit);
        assert_eq!(
            lease_a.capabilities.host_storage,
            EnforcementLevel::BestEffort
        );
        assert_eq!(
            lease_a.capabilities.egress_filter,
            EnforcementLevel::HardLimit
        );
    }
    #[cfg(target_os = "linux")]
    {
        assert!(matches!(
            lease_a.capabilities.cpu_quota,
            EnforcementLevel::HardLimit | EnforcementLevel::BestEffort | EnforcementLevel::Unsupported
        ));
        assert!(matches!(
            lease_a.capabilities.host_rss,
            EnforcementLevel::HardLimit | EnforcementLevel::BestEffort | EnforcementLevel::Unsupported
        ));
        assert_eq!(
            lease_a.capabilities.host_storage,
            EnforcementLevel::BestEffort
        );
        assert_eq!(
            lease_a.capabilities.egress_filter,
            EnforcementLevel::HardLimit
        );
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        assert_eq!(
            lease_a.capabilities.host_storage,
            EnforcementLevel::BestEffort
        );
        assert_eq!(
            lease_a.capabilities.egress_filter,
            EnforcementLevel::HardLimit
        );
    }

    let rss_a = harness_a
        .manager
        .sandbox_current_rss_bytes(&lease_a.id)
        .expect("sandbox_current_rss_bytes must return live QEMU RSS bytes");
    assert!(
        rss_a > 0 && rss_a <= 512 * 1024 * 1024,
        "expected live QEMU RSS in (0, 512 MiB], got {rss_a} bytes"
    );

    let usage_a = harness_a.manager.current_admission_usage();
    assert_eq!(usage_a.active_sandboxes, 1);
    assert_eq!(usage_a.reserved_host_rss_mb, 512);
    assert!(
        usage_a.effective_host_rss_mb <= 600,
        "expected effective_host_rss_mb <= 600 MiB, got {}",
        usage_a.effective_host_rss_mb
    );

    let rejected = harness_a
        .manager
        .spawn(spec.clone())
        .await
        .expect_err("second 512 MiB VM must fail admission under 600 MiB cap");
    assert!(
        matches!(rejected, SandboxError::AdmissionRejected(_)),
        "expected AdmissionRejected, got {rejected:?}"
    );

    assert_eq!(
        harness_a
            .manager
            .destroy(&lease_a.id)
            .await
            .expect("destroy VM in subtest (a)"),
        DestroyStatus::AllResourcesCleaned
    );
    assert_eq!(harness_a.manager.sandbox_current_rss_bytes(&lease_a.id), None);
    assert_eq!(
        harness_a.manager.current_admission_usage(),
        AdmissionUsage::default()
    );

    // (b) Bounded FIFO admission queue wakes VM #2 cleanly when VM #1 is destroyed.
    let harness_b = build_phase5_runtime(
        &fixtures,
        "minipod-p5-adm-queue",
        AdmissionLimits {
            max_total_host_rss_mb: Some(600),
            admission_queue_timeout: Duration::from_secs(15),
            max_admission_queue_depth: 4,
            ..Default::default()
        },
        None,
        None,
    );

    let vm1 = harness_b
        .manager
        .spawn(spec.clone())
        .await
        .expect("boot VM #1");

    let mgr_for_vm2 = Arc::clone(&harness_b.manager);
    let spec_for_vm2 = spec.clone();
    let vm2_task = tokio::spawn(async move { mgr_for_vm2.spawn(spec_for_vm2).await });

    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        !vm2_task.is_finished(),
        "VM #2 must block in FIFO admission queue while VM #1 holds 512 MiB"
    );

    assert_eq!(
        harness_b
            .manager
            .destroy(&vm1.id)
            .await
            .expect("destroy VM #1 to release admission slot"),
        DestroyStatus::AllResourcesCleaned
    );

    let vm2 = vm2_task
        .await
        .expect("join VM #2 spawn task")
        .expect("VM #2 must wake up and boot cleanly after VM #1 teardown");

    let usage_b = harness_b.manager.current_admission_usage();
    assert_eq!(usage_b.active_sandboxes, 1);
    assert_eq!(usage_b.reserved_host_rss_mb, 512);
    assert!(
        usage_b.effective_host_rss_mb <= 600,
        "expected effective_host_rss_mb <= 600 MiB while VM #2 runs, got {}",
        usage_b.effective_host_rss_mb
    );

    let rss_b = harness_b
        .manager
        .sandbox_current_rss_bytes(&vm2.id)
        .expect("live QEMU RSS bytes for VM #2");
    assert!(
        rss_b > 0 && rss_b <= 512 * 1024 * 1024,
        "expected VM #2 RSS in (0, 512 MiB], got {rss_b} bytes"
    );

    assert_eq!(
        harness_b
            .manager
            .destroy(&vm2.id)
            .await
            .expect("destroy VM #2"),
        DestroyStatus::AllResourcesCleaned
    );
    assert_eq!(
        harness_b.manager.current_admission_usage(),
        AdmissionUsage::default()
    );
}
