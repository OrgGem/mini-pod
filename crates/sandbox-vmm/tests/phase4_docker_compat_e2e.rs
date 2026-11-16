#![forbid(unsafe_code)]

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bollard::container::{
    Config, CreateContainerOptions, DownloadFromContainerOptions, ListContainersOptions, LogOutput,
    LogsOptions, RemoveContainerOptions, StartContainerOptions, StopContainerOptions,
    UploadToContainerOptions,
};
use bollard::errors::Error as BollardError;
use bollard::exec::{CreateExecOptions, StartExecOptions, StartExecResults};
use bollard::image::ImportImageOptions;
use bollard::models::{HostConfig, Mount, MountTypeEnum, PortBinding};
use bollard::Docker;
use bytes::Bytes;
use futures_util::StreamExt;
use sandbox_core::{
    AccelerationPolicy, DestroyStatus, ExecRequest, ExecTarget, GuestArch, IsolationMode,
    NetworkPolicy, ResourceBudget, SandboxSpec,
};
use sandbox_docker_compat::{DockerCompatPolicy, DockerCompatServer, ReaperSocketPolicy};
use sandbox_image::{
    install_bundle_atomic, BundleOverlayStore, BundleVerifier, InstalledBundle,
};
use sandbox_runtime::{
    AdmissionLimits, LocalRuntimeManager, RuntimeManager, RuntimeManagerConfig, SandboxTunnelPort,
    WarmPoolConfig,
};
use sandbox_vmm::{
    discover_qemu_binary_for_arch, discover_qemu_img_binary, QemuDriverConfig, QemuVmDriver,
};
use tar::{Archive, Builder, Header};
use testcontainers::core::{AccessMode, IntoContainerPort, Mount as TcMount, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{GenericImage, ImageExt};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

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

struct Phase4Fixtures {
    arch: GuestArch,
    src_bundle_dir: PathBuf,
    public_key: [u8; 32],
    qemu_bin: PathBuf,
    qemu_img_bin: PathBuf,
    echo_image_tar: PathBuf,
    ryuk_image_tar: PathBuf,
}

struct Phase4Harness {
    _temp: TestTempDir,
    _installed: InstalledBundle,
    manager: Arc<LocalRuntimeManager>,
}

struct EnvVarGuard {
    saved: Vec<(&'static str, Option<String>)>,
}

impl EnvVarGuard {
    fn new(updates: &[(&'static str, Option<&str>)]) -> Self {
        let mut saved = Vec::with_capacity(updates.len());
        for &(key, val) in updates {
            saved.push((key, std::env::var(key).ok()));
            match val {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
        }
        Self { saved }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        for (key, prev) in self.saved.drain(..).rev() {
            match prev {
                Some(v) => std::env::set_var(key, v),
                None => std::env::remove_var(key),
            }
        }
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

fn parse_hex_32(text: &str) -> [u8; 32] {
    let trimmed = text.trim();
    assert_eq!(trimmed.len(), 64, "expected 64 hex chars for Ed25519 key");
    let mut key = [0u8; 32];
    for (idx, chunk) in trimmed.as_bytes().chunks_exact(2).enumerate() {
        let hex_pair = std::str::from_utf8(chunk).expect("utf-8 hex");
        key[idx] = u8::from_str_radix(hex_pair, 16).expect("valid hex byte");
    }
    key
}

fn discover_phase4_fixtures(test_name: &str) -> Option<Phase4Fixtures> {
    let arch = GuestArch::host_native().unwrap_or(GuestArch::X86_64);
    let root = repo_root();
    let src_bundle_dir = root.join(".cache").join("bundles-src").join(arch.as_str());
    let pub_key_path = root.join(".cache").join("keys").join("dev-bundle.pub");
    let images_dir = root.join(".cache").join("test-images");
    let echo_image_tar = images_dir.join("echo-http.tar");
    let ryuk_image_tar = images_dir.join("ryuk.tar");

    let qemu_bin = discover_qemu_binary_for_arch(arch, None).ok();
    let qemu_img_bin = discover_qemu_img_binary(None).ok();

    let mut missing = Vec::new();
    if !src_bundle_dir.join("manifest.v1").is_file() {
        missing.push(src_bundle_dir.join("manifest.v1").display().to_string());
    }
    if !pub_key_path.is_file() {
        missing.push(pub_key_path.display().to_string());
    }
    if !echo_image_tar.is_file() {
        missing.push(echo_image_tar.display().to_string());
    }
    if !ryuk_image_tar.is_file() {
        missing.push(ryuk_image_tar.display().to_string());
    }
    if qemu_bin.is_none() {
        missing.push("qemu-system binary".to_owned());
    }
    if qemu_img_bin.is_none() {
        missing.push("qemu-img binary".to_owned());
    }

    if !missing.is_empty() {
        let msg = format!(
            "skipping {test_name}: missing Phase 4 E2E fixtures ({})",
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
    Some(Phase4Fixtures {
        arch,
        src_bundle_dir,
        public_key: parse_hex_32(&pub_key_hex),
        qemu_bin: qemu_bin.expect("checked"),
        qemu_img_bin: qemu_img_bin.expect("checked"),
        echo_image_tar,
        ryuk_image_tar,
    })
}

fn build_phase4_runtime(fixtures: &Phase4Fixtures, prefix: &str) -> Phase4Harness {
    let temp = TestTempDir::new(prefix);
    let install_parent = temp.path().join("bundles");
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&install_parent).expect("create bundle install parent");
    fs::create_dir_all(&state_dir).expect("create runtime state dir");

    let verifier =
        BundleVerifier::with_public_key(fixtures.public_key).expect("verifier from pubkey");
    let installed = install_bundle_atomic(&fixtures.src_bundle_dir, &install_parent, &verifier)
        .expect("install signed bundle atomically");
    let overlay = BundleOverlayStore::with_command_runner(
        installed.root_dir().to_path_buf(),
        verifier,
        &fixtures.qemu_img_bin,
        Arc::new(|prog, args, timeout| {
            let out = sandbox_vmm::run_confined_command_bounded(prog, args, timeout, 1024 * 1024)?;
            Ok(sandbox_image::HelperCommandOutput {
                success: out.status.success(),
                status_label: out.status.to_string(),
                stdout: out.stdout,
                stderr: out.stderr,
            })
        }),
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
        admission: AdmissionLimits::default(),
        warm_pool: WarmPoolConfig::default(),
    };

    let manager = Arc::new(
        LocalRuntimeManager::new(config, Arc::new(overlay), Arc::new(driver))
            .expect("build LocalRuntimeManager"),
    );

    Phase4Harness {
        _temp: temp,
        _installed: installed,
        manager,
    }
}

fn phase4_spec(lease_ttl: Duration) -> SandboxSpec {
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

async fn assert_create_rejected_400(docker: &Docker, label: &str, config: Config<String>) {
    let err = docker
        .create_container(None::<CreateContainerOptions<String>>, config)
        .await
        .expect_err(&format!("expected HTTP 400 rejection for {label}"));
    match err {
        BollardError::DockerResponseServerError {
            status_code: 400, ..
        } => {}
        other => panic!("expected 400 for {label}, got: {other:?}"),
    }
}

async fn http_get_loopback(port: u16) -> String {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
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

fn build_single_file_tar(path: &str, content: &[u8]) -> Vec<u8> {
    let mut builder = Builder::new(Vec::new());
    let mut header = Header::new_gnu();
    header.set_path(path).expect("set tar path");
    header.set_size(content.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder
        .append(&header, content)
        .expect("append tar file entry");
    builder.finish().expect("finish tar builder");
    builder.into_inner().expect("extract tar bytes")
}

fn extract_first_tar_file(tar_bytes: &[u8]) -> (String, Vec<u8>) {
    let mut archive = Archive::new(Cursor::new(tar_bytes));
    for entry_res in archive.entries().expect("read downloaded tar entries") {
        let mut entry = entry_res.expect("read tar entry");
        if entry.header().entry_type().is_file() {
            let path = entry.path().expect("tar entry path").display().to_string();
            let mut data = Vec::new();
            entry.read_to_end(&mut data).expect("read tar entry bytes");
            return (path, data);
        }
    }
    panic!("expected at least one file entry in downloaded tar archive");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_bollard_sdk_lifecycle_port_forward_hijack_archive_and_policy() {
    let Some(fixtures) =
        discover_phase4_fixtures("e2e_bollard_sdk_lifecycle_port_forward_hijack_archive_and_policy")
    else {
        return;
    };

    let harness = build_phase4_runtime(&fixtures, "minipod-p4-bollard");
    let lease = harness
        .manager
        .spawn(phase4_spec(Duration::from_secs(180)))
        .await
        .expect("spawn isolated sandbox");

    let compat = Arc::new(DockerCompatServer::new(
        Arc::clone(&harness.manager) as Arc<dyn SandboxTunnelPort>,
        lease.id.clone(),
        DockerCompatPolicy {
            reaper_socket: ReaperSocketPolicy::MapGuestPodmanSocket,
            ..Default::default()
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

    // 1. Connectivity: ping & version.
    let pong = docker.ping().await.expect("docker ping");
    assert_eq!(pong.trim(), "OK");
    let version = docker.version().await.expect("docker version");
    assert!(
        version.api_version.is_some() || version.version.is_some(),
        "expected version info from guest Podman: {version:?}"
    );

    // 2. Offline image import (no external registry pull inside Isolated VM).
    import_tar_image(&docker, &fixtures.echo_image_tar).await;

    // 3. Policy rejections (must fail cleanly with HTTP 400 before container creation).
    assert_create_rejected_400(
        &docker,
        "windows host bind",
        Config {
            image: Some("minipod-e2e/echo-http:1.0".to_owned()),
            host_config: Some(HostConfig {
                binds: Some(vec![r"C:\Users\test:/work".to_owned()]),
                ..Default::default()
            }),
            ..Default::default()
        },
    )
    .await;

    assert_create_rejected_400(
        &docker,
        "unix host bind",
        Config {
            image: Some("minipod-e2e/echo-http:1.0".to_owned()),
            host_config: Some(HostConfig {
                binds: Some(vec!["/Users/test:/work".to_owned()]),
                ..Default::default()
            }),
            ..Default::default()
        },
    )
    .await;

    assert_create_rejected_400(
        &docker,
        "Mounts Type=bind",
        Config {
            image: Some("minipod-e2e/echo-http:1.0".to_owned()),
            host_config: Some(HostConfig {
                mounts: Some(vec![Mount {
                    target: Some("/mnt".to_owned()),
                    source: Some("/etc".to_owned()),
                    typ: Some(MountTypeEnum::BIND),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        },
    )
    .await;

    assert_create_rejected_400(
        &docker,
        "Privileged=true",
        Config {
            image: Some("minipod-e2e/echo-http:1.0".to_owned()),
            host_config: Some(HostConfig {
                privileged: Some(true),
                ..Default::default()
            }),
            ..Default::default()
        },
    )
    .await;

    // 4. Create & start echo-http with ephemeral published port 8080/tcp.
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
                host_config: Some(HostConfig {
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

    // 5. Inspect & list must expose rewritten 127.0.0.1:<host_port>.
    let inspected = docker
        .inspect_container(&cid, None)
        .await
        .expect("inspect running container");
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

    let listed = docker
        .list_containers(Some(ListContainersOptions::<String> {
            all: false,
            ..Default::default()
        }))
        .await
        .expect("list running containers");
    let summary = listed
        .iter()
        .find(|c| c.id.as_deref() == Some(cid.as_str()))
        .expect("created container present in list_containers");
    assert!(
        summary
            .ports
            .as_ref()
            .into_iter()
            .flatten()
            .any(|p| p.private_port == 8080 && p.public_port == Some(host_port)),
        "list_containers missing rewritten public_port {host_port}: {summary:?}"
    );

    // 6. Connect directly to forwarded Host TCP port and verify HTTP response.
    let http_resp = http_get_loopback(host_port).await;
    assert!(
        http_resp.starts_with("HTTP/1.1 200 OK") && http_resp.contains("hello-minipod"),
        "unexpected forwarded HTTP response: {http_resp:?}"
    );

    // 7. Follow logs stream and observe startup banner.
    let logs_seen = tokio::time::timeout(Duration::from_secs(10), async {
        let mut logs = docker.logs(
            &cid,
            Some(LogsOptions::<String> {
                follow: true,
                stdout: true,
                stderr: true,
                ..Default::default()
            }),
        );
        let mut acc = String::new();
        while let Some(item) = logs.next().await {
            match item.expect("container log chunk") {
                LogOutput::StdOut { message }
                | LogOutput::StdErr { message }
                | LogOutput::Console { message }
                | LogOutput::StdIn { message } => {
                    acc.push_str(&String::from_utf8_lossy(&message));
                    if acc.contains("READY_ON_8080") {
                        return acc;
                    }
                }
            }
        }
        acc
    })
    .await
    .expect("timeout waiting for READY_ON_8080 log line");
    assert!(logs_seen.contains("READY_ON_8080"));

    // 8. Interactive exec hijack (101 UPGRADED) with stdin half-close (EOF).
    let exec_created = docker
        .create_exec(
            &cid,
            CreateExecOptions {
                attach_stdin: Some(true),
                attach_stdout: Some(true),
                attach_stderr: Some(true),
                cmd: Some(vec!["/bin/sh", "-c", "cat"]),
                ..Default::default()
            },
        )
        .await
        .expect("create interactive exec");

    let start_res = docker
        .start_exec(
            &exec_created.id,
            Some(StartExecOptions {
                detach: false,
                ..Default::default()
            }),
        )
        .await
        .expect("start upgraded exec");

    let StartExecResults::Attached {
        mut output,
        mut input,
    } = start_res
    else {
        panic!("expected StartExecResults::Attached");
    };

    input
        .write_all(b"hijack-half-close-payload\n")
        .await
        .expect("write exec stdin");
    input.flush().await.expect("flush exec stdin");
    input.shutdown().await.expect("half-close exec stdin EOF");

    let hijack_out = tokio::time::timeout(Duration::from_secs(10), async {
        let mut out = String::new();
        while let Some(chunk) = output.next().await {
            match chunk.expect("exec output chunk") {
                LogOutput::StdOut { message } => out.push_str(&String::from_utf8_lossy(&message)),
                LogOutput::StdErr { message } => out.push_str(&String::from_utf8_lossy(&message)),
                _ => {}
            }
        }
        out
    })
    .await
    .expect("timeout waiting for exec stdout after stdin half-close");
    assert!(
        hijack_out.contains("hijack-half-close-payload"),
        "unexpected exec hijack stdout: {hijack_out:?}"
    );

    let inspect_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let exec_info = docker
            .inspect_exec(&exec_created.id)
            .await
            .expect("inspect completed exec");
        if exec_info.running == Some(false) {
            assert_eq!(exec_info.exit_code, Some(0));
            break;
        }
        assert!(
            tokio::time::Instant::now() < inspect_deadline,
            "exec instance did not report stopped"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // 9. Container /archive upload + download round-trip.
    let upload_tar = build_single_file_tar("hello.txt", b"minipod-archive-roundtrip\n");
    docker
        .upload_to_container(
            &cid,
            Some(UploadToContainerOptions {
                path: "/work",
                no_overwrite_dir_non_dir: "true",
            }),
            Bytes::from(upload_tar),
        )
        .await
        .expect("upload_to_container tar");

    let mut dl_stream = docker.download_from_container(
        &cid,
        Some(DownloadFromContainerOptions {
            path: "/work/hello.txt",
        }),
    );
    let mut dl_bytes = Vec::new();
    while let Some(chunk) = dl_stream.next().await {
        dl_bytes.extend_from_slice(&chunk.expect("download_from_container chunk"));
    }
    let (dl_name, dl_content) = extract_first_tar_file(&dl_bytes);
    assert!(
        dl_name.ends_with("hello.txt"),
        "unexpected archive entry name: {dl_name}"
    );
    assert_eq!(dl_content, b"minipod-archive-roundtrip\n");

    // 10. Direct RuntimeManager::exec_stream with ExecTarget::Container.
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
                    "echo direct-container-exec && cat /work/hello.txt".to_owned(),
                ],
                env: BTreeMap::new(),
                cwd: Some("/work".to_owned()),
                user: None,
                deadline: Duration::from_secs(15),
                stdout_budget_bytes: 64 * 1024,
                stderr_budget_bytes: 64 * 1024,
            },
        )
        .await
        .expect("exec_stream with ExecTarget::Container");
    let direct_out = direct_stream
        .collect()
        .await
        .expect("collect ExecTarget::Container output");
    assert_eq!(direct_out.exit.code, Some(0));
    let direct_stdout = String::from_utf8_lossy(&direct_out.stdout);
    assert!(
        direct_stdout.contains("direct-container-exec")
            && direct_stdout.contains("minipod-archive-roundtrip"),
        "unexpected ExecTarget::Container stdout: {direct_stdout:?}"
    );

    // 11. Stop & remove container, verifying Host port forward closes promptly.
    docker
        .stop_container(&cid, Some(StopContainerOptions { t: 2 }))
        .await
        .expect("stop container");
    assert_loopback_port_closed(host_port).await;

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

    // 12. Clean shutdown & VM teardown.
    server.shutdown().await;
    let status = harness
        .manager
        .destroy(&lease.id)
        .await
        .expect("destroy sandbox");
    assert_eq!(status, DestroyStatus::AllResourcesCleaned);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_testcontainers_full_lifecycle_and_ryuk_reaper() {
    let Some(fixtures) =
        discover_phase4_fixtures("e2e_testcontainers_full_lifecycle_and_ryuk_reaper")
    else {
        return;
    };

    let harness = build_phase4_runtime(&fixtures, "minipod-p4-tc");
    let lease = harness
        .manager
        .spawn(phase4_spec(Duration::from_secs(180)))
        .await
        .expect("spawn isolated sandbox");

    let compat = Arc::new(DockerCompatServer::new(
        Arc::clone(&harness.manager) as Arc<dyn SandboxTunnelPort>,
        lease.id.clone(),
        DockerCompatPolicy {
            reaper_socket: ReaperSocketPolicy::MapGuestPodmanSocket,
            ..Default::default()
        },
    ));
    let server = compat
        .bind_loopback_http("127.0.0.1:0".parse().expect("loopback addr"))
        .await
        .expect("bind DockerCompatServer");

    let base_url = format!("http://{}", server.local_addr());
    let docker = Docker::connect_with_http(&base_url, 60, bollard::API_DEFAULT_VERSION)
        .expect("connect bollard HTTP client");

    import_tar_image(&docker, &fixtures.echo_image_tar).await;
    import_tar_image(&docker, &fixtures.ryuk_image_tar).await;

    let docker_host = format!("tcp://{}", server.local_addr());
    let _env_guard = EnvVarGuard::new(&[
        ("DOCKER_HOST", Some(docker_host.as_str())),
        ("TESTCONTAINERS_COMMAND", Some("remove")),
    ]);

    // 1. Start Ryuk via testcontainers with standard /var/run/docker.sock bind mount
    // (rewritten to /run/podman/podman.sock by DockerCompatServer).
    let ryuk = GenericImage::new("testcontainers/ryuk", "0.11.0")
        .with_exposed_port(8080.tcp())
        .with_wait_for(WaitFor::message_on_stdout("Started"))
        .with_mount(
            TcMount::bind_mount("/var/run/docker.sock", "/var/run/docker.sock")
                .with_access_mode(AccessMode::ReadWrite),
        )
        .start()
        .await
        .expect("start testcontainers/ryuk via Testcontainers");

    let ryuk_inspect = docker
        .inspect_container(ryuk.id(), None)
        .await
        .expect("inspect ryuk container");
    let has_reaper_socket = ryuk_inspect
        .host_config
        .as_ref()
        .and_then(|hc| hc.mounts.as_ref())
        .into_iter()
        .flatten()
        .any(|m| {
            m.source.as_deref() == Some("/run/podman/podman.sock")
                && m.target.as_deref() == Some("/var/run/docker.sock")
        })
        || ryuk_inspect
            .host_config
            .as_ref()
            .and_then(|hc| hc.binds.as_ref())
            .into_iter()
            .flatten()
            .any(|b| b.starts_with("/run/podman/podman.sock:/var/run/docker.sock"));
    assert!(
        has_reaper_socket,
        "expected Ryuk socket mount rewritten to /run/podman/podman.sock: {:?}",
        ryuk_inspect.host_config
    );

    // 2. Start workload container via testcontainers AsyncRunner.
    let echo = GenericImage::new("minipod-e2e/echo-http", "1.0")
        .with_exposed_port(8080.tcp())
        .with_wait_for(WaitFor::message_on_stdout("READY_ON_8080"))
        .start()
        .await
        .expect("start minipod-e2e/echo-http via Testcontainers");

    let running = docker
        .list_containers(Some(ListContainersOptions::<String> {
            all: false,
            ..Default::default()
        }))
        .await
        .expect("list active containers");
    assert!(running.iter().any(|c| c.id.as_deref() == Some(ryuk.id())));
    assert!(running.iter().any(|c| c.id.as_deref() == Some(echo.id())));

    // 3. Verify mapped host port & logs through Testcontainers ContainerAsync API.
    let echo_port = echo
        .get_host_port_ipv4(8080)
        .await
        .expect("get_host_port_ipv4(8080)");
    let body = http_get_loopback(echo_port).await;
    assert!(
        body.starts_with("HTTP/1.1 200 OK") && body.contains("hello-minipod"),
        "unexpected HTTP response via Testcontainers port: {body:?}"
    );
    let tc_stdout = String::from_utf8_lossy(
        &echo
            .stdout_to_vec()
            .await
            .expect("read container stdout via Testcontainers"),
    )
    .into_owned();
    assert!(tc_stdout.contains("READY_ON_8080"));

    // 4. Prove Ryuk reaper deletes labeled containers over /var/run/docker.sock -> /run/podman/podman.sock
    // once client closes its Ryuk TCP stream (simulated crash/disconnect).
    let session_id = "minipod-ryuk-e2e-session";
    let orphan = docker
        .create_container(
            None::<CreateContainerOptions<String>>,
            Config {
                image: Some("minipod-e2e/echo-http:1.0".to_owned()),
                labels: Some(HashMap::from([(
                    "org.testcontainers.session-id".to_owned(),
                    session_id.to_owned(),
                )])),
                ..Default::default()
            },
        )
        .await
        .expect("create labeled orphan container");
    let orphan_id = orphan.id;
    docker
        .start_container(&orphan_id, None::<StartContainerOptions<String>>)
        .await
        .expect("start labeled orphan container");

    let ryuk_port = ryuk
        .get_host_port_ipv4(8080)
        .await
        .expect("get ryuk mapped port");
    {
        let stream = TcpStream::connect(("127.0.0.1", ryuk_port))
            .await
            .expect("connect to forwarded Ryuk TCP port");
        let (rx, mut tx) = stream.into_split();
        let mut reader = BufReader::new(rx);
        tx.write_all(format!("label=org.testcontainers.session-id={session_id}\n").as_bytes())
            .await
            .expect("send Ryuk label filter");
        tx.flush().await.expect("flush Ryuk filter");

        let mut ack = String::new();
        tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut ack))
            .await
            .expect("timeout waiting for Ryuk ACK")
            .expect("read Ryuk ACK");
        assert_eq!(ack.trim(), "ACK", "unexpected Ryuk response: {ack:?}");
        // Dropping `tx` + `reader` closes the TCP connection to trigger Ryuk reaping.
    }

    let reap_deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    loop {
        let all = docker
            .list_containers(Some(ListContainersOptions::<String> {
                all: true,
                ..Default::default()
            }))
            .await
            .expect("poll containers during Ryuk reap");
        if !all.iter().any(|c| c.id.as_deref() == Some(orphan_id.as_str())) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < reap_deadline,
            "Ryuk did not reap labeled container {orphan_id} via /run/podman/podman.sock"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // 5. Verify Testcontainers ContainerAsync::Drop removes `echo` cleanly, then remove `ryuk`.
    let echo_id = echo.id().to_owned();
    drop(echo);

    let drop_deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let all = docker
            .list_containers(Some(ListContainersOptions::<String> {
                all: true,
                ..Default::default()
            }))
            .await
            .expect("check container removal after Testcontainers Drop");
        if !all.iter().any(|c| c.id.as_deref() == Some(echo_id.as_str())) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < drop_deadline,
            "Testcontainers Drop did not remove container {echo_id}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    ryuk.rm().await.expect("remove ryuk container cleanly");
    drop(_env_guard);

    server.shutdown().await;
    let status = harness
        .manager
        .destroy(&lease.id)
        .await
        .expect("destroy sandbox");
    assert_eq!(status, DestroyStatus::AllResourcesCleaned);
}
