//! End-to-end Phase 3 runtime tests exercising real QEMU guests and signed bundles.

use std::collections::BTreeMap;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sandbox_core::{
    AccelerationPolicy, DestroyStatus, EgressRule, EnforcementLevel, ExecRequest, ExecTarget,
    GuestArch, IsolationMode, NetworkPolicy, ResourceBudget, SandboxError, SandboxId, SandboxSpec,
};
use sandbox_image::{
    decode_hex_exact, install_bundle_atomic, BundleOverlayStore, BundleVerifier, InstalledBundle,
};
use sandbox_runtime::{
    AdmissionLimits, CollectedExecOutput, JournalLifecycleState, JournalRecord, JournalStore,
    LocalRuntimeManager, RuntimeManager, RuntimeManagerConfig, WarmPoolConfig,
};
use sandbox_vmm::{
    discover_qemu_binary_for_arch, discover_qemu_img_binary, kill_verified_orphan_process,
    ConfinedProcess, ProcessLaunchSpec, QemuDriverConfig, QemuVmDriver,
};

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
        let path = std::env::temp_dir().join(format!("{prefix}-{}-{seq}-{nanos}", std::process::id()));
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

struct TestFixtures {
    arch: GuestArch,
    src_bundle_dir: PathBuf,
    public_key: [u8; 32],
    public_key_hex: String,
    qemu_bin: PathBuf,
    qemu_img_bin: PathBuf,
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crates dir")
        .parent()
        .expect("repo root")
        .to_path_buf()
}

fn discover_fixtures(test_name: &str) -> Option<TestFixtures> {
    let arch = GuestArch::host_native().unwrap_or(GuestArch::X86_64);
    let root = repo_root();
    let src_bundle_dir = root.join(".cache").join("bundles-src").join(arch.as_str());
    let pub_key_path = root.join(".cache").join("keys").join("dev-bundle.pub");

    if !src_bundle_dir.join("manifest.v1").is_file() || !pub_key_path.is_file() {
        eprintln!(
            "[phase3_runtime_e2e::{test_name}] SKIPPED: prebuilt bundle fixtures missing at {}",
            src_bundle_dir.display()
        );
        return None;
    }

    let public_key_hex = match fs::read_to_string(&pub_key_path) {
        Ok(raw) => raw.trim().to_owned(),
        Err(err) => {
            eprintln!("[phase3_runtime_e2e::{test_name}] SKIPPED: failed reading pub key: {err}");
            return None;
        }
    };
    let public_key = decode_hex_exact::<32>(&public_key_hex).expect("valid 32-byte dev pub key");

    let qemu_bin = match discover_qemu_binary_for_arch(arch, None) {
        Ok(path) => path,
        Err(err) => {
            eprintln!("[phase3_runtime_e2e::{test_name}] SKIPPED: QEMU binary unavailable: {err}");
            return None;
        }
    };
    let qemu_img_bin = match discover_qemu_img_binary(None) {
        Ok(path) => path,
        Err(err) => {
            eprintln!(
                "[phase3_runtime_e2e::{test_name}] SKIPPED: qemu-img binary unavailable: {err}"
            );
            return None;
        }
    };

    Some(TestFixtures {
        arch,
        src_bundle_dir,
        public_key,
        public_key_hex,
        qemu_bin,
        qemu_img_bin,
    })
}

struct TestRuntimeHarness {
    _temp: TestTempDir,
    state_dir: PathBuf,
    _installed: InstalledBundle,
    manager: Arc<LocalRuntimeManager>,
}

fn try_build_manager_for_installed_bundle(
    arch: GuestArch,
    bundle_root: &Path,
    public_key: [u8; 32],
    qemu_bin: &Path,
    qemu_img_bin: &Path,
    state_dir: &Path,
) -> Result<Arc<LocalRuntimeManager>, SandboxError> {
    let verifier = BundleVerifier::with_public_key(public_key).expect("verifier from pubkey");
    let overlay = BundleOverlayStore::with_command_runner(
        bundle_root.to_path_buf(),
        verifier,
        qemu_img_bin,
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
        arch,
        qemu_bin: Some(qemu_bin.to_path_buf()),
        boot_timeout: Duration::from_secs(45),
        io_timeout: Duration::from_secs(30),
        runtime_parent_dir: None,
    })
    .expect("build QemuVmDriver");

    let config = RuntimeManagerConfig {
        state_dir: state_dir.to_path_buf(),
        sweep_interval: Duration::from_millis(250),
        graceful_shutdown_timeout: Duration::from_secs(3),
        max_copy_bytes: 16 * 1024 * 1024,
        max_copy_entries: 4096,
        cleanup_max_attempts: 8,
        cleanup_initial_delay: Duration::from_millis(50),
        admission: AdmissionLimits::default(),
        warm_pool: WarmPoolConfig::default(),
    };

    LocalRuntimeManager::new(config, Arc::new(overlay), Arc::new(driver)).map(Arc::new)
}

fn build_manager_for_installed_bundle(
    arch: GuestArch,
    bundle_root: &Path,
    public_key: [u8; 32],
    qemu_bin: &Path,
    qemu_img_bin: &Path,
    state_dir: &Path,
) -> Arc<LocalRuntimeManager> {
    try_build_manager_for_installed_bundle(
        arch,
        bundle_root,
        public_key,
        qemu_bin,
        qemu_img_bin,
        state_dir,
    )
    .expect("build LocalRuntimeManager")
}

fn build_test_runtime(fixtures: &TestFixtures, prefix: &str) -> TestRuntimeHarness {
    let temp = TestTempDir::new(prefix);
    let install_parent = temp.path().join("bundles");
    let state_dir = temp.path().join("state");
    fs::create_dir_all(&install_parent).expect("create bundle install parent");
    fs::create_dir_all(&state_dir).expect("create runtime state dir");

    let verifier =
        BundleVerifier::with_public_key(fixtures.public_key).expect("verifier from pubkey");
    let installed = install_bundle_atomic(&fixtures.src_bundle_dir, &install_parent, &verifier)
        .expect("install signed bundle atomically");
    let manager = build_manager_for_installed_bundle(
        fixtures.arch,
        installed.root_dir(),
        fixtures.public_key,
        &fixtures.qemu_bin,
        &fixtures.qemu_img_bin,
        &state_dir,
    );

    TestRuntimeHarness {
        _temp: temp,
        state_dir,
        _installed: installed,
        manager,
    }
}

fn default_spec(lease_ttl: Duration) -> SandboxSpec {
    SandboxSpec {
        isolation: IsolationMode::VmRequired,
        acceleration: AccelerationPolicy::Preferred,
        network: NetworkPolicy::Isolated,
        budget: ResourceBudget {
            guest_vcpus: 1,
            host_cpu_quota_Millicores: None,
            guest_ram_mb: 256,
            host_rss_budget_mb: Some(512),
            virtual_disk_mb: 256,
            host_storage_budget_mb: 512,
        },
        lease_ttl,
    }
}

fn shell_request(
    script: &str,
    deadline: Duration,
    stdout_budget_bytes: u64,
    stderr_budget_bytes: u64,
) -> ExecRequest {
    ExecRequest {
        target: ExecTarget::Guest,
        argv: vec![
            "/bin/sh".to_owned(),
            "-c".to_owned(),
            script.to_owned(),
        ],
        env: BTreeMap::new(),
        cwd: None,
        user: None,
        deadline,
        stdout_budget_bytes,
        stderr_budget_bytes,
    }
}

async fn run_shell(
    mgr: &LocalRuntimeManager,
    id: &SandboxId,
    script: &str,
    deadline: Duration,
) -> Result<CollectedExecOutput, SandboxError> {
    let stream = mgr
        .exec_stream(id, shell_request(script, deadline, 1024 * 1024, 256 * 1024))
        .await?;
    stream.collect().await
}

fn sandbox_work_dir(state_dir: &Path, id: &SandboxId) -> PathBuf {
    state_dir.join("sandboxes").join(id.as_str())
}

fn unix_ms_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[tokio::test]
async fn e2e_safe_copy_in_exec_copy_out_and_reject_guest_symlink() {
    let Some(fixtures) = discover_fixtures("safe_copy") else {
        return;
    };
    let harness = build_test_runtime(&fixtures, "mp-p3-copy");
    let mgr = &harness.manager;

    // Reject SharedKernelAllowed and malformed DomainAllowList policies upfront.
    let mut bad_isolation = default_spec(Duration::from_secs(30));
    bad_isolation.isolation = IsolationMode::SharedKernelAllowed;
    let err_isolation = mgr
        .spawn(bad_isolation)
        .await
        .expect_err("SharedKernelAllowed must be rejected");
    assert!(
        matches!(
            err_isolation,
            SandboxError::UnsupportedIsolationMode(_) | SandboxError::PolicyViolation(_)
        ),
        "unexpected error for SharedKernelAllowed: {err_isolation:?}"
    );

    let mut bad_net = default_spec(Duration::from_secs(30));
    bad_net.network = NetworkPolicy::DomainAllowList {
        rules: vec![EgressRule {
            domain: "example.com".to_owned(),
            port: 0,
        }],
    };
    let err_net = mgr
        .spawn(bad_net)
        .await
        .expect_err("malformed DomainAllowList with port 0 must fail validation");
    assert!(
        matches!(err_net, SandboxError::InvalidSpec(_)),
        "expected InvalidSpec for malformed DomainAllowList, got: {err_net:?}"
    );

    // Boot isolated VM and verify enforced isolation capability.
    let lease = mgr
        .spawn(default_spec(Duration::from_secs(60)))
        .await
        .expect("spawn VmRequired + Isolated VM");
    // sandbox-core models enforced containment with EnforcementLevel::HardLimit.
    assert_eq!(lease.capabilities.egress_filter, EnforcementLevel::HardLimit);

    // Confirm guest has loopback only and no external network routes (-nic none).
    let net_check = run_shell(
        mgr,
        &lease.id,
        "ls -1 /sys/class/net && echo ===ROUTE=== && awk 'NR>1{print $1}' /proc/net/route",
        Duration::from_secs(10),
    )
    .await
    .expect("query guest network interfaces");
    assert_eq!(net_check.exit.code, Some(0));
    let net_stdout = String::from_utf8_lossy(&net_check.stdout);
    let (ifaces, routes) = net_stdout
        .split_once("===ROUTE===")
        .expect("network check delimiter");
    assert_eq!(ifaces.trim(), "lo", "unexpected guest interfaces: {ifaces:?}");
    assert_eq!(routes.trim(), "", "unexpected guest routes: {routes:?}");

    // Stage host workspace directory -> copy_in -> transform with stdin -> copy_out -> verify bytes.
    let host_ws = TestTempDir::new("mp-p3-ws");
    let host_in = host_ws.path().join("in");
    let host_out = host_ws.path().join("out");
    let host_evil_out = host_ws.path().join("evil_out");
    fs::create_dir_all(host_in.join("sub")).expect("create host_in");
    fs::create_dir_all(&host_out).expect("create host_out");
    fs::create_dir_all(&host_evil_out).expect("create host_evil_out");

    fs::write(host_in.join("input.txt"), b"hello\nmini-pod\nphase3\n").expect("write input.txt");
    let binary_payload = vec![0u8, 1, 2, 255, 42, 128];
    fs::write(host_in.join("sub").join("meta.bin"), &binary_payload).expect("write meta.bin");

    mgr.copy_in(&lease.id, host_in.clone(), "/tmp/work_in".to_owned())
        .await
        .expect("copy_in host workspace");

    let stream = mgr
        .exec_stream(
            &lease.id,
            shell_request(
                "mkdir -p /tmp/work_out/nested && \
                 tr a-z A-Z < /tmp/work_in/input.txt > /tmp/work_out/result.txt && \
                 cat - >> /tmp/work_out/result.txt && \
                 cp /tmp/work_in/sub/meta.bin /tmp/work_out/nested/meta.bin && \
                 echo processed-ok && \
                 echo warn-stream >&2",
                Duration::from_secs(15),
                1024 * 1024,
                256 * 1024,
            ),
        )
        .await
        .expect("start transforming exec_stream");
    stream
        .write_stdin(b"FROM_STDIN\n".to_vec())
        .await
        .expect("write stdin payload");
    let collected = stream.collect().await.expect("collect transform stream");
    assert_eq!(collected.exit.code, Some(0));
    assert_eq!(String::from_utf8_lossy(&collected.stdout), "processed-ok\n");
    assert_eq!(String::from_utf8_lossy(&collected.stderr), "warn-stream\n");

    mgr.copy_out(&lease.id, "/tmp/work_out".to_owned(), host_out.clone())
        .await
        .expect("copy_out /tmp/work_out");
    assert_eq!(
        fs::read(host_out.join("result.txt")).expect("read result.txt"),
        b"HELLO\nMINI-POD\nPHASE3\nFROM_STDIN\n"
    );
    assert_eq!(
        fs::read(host_out.join("nested").join("meta.bin")).expect("read copied meta.bin"),
        binary_payload
    );

    // Create a malicious symlink inside guest and confirm copy_out rejects it without writing to host.
    let evil_setup = run_shell(
        mgr,
        &lease.id,
        "mkdir -p /tmp/evil_dir && echo ok > /tmp/evil_dir/ok.txt && ln -s /etc/passwd /tmp/evil_dir/passwd_link",
        Duration::from_secs(10),
    )
    .await
    .expect("create guest symlink directory");
    assert_eq!(evil_setup.exit.code, Some(0));

    let copy_evil_err = mgr
        .copy_out(&lease.id, "/tmp/evil_dir".to_owned(), host_evil_out.clone())
        .await
        .expect_err("copy_out must reject guest symlinks");
    assert!(
        matches!(copy_evil_err, SandboxError::PolicyViolation(_)),
        "expected PolicyViolation for guest symlink, got {copy_evil_err:?}"
    );
    assert!(
        !host_evil_out.join("passwd_link").exists() && !host_evil_out.join("ok.txt").exists(),
        "rejected copy_out must not leave symlink or partial files on host"
    );

    // Destroy twice and verify idempotency.
    assert_eq!(
        mgr.destroy(&lease.id).await.expect("first destroy"),
        DestroyStatus::AllResourcesCleaned
    );
    assert_eq!(
        mgr.destroy(&lease.id).await.expect("second idempotent destroy"),
        DestroyStatus::AllResourcesCleaned
    );
}

#[tokio::test]
async fn e2e_ttl_lease_renewal_and_automatic_expiry() {
    let Some(fixtures) = discover_fixtures("ttl_lease") else {
        return;
    };
    let harness = build_test_runtime(&fixtures, "mp-p3-ttl");
    let mgr = Arc::clone(&harness.manager);
    let sweeper = mgr.spawn_lease_sweeper();

    let lease = mgr
        .spawn(default_spec(Duration::from_secs(4)))
        .await
        .expect("spawn short-TTL sandbox");
    let work_dir = sandbox_work_dir(&harness.state_dir, &lease.id);
    let overlay_path = work_dir.join("overlay.qcow2");
    assert!(overlay_path.is_file(), "overlay.qcow2 should exist while active");

    // Renew before initial 4s TTL elapses.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    mgr.renew_lease(&lease.id, Duration::from_secs(4))
        .await
        .expect("renew sandbox lease");

    // Sleep past the original 4s expiry (~4.3s elapsed since spawn) and verify still alive.
    tokio::time::sleep(Duration::from_millis(2800)).await;
    let alive = run_shell(&mgr, &lease.id, "echo still-alive", Duration::from_secs(10))
        .await
        .expect("sandbox must stay alive past original TTL after renew_lease");
    assert_eq!(alive.exit.code, Some(0));
    assert_eq!(alive.stdout, b"still-alive\n");

    // Wait past the renewed TTL until sweeper tears down VM and deletes overlay artifacts.
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut expired_seen = false;
    let mut cleaned_seen = false;
    while Instant::now() < deadline {
        let exec_res = run_shell(&mgr, &lease.id, "echo expired", Duration::from_secs(5)).await;
        if matches!(
            exec_res,
            Err(SandboxError::LeaseExpired(_)) | Err(SandboxError::NotFound(_))
        ) {
            expired_seen = true;
            if !work_dir.exists() && !overlay_path.exists() {
                cleaned_seen = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    sweeper.abort();
    assert!(expired_seen, "expected exec_stream to fail after lease expiration");
    assert!(
        cleaned_seen,
        "expected sweeper cleanup of {} and {}",
        work_dir.display(),
        overlay_path.display()
    );
}

#[tokio::test]
async fn e2e_stdout_budget_deadline_priority_cancel_and_disk_cap() {
    let Some(fixtures) = discover_fixtures("budgets") else {
        return;
    };
    let harness = build_test_runtime(&fixtures, "mp-p3-budget");
    let mgr = &harness.manager;

    // Verify oversized virtual_disk_mb against host_storage_budget_mb fails admission.
    let mut bad_disk = default_spec(Duration::from_secs(60));
    bad_disk.budget.virtual_disk_mb = 320;
    bad_disk.budget.host_storage_budget_mb = 192;
    let disk_err = mgr
        .spawn(bad_disk)
        .await
        .expect_err("virtual_disk_mb > host_storage_budget_mb must fail");
    assert!(
        matches!(disk_err, SandboxError::BudgetExceeded(_)),
        "expected BudgetExceeded, got {disk_err:?}"
    );

    let mut bounded_spec = default_spec(Duration::from_secs(90));
    bounded_spec.budget.virtual_disk_mb = 256;
    bounded_spec.budget.host_storage_budget_mb = 320;
    let lease = mgr.spawn(bounded_spec).await.expect("spawn bounded VM");

    // 1. stdout_budget_bytes truncation + verification that runaway flood process group was killed.
    let flood_budget = mgr
        .exec_stream(
            &lease.id,
            shell_request(
                "while :; do printf AAAAAAAAAAAAAAAA; done",
                Duration::from_secs(15),
                8192,
                4096,
            ),
        )
        .await
        .expect("start stdout flood command");
    let flood_out = flood_budget.collect().await.expect("collect bounded flood");
    assert!(
        flood_out.exit.stdout_truncated,
        "expected stdout_truncated == true, got {:?}",
        flood_out.exit
    );
    assert!(!flood_out.exit.timed_out);
    assert!(flood_out.exit.code.is_none());
    assert!(
        flood_out.stdout.len() <= 8192,
        "received stdout ({}) exceeded 8192 byte cap",
        flood_out.stdout.len()
    );

    let ps_after_budget = run_shell(mgr, &lease.id, "ps", Duration::from_secs(10))
        .await
        .expect("inspect guest processes after budget truncation");
    let ps_budget_txt = String::from_utf8_lossy(&ps_after_budget.stdout);
    assert!(
        !ps_budget_txt.contains("AAAAAAAA"),
        "runaway flood child survived budget enforcement: {ps_budget_txt}"
    );

    // 2. Priority ExecCancel preemption under active stdout flood.
    let mut cancel_stream = mgr
        .exec_stream(
            &lease.id,
            shell_request(
                "while :; do printf BBBBBBBBBBBBBBBB; done",
                Duration::from_secs(20),
                64 * 1024 * 1024,
                64 * 1024,
            ),
        )
        .await
        .expect("start cancellable flood");
    let first_chunk = tokio::time::timeout(Duration::from_secs(5), cancel_stream.next_output())
        .await
        .expect("timed out waiting for first flood chunk")
        .expect("flood stream closed before emitting chunk");
    assert!(!first_chunk.data.is_empty());

    let cancel_started = Instant::now();
    cancel_stream.cancel().expect("send priority ExecCancel");
    let canceled = tokio::time::timeout(Duration::from_secs(8), cancel_stream.collect())
        .await
        .expect("ExecCancel did not terminate stream promptly")
        .expect("collect canceled flood");
    assert!(
        cancel_started.elapsed() < Duration::from_secs(8),
        "cancel took too long: {:?}",
        cancel_started.elapsed()
    );
    assert!(!canceled.exit.timed_out, "canceled stream reported timed_out");
    assert!(canceled.exit.code.is_none(), "expected None code on cancel");

    let ps_after_cancel = run_shell(mgr, &lease.id, "ps", Duration::from_secs(10))
        .await
        .expect("inspect guest processes after cancel");
    let ps_cancel_txt = String::from_utf8_lossy(&ps_after_cancel.stdout);
    assert!(
        !ps_cancel_txt.contains("BBBBBBBB"),
        "runaway flood child survived cancel: {ps_cancel_txt}"
    );

    // 3. Execution deadline kill.
    let timed = run_shell(
        mgr,
        &lease.id,
        "sleep 30",
        Duration::from_millis(500),
    )
    .await
    .expect("execute deadline-bound sleep");
    assert!(timed.exit.timed_out, "expected timed_out == true");
    assert!(timed.exit.code.is_none(), "expected None exit code on timeout");

    let ps_after_timeout = run_shell(mgr, &lease.id, "ps", Duration::from_secs(10))
        .await
        .expect("inspect guest processes after timeout");
    let ps_timeout_txt = String::from_utf8_lossy(&ps_after_timeout.stdout);
    assert!(
        !ps_timeout_txt.contains("sleep 30"),
        "sleep child survived deadline kill: {ps_timeout_txt}"
    );

    // 4. Bounded disk containment on the 256 MiB overlay and clean reclamation on destroy.
    let disk_fill = run_shell(
        mgr,
        &lease.id,
        "dd if=/dev/zero of=/tmp/fill.bin bs=1M count=320",
        Duration::from_secs(20),
    )
    .await
    .expect("execute bounded disk fill inside guest");
    assert_ne!(
        disk_fill.exit.code,
        Some(0),
        "writing 320 MiB into 256 MiB ext4 rootfs must fail with ENOSPC"
    );

    let work_dir = sandbox_work_dir(&harness.state_dir, &lease.id);
    let overlay_path = work_dir.join("overlay.qcow2");
    let overlay_bytes = fs::metadata(&overlay_path)
        .expect("stat overlay.qcow2")
        .len();
    assert!(
        overlay_bytes <= 320 * 1024 * 1024,
        "overlay.qcow2 ({overlay_bytes} bytes) exceeded host_storage_budget_mb (320 MiB)"
    );

    assert_eq!(
        mgr.destroy(&lease.id).await.expect("destroy bounded VM"),
        DestroyStatus::AllResourcesCleaned
    );
    assert!(
        !work_dir.exists() && !overlay_path.exists(),
        "destroy must reclaim all overlay storage artifacts"
    );
}

#[tokio::test]
async fn e2e_crash_recovery_orphan_kill_and_cleanup() {
    if std::env::var_os("MINIPOD_P3_DAEMON_HELPER").is_some() {
        run_simulated_daemon_helper().await;
        return;
    }

    let Some(fixtures) = discover_fixtures("crash_recovery") else {
        return;
    };

    // Case (a): Live orphan ConfinedProcess recorded in JournalStore with leftover overlay artifacts.
    {
        let harness = build_test_runtime(&fixtures, "mp-p3-rec-a");
        let orphan_id = SandboxId::new("orphan-live-1");
        let work_dir = sandbox_work_dir(&harness.state_dir, &orphan_id);
        fs::create_dir_all(&work_dir).expect("create orphan work_dir");
        let overlay_path = work_dir.join("overlay.qcow2");
        fs::write(&overlay_path, b"leftover-orphan-qcow2").expect("write orphan overlay");

        let spec = ProcessLaunchSpec::new(
            &fixtures.qemu_bin,
            vec![
                "-nodefaults".into(),
                "-machine".into(),
                "none".into(),
                "-display".into(),
                "none".into(),
                "-S".into(),
            ],
        );
        let mut orphan_proc = ConfinedProcess::spawn(spec).expect("spawn paused QEMU orphan");
        assert_eq!(
            orphan_proc.try_wait().expect("poll fresh orphan"),
            None,
            "paused QEMU orphan exited unexpectedly before reconciliation"
        );
        let identity = orphan_proc.start_identity();

        let journal_store = JournalStore::new(harness.state_dir.join("journals"))
            .expect("open orphan journal store");
        journal_store
            .write_record(&JournalRecord {
                sandbox_id: orphan_id.clone(),
                state: JournalLifecycleState::Active,
                pid: Some(identity.pid),
                start_token: Some(identity.start_token),
                artifact_paths: vec![work_dir.clone(), overlay_path.clone()],
                expires_at_unix_ms: unix_ms_now() + 60_000,
            })
            .expect("persist Active orphan journal");

        // While the first manager still holds `state.lock`, a concurrent runtime must be rejected.
        let TestRuntimeHarness {
            _temp: _keep_temp,
            state_dir,
            _installed: installed,
            manager,
        } = harness;
        let locked_err = match try_build_manager_for_installed_bundle(
            fixtures.arch,
            installed.root_dir(),
            fixtures.public_key,
            &fixtures.qemu_bin,
            &fixtures.qemu_img_bin,
            &state_dir,
        ) {
            Ok(_) => panic!("second runtime on locked state_dir must fail"),
            Err(err) => err,
        };
        assert!(
            matches!(locked_err, SandboxError::PolicyViolation(_)),
            "expected PolicyViolation while first runtime holds state.lock, got {locked_err:?}"
        );

        // Drop previous manager to release `state.lock` and simulate restart recovery.
        drop(manager);

        let fresh_mgr = build_manager_for_installed_bundle(
            fixtures.arch,
            installed.root_dir(),
            fixtures.public_key,
            &fixtures.qemu_bin,
            &fixtures.qemu_img_bin,
            &state_dir,
        );
        let report = fresh_mgr
            .reconcile_startup()
            .await
            .expect("reconcile_startup for live orphan");

        assert!(report.orphans_killed >= 1, "expected orphans_killed >= 1, got {report:?}");
        assert!(report.cleaned >= 1, "expected cleaned >= 1, got {report:?}");
        assert_eq!(report.remaining, 0, "expected zero remaining records: {report:?}");

        let wait_res = orphan_proc
            .wait_timeout(Duration::from_secs(3))
            .expect("wait for reconciled orphan process");
        assert!(
            wait_res.is_some(),
            "orphan process {} remained alive after reconcile_startup",
            identity.pid
        );
        assert!(!work_dir.exists() && !overlay_path.exists());
        assert!(journal_store
            .load_record(&orphan_id)
            .expect("reload orphan journal")
            .is_none());
    }

    // Case (b): Simulated daemon subprocess killed mid-flight leaving real QEMU journal & qcow2 overlay.
    {
        let temp = TestTempDir::new("mp-p3-rec-b");
        let install_parent = temp.path().join("bundles");
        let state_dir = temp.path().join("state");
        fs::create_dir_all(&install_parent).expect("create helper bundle parent");
        fs::create_dir_all(&state_dir).expect("create helper state dir");

        let verifier =
            BundleVerifier::with_public_key(fixtures.public_key).expect("verifier from pubkey");
        let installed =
            install_bundle_atomic(&fixtures.src_bundle_dir, &install_parent, &verifier)
                .expect("install helper bundle");

        let exe = std::env::current_exe().expect("locate test binary");
        let mut daemon_child = Command::new(exe)
            .arg("--exact")
            .arg("e2e_crash_recovery_orphan_kill_and_cleanup")
            .arg("--nocapture")
            .env("MINIPOD_P3_DAEMON_HELPER", "1")
            .env("MINIPOD_P3_ARCH", fixtures.arch.as_str())
            .env("MINIPOD_P3_BUNDLE_DIR", installed.root_dir())
            .env("MINIPOD_P3_PUB_KEY", &fixtures.public_key_hex)
            .env("MINIPOD_P3_QEMU_BIN", &fixtures.qemu_bin)
            .env("MINIPOD_P3_QEMU_IMG_BIN", &fixtures.qemu_img_bin)
            .env("MINIPOD_P3_STATE_DIR", &state_dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn simulated daemon child");

        let stdout = daemon_child.stdout.take().expect("daemon child stdout pipe");
        let mut reader = BufReader::new(stdout);
        let mut ready_line = String::new();
        loop {
            ready_line.clear();
            let bytes = reader
                .read_line(&mut ready_line)
                .expect("read line from simulated daemon");
            assert!(bytes > 0, "simulated daemon exited before printing READY");
            if ready_line.starts_with("READY ") {
                break;
            }
        }
        drop(reader);

        let parts: Vec<&str> = ready_line.split_whitespace().collect();
        assert_eq!(parts.len(), 4, "malformed READY line: {ready_line:?}");
        let spawned_id = SandboxId::new(parts[1]);
        let qemu_pid: u32 = parts[2].parse().expect("parse QEMU pid");
        let qemu_start_token: u64 = parts[3].parse().expect("parse QEMU start_token");

        let work_dir = sandbox_work_dir(&state_dir, &spawned_id);
        let overlay_path = work_dir.join("overlay.qcow2");
        assert!(overlay_path.is_file(), "daemon helper must have created overlay.qcow2");

        // Abruptly crash the daemon without destroy().
        daemon_child.kill().expect("kill simulated daemon");
        let _ = daemon_child.wait();

        let fresh_mgr = build_manager_for_installed_bundle(
            fixtures.arch,
            installed.root_dir(),
            fixtures.public_key,
            &fixtures.qemu_bin,
            &fixtures.qemu_img_bin,
            &state_dir,
        );
        let report = fresh_mgr
            .reconcile_startup()
            .await
            .expect("reconcile_startup after daemon crash");

        let journals_after = JournalStore::new(state_dir.join("journals"))
            .expect("open journal store after crash recovery")
            .load_records()
            .expect("load journals after crash recovery");
        let still_alive = kill_verified_orphan_process(qemu_pid, qemu_start_token);
        assert!(
            report.records_seen >= 1,
            "expected records_seen >= 1, got {report:?}, journals={journals_after:?}, kill_check={still_alive:?}"
        );
        assert!(
            report.cleaned >= 1,
            "expected cleaned >= 1, got {report:?}, journals={journals_after:?}, kill_check={still_alive:?}"
        );
        assert_eq!(
            report.remaining, 0,
            "expected remaining == 0, got {report:?}, journals={journals_after:?}"
        );
        assert!(!work_dir.exists() && !overlay_path.exists());
        assert!(journals_after.is_empty());

        let still_alive = still_alive.expect("verify no lingering QEMU process");
        assert!(!still_alive, "QEMU pid {qemu_pid} remained alive after crash recovery");
    }
}

async fn run_simulated_daemon_helper() {
    let arch_raw = std::env::var("MINIPOD_P3_ARCH").expect("MINIPOD_P3_ARCH");
    let arch: GuestArch = arch_raw.parse().expect("parse MINIPOD_P3_ARCH");
    let bundle_dir = PathBuf::from(std::env::var_os("MINIPOD_P3_BUNDLE_DIR").expect("BUNDLE_DIR"));
    let pub_hex = std::env::var("MINIPOD_P3_PUB_KEY").expect("MINIPOD_P3_PUB_KEY");
    let pub_key = decode_hex_exact::<32>(pub_hex.trim()).expect("decode MINIPOD_P3_PUB_KEY");
    let qemu_bin = PathBuf::from(std::env::var_os("MINIPOD_P3_QEMU_BIN").expect("QEMU_BIN"));
    let qemu_img_bin =
        PathBuf::from(std::env::var_os("MINIPOD_P3_QEMU_IMG_BIN").expect("QEMU_IMG_BIN"));
    let state_dir = PathBuf::from(std::env::var_os("MINIPOD_P3_STATE_DIR").expect("STATE_DIR"));

    let mgr = build_manager_for_installed_bundle(
        arch,
        &bundle_dir,
        pub_key,
        &qemu_bin,
        &qemu_img_bin,
        &state_dir,
    );
    let lease = mgr
        .spawn(default_spec(Duration::from_secs(120)))
        .await
        .expect("helper daemon spawn VM");
    let record = JournalStore::new(state_dir.join("journals"))
        .expect("open helper journal store")
        .load_record(&lease.id)
        .expect("load helper journal record")
        .expect("journal record must exist after spawn");

    println!(
        "READY {} {} {}",
        lease.id,
        record.pid.unwrap_or(0),
        record.start_token.unwrap_or(0)
    );
    std::io::stdout().flush().expect("flush READY line");

    // Hold runtime alive without calling destroy() until parent kills this process.
    std::thread::sleep(Duration::from_secs(300));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn e2e_audit_regressions_state_lock_setsid_deadline_and_stalled_stream() {
    let Some(fixtures) = discover_fixtures("audit_regressions") else {
        return;
    };
    let harness = build_test_runtime(&fixtures, "mp-p8-audit");
    let mgr = &harness.manager;

    let lease = mgr
        .spawn(default_spec(Duration::from_secs(120)))
        .await
        .expect("spawn sandbox for audit regression probes");

    // 1. Probe #1: Second runtime on shared `state_dir` is rejected before reconciliation,
    //    leaving the first runtime's live QEMU VM completely intact.
    let second_res = try_build_manager_for_installed_bundle(
        fixtures.arch,
        harness._installed.root_dir(),
        fixtures.public_key,
        &fixtures.qemu_bin,
        &fixtures.qemu_img_bin,
        &harness.state_dir,
    );
    assert!(
        matches!(second_res, Err(SandboxError::PolicyViolation(_))),
        "expected PolicyViolation for concurrent state_dir runtime, got: {}",
        match second_res {
            Ok(_) => "Ok(LocalRuntimeManager)".to_owned(),
            Err(err) => format!("{err:?}"),
        }
    );

    let alive_after_lock = run_shell(
        mgr,
        &lease.id,
        "/bin/echo vm1-intact-after-state-lock-reject",
        Duration::from_secs(10),
    )
    .await
    .expect("first runtime VM must remain alive after second runtime rejection");
    assert_eq!(alive_after_lock.exit.code, Some(0));
    assert_eq!(
        alive_after_lock.stdout,
        b"vm1-intact-after-state-lock-reject\n"
    );

    // 2. Probe #4: `setsid` detached background process cannot outlive `deadline` inside Guest.
    let detached = run_shell(
        mgr,
        &lease.id,
        "rm -f /tmp/supervisor-escaped && setsid sh -c 'sleep 1; echo survived > /tmp/supervisor-escaped' </dev/null >/dev/null 2>&1 & wait",
        Duration::from_millis(300),
    )
    .await
    .expect("run setsid deadline probe");
    assert!(
        detached.exit.timed_out,
        "expected timed_out == true for setsid deadline probe, got {:?}",
        detached.exit
    );
    assert!(detached.exit.code.is_none());

    tokio::time::sleep(Duration::from_millis(1500)).await;
    let escaped_check = run_shell(
        mgr,
        &lease.id,
        "if [ -e /tmp/supervisor-escaped ]; then echo ESCAPED; else echo CONTAINED; fi",
        Duration::from_secs(10),
    )
    .await
    .expect("verify setsid child did not write /tmp/supervisor-escaped");
    assert_eq!(escaped_check.exit.code, Some(0));
    assert_eq!(
        String::from_utf8_lossy(&escaped_check.stdout).trim(),
        "CONTAINED",
        "setsid detached child survived deadline kill!"
    );

    // 3. Probe #6a: `ExecStream::wait_exit()` drains unread output without deadlocking when
    //    stdout exceeds the 256 KiB stream credit window (`512 KiB` unread).
    let mut unread_exit_stream = mgr
        .exec_stream(
            &lease.id,
            shell_request(
                "dd if=/dev/zero bs=4096 count=128 2>/dev/null | tr '\\0' B",
                Duration::from_secs(15),
                2 * 1024 * 1024,
                64 * 1024,
            ),
        )
        .await
        .expect("start unread wait_exit stream");
    let wait_only_status = tokio::time::timeout(
        Duration::from_secs(10),
        unread_exit_stream.wait_exit(),
    )
    .await
    .expect("wait_exit() hung when caller did not drain next_output()")
    .expect("wait_exit() returned transport error");
    assert_eq!(wait_only_status.code, Some(0));

    // 4. Probe #6b: A stalled `ExecStream` whose caller never reads `next_output()` (`1 MiB`
    //    stdout saturating stream credit) must NOT block a concurrent `exec_stream` or `destroy()`.
    let stalled_stream = mgr
        .exec_stream(
            &lease.id,
            shell_request(
                "dd if=/dev/zero bs=4096 count=256 2>/dev/null | tr '\\0' A",
                Duration::from_secs(30),
                4 * 1024 * 1024,
                64 * 1024,
            ),
        )
        .await
        .expect("start stalled exec_stream");
    tokio::time::sleep(Duration::from_millis(300)).await;

    let concurrent_ok = tokio::time::timeout(
        Duration::from_secs(8),
        run_shell(
            mgr,
            &lease.id,
            "echo healthy-while-sibling-stalled",
            Duration::from_secs(5),
        ),
    )
    .await
    .expect("concurrent exec_stream hung behind stalled sibling stream")
    .expect("concurrent exec_stream failed");
    assert_eq!(concurrent_ok.exit.code, Some(0));
    assert_eq!(concurrent_ok.stdout, b"healthy-while-sibling-stalled\n");

    let destroy_status = tokio::time::timeout(Duration::from_secs(10), mgr.destroy(&lease.id))
        .await
        .expect("destroy() hung while an unread ExecStream was backpressured")
        .expect("destroy() failed");
    assert_eq!(destroy_status, DestroyStatus::AllResourcesCleaned);
    drop(stalled_stream);
}
