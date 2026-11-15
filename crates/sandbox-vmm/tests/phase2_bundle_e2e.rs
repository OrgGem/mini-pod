//! Phase 2 end-to-end integration tests for signed Portable Runtime Bundle verification,
//! atomic installation, QCOW2 CoW overlay creation, and multi-arch (`x86_64` + `aarch64`)
//! QEMU guest boot with read-only rootfs, writable `/etc` overlay, and PID 1 zombie reaping.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use sandbox_core::{AccelerationPolicy, GuestArch, NetworkPolicy, SandboxError};
use sandbox_image::{
    create_qcow2_overlay_atomic, decode_hex_exact, install_bundle_atomic, sha256_reader,
    verify_installed_bundle, BundleVerifier,
};
use sandbox_vmm::{
    discover_qemu_binary_for_arch, discover_qemu_img_binary, SpikeBootConfig, SpikeSession,
};

static NEXT_TEST_SEQ: AtomicU64 = AtomicU64::new(0);

struct TestTempDir(PathBuf);

impl TestTempDir {
    fn new(label: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "minipod-p2-e2e-{label}-{}-{}",
            std::process::id(),
            NEXT_TEST_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&dir).expect("create Phase 2 E2E temp directory");
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

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/sandbox-vmm must sit two levels below workspace root")
        .to_path_buf()
}

fn require_phase2_artifacts() -> (PathBuf, PathBuf, BundleVerifier) {
    let root = repo_root();
    let x86_64_dir = root.join(".cache").join("bundles-src").join("x86_64");
    let aarch64_dir = root.join(".cache").join("bundles-src").join("aarch64");
    let pub_key_path = root.join(".cache").join("keys").join("dev-bundle.pub");

    assert!(
        x86_64_dir.is_dir() && aarch64_dir.is_dir() && pub_key_path.is_file(),
        "Missing Phase 2 signed bundle artifacts under '{}' and '{}'. Run `powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-portable-bundles.ps1` first.",
        root.join(".cache").join("bundles-src").display(),
        pub_key_path.display()
    );

    let pub_hex = fs::read_to_string(&pub_key_path).expect("read dev-bundle.pub");
    let pub_key = decode_hex_exact::<32>(pub_hex.trim()).expect("decode dev-bundle.pub hex");
    let verifier = BundleVerifier::with_public_key(pub_key).expect("load dev bundle verifier");
    (x86_64_dir, aarch64_dir, verifier)
}

fn sha256_file(path: &Path) -> [u8; 32] {
    let mut file = File::open(path).expect("open file for SHA-256");
    let (digest, _) = sha256_reader(&mut file).expect("compute SHA-256");
    digest
}

fn copy_dir_recursive(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).expect("create copy target dir");
    for entry in fs::read_dir(src).expect("read source bundle dir") {
        let entry = entry.expect("read bundle dir entry");
        let file_type = entry.file_type().expect("inspect source entry type");
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if file_type.is_dir() {
            copy_dir_recursive(&src_path, &dst_path);
        } else if file_type.is_file() {
            fs::copy(&src_path, &dst_path).expect("copy bundle file");
        } else {
            panic!("unexpected non-regular entry in bundle source '{}'", src_path.display());
        }
    }
}

#[test]
fn bundle_tamper_and_rogue_dll_are_rejected_before_install() {
    let (x86_64_src, _, verifier) = require_phase2_artifacts();
    let tmp = TestTempDir::new("tamper");
    let staged_src = tmp.path().join("src");
    copy_dir_recursive(&x86_64_src, &staged_src);

    // (a) Flip 1 byte in rootfs/base.qcow2 -> install must fail and leave target dir empty.
    let qcow2_path = staged_src.join("rootfs").join("base.qcow2");
    {
        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&qcow2_path)
            .expect("open copied base.qcow2 for tamper test");
        let mut byte = [0u8; 1];
        f.read_exact(&mut byte).expect("read byte 0 of base.qcow2");
        byte[0] ^= 0x01;
        f.seek(SeekFrom::Start(0)).expect("seek back to byte 0");
        f.write_all(&byte).expect("write tampered byte");
        f.sync_all().expect("sync tampered file");
    }

    let install_a = tmp.path().join("install-a");
    fs::create_dir_all(&install_a).unwrap();
    let tamper_err = install_bundle_atomic(&staged_src, &install_a, &verifier);
    assert!(
        matches!(tamper_err, Err(SandboxError::PolicyViolation(_))),
        "tampered base.qcow2 must be rejected with PolicyViolation, got {tamper_err:?}"
    );
    assert_eq!(
        fs::read_dir(&install_a).unwrap().count(),
        0,
        "failed tampered install must not leave target bundle or staging dirs behind"
    );

    // (b) Restore base.qcow2 and add an undeclared rogue DLL -> install must fail cleanly.
    fs::copy(x86_64_src.join("rootfs").join("base.qcow2"), &qcow2_path)
        .expect("restore untampered base.qcow2");
    fs::write(staged_src.join("version.dll"), b"rogue-sideload-dll")
        .expect("write rogue version.dll");

    let install_b = tmp.path().join("install-b");
    fs::create_dir_all(&install_b).unwrap();
    let rogue_err = install_bundle_atomic(&staged_src, &install_b, &verifier);
    assert!(
        matches!(rogue_err, Err(SandboxError::PolicyViolation(_))),
        "undeclared version.dll must be rejected with PolicyViolation, got {rogue_err:?}"
    );
    assert_eq!(
        fs::read_dir(&install_b).unwrap().count(),
        0,
        "failed undeclared-file install must not leave target bundle or staging dirs behind"
    );
}

#[test]
fn signed_bundle_atomic_install_cow_overlay_and_boot_x86_64_and_aarch64() {
    let (x86_64_src, aarch64_src, verifier) = require_phase2_artifacts();
    let require_qemu = std::env::var_os("MINIPOD_REQUIRE_QEMU_TESTS").is_some();
    let qemu_img = match discover_qemu_img_binary(None) {
        Ok(path) => path,
        Err(SandboxError::NotFound(msg)) if !require_qemu => {
            eprintln!(
                "[phase2_bundle_e2e::signed_bundle_atomic_install_cow_overlay_and_boot_x86_64_and_aarch64] SKIPPED: {msg}"
            );
            return;
        }
        Err(err) => panic!("discover qemu-img binary: {err}"),
    };
    for arch in [GuestArch::X86_64, GuestArch::Aarch64] {
        if let Err(err) = discover_qemu_binary_for_arch(arch, None) {
            if matches!(err, SandboxError::NotFound(_)) && !require_qemu {
                eprintln!(
                    "[phase2_bundle_e2e::signed_bundle_atomic_install_cow_overlay_and_boot_x86_64_and_aarch64] SKIPPED: {err}"
                );
                return;
            }
            panic!("discover QEMU binary for {}: {err}", arch.as_str());
        }
    }

    for (arch, src_dir, expected_uname) in [
        (GuestArch::X86_64, &x86_64_src, b"x86_64\n".as_slice()),
        (GuestArch::Aarch64, &aarch64_src, b"aarch64\n".as_slice()),
    ] {
        let tmp = TestTempDir::new(arch.as_str());
        let install_dir = tmp.path().join("installed");
        let work_dir = tmp.path().join("work");
        fs::create_dir_all(&work_dir).unwrap();

        let installed = install_bundle_atomic(src_dir, &install_dir, &verifier)
            .expect("atomic install of signed bundle must succeed");
        let verified = verify_installed_bundle(installed.root_dir(), &verifier)
            .expect("in-place verification of installed bundle must succeed");
        assert_eq!(verified.manifest().guest_arch, arch);

        let base_qcow2 = verified.base_rootfs_qcow2_path();
        let pre_boot_sha = sha256_file(&base_qcow2);

        let overlay_qcow2 = work_dir.join("worker.qcow2");
        create_qcow2_overlay_atomic(&qemu_img, &base_qcow2, &overlay_qcow2, Some(384))
            .expect("create CoW overlay worker.qcow2");

        let config = SpikeBootConfig {
            arch,
            kernel_path: verified.kernel_path(),
            initrd_path: verified.initrd_path(),
            root_disk_qcow2: Some(overlay_qcow2),
            acceleration: AccelerationPolicy::Preferred,
            network: NetworkPolicy::Isolated,
            boot_timeout: Duration::from_secs(45),
            exec_timeout: Duration::from_secs(20),
            ..Default::default()
        };

        let mut session = SpikeSession::boot(&config).expect("boot signed bundle guest");
        eprintln!(
            "[phase2_bundle_e2e] booted {} guest with QEMU accel: {}",
            arch.as_str(),
            session.accelerator_used().as_qemu_arg()
        );

        let uname = session
            .exec(vec!["/bin/uname".to_owned(), "-m".to_owned()])
            .expect("exec /bin/uname -m");
        assert_eq!(uname.exit_code, 0);
        assert_eq!(uname.stdout, expected_uname);

        let pid1 = session
            .exec(vec!["/bin/cat".to_owned(), "/proc/1/comm".to_owned()])
            .expect("exec /bin/cat /proc/1/comm");
        assert_eq!(pid1.exit_code, 0);
        assert_eq!(pid1.stdout, b"tiny-init\n");

        let ro_check = session
            .exec(vec![
                "/bin/sh".to_owned(),
                "-c".to_owned(),
                "touch /bin/ro_test".to_owned(),
            ])
            .expect("exec read-only rootfs write test");
        assert_ne!(ro_check.exit_code, 0, "/bin must be mounted read-only");

        let rw_check = session
            .exec(vec![
                "/bin/sh".to_owned(),
                "-c".to_owned(),
                "echo ok > /etc/mp.conf && echo c > /var/lib/containers/p && echo w > /workspace/f && cat /etc/mp.conf /var/lib/containers/p /workspace/f".to_owned(),
            ])
            .expect("exec writable /etc overlay and bind mount test");
        assert_eq!(rw_check.exit_code, 0);
        assert_eq!(rw_check.stdout, b"ok\nc\nw\n");

        let zombie_check = session
            .exec(vec![
                "/bin/sh".to_owned(),
                "-c".to_owned(),
                "(/bin/sh -c 'exit 0' &); sleep 0.3; awk '/^State:[ \t]+Z/{z++} END{print z+0}' /proc/[0-9]*/status".to_owned(),
            ])
            .expect("exec PID 1 zombie reaping check");
        assert_eq!(zombie_check.exit_code, 0);
        assert_eq!(zombie_check.stdout, b"0\n");

        session
            .shutdown_and_cleanup()
            .expect("graceful guest shutdown and cleanup must succeed");

        let post_boot_sha = sha256_file(&base_qcow2);
        assert_eq!(
            post_boot_sha, pre_boot_sha,
            "installed base.qcow2 for {} must remain byte-for-byte unmodified after CoW overlay boot",
            arch.as_str()
        );
    }
}
