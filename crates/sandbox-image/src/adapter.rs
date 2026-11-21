//! Layer 3 adapter implementing [`DiskOverlayPort`] atop signed Portable Runtime Bundles
//! and atomic QCOW2 Copy-on-Write overlays.

use std::fmt;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use sandbox_core::{GuestArch, SandboxError, SandboxId, SandboxSpec};
use sandbox_runtime::{BundleReadGuard, DiskOverlayPort, PreparedOverlay};

use crate::crypto::BundleVerifier;
use crate::installer::{
    check_regular_file_path, map_fs_error, with_verified_installed_bundle_read_locked,
};
use crate::qcow2::{create_qcow2_overlay_atomic_with_runner, HelperCommandRunner};

/// [`DiskOverlayPort`] implementation backed by an Ed25519-verified Portable Runtime Bundle
/// and `qemu-img` Copy-on-Write QCOW2 overlays.
#[derive(Clone)]
pub struct BundleOverlayStore {
    bundle_dir: PathBuf,
    verifier: BundleVerifier,
    qemu_img_bin: PathBuf,
    command_runner: Option<HelperCommandRunner>,
}

impl fmt::Debug for BundleOverlayStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BundleOverlayStore")
            .field("bundle_dir", &self.bundle_dir)
            .field("verifier", &self.verifier)
            .field("qemu_img_bin", &self.qemu_img_bin)
            .field("has_command_runner", &self.command_runner.is_some())
            .finish()
    }
}

impl BundleOverlayStore {
    /// Creates an overlay store targeting an installed Portable Runtime Bundle directory.
    pub fn new(
        bundle_dir: impl Into<PathBuf>,
        verifier: BundleVerifier,
        qemu_img_bin: impl Into<PathBuf>,
    ) -> Result<Self, SandboxError> {
        Self::new_inner(bundle_dir.into(), verifier, qemu_img_bin.into(), None)
    }

    /// Creates an overlay store executing `qemu-img` via a confined [`HelperCommandRunner`]
    /// (such as a Win32 Job Object + handle whitelist runner injected from `sandbox-vmm`).
    pub fn with_command_runner(
        bundle_dir: impl Into<PathBuf>,
        verifier: BundleVerifier,
        qemu_img_bin: impl Into<PathBuf>,
        command_runner: HelperCommandRunner,
    ) -> Result<Self, SandboxError> {
        Self::new_inner(
            bundle_dir.into(),
            verifier,
            qemu_img_bin.into(),
            Some(command_runner),
        )
    }

    fn new_inner(
        bundle_dir: PathBuf,
        verifier: BundleVerifier,
        qemu_img_bin: PathBuf,
        command_runner: Option<HelperCommandRunner>,
    ) -> Result<Self, SandboxError> {
        if bundle_dir.as_os_str().is_empty() {
            return Err(SandboxError::InvalidSpec(
                "bundle_dir cannot be empty".to_owned(),
            ));
        }
        if qemu_img_bin.as_os_str().is_empty() {
            return Err(SandboxError::InvalidSpec(
                "qemu_img_bin cannot be empty".to_owned(),
            ));
        }
        Ok(Self {
            bundle_dir,
            verifier,
            qemu_img_bin,
            command_runner,
        })
    }

    pub fn bundle_dir(&self) -> &Path {
        &self.bundle_dir
    }

    pub fn qemu_img_bin(&self) -> &Path {
        &self.qemu_img_bin
    }
}

#[async_trait::async_trait]
impl DiskOverlayPort for BundleOverlayStore {
    async fn prepare_overlay(
        &self,
        _sandbox_id: &SandboxId,
        spec: &SandboxSpec,
        work_dir: &Path,
    ) -> Result<PreparedOverlay, SandboxError> {
        if spec.budget.virtual_disk_mb == 0 || spec.budget.host_storage_budget_mb == 0 {
            return Err(SandboxError::InvalidSpec(
                "virtual_disk_mb and host_storage_budget_mb must be greater than zero".to_owned(),
            ));
        }
        if spec.budget.virtual_disk_mb > spec.budget.host_storage_budget_mb {
            return Err(SandboxError::BudgetExceeded(format!(
                "requested virtual_disk_mb ({} MiB) exceeds host_storage_budget_mb ({} MiB)",
                spec.budget.virtual_disk_mb, spec.budget.host_storage_budget_mb
            )));
        }

        let bundle_dir = self.bundle_dir.clone();
        let verifier = self.verifier.clone();
        let qemu_img_bin = self.qemu_img_bin.clone();
        let command_runner = self.command_runner.clone();
        let overlay_path = work_dir.join("overlay.qcow2");
        let virtual_disk_mb = spec.budget.virtual_disk_mb;
        let host_budget_bytes = u64::from(spec.budget.host_storage_budget_mb) * 1024 * 1024;

        tokio::task::spawn_blocking(move || {
            with_verified_installed_bundle_read_locked(
                &bundle_dir,
                &verifier,
                |installed, read_guard| {
                    installed
                        .manifest()
                        .ensure_compatible_host_os(std::env::consts::OS)?;
                    let guest_arch = installed.manifest().guest_arch;
                    let base_rootfs = installed.base_rootfs_qcow2_path();

                create_qcow2_overlay_atomic_with_runner(
                    &qemu_img_bin,
                    &base_rootfs,
                    &overlay_path,
                    Some(virtual_disk_mb),
                    command_runner.as_ref(),
                )?;

                let meta = fs::symlink_metadata(&overlay_path).map_err(|err| {
                    map_fs_error(&overlay_path, "inspect created qcow2 overlay", err)
                })?;
                let provisioned_host_bytes = meta.len();
                if provisioned_host_bytes > host_budget_bytes {
                    let _ = fs::remove_file(&overlay_path);
                    return Err(SandboxError::BudgetExceeded(format!(
                        "provisioned overlay size ({provisioned_host_bytes} bytes) exceeds host_storage_budget_mb ({host_budget_bytes} bytes)"
                    )));
                }

                let kernel_cmdline = default_kernel_cmdline(guest_arch);
                Ok(PreparedOverlay {
                    overlay_path,
                    kernel_path: installed.kernel_path(),
                    initramfs_path: installed.initrd_path(),
                    rootfs_path: base_rootfs,
                    kernel_cmdline,
                    guest_arch: Some(guest_arch),
                    virtual_disk_mb,
                    provisioned_host_bytes,
                    bundle_guard: read_guard.map(BundleReadGuard::new),
                })
            })
        })
        .await
        .map_err(|err| SandboxError::Internal(format!("prepare_overlay task failed: {err}")))?
    }

    async fn remove_overlay(&self, overlay_path: &Path) -> Result<(), SandboxError> {
        let overlay_path = overlay_path.to_path_buf();
        tokio::task::spawn_blocking(move || match check_regular_file_path(&overlay_path, false) {
            Ok(_) => match fs::remove_file(&overlay_path) {
                Ok(()) => Ok(()),
                Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
                Err(err) => Err(map_fs_error(&overlay_path, "remove qcow2 overlay", err)),
            },
            Err(SandboxError::NotFound(_)) => Ok(()),
            Err(err) => Err(err),
        })
        .await
        .map_err(|err| SandboxError::Internal(format!("remove_overlay task failed: {err}")))?
    }
}

fn default_kernel_cmdline(arch: GuestArch) -> String {
    match arch {
        GuestArch::X86_64 => "console=ttyS0 quiet panic=-1 minipod.root=/dev/vda".to_owned(),
        GuestArch::Aarch64 => "console=ttyAMA0 quiet panic=-1 minipod.root=/dev/vda".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::collections::BTreeMap;
    use std::io::Cursor;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::Duration;

    use sandbox_core::{AccelerationPolicy, IsolationMode, NetworkPolicy, ResourceBudget};

    use crate::crypto::{public_key_from_secret, sha256_reader, sign_manifest_hex};
    use crate::manifest::{
        ArtifactRole, BundleFileEntry, BundleManifest, MANIFEST_FILENAME, MANIFEST_FORMAT_VERSION,
        SIGNATURE_FILENAME,
    };

    static SEQ: AtomicU64 = AtomicU64::new(0);

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "minipod-img-adapter-{label}-{}-{}",
                std::process::id(),
                SEQ.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn write_signed_test_bundle(dir: &Path, secret: &[u8; 32]) {
        fs::create_dir_all(dir.join("boot")).unwrap();
        fs::create_dir_all(dir.join("rootfs")).unwrap();

        let files = [
            (ArtifactRole::Kernel, "boot/vmlinuz", b"fake-kernel".as_slice()),
            (ArtifactRole::Initrd, "boot/initramfs.cpio.gz", b"fake-initrd".as_slice()),
            (ArtifactRole::BaseRootfsQcow2, "rootfs/base.qcow2", b"QFI\xfbnot-real".as_slice()),
        ];

        let mut entries = Vec::new();
        for (role, rel, data) in files {
            fs::write(dir.join(rel), data).unwrap();
            let (sha256, size_bytes) = sha256_reader(&mut Cursor::new(data)).unwrap();
            entries.push(BundleFileEntry {
                role,
                rel_path: rel.to_owned(),
                sha256,
                size_bytes,
            });
        }

        let mut pins = BTreeMap::new();
        pins.insert("alpine".to_owned(), "3.21.0".to_owned());

        let manifest = BundleManifest {
            format_version: MANIFEST_FORMAT_VERSION,
            bundle_id: "bundle-test-1".to_owned(),
            host_os: std::env::consts::OS.to_owned(),
            guest_arch: GuestArch::X86_64,
            source_pins: pins,
            entries,
        };
        let manifest_text = manifest.encode_canonical().unwrap();
        let sig_hex = sign_manifest_hex(secret, manifest_text.as_bytes());
        fs::write(dir.join(MANIFEST_FILENAME), manifest_text).unwrap();
        fs::write(dir.join(SIGNATURE_FILENAME), sig_hex).unwrap();
    }

    fn test_spec(virtual_disk_mb: u32, host_storage_budget_mb: u32) -> SandboxSpec {
        SandboxSpec {
            isolation: IsolationMode::VmRequired,
            acceleration: AccelerationPolicy::Preferred,
            network: NetworkPolicy::Isolated,
            budget: ResourceBudget {
                guest_vcpus: 1,
                host_cpu_quota_Millicores: None,
                guest_ram_mb: 128,
                host_rss_budget_mb: None,
                virtual_disk_mb,
                host_storage_budget_mb,
            },
            lease_ttl: Duration::from_secs(30),
        }
    }

    #[test]
    fn constructor_rejects_empty_paths() {
        let verifier = BundleVerifier::embedded().unwrap();
        assert!(matches!(
            BundleOverlayStore::new("", verifier.clone(), "qemu-img"),
            Err(SandboxError::InvalidSpec(_))
        ));
        assert!(matches!(
            BundleOverlayStore::new("/bundle", verifier, ""),
            Err(SandboxError::InvalidSpec(_))
        ));
    }

    #[tokio::test]
    async fn prepare_overlay_rejects_budget_exceeded_and_tampered_bundles() {
        let tmp = TempDir::new("budget-tamper");
        let bundle_dir = tmp.path().join("bundle");
        let work_dir = tmp.path().join("work");
        fs::create_dir_all(&work_dir).unwrap();

        let secret = [0x42u8; 32];
        write_signed_test_bundle(&bundle_dir, &secret);
        let verifier = BundleVerifier::with_public_key(public_key_from_secret(&secret)).unwrap();
        let store = BundleOverlayStore::new(&bundle_dir, verifier, "qemu-img").unwrap();

        // Virtual disk exceeding host storage budget must be rejected cleanly before running qemu-img.
        let err_budget = store
            .prepare_overlay(&SandboxId::new("sb-1"), &test_spec(1024, 512), &work_dir)
            .await
            .unwrap_err();
        assert!(matches!(err_budget, SandboxError::BudgetExceeded(_)));

        // Tampering any bundle file must fail verification with PolicyViolation.
        fs::write(bundle_dir.join("boot").join("vmlinuz"), b"evil-kernel").unwrap();
        let err_tamper = store
            .prepare_overlay(&SandboxId::new("sb-1"), &test_spec(256, 512), &work_dir)
            .await
            .unwrap_err();
        assert!(matches!(err_tamper, SandboxError::PolicyViolation(_)));
    }

    #[tokio::test]
    async fn remove_overlay_is_idempotent_and_rejects_directories() {
        let tmp = TempDir::new("remove");
        let verifier = BundleVerifier::embedded().unwrap();
        let store = BundleOverlayStore::new(tmp.path(), verifier, "qemu-img").unwrap();

        let overlay = tmp.path().join("overlay.qcow2");
        fs::write(&overlay, b"data").unwrap();
        store.remove_overlay(&overlay).await.unwrap();
        assert!(!overlay.exists());

        // Second remove on missing file succeeds idempotently.
        store.remove_overlay(&overlay).await.unwrap();

        // Passing a directory rather than regular file fails with PolicyViolation.
        let dir = tmp.path().join("not-a-file");
        fs::create_dir_all(&dir).unwrap();
        assert!(matches!(
            store.remove_overlay(&dir).await,
            Err(SandboxError::PolicyViolation(_))
        ));
    }

    #[tokio::test]
    async fn prepare_overlay_invokes_injected_confined_command_runner() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use crate::qcow2::HelperCommandOutput;

        let tmp = TempDir::new("custom-runner");
        let bundle_dir = tmp.path().join("bundle");
        let work_dir = tmp.path().join("work");
        fs::create_dir_all(&work_dir).unwrap();

        let secret = [0x55u8; 32];
        write_signed_test_bundle(&bundle_dir, &secret);
        let verifier = BundleVerifier::with_public_key(public_key_from_secret(&secret)).unwrap();

        let calls = Arc::new(AtomicUsize::new(0));
        let calls_ref = Arc::clone(&calls);
        let store = BundleOverlayStore::with_command_runner(
            &bundle_dir,
            verifier,
            "confined-qemu-img",
            Arc::new(move |prog, args, _timeout| {
                calls_ref.fetch_add(1, Ordering::SeqCst);
                assert_eq!(prog, Path::new("confined-qemu-img"));
                assert!(args.iter().any(|a| a == "create"));
                Ok(HelperCommandOutput {
                    success: false,
                    status_label: "simulated-failure".to_owned(),
                    stdout: Vec::new(),
                    stderr: b"confined runner invoked".to_vec(),
                })
            }),
        )
        .unwrap();

        let mut fake_qcow2 = vec![0u8; 72];
        fake_qcow2[0..4].copy_from_slice(&0x5146_49fb_u32.to_be_bytes());
        fake_qcow2[4..8].copy_from_slice(&3u32.to_be_bytes());
        fake_qcow2[24..32].copy_from_slice(&(64u64 * 1024 * 1024).to_be_bytes());
        let rootfs_path = bundle_dir.join("rootfs").join("base.qcow2");
        fs::write(&rootfs_path, &fake_qcow2).unwrap();

        let manifest_path = bundle_dir.join(MANIFEST_FILENAME);
        let old_manifest =
            BundleManifest::parse_untrusted(&fs::read_to_string(&manifest_path).unwrap()).unwrap();
        let (sha256, size_bytes) = sha256_reader(&mut Cursor::new(&fake_qcow2)).unwrap();
        let mut updated_entries = old_manifest.entries;
        for entry in &mut updated_entries {
            if entry.rel_path == "rootfs/base.qcow2" {
                entry.sha256 = sha256;
                entry.size_bytes = size_bytes;
            }
        }
        let new_manifest = BundleManifest {
            entries: updated_entries,
            ..old_manifest
        };
        let encoded = new_manifest.encode_canonical().unwrap();
        fs::write(&manifest_path, &encoded).unwrap();
        fs::write(
            bundle_dir.join(SIGNATURE_FILENAME),
            sign_manifest_hex(&secret, encoded.as_bytes()),
        )
        .unwrap();

        let err = store
            .prepare_overlay(&SandboxId::new("sb-run"), &test_spec(128, 256), &work_dir)
            .await
            .unwrap_err();
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(err.to_string().contains("confined runner invoked"), "unexpected err: {err}");
    }
}
