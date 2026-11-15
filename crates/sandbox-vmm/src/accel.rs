//! QEMU binary discovery, OS launch-error classification, and accelerator policy resolution.

use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

use sandbox_core::{AccelerationPolicy, SandboxError};

// shortcut: hardcoded x86_64 QEMU binary name; parameterize by guest architecture when Phase 2 adds aarch64 bundles
#[cfg(windows)]
const QEMU_BINARY_NAME: &str = "qemu-system-x86_64.exe";
#[cfg(not(windows))]
const QEMU_BINARY_NAME: &str = "qemu-system-x86_64";

/// Virtualization or software-emulation accelerator supported by QEMU.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Accelerator {
    /// Linux Kernel-based Virtual Machine.
    Kvm,
    /// macOS Hypervisor.framework.
    Hvf,
    /// Windows Hypervisor Platform.
    Whpx,
    /// QEMU Tiny Code Generator (software CPU emulation).
    Tcg,
}

impl Accelerator {
    /// Returns the value passed to QEMU's `-accel <name>` CLI flag.
    pub fn as_qemu_arg(&self) -> &'static str {
        match self {
            Self::Kvm => "kvm",
            Self::Hvf => "hvf",
            Self::Whpx => "whpx",
            Self::Tcg => "tcg",
        }
    }

    /// Returns `true` for hardware-assisted virtualization and `false` for software emulation (`Tcg`).
    pub fn is_hardware(&self) -> bool {
        !matches!(self, Self::Tcg)
    }
}

/// Pure QEMU binary lookup across explicit override and caller-supplied directories.
///
/// When `explicit` is `Some(path)`, it is validated directly and never falls back to `search_dirs`.
/// When `explicit` is `None`, searches `search_dirs` in order for the host QEMU binary name.
pub fn find_qemu_binary_in_dirs(
    explicit: Option<&Path>,
    search_dirs: &[PathBuf],
) -> Result<PathBuf, SandboxError> {
    if let Some(path) = explicit {
        return if path.is_file() {
            Ok(path.to_path_buf())
        } else {
            Err(SandboxError::NotFound(format!(
                "explicit QEMU binary path '{}' does not exist or is not a file",
                path.display()
            )))
        };
    }

    for dir in search_dirs {
        let candidate = dir.join(QEMU_BINARY_NAME);
        if candidate.is_file() {
            return Ok(candidate);
        }
    }

    Err(SandboxError::NotFound(format!(
        "QEMU binary '{QEMU_BINARY_NAME}' was not found in configured search directories"
    )))
}

/// Discovers the QEMU binary using `explicit` or the host process `PATH` (plus standard Windows fallback paths).
///
/// Intended strictly for outer composition roots (`sandboxd`, `sandbox-cli`); inner runtime layers
/// should pass explicit configuration or invoke [`find_qemu_binary_in_dirs`] directly.
pub fn discover_qemu_binary(explicit: Option<&Path>) -> Result<PathBuf, SandboxError> {
    if explicit.is_some() {
        return find_qemu_binary_in_dirs(explicit, &[]);
    }

    let mut search_dirs = Vec::new();
    if let Some(path_var) = std::env::var_os("PATH") {
        search_dirs.extend(
            std::env::split_paths(&path_var).filter(|dir| !dir.as_os_str().is_empty()),
        );
    }

    #[cfg(windows)]
    {
        if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA") {
            search_dirs.push(PathBuf::from(local_app_data).join("Programs").join("qemu"));
        }
        search_dirs.push(PathBuf::from(r"C:\Program Files\qemu"));
    }

    find_qemu_binary_in_dirs(None, &search_dirs)
}

/// Classifies an I/O error returned while probing or launching a QEMU binary into [`SandboxError`].
///
/// Recognizes Windows AppLocker (`1260`), WDAC / Smart App Control (`4551`), access denied (`5`),
/// and POSIX `EACCES` (`13`) / `EPERM` (`1`) as [`SandboxError::BinaryExecutionBlocked`] without
/// ever relaxing the VM isolation boundary.
pub fn classify_launch_error(qemu_bin: &Path, err: &io::Error) -> SandboxError {
    let path = qemu_bin.display();
    match err.raw_os_error() {
        Some(1260) => SandboxError::BinaryExecutionBlocked(format!(
            "QEMU binary '{path}' was blocked by Windows AppLocker / software restriction policy (OS error 1260): {err}"
        )),
        Some(4551) => SandboxError::BinaryExecutionBlocked(format!(
            "QEMU binary '{path}' was blocked by Windows Defender Application Control / Smart App Control (OS error 4551): {err}"
        )),
        Some(code @ (5 | 13 | 1)) => SandboxError::BinaryExecutionBlocked(format!(
            "QEMU binary '{path}' execution was denied by OS security or permission policy (OS error {code}): {err}"
        )),
        _ => match err.kind() {
            io::ErrorKind::PermissionDenied => SandboxError::BinaryExecutionBlocked(format!(
                "QEMU binary '{path}' execution was blocked by OS permission policy: {err}"
            )),
            io::ErrorKind::NotFound => SandboxError::NotFound(format!(
                "QEMU binary '{path}' was not found: {err}"
            )),
            _ => SandboxError::Internal(format!(
                "failed to launch QEMU binary '{path}': {err}"
            )),
        },
    }
}

/// Parses stdout from `qemu-system-x86_64 -accel help` into deduplicated [`Accelerator`] entries.
pub fn parse_accel_help(stdout: &str) -> Vec<Accelerator> {
    let mut accels = Vec::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        let accel = if trimmed.eq_ignore_ascii_case("kvm") {
            Some(Accelerator::Kvm)
        } else if trimmed.eq_ignore_ascii_case("hvf") {
            Some(Accelerator::Hvf)
        } else if trimmed.eq_ignore_ascii_case("whpx") {
            Some(Accelerator::Whpx)
        } else if trimmed.eq_ignore_ascii_case("tcg") {
            Some(Accelerator::Tcg)
        } else {
            None
        };

        if let Some(accel) = accel {
            if !accels.contains(&accel) {
                accels.push(accel);
            }
        }
    }
    accels
}

/// Probes `qemu_bin -accel help` and filters the reported accelerators by host OS feasibility.
pub fn probe_available_accelerators(qemu_bin: &Path) -> Result<Vec<Accelerator>, SandboxError> {
    let output = Command::new(qemu_bin)
        .args(["-accel", "help"])
        .output()
        .map_err(|err| classify_launch_error(qemu_bin, &err))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(SandboxError::Internal(format!(
            "QEMU accelerator probe '{}' -accel help exited with {}: {}",
            qemu_bin.display(),
            output.status,
            stderr.trim()
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(filter_host_feasible(parse_accel_help(&stdout)))
}

/// Resolves the [`Accelerator`] to pass to QEMU according to [`AccelerationPolicy`].
///
/// Strictly enforces `BRD.md` Section 1: hardware virtualization may degrade only to QEMU `Tcg`
/// under [`AccelerationPolicy::Preferred`], and never falls back to a shared-kernel runtime.
pub fn select_accelerator(
    policy: AccelerationPolicy,
    available: &[Accelerator],
) -> Result<Accelerator, SandboxError> {
    let hardware = available.iter().copied().find(|accel| accel.is_hardware());
    let tcg = available
        .iter()
        .copied()
        .find(|accel| *accel == Accelerator::Tcg);

    match policy {
        AccelerationPolicy::Required => hardware.ok_or_else(|| {
            SandboxError::AccelerationUnavailable(
                "hardware virtualization is required, but no feasible hardware accelerator (kvm/hvf/whpx) is available".to_owned(),
            )
        }),
        AccelerationPolicy::Preferred => hardware.or(tcg).ok_or_else(|| {
            SandboxError::AccelerationUnavailable(
                "no feasible QEMU accelerator (hardware or tcg) is available".to_owned(),
            )
        }),
        AccelerationPolicy::SoftwareOnly => tcg.ok_or_else(|| {
            SandboxError::AccelerationUnavailable(
                "software emulation (tcg) was requested, but QEMU does not report tcg support".to_owned(),
            )
        }),
    }
}

fn filter_host_feasible(accels: Vec<Accelerator>) -> Vec<Accelerator> {
    accels
        .into_iter()
        .filter(|accel| is_host_accelerator_feasible(*accel))
        .collect()
}

fn is_host_accelerator_feasible(accel: Accelerator) -> bool {
    match accel {
        Accelerator::Tcg => true,
        Accelerator::Kvm => kvm_device_accessible(),
        Accelerator::Hvf => macos_hv_supported(),
        Accelerator::Whpx => windows_whpx_supported(),
    }
}

#[cfg(target_os = "linux")]
fn kvm_device_accessible() -> bool {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .is_ok()
}

#[cfg(not(target_os = "linux"))]
fn kvm_device_accessible() -> bool {
    false
}

#[cfg(target_os = "macos")]
fn macos_hv_supported() -> bool {
    let output = Command::new("sysctl")
        .args(["-n", "kern.hv_support"])
        .output()
        .or_else(|err| {
            if err.kind() == io::ErrorKind::NotFound {
                Command::new("/usr/sbin/sysctl")
                    .args(["-n", "kern.hv_support"])
                    .output()
            } else {
                Err(err)
            }
        });
    matches!(
        output,
        Ok(out) if out.status.success() && String::from_utf8_lossy(&out.stdout).trim() == "1"
    )
}

#[cfg(not(target_os = "macos"))]
fn macos_hv_supported() -> bool {
    false
}

#[cfg(target_os = "windows")]
fn windows_whpx_supported() -> bool {
    // shortcut: trusts QEMU binary whpx support on Windows without calling WHvGetCapability yet; add FFI probe in os::windows if pre-spawn WHPX rejection is needed
    true
}

#[cfg(not(target_os = "windows"))]
fn windows_whpx_supported() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct TestTempDir(PathBuf);

    impl TestTempDir {
        fn new(prefix: &str) -> Self {
            static COUNTER: AtomicU64 = AtomicU64::new(0);
            let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
            let dir = std::env::temp_dir().join(format!(
                "mini-pod-vmm-{prefix}-{}-{seq}",
                std::process::id()
            ));
            fs::create_dir_all(&dir).expect("create temp test directory");
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

    #[test]
    fn accelerator_flags_and_hardware_classification() {
        assert_eq!(Accelerator::Kvm.as_qemu_arg(), "kvm");
        assert_eq!(Accelerator::Hvf.as_qemu_arg(), "hvf");
        assert_eq!(Accelerator::Whpx.as_qemu_arg(), "whpx");
        assert_eq!(Accelerator::Tcg.as_qemu_arg(), "tcg");

        assert!(Accelerator::Kvm.is_hardware());
        assert!(Accelerator::Hvf.is_hardware());
        assert!(Accelerator::Whpx.is_hardware());
        assert!(!Accelerator::Tcg.is_hardware());
    }

    #[test]
    fn parse_accel_help_handles_realistic_qemu_11_outputs() {
        let windows_out = "Accelerators supported in QEMU binary:\r\ntcg\r\nwhpx\r\n";
        assert_eq!(
            parse_accel_help(windows_out),
            vec![Accelerator::Tcg, Accelerator::Whpx]
        );

        let linux_out = "Accelerators supported in QEMU binary:\ntcg\nkvm\nxen\n";
        assert_eq!(
            parse_accel_help(linux_out),
            vec![Accelerator::Tcg, Accelerator::Kvm]
        );

        let macos_noisy = "\nAccelerators supported in QEMU binary:\n  HVF  \n  TCG\n  hvf \ngarbage line\n\n";
        assert_eq!(
            parse_accel_help(macos_noisy),
            vec![Accelerator::Hvf, Accelerator::Tcg]
        );

        assert!(parse_accel_help("").is_empty());
        assert!(parse_accel_help("Possible accelerators:\nxen\nnvmm\n").is_empty());
    }

    #[test]
    fn select_accelerator_matrix_enforces_isolation_contract() {
        // Note QEMU 11 on Windows lists `tcg` before `whpx`: Preferred must still pick hardware.
        let tcg_then_whpx = [Accelerator::Tcg, Accelerator::Whpx];
        assert_eq!(
            select_accelerator(AccelerationPolicy::Required, &tcg_then_whpx),
            Ok(Accelerator::Whpx)
        );
        assert_eq!(
            select_accelerator(AccelerationPolicy::Preferred, &tcg_then_whpx),
            Ok(Accelerator::Whpx)
        );
        assert_eq!(
            select_accelerator(AccelerationPolicy::SoftwareOnly, &tcg_then_whpx),
            Ok(Accelerator::Tcg)
        );

        let kvm_and_tcg = [Accelerator::Kvm, Accelerator::Tcg];
        assert_eq!(
            select_accelerator(AccelerationPolicy::Required, &kvm_and_tcg),
            Ok(Accelerator::Kvm)
        );
        assert_eq!(
            select_accelerator(AccelerationPolicy::Preferred, &kvm_and_tcg),
            Ok(Accelerator::Kvm)
        );
        assert_eq!(
            select_accelerator(AccelerationPolicy::SoftwareOnly, &kvm_and_tcg),
            Ok(Accelerator::Tcg)
        );

        let hvf_only = [Accelerator::Hvf];
        assert_eq!(
            select_accelerator(AccelerationPolicy::Required, &hvf_only),
            Ok(Accelerator::Hvf)
        );
        assert_eq!(
            select_accelerator(AccelerationPolicy::Preferred, &hvf_only),
            Ok(Accelerator::Hvf)
        );
        assert!(matches!(
            select_accelerator(AccelerationPolicy::SoftwareOnly, &hvf_only),
            Err(SandboxError::AccelerationUnavailable(_))
        ));

        let tcg_only = [Accelerator::Tcg];
        assert!(matches!(
            select_accelerator(AccelerationPolicy::Required, &tcg_only),
            Err(SandboxError::AccelerationUnavailable(_))
        ));
        assert_eq!(
            select_accelerator(AccelerationPolicy::Preferred, &tcg_only),
            Ok(Accelerator::Tcg)
        );
        assert_eq!(
            select_accelerator(AccelerationPolicy::SoftwareOnly, &tcg_only),
            Ok(Accelerator::Tcg)
        );

        let empty: [Accelerator; 0] = [];
        for policy in [
            AccelerationPolicy::Required,
            AccelerationPolicy::Preferred,
            AccelerationPolicy::SoftwareOnly,
        ] {
            assert!(matches!(
                select_accelerator(policy, &empty),
                Err(SandboxError::AccelerationUnavailable(_))
            ));
        }
    }

    #[test]
    fn classify_launch_error_distinguishes_policy_blocks_and_not_found() {
        let bin = Path::new("qemu-system-x86_64");

        let applocker = classify_launch_error(bin, &io::Error::from_raw_os_error(1260));
        assert!(
            matches!(&applocker, SandboxError::BinaryExecutionBlocked(msg) if msg.contains("1260") && msg.contains("AppLocker"))
        );

        let wdac = classify_launch_error(bin, &io::Error::from_raw_os_error(4551));
        assert!(
            matches!(&wdac, SandboxError::BinaryExecutionBlocked(msg) if msg.contains("4551") && msg.contains("Windows Defender Application Control"))
        );

        for raw in [5, 13, 1] {
            assert!(matches!(
                classify_launch_error(bin, &io::Error::from_raw_os_error(raw)),
                SandboxError::BinaryExecutionBlocked(_)
            ));
        }

        let perm_denied = classify_launch_error(
            bin,
            &io::Error::new(io::ErrorKind::PermissionDenied, "permission denied"),
        );
        assert!(matches!(perm_denied, SandboxError::BinaryExecutionBlocked(_)));

        let not_found =
            classify_launch_error(bin, &io::Error::new(io::ErrorKind::NotFound, "missing"));
        assert!(matches!(not_found, SandboxError::NotFound(_)));

        let other =
            classify_launch_error(bin, &io::Error::new(io::ErrorKind::BrokenPipe, "broken"));
        assert!(matches!(other, SandboxError::Internal(_)));
    }

    #[test]
    fn find_qemu_binary_in_dirs_resolves_hits_and_rejects_missing_explicit() {
        let empty_dir = TestTempDir::new("empty");
        let bin_dir = TestTempDir::new("bin");
        let fake_qemu = bin_dir.path().join(QEMU_BINARY_NAME);
        fs::write(&fake_qemu, b"dummy").expect("write dummy qemu binary");

        let search_dirs = vec![empty_dir.path().to_path_buf(), bin_dir.path().to_path_buf()];

        let found = find_qemu_binary_in_dirs(None, &search_dirs).expect("should find in second dir");
        assert_eq!(found, fake_qemu);

        let explicit_hit =
            find_qemu_binary_in_dirs(Some(&fake_qemu), &[]).expect("explicit existing path");
        assert_eq!(explicit_hit, fake_qemu);

        // Missing explicit path must fail instead of falling back to search_dirs.
        let missing = empty_dir.path().join("does-not-exist-qemu");
        assert!(matches!(
            find_qemu_binary_in_dirs(Some(&missing), &search_dirs),
            Err(SandboxError::NotFound(_))
        ));

        // Passing a directory as explicit binary must also be rejected.
        assert!(matches!(
            find_qemu_binary_in_dirs(Some(bin_dir.path()), &search_dirs),
            Err(SandboxError::NotFound(_))
        ));

        assert!(matches!(
            find_qemu_binary_in_dirs(None, &[empty_dir.path().to_path_buf()]),
            Err(SandboxError::NotFound(_))
        ));
    }

    #[test]
    fn probe_available_accelerators_classifies_missing_binary() {
        let missing = Path::new("mini-pod-definitely-missing-qemu-binary-12345");
        assert!(matches!(
            probe_available_accelerators(missing),
            Err(SandboxError::NotFound(_))
        ));
    }
}
