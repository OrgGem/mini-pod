//! QEMU command-line builder enforcing isolation, no-NIC defaults, and `virtio-serial` wiring.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use sandbox_core::{GuestArch, NetworkPolicy, SandboxError};

use crate::accel::Accelerator;
use crate::ipc::validate_socket_path;

/// Well-known `virtio-serial` port name opened inside the Linux guest by `sandbox-agent`.
pub const AGENT_VIRTIO_PORT_NAME: &str = "org.minipod.agent.0";

/// Configuration for building a headless, isolated QEMU launch command line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuLaunchConfig {
    pub qemu_bin: PathBuf,
    pub arch: GuestArch,
    pub accelerator: Accelerator,
    pub kernel_path: PathBuf,
    pub initrd_path: Option<PathBuf>,
    pub kernel_cmdline: String,
    pub root_disk_qcow2: Option<PathBuf>,
    pub vcpus: u8,
    pub ram_mb: u32,
    pub agent_socket_path: PathBuf,
    pub serial_log_path: Option<PathBuf>,
    pub network: NetworkPolicy,
}

impl QemuLaunchConfig {
    /// Validates security invariants and builds QEMU CLI arguments.
    ///
    /// Uses `-chardev socket,id=agent0,path=<sock>,server=off` against a host-bound `AF_UNIX`
    /// listener inside an owner-only directory (see [`crate::ipc`] module docs for the Phase 1
    /// Windows Named Pipe security finding).
    pub fn build_args(&self) -> Result<Vec<OsString>, SandboxError> {
        if self.vcpus == 0 {
            return Err(SandboxError::InvalidSpec(
                "QEMU vcpus must be >= 1".to_owned(),
            ));
        }
        if self.ram_mb == 0 {
            return Err(SandboxError::InvalidSpec(
                "QEMU ram_mb must be >= 1".to_owned(),
            ));
        }
        validate_socket_path(&self.agent_socket_path)?;
        validate_isolated_network(&self.network)?;
        let cleaned_root_disk = self
            .root_disk_qcow2
            .as_deref()
            .map(clean_drive_path)
            .transpose()?;

        let sock_str = self
            .agent_socket_path
            .to_str()
            .expect("validate_socket_path guarantees valid UTF-8");

        let mut args: Vec<OsString> = Vec::with_capacity(34);
        args.push("-nodefaults".into());
        args.push("-display".into());
        args.push("none".into());
        args.push("-monitor".into());
        args.push("none".into());

        args.push("-serial".into());
        if let Some(serial_log) = &self.serial_log_path {
            let mut serial_arg = OsString::from("file:");
            serial_arg.push(serial_log.as_os_str());
            args.push(serial_arg);
        } else {
            args.push("none".into());
        }

        match self.arch {
            GuestArch::X86_64 => {
                args.push("-machine".into());
                args.push("q35".into());
            }
            GuestArch::Aarch64 => {
                args.push("-machine".into());
                args.push("virt".into());
                args.push("-cpu".into());
                // Avoid slow ARMv9 pointer-auth emulation when running TCG software emulation.
                args.push(if self.accelerator.is_hardware() {
                    "host".into()
                } else {
                    "cortex-a72".into()
                });
            }
        }
        args.push("-accel".into());
        args.push(self.accelerator.as_qemu_arg().into());
        args.push("-smp".into());
        args.push(self.vcpus.to_string().into());
        args.push("-m".into());
        args.push(format!("{}M", self.ram_mb).into());

        args.push("-nic".into());
        args.push("none".into());

        args.push("-kernel".into());
        args.push(self.kernel_path.as_os_str().to_os_string());

        if let Some(initrd) = &self.initrd_path {
            args.push("-initrd".into());
            args.push(initrd.as_os_str().to_os_string());
        }
        if !self.kernel_cmdline.trim().is_empty() {
            args.push("-append".into());
            args.push(self.kernel_cmdline.as_str().into());
        }

        if let Some(disk_str) = cleaned_root_disk {
            args.push("-drive".into());
            args.push(format!("file={disk_str},if=none,format=qcow2,id=rootfs0").into());
            args.push("-device".into());
            args.push("virtio-blk-pci,drive=rootfs0".into());
        }

        args.push("-chardev".into());
        args.push(format!("socket,id=agent0,path={sock_str},server=off").into());
        args.push("-device".into());
        args.push("virtio-serial-pci".into());
        args.push("-device".into());
        args.push(format!("virtserialport,chardev=agent0,name={AGENT_VIRTIO_PORT_NAME}").into());

        Ok(args)
    }
}

fn clean_drive_path(path: &Path) -> Result<String, SandboxError> {
    let raw = path.to_str().ok_or_else(|| {
        SandboxError::InvalidSpec(format!(
            "root disk path '{}' is not valid UTF-8",
            path.display()
        ))
    })?;

    for ch in [',', '\0', '\r', '\n'] {
        if raw.contains(ch) {
            return Err(SandboxError::InvalidSpec(format!(
                "root disk path '{}' contains forbidden character {:?}",
                path.display(),
                ch
            )));
        }
    }

    let cleaned = strip_windows_verbatim_prefix(raw)?;
    if cleaned.is_empty() {
        return Err(SandboxError::InvalidSpec(
            "root disk path must not be empty".to_owned(),
        ));
    }

    Ok(cleaned)
}

fn strip_windows_verbatim_prefix(raw: &str) -> Result<String, SandboxError> {
    if let Some(rest) = raw.strip_prefix(r"\\?\") {
        if let Some(unc) = rest
            .strip_prefix(r"UNC\")
            .or_else(|| rest.strip_prefix(r"unc\"))
        {
            if unc.is_empty() {
                return Err(SandboxError::InvalidSpec(
                    "root disk UNC path must not be empty".to_owned(),
                ));
            }
            return Ok(format!(r"\\{unc}"));
        }
        return Ok(rest.to_owned());
    }
    Ok(raw.to_owned())
}

pub(crate) fn validate_isolated_network(network: &NetworkPolicy) -> Result<(), SandboxError> {
    match network {
        NetworkPolicy::Isolated => Ok(()),
        NetworkPolicy::InternetOnly
        | NetworkPolicy::DomainAllowList { .. }
        | NetworkPolicy::Unrestricted => Err(SandboxError::PolicyViolation(
            "host egress proxy is not enabled until Phase 5; refusing non-Isolated QEMU network policy".to_owned(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sandbox_core::EgressRule;

    fn sample_config() -> QemuLaunchConfig {
        QemuLaunchConfig {
            qemu_bin: PathBuf::from("qemu-system-x86_64"),
            arch: GuestArch::X86_64,
            accelerator: Accelerator::Tcg,
            kernel_path: PathBuf::from("/images/vmlinuz"),
            initrd_path: Some(PathBuf::from("/images/initrd.img")),
            kernel_cmdline: "console=ttyS0 panic=1".to_owned(),
            root_disk_qcow2: None,
            vcpus: 2,
            ram_mb: 512,
            agent_socket_path: PathBuf::from("/tmp/mp-1/a.sock"),
            serial_log_path: None,
            network: NetworkPolicy::Isolated,
        }
    }

    fn as_strings(args: &[OsString]) -> Vec<String> {
        args.iter()
            .map(|a| a.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn build_args_emits_isolated_virtio_serial_command_line() {
        let cfg = sample_config();
        let args = as_strings(&cfg.build_args().expect("valid isolated config"));

        assert!(args.contains(&"-nodefaults".to_owned()));
        assert!(args.windows(2).any(|w| w == ["-display", "none"]));
        assert!(args.windows(2).any(|w| w == ["-monitor", "none"]));
        assert!(args.windows(2).any(|w| w == ["-serial", "none"]));
        assert!(args.windows(2).any(|w| w == ["-machine", "q35"]));
        assert!(!args.contains(&"-cpu".to_owned()));
        assert!(!args.contains(&"-drive".to_owned()));
        assert!(args.windows(2).any(|w| w == ["-accel", "tcg"]));
        assert!(args.windows(2).any(|w| w == ["-smp", "2"]));
        assert!(args.windows(2).any(|w| w == ["-m", "512M"]));
        assert!(args.windows(2).any(|w| w == ["-nic", "none"]));
        assert!(args.windows(2).any(|w| w == ["-kernel", "/images/vmlinuz"]));
        assert!(args.windows(2).any(|w| w == ["-initrd", "/images/initrd.img"]));
        assert!(args.windows(2).any(|w| w == ["-append", "console=ttyS0 panic=1"]));
        assert!(args
            .windows(2)
            .any(|w| w == ["-chardev", "socket,id=agent0,path=/tmp/mp-1/a.sock,server=off"]));
        assert!(args.windows(2).any(|w| w == ["-device", "virtio-serial-pci"]));
        assert!(args
            .windows(2)
            .any(|w| w == ["-device", "virtserialport,chardev=agent0,name=org.minipod.agent.0"]));
    }

    #[test]
    fn build_args_emits_aarch64_machine_and_cpu_for_tcg_and_hardware() {
        let mut tcg_cfg = sample_config();
        tcg_cfg.qemu_bin = PathBuf::from("qemu-system-aarch64");
        tcg_cfg.arch = GuestArch::Aarch64;
        tcg_cfg.accelerator = Accelerator::Tcg;
        tcg_cfg.kernel_cmdline = "console=ttyAMA0 panic=1".to_owned();

        let tcg_args = as_strings(&tcg_cfg.build_args().expect("valid aarch64 tcg config"));
        assert!(tcg_args.windows(2).any(|w| w == ["-machine", "virt"]));
        assert!(tcg_args.windows(2).any(|w| w == ["-cpu", "cortex-a72"]));
        assert!(tcg_args.windows(2).any(|w| w == ["-accel", "tcg"]));

        for hw_accel in [Accelerator::Hvf, Accelerator::Kvm] {
            let mut hw_cfg = tcg_cfg.clone();
            hw_cfg.accelerator = hw_accel;
            let hw_args = as_strings(&hw_cfg.build_args().expect("valid aarch64 hw config"));
            assert!(hw_args.windows(2).any(|w| w == ["-machine", "virt"]));
            assert!(hw_args.windows(2).any(|w| w == ["-cpu", "host"]));
            assert!(hw_args
                .windows(2)
                .any(|w| w == ["-accel", hw_accel.as_qemu_arg()]));
        }
    }

    #[test]
    fn build_args_wires_virtio_blk_qcow2_and_strips_windows_verbatim_prefixes() {
        let mut cfg = sample_config();
        cfg.root_disk_qcow2 = Some(PathBuf::from("/var/lib/minipod/worker.qcow2"));
        let args = as_strings(&cfg.build_args().expect("valid qcow2 config"));
        assert!(args.windows(2).any(|w| {
            w == [
                "-drive",
                "file=/var/lib/minipod/worker.qcow2,if=none,format=qcow2,id=rootfs0",
            ]
        }));
        assert!(args
            .windows(2)
            .any(|w| w == ["-device", "virtio-blk-pci,drive=rootfs0"]));

        let mut verbatim_drive = sample_config();
        verbatim_drive.root_disk_qcow2 = Some(PathBuf::from(r"\\?\C:\minipod\worker.qcow2"));
        let drive_args = as_strings(&verbatim_drive.build_args().expect("verbatim drive path"));
        assert!(drive_args.windows(2).any(|w| {
            w == [
                "-drive",
                r"file=C:\minipod\worker.qcow2,if=none,format=qcow2,id=rootfs0",
            ]
        }));

        let mut verbatim_unc = sample_config();
        verbatim_unc.root_disk_qcow2 =
            Some(PathBuf::from(r"\\?\UNC\filesrv\share\worker.qcow2"));
        let unc_args = as_strings(&verbatim_unc.build_args().expect("verbatim UNC path"));
        assert!(unc_args.windows(2).any(|w| {
            w == [
                "-drive",
                r"file=\\filesrv\share\worker.qcow2,if=none,format=qcow2,id=rootfs0",
            ]
        }));
    }

    #[test]
    fn build_args_rejects_drive_option_injection_and_invalid_root_disk_paths() {
        for bad in [
            "",
            r"\\?\",
            r"\\?\UNC\",
            "/tmp/bad,format=raw/worker.qcow2",
            "C:\\dir\\bad\0.qcow2",
            "/tmp/bad\r.qcow2",
            "/tmp/bad\n.qcow2",
        ] {
            let mut cfg = sample_config();
            cfg.root_disk_qcow2 = Some(PathBuf::from(bad));
            assert!(
                matches!(cfg.build_args(), Err(SandboxError::InvalidSpec(_))),
                "expected InvalidSpec for root_disk_qcow2 {bad:?}"
            );
        }

        #[cfg(windows)]
        {
            use std::os::windows::ffi::OsStringExt;
            let non_utf8 = OsString::from_wide(&[0x0061, 0xD800]);
            let mut cfg = sample_config();
            cfg.root_disk_qcow2 = Some(PathBuf::from(non_utf8));
            assert!(matches!(cfg.build_args(), Err(SandboxError::InvalidSpec(_))));
        }
        #[cfg(unix)]
        {
            use std::ffi::OsStr;
            use std::os::unix::ffi::OsStrExt;
            let non_utf8 = OsStr::from_bytes(b"/tmp/\xff.qcow2");
            let mut cfg = sample_config();
            cfg.root_disk_qcow2 = Some(PathBuf::from(non_utf8));
            assert!(matches!(cfg.build_args(), Err(SandboxError::InvalidSpec(_))));
        }
    }

    #[test]
    fn build_args_handles_optional_serial_initrd_and_cmdline() {
        let mut cfg = sample_config();
        cfg.accelerator = Accelerator::Kvm;
        cfg.initrd_path = None;
        cfg.kernel_cmdline = "   ".to_owned();
        cfg.serial_log_path = Some(PathBuf::from("/tmp/mp-1/console.log"));

        let args = as_strings(&cfg.build_args().expect("valid config"));
        assert!(args.windows(2).any(|w| w == ["-accel", "kvm"]));
        assert!(args.windows(2).any(|w| w == ["-serial", "file:/tmp/mp-1/console.log"]));
        assert!(!args.contains(&"-initrd".to_owned()));
        assert!(!args.contains(&"-append".to_owned()));
    }

    #[test]
    fn build_args_rejects_non_isolated_network_policies_in_phase_1() {
        let disallowed = [
            NetworkPolicy::InternetOnly,
            NetworkPolicy::DomainAllowList {
                rules: vec![EgressRule {
                    domain: "example.com".to_owned(),
                    port: 443,
                }],
            },
            NetworkPolicy::Unrestricted,
        ];

        for policy in disallowed {
            let mut cfg = sample_config();
            cfg.network = policy;
            assert!(
                matches!(cfg.build_args(), Err(SandboxError::PolicyViolation(_))),
                "non-isolated policy must be rejected until Phase 5 egress proxy"
            );
        }
    }

    #[test]
    fn build_args_rejects_oversized_or_malformed_socket_path_and_zero_budgets() {
        let mut too_long = sample_config();
        too_long.agent_socket_path = PathBuf::from(format!("/tmp/{}/a.sock", "x".repeat(95)));
        assert!(matches!(
            too_long.build_args(),
            Err(SandboxError::InvalidSpec(_))
        ));

        let mut comma_path = sample_config();
        comma_path.agent_socket_path = PathBuf::from("/tmp/bad,dir/a.sock");
        assert!(matches!(
            comma_path.build_args(),
            Err(SandboxError::InvalidSpec(_))
        ));

        let mut zero_vcpu = sample_config();
        zero_vcpu.vcpus = 0;
        assert!(matches!(
            zero_vcpu.build_args(),
            Err(SandboxError::InvalidSpec(_))
        ));

        let mut zero_ram = sample_config();
        zero_ram.ram_mb = 0;
        assert!(matches!(
            zero_ram.build_args(),
            Err(SandboxError::InvalidSpec(_))
        ));
    }
}
