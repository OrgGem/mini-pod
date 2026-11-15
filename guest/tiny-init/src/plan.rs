#![forbid(unsafe_code)]
//! Pure boot-plan constants and kernel cmdline parsing for `tiny-init`.

/// Default path inside the guest rootfs for the RPC agent binary.
pub const DEFAULT_AGENT_PATH: &str = "/bin/sandbox-agent";

/// Kernel modules loaded (when `/sbin/modprobe` is present) before mounting guest storage and IPC.
pub const REQUIRED_MODULES: &[&str] = &[
    "virtio",
    "virtio_ring",
    "virtio_pci",
    "virtio_mmio",
    "virtio_console",
    "virtio_blk",
    "ext4",
    "overlay",
];

/// Mount options for the writable overlay mounted over read-only `/newroot/etc`.
pub const ETC_OVERLAY_OPTIONS: &str =
    "lowerdir=/mnt/disk/rootfs/etc,upperdir=/mnt/disk/rw/etc-upper,workdir=/mnt/disk/rw/etc-work";

/// Writable bind mounts mapped from `/mnt/disk/rw/*` onto read-only `/newroot/*` mountpoints.
pub const WRITABLE_BIND_MOUNTS: &[(&str, &str)] = &[
    ("/mnt/disk/rw/containers", "/newroot/var/lib/containers"),
    ("/mnt/disk/rw/workspace", "/newroot/workspace"),
    ("/mnt/disk/rw/tmp", "/newroot/tmp"),
    ("/mnt/disk/rw/var-tmp", "/newroot/var/tmp"),
    ("/mnt/disk/rw/root", "/newroot/root"),
];

/// Parsed guest boot configuration derived from `/proc/cmdline`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BootConfig {
    /// Optional block device path (e.g. `/dev/vda`) holding `rootfs/` and `rw/`.
    pub root_device: Option<String>,
    /// Absolute path of the guest agent binary to supervise.
    pub agent_path: String,
}

impl Default for BootConfig {
    fn default() -> Self {
        Self {
            root_device: None,
            agent_path: DEFAULT_AGENT_PATH.to_owned(),
        }
    }
}

impl BootConfig {
    /// Parses `/proc/cmdline` tokens using last-wins overrides for `minipod.root=<dev>`
    /// and `minipod.agent=<path>`, rejecting invalid or traversal paths.
    pub fn from_cmdline(cmdline: &str) -> Self {
        let mut config = Self::default();
        for token in cmdline.split_whitespace() {
            if let Some(dev) = token.strip_prefix("minipod.root=") {
                if is_valid_absolute_path(dev) {
                    config.root_device = Some(dev.to_owned());
                }
            } else if let Some(agent) = token.strip_prefix("minipod.agent=") {
                if is_valid_absolute_path(agent) {
                    config.agent_path = agent.to_owned();
                }
            }
        }
        config
    }
}

fn is_valid_absolute_path(path: &str) -> bool {
    path.starts_with('/')
        && !path.contains('\0')
        && !path.chars().any(char::is_whitespace)
        && !path.split('/').any(|seg| seg == "..")
        && path.split('/').any(|seg| !seg.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_boot_config_uses_default_agent_and_no_root() {
        assert_eq!(BootConfig::from_cmdline(""), BootConfig::default());
        assert_eq!(
            BootConfig::from_cmdline("console=ttyS0 quiet panic=-1"),
            BootConfig {
                root_device: None,
                agent_path: DEFAULT_AGENT_PATH.to_owned(),
            }
        );
    }

    #[test]
    fn parses_minipod_root_and_agent_tokens() {
        let cfg = BootConfig::from_cmdline(
            "console=ttyS0 minipod.root=/dev/vda minipod.agent=/usr/local/bin/sandbox-agent quiet",
        );
        assert_eq!(cfg.root_device.as_deref(), Some("/dev/vda"));
        assert_eq!(cfg.agent_path, "/usr/local/bin/sandbox-agent");
    }

    #[test]
    fn last_wins_override_for_root_and_agent() {
        let cfg = BootConfig::from_cmdline(
            "minipod.root=/dev/vda minipod.agent=/sbin/old minipod.root=/dev/vdb minipod.agent=/bin/new-agent",
        );
        assert_eq!(cfg.root_device.as_deref(), Some("/dev/vdb"));
        assert_eq!(cfg.agent_path, "/bin/new-agent");
    }

    #[test]
    fn rejects_relative_empty_nul_and_traversal_paths() {
        let invalid_cases = [
            "minipod.root= minipod.agent=",
            "minipod.root=/ minipod.agent=/",
            "minipod.root=dev/vda minipod.agent=bin/sandbox-agent",
            "minipod.root=/dev/../etc/passwd minipod.agent=/bin/../../sh",
            "minipod.root=/.. minipod.agent=/bin/..",
            "minipod.root=/dev/vda\0bad minipod.agent=/bin/agent\0bad",
        ];

        for cmdline in invalid_cases {
            let cfg = BootConfig::from_cmdline(cmdline);
            assert_eq!(
                cfg,
                BootConfig::default(),
                "invalid cmdline '{cmdline}' should be ignored"
            );
        }

        // Invalid trailing tokens must not clobber earlier valid values.
        let cfg = BootConfig::from_cmdline(
            "minipod.root=/dev/vda minipod.agent=/bin/custom minipod.root=../bad minipod.agent=rel",
        );
        assert_eq!(cfg.root_device.as_deref(), Some("/dev/vda"));
        assert_eq!(cfg.agent_path, "/bin/custom");
    }

    #[test]
    fn allows_filenames_containing_double_dots_without_parent_segment() {
        let cfg = BootConfig::from_cmdline("minipod.root=/dev/disk..0 minipod.agent=/bin/agent..v2");
        assert_eq!(cfg.root_device.as_deref(), Some("/dev/disk..0"));
        assert_eq!(cfg.agent_path, "/bin/agent..v2");
    }

    #[test]
    fn verifies_writable_bind_mounts_and_etc_overlay_options() {
        assert!(ETC_OVERLAY_OPTIONS.contains("lowerdir=/mnt/disk/rootfs/etc"));
        assert!(ETC_OVERLAY_OPTIONS.contains("upperdir=/mnt/disk/rw/etc-upper"));
        assert!(ETC_OVERLAY_OPTIONS.contains("workdir=/mnt/disk/rw/etc-work"));

        assert_eq!(
            WRITABLE_BIND_MOUNTS,
            &[
                ("/mnt/disk/rw/containers", "/newroot/var/lib/containers"),
                ("/mnt/disk/rw/workspace", "/newroot/workspace"),
                ("/mnt/disk/rw/tmp", "/newroot/tmp"),
                ("/mnt/disk/rw/var-tmp", "/newroot/var/tmp"),
                ("/mnt/disk/rw/root", "/newroot/root"),
            ]
        );
        for &(src, dst) in WRITABLE_BIND_MOUNTS {
            assert!(src.starts_with("/mnt/disk/rw/"));
            assert!(dst.starts_with("/newroot/"));
        }

        for expected in ["virtio_console", "virtio_blk", "ext4", "overlay"] {
            assert!(REQUIRED_MODULES.contains(&expected));
        }
    }
}
