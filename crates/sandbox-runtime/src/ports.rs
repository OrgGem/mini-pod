//! Layer 2 Clean Architecture driven ports implemented by outer Layer 3 adapters (`sandbox-image`,
//! `sandbox-vmm`) and injected at the composition root.

use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use sandbox_core::{CapabilityReport, ExecRequest, SandboxError, SandboxId, SandboxSpec};
use sandbox_protocol::StreamTargetWire;

use crate::exec_stream::ExecStream;
use crate::tunnel::TunnelStream;
use crate::RuntimeManager;

/// Per-sandbox Copy-on-Write disk overlay and verified boot artifact paths.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparedOverlay {
    pub overlay_path: PathBuf,
    pub kernel_path: PathBuf,
    pub initramfs_path: PathBuf,
    pub rootfs_path: PathBuf,
    pub kernel_cmdline: String,
    pub virtual_disk_mb: u32,
    pub provisioned_host_bytes: u64,
}

/// Driven port for preparing and removing per-sandbox CoW disk overlays.
#[async_trait::async_trait]
pub trait DiskOverlayPort: Send + Sync {
    async fn prepare_overlay(
        &self,
        sandbox_id: &SandboxId,
        spec: &SandboxSpec,
        work_dir: &Path,
    ) -> Result<PreparedOverlay, SandboxError>;

    async fn remove_overlay(&self, overlay_path: &Path) -> Result<(), SandboxError>;
}

/// Configuration passed from Layer 2 runtime orchestration to boot a single sandbox VM.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VmBootConfig {
    pub sandbox_id: SandboxId,
    pub spec: SandboxSpec,
    pub overlay: PreparedOverlay,
    pub work_dir: PathBuf,
}

/// Active VM driver session exposed to Layer 2 runtime orchestration.
#[async_trait::async_trait]
pub trait VmSessionPort: Send + Sync {
    fn pid(&self) -> u32;
    fn start_token(&self) -> u64;
    fn artifact_paths(&self) -> &[PathBuf];
    fn is_alive(&self) -> bool;
    fn current_rss_bytes(&self) -> Option<u64>;
    async fn exec_stream(&self, req: ExecRequest) -> Result<ExecStream, SandboxError>;
    async fn open_tunnel(&self, target: StreamTargetWire) -> Result<TunnelStream, SandboxError>;
    async fn copy_in_tar(
        &self,
        dst_guest: &str,
        tar_bytes: Vec<u8>,
        max_bytes: u64,
    ) -> Result<u64, SandboxError>;
    async fn copy_out_tar(
        &self,
        src_guest: &str,
        max_bytes: u64,
    ) -> Result<Vec<u8>, SandboxError>;
    async fn graceful_shutdown(&self, timeout: Duration) -> Result<bool, SandboxError>;
    async fn force_kill(&self) -> Result<(), SandboxError>;
}

/// Booted VM session metadata and verified host enforcement capabilities.
pub struct VmBootOutcome {
    pub session: Box<dyn VmSessionPort>,
    pub pid: u32,
    pub start_token: u64,
    pub artifact_paths: Vec<PathBuf>,
    pub hardware_accelerated: bool,
    pub capabilities: CapabilityReport,
}

impl fmt::Debug for VmBootOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VmBootOutcome")
            .field("pid", &self.pid)
            .field("start_token", &self.start_token)
            .field("artifact_paths", &self.artifact_paths)
            .field("hardware_accelerated", &self.hardware_accelerated)
            .field("capabilities", &self.capabilities)
            .finish_non_exhaustive()
    }
}

/// Extension port exposing host-to-guest Podman Unix socket and loopback TCP stream tunnels
/// on active [`RuntimeManager`] instances without altering the core [`RuntimeManager`] contract.
#[async_trait::async_trait]
pub trait SandboxTunnelPort: RuntimeManager {
    async fn open_podman_unix_stream(&self, id: &SandboxId) -> Result<TunnelStream, SandboxError>;
    async fn open_guest_tcp_stream(
        &self,
        id: &SandboxId,
        guest_port: u16,
    ) -> Result<TunnelStream, SandboxError>;
}

/// Driven port for booting sandbox VMs and terminating verified orphan VMM processes.
#[async_trait::async_trait]
pub trait VmRuntimePort: Send + Sync {
    async fn boot_vm(&self, config: VmBootConfig) -> Result<VmBootOutcome, SandboxError>;
    async fn kill_orphan_process(
        &self,
        pid: u32,
        expected_start_token: u64,
    ) -> Result<bool, SandboxError>;
}
