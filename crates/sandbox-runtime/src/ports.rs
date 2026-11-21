//! Layer 2 Clean Architecture driven ports implemented by outer Layer 3 adapters (`sandbox-image`,
//! `sandbox-vmm`) and injected at the composition root.

use std::fmt;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use sandbox_core::{CapabilityReport, ExecRequest, SandboxError, SandboxId, SandboxSpec};
use sandbox_protocol::StreamTargetWire;

use crate::exec_stream::ExecStream;
use crate::tunnel::TunnelStream;
use crate::RuntimeManager;

/// Opaque shared OS file lock guard keeping an installed Portable Runtime Bundle pinned from
/// overlay preparation until the VMM has launched and opened its boot artifacts.
#[allow(dead_code)]
#[derive(Clone)]
pub struct BundleReadGuard(Arc<File>);

impl BundleReadGuard {
    pub fn new(file: File) -> Self {
        Self(Arc::new(file))
    }
}

impl fmt::Debug for BundleReadGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("BundleReadGuard").field(&"<locked>").finish()
    }
}

impl PartialEq for BundleReadGuard {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl Eq for BundleReadGuard {}

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
    pub bundle_guard: Option<BundleReadGuard>,
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

/// Synchronous pre-handshake boot progress callback invoked before and immediately after spawning
/// the VMM process so crash journals persist IPC paths and `(pid, start_token)` prior to handshake.
pub type PreBootJournalHook =
    Arc<dyn Fn(Option<(u32, u64)>, &[PathBuf]) -> Result<(), SandboxError> + Send + Sync>;

/// Configuration passed from Layer 2 runtime orchestration to boot a single sandbox VM.
#[derive(Clone)]
pub struct VmBootConfig {
    pub sandbox_id: SandboxId,
    pub spec: SandboxSpec,
    pub overlay: PreparedOverlay,
    pub work_dir: PathBuf,
    pub on_boot_progress: Option<PreBootJournalHook>,
}

impl VmBootConfig {
    /// Persists pre-boot artifact paths or spawned VMM `(pid, start_token)` via `on_boot_progress`
    /// when configured by [`crate::LocalRuntimeManager`].
    pub fn record_boot_progress(
        &self,
        identity: Option<(u32, u64)>,
        artifact_paths: &[PathBuf],
    ) -> Result<(), SandboxError> {
        if let Some(hook) = &self.on_boot_progress {
            hook(identity, artifact_paths)?;
        }
        Ok(())
    }
}

impl fmt::Debug for VmBootConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VmBootConfig")
            .field("sandbox_id", &self.sandbox_id)
            .field("spec", &self.spec)
            .field("overlay", &self.overlay)
            .field("work_dir", &self.work_dir)
            .field("has_on_boot_progress", &self.on_boot_progress.is_some())
            .finish()
    }
}

/// Active VM driver session exposed to Layer 2 runtime orchestration.
#[async_trait::async_trait]
pub trait VmSessionPort: Send + Sync {
    fn pid(&self) -> u32;
    fn start_token(&self) -> u64;
    fn artifact_paths(&self) -> &[PathBuf];
    fn is_alive(&self) -> bool;
    fn current_rss_bytes(&self) -> Option<u64>;
    /// Returns the accelerator selected for this session when the driver exposes it.
    fn accelerator_name(&self) -> Option<&'static str> {
        None
    }
    async fn exec_stream(&self, req: ExecRequest) -> Result<ExecStream, SandboxError>;
    async fn open_tunnel(&self, target: StreamTargetWire) -> Result<TunnelStream, SandboxError>;
    async fn enable_egress_proxy(
        &self,
        proxy_port: u16,
    ) -> Result<tokio::sync::mpsc::Receiver<TunnelStream>, SandboxError>;
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
    pub egress_rx: Option<tokio::sync::mpsc::Receiver<TunnelStream>>,
}

impl fmt::Debug for VmBootOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VmBootOutcome")
            .field("pid", &self.pid)
            .field("start_token", &self.start_token)
            .field("artifact_paths", &self.artifact_paths)
            .field("hardware_accelerated", &self.hardware_accelerated)
            .field("capabilities", &self.capabilities)
            .field("has_egress_rx", &self.egress_rx.is_some())
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
