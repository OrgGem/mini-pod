#![forbid(unsafe_code)]
//! Layer 2 runtime manager contract: lifecycle orchestration, lease management,
//! execution streaming, driven adapter ports, safe workspace tar copy I/O, and crash journaling.

pub mod admission;
pub mod egress;
pub mod exec_stream;
pub mod journal;
pub mod manager;
pub mod ports;
pub mod safe_tar;
pub mod tunnel;

use std::fs;
use std::io::{self, ErrorKind};
use std::path::{Path, PathBuf};
use std::time::Duration;

use sandbox_core::{DestroyStatus, ExecRequest, SandboxError, SandboxId, SandboxLease, SandboxSpec};

pub use admission::{AdmissionLimits, AdmissionUsage};
pub use egress::{
    is_forbidden_ip, is_forbidden_ipv4, is_forbidden_ipv6, AsyncStream, BoxedUpstreamStream,
    HostDnsResolver, HostEgressProxy, SystemDnsResolver, TcpUpstreamDialer, UpstreamDialer,
};

pub use exec_stream::{
    CollectedExecOutput, ExecOutputChunk, ExecStream, ExecStreamHandle, OutputStreamKind,
};
pub use journal::{
    cleanup_artifacts_with_backoff, JournalLifecycleState, JournalRecord, JournalStore,
};
pub use manager::{
    validate_guest_path, LocalRuntimeManager, ReconciliationReport, RuntimeManagerConfig,
};
pub use ports::{
    DiskOverlayPort, PreparedOverlay, SandboxTunnelPort, VmBootConfig, VmBootOutcome, VmRuntimePort,
    VmSessionPort,
};
pub use safe_tar::{extract_tar_safely, measure_dir_bytes, pack_host_path_to_tar};
pub use tunnel::{TunnelStream, TunnelStreamHandle};

#[async_trait::async_trait]
pub trait RuntimeManager: Send + Sync {
    async fn spawn(&self, spec: SandboxSpec) -> Result<SandboxLease, SandboxError>;
    async fn renew_lease(&self, id: &SandboxId, ttl: Duration) -> Result<(), SandboxError>;
    async fn exec_stream(&self, id: &SandboxId, req: ExecRequest) -> Result<ExecStream, SandboxError>;
    async fn copy_in(&self, id: &SandboxId, src_host: PathBuf, dst_guest: String) -> Result<(), SandboxError>;
    async fn copy_out(&self, id: &SandboxId, src_guest: String, dst_host: PathBuf) -> Result<(), SandboxError>;
    /// Idempotent destroy operation, safe for repeated invocation by startup reconciler.
    async fn destroy(&self, id: &SandboxId) -> Result<DestroyStatus, SandboxError>;
}

pub(crate) const WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;

/// Returns `true` when `meta` represents a symlink or Windows reparse point/junction.
pub(crate) fn is_symlink_or_reparse(meta: &fs::Metadata) -> bool {
    if meta.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if (meta.file_attributes() & WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            return true;
        }
    }
    #[cfg(not(windows))]
    let _ = WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT;
    false
}

pub(crate) fn map_fs_error(path: &Path, action: &str, err: io::Error) -> SandboxError {
    match err.kind() {
        ErrorKind::NotFound => SandboxError::NotFound(format!(
            "cannot {action} '{}': {err}",
            path.display()
        )),
        ErrorKind::PermissionDenied => SandboxError::PolicyViolation(format!(
            "permission denied while attempting to {action} '{}': {err}",
            path.display()
        )),
        _ => SandboxError::Internal(format!(
            "failed to {action} '{}': {err}",
            path.display()
        )),
    }
}

#[cfg(test)]
pub(crate) mod test_util {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_SEQ: AtomicU64 = AtomicU64::new(0);

    pub(crate) struct TestTempDir(PathBuf);

    impl TestTempDir {
        pub(crate) fn new(label: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "minipod-rt-test-{label}-{}-{}",
                std::process::id(),
                TEST_SEQ.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&dir).expect("create test temp dir");
            Self(dir)
        }

        pub(crate) fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestTempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}
