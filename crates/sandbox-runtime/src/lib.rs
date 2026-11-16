#![forbid(unsafe_code)]
//! Layer 2 runtime manager contract: lifecycle orchestration, lease management,
//! execution streaming, driven adapter ports, safe workspace tar copy I/O, and crash journaling.

pub mod admission;
pub mod benchmark;
pub mod egress;
pub mod exec_stream;
pub mod journal;
pub mod manager;
pub mod ports;
pub mod safe_tar;
pub mod tunnel;
pub mod warm_pool;

use std::path::PathBuf;
use std::time::Duration;

use sandbox_core::{DestroyStatus, ExecRequest, SandboxError, SandboxId, SandboxLease, SandboxSpec};

pub use admission::{AdmissionLimits, AdmissionUsage};
pub use benchmark::{BenchmarkMetricStatus, LatencySummary, PlatformBenchmarkReport};
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
    DiskOverlayPort, PreBootJournalHook, PreparedOverlay, SandboxTunnelPort, VmBootConfig,
    VmBootOutcome, VmRuntimePort, VmSessionPort,
};
pub use safe_tar::{extract_tar_safely, measure_dir_bytes, pack_host_path_to_tar, validate_tar_bytes};
pub use tunnel::{TunnelStream, TunnelStreamHandle};
pub use warm_pool::{WarmPoolConfig, WarmPoolKey, WarmPoolStats};

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

pub(crate) use sandbox_core::safe_tar::{is_symlink_or_reparse, map_fs_error};

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
