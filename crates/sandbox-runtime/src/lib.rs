#![forbid(unsafe_code)]
//! Layer 2 runtime manager contract: lifecycle orchestration, lease management,
//! execution streaming, safe workspace copy I/O, and idempotent teardown.

use std::path::PathBuf;
use std::time::Duration;

use sandbox_core::{DestroyStatus, ExecRequest, SandboxError, SandboxId, SandboxLease, SandboxSpec};
use sandbox_protocol::StreamId;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExecStream {
    pub stream_id: StreamId,
}

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
