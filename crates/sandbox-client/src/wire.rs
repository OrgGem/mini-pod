//! Bounded length-prefixed JSON control protocol shared between `sandbox-client` and `sandboxd`.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use sandbox_core::{
    AccelerationPolicy, CapabilityReport, DestroyStatus, EgressRule, EnforcementLevel,
    ExecExitStatus, ExecRequest, ExecTarget, IsolationMode, NetworkPolicy, ResourceBudget,
    SandboxError, SandboxId, SandboxLease, SandboxSpec,
};
use serde_json::{json, Map, Value};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum control wire frame payload size (24 MiB, accommodating base64-encoded 16 MiB tar payloads).
pub const MAX_CONTROL_FRAME_BYTES: usize = 24 * 1024 * 1024;

const B64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Lossless wire representation of all 11 [`SandboxError`] variants.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireError {
    pub kind: String,
    pub message: String,
}

impl WireError {
    /// Converts a [`SandboxError`] into a wire-safe [`WireError`].
    pub fn from_sandbox_error(err: &SandboxError) -> Self {
        let (kind, msg) = match err {
            SandboxError::InvalidSpec(m) => ("InvalidSpec", m),
            SandboxError::UnsupportedIsolationMode(m) => ("UnsupportedIsolationMode", m),
            SandboxError::BinaryExecutionBlocked(m) => ("BinaryExecutionBlocked", m),
            SandboxError::AccelerationUnavailable(m) => ("AccelerationUnavailable", m),
            SandboxError::NotFound(m) => ("NotFound", m),
            SandboxError::LeaseExpired(m) => ("LeaseExpired", m),
            SandboxError::AdmissionRejected(m) => ("AdmissionRejected", m),
            SandboxError::BudgetExceeded(m) => ("BudgetExceeded", m),
            SandboxError::PolicyViolation(m) => ("PolicyViolation", m),
            SandboxError::Transport(m) => ("Transport", m),
            SandboxError::Internal(m) => ("Internal", m),
        };
        Self {
            kind: kind.to_owned(),
            message: msg.clone(),
        }
    }

    /// Reconstructs the corresponding [`SandboxError`] from this wire error.
    pub fn to_sandbox_error(&self) -> SandboxError {
        let msg = self.message.clone();
        match self.kind.as_str() {
            "InvalidSpec" => SandboxError::InvalidSpec(msg),
            "UnsupportedIsolationMode" => SandboxError::UnsupportedIsolationMode(msg),
            "BinaryExecutionBlocked" => SandboxError::BinaryExecutionBlocked(msg),
            "AccelerationUnavailable" => SandboxError::AccelerationUnavailable(msg),
            "NotFound" => SandboxError::NotFound(msg),
            "LeaseExpired" => SandboxError::LeaseExpired(msg),
            "AdmissionRejected" => SandboxError::AdmissionRejected(msg),
            "BudgetExceeded" => SandboxError::BudgetExceeded(msg),
            "PolicyViolation" => SandboxError::PolicyViolation(msg),
            "Transport" => SandboxError::Transport(msg),
            "Internal" => SandboxError::Internal(msg),
            other => SandboxError::Internal(format!("unknown wire error kind '{other}': {msg}")),
        }
    }

    fn to_json_value(&self) -> Value {
        json!({
            "kind": self.kind,
            "message": self.message,
        })
    }

    fn from_json_value(val: &Value) -> Result<Self, SandboxError> {
        let obj = expect_object(val, "WireError")?;
        let kind = req_string(obj, "kind", "WireError")?;
        if !is_known_error_kind(&kind) {
            return Err(SandboxError::Transport(format!(
                "unknown WireError kind '{kind}'"
            )));
        }
        let message = req_string(obj, "message", "WireError")?;
        Ok(Self { kind, message })
    }
}

impl From<&SandboxError> for WireError {
    fn from(err: &SandboxError) -> Self {
        Self::from_sandbox_error(err)
    }
}

impl From<SandboxError> for WireError {
    fn from(err: SandboxError) -> Self {
        Self::from_sandbox_error(&err)
    }
}

impl From<WireError> for SandboxError {
    fn from(err: WireError) -> Self {
        err.to_sandbox_error()
    }
}

fn is_known_error_kind(kind: &str) -> bool {
    matches!(
        kind,
        "InvalidSpec"
            | "UnsupportedIsolationMode"
            | "BinaryExecutionBlocked"
            | "AccelerationUnavailable"
            | "NotFound"
            | "LeaseExpired"
            | "AdmissionRejected"
            | "BudgetExceeded"
            | "PolicyViolation"
            | "Transport"
            | "Internal"
    )
}

/// Runtime status snapshot returned by `ControlRequest::Status`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DaemonStatusInfo {
    pub active_sandboxes: usize,
    pub warm_ready_vms: usize,
    pub effective_host_rss_mb: u64,
    pub reserved_host_storage_mb: u64,
    pub version: String,
}

impl DaemonStatusInfo {
    fn to_json_value(&self) -> Value {
        json!({
            "active_sandboxes": self.active_sandboxes,
            "warm_ready_vms": self.warm_ready_vms,
            "effective_host_rss_mb": self.effective_host_rss_mb,
            "reserved_host_storage_mb": self.reserved_host_storage_mb,
            "version": self.version,
        })
    }

    fn from_json_value(val: &Value) -> Result<Self, SandboxError> {
        let obj = expect_object(val, "DaemonStatusInfo")?;
        Ok(Self {
            active_sandboxes: req_usize(obj, "active_sandboxes", "DaemonStatusInfo")?,
            warm_ready_vms: req_usize(obj, "warm_ready_vms", "DaemonStatusInfo")?,
            effective_host_rss_mb: req_u64(obj, "effective_host_rss_mb", "DaemonStatusInfo")?,
            reserved_host_storage_mb: req_u64(obj, "reserved_host_storage_mb", "DaemonStatusInfo")?,
            version: req_string(obj, "version", "DaemonStatusInfo")?,
        })
    }
}

/// Live summary of an active sandbox returned by `ControlRequest::ListSandboxes`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SandboxSummaryInfo {
    pub id: SandboxId,
    pub pid: u32,
    pub alive: bool,
    pub network: NetworkPolicy,
    pub remaining_ttl_ms: u64,
    pub live_rss_bytes: Option<u64>,
    pub reserved_rss_mb: u64,
    pub host_rss_budget_mb: Option<u32>,
    pub host_storage_budget_mb: u32,
    pub docker_endpoint: Option<String>,
    pub allow_reaper_socket: bool,
}

impl SandboxSummaryInfo {
    pub fn to_json_value(&self) -> Value {
        json!({
            "id": self.id.as_str(),
            "pid": self.pid,
            "alive": self.alive,
            "network": encode_network_policy(&self.network),
            "remaining_ttl_ms": self.remaining_ttl_ms,
            "live_rss_bytes": self.live_rss_bytes,
            "reserved_rss_mb": self.reserved_rss_mb,
            "host_rss_budget_mb": self.host_rss_budget_mb,
            "host_storage_budget_mb": self.host_storage_budget_mb,
            "docker_endpoint": self.docker_endpoint,
            "allow_reaper_socket": self.allow_reaper_socket,
        })
    }

    pub fn from_json_value(val: &Value) -> Result<Self, SandboxError> {
        let obj = expect_object(val, "SandboxSummaryInfo")?;
        Ok(Self {
            id: SandboxId::new(req_string(obj, "id", "SandboxSummaryInfo")?),
            pid: req_u32(obj, "pid", "SandboxSummaryInfo")?,
            alive: req_bool(obj, "alive", "SandboxSummaryInfo")?,
            network: decode_network_policy(req_field(obj, "network", "SandboxSummaryInfo")?)?,
            remaining_ttl_ms: req_u64(obj, "remaining_ttl_ms", "SandboxSummaryInfo")?,
            live_rss_bytes: opt_u64(obj, "live_rss_bytes", "SandboxSummaryInfo")?,
            reserved_rss_mb: req_u64(obj, "reserved_rss_mb", "SandboxSummaryInfo")?,
            host_rss_budget_mb: opt_u32(obj, "host_rss_budget_mb", "SandboxSummaryInfo")?,
            host_storage_budget_mb: req_u32(obj, "host_storage_budget_mb", "SandboxSummaryInfo")?,
            docker_endpoint: opt_string(obj, "docker_endpoint", "SandboxSummaryInfo")?,
            allow_reaper_socket: req_bool(obj, "allow_reaper_socket", "SandboxSummaryInfo")?,
        })
    }
}

/// Control request sent from `sandbox-client` (or CLI/MCP) to `sandboxd`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ControlRequest {
    Status,
    Doctor,
    GetAccelerator {
        id: SandboxId,
    },
    ListSandboxes,
    Spawn {
        spec: SandboxSpec,
    },
    SpawnKeyed {
        operation_id: String,
        spec: SandboxSpec,
    },
    RenewLease {
        id: SandboxId,
        ttl_ms: u64,
    },
    ExecStart {
        id: SandboxId,
        req: ExecRequest,
    },
    CopyInTar {
        id: SandboxId,
        dst_guest: String,
        tar_bytes: Vec<u8>,
    },
    CopyOutTar {
        id: SandboxId,
        src_guest: String,
    },
    EnableDockerCompat {
        id: SandboxId,
        allow_reaper_socket: bool,
    },
    Destroy {
        id: SandboxId,
    },
    Shutdown,
}

impl ControlRequest {
    /// Serializes this request into a [`serde_json::Value`].
    pub fn to_json_value(&self) -> Value {
        match self {
            Self::Status => json!({ "type": "Status" }),
            Self::Doctor => json!({ "type": "Doctor" }),
            Self::GetAccelerator { id } => json!({ "type": "GetAccelerator", "id": id.as_str() }),
            Self::ListSandboxes => json!({ "type": "ListSandboxes" }),
            Self::Spawn { spec } => json!({
                "type": "Spawn",
                "spec": encode_sandbox_spec(spec),
            }),
            Self::SpawnKeyed { operation_id, spec } => json!({
                "type": "SpawnKeyed",
                "operation_id": operation_id,
                "spec": encode_sandbox_spec(spec),
            }),
            Self::RenewLease { id, ttl_ms } => json!({
                "type": "RenewLease",
                "id": id.as_str(),
                "ttl_ms": ttl_ms,
            }),
            Self::ExecStart { id, req } => json!({
                "type": "ExecStart",
                "id": id.as_str(),
                "req": encode_exec_request(req),
            }),
            Self::CopyInTar {
                id,
                dst_guest,
                tar_bytes,
            } => json!({
                "type": "CopyInTar",
                "id": id.as_str(),
                "dst_guest": dst_guest,
                "tar_base64": encode_base64(tar_bytes),
            }),
            Self::CopyOutTar { id, src_guest } => json!({
                "type": "CopyOutTar",
                "id": id.as_str(),
                "src_guest": src_guest,
            }),
            Self::EnableDockerCompat {
                id,
                allow_reaper_socket,
            } => json!({
                "type": "EnableDockerCompat",
                "id": id.as_str(),
                "allow_reaper_socket": allow_reaper_socket,
            }),
            Self::Destroy { id } => json!({
                "type": "Destroy",
                "id": id.as_str(),
            }),
            Self::Shutdown => json!({ "type": "Shutdown" }),
        }
    }

    /// Parses a [`ControlRequest`] from a [`serde_json::Value`].
    pub fn from_json_value(val: &Value) -> Result<Self, SandboxError> {
        let obj = expect_object(val, "ControlRequest")?;
        let kind = req_string(obj, "type", "ControlRequest")?;
        match kind.as_str() {
            "Status" => Ok(Self::Status),
            "Doctor" => Ok(Self::Doctor),
            "GetAccelerator" => Ok(Self::GetAccelerator {
                id: SandboxId::new(req_string(obj, "id", "ControlRequest::GetAccelerator")?),
            }),
            "ListSandboxes" => Ok(Self::ListSandboxes),
            "Spawn" => Ok(Self::Spawn {
                spec: decode_sandbox_spec(req_field(obj, "spec", "ControlRequest::Spawn")?)?,
            }),
            "SpawnKeyed" => Ok(Self::SpawnKeyed {
                operation_id: req_string(obj, "operation_id", "ControlRequest::SpawnKeyed")?,
                spec: decode_sandbox_spec(req_field(obj, "spec", "ControlRequest::SpawnKeyed")?)?,
            }),
            "RenewLease" => Ok(Self::RenewLease {
                id: SandboxId::new(req_string(obj, "id", "ControlRequest::RenewLease")?),
                ttl_ms: req_u64(obj, "ttl_ms", "ControlRequest::RenewLease")?,
            }),
            "ExecStart" => Ok(Self::ExecStart {
                id: SandboxId::new(req_string(obj, "id", "ControlRequest::ExecStart")?),
                req: decode_exec_request(req_field(obj, "req", "ControlRequest::ExecStart")?)?,
            }),
            "CopyInTar" => Ok(Self::CopyInTar {
                id: SandboxId::new(req_string(obj, "id", "ControlRequest::CopyInTar")?),
                dst_guest: req_string(obj, "dst_guest", "ControlRequest::CopyInTar")?,
                tar_bytes: req_bytes_b64(obj, "tar_base64", "ControlRequest::CopyInTar")?,
            }),
            "CopyOutTar" => Ok(Self::CopyOutTar {
                id: SandboxId::new(req_string(obj, "id", "ControlRequest::CopyOutTar")?),
                src_guest: req_string(obj, "src_guest", "ControlRequest::CopyOutTar")?,
            }),
            "EnableDockerCompat" => Ok(Self::EnableDockerCompat {
                id: SandboxId::new(req_string(obj, "id", "ControlRequest::EnableDockerCompat")?),
                allow_reaper_socket: req_bool(
                    obj,
                    "allow_reaper_socket",
                    "ControlRequest::EnableDockerCompat",
                )?,
            }),
            "Destroy" => Ok(Self::Destroy {
                id: SandboxId::new(req_string(obj, "id", "ControlRequest::Destroy")?),
            }),
            "Shutdown" => Ok(Self::Shutdown),
            other => Err(SandboxError::Transport(format!(
                "unknown ControlRequest type '{other}'"
            ))),
        }
    }

    /// Serializes this request into UTF-8 JSON bytes.
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, SandboxError> {
        encode_json_bytes(&self.to_json_value())
    }

    /// Parses a [`ControlRequest`] from UTF-8 JSON bytes.
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, SandboxError> {
        let value = decode_json_bytes(bytes, "ControlRequest")?;
        Self::from_json_value(&value)
    }
}

/// Control response sent from `sandboxd` back to `sandbox-client`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ControlResponse {
    Status(DaemonStatusInfo),
    Doctor { report: Value },
    Accelerator { name: Option<String> },
    SandboxList { sandboxes: Vec<SandboxSummaryInfo> },
    Spawned(SandboxLease),
    Ack,
    ExecStarted { stream_id: u32 },
    CopyOutData { tar_bytes: Vec<u8> },
    DockerCompatEndpoint { uri: String },
    Destroyed(DestroyStatus),
    Error(WireError),
}

impl ControlResponse {
    /// Serializes this response into a [`serde_json::Value`].
    pub fn to_json_value(&self) -> Value {
        match self {
            Self::Status(info) => json!({
                "type": "Status",
                "status": info.to_json_value(),
            }),
            Self::Doctor { report } => json!({ "type": "Doctor", "report": report }),
            Self::Accelerator { name } => json!({ "type": "Accelerator", "name": name }),
            Self::SandboxList { sandboxes } => json!({
                "type": "SandboxList",
                "sandboxes": sandboxes.iter().map(SandboxSummaryInfo::to_json_value).collect::<Vec<_>>(),
            }),
            Self::Spawned(lease) => json!({
                "type": "Spawned",
                "lease": encode_sandbox_lease(lease),
            }),
            Self::Ack => json!({ "type": "Ack" }),
            Self::ExecStarted { stream_id } => json!({
                "type": "ExecStarted",
                "stream_id": stream_id,
            }),
            Self::CopyOutData { tar_bytes } => json!({
                "type": "CopyOutData",
                "tar_base64": encode_base64(tar_bytes),
            }),
            Self::DockerCompatEndpoint { uri } => json!({
                "type": "DockerCompatEndpoint",
                "uri": uri,
            }),
            Self::Destroyed(status) => json!({
                "type": "Destroyed",
                "status": encode_destroy_status(status),
            }),
            Self::Error(err) => json!({
                "type": "Error",
                "error": err.to_json_value(),
            }),
        }
    }

    /// Parses a [`ControlResponse`] from a [`serde_json::Value`].
    pub fn from_json_value(val: &Value) -> Result<Self, SandboxError> {
        let obj = expect_object(val, "ControlResponse")?;
        let kind = req_string(obj, "type", "ControlResponse")?;
        match kind.as_str() {
            "Status" => Ok(Self::Status(DaemonStatusInfo::from_json_value(req_field(
                obj,
                "status",
                "ControlResponse::Status",
            )?)?)),
            "Doctor" => {
                let report = req_field(obj, "report", "ControlResponse::Doctor")?;
                if !report.is_object() {
                    return Err(SandboxError::Transport(
                        "ControlResponse::Doctor.report must be an object".to_owned(),
                    ));
                }
                Ok(Self::Doctor {
                    report: report.clone(),
                })
            }
            "Accelerator" => {
                let value = req_field(obj, "name", "ControlResponse::Accelerator")?;
                let name = match value {
                    Value::Null => None,
                    Value::String(name) => Some(name.clone()),
                    _ => return Err(SandboxError::Transport(
                        "ControlResponse::Accelerator.name must be a string or null".to_owned(),
                    )),
                };
                Ok(Self::Accelerator { name })
            }
            "SandboxList" => {
                let arr = req_field(obj, "sandboxes", "ControlResponse::SandboxList")?
                    .as_array()
                    .ok_or_else(|| {
                        SandboxError::Transport(
                            "ControlResponse::SandboxList.sandboxes must be an array".to_owned(),
                        )
                    })?;
                let mut sandboxes = Vec::with_capacity(arr.len());
                for item in arr {
                    sandboxes.push(SandboxSummaryInfo::from_json_value(item)?);
                }
                Ok(Self::SandboxList { sandboxes })
            }
            "Spawned" => Ok(Self::Spawned(decode_sandbox_lease(req_field(
                obj,
                "lease",
                "ControlResponse::Spawned",
            )?)?)),
            "Ack" => Ok(Self::Ack),
            "ExecStarted" => Ok(Self::ExecStarted {
                stream_id: req_u32(obj, "stream_id", "ControlResponse::ExecStarted")?,
            }),
            "CopyOutData" => Ok(Self::CopyOutData {
                tar_bytes: req_bytes_b64(obj, "tar_base64", "ControlResponse::CopyOutData")?,
            }),
            "DockerCompatEndpoint" => Ok(Self::DockerCompatEndpoint {
                uri: req_string(obj, "uri", "ControlResponse::DockerCompatEndpoint")?,
            }),
            "Destroyed" => Ok(Self::Destroyed(decode_destroy_status(req_field(
                obj,
                "status",
                "ControlResponse::Destroyed",
            )?)?)),
            "Error" => Ok(Self::Error(WireError::from_json_value(req_field(
                obj,
                "error",
                "ControlResponse::Error",
            )?)?)),
            other => Err(SandboxError::Transport(format!(
                "unknown ControlResponse type '{other}'"
            ))),
        }
    }

    /// Serializes this response into UTF-8 JSON bytes.
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, SandboxError> {
        encode_json_bytes(&self.to_json_value())
    }

    /// Parses a [`ControlResponse`] from UTF-8 JSON bytes.
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, SandboxError> {
        let value = decode_json_bytes(bytes, "ControlResponse")?;
        Self::from_json_value(&value)
    }
}

/// Client-to-daemon execution stream frames sent after `ControlResponse::ExecStarted`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecWireClientMsg {
    Stdin { data: Vec<u8> },
    StdinEof,
    Cancel,
}

impl ExecWireClientMsg {
    /// Serializes this execution client message into a [`serde_json::Value`].
    pub fn to_json_value(&self) -> Value {
        match self {
            Self::Stdin { data } => json!({
                "type": "Stdin",
                "data_base64": encode_base64(data),
            }),
            Self::StdinEof => json!({ "type": "StdinEof" }),
            Self::Cancel => json!({ "type": "Cancel" }),
        }
    }

    /// Parses an [`ExecWireClientMsg`] from a [`serde_json::Value`].
    pub fn from_json_value(val: &Value) -> Result<Self, SandboxError> {
        let obj = expect_object(val, "ExecWireClientMsg")?;
        let kind = req_string(obj, "type", "ExecWireClientMsg")?;
        match kind.as_str() {
            "Stdin" => Ok(Self::Stdin {
                data: req_bytes_b64(obj, "data_base64", "ExecWireClientMsg::Stdin")?,
            }),
            "StdinEof" => Ok(Self::StdinEof),
            "Cancel" => Ok(Self::Cancel),
            other => Err(SandboxError::Transport(format!(
                "unknown ExecWireClientMsg type '{other}'"
            ))),
        }
    }

    /// Serializes this execution client message into UTF-8 JSON bytes.
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, SandboxError> {
        encode_json_bytes(&self.to_json_value())
    }

    /// Parses an [`ExecWireClientMsg`] from UTF-8 JSON bytes.
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, SandboxError> {
        let value = decode_json_bytes(bytes, "ExecWireClientMsg")?;
        Self::from_json_value(&value)
    }
}

/// Daemon-to-client execution stream events sent after `ControlResponse::ExecStarted`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecWireEvent {
    Stdout { data: Vec<u8> },
    Stderr { data: Vec<u8> },
    Exit(ExecExitStatus),
    Error(WireError),
}

impl ExecWireEvent {
    /// Serializes this execution event into a [`serde_json::Value`].
    pub fn to_json_value(&self) -> Value {
        match self {
            Self::Stdout { data } => json!({
                "type": "Stdout",
                "data_base64": encode_base64(data),
            }),
            Self::Stderr { data } => json!({
                "type": "Stderr",
                "data_base64": encode_base64(data),
            }),
            Self::Exit(status) => json!({
                "type": "Exit",
                "exit": encode_exec_exit_status(status),
            }),
            Self::Error(err) => json!({
                "type": "Error",
                "error": err.to_json_value(),
            }),
        }
    }

    /// Parses an [`ExecWireEvent`] from a [`serde_json::Value`].
    pub fn from_json_value(val: &Value) -> Result<Self, SandboxError> {
        let obj = expect_object(val, "ExecWireEvent")?;
        let kind = req_string(obj, "type", "ExecWireEvent")?;
        match kind.as_str() {
            "Stdout" => Ok(Self::Stdout {
                data: req_bytes_b64(obj, "data_base64", "ExecWireEvent::Stdout")?,
            }),
            "Stderr" => Ok(Self::Stderr {
                data: req_bytes_b64(obj, "data_base64", "ExecWireEvent::Stderr")?,
            }),
            "Exit" => Ok(Self::Exit(decode_exec_exit_status(req_field(
                obj,
                "exit",
                "ExecWireEvent::Exit",
            )?)?)),
            "Error" => Ok(Self::Error(WireError::from_json_value(req_field(
                obj,
                "error",
                "ExecWireEvent::Error",
            )?)?)),
            other => Err(SandboxError::Transport(format!(
                "unknown ExecWireEvent type '{other}'"
            ))),
        }
    }

    /// Serializes this execution event into UTF-8 JSON bytes.
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, SandboxError> {
        encode_json_bytes(&self.to_json_value())
    }

    /// Parses an [`ExecWireEvent`] from UTF-8 JSON bytes.
    pub fn from_json_bytes(bytes: &[u8]) -> Result<Self, SandboxError> {
        let value = decode_json_bytes(bytes, "ExecWireEvent")?;
        Self::from_json_value(&value)
    }
}

/// Writes a length-prefixed (`4-byte BE u32`) control wire frame bounded by [`MAX_CONTROL_FRAME_BYTES`].
pub async fn write_control_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    payload: &[u8],
) -> Result<(), SandboxError> {
    if payload.is_empty() {
        return Err(SandboxError::Transport(
            "control frame payload must not be empty".to_owned(),
        ));
    }
    if payload.len() > MAX_CONTROL_FRAME_BYTES {
        return Err(SandboxError::Transport(format!(
            "control frame payload {} bytes exceeds MAX_CONTROL_FRAME_BYTES ({MAX_CONTROL_FRAME_BYTES})",
            payload.len()
        )));
    }
    let len = u32::try_from(payload.len())
        .map_err(|_| SandboxError::Transport("control frame length exceeds u32".to_owned()))?;
    writer
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|err| SandboxError::Transport(format!("failed writing frame header: {err}")))?;
    writer
        .write_all(payload)
        .await
        .map_err(|err| SandboxError::Transport(format!("failed writing frame payload: {err}")))?;
    writer
        .flush()
        .await
        .map_err(|err| SandboxError::Transport(format!("failed flushing control frame: {err}")))?;
    Ok(())
}

/// Reads a length-prefixed (`4-byte BE u32`) control wire frame bounded by [`MAX_CONTROL_FRAME_BYTES`].
///
/// Returns `Ok(None)` on a clean EOF at the frame boundary, and `Err(SandboxError::Transport(_))`
/// on truncated headers, truncated payloads, zero-length frames, or oversized frames.
pub async fn read_control_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> Result<Option<Vec<u8>>, SandboxError> {
    let mut len_buf = [0u8; 4];
    let mut read_so_far = 0usize;
    while read_so_far < 4 {
        let n = reader
            .read(&mut len_buf[read_so_far..])
            .await
            .map_err(|err| {
                SandboxError::Transport(format!("failed reading control frame header: {err}"))
            })?;
        if n == 0 {
            if read_so_far == 0 {
                return Ok(None);
            }
            return Err(SandboxError::Transport(
                "unexpected EOF while reading control frame header".to_owned(),
            ));
        }
        read_so_far += n;
    }

    let payload_len = u32::from_be_bytes(len_buf) as usize;
    if payload_len == 0 {
        return Err(SandboxError::Transport(
            "control frame length must not be zero".to_owned(),
        ));
    }
    if payload_len > MAX_CONTROL_FRAME_BYTES {
        return Err(SandboxError::Transport(format!(
            "incoming control frame length {payload_len} exceeds MAX_CONTROL_FRAME_BYTES ({MAX_CONTROL_FRAME_BYTES})"
        )));
    }

    const INITIAL_FRAME_ALLOC_CAP: usize = 64 * 1024;
    const READ_CHUNK_BYTES: usize = 16 * 1024;

    let mut payload = Vec::with_capacity(payload_len.min(INITIAL_FRAME_ALLOC_CAP));
    while payload.len() < payload_len {
        let prev = payload.len();
        let step = (payload_len - prev).min(READ_CHUNK_BYTES);
        payload.resize(prev + step, 0);
        let n = match reader.read(&mut payload[prev..]).await {
            Ok(n) => n,
            Err(err) => {
                payload.truncate(prev);
                return Err(SandboxError::Transport(format!(
                    "failed reading control frame payload: {err}"
                )));
            }
        };
        if n == 0 {
            payload.truncate(prev);
            return Err(SandboxError::Transport(
                "failed reading control frame payload: unexpected EOF".to_owned(),
            ));
        }
        payload.truncate(prev + n);
    }
    Ok(Some(payload))
}

/// Encodes `input` using standard RFC 4648 base64 with `=` padding.
pub fn encode_base64(input: &[u8]) -> String {
    if input.is_empty() {
        return String::new();
    }
    let out_len = input.len().div_ceil(3) * 4;
    let mut out = String::with_capacity(out_len);
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);

        out.push(B64_ALPHABET[(b0 >> 2) as usize] as char);
        out.push(B64_ALPHABET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(B64_ALPHABET[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(B64_ALPHABET[(b2 & 0x3f) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

/// Decodes standard RFC 4648 base64, rejecting invalid characters, whitespace, malformed padding,
/// and non-zero unused trailing padding bits.
pub fn decode_base64(encoded: &str) -> Result<Vec<u8>, SandboxError> {
    let bytes = encoded.as_bytes();
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    if !bytes.len().is_multiple_of(4) {
        return Err(SandboxError::Transport(
            "invalid base64 length: must be a multiple of 4".to_owned(),
        ));
    }

    let mut out = Vec::with_capacity((bytes.len() / 4) * 3);
    let (chunks, _) = bytes.as_chunks::<4>();
    let num_chunks = chunks.len();

    for (chunk_idx, chunk) in chunks.iter().enumerate() {
        let is_last = chunk_idx + 1 == num_chunks;
        let pad_2 = chunk[2] == b'=';
        let pad_3 = chunk[3] == b'=';

        if chunk[0] == b'=' || chunk[1] == b'=' {
            return Err(SandboxError::Transport(
                "invalid base64 padding in leading positions".to_owned(),
            ));
        }
        if (pad_2 || pad_3) && !is_last {
            return Err(SandboxError::Transport(
                "invalid base64 padding before final quantum".to_owned(),
            ));
        }
        if pad_2 && !pad_3 {
            return Err(SandboxError::Transport(
                "invalid base64 padding: single '=' followed by data character".to_owned(),
            ));
        }

        let v0 = decode_b64_sextet(chunk[0])?;
        let v1 = decode_b64_sextet(chunk[1])?;
        let v2 = if pad_2 {
            0
        } else {
            decode_b64_sextet(chunk[2])?
        };
        let v3 = if pad_3 {
            0
        } else {
            decode_b64_sextet(chunk[3])?
        };

        if pad_2 && (v1 & 0x0f) != 0 {
            return Err(SandboxError::Transport(
                "invalid base64: non-zero unused bits before '=='".to_owned(),
            ));
        }
        if !pad_2 && pad_3 && (v2 & 0x03) != 0 {
            return Err(SandboxError::Transport(
                "invalid base64: non-zero unused bits before '='".to_owned(),
            ));
        }

        out.push((v0 << 2) | (v1 >> 4));
        if !pad_2 {
            out.push((v1 << 4) | (v2 >> 2));
        }
        if !pad_3 {
            out.push((v2 << 6) | v3);
        }
    }

    Ok(out)
}

fn decode_b64_sextet(byte: u8) -> Result<u8, SandboxError> {
    match byte {
        b'A'..=b'Z' => Ok(byte - b'A'),
        b'a'..=b'z' => Ok(byte - b'a' + 26),
        b'0'..=b'9' => Ok(byte - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err(SandboxError::Transport(format!(
            "invalid base64 byte 0x{byte:02x}"
        ))),
    }
}

fn encode_json_bytes(val: &Value) -> Result<Vec<u8>, SandboxError> {
    serde_json::to_vec(val)
        .map_err(|err| SandboxError::Internal(format!("failed serializing control JSON: {err}")))
}

fn decode_json_bytes(bytes: &[u8], ctx: &str) -> Result<Value, SandboxError> {
    serde_json::from_slice(bytes)
        .map_err(|err| SandboxError::Transport(format!("invalid {ctx} JSON payload: {err}")))
}

fn encode_duration(dur: Duration) -> Value {
    json!({
        "secs": dur.as_secs(),
        "nanos": dur.subsec_nanos(),
    })
}

fn decode_duration(val: &Value, ctx: &str) -> Result<Duration, SandboxError> {
    let obj = expect_object(val, ctx)?;
    let secs = req_u64(obj, "secs", ctx)?;
    let nanos = req_u32(obj, "nanos", ctx)?;
    if nanos >= 1_000_000_000 {
        return Err(SandboxError::Transport(format!(
            "{ctx} duration nanos {nanos} must be < 1_000_000_000"
        )));
    }
    Ok(Duration::new(secs, nanos))
}

fn encode_isolation_mode(mode: IsolationMode) -> &'static str {
    match mode {
        IsolationMode::VmRequired => "VmRequired",
        IsolationMode::SharedKernelAllowed => "SharedKernelAllowed",
    }
}

fn decode_isolation_mode(val: &Value) -> Result<IsolationMode, SandboxError> {
    match val.as_str() {
        Some("VmRequired") => Ok(IsolationMode::VmRequired),
        Some("SharedKernelAllowed") => Ok(IsolationMode::SharedKernelAllowed),
        _ => Err(SandboxError::Transport(
            "invalid IsolationMode value".to_owned(),
        )),
    }
}

fn encode_acceleration_policy(policy: AccelerationPolicy) -> &'static str {
    match policy {
        AccelerationPolicy::Required => "Required",
        AccelerationPolicy::Preferred => "Preferred",
        AccelerationPolicy::SoftwareOnly => "SoftwareOnly",
    }
}

fn decode_acceleration_policy(val: &Value) -> Result<AccelerationPolicy, SandboxError> {
    match val.as_str() {
        Some("Required") => Ok(AccelerationPolicy::Required),
        Some("Preferred") => Ok(AccelerationPolicy::Preferred),
        Some("SoftwareOnly") => Ok(AccelerationPolicy::SoftwareOnly),
        _ => Err(SandboxError::Transport(
            "invalid AccelerationPolicy value".to_owned(),
        )),
    }
}

fn encode_network_policy(policy: &NetworkPolicy) -> Value {
    match policy {
        NetworkPolicy::Isolated => json!({ "type": "Isolated" }),
        NetworkPolicy::InternetOnly => json!({ "type": "InternetOnly" }),
        NetworkPolicy::DomainAllowList { rules } => json!({
            "type": "DomainAllowList",
            "rules": rules.iter().map(|r| json!({
                "domain": r.domain,
                "port": r.port,
            })).collect::<Vec<_>>(),
        }),
        NetworkPolicy::Unrestricted => json!({ "type": "Unrestricted" }),
    }
}

fn decode_network_policy(val: &Value) -> Result<NetworkPolicy, SandboxError> {
    let obj = expect_object(val, "NetworkPolicy")?;
    let kind = req_string(obj, "type", "NetworkPolicy")?;
    match kind.as_str() {
        "Isolated" => Ok(NetworkPolicy::Isolated),
        "InternetOnly" => Ok(NetworkPolicy::InternetOnly),
        "Unrestricted" => Ok(NetworkPolicy::Unrestricted),
        "DomainAllowList" => {
            let arr = req_field(obj, "rules", "NetworkPolicy::DomainAllowList")?
                .as_array()
                .ok_or_else(|| {
                    SandboxError::Transport(
                        "NetworkPolicy::DomainAllowList rules must be an array".to_owned(),
                    )
                })?;
            let mut rules = Vec::with_capacity(arr.len());
            for item in arr {
                let rule_obj = expect_object(item, "EgressRule")?;
                rules.push(EgressRule {
                    domain: req_string(rule_obj, "domain", "EgressRule")?,
                    port: req_u16(rule_obj, "port", "EgressRule")?,
                });
            }
            Ok(NetworkPolicy::DomainAllowList { rules })
        }
        other => Err(SandboxError::Transport(format!(
            "unknown NetworkPolicy type '{other}'"
        ))),
    }
}

fn encode_enforcement_level(level: EnforcementLevel) -> &'static str {
    match level {
        EnforcementLevel::HardLimit => "HardLimit",
        EnforcementLevel::BestEffort => "BestEffort",
        EnforcementLevel::Unsupported => "Unsupported",
    }
}

fn decode_enforcement_level(val: &Value) -> Result<EnforcementLevel, SandboxError> {
    match val.as_str() {
        Some("HardLimit") => Ok(EnforcementLevel::HardLimit),
        Some("BestEffort") => Ok(EnforcementLevel::BestEffort),
        Some("Unsupported") => Ok(EnforcementLevel::Unsupported),
        _ => Err(SandboxError::Transport(
            "invalid EnforcementLevel value".to_owned(),
        )),
    }
}

fn encode_resource_budget(budget: &ResourceBudget) -> Value {
    json!({
        "guest_vcpus": budget.guest_vcpus,
        "host_cpu_quota_Millicores": budget.host_cpu_quota_Millicores,
        "guest_ram_mb": budget.guest_ram_mb,
        "host_rss_budget_mb": budget.host_rss_budget_mb,
        "virtual_disk_mb": budget.virtual_disk_mb,
        "host_storage_budget_mb": budget.host_storage_budget_mb,
    })
}

fn decode_resource_budget(val: &Value) -> Result<ResourceBudget, SandboxError> {
    let obj = expect_object(val, "ResourceBudget")?;
    Ok(ResourceBudget {
        guest_vcpus: req_u8(obj, "guest_vcpus", "ResourceBudget")?,
        host_cpu_quota_Millicores: opt_u32(obj, "host_cpu_quota_Millicores", "ResourceBudget")?,
        guest_ram_mb: req_u32(obj, "guest_ram_mb", "ResourceBudget")?,
        host_rss_budget_mb: opt_u32(obj, "host_rss_budget_mb", "ResourceBudget")?,
        virtual_disk_mb: req_u32(obj, "virtual_disk_mb", "ResourceBudget")?,
        host_storage_budget_mb: req_u32(obj, "host_storage_budget_mb", "ResourceBudget")?,
    })
}

fn encode_sandbox_spec(spec: &SandboxSpec) -> Value {
    json!({
        "isolation": encode_isolation_mode(spec.isolation),
        "acceleration": encode_acceleration_policy(spec.acceleration),
        "network": encode_network_policy(&spec.network),
        "budget": encode_resource_budget(&spec.budget),
        "lease_ttl": encode_duration(spec.lease_ttl),
    })
}

fn decode_sandbox_spec(val: &Value) -> Result<SandboxSpec, SandboxError> {
    let obj = expect_object(val, "SandboxSpec")?;
    Ok(SandboxSpec {
        isolation: decode_isolation_mode(req_field(obj, "isolation", "SandboxSpec")?)?,
        acceleration: decode_acceleration_policy(req_field(obj, "acceleration", "SandboxSpec")?)?,
        network: decode_network_policy(req_field(obj, "network", "SandboxSpec")?)?,
        budget: decode_resource_budget(req_field(obj, "budget", "SandboxSpec")?)?,
        lease_ttl: decode_duration(
            req_field(obj, "lease_ttl", "SandboxSpec")?,
            "SandboxSpec.lease_ttl",
        )?,
    })
}

fn encode_capability_report(cap: &CapabilityReport) -> Value {
    json!({
        "cpu_quota": encode_enforcement_level(cap.cpu_quota),
        "host_rss": encode_enforcement_level(cap.host_rss),
        "host_storage": encode_enforcement_level(cap.host_storage),
        "egress_filter": encode_enforcement_level(cap.egress_filter),
    })
}

fn decode_capability_report(val: &Value) -> Result<CapabilityReport, SandboxError> {
    let obj = expect_object(val, "CapabilityReport")?;
    Ok(CapabilityReport {
        cpu_quota: decode_enforcement_level(req_field(obj, "cpu_quota", "CapabilityReport")?)?,
        host_rss: decode_enforcement_level(req_field(obj, "host_rss", "CapabilityReport")?)?,
        host_storage: decode_enforcement_level(req_field(
            obj,
            "host_storage",
            "CapabilityReport",
        )?)?,
        egress_filter: decode_enforcement_level(req_field(
            obj,
            "egress_filter",
            "CapabilityReport",
        )?)?,
    })
}

fn encode_sandbox_lease(lease: &SandboxLease) -> Value {
    json!({
        "id": lease.id.as_str(),
        "ttl": encode_duration(lease.ttl),
        "capabilities": encode_capability_report(&lease.capabilities),
    })
}

fn decode_sandbox_lease(val: &Value) -> Result<SandboxLease, SandboxError> {
    let obj = expect_object(val, "SandboxLease")?;
    Ok(SandboxLease {
        id: SandboxId::new(req_string(obj, "id", "SandboxLease")?),
        ttl: decode_duration(req_field(obj, "ttl", "SandboxLease")?, "SandboxLease.ttl")?,
        capabilities: decode_capability_report(req_field(obj, "capabilities", "SandboxLease")?)?,
    })
}

fn encode_destroy_status(status: &DestroyStatus) -> Value {
    match status {
        DestroyStatus::ProcessExited {
            remaining_artifacts,
        } => json!({
            "type": "ProcessExited",
            "remaining_artifacts": remaining_artifacts
                .iter()
                .map(|p| p.to_string_lossy().into_owned())
                .collect::<Vec<_>>(),
        }),
        DestroyStatus::AllResourcesCleaned => json!({ "type": "AllResourcesCleaned" }),
    }
}

fn decode_destroy_status(val: &Value) -> Result<DestroyStatus, SandboxError> {
    let obj = expect_object(val, "DestroyStatus")?;
    let kind = req_string(obj, "type", "DestroyStatus")?;
    match kind.as_str() {
        "AllResourcesCleaned" => Ok(DestroyStatus::AllResourcesCleaned),
        "ProcessExited" => {
            let arr = req_field(obj, "remaining_artifacts", "DestroyStatus::ProcessExited")?
                .as_array()
                .ok_or_else(|| {
                    SandboxError::Transport(
                        "DestroyStatus::ProcessExited remaining_artifacts must be an array"
                            .to_owned(),
                    )
                })?;
            let mut paths = Vec::with_capacity(arr.len());
            for item in arr {
                let s = item.as_str().ok_or_else(|| {
                    SandboxError::Transport(
                        "DestroyStatus remaining_artifacts entry must be a string".to_owned(),
                    )
                })?;
                paths.push(PathBuf::from(s));
            }
            Ok(DestroyStatus::ProcessExited {
                remaining_artifacts: paths,
            })
        }
        other => Err(SandboxError::Transport(format!(
            "unknown DestroyStatus type '{other}'"
        ))),
    }
}

fn encode_exec_target(target: &ExecTarget) -> Value {
    match target {
        ExecTarget::Guest => json!({ "type": "Guest" }),
        ExecTarget::Container { id_or_name } => json!({
            "type": "Container",
            "id_or_name": id_or_name,
        }),
    }
}

fn decode_exec_target(val: &Value) -> Result<ExecTarget, SandboxError> {
    let obj = expect_object(val, "ExecTarget")?;
    let kind = req_string(obj, "type", "ExecTarget")?;
    match kind.as_str() {
        "Guest" => Ok(ExecTarget::Guest),
        "Container" => Ok(ExecTarget::Container {
            id_or_name: req_string(obj, "id_or_name", "ExecTarget::Container")?,
        }),
        other => Err(SandboxError::Transport(format!(
            "unknown ExecTarget type '{other}'"
        ))),
    }
}

fn encode_exec_request(req: &ExecRequest) -> Value {
    let mut env_map = Map::with_capacity(req.env.len());
    for (k, v) in &req.env {
        env_map.insert(k.clone(), Value::String(v.clone()));
    }
    json!({
        "target": encode_exec_target(&req.target),
        "argv": req.argv,
        "env": Value::Object(env_map),
        "cwd": req.cwd,
        "user": req.user,
        "deadline": encode_duration(req.deadline),
        "stdout_budget_bytes": req.stdout_budget_bytes,
        "stderr_budget_bytes": req.stderr_budget_bytes,
    })
}

fn decode_exec_request(val: &Value) -> Result<ExecRequest, SandboxError> {
    let obj = expect_object(val, "ExecRequest")?;
    let target = decode_exec_target(req_field(obj, "target", "ExecRequest")?)?;

    let argv_arr = req_field(obj, "argv", "ExecRequest")?
        .as_array()
        .ok_or_else(|| SandboxError::Transport("ExecRequest argv must be an array".to_owned()))?;
    let mut argv = Vec::with_capacity(argv_arr.len());
    for item in argv_arr {
        let s = item.as_str().ok_or_else(|| {
            SandboxError::Transport("ExecRequest argv items must be strings".to_owned())
        })?;
        argv.push(s.to_owned());
    }

    let env_obj = req_field(obj, "env", "ExecRequest")?
        .as_object()
        .ok_or_else(|| SandboxError::Transport("ExecRequest env must be an object".to_owned()))?;
    let mut env = BTreeMap::new();
    for (k, v) in env_obj {
        let s = v.as_str().ok_or_else(|| {
            SandboxError::Transport("ExecRequest env values must be strings".to_owned())
        })?;
        env.insert(k.clone(), s.to_owned());
    }

    Ok(ExecRequest {
        target,
        argv,
        env,
        cwd: opt_string(obj, "cwd", "ExecRequest")?,
        user: opt_string(obj, "user", "ExecRequest")?,
        deadline: decode_duration(
            req_field(obj, "deadline", "ExecRequest")?,
            "ExecRequest.deadline",
        )?,
        stdout_budget_bytes: req_u64(obj, "stdout_budget_bytes", "ExecRequest")?,
        stderr_budget_bytes: req_u64(obj, "stderr_budget_bytes", "ExecRequest")?,
    })
}

fn encode_exec_exit_status(status: &ExecExitStatus) -> Value {
    json!({
        "code": status.code,
        "timed_out": status.timed_out,
        "stdout_truncated": status.stdout_truncated,
        "stderr_truncated": status.stderr_truncated,
    })
}

fn decode_exec_exit_status(val: &Value) -> Result<ExecExitStatus, SandboxError> {
    let obj = expect_object(val, "ExecExitStatus")?;
    Ok(ExecExitStatus {
        code: opt_i32(obj, "code", "ExecExitStatus")?,
        timed_out: req_bool(obj, "timed_out", "ExecExitStatus")?,
        stdout_truncated: req_bool(obj, "stdout_truncated", "ExecExitStatus")?,
        stderr_truncated: req_bool(obj, "stderr_truncated", "ExecExitStatus")?,
    })
}

fn expect_object<'a>(val: &'a Value, ctx: &str) -> Result<&'a Map<String, Value>, SandboxError> {
    val.as_object()
        .ok_or_else(|| SandboxError::Transport(format!("{ctx} must be a JSON object")))
}

fn req_field<'a>(
    obj: &'a Map<String, Value>,
    key: &str,
    ctx: &str,
) -> Result<&'a Value, SandboxError> {
    obj.get(key)
        .ok_or_else(|| SandboxError::Transport(format!("{ctx} missing required field '{key}'")))
}

fn req_string(obj: &Map<String, Value>, key: &str, ctx: &str) -> Result<String, SandboxError> {
    req_field(obj, key, ctx)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| SandboxError::Transport(format!("{ctx}.{key} must be a string")))
}

fn opt_string(
    obj: &Map<String, Value>,
    key: &str,
    ctx: &str,
) -> Result<Option<String>, SandboxError> {
    match obj.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(SandboxError::Transport(format!(
            "{ctx}.{key} must be a string or null"
        ))),
    }
}

fn req_bool(obj: &Map<String, Value>, key: &str, ctx: &str) -> Result<bool, SandboxError> {
    req_field(obj, key, ctx)?
        .as_bool()
        .ok_or_else(|| SandboxError::Transport(format!("{ctx}.{key} must be a boolean")))
}

fn req_u64(obj: &Map<String, Value>, key: &str, ctx: &str) -> Result<u64, SandboxError> {
    req_field(obj, key, ctx)?
        .as_u64()
        .ok_or_else(|| SandboxError::Transport(format!("{ctx}.{key} must be an unsigned integer")))
}

fn opt_u64(obj: &Map<String, Value>, key: &str, ctx: &str) -> Result<Option<u64>, SandboxError> {
    match obj.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v.as_u64().map(Some).ok_or_else(|| {
            SandboxError::Transport(format!("{ctx}.{key} must be an unsigned integer or null"))
        }),
    }
}

fn req_usize(obj: &Map<String, Value>, key: &str, ctx: &str) -> Result<usize, SandboxError> {
    let raw = req_u64(obj, key, ctx)?;
    usize::try_from(raw)
        .map_err(|_| SandboxError::Transport(format!("{ctx}.{key} exceeds usize range")))
}

fn req_u32(obj: &Map<String, Value>, key: &str, ctx: &str) -> Result<u32, SandboxError> {
    let raw = req_u64(obj, key, ctx)?;
    u32::try_from(raw)
        .map_err(|_| SandboxError::Transport(format!("{ctx}.{key} exceeds u32 range")))
}

fn opt_u32(obj: &Map<String, Value>, key: &str, ctx: &str) -> Result<Option<u32>, SandboxError> {
    match obj.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => {
            let raw = v.as_u64().ok_or_else(|| {
                SandboxError::Transport(format!("{ctx}.{key} must be an unsigned integer or null"))
            })?;
            u32::try_from(raw)
                .map(Some)
                .map_err(|_| SandboxError::Transport(format!("{ctx}.{key} exceeds u32 range")))
        }
    }
}

fn req_u16(obj: &Map<String, Value>, key: &str, ctx: &str) -> Result<u16, SandboxError> {
    let raw = req_u64(obj, key, ctx)?;
    u16::try_from(raw)
        .map_err(|_| SandboxError::Transport(format!("{ctx}.{key} exceeds u16 range")))
}

fn req_u8(obj: &Map<String, Value>, key: &str, ctx: &str) -> Result<u8, SandboxError> {
    let raw = req_u64(obj, key, ctx)?;
    u8::try_from(raw).map_err(|_| SandboxError::Transport(format!("{ctx}.{key} exceeds u8 range")))
}

fn opt_i32(obj: &Map<String, Value>, key: &str, ctx: &str) -> Result<Option<i32>, SandboxError> {
    match obj.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => {
            let raw = v.as_i64().ok_or_else(|| {
                SandboxError::Transport(format!("{ctx}.{key} must be a signed integer or null"))
            })?;
            i32::try_from(raw)
                .map(Some)
                .map_err(|_| SandboxError::Transport(format!("{ctx}.{key} exceeds i32 range")))
        }
    }
}

fn req_bytes_b64(obj: &Map<String, Value>, key: &str, ctx: &str) -> Result<Vec<u8>, SandboxError> {
    let encoded = req_string(obj, key, ctx)?;
    decode_base64(&encoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncWriteExt};

    fn sample_spec(network: NetworkPolicy, optional_budgets: bool) -> SandboxSpec {
        SandboxSpec {
            isolation: IsolationMode::VmRequired,
            acceleration: AccelerationPolicy::Preferred,
            network,
            budget: ResourceBudget {
                guest_vcpus: 2,
                host_cpu_quota_Millicores: optional_budgets.then_some(1500),
                guest_ram_mb: 512,
                host_rss_budget_mb: optional_budgets.then_some(768),
                virtual_disk_mb: 2048,
                host_storage_budget_mb: 4096,
            },
            lease_ttl: Duration::from_millis(45_123),
        }
    }

    fn sample_exec_request(target: ExecTarget) -> ExecRequest {
        let mut env = BTreeMap::new();
        env.insert("RUST_LOG".to_owned(), "info".to_owned());
        env.insert("EMPTY".to_owned(), String::new());
        ExecRequest {
            target,
            argv: vec!["/bin/sh".to_owned(), "-c".to_owned(), "echo hi".to_owned()],
            env,
            cwd: Some("/workspace".to_owned()),
            user: Some("1000:1000".to_owned()),
            deadline: Duration::from_secs(30),
            stdout_budget_bytes: 1024 * 1024,
            stderr_budget_bytes: 512 * 1024,
        }
    }

    #[test]
    fn base64_rfc4648_vectors_and_binary_roundtrip() {
        let vectors = [
            (b"".as_slice(), ""),
            (b"f".as_slice(), "Zg=="),
            (b"fo".as_slice(), "Zm8="),
            (b"foo".as_slice(), "Zm9v"),
            (b"foob".as_slice(), "Zm9vYg=="),
            (b"fooba".as_slice(), "Zm9vYmE="),
            (b"foobar".as_slice(), "Zm9vYmFy"),
        ];
        for (raw, expected) in vectors {
            assert_eq!(encode_base64(raw), expected);
            assert_eq!(decode_base64(expected).unwrap(), raw);
        }

        let all_bytes: Vec<u8> = (0u8..=255).collect();
        let encoded = encode_base64(&all_bytes);
        assert_eq!(decode_base64(&encoded).unwrap(), all_bytes);
    }

    #[test]
    fn base64_rejects_invalid_padding_characters_and_nonzero_unused_bits() {
        let invalid = [
            "A", "AA", "AAA", "AAAA=", "====", "A===", "AA=A", "Zg==AAAA", "Zm8=AAAA", "Zm9v\n",
            "Zm 9", "Zm9$",
            // Non-zero lower 4 bits before `==`: 'Z' = 25, 'h' = 33 (0b10_0001).
            "Zh==", // Non-zero lower 2 bits before `=`: 'Z','m','9' (61 = 0b1111_01).
            "Zm9=",
        ];
        for bad in invalid {
            assert!(
                matches!(decode_base64(bad), Err(SandboxError::Transport(_))),
                "expected invalid base64 '{bad}' to be rejected"
            );
        }
    }

    #[test]
    fn all_eleven_sandbox_error_variants_roundtrip_losslessly() {
        let all_errors = [
            SandboxError::InvalidSpec("bad spec".to_owned()),
            SandboxError::UnsupportedIsolationMode("no userns on windows".to_owned()),
            SandboxError::BinaryExecutionBlocked("wdac blocked".to_owned()),
            SandboxError::AccelerationUnavailable("no whpx".to_owned()),
            SandboxError::NotFound("sb-missing".to_owned()),
            SandboxError::LeaseExpired("ttl elapsed".to_owned()),
            SandboxError::AdmissionRejected("rss full".to_owned()),
            SandboxError::BudgetExceeded("disk limit".to_owned()),
            SandboxError::PolicyViolation("dns rebind".to_owned()),
            SandboxError::Transport("broken pipe".to_owned()),
            SandboxError::Internal("bug".to_owned()),
        ];

        for err in all_errors {
            let wire = WireError::from_sandbox_error(&err);
            assert_eq!(wire.to_sandbox_error(), err);

            let resp = ControlResponse::Error(wire.clone());
            let decoded_resp =
                ControlResponse::from_json_bytes(&resp.to_json_bytes().unwrap()).unwrap();
            assert_eq!(decoded_resp, resp);

            let evt = ExecWireEvent::Error(wire);
            let decoded_evt =
                ExecWireEvent::from_json_bytes(&evt.to_json_bytes().unwrap()).unwrap();
            assert_eq!(decoded_evt, evt);
        }

        let bad_kind_json = br#"{"kind":"NonExistentError","message":"oops"}"#;
        let bad_val: Value = serde_json::from_slice(bad_kind_json).unwrap();
        assert!(matches!(
            WireError::from_json_value(&bad_val),
            Err(SandboxError::Transport(_))
        ));
    }

    #[test]
    fn control_requests_and_responses_roundtrip_all_variants() {
        let allow_list = NetworkPolicy::DomainAllowList {
            rules: vec![
                EgressRule {
                    domain: "*.crates.io".to_owned(),
                    port: 443,
                },
                EgressRule {
                    domain: "example.com".to_owned(),
                    port: 80,
                },
            ],
        };

        let requests = [
            ControlRequest::Status,
            ControlRequest::ListSandboxes,
            ControlRequest::Spawn {
                spec: sample_spec(allow_list, true),
            },
            ControlRequest::Spawn {
                spec: SandboxSpec {
                    isolation: IsolationMode::SharedKernelAllowed,
                    acceleration: AccelerationPolicy::SoftwareOnly,
                    network: NetworkPolicy::Unrestricted,
                    ..sample_spec(NetworkPolicy::Isolated, false)
                },
            },
            ControlRequest::RenewLease {
                id: SandboxId::new("sb-1"),
                ttl_ms: 90_000,
            },
            ControlRequest::ExecStart {
                id: SandboxId::new("sb-1"),
                req: sample_exec_request(ExecTarget::Guest),
            },
            ControlRequest::ExecStart {
                id: SandboxId::new("sb-1"),
                req: ExecRequest {
                    cwd: None,
                    user: None,
                    ..sample_exec_request(ExecTarget::Container {
                        id_or_name: "pg-1".to_owned(),
                    })
                },
            },
            ControlRequest::CopyInTar {
                id: SandboxId::new("sb-1"),
                dst_guest: "/workspace".to_owned(),
                tar_bytes: vec![0, 1, 2, 254, 255],
            },
            ControlRequest::CopyOutTar {
                id: SandboxId::new("sb-1"),
                src_guest: "/workspace/out".to_owned(),
            },
            ControlRequest::EnableDockerCompat {
                id: SandboxId::new("sb-1"),
                allow_reaper_socket: true,
            },
            ControlRequest::Destroy {
                id: SandboxId::new("sb-1"),
            },
            ControlRequest::Shutdown,
        ];

        for req in requests {
            let bytes = req.to_json_bytes().unwrap();
            let decoded = ControlRequest::from_json_bytes(&bytes).unwrap();
            assert_eq!(decoded, req);
        }

        let responses = [
            ControlResponse::Status(DaemonStatusInfo {
                active_sandboxes: 3,
                warm_ready_vms: 2,
                effective_host_rss_mb: 1024,
                reserved_host_storage_mb: 8192,
                version: "0.1.0".to_owned(),
            }),
            ControlResponse::SandboxList {
                sandboxes: vec![
                    SandboxSummaryInfo {
                        id: SandboxId::new("sb-1"),
                        pid: 4242,
                        alive: true,
                        network: NetworkPolicy::Isolated,
                        remaining_ttl_ms: 299_500,
                        live_rss_bytes: Some(268_435_456),
                        reserved_rss_mb: 320,
                        host_rss_budget_mb: Some(512),
                        host_storage_budget_mb: 1024,
                        docker_endpoint: None,
                        allow_reaper_socket: false,
                    },
                    SandboxSummaryInfo {
                        id: SandboxId::new("sb-2"),
                        pid: 5151,
                        alive: true,
                        network: NetworkPolicy::InternetOnly,
                        remaining_ttl_ms: 590_000,
                        live_rss_bytes: None,
                        reserved_rss_mb: 576,
                        host_rss_budget_mb: None,
                        host_storage_budget_mb: 2048,
                        docker_endpoint: Some(r"\\.\pipe\minipod-docker-1".to_owned()),
                        allow_reaper_socket: true,
                    },
                ],
            },
            ControlResponse::Spawned(SandboxLease {
                id: SandboxId::new("sb-42"),
                ttl: Duration::from_secs(120),
                capabilities: CapabilityReport {
                    cpu_quota: EnforcementLevel::HardLimit,
                    host_rss: EnforcementLevel::BestEffort,
                    host_storage: EnforcementLevel::HardLimit,
                    egress_filter: EnforcementLevel::Unsupported,
                },
            }),
            ControlResponse::Ack,
            ControlResponse::ExecStarted { stream_id: 7 },
            ControlResponse::CopyOutData {
                tar_bytes: vec![9, 8, 7, 0, 255],
            },
            ControlResponse::DockerCompatEndpoint {
                uri: r"\\.\pipe\minipod-docker-sb-42".to_owned(),
            },
            ControlResponse::Destroyed(DestroyStatus::AllResourcesCleaned),
            ControlResponse::Destroyed(DestroyStatus::ProcessExited {
                remaining_artifacts: vec![PathBuf::from("/tmp/overlay.qcow2")],
            }),
            ControlResponse::Error(WireError::from(SandboxError::AdmissionRejected(
                "pool busy".to_owned(),
            ))),
        ];

        for resp in responses {
            let bytes = resp.to_json_bytes().unwrap();
            let decoded = ControlResponse::from_json_bytes(&bytes).unwrap();
            assert_eq!(decoded, resp);
        }
    }

    #[test]
    fn exec_wire_messages_and_events_roundtrip_all_variants() {
        let client_msgs = [
            ExecWireClientMsg::Stdin {
                data: vec![0, 1, 2, 128, 255],
            },
            ExecWireClientMsg::StdinEof,
            ExecWireClientMsg::Cancel,
        ];
        for msg in client_msgs {
            let decoded =
                ExecWireClientMsg::from_json_bytes(&msg.to_json_bytes().unwrap()).unwrap();
            assert_eq!(decoded, msg);
        }

        let events = [
            ExecWireEvent::Stdout {
                data: b"hello\n".to_vec(),
            },
            ExecWireEvent::Stderr {
                data: vec![0xff, 0x00, 0x1b],
            },
            ExecWireEvent::Exit(ExecExitStatus {
                code: Some(-15),
                timed_out: true,
                stdout_truncated: true,
                stderr_truncated: false,
            }),
            ExecWireEvent::Exit(ExecExitStatus {
                code: None,
                timed_out: false,
                stdout_truncated: false,
                stderr_truncated: true,
            }),
            ExecWireEvent::Error(WireError::from(SandboxError::LeaseExpired(
                "expired".to_owned(),
            ))),
        ];
        for evt in events {
            let decoded = ExecWireEvent::from_json_bytes(&evt.to_json_bytes().unwrap()).unwrap();
            assert_eq!(decoded, evt);
        }
    }

    #[test]
    fn wire_decode_rejects_out_of_range_numbers_and_nanos() {
        let bad_vcpu = serde_json::to_vec(&json!({
            "type": "Spawn",
            "spec": {
                "isolation": "VmRequired",
                "acceleration": "Preferred",
                "network": { "type": "Isolated" },
                "budget": {
                    "guest_vcpus": 300,
                    "host_cpu_quota_Millicores": null,
                    "guest_ram_mb": 256,
                    "host_rss_budget_mb": null,
                    "virtual_disk_mb": 1024,
                    "host_storage_budget_mb": 2048
                },
                "lease_ttl": { "secs": 60, "nanos": 0 }
            }
        }))
        .unwrap();
        assert!(matches!(
            ControlRequest::from_json_bytes(&bad_vcpu),
            Err(SandboxError::Transport(_))
        ));

        let bad_nanos = serde_json::to_vec(&json!({
            "type": "Spawn",
            "spec": {
                "isolation": "VmRequired",
                "acceleration": "Preferred",
                "network": { "type": "Isolated" },
                "budget": {
                    "guest_vcpus": 1,
                    "host_cpu_quota_Millicores": null,
                    "guest_ram_mb": 256,
                    "host_rss_budget_mb": null,
                    "virtual_disk_mb": 1024,
                    "host_storage_budget_mb": 2048
                },
                "lease_ttl": { "secs": 60, "nanos": 1_000_000_000u64 }
            }
        }))
        .unwrap();
        assert!(matches!(
            ControlRequest::from_json_bytes(&bad_nanos),
            Err(SandboxError::Transport(_))
        ));
    }

    #[tokio::test]
    async fn frame_io_roundtrip_and_rejects_eof_truncated_zero_and_oversized() {
        let (mut client, mut server) = duplex(1024 * 1024);

        let req = ControlRequest::Status;
        let payload = req.to_json_bytes().unwrap();
        write_control_frame(&mut client, &payload).await.unwrap();
        drop(client);

        let received = read_control_frame(&mut server).await.unwrap().unwrap();
        assert_eq!(ControlRequest::from_json_bytes(&received).unwrap(), req);
        assert!(read_control_frame(&mut server).await.unwrap().is_none());

        // Write rejects empty and > MAX_CONTROL_FRAME_BYTES.
        let (mut w_only, _r_unused) = duplex(1024);
        assert!(matches!(
            write_control_frame(&mut w_only, b"").await,
            Err(SandboxError::Transport(_))
        ));
        let oversized = vec![0x61u8; MAX_CONTROL_FRAME_BYTES + 1];
        assert!(matches!(
            write_control_frame(&mut w_only, &oversized).await,
            Err(SandboxError::Transport(_))
        ));

        // Read rejects zero length.
        let (mut w_zero, mut r_zero) = duplex(64);
        w_zero.write_all(&0u32.to_be_bytes()).await.unwrap();
        drop(w_zero);
        assert!(matches!(
            read_control_frame(&mut r_zero).await,
            Err(SandboxError::Transport(_))
        ));

        // Read rejects oversized length prefix without allocating 24 MiB+.
        let (mut w_big, mut r_big) = duplex(64);
        let too_big_len = (MAX_CONTROL_FRAME_BYTES as u32) + 1;
        w_big.write_all(&too_big_len.to_be_bytes()).await.unwrap();
        drop(w_big);
        assert!(matches!(
            read_control_frame(&mut r_big).await,
            Err(SandboxError::Transport(_))
        ));

        // Read rejects truncated 2-byte header.
        let (mut w_trunc_hdr, mut r_trunc_hdr) = duplex(64);
        w_trunc_hdr.write_all(&[0x00, 0x01]).await.unwrap();
        drop(w_trunc_hdr);
        assert!(matches!(
            read_control_frame(&mut r_trunc_hdr).await,
            Err(SandboxError::Transport(_))
        ));

        // Read rejects truncated payload.
        let (mut w_trunc_body, mut r_trunc_body) = duplex(64);
        w_trunc_body.write_all(&10u32.to_be_bytes()).await.unwrap();
        w_trunc_body.write_all(b"12345").await.unwrap();
        drop(w_trunc_body);
        assert!(matches!(
            read_control_frame(&mut r_trunc_body).await,
            Err(SandboxError::Transport(_))
        ));
    }

    #[tokio::test]
    async fn sixteen_mib_tar_payload_fits_within_max_control_frame_bytes() {
        let tar_bytes = vec![0xA5u8; 16 * 1024 * 1024];
        let req = ControlRequest::CopyInTar {
            id: SandboxId::new("sb-large"),
            dst_guest: "/workspace".to_owned(),
            tar_bytes,
        };
        let encoded = req.to_json_bytes().unwrap();
        assert!(
            encoded.len() < MAX_CONTROL_FRAME_BYTES,
            "16 MiB base64 CopyInTar JSON ({} bytes) must fit cleanly under MAX_CONTROL_FRAME_BYTES ({MAX_CONTROL_FRAME_BYTES})",
            encoded.len()
        );

        let (mut client, mut server) = duplex(256 * 1024);
        let write_fut = tokio::spawn(async move {
            write_control_frame(&mut client, &encoded).await.unwrap();
        });
        let received = read_control_frame(&mut server).await.unwrap().unwrap();
        write_fut.await.unwrap();

        let decoded = ControlRequest::from_json_bytes(&received).unwrap();
        assert_eq!(decoded, req);
    }

    #[tokio::test]
    async fn read_control_frame_streams_incrementally_and_rejects_short_24mib_claim() {
        let (mut w, mut r) = duplex(64);
        let claimed = MAX_CONTROL_FRAME_BYTES as u32;
        w.write_all(&claimed.to_be_bytes()).await.unwrap();
        w.write_all(b"tiny").await.unwrap();
        drop(w);
        assert!(matches!(
            read_control_frame(&mut r).await,
            Err(SandboxError::Transport(_))
        ));

        // Multi-chunk 200 KiB payload across a small duplex pipe must reassemble byte-for-byte.
        let large: Vec<u8> = (0..(200 * 1024)).map(|i| (i % 251) as u8).collect();
        let (mut cw, mut sr) = duplex(1024);
        let expected = large.clone();
        let writer = tokio::spawn(async move {
            write_control_frame(&mut cw, &large).await.unwrap();
        });
        let got = read_control_frame(&mut sr).await.unwrap().unwrap();
        writer.await.unwrap();
        assert_eq!(got, expected);

        let (_unused_w, mut size_r) = duplex(64);
        let fut = read_control_frame(&mut size_r);
        assert!(
            std::mem::size_of_val(&fut) <= 256,
            "read_control_frame future ({} bytes) must not embed multi-KiB stack buffers across .await",
            std::mem::size_of_val(&fut)
        );
    }
}
