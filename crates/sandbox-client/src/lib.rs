#![forbid(unsafe_code)]
//! Lightweight embedded Rust client SDK boundary.
//! Forbidden from pulling daemon server, VMM driver, or MCP server dependencies.

pub mod client;
pub mod safe_tar;
pub mod wire;

pub use client::{
    BoxedControlStream, ClientExecOutput, ClientExecStream, ClientOutputChunk, ClientOutputKind,
    ControlEndpoint, ControlStream, SandboxClient, DEFAULT_MAX_COPY_BYTES,
    DEFAULT_MAX_COPY_ENTRIES,
};
pub use safe_tar::{extract_tar_bytes_safely, pack_path_to_tar_bytes};
pub use wire::{
    decode_base64, encode_base64, read_control_frame, write_control_frame, ControlRequest,
    ControlResponse, DaemonStatusInfo, ExecWireClientMsg, ExecWireEvent, WireError,
    MAX_CONTROL_FRAME_BYTES,
};
