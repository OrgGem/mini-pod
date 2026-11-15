//! Layer 3 VMM driver boundary: shared QEMU lifecycle management across Linux, macOS,
//! and Windows, delegating process isolation and host IPC setup to thin OS modules.

pub mod accel;
pub mod ipc;
pub mod launch;
pub mod os;

pub use accel::{
    classify_launch_error, discover_qemu_binary, find_qemu_binary_in_dirs, parse_accel_help,
    probe_available_accelerators, select_accelerator, Accelerator,
};
pub use ipc::{
    validate_pipe_name, validate_socket_path, AgentIpcEndpoint, IpcListener, IpcStream,
    MAX_UNIX_SOCKET_PATH_BYTES,
};
pub use launch::{QemuLaunchConfig, AGENT_VIRTIO_PORT_NAME};
