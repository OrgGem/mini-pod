//! Layer 3 VMM driver boundary: shared QEMU lifecycle management across Linux, macOS,
//! and Windows, delegating process isolation and host IPC setup to thin OS modules.

pub mod accel;
pub mod ipc;
pub mod launch;
pub mod os;
pub mod process;
pub mod spike;

pub use accel::{
    classify_launch_error, discover_qemu_binary, discover_qemu_binary_for_arch,
    discover_qemu_img_binary, find_qemu_binary_for_arch_in_dirs, find_qemu_binary_in_dirs,
    parse_accel_help, probe_available_accelerators, probe_available_accelerators_for_arch,
    qemu_binary_name, qemu_img_binary_name, select_accelerator, Accelerator,
};
pub use ipc::{
    validate_pipe_name, validate_socket_path, AgentIpcEndpoint, IpcListener, IpcStream,
    MAX_UNIX_SOCKET_PATH_BYTES,
};
pub use launch::{QemuLaunchConfig, AGENT_VIRTIO_PORT_NAME};
pub use process::{
    kill_verified_orphan_process, parse_proc_stat_starttime, quote_windows_command_line,
    ConfinedProcess, ProcessExitStatus, ProcessLaunchSpec, ProcessStartIdentity, ProcessStdio,
};
pub use sandbox_core::GuestArch;
pub use spike::{SpikeBootConfig, SpikeExecOutput, SpikeSession};
