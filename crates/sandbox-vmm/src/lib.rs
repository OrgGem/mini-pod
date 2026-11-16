//! Layer 3 VMM driver boundary: shared QEMU lifecycle management across Linux, macOS,
//! and Windows, delegating process isolation and host IPC setup to thin OS modules.

pub mod accel;
pub mod driver;
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
pub use driver::{QemuDriverConfig, QemuVmDriver, QemuVmSession};
pub use ipc::{
    validate_pipe_name, validate_socket_path, AgentIpcEndpoint, IpcListener, IpcReadHalf,
    IpcStream, IpcWriteHalf, MAX_UNIX_SOCKET_PATH_BYTES,
};
#[cfg(unix)]
pub use ipc::{verify_non_owner_unix_socket_denied, CrossUserIpcCheck};
#[cfg(windows)]
pub use ipc::{create_owner_only_async_named_pipe, verify_non_owner_named_pipe_denied};
pub use launch::{QemuLaunchConfig, AGENT_VIRTIO_PORT_NAME};
pub use process::{
    kill_verified_orphan_process, millicores_to_windows_cpu_rate, parse_proc_self_cgroup_v2,
    parse_proc_stat_starttime, parse_proc_statm_rss_bytes, quote_windows_command_line,
    run_confined_command_bounded, ConfinedCommandOutput, ConfinedProcess, ProcessExitStatus,
    ProcessLaunchSpec, ProcessResourceCapabilities, ProcessStartIdentity, ProcessStdio,
};
pub use sandbox_core::GuestArch;
pub use spike::{SpikeBootConfig, SpikeExecOutput, SpikeSession};
