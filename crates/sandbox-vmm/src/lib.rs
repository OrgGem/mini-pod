//! Layer 3 VMM driver boundary: shared QEMU lifecycle management across Linux, macOS,
//! and Windows, delegating process isolation and host IPC setup to thin OS modules.

pub mod os;
