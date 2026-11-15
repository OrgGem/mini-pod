//! OS-specific process confinement, local IPC permissions, and accelerator probing.

#[cfg(windows)]
pub mod windows;

#[cfg(unix)]
pub mod unix;
