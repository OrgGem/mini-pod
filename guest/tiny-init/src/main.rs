#![deny(unsafe_code)]
//! Guest PID 1 init: read-only rootfs with writable Podman overlay, zombie reaping,
//! and shutdown signal forwarding (Linux guest target).

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod plan;

#[cfg(target_os = "linux")]
mod linux;

use std::process::ExitCode;

fn main() -> ExitCode {
    #[cfg(target_os = "linux")]
    {
        linux::run()
    }
    #[cfg(not(target_os = "linux"))]
    {
        eprintln!("tiny-init is only supported on Linux guests");
        ExitCode::FAILURE
    }
}
