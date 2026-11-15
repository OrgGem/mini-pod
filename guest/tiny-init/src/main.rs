#![forbid(unsafe_code)]
//! Guest PID 1 init: read-only rootfs with writable Podman overlay, zombie reaping,
//! and shutdown signal forwarding (Linux guest target).

use std::process::ExitCode;

fn main() -> ExitCode {
    ExitCode::SUCCESS
}
