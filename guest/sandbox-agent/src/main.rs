#![forbid(unsafe_code)]
//! Guest RPC daemon: Execution Supervisor (process group / sub-cgroup kill on deadline
//! or stdout/stderr budget overflow) and internal Podman Unix socket relay.

use std::process::ExitCode;

fn main() -> ExitCode {
    let _ = sandbox_protocol::PROTOCOL_VERSION;
    ExitCode::SUCCESS
}
