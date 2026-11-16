#![forbid(unsafe_code)]
//! Layer 4 daemon composition root: local IPC authentication, runtime wiring,
//! Docker compatibility server, and MCP adapter.

use std::process::ExitCode;

use sandboxd::config::{parse_env_args, Command};
use sandboxd::{mcp, server};

fn main() -> ExitCode {
    let cmd = match parse_env_args() {
        Ok(cmd) => cmd,
        Err(err) => {
            eprintln!("sandboxd error: {err}");
            return ExitCode::FAILURE;
        }
    };

    if let Command::Help(usage) = cmd {
        print!("{usage}");
        return ExitCode::SUCCESS;
    }

    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(err) => {
            eprintln!("sandboxd failed to initialize Tokio runtime: {err}");
            return ExitCode::FAILURE;
        }
    };

    let res = rt.block_on(async move {
        match cmd {
            Command::Help(_) => Ok(()),
            Command::Serve(cfg) => server::run_serve(*cfg).await,
            Command::Mcp(cfg) => mcp::run_mcp(cfg).await,
        }
    });

    match res {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("sandboxd error: {err}");
            ExitCode::FAILURE
        }
    }
}
