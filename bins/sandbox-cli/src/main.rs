#![forbid(unsafe_code)]
//! Layer 4 CLI composition root: user commands routed through `sandbox-client`.

mod cli;
mod compose;
mod doctor;
mod image_build;
mod run;
mod tui;

use std::process::ExitCode;

use cli::{execute_cli, parse_env_args, CliCommand, CliOutcome};

fn main() -> ExitCode {
    let parsed = match parse_env_args() {
        Ok(CliOutcome::Help(usage)) => {
            print!("{usage}");
            return ExitCode::SUCCESS;
        }
        Ok(CliOutcome::Run(parsed)) => parsed,
        Err(err) => {
            eprintln!("sandbox-cli error: {err}");
            return ExitCode::FAILURE;
        }
    };

    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(err) => {
            eprintln!("sandbox-cli failed to initialize Tokio runtime: {err}");
            return ExitCode::FAILURE;
        }
    };

    let bounded_shutdown = matches!(
        &parsed.command,
        CliCommand::Run(_) | CliCommand::Doctor { smoke: Some(_) }
    );
    let result = rt.block_on(execute_cli(parsed));
    if bounded_shutdown {
        // A cancelled stdout/stderr write can still be blocked in Tokio's blocking pool.
        rt.shutdown_timeout(std::time::Duration::from_secs(2));
    } else {
        drop(rt);
    }

    match result {
        Ok(code) => ExitCode::from(code),
        Err(err) => {
            eprintln!("sandbox-cli error: {err}");
            ExitCode::FAILURE
        }
    }
}
