#![forbid(unsafe_code)]
//! Layer 4 CLI composition root: user commands routed through `sandbox-client`.

mod cli;
mod compose;
mod image_build;
mod run;
mod tui;

use std::process::ExitCode;

use cli::{execute_cli, parse_env_args, CliOutcome};

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

    match rt.block_on(execute_cli(parsed)) {
        Ok(code) => ExitCode::from(code),
        Err(err) => {
            eprintln!("sandbox-cli error: {err}");
            ExitCode::FAILURE
        }
    }
}
