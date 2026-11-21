//! One-shot sandbox execution and cleanup.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::Duration;

use sandbox_client::{ClientOutputKind, SandboxClient};
use sandbox_core::safe_tar::ensure_safe_dir_path;
use sandbox_core::{
    DestroyStatus, ExecExitStatus, ExecRequest, SandboxError, SandboxId, SandboxSpec,
};
use serde_json::json;
use tokio::io::AsyncWriteExt;
use tokio::sync::watch;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunSpec {
    pub spec: SandboxSpec,
    pub request: ExecRequest,
    pub input: Option<(PathBuf, String)>,
    pub output: Option<(String, PathBuf)>,
}

struct RunReport {
    id: Option<String>,
    interrupted: bool,
    error: Option<String>,
    workload_status: &'static str,
    exit: Option<ExecExitStatus>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    copy_status: &'static str,
    copy_bytes: Option<u64>,
    copy_error: Option<String>,
    cleanup_status: &'static str,
    remaining_artifacts: Vec<String>,
    cleanup_error: Option<String>,
}

impl RunReport {
    fn new() -> Self {
        Self {
            id: None,
            interrupted: false,
            error: None,
            workload_status: "not_started",
            exit: None,
            stdout: Vec::new(),
            stderr: Vec::new(),
            copy_status: "skipped",
            copy_bytes: None,
            copy_error: None,
            cleanup_status: "not_started",
            remaining_artifacts: Vec::new(),
            cleanup_error: None,
        }
    }

    fn code(&self) -> u8 {
        if self.cleanup_status == "ProcessExited" || self.cleanup_status == "error" {
            return 1;
        }
        if self.interrupted {
            return 130;
        }
        if self.error.is_some() || self.copy_status == "failed" {
            return 1;
        }
        match self.exit {
            Some(exit) if exit.timed_out => 124,
            Some(exit) if exit.stdout_truncated || exit.stderr_truncated => 1,
            Some(exit) => match exit.code {
                Some(0) => 0,
                Some(code) => ((code & 0xff) as u8).max(1),
                None => 1,
            },
            None => 1,
        }
    }

    fn emit(&self, json_mode: bool) {
        if json_mode {
            let value = json!({
                "id": self.id,
                "interrupted": self.interrupted,
                "error": self.error,
                "workload": {
                    "status": self.workload_status,
                    "exit_code": self.exit.and_then(|exit| exit.code),
                    "timed_out": self.exit.is_some_and(|exit| exit.timed_out),
                    "stdout_truncated": self.exit.is_some_and(|exit| exit.stdout_truncated),
                    "stderr_truncated": self.exit.is_some_and(|exit| exit.stderr_truncated),
                    "stdout": String::from_utf8_lossy(&self.stdout),
                    "stderr": String::from_utf8_lossy(&self.stderr),
                },
                "copy_out": { "status": self.copy_status, "bytes": self.copy_bytes, "error": self.copy_error },
                "cleanup": {
                    "status": self.cleanup_status,
                    "remaining_artifacts": self.remaining_artifacts,
                    "error": self.cleanup_error,
                },
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&value).unwrap_or_else(|_| value.to_string())
            );
            return;
        }
        if let Some(error) = &self.error {
            eprintln!("[sandbox-cli] {error}");
        }
        if let Some(error) = &self.copy_error {
            eprintln!("[sandbox-cli] copy-out failed: {error}");
        }
        if let Some(exit) = self.exit {
            if exit.timed_out {
                eprintln!("[sandbox-cli] execution timed out");
            }
            if exit.stdout_truncated {
                eprintln!("[sandbox-cli] stdout truncated at budget limit");
            }
            if exit.stderr_truncated {
                eprintln!("[sandbox-cli] stderr truncated at budget limit");
            }
        }
        if self.cleanup_status == "ProcessExited" {
            eprintln!(
                "[sandbox-cli] sandbox {} exited but cleanup remains: {}",
                self.id.as_deref().unwrap_or("unknown"),
                self.remaining_artifacts.join(", ")
            );
        }
        if let Some(error) = &self.cleanup_error {
            eprintln!(
                "[sandbox-cli] sandbox {} cleanup failed: {error}",
                self.id.as_deref().unwrap_or("unknown")
            );
        }
    }
}

/// Runs an isolated workload and always attempts to destroy a successfully created sandbox.
pub async fn execute_run(
    client: &SandboxClient,
    json_mode: bool,
    run: RunSpec,
) -> Result<u8, SandboxError> {
    let mut report = RunReport::new();
    if let Some((_, destination)) = &run.output {
        if let Err(error) = validate_output_destination(destination) {
            report.copy_status = "failed";
            report.copy_error = Some(error.to_string());
            report.emit(json_mode);
            return Ok(report.code());
        }
    }

    let (signal_task, mut interrupted) = watch_interrupts()?;
    let lease = match client.spawn(run.spec).await {
        Ok(lease) => lease,
        Err(error) => {
            report.interrupted = *interrupted.borrow();
            report.error = Some(format!("failed to spawn sandbox: {error}"));
            if matches!(
                error,
                SandboxError::Transport(_) | SandboxError::Internal(_)
            ) {
                report.cleanup_status = "unknown";
                report.cleanup_error = Some(
                    "no sandbox ID was received; allocation and cleanup cannot be confirmed"
                        .to_owned(),
                );
            }
            signal_task.abort();
            report.emit(json_mode);
            return Ok(report.code());
        }
    };
    let id = lease.id;
    report.id = Some(id.as_str().to_owned());

    let (renewal_tx, mut renewal) = watch::channel(None::<String>);
    let renewal_client = client.clone();
    let renewal_id = id.clone();
    let ttl = lease.ttl;
    let renew_task = tokio::spawn(async move {
        let interval = (ttl / 3)
            .max(Duration::from_millis(100))
            .min(Duration::from_secs(30));
        loop {
            tokio::time::sleep(interval).await;
            let result =
                tokio::time::timeout(interval, renewal_client.renew_lease(&renewal_id, ttl)).await;
            let error = match result {
                Ok(Ok(())) => continue,
                Ok(Err(error)) => format!("lease renewal failed: {error}"),
                Err(_) => "lease renewal timed out".to_owned(),
            };
            let _ = renewal_tx.send(Some(error));
            break;
        }
    });

    run_workload(
        client,
        &id,
        &run.request,
        run.input,
        run.output,
        json_mode,
        &mut interrupted,
        &mut renewal,
        &mut report,
    )
    .await;
    renew_task.abort();
    let _ = renew_task.await;
    report.interrupted |= *interrupted.borrow();

    match tokio::time::timeout(Duration::from_secs(30), client.destroy(&id)).await {
        Ok(Ok(DestroyStatus::AllResourcesCleaned)) => report.cleanup_status = "AllResourcesCleaned",
        Ok(Ok(DestroyStatus::ProcessExited {
            remaining_artifacts,
        })) => {
            report.cleanup_status = "ProcessExited";
            report.remaining_artifacts = remaining_artifacts
                .iter()
                .map(|path| path.display().to_string())
                .collect();
        }
        Ok(Err(error)) => {
            report.cleanup_status = "error";
            report.cleanup_error = Some(error.to_string());
        }
        Err(_) => {
            report.cleanup_status = "error";
            report.cleanup_error =
                Some("destroy timed out; the cleanup outcome is unknown".to_owned());
        }
    }
    report.interrupted |= *interrupted.borrow();
    signal_task.abort();
    report.emit(json_mode);
    Ok(report.code())
}

async fn run_workload(
    client: &SandboxClient,
    id: &SandboxId,
    request: &ExecRequest,
    input: Option<(PathBuf, String)>,
    output: Option<(String, PathBuf)>,
    json_mode: bool,
    interrupted: &mut watch::Receiver<bool>,
    renewal: &mut watch::Receiver<Option<String>>,
    report: &mut RunReport,
) {
    if !record_abort(interrupted, renewal, report) {
        return;
    }
    if let Some((source, destination)) = input {
        let copy = tokio::select! {
            result = client.copy_in_path(id, source, destination) => result,
            _ = interrupted.changed() => {
                record_abort(interrupted, renewal, report);
                return;
            },
            _ = renewal.changed() => {
                record_abort(interrupted, renewal, report);
                return;
            },
        };
        if let Err(error) = copy {
            report.error = Some(format!("copy-in failed: {error}"));
            return;
        }
        if !record_abort(interrupted, renewal, report) {
            return;
        }
    }

    if let Err(error) = execute_workload(
        client,
        id,
        request.clone(),
        json_mode,
        interrupted,
        renewal,
        report,
    )
    .await
    {
        report.workload_status = if report.interrupted {
            "interrupted"
        } else {
            "failed"
        };
        report.error = Some(error);
        return;
    }
    if !record_abort(interrupted, renewal, report) || report.workload_status != "completed" {
        return;
    }

    if let Some((source, destination)) = output {
        match copy_output(client, id, &source, &destination, interrupted, renewal).await {
            Ok(bytes) => {
                report.copy_status = "copied";
                report.copy_bytes = Some(bytes);
            }
            Err(error) => {
                report.copy_status = "failed";
                report.copy_error = Some(error);
                record_abort(interrupted, renewal, report);
            }
        }
    }
}

async fn execute_workload(
    client: &SandboxClient,
    id: &SandboxId,
    request: ExecRequest,
    json_mode: bool,
    interrupted: &mut watch::Receiver<bool>,
    renewal: &mut watch::Receiver<Option<String>>,
    report: &mut RunReport,
) -> Result<(), String> {
    let mut stream = tokio::select! {
        result = client.exec_stream(id, request.clone()) => result.map_err(|error| format!("failed to start execution: {error}"))?,
        _ = interrupted.changed() => {
            record_abort(interrupted, renewal, report);
            return Err(report.error.clone().unwrap_or_else(|| "interrupted".to_owned()));
        },
        _ = renewal.changed() => {
            record_abort(interrupted, renewal, report);
            return Err(report.error.clone().unwrap_or_else(|| "lease renewal stopped".to_owned()));
        },
    };
    stream.close_stdin();
    report.workload_status = "failed";
    let mut stdout = tokio::io::stdout();
    let mut stderr = tokio::io::stderr();

    loop {
        if !record_abort(interrupted, renewal, report) {
            let _ = stream.cancel();
            let _ = tokio::time::timeout(Duration::from_secs(2), stream.wait_exit()).await;
            return Err(report
                .error
                .clone()
                .unwrap_or_else(|| "interrupted".to_owned()));
        }
        let next = tokio::select! {
            chunk = stream.next_output() => chunk,
            _ = interrupted.changed() => continue,
            _ = renewal.changed() => continue,
        };
        let Some(chunk) = next else { break };
        if json_mode {
            let (output, budget) = match chunk.stream {
                ClientOutputKind::Stdout => (&mut report.stdout, request.stdout_budget_bytes),
                ClientOutputKind::Stderr => (&mut report.stderr, request.stderr_budget_bytes),
            };
            if output.len() as u64 + chunk.data.len() as u64 > budget {
                let _ = stream.cancel();
                return Err("execution output exceeded its configured budget".to_owned());
            }
            output.extend_from_slice(&chunk.data);
        } else {
            let write_result = match chunk.stream {
                ClientOutputKind::Stdout => match stdout.write_all(&chunk.data).await {
                    Ok(()) => stdout.flush().await,
                    Err(error) => Err(error),
                },
                ClientOutputKind::Stderr => match stderr.write_all(&chunk.data).await {
                    Ok(()) => stderr.flush().await,
                    Err(error) => Err(error),
                },
            };
            if let Err(error) = write_result {
                let _ = stream.cancel();
                return Err(format!("failed writing execution output: {error}"));
            }
        }
    }
    let exit = tokio::select! {
        result = stream.wait_exit() => result.map_err(|error| format!("execution failed: {error}"))?,
        _ = interrupted.changed() => {
            let _ = stream.cancel();
            record_abort(interrupted, renewal, report);
            return Err(report.error.clone().unwrap_or_else(|| "interrupted".to_owned()));
        },
        _ = renewal.changed() => {
            let _ = stream.cancel();
            record_abort(interrupted, renewal, report);
            return Err(report.error.clone().unwrap_or_else(|| "lease renewal stopped".to_owned()));
        },
    };
    report.exit = Some(exit);
    if exit.code == Some(0) && !exit.timed_out && !exit.stdout_truncated && !exit.stderr_truncated {
        report.workload_status = "completed";
    }
    Ok(())
}

fn record_abort(
    interrupted: &watch::Receiver<bool>,
    renewal: &watch::Receiver<Option<String>>,
    report: &mut RunReport,
) -> bool {
    if *interrupted.borrow() {
        report.interrupted = true;
        report.error = Some("execution interrupted".to_owned());
        return false;
    }
    if let Some(error) = renewal.borrow().as_ref() {
        report.error = Some(error.clone());
        return false;
    }
    true
}

fn watch_interrupts() -> Result<(tokio::task::JoinHandle<()>, watch::Receiver<bool>), SandboxError>
{
    let (sender, receiver) = watch::channel(false);
    #[cfg(unix)]
    let task = {
        let mut signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
            .map_err(|error| {
                SandboxError::Internal(format!("cannot register interrupt handler: {error}"))
            })?;
        tokio::spawn(async move {
            if signal.recv().await.is_some() {
                let _ = sender.send(true);
            }
        })
    };
    #[cfg(windows)]
    let task = {
        let mut ctrl_c = tokio::signal::windows::ctrl_c().map_err(|error| {
            SandboxError::Internal(format!("cannot register Ctrl+C handler: {error}"))
        })?;
        let mut ctrl_break = tokio::signal::windows::ctrl_break().map_err(|error| {
            SandboxError::Internal(format!("cannot register Ctrl+Break handler: {error}"))
        })?;
        tokio::spawn(async move {
            tokio::select! {
                _ = ctrl_c.recv() => {},
                _ = ctrl_break.recv() => {},
            }
            let _ = sender.send(true);
        })
    };
    Ok((task, receiver))
}

fn validate_output_destination(destination: &Path) -> Result<(), SandboxError> {
    let name = destination
        .file_name()
        .filter(|name| !name.is_empty())
        .ok_or_else(|| {
            SandboxError::InvalidSpec(format!(
                "output destination '{}' must name a new directory",
                destination.display()
            ))
        })?;
    let _ = name;
    let parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    ensure_safe_dir_path(parent, false)?;
    match fs::symlink_metadata(destination) {
        Ok(_) => Err(SandboxError::PolicyViolation(format!(
            "output destination '{}' already exists",
            destination.display()
        ))),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(SandboxError::Internal(format!(
            "cannot inspect output destination '{}': {error}",
            destination.display()
        ))),
    }
}

async fn copy_output(
    client: &SandboxClient,
    id: &SandboxId,
    source: &str,
    destination: &Path,
    interrupted: &watch::Receiver<bool>,
    renewal: &watch::Receiver<Option<String>>,
) -> Result<u64, String> {
    let parent = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut stage = OutputStage::create(parent).map_err(|error| error.to_string())?;
    let result = async {
        let bytes = client
            .copy_out_to_path(id, source, &stage.path)
            .await
            .map_err(|error| error.to_string())?;
        if *interrupted.borrow() {
            return Err("interrupted before publishing output".to_owned());
        }
        if let Some(error) = renewal.borrow().as_ref() {
            return Err(error.clone());
        }
        renamore::rename_exclusive(&stage.path, destination).map_err(|error| {
            format!(
                "cannot publish output to '{}': {error}",
                destination.display()
            )
        })?;
        stage.published = true;
        Ok(bytes)
    }
    .await;
    if !stage.published {
        if let Err(error) = stage.remove() {
            return Err(format!(
                "{}; cannot remove staging directory '{}': {error}",
                result.err().unwrap_or_else(|| "copy-out failed".to_owned()),
                stage.path.display()
            ));
        }
    }
    result
}

struct OutputStage {
    path: PathBuf,
    published: bool,
}

impl OutputStage {
    fn create(parent: &Path) -> Result<Self, SandboxError> {
        for _ in 0..16 {
            let mut random = [0u8; 16];
            getrandom::getrandom(&mut random).map_err(|error| {
                SandboxError::Internal(format!("cannot generate staging directory name: {error}"))
            })?;
            let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
            let path = parent.join(format!(".minipod-output-{suffix}"));
            if path.exists() {
                continue;
            }
            #[cfg(unix)]
            let result = {
                use std::os::unix::fs::DirBuilderExt;
                fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&path)
                    .map_err(|error| error.to_string())
            };
            #[cfg(windows)]
            let result = sandbox_vmm::os::windows::create_owner_only_dir(&path)
                .map_err(|error| error.to_string());
            match result {
                Ok(()) => {
                    return Ok(Self {
                        path,
                        published: false,
                    })
                }
                Err(error) => {
                    return Err(SandboxError::Internal(format!(
                        "cannot create output staging directory '{}': {error}",
                        path.display()
                    )))
                }
            }
        }
        Err(SandboxError::Internal(
            "could not allocate output staging directory".to_owned(),
        ))
    }

    fn remove(&mut self) -> std::io::Result<()> {
        match fs::remove_dir_all(&self.path) {
            Ok(()) => {
                self.published = true;
                Ok(())
            }
            Err(error) if error.kind() == ErrorKind::NotFound => {
                self.published = true;
                Ok(())
            }
            Err(error) => Err(error),
        }
    }
}

impl Drop for OutputStage {
    fn drop(&mut self) {
        if !self.published {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}
