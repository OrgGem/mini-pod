//! Daemon-backed preflight diagnostics.

use std::time::Duration;

use sandbox_client::{ControlEndpoint, SandboxClient};
use sandbox_core::{SandboxError, SandboxSpec};
use serde_json::{json, Value};

use crate::run::execute_smoke;

pub async fn execute_doctor(
    client: &SandboxClient,
    json_mode: bool,
    smoke_spec: Option<SandboxSpec>,
) -> Result<u8, SandboxError> {
    let endpoint = match client.endpoint() {
        ControlEndpoint::UnixSocket(path) => format!("unix://{}", path.display()),
        ControlEndpoint::NamedPipe(name) => format!("npipe://{name}"),
    };
    let mut daemon =
        json!({ "status": "error", "endpoint": endpoint, "version": null, "detail": null });
    let mut diagnostics = unknown_diagnostics();
    let mut diagnostic_error = None;

    match tokio::time::timeout(Duration::from_secs(5), client.status()).await {
        Ok(Ok(status)) => {
            daemon["status"] = json!("ok");
            daemon["version"] = json!(status.version);
            match tokio::time::timeout(Duration::from_secs(120), client.doctor()).await {
                Ok(Ok(report)) => diagnostics = report,
                Ok(Err(error)) => diagnostic_error = Some(error.to_string()),
                Err(_) => diagnostic_error = Some("daemon diagnostics timed out".to_owned()),
            }
        }
        Ok(Err(error)) => daemon["detail"] = json!(error.to_string()),
        Err(_) => daemon["detail"] = json!("daemon status request timed out"),
    }

    let (smoke, smoke_ok) = match smoke_spec {
        Some(spec) if daemon["status"] == "ok" => match Box::pin(execute_smoke(client, spec)).await {
            Ok(result) => result,
            Err(error) => (
                json!({ "status": "error", "error": error.to_string() }),
                false,
            ),
        },
        Some(_) => (
            json!({ "status": "not_run", "detail": "Daemon is unavailable." }),
            false,
        ),
        None => (json!({ "status": "not_run" }), true),
    };

    let report = json!({
        "daemon": daemon,
        "guest_arch": diagnostics.get("guest_arch").cloned().unwrap_or(Value::Null),
        "qemu": diagnostics.get("qemu").cloned().unwrap_or_else(unknown_check),
        "qemu_img": diagnostics.get("qemu_img").cloned().unwrap_or_else(unknown_check),
        "bundle": diagnostics.get("bundle").cloned().unwrap_or_else(unknown_check),
        "accelerators": diagnostics.get("accelerators").cloned().unwrap_or_else(unknown_check),
        "diagnostic_error": diagnostic_error,
        "smoke": smoke,
    });
    let all_ready = ["daemon", "qemu", "qemu_img", "bundle", "accelerators"]
        .iter()
        .all(|name| report[*name]["status"] == "ok")
        && report["diagnostic_error"].is_null()
        && smoke_ok;

    if json_mode {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_else(|_| report.to_string())
        );
    } else {
        for name in ["daemon", "qemu", "qemu_img", "bundle", "accelerators"] {
            let check = &report[name];
            let status = check["status"].as_str().unwrap_or("unknown");
            let detail = check["detail"].as_str().unwrap_or("");
            let path = check["path"]
                .as_str()
                .or_else(|| check["endpoint"].as_str())
                .unwrap_or("");
            println!("{name}: {status} {path} {detail}");
        }
        if let Some(version) = report["daemon"]["version"].as_str() {
            println!("daemon version: {version}");
        }
        if let Some(candidates) = report["accelerators"]["candidates"].as_array() {
            let names: Vec<_> = candidates.iter().filter_map(Value::as_str).collect();
            if !names.is_empty() {
                println!("accelerator candidates: {}", names.join(", "));
            }
        }
        if let Some(error) = report["diagnostic_error"].as_str() {
            eprintln!("daemon diagnostics unavailable: {error}");
        }
        let smoke = &report["smoke"];
        println!("smoke: {}", smoke["status"].as_str().unwrap_or("unknown"));
        if let Some(id) = smoke["id"].as_str() {
            println!("smoke sandbox: {id}");
        }
        for name in ["boot_handshake", "accelerator", "workload", "cleanup"] {
            if smoke[name].is_object() {
                let section = &smoke[name];
                let status = section["status"].as_str().unwrap_or("unknown");
                let used = section["used"].as_str().unwrap_or("");
                let detail = section["detail"]
                    .as_str()
                    .or_else(|| section["error"].as_str())
                    .unwrap_or("");
                println!("smoke {name}: {status} {used} {detail}");
                if let Some(artifacts) = section["remaining_artifacts"].as_array() {
                    for artifact in artifacts.iter().filter_map(Value::as_str) {
                        eprintln!("remaining artifact: {artifact}");
                    }
                }
            }
        }
        if let Some(error) = smoke["error"].as_str() {
            eprintln!("smoke error: {error}");
        }
    }
    Ok(if all_ready { 0 } else { 1 })
}

fn unknown_check() -> Value {
    json!({ "status": "unknown", "detail": "Daemon diagnostics are unavailable." })
}

fn unknown_diagnostics() -> Value {
    json!({
        "guest_arch": null,
        "qemu": unknown_check(),
        "qemu_img": unknown_check(),
        "bundle": unknown_check(),
        "accelerators": { "status": "unknown", "candidates": [], "detail": "Daemon diagnostics are unavailable." },
    })
}
