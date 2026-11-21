//! Diagnostics using the exact runtime inputs captured at daemon startup.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::time::Duration;

use sandbox_core::GuestArch;
use sandbox_image::{verify_installed_bundle, BundleVerifier};
use sandbox_vmm::{probe_available_accelerators_for_arch, run_confined_command_bounded};
use serde_json::{json, Value};

#[derive(Clone)]
pub(crate) struct DoctorInputs {
    pub bundle_dir: PathBuf,
    pub verifier: BundleVerifier,
    pub qemu_bin: PathBuf,
    pub qemu_img_bin: PathBuf,
    pub arch: GuestArch,
}

impl DoctorInputs {
    pub fn collect(&self) -> Value {
        let qemu = probe_binary(&self.qemu_bin);
        let qemu_img = probe_binary(&self.qemu_img_bin);
        let accelerators = match probe_available_accelerators_for_arch(&self.qemu_bin, self.arch) {
            Ok(accelerators) if !accelerators.is_empty() => json!({
                "status": "ok",
                "candidates": accelerators.iter().map(|accel| accel.as_qemu_arg()).collect::<Vec<_>>(),
                "detail": "Candidates are filtered for host and guest architecture; actual boot is not tested.",
            }),
            Ok(_) => json!({
                "status": "error",
                "candidates": [],
                "detail": "No accelerator candidates are available for the configured guest architecture.",
            }),
            Err(error) => {
                json!({ "status": "error", "candidates": [], "detail": error.to_string() })
            }
        };
        let bundle = match verify_installed_bundle(&self.bundle_dir, &self.verifier) {
            Ok(installed) if !installed.manifest().matches_host_os(std::env::consts::OS) => {
                json!({
                    "status": "error",
                    "path": self.bundle_dir.display().to_string(),
                    "detail": format!("Bundle host_os '{}' is incompatible with current host OS '{}'.", installed.manifest().host_os, std::env::consts::OS),
                })
            }
            Ok(installed) if installed.manifest().guest_arch != self.arch => {
                json!({
                    "status": "error",
                    "path": self.bundle_dir.display().to_string(),
                    "detail": format!("Bundle guest architecture {} differs from configured architecture {}.", installed.manifest().guest_arch, self.arch),
                })
            }
            Ok(installed) => {
                json!({
                    "status": "ok",
                    "path": self.bundle_dir.display().to_string(),
                    "guest_arch": installed.manifest().guest_arch.as_str(),
                    "host_os": installed.manifest().host_os,
                    "detail": "Signature and bundle contents verified.",
                })
            }
            Err(error) => {
                json!({ "status": "error", "path": self.bundle_dir.display().to_string(), "detail": error.to_string() })
            }
        };
        json!({
            "guest_arch": self.arch.as_str(),
            "qemu": qemu,
            "qemu_img": qemu_img,
            "bundle": bundle,
            "accelerators": accelerators,
        })
    }
}

fn probe_binary(path: &Path) -> Value {
    let args = [OsString::from("--version")];
    match run_confined_command_bounded(path, &args, Duration::from_secs(15), 256 * 1024) {
        Ok(output) if output.status.success() => {
            let version = String::from_utf8_lossy(&output.stdout);
            let first_line = version.lines().next().unwrap_or_default();
            json!({ "status": "ok", "path": path.display().to_string(), "detail": first_line })
        }
        Ok(output) => json!({
            "status": "error",
            "path": path.display().to_string(),
            "detail": format!("--version exited with {}: {}", output.status, String::from_utf8_lossy(&output.stderr).trim()),
        }),
        Err(error) => {
            json!({ "status": "error", "path": path.display().to_string(), "detail": error.to_string() })
        }
    }
}

pub(crate) fn unknown() -> Value {
    let unknown =
        json!({ "status": "unknown", "detail": "Daemon runtime configuration is unavailable." });
    json!({
        "guest_arch": null,
        "qemu": unknown,
        "qemu_img": unknown,
        "bundle": unknown,
        "accelerators": { "status": "unknown", "candidates": [], "detail": "Daemon runtime configuration is unavailable." },
    })
}
