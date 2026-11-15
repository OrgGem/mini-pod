//! Phase 1 end-to-end integration tests for owner-only local IPC permissions and live QEMU
//! `virtio-serial` guest boot, handshake, exec, ping, and teardown.

use std::path::Path;

use sandbox_core::{AccelerationPolicy, NetworkPolicy};
use sandbox_vmm::{AgentIpcEndpoint, SpikeBootConfig, SpikeSession};

#[test]
fn ipc_endpoint_enforces_owner_only_permissions() {
    let endpoint = AgentIpcEndpoint::bind_temp("e2e-acl").expect("bind temp IPC endpoint");
    let sock_path = endpoint.socket_path().to_path_buf();
    let runtime_dir = sock_path
        .parent()
        .expect("endpoint socket path must have parent runtime dir")
        .to_path_buf();

    assert!(sock_path.exists(), "bound socket path must exist");
    assert!(runtime_dir.is_dir(), "runtime dir must exist");

    #[cfg(windows)]
    {
        use sandbox_vmm::os::windows::{
            create_owner_only_named_pipe, current_user_sid_string, inspect_path_sddl,
            validate_owner_only_dacl,
        };

        let user_sid = current_user_sid_string().expect("resolve current user SID");
        let forbidden_trustees = ["WD", "AN", "BU", "AU", "SY", "BA"];

        let dir_sddl = inspect_path_sddl(&runtime_dir).expect("inspect runtime dir SDDL");
        validate_owner_only_dacl(
            &dir_sddl,
            &user_sid,
            true,
            &runtime_dir.display().to_string(),
        )
        .expect("runtime dir must enforce protected owner-only DACL");
        for trustee in forbidden_trustees {
            assert!(
                !dir_sddl.contains(trustee),
                "runtime dir SDDL '{dir_sddl}' must not contain '{trustee}'"
            );
        }

        let sock_sddl = inspect_path_sddl(&sock_path).expect("inspect socket SDDL");
        validate_owner_only_dacl(
            &sock_sddl,
            &user_sid,
            false,
            &sock_path.display().to_string(),
        )
        .expect("socket file must allow strictly current user owner SID");
        for trustee in forbidden_trustees {
            assert!(
                !sock_sddl.contains(trustee),
                "socket SDDL '{sock_sddl}' must not contain '{trustee}'"
            );
        }

        let pipe_name = format!("minipod-e2e-acl-{}", std::process::id());
        let pipe =
            create_owner_only_named_pipe(&pipe_name).expect("create owner-only named pipe");
        let pipe_sddl = pipe.inspect_pipe_sddl().expect("inspect named pipe SDDL");
        validate_owner_only_dacl(&pipe_sddl, &user_sid, true, pipe.pipe_path())
            .expect("named pipe must enforce protected owner-only DACL");
        for trustee in forbidden_trustees {
            assert!(
                !pipe_sddl.contains(trustee),
                "named pipe SDDL '{pipe_sddl}' must not contain '{trustee}'"
            );
        }
        drop(pipe);
    }

    #[cfg(unix)]
    {
        use std::fs;
        use std::os::unix::fs::{symlink, MetadataExt};
        use sandbox_core::SandboxError;
        use sandbox_vmm::os::unix::ensure_owner_only_dir;

        let dir_meta = fs::symlink_metadata(&runtime_dir).expect("stat runtime dir");
        assert!(!dir_meta.file_type().is_symlink());
        assert!(dir_meta.is_dir());
        assert_eq!(dir_meta.mode() & 0o777, 0o700);

        let sock_meta = fs::symlink_metadata(&sock_path).expect("stat socket file");
        assert!(!sock_meta.file_type().is_symlink());
        assert_eq!(sock_meta.mode() & 0o777, 0o600);

        let link_dir = std::env::temp_dir().join(format!("mp-e2e-link-{}", std::process::id()));
        let _ = fs::remove_file(&link_dir);
        symlink(&runtime_dir, &link_dir).expect("create symlink to runtime dir");
        let link_res = ensure_owner_only_dir(&link_dir);
        let _ = fs::remove_file(&link_dir);
        assert!(
            matches!(link_res, Err(SandboxError::PolicyViolation(_))),
            "symlink runtime dir must be rejected, got {link_res:?}"
        );
    }

    drop(endpoint);
    assert!(
        !sock_path.exists(),
        "socket '{}' must be removed when AgentIpcEndpoint drops",
        sock_path.display()
    );
    assert!(
        !runtime_dir.exists(),
        "runtime dir '{}' must be removed when AgentIpcEndpoint drops",
        runtime_dir.display()
    );
}

#[test]
fn qemu_boot_handshake_exec_ping_and_clean_teardown() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/sandbox-vmm must sit two levels below workspace root");
    let guest_dir = repo_root.join(".cache").join("spike-guest");
    let kernel_path = guest_dir.join("vmlinuz-virt");
    let initrd_path = guest_dir.join("initramfs.cpio.gz");

    assert!(
        kernel_path.is_file() && initrd_path.is_file(),
        "Missing Phase 1 Linux spike guest images in '{}'. Run `powershell -ExecutionPolicy Bypass -File scripts/build-spike-guest.ps1` first.",
        guest_dir.display()
    );

    let config = SpikeBootConfig {
        kernel_path,
        initrd_path,
        acceleration: AccelerationPolicy::Preferred,
        network: NetworkPolicy::Isolated,
        ..Default::default()
    };

    let mut session = SpikeSession::boot(&config).expect("boot QEMU spike guest");
    eprintln!(
        "[spike_e2e] booted Linux guest with QEMU accel: {}",
        session.accelerator_used().as_qemu_arg()
    );
    let runtime_dir = session.runtime_dir().to_path_buf();
    assert!(
        runtime_dir.is_dir(),
        "runtime dir '{}' should exist during active session",
        runtime_dir.display()
    );

    session.ping(42).expect("initial ping(42) should succeed");

    let uname = session
        .exec(vec!["/bin/uname".to_owned(), "-s".to_owned()])
        .expect("exec /bin/uname -s");
    assert_eq!(uname.exit_code, 0);
    assert_eq!(uname.stdout, b"Linux\n");

    let err_cmd = session
        .exec(vec![
            "/bin/sh".to_owned(),
            "-c".to_owned(),
            "echo err-out >&2; exit 7".to_owned(),
        ])
        .expect("exec stderr/exit-7 shell script");
    assert_eq!(err_cmd.exit_code, 7);
    let stderr_text = String::from_utf8_lossy(&err_cmd.stderr);
    assert!(
        stderr_text.contains("err-out"),
        "expected stderr to contain 'err-out', got {stderr_text:?}"
    );

    let missing = session
        .exec(vec!["/nonexistent/minipod-bin".to_owned()])
        .expect("exec missing binary should return exit code 127 without breaking session");
    assert_eq!(missing.exit_code, 127);

    session.ping(99).expect("post-exec ping(99) should succeed");

    session
        .shutdown_and_cleanup()
        .expect("graceful QEMU shutdown and cleanup should succeed");
    assert!(
        !runtime_dir.exists(),
        "runtime dir '{}' must not remain after shutdown_and_cleanup",
        runtime_dir.display()
    );
}
