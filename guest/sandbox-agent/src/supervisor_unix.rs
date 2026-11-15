//! Unix process-group isolation, parent-death guard, user switching, and group kill helpers.

use std::fs;
use std::io;
use std::os::unix::process::CommandExt;
use std::process::Command;

use crate::supervisor::resolve_user_ids_from_tables;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct UnixUser {
    pub uid: libc::uid_t,
    pub gid: libc::gid_t,
}

/// Resolves numeric `uid[:gid]` or `/etc/passwd` + `/etc/group` entries before `fork()`.
pub(crate) fn resolve_user(spec: &str) -> Result<UnixUser, String> {
    let passwd = read_optional_table("/etc/passwd")?;
    let group = read_optional_table("/etc/group")?;
    let (uid_u32, gid_u32) =
        resolve_user_ids_from_tables(spec, passwd.as_deref(), group.as_deref())?;
    let uid = libc::uid_t::try_from(uid_u32)
        .map_err(|_| format!("resolved uid {uid_u32} exceeds platform uid_t range"))?;
    let gid = libc::gid_t::try_from(gid_u32)
        .map_err(|_| format!("resolved gid {gid_u32} exceeds platform gid_t range"))?;
    Ok(UnixUser { uid, gid })
}

fn read_optional_table(path: &str) -> Result<Option<String>, String> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(format!("failed to read '{path}' for user lookup: {err}")),
    }
}

/// Configures child process to enter a dedicated process group (`pgid == child_pid`)
/// and optionally switch `gid`/`uid` prior to `execve()`.
#[allow(unsafe_code)]
pub(crate) fn configure_command(cmd: &mut Command, user: Option<UnixUser>) {
    // SAFETY: The `pre_exec` hook runs between `fork()` and `execve()` and invokes only
    // async-signal-safe syscalls (`setpgid`, `prctl` on Linux, `setgid`, `setuid`) using
    // `Copy` primitive IDs resolved prior to `fork()` without allocating or locking.
    unsafe {
        cmd.pre_exec(move || {
            if libc::setpgid(0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            #[cfg(target_os = "linux")]
            {
                let _ = libc::prctl(
                    libc::PR_SET_PDEATHSIG,
                    libc::SIGKILL as libc::c_ulong,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                    0 as libc::c_ulong,
                );
            }
            if let Some(u) = user {
                if libc::setgid(u.gid) != 0 {
                    return Err(io::Error::last_os_error());
                }
                if libc::setuid(u.uid) != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
}

/// Immediately sends `SIGKILL` to every process in the dedicated process group `pgid`.
#[allow(unsafe_code)]
pub(crate) fn kill_process_group(pgid: u32) {
    let Ok(raw_pid) = libc::pid_t::try_from(pgid) else {
        return;
    };
    if raw_pid <= 0 {
        return;
    }
    // SAFETY: `raw_pid` is strictly positive and names the child's dedicated process group
    // established in `pre_exec` via `setpgid(0, 0)`, so `-raw_pid` targets only that tree.
    unsafe {
        let _ = libc::kill(-raw_pid, libc::SIGKILL);
    }
}
